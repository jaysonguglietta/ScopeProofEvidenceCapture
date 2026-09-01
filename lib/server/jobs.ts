import { assertPermission, loadActiveUser, type AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { collectorConfiguration, CollectorError, runCollector, type CollectorProvider } from "./collectors";
import { createAuditCheckpoint } from "./checkpoints";
import { randomId } from "./crypto";
import { getEnv } from "./env";
import { rotateStoredKeys } from "./key-operations";
import { publishOperationalHealth } from "./monitoring";
import { reconcileNativeProvenanceOrphans } from "./native-provenance-reconciliation";
import { storeEvidence } from "./evidence";
import { purgeRateLimitBuckets } from "./rate-limit";
import { purgeExpiredEvidence } from "./retention";
import { classifyErrorForLogging } from "./safe-error";
import { processDueSbomWork } from "./sbom";

const systemActor: AuthenticatedUser = { id: "system:scheduler", email: "scheduler@scopeproof.internal", displayName: "Scopeproof Scheduler", role: "admin" };

async function authorizedJobActor(job: Record<string, unknown>, supplied?: AuthenticatedUser): Promise<AuthenticatedUser> {
  const requestedBy = String(job.requested_by || "");
  if (String(job.trigger_type) === "scheduled" && requestedBy === systemActor.id) return systemActor;
  const current = await loadActiveUser(requestedBy);
  if (!current || (supplied && supplied.id !== current.id)) throw new CollectorError("The requesting user is no longer authorized to collect evidence.", "AUTHORIZATION_REVOKED", false);
  try { assertPermission(current, "collect_evidence"); }
  catch { throw new CollectorError("The requesting user is no longer authorized to collect evidence.", "AUTHORIZATION_REVOKED", false); }
  return current;
}

export async function ensureDefaultCollectors(actor: AuthenticatedUser): Promise<void> {
  const env = getEnv();
  const defaults: Array<[CollectorProvider, string, string]> = [
    ["aws", "AWS production controls", "0 7 * * *"], ["github", "GitHub code controls", "0 18 * * *"], ["okta", "Okta identity controls", "30 15 * * *"],
    ["cloudflare", "Cloudflare edge controls", "0 10 * * *"], ["browser", "Browser configuration captures", "0 11 * * 1"],
  ];
  for (const [provider, name, cron] of defaults) {
    const id = `collector_${provider}`;
    const configuration = collectorConfiguration(provider);
    await env.DB.prepare(`INSERT INTO collectors (id, provider, display_name, schedule_cron, status, last_error, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`).bind(id, provider, name, cron, configuration.configured ? "healthy" : "not_configured", configuration.configured ? null : `Missing: ${configuration.missing.join(", ")}`, actor.id).run();
  }
}

export async function queueCollection(collectorId: string, actor: AuthenticatedUser, triggerType: "manual" | "scheduled" | "retry" = "manual", assessmentId?: string): Promise<string> {
  const env = getEnv();
  const collector = await env.DB.prepare("SELECT id FROM collectors WHERE id = ? AND enabled = 1").bind(collectorId).first();
  if (!collector) throw new Error("Collector is unavailable or disabled.");
  if (assessmentId && !(await env.DB.prepare("SELECT 1 FROM assessments WHERE id = ? AND status = 'active' AND scope_mode = 'explicit' AND catalog_id IS NOT NULL AND json_array_length(systems_json) > 0 AND json_array_length(controls_json) > 0").bind(assessmentId).first())) throw new Response(JSON.stringify({ error: "Collections require an active assessment with an explicit, non-empty, versioned scope." }), { status: 409, headers: { "content-type": "application/json" } });
  const id = randomId("job");
  await executeAuditedBatch(actor, "collection.queued", "collection_job", id, { collectorId, triggerType }, [
    env.DB.prepare("INSERT INTO collection_jobs (id, collector_id, requested_by, trigger_type, assessment_id) VALUES (?, ?, ?, ?, ?)").bind(id, collectorId, actor.id, triggerType, assessmentId || null),
  ]);
  return id;
}

export async function processJob(jobId: string, actor?: AuthenticatedUser): Promise<{ status: string; artifacts: number; error?: string }> {
  const env = getEnv();
  const job = await env.DB.prepare("SELECT * FROM collection_jobs WHERE id = ?").bind(jobId).first<Record<string, unknown>>();
  if (!job) throw new Error("Collection job not found.");
  const collector = await env.DB.prepare("SELECT * FROM collectors WHERE id = ?").bind(job.collector_id).first<Record<string, unknown>>();
  if (!collector) throw new Error("Collector not found.");
  let runActor: AuthenticatedUser;
  try { runActor = await authorizedJobActor(job, actor); }
  catch (error) {
    const failure = error instanceof CollectorError ? error : new CollectorError("The collection requester could not be authorized.", "AUTHORIZATION_REVOKED", false);
    const completedAt = new Date().toISOString();
    await executeAuditedBatch(systemActor, "collection.authorization_revoked", "collection_job", jobId, { code: failure.code, requestedBy: job.requested_by }, [
      env.DB.prepare("UPDATE collection_jobs SET status = 'failed', error_code = ?, error_message = ?, completed_at = ?, lease_id = NULL, lease_expires_at = NULL WHERE id = ? AND status IN ('queued', 'retrying', 'running')").bind(failure.code, failure.message, completedAt, jobId),
    ], { sql: "EXISTS (SELECT 1 FROM collection_jobs WHERE id = ? AND status = 'failed' AND error_code = 'AUTHORIZATION_REVOKED')", bindings: [jobId] });
    return { status: "failed", artifacts: 0, error: failure.message };
  }
  if (Number(collector.enabled) !== 1) {
    const completedAt = new Date().toISOString();
    await executeAuditedBatch(runActor, "collection.disabled", "collection_job", jobId, { collectorId: collector.id, code: "COLLECTOR_DISABLED" }, [
      env.DB.prepare("UPDATE collection_jobs SET status = 'failed', error_code = 'COLLECTOR_DISABLED', error_message = 'The collector was disabled before execution.', completed_at = ?, lease_id = NULL, lease_expires_at = NULL WHERE id = ? AND status IN ('queued', 'retrying', 'running')").bind(completedAt, jobId),
    ], { sql: "EXISTS (SELECT 1 FROM collection_jobs WHERE id = ? AND status = 'failed' AND error_code = 'COLLECTOR_DISABLED')", bindings: [jobId] });
    return { status: "failed", artifacts: 0, error: "The collector was disabled before execution." };
  }
  const attempt = Number(job.attempt || 0) + 1;
  const leaseId = randomId("lease");
  const startedAt = new Date().toISOString();
  const leaseExpiresAt = new Date(Date.now() + 30 * 60_000).toISOString();
  const [claim] = await executeAuditedBatch(runActor, "collection.started", "collection_job", jobId, { collectorId: collector.id, attempt, leaseId, leaseExpiresAt }, [
    env.DB.prepare(`UPDATE collection_jobs SET status = 'running', attempt = ?, started_at = ?, lease_id = ?, lease_expires_at = ?, error_code = NULL, error_message = NULL
      WHERE id = ? AND EXISTS (SELECT 1 FROM collectors WHERE id = ? AND enabled = 1)
        AND (status = 'queued' OR (status = 'retrying' AND next_attempt_at <= ?) OR (status = 'running' AND lease_expires_at < ?))`).bind(attempt, startedAt, leaseId, leaseExpiresAt, jobId, collector.id, startedAt, startedAt),
    env.DB.prepare("UPDATE collectors SET status = 'running', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND enabled = 1 AND EXISTS (SELECT 1 FROM collection_jobs WHERE id = ? AND lease_id = ?)").bind(collector.id, jobId, leaseId),
  ], { sql: "EXISTS (SELECT 1 FROM collection_jobs WHERE id = ? AND lease_id = ?)", bindings: [jobId, leaseId] });
  if (!claim.meta.changes) {
    const currentCollector = await env.DB.prepare("SELECT enabled FROM collectors WHERE id = ?").bind(collector.id).first<{ enabled: number }>();
    if (!currentCollector || Number(currentCollector.enabled) !== 1) {
      const completedAt = new Date().toISOString();
      await executeAuditedBatch(runActor, "collection.disabled", "collection_job", jobId, { collectorId: collector.id, code: "COLLECTOR_DISABLED" }, [
        env.DB.prepare("UPDATE collection_jobs SET status = 'failed', error_code = 'COLLECTOR_DISABLED', error_message = 'The collector was disabled before execution.', completed_at = ?, lease_id = NULL, lease_expires_at = NULL WHERE id = ? AND status IN ('queued', 'retrying', 'running')").bind(completedAt, jobId),
      ], { sql: "EXISTS (SELECT 1 FROM collection_jobs WHERE id = ? AND status = 'failed' AND error_code = 'COLLECTOR_DISABLED')", bindings: [jobId] });
      return { status: "failed", artifacts: 0, error: "The collector was disabled before execution." };
    }
    return { status: String(job.status), artifacts: Number(job.artifact_count || 0), error: "Collection job is already claimed." };
  }
  try {
    const stillEnabled = await env.DB.prepare("SELECT 1 FROM collectors WHERE id = ? AND enabled = 1").bind(collector.id).first();
    if (!stillEnabled) throw new CollectorError("The collector was disabled before its outbound request.", "COLLECTOR_DISABLED", false);
    const collection = await runCollector(String(collector.provider) as CollectorProvider, { actor: runActor, config: JSON.parse(String(collector.config_json || "{}")) });
    let stored = 0;
    for (const artifact of collection.artifacts) {
      const ownsLease = await env.DB.prepare("SELECT 1 FROM collection_jobs WHERE id = ? AND status = 'running' AND lease_id = ? AND lease_expires_at > ?").bind(jobId, leaseId, new Date().toISOString()).first();
      if (!ownsLease) throw new CollectorError("Collection lease expired before evidence persistence.", "LEASE_LOST", true);
      const result = await storeEvidence({ ...artifact, createdBy: runActor, collectorId: String(collector.id), jobId, assessmentId: String(job.assessment_id || ""), coverageStatus: collection.coverage.complete ? "complete" : "partial", coverage: collection.coverage });
      if (!result.deduplicated) stored += 1;
    }
    const completed = new Date().toISOString();
    const finalStatus = collection.coverage.complete ? "completed" : "partial";
    await executeAuditedBatch(runActor, `collection.${finalStatus}`, "collection_job", jobId, { collectorId: collector.id, artifactCount: stored, attempt, coverage: collection.coverage }, [
      env.DB.prepare("UPDATE collection_jobs SET status = ?, artifact_count = ?, completed_at = ?, coverage_status = ?, coverage_json = ?, lease_id = NULL, lease_expires_at = NULL WHERE id = ? AND status = 'running' AND lease_id = ?").bind(finalStatus, stored, completed, collection.coverage.complete ? "complete" : "partial", JSON.stringify(collection.coverage), jobId, leaseId),
      env.DB.prepare("UPDATE collectors SET status = ?, last_run_at = ?, last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND EXISTS (SELECT 1 FROM collection_jobs WHERE id = ? AND status = ? AND completed_at = ?)").bind(collection.coverage.complete ? "healthy" : "action_needed", completed, collection.coverage.complete ? null : collection.coverage.omissions.join(" ").slice(0, 1000), collector.id, jobId, finalStatus, completed),
    ], { sql: "EXISTS (SELECT 1 FROM collection_jobs WHERE id = ? AND status = ? AND completed_at = ?)", bindings: [jobId, finalStatus, completed] });
    return { status: finalStatus, artifacts: stored, error: collection.coverage.complete ? undefined : collection.coverage.omissions.join(" ") };
  } catch (error) {
    const collectorError = error instanceof CollectorError ? error : new CollectorError(error instanceof Error ? error.message : "Unknown collector failure", "INTERNAL_ERROR", true);
    const maxAttempts = Number(job.max_attempts || 3);
    const retry = collectorError.retryable && attempt < maxAttempts;
    const nextAttemptAt = retry ? new Date(Date.now() + Math.min(60 * 60_000, 2 ** attempt * 60_000)).toISOString() : null;
    await executeAuditedBatch(runActor, retry ? "collection.retry_scheduled" : "collection.failed", "collection_job", jobId, { collectorId: collector.id, attempt, code: collectorError.code, retryAt: nextAttemptAt }, [
      env.DB.prepare("UPDATE collection_jobs SET status = ?, next_attempt_at = ?, error_code = ?, error_message = ?, completed_at = ?, lease_id = NULL, lease_expires_at = NULL WHERE id = ? AND status = 'running' AND lease_id = ?").bind(retry ? "retrying" : "failed", nextAttemptAt, collectorError.code, collectorError.message.slice(0, 1000), retry ? null : new Date().toISOString(), jobId, leaseId),
      env.DB.prepare("UPDATE collectors SET status = 'action_needed', last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND EXISTS (SELECT 1 FROM collection_jobs WHERE id = ? AND lease_id IS NULL AND status = ? AND attempt = ?)").bind(collectorError.message.slice(0, 1000), collector.id, jobId, retry ? "retrying" : "failed", attempt),
    ], { sql: "EXISTS (SELECT 1 FROM collection_jobs WHERE id = ? AND lease_id IS NULL AND status = ? AND attempt = ?)", bindings: [jobId, retry ? "retrying" : "failed", attempt] });
    return { status: retry ? "retrying" : "failed", artifacts: 0, error: collectorError.message };
  }
}

export async function processDueWork(now = new Date()): Promise<void> {
  const env = getEnv();
  let isolatedFailures = 0;
  const isolate = async (stage: string, operation: () => Promise<void>, resourceId?: string): Promise<void> => {
    try { await operation(); }
    catch (error) {
      isolatedFailures += 1;
      console.error("scopeproof_maintenance_stage_failure", { stage, resourceId, errorClass: classifyErrorForLogging(error) });
    }
  };
  await isolate("evidence_retention", async () => { await purgeExpiredEvidence(now, systemActor); });
  await isolate("rate_limit_retention", async () => { await purgeRateLimitBuckets(Math.floor(now.getTime() / 1_000)); });
  await isolate("collection_retries", async () => {
    const dueRetries = (await env.DB.prepare("SELECT id FROM collection_jobs WHERE status = 'queued' OR (status = 'retrying' AND next_attempt_at <= ?) OR (status = 'running' AND lease_expires_at < ?) ORDER BY created_at, id LIMIT 10").bind(now.toISOString(), now.toISOString()).all<{ id: string }>()).results;
    for (const job of dueRetries) await isolate("collection_job", async () => { await processJob(job.id); }, job.id);
  });
  await isolate("sbom_jobs", async () => { await processDueSbomWork(now); });
  await isolate("native_provenance_reconciliation", async () => { await reconcileNativeProvenanceOrphans(now); });
  await isolate("scheduled_collectors", async () => {
    const collectors = (await env.DB.prepare("SELECT id, schedule_cron, last_run_at FROM collectors WHERE enabled = 1 AND schedule_cron IS NOT NULL").all<{ id: string; schedule_cron: string; last_run_at: string | null }>()).results;
    for (const collector of collectors) await isolate("scheduled_collector", async () => {
      if (!isCronDue(collector.schedule_cron, now, collector.last_run_at ? new Date(collector.last_run_at) : null)) return;
      const assessment = await env.DB.prepare("SELECT id FROM assessments WHERE status = 'active' ORDER BY period_end DESC LIMIT 1").first<{ id: string }>();
      if (!assessment) { console.error("scopeproof_scheduled_collection_skipped", { collectorId: collector.id, reason: "no_active_assessment" }); return; }
      const jobId = await queueCollection(collector.id, systemActor, "scheduled", assessment.id);
      await processJob(jobId, systemActor);
    }, collector.id);
  });
  await isolate("key_rotation", async () => { await rotateStoredKeys(systemActor, 5); });
  // These safeguards must be attempted even when every earlier maintenance
  // domain is unhealthy. Their failures are independently observable.
  await isolate("audit_checkpoint", async () => { await createAuditCheckpoint(now); });
  await isolate("operational_health", async () => { await publishOperationalHealth(now); });
  if (isolatedFailures > 0) {
    // Keep the scheduled invocation visibly failed without retaining raw
    // provider responses, user input, resource identifiers, or secrets.
    throw new AggregateError([], `Scopeproof maintenance completed with ${isolatedFailures} isolated failure${isolatedFailures === 1 ? "" : "s"}.`);
  }
}

function isCronDue(expression: string, now: Date, lastRun: Date | null): boolean {
  const [minute, hour, , , weekday] = expression.trim().split(/\s+/);
  const matches = (value: string, actual: number) => value === "*" || Number(value) === actual;
  if (!matches(minute, now.getUTCMinutes()) || !matches(hour, now.getUTCHours()) || !matches(weekday, now.getUTCDay())) return false;
  return !lastRun || now.getTime() - lastRun.getTime() > 55 * 60_000;
}
