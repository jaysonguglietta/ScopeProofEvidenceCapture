import type { AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { collectorConfiguration, CollectorError, runCollector, type CollectorProvider } from "./collectors";
import { randomId } from "./crypto";
import { getEnv } from "./env";
import { storeEvidence } from "./evidence";

const systemActor: AuthenticatedUser = { id: "system:scheduler", email: "scheduler@scopeproof.internal", displayName: "Scopeproof Scheduler", role: "admin" };

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

export async function queueCollection(collectorId: string, actor: AuthenticatedUser, triggerType: "manual" | "scheduled" | "retry" = "manual"): Promise<string> {
  const env = getEnv();
  const collector = await env.DB.prepare("SELECT id FROM collectors WHERE id = ? AND enabled = 1").bind(collectorId).first();
  if (!collector) throw new Error("Collector is unavailable or disabled.");
  const id = randomId("job");
  await executeAuditedBatch(actor, "collection.queued", "collection_job", id, { collectorId, triggerType }, [
    env.DB.prepare("INSERT INTO collection_jobs (id, collector_id, requested_by, trigger_type) VALUES (?, ?, ?, ?)").bind(id, collectorId, actor.id, triggerType),
  ]);
  return id;
}

export async function processJob(jobId: string, actor?: AuthenticatedUser): Promise<{ status: string; artifacts: number; error?: string }> {
  const env = getEnv();
  const job = await env.DB.prepare("SELECT * FROM collection_jobs WHERE id = ?").bind(jobId).first<Record<string, unknown>>();
  if (!job) throw new Error("Collection job not found.");
  const collector = await env.DB.prepare("SELECT * FROM collectors WHERE id = ?").bind(job.collector_id).first<Record<string, unknown>>();
  if (!collector) throw new Error("Collector not found.");
  const runActor = actor || systemActor;
  const attempt = Number(job.attempt || 0) + 1;
  await executeAuditedBatch(runActor, "collection.started", "collection_job", jobId, { collectorId: collector.id, attempt }, [
    env.DB.prepare("UPDATE collection_jobs SET status = 'running', attempt = ?, started_at = ?, error_code = NULL, error_message = NULL WHERE id = ?").bind(attempt, new Date().toISOString(), jobId),
    env.DB.prepare("UPDATE collectors SET status = 'running', updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(collector.id),
  ]);
  try {
    const artifacts = await runCollector(String(collector.provider) as CollectorProvider, { actor: runActor, config: JSON.parse(String(collector.config_json || "{}")) });
    let stored = 0;
    for (const artifact of artifacts) {
      const result = await storeEvidence({ ...artifact, createdBy: runActor, collectorId: String(collector.id), jobId });
      if (!result.deduplicated) stored += 1;
    }
    const completed = new Date().toISOString();
    await executeAuditedBatch(runActor, "collection.completed", "collection_job", jobId, { collectorId: collector.id, artifactCount: stored, attempt }, [
      env.DB.prepare("UPDATE collection_jobs SET status = 'completed', artifact_count = ?, completed_at = ? WHERE id = ?").bind(stored, completed, jobId),
      env.DB.prepare("UPDATE collectors SET status = 'healthy', last_run_at = ?, last_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(completed, collector.id),
    ]);
    return { status: "completed", artifacts: stored };
  } catch (error) {
    const collectorError = error instanceof CollectorError ? error : new CollectorError(error instanceof Error ? error.message : "Unknown collector failure", "INTERNAL_ERROR", true);
    const maxAttempts = Number(job.max_attempts || 3);
    const retry = collectorError.retryable && attempt < maxAttempts;
    const nextAttemptAt = retry ? new Date(Date.now() + Math.min(60 * 60_000, 2 ** attempt * 60_000)).toISOString() : null;
    await executeAuditedBatch(runActor, retry ? "collection.retry_scheduled" : "collection.failed", "collection_job", jobId, { collectorId: collector.id, attempt, code: collectorError.code, retryAt: nextAttemptAt }, [
      env.DB.prepare("UPDATE collection_jobs SET status = ?, next_attempt_at = ?, error_code = ?, error_message = ?, completed_at = ? WHERE id = ?").bind(retry ? "retrying" : "failed", nextAttemptAt, collectorError.code, collectorError.message.slice(0, 1000), retry ? null : new Date().toISOString(), jobId),
      env.DB.prepare("UPDATE collectors SET status = 'action_needed', last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(collectorError.message.slice(0, 1000), collector.id),
    ]);
    return { status: retry ? "retrying" : "failed", artifacts: 0, error: collectorError.message };
  }
}

export async function processDueWork(now = new Date()): Promise<void> {
  const env = getEnv();
  const dueRetries = (await env.DB.prepare("SELECT id FROM collection_jobs WHERE status = 'retrying' AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT 10").bind(now.toISOString()).all<{ id: string }>()).results;
  for (const job of dueRetries) await processJob(job.id);
  const collectors = (await env.DB.prepare("SELECT id, schedule_cron, last_run_at FROM collectors WHERE enabled = 1 AND schedule_cron IS NOT NULL").all<{ id: string; schedule_cron: string; last_run_at: string | null }>()).results;
  for (const collector of collectors) {
    if (!isCronDue(collector.schedule_cron, now, collector.last_run_at ? new Date(collector.last_run_at) : null)) continue;
    const jobId = await queueCollection(collector.id, systemActor, "scheduled");
    await processJob(jobId, systemActor);
  }
}

function isCronDue(expression: string, now: Date, lastRun: Date | null): boolean {
  const [minute, hour, , , weekday] = expression.trim().split(/\s+/);
  const matches = (value: string, actual: number) => value === "*" || Number(value) === actual;
  if (!matches(minute, now.getUTCMinutes()) || !matches(hour, now.getUTCHours()) || !matches(weekday, now.getUTCDay())) return false;
  return !lastRun || now.getTime() - lastRun.getTime() > 55 * 60_000;
}
