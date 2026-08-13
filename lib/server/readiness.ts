import { verifyAuditChain } from "./audit";
import { getLatestAuditCheckpoint, verifyLatestAuditCheckpoint } from "./checkpoints";
import { getEnv } from "./env";
import { keyRotationBacklog, validateRetainedKeyReferences } from "./key-operations";

export type ReadinessCheck = { id: string; status: "pass" | "warn" | "fail"; summary: string; details?: unknown };

export async function productionReadiness(): Promise<{ ready: boolean; checkedAt: string; checks: ReadinessCheck[] }> {
  const env = getEnv();
  const checks: ReadinessCheck[] = [];
  const required = [
    ["evidence_keys", Boolean(env.EVIDENCE_KEYRING_JSON || env.EVIDENCE_ENCRYPTION_KEY), "Evidence encryption keyring is configured."],
    ["audit_keys", Boolean(env.AUDIT_KEYRING_JSON || env.AUDIT_HMAC_KEY), "Audit HMAC keyring is configured."],
    ["package_signing", Boolean(env.PACKAGE_SIGNING_PRIVATE_KEY && env.PACKAGE_SIGNING_PUBLIC_KEY), "Package signing keypair is configured."],
    ["trusted_origins", Boolean(env.TRUSTED_APP_ORIGINS), "Trusted application origins are configured."],
    ["bootstrap_admin", Boolean(env.BOOTSTRAP_ADMIN_EMAILS), "Bootstrap administrator allowlist is configured."],
  ] as const;
  for (const [id, present, summary] of required) checks.push({ id, status: present ? "pass" : "fail", summary: present ? summary : `${summary.replace(" is configured.", "")} is missing.` });

  try {
    const references = await validateRetainedKeyReferences();
    checks.push({ id: "retained_keys", status: references.valid ? "pass" : "fail", summary: references.valid ? "Every retained encrypted or signed record has a retained key." : "Retained records reference unavailable keys.", details: references.missing });
    const backlog = await keyRotationBacklog();
    checks.push({ id: "key_rotation", status: backlog === 0 ? "pass" : "warn", summary: backlog === 0 ? "Stored ciphertext uses the active encryption keys." : `${backlog} stored records remain queued for key rotation.`, details: { backlog } });
  } catch (error) {
    checks.push({ id: "retained_keys", status: "fail", summary: "Key configuration could not be validated.", details: error instanceof Error ? error.message : String(error) });
  }

  try {
    const integrity = await verifyAuditChain();
    checks.push({ id: "audit_integrity", status: integrity.valid ? "pass" : "fail", summary: integrity.valid ? `Audit chain verified across ${integrity.checked} events.` : "Audit chain verification failed.", details: integrity });
    const checkpoint = await getLatestAuditCheckpoint();
    const age = checkpoint ? Date.now() - Date.parse(checkpoint.createdAt) : Number.POSITIVE_INFINITY;
    const checkpointVerification = checkpoint ? await verifyLatestAuditCheckpoint() : { valid: false, reason: "missing_checkpoint" };
    const checkpointHealthy = integrity.checked === 0 || Boolean(checkpoint && age <= 30 * 60_000 && checkpointVerification.valid);
    checks.push({ id: "audit_checkpoint", status: checkpointHealthy ? "pass" : "fail", summary: integrity.checked === 0 ? "No audit events require a checkpoint yet." : checkpointHealthy ? `Latest audit checkpoint anchors sequence ${checkpoint?.sequence}.` : "The audit log lacks a recent, valid signed checkpoint.", details: checkpoint ? { sequence: checkpoint.sequence, createdAt: checkpoint.createdAt, externalStatus: checkpoint.externalStatus, publicKeyFingerprint: checkpoint.publicKeyFingerprint, verification: checkpointVerification } : checkpointVerification });
    if (checkpoint && checkpoint.externalStatus !== "delivered") checks.push({ id: "independent_checkpoint", status: "warn", summary: checkpoint.externalStatus === "failed" ? "Independent checkpoint delivery failed." : "Independent checkpoint delivery is not configured." });
  } catch (error) {
    checks.push({ id: "audit_integrity", status: "fail", summary: "Audit integrity could not be verified.", details: error instanceof Error ? error.message : String(error) });
  }

  const collectorCounts = await env.DB.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN status = 'healthy' THEN 1 ELSE 0 END) AS healthy, SUM(CASE WHEN status = 'action_needed' THEN 1 ELSE 0 END) AS action_needed FROM collectors WHERE enabled = 1").first<{ total: number; healthy: number; action_needed: number }>();
  const healthy = Number(collectorCounts?.healthy || 0);
  checks.push({ id: "collectors", status: healthy > 0 && Number(collectorCounts?.action_needed || 0) === 0 ? "pass" : "warn", summary: healthy > 0 ? `${healthy} evidence collectors are healthy.` : "No evidence collector is currently healthy.", details: collectorCounts });
  const activeAssessments = await env.DB.prepare("SELECT COUNT(*) AS count FROM assessments WHERE status = 'active'").first<{ count: number }>();
  checks.push({ id: "active_assessment", status: Number(activeAssessments?.count || 0) > 0 ? "pass" : "warn", summary: Number(activeAssessments?.count || 0) > 0 ? "At least one assessment is active." : "No assessment is active; scheduled collection will remain paused." });

  const jiraConfigured = Boolean(env.JIRA_OAUTH_CLIENT_ID && env.JIRA_OAUTH_CLIENT_SECRET && env.JIRA_OAUTH_CALLBACK_URL && (env.JIRA_OAUTH_KEYRING_JSON || env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY));
  checks.push({ id: "jira_cloud", status: jiraConfigured ? "pass" : "warn", summary: jiraConfigured ? "Jira Cloud OAuth is configured." : "Jira Cloud OAuth is not configured." });
  const timestampConfigured = Boolean(env.RFC3161_TSA_URL && env.RFC3161_VERIFIER_URL && (env.RFC3161_VERIFIER_PUBLIC_KEY || env.RFC3161_VERIFIER_PUBLIC_KEYS));
  checks.push({ id: "trusted_timestamp", status: timestampConfigured ? "pass" : "warn", summary: timestampConfigured ? "Trusted timestamp issuance and verification are configured." : "External RFC 3161 timestamping is not fully configured." });
  return { ready: checks.every((check) => check.status !== "fail"), checkedAt: new Date().toISOString(), checks };
}
