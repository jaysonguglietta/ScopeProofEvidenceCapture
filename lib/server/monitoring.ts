import { activeAuditKeyId, hmac, stableJson } from "./crypto";
import { getEnv } from "./env";
import { boundedFetch } from "./outbound";

type HealthCounts = {
  collector_action_needed: number;
  job_failed: number;
  jira_unknown: number;
  package_failed: number;
  purge_failed: number;
};

function endpoint(): URL | null {
  const env = getEnv();
  if (!env.SECURITY_EVENT_ENDPOINT) return null;
  let url: URL;
  try { url = new URL(env.SECURITY_EVENT_ENDPOINT); } catch { throw new Error("SECURITY_EVENT_ENDPOINT is invalid."); }
  const hosts = new Set(String(env.SECURITY_EVENT_ALLOWED_HOSTS || "").split(",").map((value) => value.trim().toLowerCase()).filter(Boolean));
  if (url.protocol !== "https:" || url.username || url.password || url.hash || !hosts.has(url.hostname.toLowerCase())) throw new Error("Security monitoring delivery is not restricted to an approved HTTPS host.");
  return url;
}

export async function publishOperationalHealth(now = new Date()): Promise<void> {
  const url = endpoint();
  if (!url) return;
  const env = getEnv();
  const since = new Date(now.getTime() - 24 * 60 * 60_000).toISOString();
  const counts = await env.DB.prepare(`SELECT
    (SELECT COUNT(*) FROM collectors WHERE enabled = 1 AND status = 'action_needed') AS collector_action_needed,
    (SELECT COUNT(*) FROM collection_jobs WHERE status = 'failed' AND completed_at >= ?) AS job_failed,
    (SELECT COUNT(*) FROM jira_upload_operations WHERE status = 'unknown') AS jira_unknown,
    (SELECT COUNT(*) FROM export_packages WHERE status = 'failed' AND completed_at >= ?) AS package_failed,
    (SELECT COUNT(*) FROM audit_events WHERE action IN ('evidence.purge_failed','package.purge_failed') AND occurred_at >= ?) AS purge_failed`).bind(since, since, since).first<HealthCounts>();
  const checkpoint = await env.DB.prepare("SELECT sequence, created_at, external_status FROM audit_checkpoints ORDER BY sequence DESC LIMIT 1").first<{ sequence: number; created_at: string; external_status: string }>();
  const payload = stableJson({
    schemaVersion: 1,
    type: "scopeproof.operational_health",
    observedAt: now.toISOString(),
    windowStartedAt: since,
    counts: counts || { collector_action_needed: 0, job_failed: 0, jira_unknown: 0, package_failed: 0, purge_failed: 0 },
    latestAuditCheckpoint: checkpoint ? { sequence: checkpoint.sequence, createdAt: checkpoint.created_at, externalStatus: checkpoint.external_status } : null,
  });
  const keyId = activeAuditKeyId();
  const signature = await hmac(payload, keyId);
  const response = await boundedFetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json",
      "x-scopeproof-signature": signature,
      "x-scopeproof-key-id": keyId,
      ...(env.SECURITY_EVENT_TOKEN ? { authorization: `Bearer ${env.SECURITY_EVENT_TOKEN}` } : {}),
    },
    body: payload,
  }, { label: "Security monitoring", allowedOrigins: [url.origin], maximumBytes: 64_000, timeoutMs: 15_000 });
  if (!response.ok) throw new Error(`Security monitoring endpoint returned HTTP ${response.status}.`);
}
