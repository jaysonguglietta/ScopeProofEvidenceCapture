import type { AuthenticatedUser } from "./auth";
import { activeAuditKeyId, hmac, randomId, sha256, stableJson } from "./crypto";
import { getEnv } from "./env";

export async function executeAuditedBatch(actor: AuthenticatedUser, action: string, resourceType: string, resourceId: string, details: Record<string, unknown>, mutations: D1PreparedStatement[], auditCondition?: { sql: string; bindings: unknown[] }): Promise<D1Result[]> {
  const env = getEnv();
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const previous = await env.DB.prepare("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").first<{ event_hash: string }>();
    const id = randomId("evt");
    const occurredAt = new Date().toISOString();
    const previousHash = previous?.event_hash || "GENESIS";
    const canonical = stableJson({ id, occurredAt, actorId: actor.id, actorEmail: actor.email, action, resourceType, resourceId, details, previousHash });
    const eventHash = await sha256(canonical);
    const hmacKeyId = activeAuditKeyId();
    const signature = await hmac(eventHash, hmacKeyId);
    try {
      const auditSql = auditCondition
        ? `INSERT INTO audit_events (id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature, hmac_key_id)
          SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE ${auditCondition.sql}`
        : `INSERT INTO audit_events (id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature, hmac_key_id)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
      const results = await env.DB.batch([
        ...mutations,
        env.DB.prepare(auditSql).bind(id, occurredAt, actor.id, actor.email, action, resourceType, resourceId, stableJson(details), previousHash, eventHash, signature, hmacKeyId, ...(auditCondition?.bindings || [])),
      ]);
      return results.slice(0, mutations.length);
    } catch (error) {
      console.error("scopeproof_audited_batch_failure", { action, resourceType, resourceId, attempt: attempt + 1, retryable: String(error).includes("audit chain head changed") });
      if (attempt === 2 || !String(error).includes("audit chain head changed")) throw error;
    }
  }
  throw new Error("Audited database batch exhausted its retry budget.");
}

export async function appendAuditEvent(actor: AuthenticatedUser, action: string, resourceType: string, resourceId: string, details: Record<string, unknown> = {}): Promise<void> {
  await executeAuditedBatch(actor, action, resourceType, resourceId, details, []);
}

export type AuditChainVerification = { valid: boolean; checked: number; failedAt?: number; failureReason?: "invalid_details_json" | "non_canonical_details" | "chain_mismatch" | "verification_limit_exceeded" };

export async function verifyAuditChain(maximumEvents = 100_000): Promise<AuditChainVerification> {
  const env = getEnv();
  const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM audit_events").first<{ count: number }>();
  if (Number(count?.count || 0) > maximumEvents) return { valid: false, checked: 0, failureReason: "verification_limit_exceeded" };
  let previousHash = "GENESIS";
  let checked = 0;
  let afterSequence = 0;
  while (checked < maximumEvents) {
    const rows = (await env.DB.prepare("SELECT sequence, id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature, hmac_key_id FROM audit_events WHERE sequence > ? ORDER BY sequence ASC LIMIT 500").bind(afterSequence).all<Record<string, unknown>>()).results;
    if (!rows.length) break;
    for (const row of rows) {
    let details: unknown;
    try { details = JSON.parse(String(row.details_json || "{}")); }
    catch { return { valid: false, checked, failedAt: Number(row.sequence), failureReason: "invalid_details_json" }; }
    try {
      if (stableJson(details) !== String(row.details_json)) return { valid: false, checked, failedAt: Number(row.sequence), failureReason: "non_canonical_details" };
    } catch {
      return { valid: false, checked, failedAt: Number(row.sequence), failureReason: "non_canonical_details" };
    }
    const canonical = stableJson({ id: row.id, occurredAt: row.occurred_at, actorId: row.actor_id, actorEmail: row.actor_email, action: row.action, resourceType: row.resource_type, resourceId: row.resource_id, details, previousHash: row.previous_hash });
    const eventHash = await sha256(canonical);
    let signature: string; try { signature = await hmac(eventHash, String(row.hmac_key_id || "legacy-v1")); } catch { return { valid: false, checked, failedAt: Number(row.sequence), failureReason: "chain_mismatch" }; }
    if (row.previous_hash !== previousHash || row.event_hash !== eventHash || row.signature !== signature) return { valid: false, checked, failedAt: Number(row.sequence), failureReason: "chain_mismatch" };
    previousHash = eventHash;
    afterSequence = Number(row.sequence);
    checked += 1;
    }
  }
  return { valid: true, checked };
}
