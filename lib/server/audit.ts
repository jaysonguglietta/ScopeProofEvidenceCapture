import type { AuthenticatedUser } from "./auth";
import { hmac, randomId, sha256, stableJson } from "./crypto";
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
    const signature = await hmac(eventHash);
    try {
      const auditSql = auditCondition
        ? `INSERT INTO audit_events (id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature)
          SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE ${auditCondition.sql}`
        : `INSERT INTO audit_events (id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
      const results = await env.DB.batch([
        ...mutations,
        env.DB.prepare(auditSql).bind(id, occurredAt, actor.id, actor.email, action, resourceType, resourceId, stableJson(details), previousHash, eventHash, signature, ...(auditCondition?.bindings || [])),
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

export type AuditChainVerification = { valid: boolean; checked: number; failedAt?: number; failureReason?: "invalid_details_json" | "non_canonical_details" | "chain_mismatch" };

export async function verifyAuditChain(): Promise<AuditChainVerification> {
  const rows = (await getEnv().DB.prepare("SELECT sequence, id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature FROM audit_events ORDER BY sequence ASC").all<Record<string, unknown>>()).results;
  let previousHash = "GENESIS";
  for (const row of rows) {
    let details: unknown;
    try { details = JSON.parse(String(row.details_json || "{}")); }
    catch { return { valid: false, checked: Number(row.sequence) - 1, failedAt: Number(row.sequence), failureReason: "invalid_details_json" }; }
    try {
      if (stableJson(details) !== String(row.details_json)) return { valid: false, checked: Number(row.sequence) - 1, failedAt: Number(row.sequence), failureReason: "non_canonical_details" };
    } catch {
      return { valid: false, checked: Number(row.sequence) - 1, failedAt: Number(row.sequence), failureReason: "non_canonical_details" };
    }
    const canonical = stableJson({ id: row.id, occurredAt: row.occurred_at, actorId: row.actor_id, actorEmail: row.actor_email, action: row.action, resourceType: row.resource_type, resourceId: row.resource_id, details, previousHash: row.previous_hash });
    const eventHash = await sha256(canonical);
    const signature = await hmac(eventHash);
    if (row.previous_hash !== previousHash || row.event_hash !== eventHash || row.signature !== signature) return { valid: false, checked: Number(row.sequence) - 1, failedAt: Number(row.sequence), failureReason: "chain_mismatch" };
    previousHash = eventHash;
  }
  return { valid: true, checked: rows.length };
}
