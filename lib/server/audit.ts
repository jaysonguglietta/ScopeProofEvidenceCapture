import type { AuthenticatedUser } from "./auth";
import { verifyLatestAuditCheckpoint } from "./checkpoints";
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
      const guardId = auditCondition && mutations.length ? randomId("audit_guard") : null;
      const auditSql = auditCondition
        ? `INSERT INTO audit_events (id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature, hmac_key_id)
          SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
          WHERE ${guardId ? "EXISTS (SELECT 1 FROM audit_batch_guards WHERE id = ? AND mutation_changes > 0)" : auditCondition.sql}`
        : `INSERT INTO audit_events (id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature, hmac_key_id)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
      const statements: D1PreparedStatement[] = [];
      if (guardId) {
        statements.push(env.DB.prepare("INSERT INTO audit_batch_guards (id, baseline_changes, mutation_changes, valid) VALUES (?, total_changes(), 0, 1)").bind(guardId));
      }
      statements.push(...mutations);
      if (guardId && auditCondition) {
        // total_changes() is evaluated before this UPDATE. Subtracting the
        // guard INSERT yields the aggregate change count for every mutation,
        // not merely SQLite's changes() value for the final statement.
        statements.push(env.DB.prepare(`UPDATE audit_batch_guards
          SET mutation_changes = total_changes() - baseline_changes - 1,
              valid = CASE WHEN total_changes() - baseline_changes - 1 = 0 OR (${auditCondition.sql}) THEN 1 ELSE 0 END
          WHERE id = ?`).bind(...auditCondition.bindings, guardId));
      }
      statements.push(env.DB.prepare(auditSql).bind(id, occurredAt, actor.id, actor.email, action, resourceType, resourceId, stableJson(details), previousHash, eventHash, signature, hmacKeyId, ...(guardId ? [guardId] : (auditCondition?.bindings || []))));
      if (guardId) statements.push(env.DB.prepare("DELETE FROM audit_batch_guards WHERE id = ?").bind(guardId));
      const results = await env.DB.batch(statements);
      const mutationOffset = guardId ? 1 : 0;
      return results.slice(mutationOffset, mutationOffset + mutations.length);
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

export type AuditChainVerification = { valid: boolean; checked: number; anchoredAt?: number; failedAt?: number; failureReason?: "invalid_details_json" | "non_canonical_details" | "chain_mismatch" | "checkpoint_invalid" | "verification_limit_exceeded" };

const AUDIT_VERIFICATION_CACHE_TTL_MS = 30_000;
let auditVerificationCache: { key: string; maximumEvents: number; expiresAt: number; result: AuditChainVerification } | null = null;

export async function verifyAuditChain(maximumEvents = 10_000): Promise<AuditChainVerification> {
  const env = getEnv();
  const head = await env.DB.prepare("SELECT sequence, event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").first<{ sequence: number; event_hash: string }>();
  const checkpoint = await env.DB.prepare(`SELECT c.sequence, c.event_hash, c.checkpoint_sha256, c.external_status, c.external_receipt_sha256,
    d.id AS delivery_attempt_id, d.external_receipt_sha256 AS delivery_attempt_receipt_sha256
    FROM audit_checkpoints c
    LEFT JOIN audit_checkpoint_delivery_attempts d ON d.checkpoint_id = c.id AND d.status = 'delivered'
    ORDER BY c.sequence DESC LIMIT 1`).first<{ sequence: number; event_hash: string; checkpoint_sha256: string; external_status: string; external_receipt_sha256: string | null; delivery_attempt_id: string | null; delivery_attempt_receipt_sha256: string | null }>();
  const cacheKey = `${Number(head?.sequence || 0)}:${head?.event_hash || "GENESIS"}:${Number(checkpoint?.sequence || 0)}:${checkpoint?.event_hash || "NONE"}:${checkpoint?.checkpoint_sha256 || "NONE"}:${checkpoint?.external_status || "NONE"}:${checkpoint?.external_receipt_sha256 || "NONE"}:${checkpoint?.delivery_attempt_id || "NONE"}:${checkpoint?.delivery_attempt_receipt_sha256 || "NONE"}`;
  if (auditVerificationCache?.key === cacheKey && auditVerificationCache.maximumEvents === maximumEvents && auditVerificationCache.expiresAt > Date.now()) return auditVerificationCache.result;
  const finish = (result: AuditChainVerification): AuditChainVerification => {
    auditVerificationCache = { key: cacheKey, maximumEvents, expiresAt: Date.now() + AUDIT_VERIFICATION_CACHE_TTL_MS, result };
    return result;
  };
  let previousHash = "GENESIS";
  let anchoredAt = 0;
  if (checkpoint) {
    const verification = await verifyLatestAuditCheckpoint();
    if (!verification.valid || verification.sequence !== Number(checkpoint.sequence)) {
      return finish({ valid: false, checked: 0, failedAt: Number(checkpoint.sequence), failureReason: "checkpoint_invalid" });
    }
    anchoredAt = Number(checkpoint.sequence);
    previousHash = checkpoint.event_hash;
  }
  const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE sequence > ?").bind(anchoredAt).first<{ count: number }>();
  if (Number(count?.count || 0) > maximumEvents) return finish({ valid: false, checked: anchoredAt, anchoredAt: anchoredAt || undefined, failureReason: "verification_limit_exceeded" });
  let verifiedTail = 0;
  let afterSequence = anchoredAt;
  while (verifiedTail < maximumEvents) {
    const rows = (await env.DB.prepare("SELECT sequence, id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature, hmac_key_id FROM audit_events WHERE sequence > ? ORDER BY sequence ASC LIMIT 500").bind(afterSequence).all<Record<string, unknown>>()).results;
    if (!rows.length) break;
    for (const row of rows) {
    let details: unknown;
    try { details = JSON.parse(String(row.details_json || "{}")); }
    catch { return finish({ valid: false, checked: anchoredAt + verifiedTail, anchoredAt: anchoredAt || undefined, failedAt: Number(row.sequence), failureReason: "invalid_details_json" }); }
    try {
      if (stableJson(details) !== String(row.details_json)) return finish({ valid: false, checked: anchoredAt + verifiedTail, anchoredAt: anchoredAt || undefined, failedAt: Number(row.sequence), failureReason: "non_canonical_details" });
    } catch {
      return finish({ valid: false, checked: anchoredAt + verifiedTail, anchoredAt: anchoredAt || undefined, failedAt: Number(row.sequence), failureReason: "non_canonical_details" });
    }
    const canonical = stableJson({ id: row.id, occurredAt: row.occurred_at, actorId: row.actor_id, actorEmail: row.actor_email, action: row.action, resourceType: row.resource_type, resourceId: row.resource_id, details, previousHash: row.previous_hash });
    const eventHash = await sha256(canonical);
    let signature: string; try { signature = await hmac(eventHash, String(row.hmac_key_id || "legacy-v1")); } catch { return finish({ valid: false, checked: anchoredAt + verifiedTail, anchoredAt: anchoredAt || undefined, failedAt: Number(row.sequence), failureReason: "chain_mismatch" }); }
    if (row.previous_hash !== previousHash || row.event_hash !== eventHash || row.signature !== signature) return finish({ valid: false, checked: anchoredAt + verifiedTail, anchoredAt: anchoredAt || undefined, failedAt: Number(row.sequence), failureReason: "chain_mismatch" });
    previousHash = eventHash;
    afterSequence = Number(row.sequence);
    verifiedTail += 1;
    }
  }
  return finish({ valid: true, checked: anchoredAt + verifiedTail, anchoredAt: anchoredAt || undefined });
}
