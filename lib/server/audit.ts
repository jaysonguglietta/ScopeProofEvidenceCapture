import type { AuthenticatedUser } from "./auth";
import { hmac, randomId, sha256, stableJson } from "./crypto";
import { getEnv } from "./env";

export async function appendAuditEvent(actor: AuthenticatedUser, action: string, resourceType: string, resourceId: string, details: Record<string, unknown> = {}): Promise<void> {
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
      await env.DB.prepare(`INSERT INTO audit_events (id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, occurredAt, actor.id, actor.email, action, resourceType, resourceId, stableJson(details), previousHash, eventHash, signature).run();
      return;
    } catch (error) {
      if (attempt === 2 || !String(error).includes("audit chain head changed")) throw error;
    }
  }
}

export async function verifyAuditChain(): Promise<{ valid: boolean; checked: number; failedAt?: number }> {
  const rows = (await getEnv().DB.prepare("SELECT sequence, id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature FROM audit_events ORDER BY sequence ASC").all<Record<string, unknown>>()).results;
  let previousHash = "GENESIS";
  for (const row of rows) {
    const details = JSON.parse(String(row.details_json || "{}"));
    const canonical = stableJson({ id: row.id, occurredAt: row.occurred_at, actorId: row.actor_id, actorEmail: row.actor_email, action: row.action, resourceType: row.resource_type, resourceId: row.resource_id, details, previousHash: row.previous_hash });
    const eventHash = await sha256(canonical);
    const signature = await hmac(eventHash);
    if (row.previous_hash !== previousHash || row.event_hash !== eventHash || row.signature !== signature) return { valid: false, checked: Number(row.sequence) - 1, failedAt: Number(row.sequence) };
    previousHash = eventHash;
  }
  return { valid: true, checked: rows.length };
}
