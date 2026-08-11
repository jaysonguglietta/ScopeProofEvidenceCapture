import { jsonError, requireApiPermission, requireSameOrigin } from "../../../../../lib/server/auth";
import { executeAuditedBatch } from "../../../../../lib/server/audit";
import { getEnv } from "../../../../../lib/server/env";
import { enforceRateLimit, requireBoundedContentLength } from "../../../../../lib/server/rate-limit";

export async function PUT(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_retention");
    await enforceRateLimit(request, actor.id, "retention:hold", 20, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const { id } = await context.params;
    const body = await request.json() as { reason?: unknown; expiresAt?: unknown };
    const reason = String(body.reason || "").trim();
    const expiresAt = new Date(String(body.expiresAt || ""));
    const now = new Date();
    if (reason.length < 20 || reason.length > 1_000 || !Number.isFinite(expiresAt.getTime()) || expiresAt <= now || expiresAt.getTime() > now.getTime() + 365 * 86_400_000) {
      return Response.json({ error: "A 20–1,000 character reason and a future hold expiry within one year are required." }, { status: 400 });
    }
    const artifact = await getEnv().DB.prepare("SELECT id FROM evidence_artifacts WHERE id = ? AND status NOT IN ('expired', 'purged') AND expires_at > ?").bind(id, now.toISOString()).first();
    if (!artifact) return Response.json({ error: "Retainable evidence not found." }, { status: 404 });
    const expiry = expiresAt.toISOString();
    await executeAuditedBatch(actor, "retention.hold_set", "evidence", id, { ownerId: actor.id, reason, expiresAt: expiry }, [
      getEnv().DB.prepare(`INSERT INTO retention_holds (evidence_id, owner_id, reason, expires_at) VALUES (?, ?, ?, ?)
        ON CONFLICT(evidence_id) DO UPDATE SET owner_id = excluded.owner_id, reason = excluded.reason, expires_at = excluded.expires_at, updated_at = CURRENT_TIMESTAMP`).bind(id, actor.id, reason, expiry),
    ], { sql: "EXISTS (SELECT 1 FROM retention_holds WHERE evidence_id = ? AND owner_id = ? AND expires_at = ?)", bindings: [id, actor.id, expiry] });
    return Response.json({ held: true, ownerId: actor.id, reason, expiresAt: expiry });
  } catch (error) { return jsonError(error); }
}

export async function DELETE(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_retention");
    await enforceRateLimit(request, actor.id, "retention:release", 20, 3_600);
    const { id } = await context.params;
    const releasedAt = new Date().toISOString();
    const hold = await getEnv().DB.prepare("SELECT owner_id, reason, expires_at FROM retention_holds WHERE evidence_id = ? AND expires_at > ?").bind(id, releasedAt).first<{ owner_id: string; reason: string; expires_at: string }>();
    if (!hold) return Response.json({ error: "Active retention hold not found." }, { status: 404 });
    await executeAuditedBatch(actor, "retention.hold_released", "evidence", id, { previousOwnerId: hold.owner_id, reason: hold.reason, previousExpiresAt: hold.expires_at, releasedAt }, [
      getEnv().DB.prepare("UPDATE retention_holds SET expires_at = ?, updated_at = CURRENT_TIMESTAMP WHERE evidence_id = ? AND expires_at > ?").bind(releasedAt, id, releasedAt),
    ], { sql: "EXISTS (SELECT 1 FROM retention_holds WHERE evidence_id = ? AND expires_at = ?)", bindings: [id, releasedAt] });
    return Response.json({ held: false, releasedAt });
  } catch (error) { return jsonError(error); }
}
