import { jsonError, requireApiPermission, requireSameOrigin } from "../../../../../lib/server/auth";
import { executeAuditedBatch } from "../../../../../lib/server/audit";
import { getEnv } from "../../../../../lib/server/env";
import { enforceRateLimit, requireBoundedContentLength } from "../../../../../lib/server/rate-limit";
import { randomId, sha256, stableJson } from "../../../../../lib/server/crypto";

export async function PUT(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_retention");
    await enforceRateLimit(request, actor.id, "retention:hold", 20, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const { id } = await context.params;
    const body = await request.json() as { reason?: unknown; expiresAt?: unknown };
    if (Object.keys(body).some((key) => !["reason", "expiresAt"].includes(key))) return Response.json({ error: "Retention request contains unsupported fields." }, { status: 400 });
    const reason = String(body.reason || "").trim();
    const expiresAt = new Date(String(body.expiresAt || ""));
    const now = new Date();
    if (reason.length < 20 || reason.length > 1_000 || !Number.isFinite(expiresAt.getTime()) || expiresAt <= now || expiresAt.getTime() > now.getTime() + 365 * 86_400_000) {
      return Response.json({ error: "A 20–1,000 character reason and a future hold expiry within one year are required." }, { status: 400 });
    }
    const nowISO = now.toISOString();
    const expiry = expiresAt.toISOString();
    const [, result] = await executeAuditedBatch(actor, "retention.hold_set", "evidence", id, { ownerId: actor.id, reason, expiresAt: expiry }, [
      getEnv().DB.prepare(`UPDATE retention_hold_release_requests SET status = 'cancelled'
        WHERE evidence_id = ? AND status = 'pending'
          AND (hold_owner_id != ? OR hold_reason != ? OR hold_expires_at != ?)`)
        .bind(id, actor.id, reason, expiry),
      getEnv().DB.prepare(`INSERT INTO retention_holds (evidence_id, owner_id, reason, expires_at)
        SELECT ?, ?, ?, ? WHERE EXISTS (
          SELECT 1 FROM evidence_artifacts WHERE id = ? AND status NOT IN ('expired', 'purged') AND expires_at > ?
        )
        ON CONFLICT(evidence_id) DO UPDATE SET owner_id = excluded.owner_id, reason = excluded.reason, expires_at = excluded.expires_at, updated_at = CURRENT_TIMESTAMP
        WHERE EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = excluded.evidence_id AND status NOT IN ('expired', 'purged') AND expires_at > ?)`).bind(id, actor.id, reason, expiry, id, nowISO, nowISO),
    ], { sql: "EXISTS (SELECT 1 FROM retention_holds WHERE evidence_id = ? AND owner_id = ? AND reason = ? AND expires_at = ?)", bindings: [id, actor.id, reason, expiry] });
    if (!result.meta.changes) return Response.json({ error: "The evidence became non-retainable before the hold was committed." }, { status: 409 });
    return Response.json({ held: true, ownerId: actor.id, reason, expiresAt: expiry });
  } catch (error) { return jsonError(error); }
}

export async function DELETE(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_retention");
    await enforceRateLimit(request, actor.id, "retention:release", 20, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const { id } = await context.params;
    const body = await request.json().catch(() => ({})) as { reason?: unknown; requestId?: unknown; requestDigest?: unknown };
    if (Object.keys(body).some((key) => !["reason", "requestId", "requestDigest"].includes(key))) return Response.json({ error: "Hold-release request contains unsupported fields." }, { status: 400 });
    const now = new Date();
    const nowISO = now.toISOString();
    const requestId = String(body.requestId || "");
    if (!requestId) {
      const hold = await getEnv().DB.prepare("SELECT owner_id, reason, expires_at FROM retention_holds WHERE evidence_id = ? AND expires_at > ?").bind(id, nowISO).first<{ owner_id: string; reason: string; expires_at: string }>();
      if (!hold) return Response.json({ error: "Active retention hold not found." }, { status: 404 });
      const reason = String(body.reason || "").trim();
      if (reason.length < 20 || reason.length > 1_000) return Response.json({ error: "Requesting hold release requires a 20–1,000 character reason." }, { status: 400 });
      const releaseRequestId = randomId("hrr");
      const expiresAt = new Date(now.getTime() + 24 * 60 * 60_000).toISOString();
      const holdFacts = { holdOwnerId: hold.owner_id, holdReason: hold.reason, holdExpiresAt: hold.expires_at };
      const requestDigest = await sha256(stableJson({ schemaVersion: 2, releaseRequestId, evidenceId: id, requestedBy: actor.id, reason, ...holdFacts, requestedAt: nowISO, expiresAt }));
      const [, created] = await executeAuditedBatch(actor, "retention.hold_release_requested", "evidence", id, { releaseRequestId, requestDigest, reason, ...holdFacts, expiresAt }, [
        getEnv().DB.prepare("UPDATE retention_hold_release_requests SET status = 'expired' WHERE evidence_id = ? AND status = 'pending' AND expires_at <= ?")
          .bind(id, nowISO),
        getEnv().DB.prepare(`INSERT INTO retention_hold_release_requests
          (id, evidence_id, requested_by, reason, request_digest, hold_owner_id, hold_reason, hold_expires_at, status, requested_at, expires_at)
          SELECT ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ? WHERE EXISTS (
            SELECT 1 FROM retention_holds WHERE evidence_id = ? AND owner_id = ? AND reason = ? AND expires_at = ?
          )
          AND NOT EXISTS (SELECT 1 FROM retention_hold_release_requests WHERE evidence_id = ? AND status = 'pending' AND expires_at > ?)`)
          .bind(releaseRequestId, id, actor.id, reason, requestDigest, hold.owner_id, hold.reason, hold.expires_at, nowISO, expiresAt, id, hold.owner_id, hold.reason, hold.expires_at, id, nowISO),
      ], { sql: "EXISTS (SELECT 1 FROM retention_hold_release_requests WHERE id = ? AND status = 'pending' AND request_digest = ?)", bindings: [releaseRequestId, requestDigest] });
      if (!created.meta.changes) return Response.json({ error: "A pending release request already exists or the hold changed concurrently." }, { status: 409 });
      return Response.json({ held: true, release: { id: releaseRequestId, status: "pending", requestedBy: actor.id, requestDigest, expiresAt, requiresDifferentAdministrator: true } }, { status: 202 });
    }
    if (!/^hrr_[a-f0-9]{32}$/u.test(requestId)) return Response.json({ error: "Release request identifier is invalid." }, { status: 400 });
    const requestDigest = String(body.requestDigest || "").trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/u.test(requestDigest)) return Response.json({ error: "The exact release-request digest is required for approval." }, { status: 400 });
    const pending = await getEnv().DB.prepare(`SELECT requested_by, reason, request_digest, requested_at, expires_at, hold_owner_id, hold_reason, hold_expires_at
      FROM retention_hold_release_requests WHERE id = ? AND evidence_id = ? AND status = 'pending' AND expires_at > ?`)
      .bind(requestId, id, nowISO).first<{ requested_by: string; reason: string; request_digest: string; requested_at: string; expires_at: string; hold_owner_id: string; hold_reason: string; hold_expires_at: string }>();
    if (!pending) return Response.json({ error: "Pending hold-release request not found or expired." }, { status: 404 });
    if (pending.requested_by === actor.id) return Response.json({ error: "The administrator who requested hold release cannot approve it." }, { status: 403 });
    if (pending.request_digest !== requestDigest) return Response.json({ error: "The hold-release request changed. Reload and verify its digest." }, { status: 409 });
    const expectedRequestDigest = await sha256(stableJson({
      schemaVersion: 2, releaseRequestId: requestId, evidenceId: id, requestedBy: pending.requested_by, reason: pending.reason,
      holdOwnerId: pending.hold_owner_id, holdReason: pending.hold_reason, holdExpiresAt: pending.hold_expires_at,
      requestedAt: pending.requested_at, expiresAt: pending.expires_at,
    }));
    if (expectedRequestDigest !== requestDigest) return Response.json({ error: "The persisted hold-release request failed its immutable digest check." }, { status: 409 });
    const releasedAt = new Date().toISOString();
    const [result] = await executeAuditedBatch(actor, "retention.hold_released", "evidence", id, {
      requestId, requestDigest, requestedBy: pending.requested_by, approvedBy: actor.id,
      previousOwnerId: pending.hold_owner_id, reason: pending.reason, previousHoldReason: pending.hold_reason,
      previousExpiresAt: pending.hold_expires_at, releasedAt,
    }, [
      getEnv().DB.prepare(`UPDATE retention_hold_release_requests SET status = 'approved', approved_by = ?, approved_at = ?, released_at = ?
        WHERE id = ? AND evidence_id = ? AND status = 'pending' AND requested_by != ? AND request_digest = ? AND expires_at > ?
          AND EXISTS (
            SELECT 1 FROM retention_holds h
            WHERE h.evidence_id = retention_hold_release_requests.evidence_id
              AND h.owner_id = retention_hold_release_requests.hold_owner_id
              AND h.reason = retention_hold_release_requests.hold_reason
              AND h.expires_at = retention_hold_release_requests.hold_expires_at
              AND h.expires_at > ?
          )`)
        .bind(actor.id, releasedAt, releasedAt, requestId, id, actor.id, requestDigest, releasedAt, releasedAt),
      getEnv().DB.prepare(`UPDATE retention_holds SET expires_at = ?, updated_at = CURRENT_TIMESTAMP
        WHERE evidence_id = ? AND owner_id = ? AND reason = ? AND expires_at = ?
          AND EXISTS (
            SELECT 1 FROM retention_hold_release_requests
            WHERE id = ? AND evidence_id = ? AND status = 'approved' AND approved_by = ?
              AND request_digest = ? AND hold_owner_id = ? AND hold_reason = ? AND hold_expires_at = ?
          )`)
        .bind(releasedAt, id, pending.hold_owner_id, pending.hold_reason, pending.hold_expires_at,
          requestId, id, actor.id, requestDigest, pending.hold_owner_id, pending.hold_reason, pending.hold_expires_at),
    ], {
      sql: `EXISTS (
          SELECT 1 FROM retention_hold_release_requests
          WHERE id = ? AND evidence_id = ? AND status = 'approved' AND approved_by = ? AND released_at = ?
            AND request_digest = ? AND hold_owner_id = ? AND hold_reason = ? AND hold_expires_at = ?
        ) AND EXISTS (
          SELECT 1 FROM retention_holds WHERE evidence_id = ? AND owner_id = ? AND reason = ? AND expires_at = ?
        )`,
      bindings: [requestId, id, actor.id, releasedAt, requestDigest, pending.hold_owner_id, pending.hold_reason, pending.hold_expires_at,
        id, pending.hold_owner_id, pending.hold_reason, releasedAt],
    });
    if (!result.meta.changes) return Response.json({ error: "The retention hold or release request changed concurrently." }, { status: 409 });
    return Response.json({ held: false, releasedAt, approvedBy: actor.id, requestedBy: pending.requested_by, requestId, requestDigest });
  } catch (error) { return jsonError(error); }
}
