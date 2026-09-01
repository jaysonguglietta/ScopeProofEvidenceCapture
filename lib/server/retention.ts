import type { AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { getEnv } from "./env";
import { classifyErrorForLogging } from "./safe-error";

export async function purgeExpiredEvidence(now: Date, actor: AuthenticatedUser): Promise<void> {
  const env = getEnv();
  const timestamp = now.toISOString();
  const evidence = (await env.DB.prepare(`SELECT e.id, e.r2_key, e.expires_at, e.rotation_pending_r2_key, e.rotation_previous_r2_key FROM evidence_artifacts e
    LEFT JOIN retention_holds h ON h.evidence_id = e.id AND h.expires_at > ?
    WHERE e.expires_at <= ? AND e.status != 'purged' AND h.evidence_id IS NULL
      AND (e.rotation_lease_id IS NULL OR e.rotation_lease_expires_at <= ?)
      AND NOT EXISTS (SELECT 1 FROM assessments a WHERE a.id = e.assessment_id AND a.status IN ('draft', 'active'))
    ORDER BY e.expires_at LIMIT 100`).bind(timestamp, timestamp, timestamp).all<{ id: string; r2_key: string; expires_at: string; rotation_pending_r2_key: string | null; rotation_previous_r2_key: string | null }>()).results;
  for (const item of evidence) {
    const [claim] = await executeAuditedBatch(actor, "retention.purge_started", "evidence", item.id, { expiredAt: item.expires_at }, [
      env.DB.prepare(`UPDATE evidence_artifacts SET status = 'expired' WHERE id = ? AND status NOT IN ('expired', 'purged')
        AND NOT EXISTS (SELECT 1 FROM retention_holds WHERE evidence_id = ? AND expires_at > ?)
        AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?)
        AND NOT EXISTS (SELECT 1 FROM assessments a WHERE a.id = evidence_artifacts.assessment_id AND a.status IN ('draft', 'active'))`).bind(item.id, item.id, timestamp, timestamp),
    ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND status = 'expired')", bindings: [item.id] });
    if (!claim.meta.changes && !(await env.DB.prepare("SELECT 1 FROM evidence_artifacts WHERE id = ? AND status = 'expired'").bind(item.id).first())) continue;
    try {
      for (const key of [...new Set([item.r2_key, item.rotation_pending_r2_key, item.rotation_previous_r2_key].filter((value): value is string => Boolean(value)))]) await env.EVIDENCE_BUCKET.delete(key);
    } catch (error) {
      const errorClass = classifyErrorForLogging(error);
      await executeAuditedBatch(actor, "evidence.purge_failed", "evidence", item.id, { expiredAt: item.expires_at, errorClass }, [
        env.DB.prepare("UPDATE evidence_artifacts SET purge_attempts = purge_attempts + 1, purge_error = ? WHERE id = ? AND status != 'purged'").bind(`Object deletion failed (${errorClass}).`, item.id),
      ]);
      continue;
    }
    await executeAuditedBatch(actor, "evidence.purged", "evidence", item.id, { expiredAt: item.expires_at, purgedAt: timestamp }, [
      env.DB.prepare("UPDATE evidence_artifacts SET status = 'purged', r2_key = '', rotation_pending_r2_key = NULL, rotation_previous_r2_key = NULL, rotation_lease_id = NULL, rotation_lease_expires_at = NULL, purged_at = ?, purge_attempts = purge_attempts + 1, purge_error = NULL WHERE id = ? AND status != 'purged'").bind(timestamp, item.id),
    ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND status = 'purged' AND purged_at = ?)", bindings: [item.id, timestamp] });
  }

  const packages = (await env.DB.prepare(`SELECT id, r2_key, rotation_pending_r2_key, rotation_previous_r2_key FROM export_packages
    WHERE status = 'ready' AND expires_at <= ? AND r2_key IS NOT NULL
      AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?) LIMIT 100`)
    .bind(timestamp, timestamp).all<{ id: string; r2_key: string; rotation_pending_r2_key: string | null; rotation_previous_r2_key: string | null }>()).results;
  for (const item of packages) {
    const purgeLease = `purge:${crypto.randomUUID()}`;
    const purgeLeaseExpiresAt = new Date(now.getTime() + 5 * 60_000).toISOString();
    const [claim] = await executeAuditedBatch(actor, "retention.package_purge_started", "export_package", item.id, { purgedAt: timestamp }, [
      env.DB.prepare(`UPDATE export_packages SET rotation_lease_id = ?, rotation_lease_expires_at = ?
        WHERE id = ? AND status = 'ready' AND expires_at <= ?
          AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?)`)
        .bind(purgeLease, purgeLeaseExpiresAt, item.id, timestamp, timestamp),
    ], { sql: "EXISTS (SELECT 1 FROM export_packages WHERE id = ? AND rotation_lease_id = ?)", bindings: [item.id, purgeLease] });
    if (!claim.meta.changes) continue;
    try { for (const key of [...new Set([item.r2_key, item.rotation_pending_r2_key, item.rotation_previous_r2_key].filter((value): value is string => Boolean(value)))]) await env.EVIDENCE_BUCKET.delete(key); }
    catch (error) {
      const errorClass = classifyErrorForLogging(error);
      await executeAuditedBatch(actor, "package.purge_failed", "export_package", item.id, { errorClass }, [
        env.DB.prepare("UPDATE export_packages SET error_message = ?, rotation_lease_id = NULL, rotation_lease_expires_at = NULL WHERE id = ? AND status = 'ready' AND rotation_lease_id = ?").bind(`Object deletion failed (${errorClass}).`, item.id, purgeLease),
      ]);
      continue;
    }
    await executeAuditedBatch(actor, "package.purged", "export_package", item.id, { purgedAt: timestamp }, [
      env.DB.prepare("UPDATE export_packages SET status = 'failed', r2_key = NULL, rotation_pending_r2_key = NULL, rotation_previous_r2_key = NULL, rotation_lease_id = NULL, rotation_lease_expires_at = NULL, error_message = 'Expired and purged by retention policy.' WHERE id = ? AND status = 'ready' AND rotation_lease_id = ?").bind(item.id, purgeLease),
    ], { sql: "EXISTS (SELECT 1 FROM export_packages WHERE id = ? AND r2_key IS NULL)", bindings: [item.id] });
  }
}
