import type { AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { getEnv } from "./env";

export async function purgeExpiredEvidence(now: Date, actor: AuthenticatedUser): Promise<void> {
  const env = getEnv();
  const timestamp = now.toISOString();
  const evidence = (await env.DB.prepare(`SELECT e.id, e.r2_key, e.expires_at FROM evidence_artifacts e
    LEFT JOIN retention_holds h ON h.evidence_id = e.id AND h.expires_at > ?
    WHERE e.expires_at <= ? AND e.status != 'purged' AND h.evidence_id IS NULL
    ORDER BY e.expires_at LIMIT 100`).bind(timestamp, timestamp).all<{ id: string; r2_key: string; expires_at: string }>()).results;
  for (const item of evidence) {
    const [claim] = await executeAuditedBatch(actor, "retention.purge_started", "evidence", item.id, { expiredAt: item.expires_at }, [
      env.DB.prepare(`UPDATE evidence_artifacts SET status = 'expired' WHERE id = ? AND status NOT IN ('expired', 'purged')
        AND NOT EXISTS (SELECT 1 FROM retention_holds WHERE evidence_id = ? AND expires_at > ?)`).bind(item.id, item.id, timestamp),
    ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND status = 'expired')", bindings: [item.id] });
    if (!claim.meta.changes && !(await env.DB.prepare("SELECT 1 FROM evidence_artifacts WHERE id = ? AND status = 'expired'").bind(item.id).first())) continue;
    try {
      await env.EVIDENCE_BUCKET.delete(item.r2_key);
    } catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 500) : "Object deletion failed";
      await executeAuditedBatch(actor, "evidence.purge_failed", "evidence", item.id, { expiredAt: item.expires_at, error: message }, [
        env.DB.prepare("UPDATE evidence_artifacts SET purge_attempts = purge_attempts + 1, purge_error = ? WHERE id = ? AND status != 'purged'").bind(message, item.id),
      ]);
      continue;
    }
    await executeAuditedBatch(actor, "evidence.purged", "evidence", item.id, { expiredAt: item.expires_at, purgedAt: timestamp }, [
      env.DB.prepare("UPDATE evidence_artifacts SET status = 'purged', r2_key = '', purged_at = ?, purge_attempts = purge_attempts + 1, purge_error = NULL WHERE id = ? AND status != 'purged'").bind(timestamp, item.id),
    ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND status = 'purged' AND purged_at = ?)", bindings: [item.id, timestamp] });
  }

  const packages = (await env.DB.prepare("SELECT id, r2_key FROM export_packages WHERE status = 'ready' AND expires_at <= ? AND r2_key IS NOT NULL LIMIT 100").bind(timestamp).all<{ id: string; r2_key: string }>()).results;
  for (const item of packages) {
    try { await env.EVIDENCE_BUCKET.delete(item.r2_key); }
    catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 500) : "Object deletion failed";
      await executeAuditedBatch(actor, "package.purge_failed", "export_package", item.id, { error: message }, [
        env.DB.prepare("UPDATE export_packages SET error_message = ? WHERE id = ? AND status = 'ready'").bind(`Purge failed: ${message}`, item.id),
      ]);
      continue;
    }
    await executeAuditedBatch(actor, "package.purged", "export_package", item.id, { purgedAt: timestamp }, [
      env.DB.prepare("UPDATE export_packages SET status = 'failed', r2_key = NULL, error_message = 'Expired and purged by retention policy.' WHERE id = ? AND status = 'ready'").bind(item.id),
    ], { sql: "EXISTS (SELECT 1 FROM export_packages WHERE id = ? AND r2_key IS NULL)", bindings: [item.id] });
  }
}
