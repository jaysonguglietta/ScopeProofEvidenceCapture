import type { AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { activeEvidenceKeyId, availableAuditKeyIds, availableEvidenceKeyIds, decryptEvidence, decryptSecret, encryptEvidence, encryptSecret, rotatingSecretKeyring, stableJson } from "./crypto";
import { getEnv } from "./env";

type EvidenceKeyRow = { id: string; control_id: string; source: string; captured_at: string; r2_key: string; encryption_iv: string; encryption_key_id: string; sha256: string; expires_at: string };
type PackageKeyRow = { id: string; r2_key: string; encryption_key_id: string; sha256: string; expires_at: string };
type JiraKeyRow = { id: string; user_id: string; access_token_ciphertext: string; access_token_iv: string; refresh_token_ciphertext: string; refresh_token_iv: string; token_key_id: string; token_version: number };
const ROTATION_LEASE_MS = 5 * 60_000;

function jiraAad(id: string, userId: string, kind: "access" | "refresh"): string {
  return stableJson({ purpose: "jira-oauth-token", version: 1, connectionId: id, userId, kind });
}

async function rotateEvidenceObject(row: EvidenceKeyRow, actor: AuthenticatedUser): Promise<boolean> {
  const env = getEnv();
  const now = new Date();
  const nowISO = now.toISOString();
  const leaseId = crypto.randomUUID();
  const leaseExpiresAt = new Date(now.getTime() + ROTATION_LEASE_MS).toISOString();
  const nextKey = `${row.r2_key}.rekey-${crypto.randomUUID()}`;
  const claim = await env.DB.prepare(`UPDATE evidence_artifacts SET rotation_lease_id = ?, rotation_lease_expires_at = ?, rotation_pending_r2_key = ?
    WHERE id = ? AND r2_key = ? AND encryption_key_id = ? AND status NOT IN ('expired', 'purged') AND expires_at > ?
      AND rotation_pending_r2_key IS NULL AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?)`)
    .bind(leaseId, leaseExpiresAt, nextKey, row.id, row.r2_key, row.encryption_key_id, nowISO, nowISO).run();
  if (!claim.meta.changes) return false;
  const releaseClaim = async () => {
    await env.DB.prepare("UPDATE evidence_artifacts SET rotation_lease_id = NULL, rotation_lease_expires_at = NULL, rotation_pending_r2_key = NULL WHERE id = ? AND rotation_lease_id = ? AND rotation_pending_r2_key = ?")
      .bind(row.id, leaseId, nextKey).run();
  };
  const object = await env.EVIDENCE_BUCKET.get(row.r2_key);
  if (!object) { await releaseClaim(); throw new Error(`Encrypted evidence object ${row.id} is missing during key rotation.`); }
  const aad = stableJson({ id: row.id, controlId: row.control_id, source: row.source, capturedAt: row.captured_at });
  let encrypted: Awaited<ReturnType<typeof encryptEvidence>>;
  try {
    const plain = await decryptEvidence(new Uint8Array(await object.arrayBuffer()), row.encryption_iv, aad, row.encryption_key_id);
    encrypted = await encryptEvidence(plain, aad);
    await env.EVIDENCE_BUCKET.put(nextKey, encrypted.ciphertext, {
      httpMetadata: object.httpMetadata,
      customMetadata: { ...(object.customMetadata || {}), evidenceId: row.id, sha256: row.sha256, encryptionVersion: "2", encryptionKeyId: encrypted.keyId },
    });
  } catch (error) {
    await env.EVIDENCE_BUCKET.delete(nextKey).catch(() => undefined);
    await releaseClaim();
    throw error;
  }
  try {
    const [updated] = await executeAuditedBatch(actor, "key.evidence_rotated", "evidence", row.id, { previousKeyId: row.encryption_key_id, activeKeyId: encrypted.keyId }, [
      env.DB.prepare(`UPDATE evidence_artifacts SET r2_key = ?, encryption_iv = ?, encryption_version = 2, encryption_key_id = ?,
        rotation_previous_r2_key = ?, rotation_pending_r2_key = NULL, rotation_lease_id = NULL, rotation_lease_expires_at = NULL
        WHERE id = ? AND r2_key = ? AND encryption_key_id = ? AND rotation_lease_id = ? AND rotation_pending_r2_key = ?
          AND status NOT IN ('expired', 'purged') AND expires_at > ?`)
        .bind(nextKey, encrypted.iv, encrypted.keyId, row.r2_key, row.id, row.r2_key, row.encryption_key_id, leaseId, nextKey, new Date().toISOString()),
    ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND r2_key = ? AND encryption_key_id = ?)", bindings: [row.id, nextKey, encrypted.keyId] });
    if (!updated.meta.changes) { await env.EVIDENCE_BUCKET.delete(nextKey); await releaseClaim(); return false; }
  } catch (error) {
    await env.EVIDENCE_BUCKET.delete(nextKey);
    await releaseClaim();
    throw error;
  }
  try {
    await env.EVIDENCE_BUCKET.delete(row.r2_key);
    await executeAuditedBatch(actor, "key.evidence_previous_object_deleted", "evidence", row.id, { previousKeyId: row.encryption_key_id }, [
      env.DB.prepare("UPDATE evidence_artifacts SET rotation_previous_r2_key = NULL WHERE id = ? AND r2_key = ? AND rotation_previous_r2_key = ?")
        .bind(row.id, nextKey, row.r2_key),
    ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND r2_key = ? AND rotation_previous_r2_key IS NULL)", bindings: [row.id, nextKey] });
  } catch (error) { console.error("scopeproof_rekey_old_object_delete_failure", { type: "evidence", id: row.id, error: String(error) }); }
  return true;
}

async function rotatePackageObject(row: PackageKeyRow, actor: AuthenticatedUser): Promise<boolean> {
  const env = getEnv();
  const now = new Date();
  const nowISO = now.toISOString();
  const leaseId = crypto.randomUUID();
  const leaseExpiresAt = new Date(now.getTime() + ROTATION_LEASE_MS).toISOString();
  const nextKey = `${row.r2_key}.rekey-${crypto.randomUUID()}`;
  const claim = await env.DB.prepare(`UPDATE export_packages SET rotation_lease_id = ?, rotation_lease_expires_at = ?, rotation_pending_r2_key = ?
    WHERE id = ? AND r2_key = ? AND encryption_key_id = ? AND status = 'ready' AND expires_at > ?
      AND rotation_pending_r2_key IS NULL AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?)`)
    .bind(leaseId, leaseExpiresAt, nextKey, row.id, row.r2_key, row.encryption_key_id, nowISO, nowISO).run();
  if (!claim.meta.changes) return false;
  const releaseClaim = async () => {
    await env.DB.prepare("UPDATE export_packages SET rotation_lease_id = NULL, rotation_lease_expires_at = NULL, rotation_pending_r2_key = NULL WHERE id = ? AND rotation_lease_id = ? AND rotation_pending_r2_key = ?")
      .bind(row.id, leaseId, nextKey).run();
  };
  const object = await env.EVIDENCE_BUCKET.get(row.r2_key);
  if (!object) { await releaseClaim(); throw new Error(`Encrypted package object ${row.id} is missing during key rotation.`); }
  const aad = stableJson({ id: row.id, type: "assessor_package" });
  const iv = object.customMetadata?.encryptionIv;
  if (!iv) { await releaseClaim(); throw new Error(`Encrypted package ${row.id} is missing its IV.`); }
  let encrypted: Awaited<ReturnType<typeof encryptEvidence>>;
  try {
    const plain = await decryptEvidence(new Uint8Array(await object.arrayBuffer()), iv, aad, row.encryption_key_id);
    encrypted = await encryptEvidence(plain, aad);
    await env.EVIDENCE_BUCKET.put(nextKey, encrypted.ciphertext, {
      httpMetadata: object.httpMetadata,
      customMetadata: { ...(object.customMetadata || {}), packageId: row.id, sha256: row.sha256, encryptionIv: encrypted.iv, encryptionVersion: "2", encryptionKeyId: encrypted.keyId },
    });
  } catch (error) {
    await env.EVIDENCE_BUCKET.delete(nextKey).catch(() => undefined);
    await releaseClaim();
    throw error;
  }
  try {
    const [updated] = await executeAuditedBatch(actor, "key.package_rotated", "export_package", row.id, { previousKeyId: row.encryption_key_id, activeKeyId: encrypted.keyId }, [
      env.DB.prepare(`UPDATE export_packages SET r2_key = ?, encryption_key_id = ?, rotation_previous_r2_key = ?,
        rotation_pending_r2_key = NULL, rotation_lease_id = NULL, rotation_lease_expires_at = NULL
        WHERE id = ? AND r2_key = ? AND encryption_key_id = ? AND rotation_lease_id = ? AND rotation_pending_r2_key = ? AND status = 'ready' AND expires_at > ?`)
        .bind(nextKey, encrypted.keyId, row.r2_key, row.id, row.r2_key, row.encryption_key_id, leaseId, nextKey, new Date().toISOString()),
    ], { sql: "EXISTS (SELECT 1 FROM export_packages WHERE id = ? AND r2_key = ? AND encryption_key_id = ?)", bindings: [row.id, nextKey, encrypted.keyId] });
    if (!updated.meta.changes) { await env.EVIDENCE_BUCKET.delete(nextKey); await releaseClaim(); return false; }
  } catch (error) {
    await env.EVIDENCE_BUCKET.delete(nextKey);
    await releaseClaim();
    throw error;
  }
  try {
    await env.EVIDENCE_BUCKET.delete(row.r2_key);
    await executeAuditedBatch(actor, "key.package_previous_object_deleted", "export_package", row.id, { previousKeyId: row.encryption_key_id }, [
      env.DB.prepare("UPDATE export_packages SET rotation_previous_r2_key = NULL WHERE id = ? AND r2_key = ? AND rotation_previous_r2_key = ?")
        .bind(row.id, nextKey, row.r2_key),
    ], { sql: "EXISTS (SELECT 1 FROM export_packages WHERE id = ? AND r2_key = ? AND rotation_previous_r2_key IS NULL)", bindings: [row.id, nextKey] });
  } catch (error) { console.error("scopeproof_rekey_old_object_delete_failure", { type: "package", id: row.id, error: String(error) }); }
  return true;
}

async function rotateJiraToken(row: JiraKeyRow, actor: AuthenticatedUser): Promise<boolean> {
  const env = getEnv();
  const ring = rotatingSecretKeyring(env.JIRA_OAUTH_KEYRING_JSON, env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY, env.JIRA_OAUTH_ACTIVE_KEY_ID, "Jira OAuth token");
  const oldKey = ring.values[row.token_key_id];
  if (!oldKey) throw new Error(`Jira OAuth token key ${row.token_key_id} is unavailable during rotation.`);
  const activeKey = ring.values[ring.activeId];
  const access = await decryptSecret(row.access_token_ciphertext, row.access_token_iv, oldKey, "JIRA_OAUTH_TOKEN_ENCRYPTION_KEY", jiraAad(row.id, row.user_id, "access"));
  const refresh = await decryptSecret(row.refresh_token_ciphertext, row.refresh_token_iv, oldKey, "JIRA_OAUTH_TOKEN_ENCRYPTION_KEY", jiraAad(row.id, row.user_id, "refresh"));
  const nextAccess = await encryptSecret(access, activeKey, "JIRA_OAUTH_TOKEN_ENCRYPTION_KEY", jiraAad(row.id, row.user_id, "access"));
  const nextRefresh = await encryptSecret(refresh, activeKey, "JIRA_OAUTH_TOKEN_ENCRYPTION_KEY", jiraAad(row.id, row.user_id, "refresh"));
  const [updated] = await executeAuditedBatch(actor, "key.jira_tokens_rotated", "jira_connection", row.id, { previousKeyId: row.token_key_id, activeKeyId: ring.activeId }, [
    env.DB.prepare(`UPDATE jira_connections SET access_token_ciphertext = ?, access_token_iv = ?, refresh_token_ciphertext = ?, refresh_token_iv = ?, token_key_id = ?, token_version = token_version + 1, updated_at = CURRENT_TIMESTAMP
      WHERE id = ? AND token_version = ? AND token_key_id = ? AND refresh_lease_id IS NULL`).bind(nextAccess.ciphertext, nextAccess.iv, nextRefresh.ciphertext, nextRefresh.iv, ring.activeId, row.id, row.token_version, row.token_key_id),
  ], { sql: "EXISTS (SELECT 1 FROM jira_connections WHERE id = ? AND token_key_id = ? AND token_version = ?)", bindings: [row.id, ring.activeId, row.token_version + 1] });
  return Boolean(updated.meta.changes);
}

async function reconcileRotationGarbage(actor: AuthenticatedUser, limit: number): Promise<void> {
  const env = getEnv();
  const now = new Date().toISOString();
  const evidence = (await env.DB.prepare(`SELECT id, r2_key, rotation_pending_r2_key, rotation_previous_r2_key FROM evidence_artifacts
    WHERE (rotation_pending_r2_key IS NOT NULL OR rotation_previous_r2_key IS NOT NULL)
      AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?) ORDER BY created_at LIMIT ?`)
    .bind(now, limit).all<{ id: string; r2_key: string; rotation_pending_r2_key: string | null; rotation_previous_r2_key: string | null }>()).results;
  for (const row of evidence) {
    const garbage = [...new Set([row.rotation_pending_r2_key, row.rotation_previous_r2_key].filter((key): key is string => Boolean(key) && key !== row.r2_key))];
    try {
      for (const key of garbage) await env.EVIDENCE_BUCKET.delete(key);
      await executeAuditedBatch(actor, "key.evidence_rotation_reconciled", "evidence", row.id, { deletedObjectCount: garbage.length }, [
        env.DB.prepare(`UPDATE evidence_artifacts SET rotation_pending_r2_key = NULL, rotation_previous_r2_key = NULL,
          rotation_lease_id = NULL, rotation_lease_expires_at = NULL
          WHERE id = ? AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?)`)
          .bind(row.id, now),
      ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND rotation_pending_r2_key IS NULL AND rotation_previous_r2_key IS NULL)", bindings: [row.id] });
    } catch (error) { console.error("scopeproof_rekey_reconciliation_failure", { type: "evidence", id: row.id, error: String(error) }); }
  }
  const packages = (await env.DB.prepare(`SELECT id, r2_key, rotation_pending_r2_key, rotation_previous_r2_key FROM export_packages
    WHERE (rotation_pending_r2_key IS NOT NULL OR rotation_previous_r2_key IS NOT NULL)
      AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?) ORDER BY created_at LIMIT ?`)
    .bind(now, limit).all<{ id: string; r2_key: string; rotation_pending_r2_key: string | null; rotation_previous_r2_key: string | null }>()).results;
  for (const row of packages) {
    const garbage = [...new Set([row.rotation_pending_r2_key, row.rotation_previous_r2_key].filter((key): key is string => Boolean(key) && key !== row.r2_key))];
    try {
      for (const key of garbage) await env.EVIDENCE_BUCKET.delete(key);
      await executeAuditedBatch(actor, "key.package_rotation_reconciled", "export_package", row.id, { deletedObjectCount: garbage.length }, [
        env.DB.prepare(`UPDATE export_packages SET rotation_pending_r2_key = NULL, rotation_previous_r2_key = NULL,
          rotation_lease_id = NULL, rotation_lease_expires_at = NULL
          WHERE id = ? AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?)`)
          .bind(row.id, now),
      ], { sql: "EXISTS (SELECT 1 FROM export_packages WHERE id = ? AND rotation_pending_r2_key IS NULL AND rotation_previous_r2_key IS NULL)", bindings: [row.id] });
    } catch (error) { console.error("scopeproof_rekey_reconciliation_failure", { type: "package", id: row.id, error: String(error) }); }
  }
}

export async function rotateStoredKeys(actor: AuthenticatedUser, limit = 10): Promise<{ evidence: number; packages: number; jiraConnections: number; remaining: number }> {
  const env = getEnv();
  const boundedLimit = Math.min(Math.max(Math.floor(limit), 1), 25);
  await reconcileRotationGarbage(actor, boundedLimit);
  const activeEvidence = activeEvidenceKeyId();
  const now = new Date().toISOString();
  const evidence = (await env.DB.prepare(`SELECT id, control_id, source, captured_at, r2_key, encryption_iv, encryption_key_id, sha256, expires_at FROM evidence_artifacts
    WHERE status NOT IN ('expired', 'purged') AND expires_at > ? AND encryption_key_id != ?
      AND rotation_pending_r2_key IS NULL AND rotation_previous_r2_key IS NULL
      AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?) ORDER BY created_at LIMIT ?`)
    .bind(now, activeEvidence, now, boundedLimit).all<EvidenceKeyRow>()).results;
  let evidenceRotated = 0;
  for (const row of evidence) if (await rotateEvidenceObject(row, actor)) evidenceRotated += 1;
  let budget = boundedLimit - evidence.length;
  const packages = budget > 0 ? (await env.DB.prepare(`SELECT id, r2_key, encryption_key_id, sha256, expires_at FROM export_packages
    WHERE status = 'ready' AND expires_at > ? AND r2_key IS NOT NULL AND encryption_key_id != ?
      AND rotation_pending_r2_key IS NULL AND rotation_previous_r2_key IS NULL
      AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?) ORDER BY created_at LIMIT ?`)
    .bind(now, activeEvidence, now, budget).all<PackageKeyRow>()).results : [];
  let packagesRotated = 0;
  for (const row of packages) if (await rotatePackageObject(row, actor)) packagesRotated += 1;
  budget -= packages.length;
  const jiraRingConfigured = Boolean(env.JIRA_OAUTH_KEYRING_JSON || env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY);
  const jiraRing = jiraRingConfigured ? rotatingSecretKeyring(env.JIRA_OAUTH_KEYRING_JSON, env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY, env.JIRA_OAUTH_ACTIVE_KEY_ID, "Jira OAuth token") : null;
  const jiraRows = budget > 0 && jiraRing ? (await env.DB.prepare("SELECT id, user_id, access_token_ciphertext, access_token_iv, refresh_token_ciphertext, refresh_token_iv, token_key_id, token_version FROM jira_connections WHERE token_key_id != ? AND refresh_lease_id IS NULL ORDER BY updated_at LIMIT ?").bind(jiraRing.activeId, budget).all<JiraKeyRow>()).results : [];
  let jiraConnections = 0;
  for (const row of jiraRows) if (await rotateJiraToken(row, actor)) jiraConnections += 1;
  const remaining = await keyRotationBacklog();
  return { evidence: evidenceRotated, packages: packagesRotated, jiraConnections, remaining };
}

export async function keyRotationBacklog(): Promise<number> {
  const env = getEnv();
  const activeEvidence = activeEvidenceKeyId();
  const jiraRing = (env.JIRA_OAUTH_KEYRING_JSON || env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY)
    ? rotatingSecretKeyring(env.JIRA_OAUTH_KEYRING_JSON, env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY, env.JIRA_OAUTH_ACTIVE_KEY_ID, "Jira OAuth token") : null;
  const row = await env.DB.prepare(`SELECT
      (SELECT COUNT(*) FROM evidence_artifacts WHERE status != 'purged' AND encryption_key_id != ?) +
      (SELECT COUNT(*) FROM export_packages WHERE status = 'ready' AND r2_key IS NOT NULL AND encryption_key_id != ?) +
      (SELECT COUNT(*) FROM jira_connections WHERE token_key_id != ?) +
      (SELECT COUNT(*) FROM evidence_artifacts WHERE rotation_pending_r2_key IS NOT NULL OR rotation_previous_r2_key IS NOT NULL) +
      (SELECT COUNT(*) FROM export_packages WHERE rotation_pending_r2_key IS NOT NULL OR rotation_previous_r2_key IS NOT NULL) AS count`).bind(activeEvidence, activeEvidence, jiraRing?.activeId || "legacy-v1").first<{ count: number }>();
  return Number(row?.count || 0);
}

export async function validateRetainedKeyReferences(): Promise<{ valid: boolean; missing: Array<{ purpose: string; keyId: string; references: number }> }> {
  const env = getEnv();
  const evidenceIds = new Set(availableEvidenceKeyIds());
  const auditIds = new Set(availableAuditKeyIds());
  const jiraRing = (env.JIRA_OAUTH_KEYRING_JSON || env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY)
    ? rotatingSecretKeyring(env.JIRA_OAUTH_KEYRING_JSON, env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY, env.JIRA_OAUTH_ACTIVE_KEY_ID, "Jira OAuth token") : null;
  const missing: Array<{ purpose: string; keyId: string; references: number }> = [];
  const checks: Array<{ purpose: string; sql: string; retained: Set<string> }> = [
    { purpose: "evidence", sql: "SELECT encryption_key_id AS key_id, COUNT(*) AS count FROM evidence_artifacts WHERE status != 'purged' GROUP BY encryption_key_id", retained: evidenceIds },
    { purpose: "export_package", sql: "SELECT encryption_key_id AS key_id, COUNT(*) AS count FROM export_packages WHERE status = 'ready' GROUP BY encryption_key_id", retained: evidenceIds },
    { purpose: "audit_event", sql: "SELECT hmac_key_id AS key_id, COUNT(*) AS count FROM audit_events GROUP BY hmac_key_id", retained: auditIds },
    { purpose: "jira_receipt", sql: "SELECT hmac_key_id AS key_id, COUNT(*) AS count FROM jira_upload_receipts GROUP BY hmac_key_id", retained: auditIds },
  ];
  if (jiraRing) checks.push({ purpose: "jira_connection", sql: "SELECT token_key_id AS key_id, COUNT(*) AS count FROM jira_connections GROUP BY token_key_id", retained: new Set(Object.keys(jiraRing.values)) });
  for (const check of checks) {
    const rows = (await env.DB.prepare(check.sql).all<{ key_id: string; count: number }>()).results;
    for (const row of rows) if (!check.retained.has(row.key_id || "legacy-v1")) missing.push({ purpose: check.purpose, keyId: row.key_id || "legacy-v1", references: Number(row.count) });
  }
  return { valid: missing.length === 0, missing };
}
