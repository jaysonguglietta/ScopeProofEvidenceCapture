import type { AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { activeEvidenceKeyId, availableAuditKeyIds, availableEvidenceKeyIds, decryptEvidence, decryptSecret, encryptEvidence, encryptSecret, rotatingSecretKeyring, stableJson } from "./crypto";
import { getEnv } from "./env";
import { classifyObjectRotation, jiraRotationReachedActiveState, nextRotationFailureState, type ObjectRotationDisposition, type ObjectRotationState, type RotationAttemptState } from "./key-rotation-reconciliation";
import { classifyErrorForLogging } from "./safe-error";

type EvidenceKeyRow = { id: string; control_id: string; source: string; captured_at: string; r2_key: string; encryption_iv: string; encryption_key_id: string; sha256: string; expires_at: string };
type PackageKeyRow = { id: string; r2_key: string; encryption_key_id: string; sha256: string; expires_at: string };
type JiraKeyRow = { id: string; user_id: string; access_token_ciphertext: string; access_token_iv: string; refresh_token_ciphertext: string; refresh_token_iv: string; token_key_id: string; token_version: number };
const ROTATION_LEASE_MS = 5 * 60_000;
const ROTATION_ACTION_REQUIRED_AFTER = 5;
type RotationResourceType = "evidence" | "package" | "jira_connection";
type RotationFailureCode = "CRYPTOGRAPHIC_FAILURE" | "MISSING_METADATA" | "MISSING_OBJECT" | "RETAINED_KEY_UNAVAILABLE" | "STORAGE_OR_DATABASE_FAILURE";
type StoredObjectRotationRow = { r2_key: string; encryption_key_id: string; rotation_pending_r2_key: string | null; rotation_previous_r2_key: string | null };
type StoredRotationAttempt = { attempt_count: number; status: RotationAttemptState["status"]; last_attempt_id: string };

export type KeyRotationRetrySummary = {
  total: number;
  retrying: number;
  actionRequired: number;
  resolved: number;
  due: number;
  oldestUnresolvedAt: string | null;
};

function objectRotationState(row: StoredObjectRotationRow): ObjectRotationState {
  return {
    currentKey: row.r2_key,
    encryptionKeyId: row.encryption_key_id,
    pendingKey: row.rotation_pending_r2_key,
    previousKey: row.rotation_previous_r2_key,
  };
}

async function authoritativeObjectRotationDisposition(
  type: "evidence" | "package",
  resourceId: string,
  nextKey: string,
  nextEncryptionKeyId: string,
): Promise<ObjectRotationDisposition | "unavailable"> {
  try {
    const statement = type === "evidence"
      ? "SELECT r2_key, encryption_key_id, rotation_pending_r2_key, rotation_previous_r2_key FROM evidence_artifacts WHERE id = ?"
      : "SELECT r2_key, encryption_key_id, rotation_pending_r2_key, rotation_previous_r2_key FROM export_packages WHERE id = ?";
    const row = await getEnv().DB.prepare(statement).bind(resourceId).first<StoredObjectRotationRow>();
    return classifyObjectRotation(row ? objectRotationState(row) : null, { nextKey, nextEncryptionKeyId });
  } catch {
    // An unavailable read is not proof that the new object is unreferenced.
    return "unavailable";
  }
}

async function deleteOnlyProvenRotationLoser(
  type: "evidence" | "package",
  resourceId: string,
  nextKey: string,
  nextEncryptionKeyId: string,
): Promise<boolean> {
  const disposition = await authoritativeObjectRotationDisposition(type, resourceId, nextKey, nextEncryptionKeyId);
  if (disposition === "committed") return true;
  if (disposition === "proven_loser") await getEnv().EVIDENCE_BUCKET.delete(nextKey);
  return false;
}

function rotationFailureCode(error: unknown): RotationFailureCode {
  const message = error instanceof Error ? error.message : "";
  if (/object .* is missing during key rotation/u.test(message)) return "MISSING_OBJECT";
  if (/missing its IV/u.test(message)) return "MISSING_METADATA";
  if (/key .* is unavailable during rotation/u.test(message)) return "RETAINED_KEY_UNAVAILABLE";
  if (/decrypt|encrypt|cipher|authentication|OperationError/u.test(message)) return "CRYPTOGRAPHIC_FAILURE";
  return "STORAGE_OR_DATABASE_FAILURE";
}

function rotationResourceType(type: RotationResourceType): string {
  return type === "evidence" ? "evidence" : type === "package" ? "export_package" : "jira_connection";
}

async function recordRotationFailure(actor: AuthenticatedUser, type: RotationResourceType, resourceId: string, error: unknown): Promise<void> {
  const env = getEnv();
  const errorCode = rotationFailureCode(error);
  for (let contentionAttempt = 0; contentionAttempt < 3; contentionAttempt += 1) {
    const previous = await env.DB.prepare("SELECT attempt_count, status, last_attempt_id FROM key_rotation_attempts WHERE resource_type = ? AND resource_id = ?")
      .bind(type, resourceId).first<StoredRotationAttempt>();
    const attemptedAtMs = Date.now();
    const attemptedAt = new Date(attemptedAtMs).toISOString();
    const attemptId = crypto.randomUUID();
    const next = nextRotationFailureState(previous ? {
      attemptCount: Number(previous.attempt_count), status: previous.status, lastAttemptId: previous.last_attempt_id,
    } : null, attemptedAtMs, ROTATION_ACTION_REQUIRED_AFTER);
    const mutation = previous
      ? env.DB.prepare(`UPDATE key_rotation_attempts SET attempt_count = ?, status = ?, next_attempt_at = ?, last_error_code = ?,
          first_failed_at = CASE WHEN status = 'resolved' THEN ? ELSE first_failed_at END,
          last_attempt_at = ?, last_attempt_id = ?, resolved_at = NULL
        WHERE resource_type = ? AND resource_id = ? AND attempt_count = ? AND status = ? AND last_attempt_id = ?`)
        .bind(next.attemptCount, next.status, next.nextAttemptAt, errorCode, attemptedAt, attemptedAt, attemptId,
          type, resourceId, previous.attempt_count, previous.status, previous.last_attempt_id)
      : env.DB.prepare(`INSERT INTO key_rotation_attempts
          (resource_type, resource_id, attempt_count, status, next_attempt_at, last_error_code, first_failed_at, last_attempt_at, last_attempt_id, resolved_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
        ON CONFLICT(resource_type, resource_id) DO NOTHING`)
        .bind(type, resourceId, next.attemptCount, next.status, next.nextAttemptAt, errorCode, attemptedAt, attemptedAt, attemptId);
    try {
      const [recorded] = await executeAuditedBatch(actor, next.status === "action_required" ? "key.rotation_action_required" : "key.rotation_retry_scheduled", rotationResourceType(type), resourceId,
        { attemptCount: next.attemptCount, errorCode, nextAttemptAt: next.nextAttemptAt }, [mutation], {
          sql: "EXISTS (SELECT 1 FROM key_rotation_attempts WHERE resource_type = ? AND resource_id = ? AND last_attempt_id = ? AND attempt_count = ? AND status = ? AND last_error_code = ?)",
          bindings: [type, resourceId, attemptId, next.attemptCount, next.status, errorCode],
        });
      if (!recorded.meta.changes) continue;
    } catch (writeError) {
      const current = await env.DB.prepare(`SELECT attempt_count, status, last_attempt_id FROM key_rotation_attempts
        WHERE resource_type = ? AND resource_id = ?`).bind(type, resourceId).first<StoredRotationAttempt>();
      if (current?.last_attempt_id !== attemptId) {
        const contentionWonByPeer = previous
          ? Boolean(current && current.last_attempt_id !== previous.last_attempt_id)
          : Boolean(current);
        if (contentionWonByPeer) continue;
        throw writeError;
      }
    }
    console.error(next.status === "action_required" ? "scopeproof_key_rotation_action_required" : "scopeproof_key_rotation_retry_scheduled",
      { resourceType: type, resourceId, attemptCount: next.attemptCount, errorCode, nextAttemptAt: next.nextAttemptAt });
    return;
  }
  throw new Error("Key-rotation failure tracking exceeded its bounded contention retry budget.");
}

async function resolveRotationFailure(actor: AuthenticatedUser, type: RotationResourceType, resourceId: string): Promise<void> {
  const env = getEnv();
  const previous = await env.DB.prepare("SELECT attempt_count, status, last_attempt_id FROM key_rotation_attempts WHERE resource_type = ? AND resource_id = ? AND status != 'resolved'")
    .bind(type, resourceId).first<StoredRotationAttempt>();
  if (!previous) return;
  const resolvedAt = new Date().toISOString();
  try {
    await executeAuditedBatch(actor, "key.rotation_recovered", rotationResourceType(type), resourceId, { previousAttempts: Number(previous.attempt_count) }, [
      env.DB.prepare(`UPDATE key_rotation_attempts SET status = 'resolved', next_attempt_at = NULL, resolved_at = ?, last_attempt_at = ?
        WHERE resource_type = ? AND resource_id = ? AND attempt_count = ? AND status = ? AND last_attempt_id = ?`)
        .bind(resolvedAt, resolvedAt, type, resourceId, previous.attempt_count, previous.status, previous.last_attempt_id),
    ], { sql: "EXISTS (SELECT 1 FROM key_rotation_attempts WHERE resource_type = ? AND resource_id = ? AND status = 'resolved' AND resolved_at = ? AND last_attempt_id = ?)", bindings: [type, resourceId, resolvedAt, previous.last_attempt_id] });
  } catch (error) {
    const committed = await env.DB.prepare("SELECT 1 FROM key_rotation_attempts WHERE resource_type = ? AND resource_id = ? AND status = 'resolved' AND next_attempt_at IS NULL AND resolved_at = ? AND last_attempt_id = ?")
      .bind(type, resourceId, resolvedAt, previous.last_attempt_id).first();
    if (!committed) throw error;
  }
}

async function rotateIsolated(actor: AuthenticatedUser, type: RotationResourceType, resourceId: string, operation: () => Promise<boolean>): Promise<boolean> {
  let rotated: boolean;
  try {
    rotated = await operation();
  } catch (error) {
    try { await recordRotationFailure(actor, type, resourceId, error); }
    catch (trackingError) { console.error("scopeproof_key_rotation_failure_tracking_failed", { resourceType: type, resourceId, errorClass: classifyErrorForLogging(trackingError) }); }
    return false;
  }
  if (rotated) {
    try { await resolveRotationFailure(actor, type, resourceId); }
    catch (trackingError) { console.error("scopeproof_key_rotation_recovery_tracking_failed", { resourceType: type, resourceId, errorClass: classifyErrorForLogging(trackingError) }); }
  }
  return rotated;
}

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
          AND status NOT IN ('expired', 'purged') AND expires_at > ? AND rotation_lease_expires_at > ?`)
        .bind(nextKey, encrypted.iv, encrypted.keyId, row.r2_key, row.id, row.r2_key, row.encryption_key_id, leaseId, nextKey, new Date().toISOString(), new Date().toISOString()),
    ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND r2_key = ? AND encryption_key_id = ?)", bindings: [row.id, nextKey, encrypted.keyId] });
    if (!updated.meta.changes) throw new Error("The evidence key-rotation switch did not commit.");
  } catch (error) {
    if (!await deleteOnlyProvenRotationLoser("evidence", row.id, nextKey, encrypted.keyId)) throw error;
  }
  try {
    await env.EVIDENCE_BUCKET.delete(row.r2_key);
    await executeAuditedBatch(actor, "key.evidence_previous_object_deleted", "evidence", row.id, { previousKeyId: row.encryption_key_id }, [
      env.DB.prepare("UPDATE evidence_artifacts SET rotation_previous_r2_key = NULL WHERE id = ? AND r2_key = ? AND rotation_previous_r2_key = ?")
        .bind(row.id, nextKey, row.r2_key),
    ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND r2_key = ? AND rotation_previous_r2_key IS NULL)", bindings: [row.id, nextKey] });
  } catch (error) { console.error("scopeproof_rekey_old_object_delete_failure", { type: "evidence", id: row.id, errorClass: classifyErrorForLogging(error) }); }
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
        WHERE id = ? AND r2_key = ? AND encryption_key_id = ? AND rotation_lease_id = ? AND rotation_pending_r2_key = ? AND status = 'ready' AND expires_at > ? AND rotation_lease_expires_at > ?`)
        .bind(nextKey, encrypted.keyId, row.r2_key, row.id, row.r2_key, row.encryption_key_id, leaseId, nextKey, new Date().toISOString(), new Date().toISOString()),
    ], { sql: "EXISTS (SELECT 1 FROM export_packages WHERE id = ? AND r2_key = ? AND encryption_key_id = ?)", bindings: [row.id, nextKey, encrypted.keyId] });
    if (!updated.meta.changes) throw new Error("The package key-rotation switch did not commit.");
  } catch (error) {
    if (!await deleteOnlyProvenRotationLoser("package", row.id, nextKey, encrypted.keyId)) throw error;
  }
  try {
    await env.EVIDENCE_BUCKET.delete(row.r2_key);
    await executeAuditedBatch(actor, "key.package_previous_object_deleted", "export_package", row.id, { previousKeyId: row.encryption_key_id }, [
      env.DB.prepare("UPDATE export_packages SET rotation_previous_r2_key = NULL WHERE id = ? AND r2_key = ? AND rotation_previous_r2_key = ?")
        .bind(row.id, nextKey, row.r2_key),
    ], { sql: "EXISTS (SELECT 1 FROM export_packages WHERE id = ? AND r2_key = ? AND rotation_previous_r2_key IS NULL)", bindings: [row.id, nextKey] });
  } catch (error) { console.error("scopeproof_rekey_old_object_delete_failure", { type: "package", id: row.id, errorClass: classifyErrorForLogging(error) }); }
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
  try {
    const [updated] = await executeAuditedBatch(actor, "key.jira_tokens_rotated", "jira_connection", row.id, { previousKeyId: row.token_key_id, activeKeyId: ring.activeId }, [
      env.DB.prepare(`UPDATE jira_connections SET access_token_ciphertext = ?, access_token_iv = ?, refresh_token_ciphertext = ?, refresh_token_iv = ?, token_key_id = ?, token_version = token_version + 1, updated_at = CURRENT_TIMESTAMP
        WHERE id = ? AND token_version = ? AND token_key_id = ? AND refresh_lease_id IS NULL`).bind(nextAccess.ciphertext, nextAccess.iv, nextRefresh.ciphertext, nextRefresh.iv, ring.activeId, row.id, row.token_version, row.token_key_id),
    ], { sql: "EXISTS (SELECT 1 FROM jira_connections WHERE id = ? AND token_key_id = ? AND token_version = ?)", bindings: [row.id, ring.activeId, row.token_version + 1] });
    if (updated.meta.changes) return true;
  } catch (error) {
    const state = await env.DB.prepare("SELECT token_key_id, token_version FROM jira_connections WHERE id = ?")
      .bind(row.id).first<{ token_key_id: string; token_version: number }>();
    if (!jiraRotationReachedActiveState(state ? { tokenKeyId: state.token_key_id, tokenVersion: Number(state.token_version) } : null, ring.activeId, row.token_version + 1)) throw error;
    return true;
  }
  const state = await env.DB.prepare("SELECT token_key_id, token_version FROM jira_connections WHERE id = ?")
    .bind(row.id).first<{ token_key_id: string; token_version: number }>();
  return jiraRotationReachedActiveState(state ? { tokenKeyId: state.token_key_id, tokenVersion: Number(state.token_version) } : null, ring.activeId, row.token_version + 1);
}

async function reconcileRotationGarbage(actor: AuthenticatedUser, limit: number): Promise<void> {
  const env = getEnv();
  const now = new Date().toISOString();
  const cleanupLeaseExpiresAt = new Date(Date.parse(now) + ROTATION_LEASE_MS).toISOString();
  const evidence = (await env.DB.prepare(`SELECT id, r2_key, rotation_pending_r2_key, rotation_previous_r2_key FROM evidence_artifacts
    WHERE (rotation_pending_r2_key IS NOT NULL OR rotation_previous_r2_key IS NOT NULL)
      AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?) ORDER BY created_at LIMIT ?`)
    .bind(now, limit).all<{ id: string; r2_key: string; rotation_pending_r2_key: string | null; rotation_previous_r2_key: string | null }>()).results;
  for (const row of evidence) {
    const cleanupLeaseId = crypto.randomUUID();
    const claim = await env.DB.prepare(`UPDATE evidence_artifacts SET rotation_lease_id = ?, rotation_lease_expires_at = ?
      WHERE id = ? AND r2_key = ? AND rotation_pending_r2_key IS ? AND rotation_previous_r2_key IS ?
        AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?)`)
      .bind(cleanupLeaseId, cleanupLeaseExpiresAt, row.id, row.r2_key, row.rotation_pending_r2_key, row.rotation_previous_r2_key, now).run();
    if (!claim.meta.changes) continue;
    const garbage = [...new Set([row.rotation_pending_r2_key, row.rotation_previous_r2_key].filter((key): key is string => Boolean(key) && key !== row.r2_key))];
    try {
      for (const key of garbage) await env.EVIDENCE_BUCKET.delete(key);
      await executeAuditedBatch(actor, "key.evidence_rotation_reconciled", "evidence", row.id, { deletedObjectCount: garbage.length }, [
        env.DB.prepare(`UPDATE evidence_artifacts SET rotation_pending_r2_key = NULL, rotation_previous_r2_key = NULL,
          rotation_lease_id = NULL, rotation_lease_expires_at = NULL
          WHERE id = ? AND r2_key = ? AND rotation_lease_id = ?
            AND rotation_pending_r2_key IS ? AND rotation_previous_r2_key IS ?`)
          .bind(row.id, row.r2_key, cleanupLeaseId, row.rotation_pending_r2_key, row.rotation_previous_r2_key),
      ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND r2_key = ? AND rotation_pending_r2_key IS NULL AND rotation_previous_r2_key IS NULL AND rotation_lease_id IS NULL)", bindings: [row.id, row.r2_key] });
    } catch (error) { console.error("scopeproof_rekey_reconciliation_failure", { type: "evidence", id: row.id, errorClass: classifyErrorForLogging(error) }); }
  }
  const packages = (await env.DB.prepare(`SELECT id, r2_key, rotation_pending_r2_key, rotation_previous_r2_key FROM export_packages
    WHERE (rotation_pending_r2_key IS NOT NULL OR rotation_previous_r2_key IS NOT NULL)
      AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?) ORDER BY created_at LIMIT ?`)
    .bind(now, limit).all<{ id: string; r2_key: string; rotation_pending_r2_key: string | null; rotation_previous_r2_key: string | null }>()).results;
  for (const row of packages) {
    const cleanupLeaseId = crypto.randomUUID();
    const claim = await env.DB.prepare(`UPDATE export_packages SET rotation_lease_id = ?, rotation_lease_expires_at = ?
      WHERE id = ? AND r2_key = ? AND rotation_pending_r2_key IS ? AND rotation_previous_r2_key IS ?
        AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?)`)
      .bind(cleanupLeaseId, cleanupLeaseExpiresAt, row.id, row.r2_key, row.rotation_pending_r2_key, row.rotation_previous_r2_key, now).run();
    if (!claim.meta.changes) continue;
    const garbage = [...new Set([row.rotation_pending_r2_key, row.rotation_previous_r2_key].filter((key): key is string => Boolean(key) && key !== row.r2_key))];
    try {
      for (const key of garbage) await env.EVIDENCE_BUCKET.delete(key);
      await executeAuditedBatch(actor, "key.package_rotation_reconciled", "export_package", row.id, { deletedObjectCount: garbage.length }, [
        env.DB.prepare(`UPDATE export_packages SET rotation_pending_r2_key = NULL, rotation_previous_r2_key = NULL,
          rotation_lease_id = NULL, rotation_lease_expires_at = NULL
          WHERE id = ? AND r2_key = ? AND rotation_lease_id = ?
            AND rotation_pending_r2_key IS ? AND rotation_previous_r2_key IS ?`)
          .bind(row.id, row.r2_key, cleanupLeaseId, row.rotation_pending_r2_key, row.rotation_previous_r2_key),
      ], { sql: "EXISTS (SELECT 1 FROM export_packages WHERE id = ? AND r2_key = ? AND rotation_pending_r2_key IS NULL AND rotation_previous_r2_key IS NULL AND rotation_lease_id IS NULL)", bindings: [row.id, row.r2_key] });
    } catch (error) { console.error("scopeproof_rekey_reconciliation_failure", { type: "package", id: row.id, errorClass: classifyErrorForLogging(error) }); }
  }
}

async function rotationStillRequired(type: RotationResourceType, resourceId: string, activeEvidenceKey: string, activeJiraKey: string | null): Promise<boolean> {
  const env = getEnv();
  if (type === "evidence") {
    const row = await env.DB.prepare("SELECT status, r2_key, encryption_key_id FROM evidence_artifacts WHERE id = ?").bind(resourceId)
      .first<{ status: string; r2_key: string; encryption_key_id: string }>();
    if (!row || row.status === "purged") return false;
    if (row.encryption_key_id !== activeEvidenceKey) return true;
    const object = await env.EVIDENCE_BUCKET.head(row.r2_key);
    return !object || object.customMetadata?.encryptionKeyId !== activeEvidenceKey;
  }
  if (type === "package") {
    const row = await env.DB.prepare("SELECT status, r2_key, encryption_key_id FROM export_packages WHERE id = ?").bind(resourceId)
      .first<{ status: string; r2_key: string | null; encryption_key_id: string }>();
    if (!row || row.status !== "ready" || !row.r2_key) return false;
    if (row.encryption_key_id !== activeEvidenceKey) return true;
    const object = await env.EVIDENCE_BUCKET.head(row.r2_key);
    return !object || object.customMetadata?.encryptionKeyId !== activeEvidenceKey;
  }
  if (!activeJiraKey) return true;
  const row = await env.DB.prepare("SELECT token_key_id FROM jira_connections WHERE id = ?").bind(resourceId).first<{ token_key_id: string }>();
  return Boolean(row && row.token_key_id !== activeJiraKey);
}

async function reconcileHealthyRotationAttempts(actor: AuthenticatedUser, activeEvidenceKey: string, activeJiraKey: string | null, limit: number): Promise<void> {
  const attempts = (await getEnv().DB.prepare(`SELECT resource_type, resource_id FROM key_rotation_attempts
    WHERE status != 'resolved' ORDER BY last_attempt_at, resource_type, resource_id LIMIT ?`)
    .bind(Math.min(Math.max(Math.floor(limit), 1), 25)).all<{ resource_type: RotationResourceType; resource_id: string }>()).results;
  for (const attempt of attempts) {
    try {
      if (!await rotationStillRequired(attempt.resource_type, attempt.resource_id, activeEvidenceKey, activeJiraKey)) {
        await resolveRotationFailure(actor, attempt.resource_type, attempt.resource_id);
      }
    } catch (error) {
      console.error("scopeproof_key_rotation_recovery_tracking_failed", { resourceType: attempt.resource_type, resourceId: attempt.resource_id, errorClass: classifyErrorForLogging(error) });
    }
  }
}

export async function rotateStoredKeys(actor: AuthenticatedUser, limit = 10): Promise<{ evidence: number; packages: number; jiraConnections: number; remaining: number }> {
  const env = getEnv();
  const boundedLimit = Math.min(Math.max(Math.floor(limit), 1), 25);
  await reconcileRotationGarbage(actor, boundedLimit);
  const activeEvidence = activeEvidenceKeyId();
  const jiraRingConfigured = Boolean(env.JIRA_OAUTH_KEYRING_JSON || env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY);
  const jiraRing = jiraRingConfigured ? rotatingSecretKeyring(env.JIRA_OAUTH_KEYRING_JSON, env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY, env.JIRA_OAUTH_ACTIVE_KEY_ID, "Jira OAuth token") : null;
  await reconcileHealthyRotationAttempts(actor, activeEvidence, jiraRing?.activeId || null, boundedLimit);
  const now = new Date().toISOString();
  const evidence = (await env.DB.prepare(`SELECT id, control_id, source, captured_at, r2_key, encryption_iv, encryption_key_id, sha256, expires_at FROM evidence_artifacts
    WHERE status NOT IN ('expired', 'purged') AND expires_at > ? AND encryption_key_id != ?
      AND rotation_pending_r2_key IS NULL AND rotation_previous_r2_key IS NULL
      AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?)
      AND NOT EXISTS (SELECT 1 FROM key_rotation_attempts k WHERE k.resource_type = 'evidence' AND k.resource_id = evidence_artifacts.id AND k.status != 'resolved' AND k.next_attempt_at > ?)
      ORDER BY created_at LIMIT ?`)
    .bind(now, activeEvidence, now, now, boundedLimit).all<EvidenceKeyRow>()).results;
  let evidenceRotated = 0;
  for (const row of evidence) if (await rotateIsolated(actor, "evidence", row.id, () => rotateEvidenceObject(row, actor))) evidenceRotated += 1;
  let budget = boundedLimit - evidence.length;
  const packages = budget > 0 ? (await env.DB.prepare(`SELECT id, r2_key, encryption_key_id, sha256, expires_at FROM export_packages
    WHERE status = 'ready' AND expires_at > ? AND r2_key IS NOT NULL AND encryption_key_id != ?
      AND rotation_pending_r2_key IS NULL AND rotation_previous_r2_key IS NULL
      AND (rotation_lease_id IS NULL OR rotation_lease_expires_at <= ?)
      AND NOT EXISTS (SELECT 1 FROM key_rotation_attempts k WHERE k.resource_type = 'package' AND k.resource_id = export_packages.id AND k.status != 'resolved' AND k.next_attempt_at > ?)
      ORDER BY created_at LIMIT ?`)
    .bind(now, activeEvidence, now, now, budget).all<PackageKeyRow>()).results : [];
  let packagesRotated = 0;
  for (const row of packages) if (await rotateIsolated(actor, "package", row.id, () => rotatePackageObject(row, actor))) packagesRotated += 1;
  budget -= packages.length;
  const jiraRows = budget > 0 && jiraRing ? (await env.DB.prepare(`SELECT id, user_id, access_token_ciphertext, access_token_iv, refresh_token_ciphertext, refresh_token_iv, token_key_id, token_version FROM jira_connections
    WHERE token_key_id != ? AND refresh_lease_id IS NULL
      AND NOT EXISTS (SELECT 1 FROM key_rotation_attempts k WHERE k.resource_type = 'jira_connection' AND k.resource_id = jira_connections.id AND k.status != 'resolved' AND k.next_attempt_at > ?)
    ORDER BY updated_at LIMIT ?`).bind(jiraRing.activeId, now, budget).all<JiraKeyRow>()).results : [];
  let jiraConnections = 0;
  for (const row of jiraRows) if (await rotateIsolated(actor, "jira_connection", row.id, () => rotateJiraToken(row, actor))) jiraConnections += 1;
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

export async function keyRotationRetrySummary(now = new Date()): Promise<KeyRotationRetrySummary> {
  const timestamp = now.toISOString();
  const row = await getEnv().DB.prepare(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN status = 'retrying' THEN 1 ELSE 0 END) AS retrying,
      SUM(CASE WHEN status = 'action_required' THEN 1 ELSE 0 END) AS action_required,
      SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) AS resolved,
      SUM(CASE WHEN status != 'resolved' AND next_attempt_at <= ? THEN 1 ELSE 0 END) AS due,
      MIN(CASE WHEN status != 'resolved' THEN first_failed_at END) AS oldest_unresolved_at
    FROM key_rotation_attempts`).bind(timestamp).first<Record<string, unknown>>();
  return {
    total: Number(row?.total || 0),
    retrying: Number(row?.retrying || 0),
    actionRequired: Number(row?.action_required || 0),
    resolved: Number(row?.resolved || 0),
    due: Number(row?.due || 0),
    oldestUnresolvedAt: row?.oldest_unresolved_at ? String(row.oldest_unresolved_at) : null,
  };
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
