import type { AuthenticatedUser, Role } from "./auth";
import { executeAuditedBatch } from "./audit";
import { base64ToBytes, sha256 } from "./crypto";
import { getEnv } from "./env";
import { NATIVE_ORPHAN_GRACE_MS } from "./native-provenance-contract";
import { classifyErrorForLogging } from "./safe-error";

export { NATIVE_ORPHAN_GRACE_MS } from "./native-provenance-contract";

const deviceIdPattern = /^dev_[a-f0-9]{32}$/;
const evidenceIdPattern = /^EV-[A-Z0-9]{10,32}$/;
const artifactIdPattern = /^ev_[a-f0-9]{32}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const leaseIdPattern = /^chain_lease_[a-f0-9]{32}$/;
const collectEvidenceRoles = new Set<Role>(["admin", "compliance_lead"]);
const activeArtifactStatuses = new Set(["needs_review", "approved", "expiring"]);
const terminalArtifactStatuses = new Set(["rejected", "returned", "superseded", "expired", "purged"]);
const systemActor: AuthenticatedUser = {
  id: "system:scheduler",
  email: "scheduler@scopeproof.internal",
  displayName: "Scopeproof Scheduler",
  role: "admin",
};

export const NATIVE_RECONCILIATION_MAXIMUM_ITEMS = 25;

type PendingDeviceRow = Record<string, unknown> & {
  id: string;
  display_name: string;
  platform: string;
  owner_id: string;
  status: string;
  owner_email: string | null;
  owner_display_name: string | null;
  owner_role: string | null;
  owner_status: string | null;
  provenance_key_id: string | null;
  provenance_public_key: string | null;
  chain_sequence: number;
  chain_event_hash: string;
  chain_pending_lease_id: string;
  chain_pending_sequence: number;
  chain_pending_previous_hash: string;
  chain_pending_event_hash: string;
  chain_pending_evidence_id: string;
  chain_pending_expires_at: string;
  cursor_expires_epoch: number;
};

type OrphanArtifactRow = Record<string, unknown> & {
  queue_artifact_id: string;
  queue_due_at: string;
  cursor_due_epoch: number;
  id: string | null;
  device_id: string | null;
  type: string | null;
  content_type: string | null;
  source: string | null;
  status: string | null;
  sha256: string | null;
  manifest_sha256: string | null;
  created_at: string | null;
  has_finalized_manifest: number;
  has_pending_reservation: number;
};

type PendingAuthority = {
  deviceId: string;
  displayName: string;
  platform: string;
  ownerId: string;
  deviceStatus: "active" | "revoked";
  ownerStatus: string | null;
  ownerRole: string | null;
  provenanceKeyId: string | null;
  provenancePublicKey: string | null;
  chainSequence: number;
  chainEventHash: string;
  leaseId: string;
  pendingSequence: number;
  previousHash: string;
  eventHash: string;
  evidenceId: string;
  leaseExpiresAt: string;
};

type CandidateArtifact = {
  id: string;
  deviceId: string;
  createdBy: string;
  chainPreviousHash: string;
  chainEventHash: string;
  expiresAt: string;
  imageSha256: string;
  manifestSha256: string;
  jiraIssueKey: string | null;
  safetyScanCompletedAt: string;
  safetyScanPolicy: string;
  serverSafetyScanCompletedAt: string;
  serverSafetyScanPolicy: string;
  serverSafetyScannerOrigin: string;
  serverSafetyReceiptSha256: string;
  source: string;
  status: string;
  timestampAuthority: string;
  timestampToken: string;
};

export type NativeProvenanceReconciliationResult = {
  examined: number;
  finalized: number;
  releasedReservations: number;
  quarantinedArtifacts: number;
  drainedQueueEntries: number;
  failures: number;
};

type ReconciliationKeysetCursor = Readonly<{ epoch: number; id: string }>;

type ReconciliationCursorState = Readonly<{
  revision: number;
  pending: ReconciliationKeysetCursor | null;
  orphan: ReconciliationKeysetCursor | null;
}>;

type ReconciliationCursorStateRow = {
  id: string;
  revision: number;
  pending_cursor_expires_epoch: number | null;
  pending_cursor_device_id: string | null;
  orphan_cursor_due_epoch: number | null;
  orphan_cursor_artifact_id: string | null;
};

/**
 * Reconciles only expired device-chain reservations and due entries from the
 * sparse native-artifact queue. The pass is intentionally bounded independently
 * per domain, never reads or deletes R2 bytes, and every state mutation is an
 * audited compare-and-swap over the exact authority observed by the scheduler.
 * Durable circular keysets ensure a malformed row cannot pin either domain or
 * make the other domain surrender its work budget.
 */
export async function reconcileNativeProvenanceOrphans(
  now = new Date(),
  maximumItems = NATIVE_RECONCILIATION_MAXIMUM_ITEMS,
): Promise<NativeProvenanceReconciliationResult> {
  const nowIso = canonicalDate(now, "Native reconciliation time");
  if (!Number.isSafeInteger(maximumItems) || maximumItems < 1 || maximumItems > 100) {
    throw new Error("Native reconciliation item bound is invalid.");
  }
  const result: NativeProvenanceReconciliationResult = {
    examined: 0,
    finalized: 0,
    releasedReservations: 0,
    quarantinedArtifacts: 0,
    drainedQueueEntries: 0,
    failures: 0,
  };
  const observedCursors = await loadReconciliationCursorState();
  const pendingRows = await loadExpiredReservationPage(observedCursors.pending, nowIso, maximumItems);

  for (const row of pendingRows) {
    result.examined += 1;
    try {
      const pending = parsePendingAuthority(row, nowIso);
      const authorityProblem = await pendingAuthorityProblem(pending);
      if (authorityProblem) {
        if (await releaseExpiredReservation(pending, nowIso, authorityProblem)) result.releasedReservations += 1;
        continue;
      }
      const candidates = await loadExactCandidates(pending, nowIso);
      if (candidates.length === 1) {
        if (await finalizeExactCandidate(pending, candidates[0], nowIso)) result.finalized += 1;
      } else if (candidates.length === 0) {
        if (await releaseExpiredReservation(pending, nowIso, "ARTIFACT_NOT_FOUND")) result.releasedReservations += 1;
      } else {
        throw new Error("An expired native reservation has ambiguous artifact authority.");
      }
    } catch (error) {
      result.failures += 1;
      console.error("scopeproof_native_reconciliation_item_failed", {
        errorClass: classifyErrorForLogging(error),
        stage: "expired_reservation",
      });
    }
  }

  const cutoff = new Date(now.getTime() - NATIVE_ORPHAN_GRACE_MS).toISOString();
  const orphanRows = await loadOrphanCandidatePage(observedCursors.orphan, nowIso, maximumItems);
  for (const row of orphanRows) {
    result.examined += 1;
    try {
      const hasFinalizedManifest = exactBooleanInteger(row.has_finalized_manifest, "manifest authority");
      const hasPendingReservation = exactBooleanInteger(row.has_pending_reservation, "reservation authority");
      if (hasFinalizedManifest) {
        if (await drainReconciliationQueueEntry(row, nowIso, "FINALIZED")) result.drainedQueueEntries += 1;
      } else if (row.id === null) {
        if (await drainReconciliationQueueEntry(row, nowIso, "ARTIFACT_MISSING")) result.drainedQueueEntries += 1;
      } else if (isTerminalQueueArtifact(row)) {
        if (await drainReconciliationQueueEntry(row, nowIso, "ARTIFACT_NO_LONGER_ELIGIBLE")) result.drainedQueueEntries += 1;
      } else if (!hasPendingReservation && await quarantineOrphanArtifact(row, nowIso, cutoff)) {
        result.quarantinedArtifacts += 1;
      }
    } catch (error) {
      result.failures += 1;
      console.error("scopeproof_native_reconciliation_item_failed", {
        errorClass: classifyErrorForLogging(error),
        stage: "orphan_artifact",
      });
    }
  }

  const pendingCursor = pendingRows.length ? cursorFromPendingRow(pendingRows[pendingRows.length - 1]) : null;
  const orphanCursor = orphanRows.length ? cursorFromOrphanRow(orphanRows[orphanRows.length - 1]) : null;
  await advanceReconciliationCursors(observedCursors, pendingCursor, orphanCursor, nowIso);

  if (result.failures > 0) {
    throw new AggregateError([], `Native provenance reconciliation completed with ${result.failures} isolated failure${result.failures === 1 ? "" : "s"}.`);
  }
  return result;
}

async function loadReconciliationCursorState(): Promise<ReconciliationCursorState> {
  const row = await getEnv().DB.prepare(`SELECT id, revision, pending_cursor_expires_epoch,
      pending_cursor_device_id, orphan_cursor_due_epoch, orphan_cursor_artifact_id
    FROM native_provenance_reconciliation_state WHERE id = 'native_provenance'`)
    .first<ReconciliationCursorStateRow>();
  if (!row || row.id !== "native_provenance") throw new Error("Native reconciliation cursor state is unavailable.");
  return Object.freeze({
    revision: exactInteger(row.revision, 0, Number.MAX_SAFE_INTEGER - 1, "cursor revision"),
    pending: parseKeysetCursor(row.pending_cursor_expires_epoch, row.pending_cursor_device_id, "pending cursor"),
    orphan: parseKeysetCursor(row.orphan_cursor_due_epoch, row.orphan_cursor_artifact_id, "orphan cursor"),
  });
}

async function loadExpiredReservationPage(
  cursor: ReconciliationKeysetCursor | null,
  nowIso: string,
  limit: number,
): Promise<PendingDeviceRow[]> {
  const env = getEnv();
  const select = `SELECT d.id, d.display_name, d.platform, d.owner_id, d.status,
      d.provenance_key_id, d.provenance_public_key, d.chain_sequence, d.chain_event_hash,
      d.chain_pending_lease_id, d.chain_pending_sequence, d.chain_pending_previous_hash,
      d.chain_pending_event_hash, d.chain_pending_evidence_id, d.chain_pending_expires_at,
      unixepoch(d.chain_pending_expires_at) AS cursor_expires_epoch,
      u.email AS owner_email, u.display_name AS owner_display_name, u.role AS owner_role, u.status AS owner_status
    FROM capture_devices d LEFT JOIN users u ON u.id = d.owner_id`;
  const due = `d.chain_pending_lease_id IS NOT NULL
    AND unixepoch(d.chain_pending_expires_at) IS NOT NULL
    AND unixepoch(d.chain_pending_expires_at) <= unixepoch(?)`;
  if (!cursor) {
    return (await env.DB.prepare(`${select} WHERE ${due}
      ORDER BY unixepoch(d.chain_pending_expires_at), d.id LIMIT ?`)
      .bind(nowIso, limit).all<PendingDeviceRow>()).results;
  }
  const rows = (await env.DB.prepare(`${select} WHERE ${due}
      AND (unixepoch(d.chain_pending_expires_at) > ?
        OR (unixepoch(d.chain_pending_expires_at) = ? AND d.id > ?))
      ORDER BY unixepoch(d.chain_pending_expires_at), d.id LIMIT ?`)
    .bind(nowIso, cursor.epoch, cursor.epoch, cursor.id, limit).all<PendingDeviceRow>()).results;
  if (rows.length < limit) {
    const wrapped = (await env.DB.prepare(`${select} WHERE ${due}
        AND (unixepoch(d.chain_pending_expires_at) < ?
          OR (unixepoch(d.chain_pending_expires_at) = ? AND d.id <= ?))
        ORDER BY unixepoch(d.chain_pending_expires_at), d.id LIMIT ?`)
      .bind(nowIso, cursor.epoch, cursor.epoch, cursor.id, limit - rows.length).all<PendingDeviceRow>()).results;
    rows.push(...wrapped);
  }
  return rows;
}

async function loadOrphanCandidatePage(
  cursor: ReconciliationKeysetCursor | null,
  nowIso: string,
  limit: number,
): Promise<OrphanArtifactRow[]> {
  const env = getEnv();
  const select = `SELECT q.artifact_id AS queue_artifact_id, q.due_at AS queue_due_at,
      unixepoch(q.due_at) AS cursor_due_epoch,
      e.id, e.device_id, e.type, e.content_type, e.source, e.status, e.sha256, e.manifest_sha256, e.created_at,
      EXISTS (SELECT 1 FROM native_evidence_manifests n WHERE n.artifact_id = e.id) AS has_finalized_manifest,
      EXISTS (SELECT 1 FROM capture_devices d WHERE d.id = e.device_id
        AND d.chain_pending_lease_id IS NOT NULL) AS has_pending_reservation
    FROM native_provenance_reconciliation_queue q
    LEFT JOIN evidence_artifacts e ON e.id = q.artifact_id`;
  const due = `unixepoch(q.due_at) IS NOT NULL AND unixepoch(q.due_at) <= unixepoch(?)`;
  if (!cursor) {
    return (await env.DB.prepare(`${select} WHERE ${due}
      ORDER BY unixepoch(q.due_at), q.artifact_id LIMIT ?`)
      .bind(nowIso, limit).all<OrphanArtifactRow>()).results;
  }
  const rows = (await env.DB.prepare(`${select} WHERE ${due}
      AND (unixepoch(q.due_at) > ? OR (unixepoch(q.due_at) = ? AND q.artifact_id > ?))
      ORDER BY unixepoch(q.due_at), q.artifact_id LIMIT ?`)
    .bind(nowIso, cursor.epoch, cursor.epoch, cursor.id, limit).all<OrphanArtifactRow>()).results;
  if (rows.length < limit) {
    const wrapped = (await env.DB.prepare(`${select} WHERE ${due}
        AND (unixepoch(q.due_at) < ? OR (unixepoch(q.due_at) = ? AND q.artifact_id <= ?))
        ORDER BY unixepoch(q.due_at), q.artifact_id LIMIT ?`)
      .bind(nowIso, cursor.epoch, cursor.epoch, cursor.id, limit - rows.length).all<OrphanArtifactRow>()).results;
    rows.push(...wrapped);
  }
  return rows;
}

function cursorFromPendingRow(row: PendingDeviceRow): ReconciliationKeysetCursor {
  return Object.freeze({
    epoch: exactInteger(row.cursor_expires_epoch, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, "pending cursor epoch"),
    id: exactCursorId(row.id, "pending cursor identifier"),
  });
}

function cursorFromOrphanRow(row: OrphanArtifactRow): ReconciliationKeysetCursor {
  return Object.freeze({
    epoch: exactInteger(row.cursor_due_epoch, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, "orphan cursor epoch"),
    id: exactCursorId(row.queue_artifact_id, "orphan cursor identifier"),
  });
}

function parseKeysetCursor(epoch: unknown, id: unknown, label: string): ReconciliationKeysetCursor | null {
  if (epoch === null && id === null) return null;
  if (epoch === null || id === null) throw new Error(`Native reconciliation ${label} is malformed.`);
  return Object.freeze({
    epoch: exactInteger(epoch, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER, `${label} epoch`),
    id: exactCursorId(id, `${label} identifier`),
  });
}

async function advanceReconciliationCursors(
  observed: ReconciliationCursorState,
  pending: ReconciliationKeysetCursor | null,
  orphan: ReconciliationKeysetCursor | null,
  nowIso: string,
): Promise<void> {
  if (sameCursor(observed.pending, pending) && sameCursor(observed.orphan, orphan)) return;
  const env = getEnv();
  const [change] = await executeAuditedBatch(systemActor, "native_provenance.cursors_advanced", "maintenance_state", "native_provenance", {
    fromRevision: observed.revision,
    orphanCursorAdvanced: !sameCursor(observed.orphan, orphan),
    pendingCursorAdvanced: !sameCursor(observed.pending, pending),
    toRevision: observed.revision + 1,
  }, [
    env.DB.prepare(`UPDATE native_provenance_reconciliation_state
      SET revision = ?, pending_cursor_expires_epoch = ?, pending_cursor_device_id = ?,
        orphan_cursor_due_epoch = ?, orphan_cursor_artifact_id = ?, updated_at = ?
      WHERE id = 'native_provenance' AND revision = ?
        AND pending_cursor_expires_epoch IS ? AND pending_cursor_device_id IS ?
        AND orphan_cursor_due_epoch IS ? AND orphan_cursor_artifact_id IS ?`)
      .bind(observed.revision + 1, pending?.epoch ?? null, pending?.id ?? null,
        orphan?.epoch ?? null, orphan?.id ?? null, nowIso, observed.revision,
        observed.pending?.epoch ?? null, observed.pending?.id ?? null,
        observed.orphan?.epoch ?? null, observed.orphan?.id ?? null),
  ], {
    sql: `EXISTS (SELECT 1 FROM native_provenance_reconciliation_state
      WHERE id = 'native_provenance' AND revision = ?
        AND pending_cursor_expires_epoch IS ? AND pending_cursor_device_id IS ?
        AND orphan_cursor_due_epoch IS ? AND orphan_cursor_artifact_id IS ? AND updated_at = ?)`,
    bindings: [observed.revision + 1, pending?.epoch ?? null, pending?.id ?? null,
      orphan?.epoch ?? null, orphan?.id ?? null, nowIso],
  });
  if (!change?.meta.changes) throw new Error("Native reconciliation cursor authority changed.");
}

function sameCursor(left: ReconciliationKeysetCursor | null, right: ReconciliationKeysetCursor | null): boolean {
  if (!left || !right) return left === right;
  return left.epoch === right.epoch && left.id === right.id;
}

function parsePendingAuthority(row: PendingDeviceRow, nowIso: string): PendingAuthority {
  const deviceId = exactPattern(row.id, deviceIdPattern, "device identifier");
  const ownerId = exactBoundedText(row.owner_id, 256, "device owner identifier");
  const chainSequence = exactInteger(row.chain_sequence, 0, 2_147_483_646, "device chain sequence");
  const pendingSequence = exactInteger(row.chain_pending_sequence, 1, 2_147_483_647, "pending chain sequence");
  const chainEventHash = exactChainHash(row.chain_event_hash, chainSequence, "device chain event hash");
  const previousHash = exactChainHash(row.chain_pending_previous_hash, chainSequence, "pending previous hash");
  const eventHash = exactPattern(row.chain_pending_event_hash, digestPattern, "pending event hash");
  const leaseExpiresAt = canonicalTextInstant(row.chain_pending_expires_at, "pending lease expiry");
  if (Date.parse(leaseExpiresAt) > Date.parse(nowIso)) throw new Error("Native reconciliation selected an active reservation.");
  const deviceStatus = row.status === "active" || row.status === "revoked" ? row.status : null;
  if (!deviceStatus) throw new Error("Native reservation device status is invalid.");
  return Object.freeze({
    deviceId,
    displayName: exactBoundedText(row.display_name, 160, "device display name"),
    platform: exactBoundedText(row.platform, 32, "device platform"),
    ownerId,
    deviceStatus,
    ownerStatus: typeof row.owner_status === "string" ? row.owner_status : null,
    ownerRole: typeof row.owner_role === "string" ? row.owner_role : null,
    provenanceKeyId: typeof row.provenance_key_id === "string" ? row.provenance_key_id : null,
    provenancePublicKey: typeof row.provenance_public_key === "string" ? row.provenance_public_key : null,
    chainSequence,
    chainEventHash,
    leaseId: exactPattern(row.chain_pending_lease_id, leaseIdPattern, "pending lease identifier"),
    pendingSequence,
    previousHash,
    eventHash,
    evidenceId: exactPattern(row.chain_pending_evidence_id, evidenceIdPattern, "local evidence identifier"),
    leaseExpiresAt,
  });
}

async function pendingAuthorityProblem(pending: PendingAuthority): Promise<"DEVICE_OR_OWNER_REVOKED" | "CHAIN_AUTHORITY_MISMATCH" | "PINNED_KEY_INVALID" | null> {
  if (pending.deviceStatus !== "active" || pending.ownerStatus !== "active" || !collectEvidenceRoles.has(pending.ownerRole as Role)) {
    return "DEVICE_OR_OWNER_REVOKED";
  }
  if (pending.pendingSequence !== pending.chainSequence + 1 || pending.previousHash !== pending.chainEventHash) {
    return "CHAIN_AUTHORITY_MISMATCH";
  }
  if (!pending.provenanceKeyId || !digestPattern.test(pending.provenanceKeyId) || !pending.provenancePublicKey) {
    return "PINNED_KEY_INVALID";
  }
  try {
    const publicKey = base64ToBytes(pending.provenancePublicKey);
    if (publicKey.byteLength !== 65 || publicKey[0] !== 0x04 || await sha256(publicKey) !== pending.provenanceKeyId) {
      return "PINNED_KEY_INVALID";
    }
  } catch {
    return "PINNED_KEY_INVALID";
  }
  return null;
}

async function loadExactCandidates(pending: PendingAuthority, nowIso: string): Promise<CandidateArtifact[]> {
  const sourcePrefix = `Scopeproof Capture / ${pending.deviceId} / ${pending.evidenceId} / `;
  const rows = (await getEnv().DB.prepare(`SELECT id, device_id, created_by, sha256, manifest_sha256, jira_issue_key,
      chain_previous_hash, chain_event_hash, source, status, expires_at,
      safety_scan_sha256, safety_scan_policy, safety_scan_completed_at,
      server_safety_scan_sha256, server_safety_scan_policy, server_safety_scan_completed_at,
      server_safety_scanner_origin, server_safety_receipt_sha256, timestamp_authority, timestamp_token
    FROM evidence_artifacts
    WHERE device_id = ? AND created_by = ? AND chain_previous_hash = ? AND chain_event_hash = ?
      AND type = 'screenshot' AND content_type = 'image/png'
      AND status IN ('needs_review', 'approved', 'expiring') AND unixepoch(expires_at) > unixepoch(?)
      AND source LIKE ?
      AND NOT EXISTS (SELECT 1 FROM native_evidence_manifests n WHERE n.artifact_id = evidence_artifacts.id)
    ORDER BY created_at, id LIMIT 2`)
    .bind(pending.deviceId, pending.ownerId, pending.previousHash, pending.eventHash, nowIso, `${sourcePrefix}%`)
    .all<Record<string, unknown>>()).results;
  return rows.map((row) => parseExactCandidate(row, pending, sourcePrefix, nowIso));
}

function parseExactCandidate(row: Record<string, unknown>, pending: PendingAuthority, sourcePrefix: string, nowIso: string): CandidateArtifact {
  const source = exactBoundedText(row.source, 512, "native evidence source");
  if (!source.startsWith(sourcePrefix) || source.length === sourcePrefix.length) throw new Error("Native evidence source is not exactly bound to the pending local identity.");
  const imageSha256 = exactPattern(row.sha256, digestPattern, "native image digest");
  const manifestSha256 = exactPattern(row.manifest_sha256, digestPattern, "native manifest digest");
  if (row.chain_previous_hash !== pending.previousHash || row.chain_event_hash !== pending.eventHash ||
      row.device_id !== pending.deviceId || row.created_by !== pending.ownerId ||
      row.safety_scan_sha256 !== imageSha256 || row.server_safety_scan_sha256 !== imageSha256 ||
      !digestPattern.test(String(row.server_safety_receipt_sha256 || ""))) {
    throw new Error("Native evidence candidate does not match its exact safety and chain authority.");
  }
  const safetyScanCompletedAt = canonicalTextInstant(row.safety_scan_completed_at, "client safety completion");
  const serverSafetyScanCompletedAt = canonicalTextInstant(row.server_safety_scan_completed_at, "server safety completion");
  const expiresAt = canonicalTextInstant(row.expires_at, "native evidence expiry");
  if (Date.parse(expiresAt) <= Date.parse(nowIso)) throw new Error("Expired native evidence cannot be finalized.");
  const scanner = new URL(exactBoundedText(row.server_safety_scanner_origin, 512, "server safety scanner origin"));
  if (scanner.protocol !== "https:" || scanner.origin !== String(row.server_safety_scanner_origin) || scanner.username || scanner.password) {
    throw new Error("Native evidence scanner origin is invalid.");
  }
  const safetyScanPolicy = exactBoundedText(row.safety_scan_policy, 128, "client safety policy");
  const serverSafetyScanPolicy = exactBoundedText(row.server_safety_scan_policy, 128, "server safety policy");
  const timestampAuthority = exactBoundedText(row.timestamp_authority, 256, "timestamp authority");
  const timestampToken = exactBoundedText(row.timestamp_token, 65_536, "timestamp token");
  const status = exactBoundedText(row.status, 32, "native evidence status");
  if (!activeArtifactStatuses.has(status)) throw new Error("Native evidence candidate status is invalid.");
  const jiraIssueKey = row.jira_issue_key === null || row.jira_issue_key === undefined
    ? null
    : exactBoundedText(row.jira_issue_key, 64, "Jira issue key");
  return Object.freeze({
    id: exactPattern(row.id, artifactIdPattern, "artifact identifier"),
    deviceId: pending.deviceId,
    createdBy: pending.ownerId,
    chainPreviousHash: pending.previousHash,
    chainEventHash: pending.eventHash,
    expiresAt,
    imageSha256,
    manifestSha256,
    jiraIssueKey,
    safetyScanCompletedAt,
    safetyScanPolicy,
    serverSafetyScanCompletedAt,
    serverSafetyScanPolicy,
    serverSafetyScannerOrigin: scanner.origin,
    serverSafetyReceiptSha256: String(row.server_safety_receipt_sha256),
    source,
    status,
    timestampAuthority,
    timestampToken,
  });
}

const exactArtifactAuthoritySql = `e.id = ? AND e.device_id = ? AND e.created_by = ?
  AND e.type = 'screenshot' AND e.content_type = 'image/png' AND e.status = ?
  AND e.source = ? AND e.sha256 = ? AND e.manifest_sha256 = ?
  AND COALESCE(e.jira_issue_key, '') = COALESCE(?, '')
  AND e.chain_previous_hash = ? AND e.chain_event_hash = ?
  AND e.expires_at = ? AND unixepoch(e.expires_at) > unixepoch(?)
  AND e.safety_scan_sha256 = ? AND e.safety_scan_policy = ? AND e.safety_scan_completed_at = ?
  AND e.server_safety_scan_sha256 = ? AND e.server_safety_scan_policy = ?
  AND e.server_safety_scan_completed_at = ? AND e.server_safety_scanner_origin = ?
  AND e.server_safety_receipt_sha256 = ? AND e.timestamp_authority = ? AND e.timestamp_token = ?`;

function exactArtifactAuthorityBindings(artifact: CandidateArtifact, nowIso: string): unknown[] {
  return [
    artifact.id, artifact.deviceId, artifact.createdBy, artifact.status, artifact.source,
    artifact.imageSha256, artifact.manifestSha256, artifact.jiraIssueKey,
    artifact.chainPreviousHash, artifact.chainEventHash, artifact.expiresAt, nowIso,
    artifact.imageSha256, artifact.safetyScanPolicy, artifact.safetyScanCompletedAt,
    artifact.imageSha256, artifact.serverSafetyScanPolicy, artifact.serverSafetyScanCompletedAt,
    artifact.serverSafetyScannerOrigin, artifact.serverSafetyReceiptSha256,
    artifact.timestampAuthority, artifact.timestampToken,
  ];
}

async function finalizeExactCandidate(pending: PendingAuthority, artifact: CandidateArtifact, nowIso: string): Promise<boolean> {
  const env = getEnv();
  const manifestIdentity = `${pending.deviceId}:${pending.evidenceId}`;
  const exactExisting = async (): Promise<boolean> => Boolean(await env.DB.prepare(`SELECT 1
      FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
      WHERE n.id = ? AND n.device_id = ? AND n.local_evidence_id = ? AND n.artifact_id = ?
        AND n.manifest_sha256 = ? AND n.image_sha256 = ? AND COALESCE(n.jira_issue_key, '') = COALESCE(?, '')
        AND n.chain_sequence = ? AND n.chain_event_hash = ? AND n.provenance_key_id = ?
        AND d.chain_sequence >= n.chain_sequence AND d.provenance_key_id = n.provenance_key_id`)
    .bind(manifestIdentity, pending.deviceId, pending.evidenceId, artifact.id, artifact.manifestSha256,
      artifact.imageSha256, artifact.jiraIssueKey, pending.pendingSequence, pending.eventHash,
      pending.provenanceKeyId).first());
  if (await exactExisting()) return false;
  try {
    const changes = await executeAuditedBatch(systemActor, "native_provenance.reconciled", "evidence", artifact.id, {
      deviceId: pending.deviceId,
      evidenceId: pending.evidenceId,
      leaseExpiresAt: pending.leaseExpiresAt,
      sequence: pending.pendingSequence,
    }, [
      env.DB.prepare(`INSERT INTO native_evidence_manifests
        (id, device_id, local_evidence_id, artifact_id, manifest_sha256, image_sha256, jira_issue_key,
         chain_sequence, chain_event_hash, provenance_key_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(manifestIdentity, pending.deviceId, pending.evidenceId, artifact.id, artifact.manifestSha256,
          artifact.imageSha256, artifact.jiraIssueKey, pending.pendingSequence, pending.eventHash,
          pending.provenanceKeyId),
      env.DB.prepare(`UPDATE capture_devices SET chain_sequence = ?, chain_event_hash = ?,
          chain_pending_lease_id = NULL, chain_pending_sequence = NULL, chain_pending_previous_hash = NULL,
          chain_pending_event_hash = NULL, chain_pending_evidence_id = NULL, chain_pending_expires_at = NULL
        WHERE id = ? AND owner_id = ? AND status = 'active' AND provenance_key_id = ? AND provenance_public_key = ?
          AND chain_sequence = ? AND chain_event_hash = ? AND chain_pending_lease_id = ?
          AND chain_pending_sequence = ? AND chain_pending_previous_hash = ? AND chain_pending_event_hash = ?
          AND chain_pending_evidence_id = ? AND chain_pending_expires_at = ?
          AND EXISTS (SELECT 1 FROM users u WHERE u.id = ? AND u.id = capture_devices.owner_id
            AND u.status = 'active' AND u.role IN ('admin', 'compliance_lead'))
          AND EXISTS (SELECT 1 FROM evidence_artifacts e WHERE ${exactArtifactAuthoritySql})`)
        .bind(pending.pendingSequence, pending.eventHash, pending.deviceId, pending.ownerId,
          pending.provenanceKeyId, pending.provenancePublicKey, pending.chainSequence, pending.chainEventHash,
          pending.leaseId, pending.pendingSequence, pending.previousHash, pending.eventHash, pending.evidenceId,
          pending.leaseExpiresAt, pending.ownerId, ...exactArtifactAuthorityBindings(artifact, nowIso)),
      env.DB.prepare("DELETE FROM native_provenance_reconciliation_queue WHERE artifact_id = ?")
        .bind(artifact.id),
    ], {
      sql: `EXISTS (SELECT 1 FROM native_evidence_manifests WHERE id = ? AND artifact_id = ?
          AND manifest_sha256 = ? AND image_sha256 = ? AND chain_sequence = ? AND chain_event_hash = ?
          AND provenance_key_id = ?)
        AND EXISTS (SELECT 1 FROM capture_devices WHERE id = ? AND chain_sequence = ?
          AND chain_event_hash = ? AND chain_pending_lease_id IS NULL)
        AND EXISTS (SELECT 1 FROM users WHERE id = ? AND status = 'active'
          AND role IN ('admin', 'compliance_lead'))
        AND EXISTS (SELECT 1 FROM evidence_artifacts e WHERE ${exactArtifactAuthoritySql})
        AND NOT EXISTS (SELECT 1 FROM native_provenance_reconciliation_queue WHERE artifact_id = ?)`,
      bindings: [manifestIdentity, artifact.id, artifact.manifestSha256, artifact.imageSha256,
        pending.pendingSequence, pending.eventHash, pending.provenanceKeyId, pending.deviceId,
        pending.pendingSequence, pending.eventHash, pending.ownerId,
        ...exactArtifactAuthorityBindings(artifact, nowIso), artifact.id],
    });
    if (changes.length !== 3 || changes.slice(0, 2).some((change) => !change.meta.changes)) {
      throw new Error("Native reconciliation did not commit every exact chain fact.");
    }
    return true;
  } catch (error) {
    if (await exactExisting()) return false;
    throw error;
  }
}

async function releaseExpiredReservation(
  pending: PendingAuthority,
  nowIso: string,
  reason: "ARTIFACT_NOT_FOUND" | "DEVICE_OR_OWNER_REVOKED" | "CHAIN_AUTHORITY_MISMATCH" | "PINNED_KEY_INVALID",
): Promise<boolean> {
  const env = getEnv();
  const reasonAuthority = releaseReasonAuthority(pending, nowIso, reason);
  const [change] = await executeAuditedBatch(systemActor, "native_provenance.reservation_released", "capture_device", pending.deviceId, {
    evidenceId: pending.evidenceId,
    expiredAt: pending.leaseExpiresAt,
    reason,
    sequence: pending.pendingSequence,
  }, [
    env.DB.prepare(`UPDATE capture_devices SET chain_pending_lease_id = NULL, chain_pending_sequence = NULL,
        chain_pending_previous_hash = NULL, chain_pending_event_hash = NULL,
        chain_pending_evidence_id = NULL, chain_pending_expires_at = NULL
      WHERE id = ? AND owner_id = ? AND chain_sequence = ? AND chain_event_hash = ?
        AND status = ? AND provenance_key_id IS ? AND provenance_public_key IS ?
        AND chain_pending_lease_id = ? AND chain_pending_sequence = ? AND chain_pending_previous_hash = ?
        AND chain_pending_event_hash = ? AND chain_pending_evidence_id = ? AND chain_pending_expires_at = ?
        AND unixepoch(chain_pending_expires_at) <= unixepoch(?) AND (${reasonAuthority.sql})`)
      .bind(pending.deviceId, pending.ownerId, pending.chainSequence, pending.chainEventHash,
        pending.deviceStatus, pending.provenanceKeyId, pending.provenancePublicKey,
        pending.leaseId, pending.pendingSequence, pending.previousHash, pending.eventHash,
        pending.evidenceId, pending.leaseExpiresAt, nowIso, ...reasonAuthority.bindings),
  ], {
    sql: `EXISTS (SELECT 1 FROM capture_devices WHERE id = ? AND owner_id = ? AND chain_sequence = ?
      AND chain_event_hash = ? AND status = ? AND provenance_key_id IS ? AND provenance_public_key IS ?
      AND chain_pending_lease_id IS NULL)${reasonAuthority.postconditionSql}`,
    bindings: [pending.deviceId, pending.ownerId, pending.chainSequence, pending.chainEventHash, pending.deviceStatus,
      pending.provenanceKeyId, pending.provenancePublicKey, ...reasonAuthority.postconditionBindings],
  });
  return Boolean(change?.meta.changes);
}

function releaseReasonAuthority(
  pending: PendingAuthority,
  nowIso: string,
  reason: "ARTIFACT_NOT_FOUND" | "DEVICE_OR_OWNER_REVOKED" | "CHAIN_AUTHORITY_MISMATCH" | "PINNED_KEY_INVALID",
): { sql: string; bindings: unknown[]; postconditionSql: string; postconditionBindings: unknown[] } {
  const activeMembership = `status = 'active' AND EXISTS (SELECT 1 FROM users u
    WHERE u.id = capture_devices.owner_id AND u.status = 'active'
      AND u.role IN ('admin', 'compliance_lead'))`;
  const activeMembershipPostcondition = ` AND EXISTS (SELECT 1 FROM users u
    WHERE u.id = ? AND u.status = 'active' AND u.role IN ('admin', 'compliance_lead'))`;
  const matchingChain = "chain_pending_sequence = chain_sequence + 1 AND chain_pending_previous_hash = chain_event_hash";
  if (reason === "ARTIFACT_NOT_FOUND") {
    const sourcePrefix = `Scopeproof Capture / ${pending.deviceId} / ${pending.evidenceId} / %`;
    const absence = `NOT EXISTS (SELECT 1 FROM evidence_artifacts e
      WHERE e.device_id = ? AND e.created_by = ? AND e.chain_previous_hash = ? AND e.chain_event_hash = ?
        AND e.type = 'screenshot' AND e.content_type = 'image/png'
        AND e.status IN ('needs_review', 'approved', 'expiring') AND unixepoch(e.expires_at) > unixepoch(?)
        AND e.source LIKE ?
        AND NOT EXISTS (SELECT 1 FROM native_evidence_manifests n WHERE n.artifact_id = e.id))`;
    const bindings = [pending.deviceId, pending.ownerId, pending.previousHash, pending.eventHash, nowIso, sourcePrefix];
    return {
      sql: `${activeMembership} AND ${matchingChain} AND ${absence}`,
      bindings,
      postconditionSql: `${activeMembershipPostcondition} AND ${absence}`,
      postconditionBindings: [pending.ownerId, ...bindings],
    };
  }
  if (reason === "DEVICE_OR_OWNER_REVOKED") {
    const invalidMembership = `(status <> 'active' OR NOT EXISTS (SELECT 1 FROM users u
      WHERE u.id = ? AND u.status = 'active' AND u.role IN ('admin', 'compliance_lead')))`;
    const postcondition = ` AND EXISTS (SELECT 1 FROM capture_devices d WHERE d.id = ? AND
      (d.status <> 'active' OR NOT EXISTS (SELECT 1 FROM users u WHERE u.id = d.owner_id
        AND u.status = 'active' AND u.role IN ('admin', 'compliance_lead'))))`;
    return {
      sql: invalidMembership,
      bindings: [pending.ownerId],
      postconditionSql: postcondition,
      postconditionBindings: [pending.deviceId],
    };
  }
  if (reason === "CHAIN_AUTHORITY_MISMATCH") {
    return {
      sql: `${activeMembership} AND (chain_pending_sequence <> chain_sequence + 1 OR chain_pending_previous_hash <> chain_event_hash)`,
      bindings: [],
      postconditionSql: activeMembershipPostcondition,
      postconditionBindings: [pending.ownerId],
    };
  }
  // The cryptographic key mismatch is proven before mutation; exact equality
  // on both observed key fields above makes any concurrent repair lose the CAS.
  return {
    sql: `${activeMembership} AND ${matchingChain}`,
    bindings: [],
    postconditionSql: activeMembershipPostcondition,
    postconditionBindings: [pending.ownerId],
  };
}

function isTerminalQueueArtifact(row: OrphanArtifactRow): boolean {
  return typeof row.status === "string" && terminalArtifactStatuses.has(row.status);
}

async function drainReconciliationQueueEntry(
  row: OrphanArtifactRow,
  nowIso: string,
  reason: "FINALIZED" | "ARTIFACT_MISSING" | "ARTIFACT_NO_LONGER_ELIGIBLE",
): Promise<boolean> {
  const env = getEnv();
  const queueArtifactId = exactCursorId(row.queue_artifact_id, "queue artifact identifier");
  const queueDueAt = canonicalTextInstant(row.queue_due_at, "queue due time");
  if (Date.parse(queueDueAt) > Date.parse(nowIso)) throw new Error("A future native queue entry cannot be drained.");
  let authoritySql: string;
  let authorityBindings: unknown[];
  if (reason === "FINALIZED") {
    authoritySql = "EXISTS (SELECT 1 FROM native_evidence_manifests n WHERE n.artifact_id = ?)";
    authorityBindings = [queueArtifactId];
  } else if (reason === "ARTIFACT_MISSING") {
    authoritySql = "NOT EXISTS (SELECT 1 FROM evidence_artifacts e WHERE e.id = ?)";
    authorityBindings = [queueArtifactId];
  } else {
    const terminalStatus = exactBoundedText(row.status, 32, "terminal queue artifact status");
    if (!terminalArtifactStatuses.has(terminalStatus)) throw new Error("Native queue artifact is not terminal.");
    authoritySql = "EXISTS (SELECT 1 FROM evidence_artifacts e WHERE e.id = ? AND e.status = ?)";
    authorityBindings = [queueArtifactId, terminalStatus];
  }
  const resourceId = artifactIdPattern.test(queueArtifactId)
    ? queueArtifactId
    : `native_queue_${await sha256(queueArtifactId)}`;
  const [change] = await executeAuditedBatch(systemActor, "native_provenance.queue_entry_drained", "maintenance_state", resourceId, {
    dueAt: queueDueAt,
    reason,
  }, [
    env.DB.prepare(`DELETE FROM native_provenance_reconciliation_queue
      WHERE artifact_id = ? AND due_at = ? AND unixepoch(due_at) <= unixepoch(?)
        AND (${authoritySql})`)
      .bind(queueArtifactId, queueDueAt, nowIso, ...authorityBindings),
  ], {
    sql: `NOT EXISTS (SELECT 1 FROM native_provenance_reconciliation_queue
        WHERE artifact_id = ? AND due_at = ?)
      AND (${authoritySql})`,
    bindings: [queueArtifactId, queueDueAt, ...authorityBindings],
  });
  return Boolean(change?.meta.changes);
}

async function quarantineOrphanArtifact(row: OrphanArtifactRow, nowIso: string, cutoff: string): Promise<boolean> {
  const queueArtifactId = exactCursorId(row.queue_artifact_id, "queue artifact identifier");
  const queueDueAt = canonicalTextInstant(row.queue_due_at, "queue due time");
  const id = exactPattern(row.id, artifactIdPattern, "orphan artifact identifier");
  if (queueArtifactId !== id || Date.parse(queueDueAt) > Date.parse(nowIso)) {
    throw new Error("Orphan evidence queue authority is invalid.");
  }
  const deviceId = exactPattern(row.device_id, deviceIdPattern, "orphan device identifier");
  if (row.type !== "screenshot" || row.content_type !== "image/png") throw new Error("Orphan evidence type is invalid.");
  const source = exactBoundedText(row.source, 512, "orphan artifact source");
  if (!source.startsWith(`Scopeproof Capture / ${deviceId} / `)) throw new Error("Orphan evidence source is not bound to its device.");
  const status = exactBoundedText(row.status, 32, "orphan artifact status");
  if (!activeArtifactStatuses.has(status)) throw new Error("Orphan artifact status is invalid.");
  const imageSha256 = exactPattern(row.sha256, digestPattern, "orphan image digest");
  const manifestSha256 = exactPattern(row.manifest_sha256, digestPattern, "orphan manifest digest");
  // D1's CURRENT_TIMESTAMP default is the exact UTC form
  // `YYYY-MM-DD HH:MM:SS`, while explicitly supplied historical rows may use
  // canonical ISO. Preserve the observed text for the mutation CAS and let
  // SQLite's unixepoch() provide the age authority; JavaScript would otherwise
  // interpret the space-separated form in the host's local timezone.
  const createdAt = exactBoundedText(row.created_at, 32, "orphan creation time");
  const changes = await executeAuditedBatch(systemActor, "native_provenance.artifact_quarantined", "evidence", id, {
    detectedAt: nowIso,
    deviceId,
    reason: "MISSING_FINALIZED_CHAIN_LINK",
  }, [
    getEnv().DB.prepare(`UPDATE evidence_artifacts SET status = 'returned', approved_by = NULL, approved_at = NULL
      WHERE id = ? AND device_id = ? AND source = ? AND status = ? AND sha256 = ? AND manifest_sha256 = ?
        AND created_at = ? AND unixepoch(created_at) <= unixepoch(?)
        AND EXISTS (SELECT 1 FROM native_provenance_reconciliation_queue q
          WHERE q.artifact_id = evidence_artifacts.id AND q.due_at = ?
            AND unixepoch(q.due_at) <= unixepoch(?))
        AND NOT EXISTS (SELECT 1 FROM native_evidence_manifests n WHERE n.artifact_id = evidence_artifacts.id)
        AND NOT EXISTS (SELECT 1 FROM capture_devices d WHERE d.id = evidence_artifacts.device_id
          AND d.chain_pending_lease_id IS NOT NULL)`)
      .bind(id, deviceId, source, status, imageSha256, manifestSha256, createdAt, cutoff, queueDueAt, nowIso),
    getEnv().DB.prepare(`DELETE FROM native_provenance_reconciliation_queue
      WHERE artifact_id = ? AND due_at = ?
        AND EXISTS (SELECT 1 FROM evidence_artifacts e WHERE e.id = ? AND e.status = 'returned')`)
      .bind(id, queueDueAt, id),
  ], {
    sql: `EXISTS (SELECT 1 FROM evidence_artifacts e WHERE e.id = ? AND e.status = 'returned'
      AND e.device_id = ? AND e.source = ? AND e.sha256 = ? AND e.manifest_sha256 = ? AND e.created_at = ?
      AND e.approved_by IS NULL AND e.approved_at IS NULL
      AND NOT EXISTS (SELECT 1 FROM native_evidence_manifests n WHERE n.artifact_id = e.id)
      AND NOT EXISTS (SELECT 1 FROM capture_devices d WHERE d.id = e.device_id
        AND d.chain_pending_lease_id IS NOT NULL))
      AND NOT EXISTS (SELECT 1 FROM native_provenance_reconciliation_queue WHERE artifact_id = ?)`,
    bindings: [id, deviceId, source, imageSha256, manifestSha256, createdAt, id],
  });
  if (changes.length !== 2 || changes.some((change) => !change.meta.changes)) {
    throw new Error("Native artifact quarantine did not drain its exact queue authority.");
  }
  return true;
}

function exactPattern(value: unknown, pattern: RegExp, label: string): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`Native reconciliation ${label} is malformed.`);
  return value;
}

function exactBoundedText(value: unknown, maximum: number, label: string): string {
  if (typeof value !== "string" || value.length < 1 || value.length > maximum || value !== value.trim()) {
    throw new Error(`Native reconciliation ${label} is malformed.`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) throw new Error(`Native reconciliation ${label} is malformed.`);
  }
  return value;
}

function exactCursorId(value: unknown, label: string): string {
  // The cursor must be able to step past a malformed application identifier;
  // requiring only SQLite's actual TEXT type prevents that row from pinning a
  // page while every comparison and write remains parameter-bound.
  if (typeof value !== "string") throw new Error(`Native reconciliation ${label} is malformed.`);
  return value;
}

function exactBooleanInteger(value: unknown, label: string): boolean {
  if (value !== 0 && value !== 1) throw new Error(`Native reconciliation ${label} is malformed.`);
  return value === 1;
}

function exactInteger(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new Error(`Native reconciliation ${label} is malformed.`);
  }
  return Number(value);
}

function exactChainHash(value: unknown, sequence: number, label: string): string {
  if ((sequence === 0 && value === "GENESIS") || (sequence > 0 && typeof value === "string" && digestPattern.test(value))) {
    return value as string;
  }
  throw new Error(`Native reconciliation ${label} is malformed.`);
}

function canonicalTextInstant(value: unknown, label: string): string {
  if (typeof value !== "string") throw new Error(`Native reconciliation ${label} is malformed.`);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`Native reconciliation ${label} is malformed.`);
  }
  return value;
}

function canonicalDate(value: Date, label: string): string {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) throw new Error(`${label} is invalid.`);
  return value.toISOString();
}
