import { base64ToBytes, randomId, sha256, signPackage, stableJson } from "./crypto";
import {
  CHECKPOINT_DELIVERY_CLAIM_LEASE_MS,
  CHECKPOINT_DELIVERY_CLAIM_SQL,
  CHECKPOINT_DELIVERY_MAX_ATTEMPTS,
  checkpointDeliveryBackoffMs,
  classifyCheckpointDelivery,
  type CheckpointDeliveryAttemptState,
  type ExpectedCheckpointDelivery,
} from "./checkpoint-delivery-retry";
import { getEnv, requireEnv } from "./env";
import { auditCheckpointEndpoint } from "./external-trust-config";
import { boundedFetch } from "./outbound";

export { validateAuditCheckpointConfiguration } from "./external-trust-config";

type AuditHead = { sequence: number; event_hash: string; hmac_key_id: string };
type CheckpointRow = Record<string, unknown>;
type DeliveryAttemptRow = Record<string, unknown>;
type DeliveryRetryStateRow = {
  checkpoint_id: string;
  checkpoint_sha256: string;
  status: "retrying" | "claimed" | "action_required" | "delivered";
  attempt_count: number;
  next_attempt_at: string | null;
  lease_id: string | null;
  lease_expires_at: string | null;
  endpoint_origin: string | null;
  last_attempt_id: string | null;
  last_attempt_at: string | null;
  last_failure_code: string | null;
  delivered_attempt_id: string | null;
};
type DeliveryClaim = {
  attemptId: string;
  leaseId: string;
  attemptedAt: string;
  endpointOrigin: string;
  attemptCount: number;
};
type DeliveryFailureCode =
  | "AUDIT_HEAD_CHANGED"
  | "CHECKPOINT_CORE_INVALID"
  | "DELIVERY_REQUEST_FAILED"
  | "ENDPOINT_HTTP_ERROR"
  | "EXTERNAL_RECEIPT_INVALID"
  | "RECEIPT_BINDING_FAILED"
  | "RECEIPT_STORAGE_FAILED"
  | "DELIVERY_COMMIT_PRECONDITION_FAILED"
  | "DELIVERY_CLAIM_EXPIRED";

const CHECKPOINT_COLUMNS = `id, sequence, event_hash, event_count, hmac_key_id, checkpoint_sha256, signature,
  public_key_fingerprint, r2_key, external_status, external_receipt, external_receipt_sha256,
  external_receipt_signature, external_receipt_r2_key, created_at`;
const DELIVERY_ATTEMPT_COLUMNS = `id, checkpoint_id, checkpoint_sha256, sequence, endpoint_origin, attempted_at, status,
  external_receipt, external_receipt_sha256, external_receipt_signature, external_receipt_r2_key, failure_code, created_at`;
const DELIVERY_RETRY_STATE_COLUMNS = `checkpoint_id, checkpoint_sha256, status, attempt_count, next_attempt_at,
  lease_id, lease_expires_at, endpoint_origin, last_attempt_id, last_attempt_at, last_failure_code, delivered_attempt_id`;
const exactBuffer = (bytes: Uint8Array): ArrayBuffer => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

export type AuditCheckpoint = {
  id: string;
  sequence: number;
  eventHash: string;
  eventCount: number;
  hmacKeyId: string;
  checkpointSha256: string;
  signature: string;
  publicKey: string;
  publicKeyFingerprint: string;
  r2Key: string;
  externalStatus: "delivered" | "not_configured" | "failed";
  externalReceipt: string | null;
  externalReceiptSha256: string | null;
  externalReceiptSignature: string | null;
  externalReceiptR2Key: string | null;
  externalDeliveryAttemptId: string | null;
  externalFailureCode: string | null;
  createdAt: string;
};

type ExternalCheckpointReceipt = { version: 1; checkpointSha256: string; sequence: number; receivedAt: string; receiptId: string; signature: string };
type VerifiedCheckpointCore = { envelope: Record<string, unknown>; envelopeText: string; publicKey: string };

class CheckpointDeliveryError extends Error {
  constructor(readonly code: DeliveryFailureCode) {
    super(code);
    this.name = "CheckpointDeliveryError";
  }
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

async function verifyP256Signature(publicKeyBase64: string, signatureBase64: string, payload: string): Promise<boolean> {
  try {
    const signature = base64ToBytes(signatureBase64);
    if (signature.byteLength !== 64) return false;
    const key = await crypto.subtle.importKey("spki", exactBuffer(base64ToBytes(publicKeyBase64)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, exactBuffer(signature), exactBuffer(new TextEncoder().encode(payload)));
  } catch { return false; }
}

async function verifyExternalReceipt(receipt: ExternalCheckpointReceipt, checkpointSha256: string, sequence: number): Promise<boolean> {
  if (!hasExactKeys(receipt as unknown as Record<string, unknown>, ["version", "checkpointSha256", "sequence", "receivedAt", "receiptId", "signature"])) return false;
  if (receipt.version !== 1 || receipt.checkpointSha256 !== checkpointSha256 || receipt.sequence !== sequence
    || !/^receipt_[A-Za-z0-9._:-]{8,160}$/.test(receipt.receiptId) || !Number.isFinite(Date.parse(receipt.receivedAt))) return false;
  const unsigned = stableJson({ version: receipt.version, checkpointSha256: receipt.checkpointSha256, sequence: receipt.sequence, receivedAt: receipt.receivedAt, receiptId: receipt.receiptId });
  return verifyP256Signature(requireEnv("AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY"), receipt.signature, unsigned);
}

async function deliverCheckpoint(url: URL, token: string | undefined, body: string, checkpointSha256: string, sequence: number): Promise<ExternalCheckpointReceipt> {
  let response: Response;
  try {
    response = await boundedFetch(url, {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json", "idempotency-key": checkpointSha256, ...(token ? { authorization: `Bearer ${token}` } : {}) },
      body,
    }, { label: "Audit checkpoint", allowedOrigins: [url.origin], maximumBytes: 64_000, timeoutMs: 15_000 });
  } catch { throw new CheckpointDeliveryError("DELIVERY_REQUEST_FAILED"); }
  if (!response.ok) throw new CheckpointDeliveryError("ENDPOINT_HTTP_ERROR");
  const text = await response.text();
  if (text.length > 8_000) throw new CheckpointDeliveryError("EXTERNAL_RECEIPT_INVALID");
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { throw new CheckpointDeliveryError("EXTERNAL_RECEIPT_INVALID"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new CheckpointDeliveryError("EXTERNAL_RECEIPT_INVALID");
  const value = parsed as Record<string, unknown>;
  if (!hasExactKeys(value, ["version", "checkpointSha256", "sequence", "receivedAt", "receiptId", "signature"])) throw new CheckpointDeliveryError("EXTERNAL_RECEIPT_INVALID");
  const receipt: ExternalCheckpointReceipt = { version: Number(value.version) as 1, checkpointSha256: String(value.checkpointSha256 || ""), sequence: Number(value.sequence), receivedAt: String(value.receivedAt || ""), receiptId: String(value.receiptId || ""), signature: String(value.signature || "") };
  if (!await verifyExternalReceipt(receipt, checkpointSha256, sequence)) throw new CheckpointDeliveryError("EXTERNAL_RECEIPT_INVALID");
  return receipt;
}

async function loadCheckpointForSequence(sequence: number): Promise<CheckpointRow | null> {
  return getEnv().DB.prepare(`SELECT ${CHECKPOINT_COLUMNS} FROM audit_checkpoints WHERE sequence = ?`).bind(sequence).first<CheckpointRow>();
}

async function loadLatestCheckpointRow(): Promise<CheckpointRow | null> {
  return getEnv().DB.prepare(`SELECT ${CHECKPOINT_COLUMNS} FROM audit_checkpoints ORDER BY sequence DESC LIMIT 1`).first<CheckpointRow>();
}

async function loadDeliveredAttempt(checkpointId: string): Promise<DeliveryAttemptRow | null> {
  return getEnv().DB.prepare(`SELECT ${DELIVERY_ATTEMPT_COLUMNS} FROM audit_checkpoint_delivery_attempts
    WHERE checkpoint_id = ? AND status = 'delivered' LIMIT 1`).bind(checkpointId).first<DeliveryAttemptRow>();
}

async function loadLatestFailedAttempt(checkpointId: string): Promise<DeliveryAttemptRow | null> {
  return getEnv().DB.prepare(`SELECT ${DELIVERY_ATTEMPT_COLUMNS} FROM audit_checkpoint_delivery_attempts
    WHERE checkpoint_id = ? AND status = 'failed' ORDER BY created_at DESC, id DESC LIMIT 1`).bind(checkpointId).first<DeliveryAttemptRow>();
}

async function loadAttemptById(attemptId: string): Promise<DeliveryAttemptRow | null> {
  return getEnv().DB.prepare(`SELECT ${DELIVERY_ATTEMPT_COLUMNS} FROM audit_checkpoint_delivery_attempts WHERE id = ?`)
    .bind(attemptId).first<DeliveryAttemptRow>();
}

async function loadDeliveryRetryState(checkpointId: string): Promise<DeliveryRetryStateRow | null> {
  return getEnv().DB.prepare(`SELECT ${DELIVERY_RETRY_STATE_COLUMNS} FROM audit_checkpoint_delivery_retry_state WHERE checkpoint_id = ?`)
    .bind(checkpointId).first<DeliveryRetryStateRow>();
}

function failedAttemptMatches(row: DeliveryAttemptRow | null, checkpoint: CheckpointRow, claim: DeliveryClaim, code: DeliveryFailureCode, completedAt: string): boolean {
  return Boolean(row && String(row.id) === claim.attemptId && String(row.checkpoint_id) === String(checkpoint.id)
    && String(row.checkpoint_sha256) === String(checkpoint.checkpoint_sha256) && Number(row.sequence) === Number(checkpoint.sequence)
    && String(row.endpoint_origin) === claim.endpointOrigin && String(row.attempted_at) === claim.attemptedAt
    && String(row.status) === "failed" && row.external_receipt == null && row.external_receipt_sha256 == null
    && row.external_receipt_signature == null && row.external_receipt_r2_key == null
    && String(row.failure_code) === code && String(row.created_at) === completedAt);
}

async function deliveryRetryState(checkpointId: string): Promise<{ exhausted: boolean; failureCount: number }> {
  const state = await loadDeliveryRetryState(checkpointId);
  if (!state) return { exhausted: true, failureCount: CHECKPOINT_DELIVERY_MAX_ATTEMPTS };
  const attemptCount = Number(state.attempt_count);
  return {
    exhausted: state.status === "action_required" || !Number.isSafeInteger(attemptCount) || attemptCount >= CHECKPOINT_DELIVERY_MAX_ATTEMPTS,
    failureCount: Number.isSafeInteger(attemptCount) ? attemptCount : CHECKPOINT_DELIVERY_MAX_ATTEMPTS,
  };
}

async function completeFailedClaim(
  row: CheckpointRow,
  claim: DeliveryClaim,
  code: DeliveryFailureCode,
  completedAt = new Date().toISOString(),
): Promise<"committed" | "not_owner" | "uncertain"> {
  let responseCertain = true;
  let changes = 0;
  try {
    const inserted = await getEnv().DB.prepare(`INSERT INTO audit_checkpoint_delivery_attempts
      (id, checkpoint_id, checkpoint_sha256, sequence, endpoint_origin, attempted_at, status, failure_code, created_at)
      SELECT ?, checkpoint.id, checkpoint.checkpoint_sha256, checkpoint.sequence, ?, ?, 'failed', ?, ?
      FROM audit_checkpoint_delivery_retry_state retry
      JOIN audit_checkpoints checkpoint ON checkpoint.id = retry.checkpoint_id
      WHERE retry.checkpoint_id = ? AND retry.checkpoint_sha256 = ?
        AND retry.status = 'claimed' AND retry.lease_id = ? AND retry.last_attempt_id = ?
        AND retry.last_attempt_at = ? AND retry.endpoint_origin = ?
        AND checkpoint.sequence = ? AND checkpoint.external_status <> 'delivered'
        AND NOT EXISTS (SELECT 1 FROM audit_checkpoint_delivery_attempts delivered
          WHERE delivered.checkpoint_id = retry.checkpoint_id AND delivered.status = 'delivered')`)
      .bind(claim.attemptId, claim.endpointOrigin, claim.attemptedAt, code, completedAt,
        row.id, row.checkpoint_sha256, claim.leaseId, claim.attemptId, claim.attemptedAt, claim.endpointOrigin, row.sequence).run();
    changes = Number(inserted.meta.changes || 0);
  } catch {
    responseCertain = false;
  }
  try {
    const authoritative = await loadAttemptById(claim.attemptId);
    if (failedAttemptMatches(authoritative, row, claim, code, completedAt)) {
      console.error(claim.attemptCount >= CHECKPOINT_DELIVERY_MAX_ATTEMPTS
        ? "scopeproof_audit_checkpoint_delivery_action_required"
        : "scopeproof_audit_checkpoint_delivery_failure", {
        checkpointId: String(row.id), sequence: Number(row.sequence), attemptId: claim.attemptId, code, failureCount: claim.attemptCount,
      });
      return "committed";
    }
    return responseCertain && changes === 0 ? "not_owner" : "uncertain";
  } catch {
    return "uncertain";
  }
}

async function ensureDeliveryRetryState(row: CheckpointRow, now: Date): Promise<DeliveryRetryStateRow | null> {
  const at = now.toISOString();
  try {
    await getEnv().DB.prepare(`INSERT INTO audit_checkpoint_delivery_retry_state
      (checkpoint_id, checkpoint_sha256, status, attempt_count, next_attempt_at, created_at, updated_at)
      SELECT id, checkpoint_sha256, 'retrying', 0, ?, created_at, ?
      FROM audit_checkpoints
      WHERE id = ? AND checkpoint_sha256 = ? AND sequence = ? AND external_status <> 'delivered'
        AND NOT EXISTS (SELECT 1 FROM audit_checkpoint_delivery_attempts delivered
          WHERE delivered.checkpoint_id = audit_checkpoints.id AND delivered.status = 'delivered')
      ON CONFLICT(checkpoint_id) DO NOTHING`)
      .bind(at, at, row.id, row.checkpoint_sha256, row.sequence).run();
  } catch {
    // The INSERT response can be ambiguous. The authoritative identity-bound
    // read below decides whether it is safe to continue.
  }
  try {
    const state = await loadDeliveryRetryState(String(row.id));
    return state && state.checkpoint_sha256 === String(row.checkpoint_sha256) ? state : null;
  } catch {
    return null;
  }
}

async function recoverExpiredDeliveryClaim(row: CheckpointRow, state: DeliveryRetryStateRow, now: Date): Promise<boolean> {
  if (state.status !== "claimed") return true;
  const leaseExpiry = Date.parse(String(state.lease_expires_at || ""));
  if (!Number.isFinite(leaseExpiry) || leaseExpiry > now.getTime() || !state.lease_id || !state.last_attempt_id
    || !state.last_attempt_at || !state.endpoint_origin) return false;
  const claim: DeliveryClaim = {
    attemptId: state.last_attempt_id,
    leaseId: state.lease_id,
    attemptedAt: state.last_attempt_at,
    endpointOrigin: state.endpoint_origin,
    attemptCount: Number(state.attempt_count),
  };
  const completion = await completeFailedClaim(row, claim, "DELIVERY_CLAIM_EXPIRED", now.toISOString());
  if (completion === "uncertain") return false;
  try {
    const authoritative = await loadDeliveryRetryState(String(row.id));
    return Boolean(authoritative && authoritative.checkpoint_sha256 === String(row.checkpoint_sha256)
      && authoritative.status !== "claimed");
  } catch {
    return false;
  }
}

async function claimCheckpointDelivery(row: CheckpointRow, endpointOrigin: string, now: Date): Promise<DeliveryClaim | null> {
  let state = await ensureDeliveryRetryState(row, now);
  if (!state || state.status === "delivered" || state.status === "action_required") return null;
  if (state.status === "claimed") {
    if (!await recoverExpiredDeliveryClaim(row, state, now)) return null;
    state = await loadDeliveryRetryState(String(row.id));
    if (!state || state.status !== "retrying") return null;
  }
  if (state.status !== "retrying" || Number(state.attempt_count) >= CHECKPOINT_DELIVERY_MAX_ATTEMPTS) return null;
  const dueAt = Date.parse(String(state.next_attempt_at || ""));
  if (!Number.isFinite(dueAt) || dueAt > now.getTime()) return null;

  const attemptCount = Number(state.attempt_count) + 1;
  const attemptId = randomId("checkpoint_delivery");
  const leaseId = randomId("checkpoint_delivery_lease");
  const attemptedAt = now.toISOString();
  const leaseExpiresAt = new Date(now.getTime() + CHECKPOINT_DELIVERY_CLAIM_LEASE_MS).toISOString();
  const nextAttemptAt = new Date(now.getTime() + checkpointDeliveryBackoffMs(attemptCount)).toISOString();
  try {
    await getEnv().DB.prepare(CHECKPOINT_DELIVERY_CLAIM_SQL)
      .bind(nextAttemptAt, leaseId, leaseExpiresAt, endpointOrigin, attemptId, attemptedAt, attemptedAt,
        row.id, row.checkpoint_sha256, state.attempt_count, CHECKPOINT_DELIVERY_MAX_ATTEMPTS, attemptedAt).run();
  } catch {
    // Lost D1 responses are resolved by the exact-claim read below. If that
    // read also fails, this invocation performs no outbound request and the
    // expiring claim is recovered by a later invocation.
  }
  try {
    const claimed = await loadDeliveryRetryState(String(row.id));
    if (claimed?.status !== "claimed" || claimed.checkpoint_sha256 !== String(row.checkpoint_sha256)
      || claimed.lease_id !== leaseId || claimed.last_attempt_id !== attemptId || claimed.last_attempt_at !== attemptedAt
      || claimed.endpoint_origin !== endpointOrigin || Number(claimed.attempt_count) !== attemptCount) return null;
    return { attemptId, leaseId, attemptedAt, endpointOrigin, attemptCount };
  } catch {
    return null;
  }
}

async function currentHeadMatchesCheckpoint(row: CheckpointRow): Promise<boolean> {
  const head = await getEnv().DB.prepare("SELECT sequence, event_hash, hmac_key_id FROM audit_events ORDER BY sequence DESC LIMIT 1").first<AuditHead>();
  return Boolean(head && head.sequence === Number(row.sequence) && head.event_hash === String(row.event_hash) && head.hmac_key_id === String(row.hmac_key_id));
}

async function verifyCheckpointCore(row: CheckpointRow): Promise<{ valid: true; value: VerifiedCheckpointCore } | { valid: false; reason: string }> {
  const env = getEnv();
  const sequence = Number(row.sequence);
  const anchor = await env.DB.prepare("SELECT event_hash, hmac_key_id FROM audit_events WHERE sequence = ?").bind(sequence).first<{ event_hash: string; hmac_key_id: string }>();
  const actualCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE sequence <= ?").bind(sequence).first<{ count: number }>();
  if (!anchor || anchor.event_hash !== String(row.event_hash) || anchor.hmac_key_id !== String(row.hmac_key_id) || Number(actualCount?.count || 0) !== Number(row.event_count)) {
    return { valid: false, reason: "checkpoint_audit_anchor_mismatch" };
  }
  const object = await env.EVIDENCE_BUCKET.get(String(row.r2_key));
  if (!object) return { valid: false, reason: "missing_checkpoint_object" };
  if (Number(object.size || 0) > 64_000) return { valid: false, reason: "invalid_checkpoint_json" };
  const metadata = object.customMetadata || {};
  if (metadata.checkpointSha256 !== String(row.checkpoint_sha256) || metadata.sequence !== String(sequence)
    || metadata.publicKeyFingerprint !== String(row.public_key_fingerprint)) return { valid: false, reason: "checkpoint_object_metadata_mismatch" };
  const envelopeText = await object.text();
  if (envelopeText.length > 64_000) return { valid: false, reason: "invalid_checkpoint_json" };
  let envelope: Record<string, unknown>;
  try { envelope = JSON.parse(envelopeText) as Record<string, unknown>; }
  catch { return { valid: false, reason: "invalid_checkpoint_json" }; }
  if (!envelope || Array.isArray(envelope) || !hasExactKeys(envelope, ["version", "id", "sequence", "eventHash", "eventCount", "hmacKeyId", "createdAt", "checkpointSha256", "signatureAlgorithm", "signature", "publicKey", "publicKeyFingerprint"])) {
    return { valid: false, reason: "checkpoint_record_mismatch" };
  }
  const unsigned = { version: envelope.version, id: envelope.id, sequence: envelope.sequence, eventHash: envelope.eventHash, eventCount: envelope.eventCount, hmacKeyId: envelope.hmacKeyId, createdAt: envelope.createdAt };
  const canonical = stableJson(unsigned);
  const digest = await sha256(canonical);
  const publicKey = String(envelope.publicKey || "");
  if (publicKey !== requireEnv("PACKAGE_SIGNING_PUBLIC_KEY")) return { valid: false, reason: "untrusted_checkpoint_signing_key" };
  const fingerprint = await sha256(publicKey);
  if (Number(envelope.version) !== 1 || String(envelope.signatureAlgorithm) !== "ECDSA_P256_SHA256" || String(envelope.id) !== String(row.id)
    || Number(envelope.sequence) !== sequence || String(envelope.eventHash) !== String(row.event_hash) || Number(envelope.eventCount) !== Number(row.event_count)
    || String(envelope.hmacKeyId) !== String(row.hmac_key_id) || String(envelope.createdAt) !== String(row.created_at)
    || digest !== String(row.checkpoint_sha256) || digest !== String(envelope.checkpointSha256) || String(envelope.signature) !== String(row.signature)
    || fingerprint !== String(row.public_key_fingerprint) || fingerprint !== String(envelope.publicKeyFingerprint)) {
    return { valid: false, reason: "checkpoint_record_mismatch" };
  }
  if (!await verifyP256Signature(publicKey, String(envelope.signature || ""), canonical)) return { valid: false, reason: "invalid_checkpoint_signature" };
  return { valid: true, value: { envelope, envelopeText, publicKey } };
}

async function deleteAttemptObject(r2Key: string): Promise<void> {
  await getEnv().EVIDENCE_BUCKET.delete(r2Key);
}

async function attemptCheckpointDelivery(row: CheckpointRow, now: Date): Promise<void> {
  if (String(row.external_status) === "delivered" || await loadDeliveredAttempt(String(row.id))) return;
  let endpoint: ReturnType<typeof auditCheckpointEndpoint>;
  try { endpoint = auditCheckpointEndpoint(getEnv()); }
  catch {
    console.error("scopeproof_audit_checkpoint_configuration_invalid", { checkpointId: String(row.id), sequence: Number(row.sequence) });
    return;
  }
  if (!endpoint) return;

  // Every invocation must own one durable, expiring CAS claim before it can
  // perform outbound I/O. Concurrent jobs, an ambiguous claim response, and a
  // stale worker therefore cannot create a hot duplicate-POST loop.
  const claim = await claimCheckpointDelivery(row, endpoint.url.origin, now);
  if (!claim) return;
  if (!await currentHeadMatchesCheckpoint(row)) {
    await completeFailedClaim(row, claim, "AUDIT_HEAD_CHANGED");
    return;
  }
  const core = await verifyCheckpointCore(row);
  if (!core.valid) {
    await completeFailedClaim(row, claim, "CHECKPOINT_CORE_INVALID");
    return;
  }

  let verifiedReceipt: ExternalCheckpointReceipt;
  try { verifiedReceipt = await deliverCheckpoint(endpoint.url, endpoint.token, core.value.envelopeText, String(row.checkpoint_sha256), Number(row.sequence)); }
  catch (error) {
    const code = error instanceof CheckpointDeliveryError ? error.code : "DELIVERY_REQUEST_FAILED";
    await completeFailedClaim(row, claim, code);
    return;
  }
  if (!await currentHeadMatchesCheckpoint(row)) {
    await completeFailedClaim(row, claim, "AUDIT_HEAD_CHANGED");
    return;
  }

  const externalReceipt = stableJson(verifiedReceipt);
  const boundAt = new Date().toISOString();
  const receiptBinding = {
    version: 2,
    deliveryAttemptId: claim.attemptId,
    checkpointId: String(row.id),
    checkpointSha256: String(row.checkpoint_sha256),
    sequence: Number(row.sequence),
    endpointOrigin: claim.endpointOrigin,
    attemptedAt: claim.attemptedAt,
    externalReceipt: verifiedReceipt,
    boundAt,
  };
  const receiptCanonical = stableJson(receiptBinding);
  let receiptSigned: Awaited<ReturnType<typeof signPackage>>;
  try { receiptSigned = await signPackage(receiptCanonical); }
  catch {
    await completeFailedClaim(row, claim, "RECEIPT_BINDING_FAILED");
    return;
  }
  if (receiptSigned.publicKey !== core.value.publicKey) {
    await completeFailedClaim(row, claim, "RECEIPT_BINDING_FAILED");
    return;
  }
  const receiptEnvelope = stableJson({ ...receiptBinding, signatureAlgorithm: "ECDSA_P256_SHA256", signature: receiptSigned.signature, publicKey: receiptSigned.publicKey });
  const externalReceiptSha256 = await sha256(receiptEnvelope);
  const month = String(row.created_at).slice(0, 7);
  const externalReceiptR2Key = `audit-checkpoints/${month}/${String(row.id)}.external-receipts/${claim.attemptId}.json`;
  try {
    await getEnv().EVIDENCE_BUCKET.put(externalReceiptR2Key, receiptEnvelope, {
      httpMetadata: { contentType: "application/json" },
      customMetadata: {
        deliveryAttemptId: claim.attemptId,
        checkpointId: String(row.id),
        checkpointSha256: String(row.checkpoint_sha256),
        externalReceiptSha256,
        sequence: String(row.sequence),
      },
    });
  } catch {
    // A failed R2 response is not proof that the object was absent. Preserve
    // any uncertain candidate and let the exact claim complete as failed.
    await completeFailedClaim(row, claim, "RECEIPT_STORAGE_FAILED");
    return;
  }

  const expectedDelivery: ExpectedCheckpointDelivery = {
    attemptId: claim.attemptId,
    checkpointId: String(row.id),
    checkpointSha256: String(row.checkpoint_sha256),
    sequence: Number(row.sequence),
    endpointOrigin: claim.endpointOrigin,
    attemptedAt: claim.attemptedAt,
    externalReceipt,
    externalReceiptSha256,
    externalReceiptSignature: receiptSigned.signature,
    externalReceiptR2Key,
    createdAt: boundAt,
  };
  let responseCertain = true;
  let changes = 0;
  try {
    const inserted = await getEnv().DB.prepare(`INSERT INTO audit_checkpoint_delivery_attempts
      (id, checkpoint_id, checkpoint_sha256, sequence, endpoint_origin, attempted_at, status, external_receipt,
       external_receipt_sha256, external_receipt_signature, external_receipt_r2_key, created_at)
      SELECT ?, c.id, c.checkpoint_sha256, c.sequence, ?, ?, 'delivered', ?, ?, ?, ?, ?
      FROM audit_checkpoint_delivery_retry_state retry
      JOIN audit_checkpoints c ON c.id = retry.checkpoint_id
      WHERE retry.checkpoint_id = ? AND retry.checkpoint_sha256 = ?
        AND retry.status = 'claimed' AND retry.lease_id = ? AND retry.last_attempt_id = ?
        AND retry.last_attempt_at = ? AND retry.endpoint_origin = ?
        AND c.sequence = ? AND c.event_hash = ? AND c.hmac_key_id = ?
        AND c.external_status <> 'delivered'
        AND c.sequence = (SELECT sequence FROM audit_events ORDER BY sequence DESC LIMIT 1)
        AND c.event_hash = (SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1)
        AND c.hmac_key_id = (SELECT hmac_key_id FROM audit_events ORDER BY sequence DESC LIMIT 1)
        AND c.event_count = (SELECT COUNT(*) FROM audit_events WHERE sequence <= c.sequence)
        AND NOT EXISTS (SELECT 1 FROM audit_checkpoint_delivery_attempts d WHERE d.checkpoint_id = c.id AND d.status = 'delivered')`)
      .bind(claim.attemptId, claim.endpointOrigin, claim.attemptedAt, externalReceipt, externalReceiptSha256,
        receiptSigned.signature, externalReceiptR2Key, boundAt, row.id, row.checkpoint_sha256, claim.leaseId,
        claim.attemptId, claim.attemptedAt, claim.endpointOrigin, row.sequence, row.event_hash, row.hmac_key_id).run();
    changes = Number(inserted.meta.changes || 0);
  } catch {
    responseCertain = false;
  }

  let disposition: ReturnType<typeof classifyCheckpointDelivery> = "uncertain";
  try {
    const winner = await loadDeliveredAttempt(String(row.id));
    const authoritative: CheckpointDeliveryAttemptState | null = winner ? {
      id: String(winner.id), checkpointId: String(winner.checkpoint_id), checkpointSha256: String(winner.checkpoint_sha256),
      sequence: Number(winner.sequence), endpointOrigin: String(winner.endpoint_origin), attemptedAt: String(winner.attempted_at),
      status: String(winner.status), externalReceipt: winner.external_receipt == null ? null : String(winner.external_receipt),
      externalReceiptSha256: winner.external_receipt_sha256 == null ? null : String(winner.external_receipt_sha256),
      externalReceiptSignature: winner.external_receipt_signature == null ? null : String(winner.external_receipt_signature),
      externalReceiptR2Key: winner.external_receipt_r2_key == null ? null : String(winner.external_receipt_r2_key),
      failureCode: winner.failure_code == null ? null : String(winner.failure_code), createdAt: String(winner.created_at),
    } : null;
    disposition = classifyCheckpointDelivery(authoritative, expectedDelivery);
  } catch {
    disposition = "uncertain";
  }
  if (disposition === "committed") return;
  if (disposition === "proven_loser") {
    await deleteAttemptObject(externalReceiptR2Key);
    return;
  }
  if (!responseCertain || changes !== 0) return;

  const failed = await completeFailedClaim(row, claim, "DELIVERY_COMMIT_PRECONDITION_FAILED");
  if (failed === "committed") await deleteAttemptObject(externalReceiptR2Key);
}

function legacyDelivery(row: CheckpointRow): Pick<AuditCheckpoint, "externalStatus" | "externalReceipt" | "externalReceiptSha256" | "externalReceiptSignature" | "externalReceiptR2Key" | "externalDeliveryAttemptId" | "externalFailureCode"> {
  return {
    externalStatus: String(row.external_status) as AuditCheckpoint["externalStatus"],
    externalReceipt: row.external_receipt ? String(row.external_receipt) : null,
    externalReceiptSha256: row.external_receipt_sha256 ? String(row.external_receipt_sha256) : null,
    externalReceiptSignature: row.external_receipt_signature ? String(row.external_receipt_signature) : null,
    externalReceiptR2Key: row.external_receipt_r2_key ? String(row.external_receipt_r2_key) : null,
    externalDeliveryAttemptId: null,
    externalFailureCode: String(row.external_status) === "failed" ? "LEGACY_DELIVERY_FAILED" : null,
  };
}

async function effectiveDelivery(row: CheckpointRow): Promise<Pick<AuditCheckpoint, "externalStatus" | "externalReceipt" | "externalReceiptSha256" | "externalReceiptSignature" | "externalReceiptR2Key" | "externalDeliveryAttemptId" | "externalFailureCode">> {
  if (String(row.external_status) === "delivered") return legacyDelivery(row);
  const delivered = await loadDeliveredAttempt(String(row.id));
  if (delivered) {
    return {
      externalStatus: "delivered",
      externalReceipt: delivered.external_receipt ? String(delivered.external_receipt) : null,
      externalReceiptSha256: delivered.external_receipt_sha256 ? String(delivered.external_receipt_sha256) : null,
      externalReceiptSignature: delivered.external_receipt_signature ? String(delivered.external_receipt_signature) : null,
      externalReceiptR2Key: delivered.external_receipt_r2_key ? String(delivered.external_receipt_r2_key) : null,
      externalDeliveryAttemptId: String(delivered.id),
      externalFailureCode: null,
    };
  }
  const failed = await loadLatestFailedAttempt(String(row.id));
  if (failed) {
    const retry = await deliveryRetryState(String(row.id));
    return { externalStatus: "failed", externalReceipt: null, externalReceiptSha256: null, externalReceiptSignature: null, externalReceiptR2Key: null, externalDeliveryAttemptId: String(failed.id), externalFailureCode: retry.exhausted ? "DELIVERY_RETRY_EXHAUSTED" : String(failed.failure_code || "DELIVERY_FAILED") };
  }
  return legacyDelivery(row);
}

export async function createAuditCheckpoint(now = new Date()): Promise<AuditCheckpoint | null> {
  const env = getEnv();
  const head = await env.DB.prepare("SELECT sequence, event_hash, hmac_key_id FROM audit_events ORDER BY sequence DESC LIMIT 1").first<AuditHead>();
  if (!head) return null;
  const existing = await loadCheckpointForSequence(head.sequence);
  if (existing) {
    if (String(existing.event_hash) !== head.event_hash || String(existing.hmac_key_id) !== head.hmac_key_id) throw new Error("The immutable checkpoint does not match the current audit head.");
    await attemptCheckpointDelivery(existing, now);
    return getLatestAuditCheckpoint();
  }
  const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE sequence <= ?").bind(head.sequence).first<{ count: number }>();
  const createdAt = now.toISOString();
  const id = randomId("checkpoint");
  const unsigned = {
    version: 1,
    id,
    sequence: head.sequence,
    eventHash: head.event_hash,
    eventCount: Number(count?.count || 0),
    hmacKeyId: head.hmac_key_id || "legacy-v1",
    createdAt,
  };
  const canonical = stableJson(unsigned);
  const checkpointSha256 = await sha256(canonical);
  const signed = await signPackage(canonical);
  const publicKeyFingerprint = await sha256(signed.publicKey);
  const envelope = stableJson({ ...unsigned, checkpointSha256, signatureAlgorithm: "ECDSA_P256_SHA256", signature: signed.signature, publicKey: signed.publicKey, publicKeyFingerprint });
  const month = createdAt.slice(0, 7);
  const r2Key = `audit-checkpoints/${month}/${id}.json`;
  await env.EVIDENCE_BUCKET.put(r2Key, envelope, {
    httpMetadata: { contentType: "application/json" },
    customMetadata: { checkpointSha256, sequence: String(head.sequence), publicKeyFingerprint },
  });

  let checkpoint: CheckpointRow;
  try {
    await env.DB.prepare(`INSERT INTO audit_checkpoints
      (id, sequence, event_hash, event_count, hmac_key_id, checkpoint_sha256, signature, public_key_fingerprint, r2_key, external_status, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'not_configured', ?)`).bind(id, head.sequence, head.event_hash, unsigned.eventCount, unsigned.hmacKeyId, checkpointSha256, signed.signature, publicKeyFingerprint, r2Key, createdAt).run();
    const inserted = await loadCheckpointForSequence(head.sequence);
    if (!inserted) throw new Error("The committed audit checkpoint could not be reloaded.");
    checkpoint = inserted;
  } catch (error) {
    const winner = await loadCheckpointForSequence(head.sequence);
    if (!winner) throw error;
    // A D1 response may be ambiguous after the INSERT committed. Preserve the
    // object when our own immutable row won; only a true race loser may remove
    // the object it created.
    const ownCommittedRow = String(winner.id) === id && String(winner.r2_key) === r2Key
      && String(winner.checkpoint_sha256) === checkpointSha256;
    if (!ownCommittedRow) await env.EVIDENCE_BUCKET.delete(r2Key);
    if (String(winner.event_hash) !== head.event_hash || String(winner.hmac_key_id) !== head.hmac_key_id) throw new Error("The winning immutable checkpoint does not match the audit head.");
    checkpoint = winner;
  }
  await attemptCheckpointDelivery(checkpoint, now);
  return getLatestAuditCheckpoint();
}

export async function getLatestAuditCheckpoint(): Promise<AuditCheckpoint | null> {
  const row = await loadLatestCheckpointRow();
  if (!row) return null;
  const object = await getEnv().EVIDENCE_BUCKET.get(String(row.r2_key));
  let publicKey = "";
  if (object && Number(object.size || 0) <= 64_000) {
    try { publicKey = String((JSON.parse(await object.text()) as { publicKey?: string }).publicKey || ""); } catch { publicKey = ""; }
  }
  const delivery = await effectiveDelivery(row);
  return {
    id: String(row.id), sequence: Number(row.sequence), eventHash: String(row.event_hash), eventCount: Number(row.event_count),
    hmacKeyId: String(row.hmac_key_id), checkpointSha256: String(row.checkpoint_sha256), signature: String(row.signature),
    publicKey, publicKeyFingerprint: String(row.public_key_fingerprint), r2Key: String(row.r2_key), ...delivery,
    createdAt: String(row.created_at),
  };
}

async function verifyLegacyDelivery(row: CheckpointRow, publicKey: string): Promise<{ valid: boolean; reason?: string }> {
  if (!row.external_receipt || !row.external_receipt_sha256 || !row.external_receipt_signature || !row.external_receipt_r2_key) return { valid: false, reason: "missing_signed_external_receipt" };
  const externalReceiptText = String(row.external_receipt);
  if (externalReceiptText.length > 8_000) return { valid: false, reason: "invalid_external_receipt_json" };
  let externalReceipt: ExternalCheckpointReceipt;
  try { externalReceipt = JSON.parse(externalReceiptText) as ExternalCheckpointReceipt; }
  catch { return { valid: false, reason: "invalid_external_receipt_json" }; }
  if (!await verifyExternalReceipt(externalReceipt, String(row.checkpoint_sha256), Number(row.sequence))) return { valid: false, reason: "invalid_external_receipt_signature" };
  const receiptObject = await getEnv().EVIDENCE_BUCKET.get(String(row.external_receipt_r2_key));
  if (!receiptObject || Number(receiptObject.size || 0) > 64_000) return { valid: false, reason: "missing_external_receipt_object" };
  const receiptText = await receiptObject.text();
  if (receiptText.length > 64_000 || await sha256(receiptText) !== String(row.external_receipt_sha256)) return { valid: false, reason: "external_receipt_digest_mismatch" };
  let receiptEnvelope: Record<string, unknown>;
  try { receiptEnvelope = JSON.parse(receiptText) as Record<string, unknown>; }
  catch { return { valid: false, reason: "invalid_external_receipt_envelope" }; }
  if (!receiptEnvelope || Array.isArray(receiptEnvelope) || !hasExactKeys(receiptEnvelope, ["version", "checkpointId", "checkpointSha256", "sequence", "externalReceipt", "boundAt", "signatureAlgorithm", "signature", "publicKey"])) return { valid: false, reason: "external_receipt_binding_mismatch" };
  const receiptBinding = { version: receiptEnvelope.version, checkpointId: receiptEnvelope.checkpointId, checkpointSha256: receiptEnvelope.checkpointSha256, sequence: receiptEnvelope.sequence, externalReceipt: receiptEnvelope.externalReceipt, boundAt: receiptEnvelope.boundAt };
  const receiptCanonical = stableJson(receiptBinding);
  if (Number(receiptEnvelope.version) !== 1 || String(receiptEnvelope.signatureAlgorithm) !== "ECDSA_P256_SHA256" || String(receiptEnvelope.checkpointId) !== String(row.id)
    || String(receiptEnvelope.checkpointSha256) !== String(row.checkpoint_sha256) || Number(receiptEnvelope.sequence) !== Number(row.sequence)
    || stableJson(receiptEnvelope.externalReceipt) !== externalReceiptText || String(receiptEnvelope.signature) !== String(row.external_receipt_signature)
    || String(receiptEnvelope.publicKey) !== publicKey || !await verifyP256Signature(publicKey, String(receiptEnvelope.signature || ""), receiptCanonical)) {
    return { valid: false, reason: "external_receipt_binding_mismatch" };
  }
  return { valid: true };
}

async function verifyAttemptDelivery(row: CheckpointRow, attempt: DeliveryAttemptRow, publicKey: string): Promise<{ valid: boolean; reason?: string }> {
  if (String(attempt.status) !== "delivered" || String(attempt.checkpoint_id) !== String(row.id)
    || String(attempt.checkpoint_sha256) !== String(row.checkpoint_sha256) || Number(attempt.sequence) !== Number(row.sequence)
    || !attempt.external_receipt || !attempt.external_receipt_sha256 || !attempt.external_receipt_signature || !attempt.external_receipt_r2_key) {
    return { valid: false, reason: "checkpoint_delivery_attempt_mismatch" };
  }
  const attemptId = String(attempt.id);
  const expectedR2Key = `audit-checkpoints/${String(row.created_at).slice(0, 7)}/${String(row.id)}.external-receipts/${attemptId}.json`;
  if (!/^checkpoint_delivery_[A-Za-z0-9._:-]{8,200}$/.test(attemptId) || String(attempt.external_receipt_r2_key) !== expectedR2Key) return { valid: false, reason: "checkpoint_delivery_attempt_mismatch" };
  const externalReceiptText = String(attempt.external_receipt);
  if (externalReceiptText.length > 8_000) return { valid: false, reason: "invalid_external_receipt_json" };
  let externalReceipt: ExternalCheckpointReceipt;
  try { externalReceipt = JSON.parse(externalReceiptText) as ExternalCheckpointReceipt; }
  catch { return { valid: false, reason: "invalid_external_receipt_json" }; }
  if (!await verifyExternalReceipt(externalReceipt, String(row.checkpoint_sha256), Number(row.sequence))) return { valid: false, reason: "invalid_external_receipt_signature" };
  const receiptObject = await getEnv().EVIDENCE_BUCKET.get(expectedR2Key);
  if (!receiptObject || Number(receiptObject.size || 0) > 64_000) return { valid: false, reason: "missing_external_receipt_object" };
  const metadata = receiptObject.customMetadata || {};
  if (!hasExactKeys(metadata, ["deliveryAttemptId", "checkpointId", "checkpointSha256", "externalReceiptSha256", "sequence"])
    || metadata.deliveryAttemptId !== attemptId || metadata.checkpointId !== String(row.id) || metadata.checkpointSha256 !== String(row.checkpoint_sha256)
    || metadata.externalReceiptSha256 !== String(attempt.external_receipt_sha256) || metadata.sequence !== String(row.sequence)) return { valid: false, reason: "external_receipt_object_metadata_mismatch" };
  const receiptText = await receiptObject.text();
  if (receiptText.length > 64_000 || await sha256(receiptText) !== String(attempt.external_receipt_sha256)) return { valid: false, reason: "external_receipt_digest_mismatch" };
  let receiptEnvelope: Record<string, unknown>;
  try { receiptEnvelope = JSON.parse(receiptText) as Record<string, unknown>; }
  catch { return { valid: false, reason: "invalid_external_receipt_envelope" }; }
  if (!receiptEnvelope || Array.isArray(receiptEnvelope) || !hasExactKeys(receiptEnvelope, ["version", "deliveryAttemptId", "checkpointId", "checkpointSha256", "sequence", "endpointOrigin", "attemptedAt", "externalReceipt", "boundAt", "signatureAlgorithm", "signature", "publicKey"])) return { valid: false, reason: "external_receipt_binding_mismatch" };
  const receiptBinding = {
    version: receiptEnvelope.version,
    deliveryAttemptId: receiptEnvelope.deliveryAttemptId,
    checkpointId: receiptEnvelope.checkpointId,
    checkpointSha256: receiptEnvelope.checkpointSha256,
    sequence: receiptEnvelope.sequence,
    endpointOrigin: receiptEnvelope.endpointOrigin,
    attemptedAt: receiptEnvelope.attemptedAt,
    externalReceipt: receiptEnvelope.externalReceipt,
    boundAt: receiptEnvelope.boundAt,
  };
  const receiptCanonical = stableJson(receiptBinding);
  if (Number(receiptEnvelope.version) !== 2 || String(receiptEnvelope.signatureAlgorithm) !== "ECDSA_P256_SHA256" || String(receiptEnvelope.deliveryAttemptId) !== attemptId
    || String(receiptEnvelope.checkpointId) !== String(row.id) || String(receiptEnvelope.checkpointSha256) !== String(row.checkpoint_sha256)
    || Number(receiptEnvelope.sequence) !== Number(row.sequence) || String(receiptEnvelope.endpointOrigin) !== String(attempt.endpoint_origin)
    || String(receiptEnvelope.attemptedAt) !== String(attempt.attempted_at) || stableJson(receiptEnvelope.externalReceipt) !== externalReceiptText
    || String(receiptEnvelope.signature) !== String(attempt.external_receipt_signature) || String(receiptEnvelope.publicKey) !== publicKey
    || !Number.isFinite(Date.parse(String(receiptEnvelope.attemptedAt))) || !Number.isFinite(Date.parse(String(receiptEnvelope.boundAt)))
    || !await verifyP256Signature(publicKey, String(receiptEnvelope.signature || ""), receiptCanonical)) {
    return { valid: false, reason: "external_receipt_binding_mismatch" };
  }
  return { valid: true };
}

export async function verifyLatestAuditCheckpoint(): Promise<{ valid: boolean; reason?: string; sequence?: number }> {
  const row = await loadLatestCheckpointRow();
  if (!row) return { valid: false, reason: "missing_checkpoint" };
  const sequence = Number(row.sequence);
  try {
    const core = await verifyCheckpointCore(row);
    if (!core.valid) return { valid: false, reason: core.reason, sequence };
    if (String(row.external_status) === "delivered") {
      const verified = await verifyLegacyDelivery(row, core.value.publicKey);
      return verified.valid ? { valid: true, sequence } : { valid: false, reason: verified.reason, sequence };
    }
    const attempt = await loadDeliveredAttempt(String(row.id));
    if (!attempt) return { valid: false, reason: "checkpoint_not_independently_delivered", sequence };
    const verified = await verifyAttemptDelivery(row, attempt, core.value.publicKey);
    return verified.valid ? { valid: true, sequence } : { valid: false, reason: verified.reason, sequence };
  } catch {
    return { valid: false, reason: "invalid_checkpoint_key", sequence };
  }
}
