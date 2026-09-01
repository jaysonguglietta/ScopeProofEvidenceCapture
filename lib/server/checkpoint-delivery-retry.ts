export const CHECKPOINT_DELIVERY_MAX_ATTEMPTS = 10;
export const CHECKPOINT_DELIVERY_RETRY_BASE_MS = 60_000;
export const CHECKPOINT_DELIVERY_RETRY_MAX_MS = 6 * 60 * 60_000;
export const CHECKPOINT_DELIVERY_CLAIM_LEASE_MS = 2 * 60_000;

export const CHECKPOINT_DELIVERY_CLAIM_SQL = `UPDATE audit_checkpoint_delivery_retry_state
  SET status = 'claimed', attempt_count = attempt_count + 1, next_attempt_at = ?, lease_id = ?, lease_expires_at = ?,
    endpoint_origin = ?, last_attempt_id = ?, last_attempt_at = ?, updated_at = ?
  WHERE checkpoint_id = ? AND checkpoint_sha256 = ? AND status = 'retrying' AND attempt_count = ?
    AND attempt_count < ? AND next_attempt_at <= ?
    AND NOT EXISTS (SELECT 1 FROM audit_checkpoint_delivery_attempts delivered
      WHERE delivered.checkpoint_id = audit_checkpoint_delivery_retry_state.checkpoint_id AND delivered.status = 'delivered')`;

export function checkpointDeliveryBackoffMs(attemptCountInput: number): number {
  const attemptCount = Number.isSafeInteger(attemptCountInput) && attemptCountInput > 0
    ? Math.min(attemptCountInput, CHECKPOINT_DELIVERY_MAX_ATTEMPTS)
    : CHECKPOINT_DELIVERY_MAX_ATTEMPTS;
  return Math.min(
    CHECKPOINT_DELIVERY_RETRY_MAX_MS,
    CHECKPOINT_DELIVERY_RETRY_BASE_MS * (2 ** Math.min(attemptCount - 1, 16)),
  );
}

export type ExpectedCheckpointDelivery = {
  attemptId: string;
  checkpointId: string;
  checkpointSha256: string;
  sequence: number;
  endpointOrigin: string;
  attemptedAt: string;
  externalReceipt: string;
  externalReceiptSha256: string;
  externalReceiptSignature: string;
  externalReceiptR2Key: string;
  createdAt: string;
};

export type CheckpointDeliveryAttemptState = {
  id: string;
  checkpointId: string;
  checkpointSha256: string;
  sequence: number;
  endpointOrigin: string;
  attemptedAt: string;
  status: string;
  externalReceipt: string | null;
  externalReceiptSha256: string | null;
  externalReceiptSignature: string | null;
  externalReceiptR2Key: string | null;
  failureCode: string | null;
  createdAt: string;
};

export type CheckpointDeliveryDisposition = "committed" | "proven_loser" | "uncertain";

/**
 * Classify an authoritative delivered-attempt read after a potentially
 * ambiguous database response. A candidate object is deletable only when a
 * different immutable winner for the same checkpoint is visible and does not
 * reference the candidate key. Missing, malformed, or candidate-referencing
 * state is deliberately uncertain.
 */
export function classifyCheckpointDelivery(
  delivered: CheckpointDeliveryAttemptState | null,
  expected: ExpectedCheckpointDelivery,
): CheckpointDeliveryDisposition {
  if (!delivered || delivered.status !== "delivered" || delivered.checkpointId !== expected.checkpointId
    || delivered.checkpointSha256 !== expected.checkpointSha256 || delivered.sequence !== expected.sequence) return "uncertain";
  if (delivered.id === expected.attemptId) {
    return delivered.endpointOrigin === expected.endpointOrigin
      && delivered.attemptedAt === expected.attemptedAt
      && delivered.externalReceipt === expected.externalReceipt
      && delivered.externalReceiptSha256 === expected.externalReceiptSha256
      && delivered.externalReceiptSignature === expected.externalReceiptSignature
      && delivered.externalReceiptR2Key === expected.externalReceiptR2Key
      && delivered.failureCode === null
      && delivered.createdAt === expected.createdAt
      ? "committed"
      : "uncertain";
  }
  return delivered.externalReceiptR2Key && delivered.externalReceiptR2Key !== expected.externalReceiptR2Key
    ? "proven_loser"
    : "uncertain";
}
