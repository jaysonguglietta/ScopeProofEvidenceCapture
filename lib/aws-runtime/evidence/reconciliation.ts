import {
  asResourceId,
  asSha256,
  asTenantId,
  asUploadIntentId,
  assertBoundedText,
  assertRevision,
  canonicalInstant,
  safeEqual,
  sha256Hex,
  stableJson,
  type JsonValue,
  TenantSecurityError,
} from "../contracts.ts";
import type { EvidenceMimeType } from "../upload.ts";
import {
  asBucketName,
  asControlId,
  asEvidenceMimeType,
  asKmsKeyArn,
  assertExactObjectVersion,
  buildControlledEvidenceKeys,
} from "./primitives.ts";

export type ReconciliationObjectLockMode = "GOVERNANCE" | "COMPLIANCE";

export interface PromotionFacts {
  readonly schemaVersion: 1;
  readonly tenantId: string;
  readonly uploadIntentId: string;
  readonly evidenceId: string;
  readonly controlId: string;
  readonly quarantineBucket: string;
  readonly quarantineKey: string;
  readonly quarantineVersionId: string;
  readonly evidenceBucket: string;
  readonly evidenceKey: string;
  readonly evidenceVersionId: string;
  readonly sha256: string;
  readonly byteSize: number;
  readonly contentType: EvidenceMimeType;
  readonly copyAttemptId: string;
  readonly copyFence: number;
  readonly dlpPolicyVersion: string;
  readonly dlpReceiptSha256: string;
  readonly dlpScannedAt: string;
  readonly dlpScannerRequestId: string;
  readonly kmsKeyArn: string;
  readonly objectLockMode: ReconciliationObjectLockMode;
  readonly promotionAttemptId: string;
  readonly promotionFence: number;
  readonly retainUntil: string;
  readonly uploadedAt: string;
  readonly promotedAt: string;
  readonly providerRequestId: string;
}

export interface PromotionReconciliationRequest extends Omit<PromotionFacts, "schemaVersion"> {
  readonly receiptId: string;
  readonly expectedUploadRevision: number;
  readonly expectedEvidenceRevision: number;
  readonly promotionLeaseExpiresAt: string;
  /** Copied from the upload intent and rechecked inside the transaction. */
  readonly requiredRetentionUntil: string;
}

export interface PromotionReconciliationPolicy {
  readonly quarantineBucket: string;
  readonly evidenceBucket: string;
  readonly evidenceKmsKeyArn: string;
  readonly objectLockMode: ReconciliationObjectLockMode;
  readonly maximumBytes?: number;
}

export interface AtomicPromotionCommand {
  readonly tenantId: string;
  readonly receiptId: string;
  readonly expectedUploadRevision: number;
  readonly expectedEvidenceRevision: number;
  readonly idempotencyDigest: string;
  readonly promotionLeaseExpiresAt: string;
  readonly requiredRetentionUntil: string;
  readonly facts: PromotionFacts;
}

export interface CommittedPromotionSnapshot {
  readonly receiptId: string;
  readonly idempotencyDigest: string;
  readonly uploadRevision: number;
  readonly evidenceRevision: number;
  readonly facts: PromotionFacts;
}

export type AtomicPromotionResult =
  | { readonly outcome: "applied" | "already_applied"; readonly committed: true; readonly snapshot: CommittedPromotionSnapshot }
  | { readonly outcome: "condition_failed"; readonly committed: false; readonly reason: "missing" | "wrong_state" | "revision_changed" | "idempotency_conflict" };

/**
 * Implementations MUST perform the intent CAS, evidence CAS, and receipt insert
 * in one database transaction. The transaction must recheck the intent's
 * tenant, evidence id, key, checksum, size, MIME type, status, revision, and
 * required retention before it writes. An idempotency conflict must never be
 * converted into `already_applied`; that outcome is valid only when every fact
 * matches.
 */
export interface AtomicPromotionStore {
  transactPromotion(command: AtomicPromotionCommand): Promise<AtomicPromotionResult>;
}

export interface PromotionReconciliationOutcome {
  readonly outcome: "applied" | "already_applied";
  readonly receiptId: string;
  readonly idempotencyDigest: string;
  readonly uploadRevision: number;
  readonly evidenceRevision: number;
  readonly facts: PromotionFacts;
}

export async function reconcileEvidencePromotion(
  store: AtomicPromotionStore,
  request: PromotionReconciliationRequest,
  policy: PromotionReconciliationPolicy,
): Promise<PromotionReconciliationOutcome> {
  const normalizedPolicy = normalizePolicy(policy);
  const facts = normalizeFacts(request, normalizedPolicy.maximumBytes);
  assertPolicy(facts, normalizedPolicy);
  const receiptId = asResourceId(request.receiptId, ["rcp"]);
  assertNonnegativeRevision(request.expectedUploadRevision);
  assertNonnegativeRevision(request.expectedEvidenceRevision);
  const requiredRetentionUntil = canonicalInstant(request.requiredRetentionUntil, "Required retention time");
  const promotionLeaseExpiresAt = canonicalInstant(request.promotionLeaseExpiresAt, "Promotion lease expiry");
  if (Date.parse(promotionLeaseExpiresAt) <= Date.parse(facts.promotedAt) ||
      Date.parse(promotionLeaseExpiresAt) > Date.parse(facts.promotedAt) + 15 * 60_000) {
    throw new TenantSecurityError("CONCURRENT_MODIFICATION", "Promotion lease is expired or unbounded.", 409);
  }
  if (Date.parse(facts.retainUntil) < Date.parse(requiredRetentionUntil)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "S3 retention is shorter than the upload intent requires.", 409);
  }
  const idempotencyDigest = await promotionDigest(facts);
  const command: AtomicPromotionCommand = Object.freeze({
    tenantId: facts.tenantId,
    receiptId,
    expectedUploadRevision: request.expectedUploadRevision,
    expectedEvidenceRevision: request.expectedEvidenceRevision,
    idempotencyDigest,
    promotionLeaseExpiresAt,
    requiredRetentionUntil,
    facts,
  });
  const result = await store.transactPromotion(command);
  if (result?.outcome === "condition_failed" && result.committed === false) {
    throw new TenantSecurityError(
      result.reason === "idempotency_conflict" ? "UPLOAD_MISMATCH" : "CONCURRENT_MODIFICATION",
      result.reason === "idempotency_conflict"
        ? "A promotion receipt already exists with different immutable facts."
        : "Promotion state changed before the database transaction committed.",
      409,
    );
  }
  if ((result?.outcome !== "applied" && result?.outcome !== "already_applied") || result.committed !== true) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Database reconciliation returned an invalid transaction result.", 409);
  }
  assertCommittedSnapshot(command, result.snapshot);
  return Object.freeze({ outcome: result.outcome, ...result.snapshot });
}

function assertNonnegativeRevision(value: number): void {
  assertRevision(value, value);
}

function normalizePolicy(policy: PromotionReconciliationPolicy): Required<PromotionReconciliationPolicy> {
  const maximumBytes = policy.maximumBytes ?? 25 * 1024 * 1024;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 5 * 1024 * 1024 * 1024) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Evidence size policy is invalid.");
  }
  if (!(["GOVERNANCE", "COMPLIANCE"] as const).includes(policy.objectLockMode)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Object Lock policy is invalid.");
  }
  const quarantineBucket = asBucketName(policy.quarantineBucket);
  const evidenceBucket = asBucketName(policy.evidenceBucket);
  if (quarantineBucket === evidenceBucket) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Quarantine and evidence buckets must be separate.");
  }
  return Object.freeze({
    quarantineBucket,
    evidenceBucket,
    evidenceKmsKeyArn: asKmsKeyArn(policy.evidenceKmsKeyArn),
    objectLockMode: policy.objectLockMode,
    maximumBytes,
  });
}

function normalizeFacts(input: PromotionReconciliationRequest, maximumBytes: number): PromotionFacts {
  const tenantId = asTenantId(input.tenantId);
  const uploadIntentId = asUploadIntentId(input.uploadIntentId);
  const evidenceId = asResourceId(input.evidenceId, ["evd"]);
  const controlId = asControlId(input.controlId);
  const contentType = asEvidenceMimeType(input.contentType);
  const keys = buildControlledEvidenceKeys({ tenantId, controlId, uploadIntentId, evidenceId, contentType });
  if (input.quarantineKey !== keys.quarantineKey || input.evidenceKey !== keys.evidenceKey) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion keys are outside the exact tenant control namespace.", 409);
  }
  if (!Number.isSafeInteger(input.byteSize) || input.byteSize < 1 || input.byteSize > maximumBytes) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Promoted evidence byte size is outside policy.", 422);
  }
  const promotedAt = canonicalInstant(input.promotedAt, "Promotion time");
  const uploadedAt = canonicalInstant(input.uploadedAt, "Source upload time");
  const dlpScannedAt = canonicalInstant(input.dlpScannedAt, "DLP scan time");
  const retainUntil = canonicalInstant(input.retainUntil, "Retention time");
  if (Date.parse(promotedAt) < Date.parse(uploadedAt)) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion time predates the exact source upload.", 409);
  }
  if (Date.parse(retainUntil) <= Date.parse(promotedAt)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Promotion requires future S3 Object Lock retention.", 409);
  }
  if (Date.parse(dlpScannedAt) < Date.parse(uploadedAt) || Date.parse(dlpScannedAt) > Date.parse(promotedAt)) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "DLP scan is not bound to the promotion interval.", 409);
  }
  const dlpPolicyVersion = assertBoundedText(input.dlpPolicyVersion, "DLP policy version", 3, 64);
  const dlpScannerRequestId = assertBoundedText(input.dlpScannerRequestId, "DLP scanner request id", 8, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(dlpPolicyVersion) ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(dlpScannerRequestId)) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "DLP receipt identity is invalid.", 409);
  }
  if (!(["GOVERNANCE", "COMPLIANCE"] as const).includes(input.objectLockMode)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Promotion Object Lock mode is invalid.", 409);
  }
  const providerRequestId = assertBoundedText(input.providerRequestId, "S3 request id", 3, 200);
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:+/-]{2,199}$/.test(providerRequestId)) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "S3 request id is invalid.");
  }
  const copyAttemptId = assertBoundedText(input.copyAttemptId, "Copy attempt id", 36, 36);
  const promotionAttemptId = assertBoundedText(input.promotionAttemptId, "Promotion attempt id", 36, 36);
  if (!/^pat_[a-f0-9]{32}$/.test(copyAttemptId) ||
      !Number.isSafeInteger(input.copyFence) || input.copyFence < 1 ||
      !/^pat_[a-f0-9]{32}$/.test(promotionAttemptId) ||
      !Number.isSafeInteger(input.promotionFence) || input.promotionFence < input.copyFence) {
    throw new TenantSecurityError("CONCURRENT_MODIFICATION", "Promotion fencing identity is invalid.", 409);
  }
  return Object.freeze({
    schemaVersion: 1,
    tenantId,
    uploadIntentId,
    evidenceId,
    controlId,
    quarantineBucket: asBucketName(input.quarantineBucket),
    quarantineKey: keys.quarantineKey,
    quarantineVersionId: assertExactObjectVersion(input.quarantineVersionId),
    evidenceBucket: asBucketName(input.evidenceBucket),
    evidenceKey: keys.evidenceKey,
    evidenceVersionId: assertExactObjectVersion(input.evidenceVersionId),
    sha256: asSha256(input.sha256),
    byteSize: input.byteSize,
    contentType,
    copyAttemptId,
    copyFence: input.copyFence,
    dlpPolicyVersion,
    dlpReceiptSha256: asSha256(input.dlpReceiptSha256),
    dlpScannedAt,
    dlpScannerRequestId,
    kmsKeyArn: asKmsKeyArn(input.kmsKeyArn),
    objectLockMode: input.objectLockMode,
    promotionAttemptId,
    promotionFence: input.promotionFence,
    retainUntil,
    uploadedAt,
    promotedAt,
    providerRequestId,
  });
}

function assertPolicy(facts: PromotionFacts, policy: Required<PromotionReconciliationPolicy>): void {
  if (
    facts.quarantineBucket !== policy.quarantineBucket ||
    facts.evidenceBucket !== policy.evidenceBucket ||
    facts.kmsKeyArn !== policy.evidenceKmsKeyArn
  ) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion storage does not match tenant policy.", 409);
  }
  if (facts.objectLockMode !== policy.objectLockMode) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Promotion Object Lock mode does not match tenant policy.", 409);
  }
}

async function promotionDigest(facts: PromotionFacts): Promise<string> {
  return sha256Hex(`scopeproof-promotion-reconciliation-v1\n${stableJson(facts as unknown as JsonValue)}`);
}

function assertCommittedSnapshot(command: AtomicPromotionCommand, snapshot: CommittedPromotionSnapshot): void {
  if (
    snapshot.receiptId !== command.receiptId ||
    !safeEqual(snapshot.idempotencyDigest, command.idempotencyDigest) ||
    snapshot.uploadRevision !== command.expectedUploadRevision + 1 ||
    snapshot.evidenceRevision !== command.expectedEvidenceRevision + 1 ||
    !safeEqual(canonicalFacts(snapshot.facts), canonicalFacts(command.facts))
  ) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Database reconciliation returned conflicting or partial promotion state.", 409);
  }
}

function canonicalFacts(facts: PromotionFacts): string {
  return stableJson(facts as unknown as JsonValue);
}
