import {
  asResourceId,
  asSha256,
  asTenantId,
  asUploadIntentId,
  asUserId,
  assertBoundedText,
  assertRevision,
  assertVersionId,
  canonicalInstant,
  containsAsciiControlCharacters,
  epochMilliseconds,
  safeEqual,
  sha256Hex,
  type ExactObjectKey,
  type ResourceId,
  type Sha256Hex,
  type TenantId,
  TenantSecurityError,
  type UploadIntentId,
  type UserId,
} from "./contracts.ts";

export const DEFAULT_MAXIMUM_UPLOAD_BYTES = 25 * 1024 * 1024;
export const MAXIMUM_UPLOAD_TTL_MS = 10 * 60_000;

export type EvidenceMimeType =
  | "image/png"
  | "application/json"
  | "application/spdx+json"
  | "application/vnd.cyclonedx+json"
  | "text/plain"
  | "text/csv";

const supportedMimeTypes: ReadonlySet<EvidenceMimeType> = new Set([
  "image/png",
  "application/json",
  "application/spdx+json",
  "application/vnd.cyclonedx+json",
  "text/plain",
  "text/csv",
]);

const mimeExtension: Record<EvidenceMimeType, string> = {
  "image/png": "png",
  "application/json": "json",
  "application/spdx+json": "spdx.json",
  "application/vnd.cyclonedx+json": "cdx.json",
  "text/plain": "txt",
  "text/csv": "csv",
};

export type UploadStatus = "issued" | "quarantined" | "validated" | "promoted" | "rejected" | "expired";

interface UploadBase {
  readonly schemaVersion: 1;
  readonly id: UploadIntentId;
  readonly tenantId: TenantId;
  readonly requestedBy: UserId;
  readonly resourceId: ResourceId;
  readonly expectedSha256: Sha256Hex;
  readonly expectedSize: number;
  readonly contentType: EvidenceMimeType;
  readonly nonceDigest: Sha256Hex;
  readonly quarantineKey: ExactObjectKey;
  readonly finalKey: ExactObjectKey;
  readonly issuedAt: string;
  readonly expiresAt: string;
  readonly requiredRetentionUntil: string;
  readonly revision: number;
  readonly status: UploadStatus;
}

export interface IssuedUpload extends UploadBase { readonly status: "issued" }

export interface QuarantinedUpload extends UploadBase {
  readonly status: "quarantined";
  readonly consumedAt: string;
  readonly quarantineReceipt: QuarantineReceipt;
}

export interface ValidatedUpload extends UploadBase {
  readonly status: "validated";
  readonly consumedAt: string;
  readonly quarantineReceipt: QuarantineReceipt;
  readonly validation: ValidationReport & { readonly completedAt: string };
}

export interface PromotedUpload extends UploadBase {
  readonly status: "promoted";
  readonly consumedAt: string;
  readonly quarantineReceipt: QuarantineReceipt;
  readonly validation: ValidationReport & { readonly completedAt: string };
  readonly promotionReceipt: PromotionReceipt;
}

export interface RejectedUpload extends UploadBase {
  readonly status: "rejected";
  readonly rejectedAt: string;
  readonly rejectionCode: UploadRejectionCode;
  readonly rejectionReason: string;
  readonly quarantineReceipt?: QuarantineReceipt;
}

export interface ExpiredUpload extends UploadBase {
  readonly status: "expired";
  readonly expiredAt: string;
}

export type UploadLifecycle = IssuedUpload | QuarantinedUpload | ValidatedUpload | PromotedUpload | RejectedUpload | ExpiredUpload;

export interface QuarantineReceipt {
  readonly tenantId: TenantId;
  readonly key: ExactObjectKey;
  readonly versionId: string;
  readonly sha256: Sha256Hex;
  readonly byteSize: number;
  readonly contentType: EvidenceMimeType;
  readonly receivedAt: string;
  readonly providerRequestId: string;
}

export interface ValidationReport {
  readonly tenantId: TenantId;
  readonly key: ExactObjectKey;
  readonly versionId: string;
  readonly sha256: Sha256Hex;
  readonly byteSize: number;
  readonly contentType: EvidenceMimeType;
  readonly safe: boolean;
  readonly scannerPolicy: string;
  readonly scannerDigest: Sha256Hex;
}

export interface PromotionReceipt {
  readonly tenantId: TenantId;
  readonly sourceKey: ExactObjectKey;
  readonly sourceVersionId: string;
  readonly finalKey: ExactObjectKey;
  readonly finalVersionId: string;
  readonly sha256: Sha256Hex;
  readonly byteSize: number;
  readonly contentType: EvidenceMimeType;
  readonly kmsKeyArn: string;
  readonly objectLockMode: "GOVERNANCE" | "COMPLIANCE";
  readonly retainUntil: string;
  readonly promotedAt: string;
  readonly providerRequestId: string;
}

export type UploadRejectionCode = "checksum_mismatch" | "size_mismatch" | "mime_mismatch" | "unsafe_content" | "operator_rejected" | "validation_failed";

function asMimeType(value: string): EvidenceMimeType {
  if (!supportedMimeTypes.has(value as EvidenceMimeType)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Evidence MIME type is not allowed.", 415);
  }
  return value as EvidenceMimeType;
}

function assertSize(value: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Evidence byte size is outside the allowed range.", 413);
  }
  return value;
}

export function exactObjectKey(value: string): ExactObjectKey {
  const key = String(value || "");
  if (!key || key.length > 512 || key.startsWith("/") || key.endsWith("/") || key.includes("//") || key.includes("\\") || key.includes("%") || /(^|\/)\.\.?($|\/)/.test(key) || containsAsciiControlCharacters(key)) {
    throw new TenantSecurityError("INVALID_OBJECT_KEY", "Object key is not canonical.");
  }
  const parts = key.split("/");
  if (parts.some((part) => !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(part))) {
    throw new TenantSecurityError("INVALID_OBJECT_KEY", "Object key is not canonical.");
  }
  return key as ExactObjectKey;
}

export function buildUploadKeys(tenantIdValue: string, intentIdValue: string, resourceIdValue: string, contentTypeValue: string): { quarantineKey: ExactObjectKey; finalKey: ExactObjectKey } {
  const tenantId = asTenantId(tenantIdValue);
  const intentId = asUploadIntentId(intentIdValue);
  const resourceId = asResourceId(resourceIdValue);
  const contentType = asMimeType(contentTypeValue);
  return {
    quarantineKey: exactObjectKey(`tenants/${tenantId}/quarantine/${intentId}.upload`),
    finalKey: exactObjectKey(`tenants/${tenantId}/evidence/${resourceId}.${mimeExtension[contentType]}`),
  };
}

function assertNonce(value: string): string {
  const nonce = String(value || "");
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(nonce)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "A high-entropy upload nonce is required.");
  }
  return nonce;
}

async function nonceDigest(tenantId: TenantId, intentId: UploadIntentId, nonce: string): Promise<Sha256Hex> {
  return sha256Hex(`scopeproof-upload-nonce-v1\n${tenantId}\n${intentId}\n${nonce}`);
}

export async function issueUploadIntent(input: {
  id: string;
  tenantId: string;
  requestedBy: UserId;
  resourceId: string;
  expectedSha256: string;
  expectedSize: number;
  contentType: string;
  nonce: string;
  issuedAt: Date;
  expiresAt: Date;
  requiredRetentionUntil: Date;
  maximumBytes?: number;
}): Promise<IssuedUpload> {
  const id = asUploadIntentId(input.id);
  const tenantId = asTenantId(input.tenantId);
  const resourceId = asResourceId(input.resourceId);
  const contentType = asMimeType(input.contentType);
  const maximumBytes = input.maximumBytes ?? DEFAULT_MAXIMUM_UPLOAD_BYTES;
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes > 5 * 1024 * 1024 * 1024) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Maximum upload size is invalid.");
  }
  const expectedSize = assertSize(input.expectedSize, maximumBytes);
  const issuedAt = canonicalInstant(input.issuedAt, "Upload issue time");
  const expiresAt = canonicalInstant(input.expiresAt, "Upload expiry");
  const retention = canonicalInstant(input.requiredRetentionUntil, "Required retention");
  const ttl = Date.parse(expiresAt) - Date.parse(issuedAt);
  if (ttl <= 0 || ttl > MAXIMUM_UPLOAD_TTL_MS || Date.parse(retention) <= Date.parse(expiresAt)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload validity or retention window is invalid.");
  }
  const nonce = assertNonce(input.nonce);
  const keys = buildUploadKeys(tenantId, id, resourceId, contentType);
  return Object.freeze({
    schemaVersion: 1,
    id,
    tenantId,
    requestedBy: asUserId(input.requestedBy),
    resourceId,
    expectedSha256: asSha256(input.expectedSha256),
    expectedSize,
    contentType,
    nonceDigest: await nonceDigest(tenantId, id, nonce),
    ...keys,
    issuedAt,
    expiresAt,
    requiredRetentionUntil: retention,
    revision: 0,
    status: "issued",
  });
}

function assertTenantAndKey(intent: UploadLifecycle, tenantId: TenantId, key: ExactObjectKey, expectedKey: ExactObjectKey): void {
  if (tenantId !== intent.tenantId || key !== expectedKey) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Upload receipt does not match its exact tenant object key.", 409);
  }
}

function mismatchCode(intent: UploadLifecycle, value: { sha256: Sha256Hex; byteSize: number; contentType: EvidenceMimeType }): UploadRejectionCode | null {
  if (value.sha256 !== intent.expectedSha256) return "checksum_mismatch";
  if (value.byteSize !== intent.expectedSize) return "size_mismatch";
  if (value.contentType !== intent.contentType) return "mime_mismatch";
  return null;
}

export async function recordQuarantinedUpload(intent: UploadLifecycle, input: {
  expectedRevision: number;
  nonce: string;
  now: Date;
  receipt: QuarantineReceipt;
}): Promise<QuarantinedUpload> {
  assertRevision(intent.revision, input.expectedRevision);
  if (intent.status !== "issued") {
    throw new TenantSecurityError(intent.status === "quarantined" || intent.status === "validated" || intent.status === "promoted" ? "UPLOAD_INTENT_REPLAYED" : "ILLEGAL_STATE_TRANSITION", "Upload intent has already been consumed.", 409);
  }
  if (input.now.getTime() >= epochMilliseconds(intent.expiresAt, "Upload expiry")) {
    throw new TenantSecurityError("UPLOAD_INTENT_EXPIRED", "Upload intent has expired.", 410);
  }
  const presentedDigest = await nonceDigest(intent.tenantId, intent.id, assertNonce(input.nonce));
  if (!safeEqual(presentedDigest, intent.nonceDigest)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload nonce is invalid.", 401);
  }
  const receipt = normalizeQuarantineReceipt(input.receipt, Math.max(DEFAULT_MAXIMUM_UPLOAD_BYTES, intent.expectedSize));
  assertTenantAndKey(intent, receipt.tenantId, receipt.key, intent.quarantineKey);
  const receivedAt = Date.parse(receipt.receivedAt);
  if (receivedAt < Date.parse(intent.issuedAt) || receivedAt >= Date.parse(intent.expiresAt) || receivedAt > input.now.getTime()) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Quarantine receipt timestamp is outside the upload window.", 409);
  }
  const mismatch = mismatchCode(intent, receipt);
  if (mismatch) throw new TenantSecurityError("UPLOAD_MISMATCH", `Quarantine ${mismatch.replace("_", " ")}.`, 422);
  return Object.freeze({ ...intent, status: "quarantined", revision: intent.revision + 1, consumedAt: canonicalInstant(input.now), quarantineReceipt: receipt });
}

function normalizeQuarantineReceipt(receipt: QuarantineReceipt, maximumBytes: number): QuarantineReceipt {
  return Object.freeze({
    tenantId: asTenantId(receipt.tenantId),
    key: exactObjectKey(receipt.key),
    versionId: assertVersionId(receipt.versionId),
    sha256: asSha256(receipt.sha256),
    byteSize: assertSize(receipt.byteSize, maximumBytes),
    contentType: asMimeType(receipt.contentType),
    receivedAt: canonicalInstant(receipt.receivedAt, "Upload receipt time"),
    providerRequestId: assertBoundedText(receipt.providerRequestId, "Provider request id", 3, 200),
  });
}

export function completeUploadValidation(intent: UploadLifecycle, input: {
  expectedRevision: number;
  now: Date;
  report: ValidationReport;
}): ValidatedUpload | RejectedUpload {
  assertRevision(intent.revision, input.expectedRevision);
  if (intent.status !== "quarantined") throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "Only quarantined uploads can be validated.", 409);
  const report: ValidationReport = Object.freeze({
    tenantId: asTenantId(input.report.tenantId),
    key: exactObjectKey(input.report.key),
    versionId: assertVersionId(input.report.versionId),
    sha256: asSha256(input.report.sha256),
    byteSize: assertSize(input.report.byteSize, Math.max(DEFAULT_MAXIMUM_UPLOAD_BYTES, intent.expectedSize)),
    contentType: asMimeType(input.report.contentType),
    safe: input.report.safe === true,
    scannerPolicy: assertBoundedText(input.report.scannerPolicy, "Scanner policy", 3, 160),
    scannerDigest: asSha256(input.report.scannerDigest),
  });
  assertTenantAndKey(intent, report.tenantId, report.key, intent.quarantineKey);
  if (report.versionId !== intent.quarantineReceipt.versionId) throw new TenantSecurityError("UPLOAD_MISMATCH", "Validation used a different quarantine version.", 409);
  if (input.now.getTime() < Date.parse(intent.quarantineReceipt.receivedAt)) throw new TenantSecurityError("UPLOAD_MISMATCH", "Validation timestamp precedes the quarantine receipt.", 409);
  const mismatch = mismatchCode(intent, report);
  if (mismatch || !report.safe) {
    const rejectionCode = mismatch || "unsafe_content";
    return Object.freeze({
      ...intent,
      status: "rejected",
      revision: intent.revision + 1,
      rejectedAt: canonicalInstant(input.now),
      rejectionCode,
      rejectionReason: rejectionCode.replaceAll("_", " "),
    });
  }
  return Object.freeze({ ...intent, status: "validated", revision: intent.revision + 1, validation: { ...report, completedAt: canonicalInstant(input.now) } });
}

export function promoteValidatedUpload(intent: UploadLifecycle, input: {
  expectedRevision: number;
  expectedKmsKeyArn: string;
  expectedObjectLockMode: "GOVERNANCE" | "COMPLIANCE";
  receipt: PromotionReceipt;
}): PromotedUpload {
  assertRevision(intent.revision, input.expectedRevision);
  if (intent.status !== "validated") throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "Only validated uploads can be promoted.", 409);
  const receipt: PromotionReceipt = Object.freeze({
    tenantId: asTenantId(input.receipt.tenantId),
    sourceKey: exactObjectKey(input.receipt.sourceKey),
    sourceVersionId: assertVersionId(input.receipt.sourceVersionId, "Source version"),
    finalKey: exactObjectKey(input.receipt.finalKey),
    finalVersionId: assertVersionId(input.receipt.finalVersionId, "Final version"),
    sha256: asSha256(input.receipt.sha256),
    byteSize: assertSize(input.receipt.byteSize, Math.max(DEFAULT_MAXIMUM_UPLOAD_BYTES, intent.expectedSize)),
    contentType: asMimeType(input.receipt.contentType),
    kmsKeyArn: assertKmsKeyArn(input.receipt.kmsKeyArn),
    objectLockMode: input.receipt.objectLockMode,
    retainUntil: canonicalInstant(input.receipt.retainUntil, "Object retention"),
    promotedAt: canonicalInstant(input.receipt.promotedAt, "Promotion time"),
    providerRequestId: assertBoundedText(input.receipt.providerRequestId, "Provider request id", 3, 200),
  });
  assertTenantAndKey(intent, receipt.tenantId, receipt.sourceKey, intent.quarantineKey);
  if (receipt.finalKey !== intent.finalKey || receipt.sourceVersionId !== intent.quarantineReceipt.versionId) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion does not match the validated source and exact destination.", 409);
  }
  if (mismatchCode(intent, receipt)) throw new TenantSecurityError("UPLOAD_MISMATCH", "Promoted bytes do not match the validated upload.", 422);
  const expectedKmsKeyArn = assertKmsKeyArn(input.expectedKmsKeyArn);
  if (receipt.kmsKeyArn !== expectedKmsKeyArn) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion did not use the configured KMS key.", 409);
  }
  if (!['GOVERNANCE', 'COMPLIANCE'].includes(input.expectedObjectLockMode) || receipt.objectLockMode !== input.expectedObjectLockMode || Date.parse(receipt.retainUntil) < Date.parse(intent.requiredRetentionUntil) || Date.parse(receipt.retainUntil) <= Date.parse(receipt.promotedAt)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Promoted evidence does not satisfy required Object Lock retention.", 409);
  }
  if (Date.parse(receipt.promotedAt) < Date.parse(intent.validation.completedAt)) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion timestamp precedes validation.", 409);
  }
  return Object.freeze({ ...intent, status: "promoted", revision: intent.revision + 1, promotionReceipt: receipt });
}

function assertKmsKeyArn(value: string): string {
  const arn = String(value || "");
  if (!/^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key\/[0-9A-Za-z-]{1,128}$/.test(arn)) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion did not use an approved customer-managed KMS key.");
  }
  return arn;
}

export function rejectUpload(intent: UploadLifecycle, input: { expectedRevision: number; now: Date; code: "operator_rejected" | "validation_failed"; reason: string }): RejectedUpload {
  assertRevision(intent.revision, input.expectedRevision);
  if (!['issued', 'quarantined'].includes(intent.status)) throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "This upload can no longer be rejected.", 409);
  return Object.freeze({ ...intent, status: "rejected", revision: intent.revision + 1, rejectedAt: canonicalInstant(input.now), rejectionCode: input.code, rejectionReason: assertBoundedText(input.reason, "Rejection reason", 10, 500) });
}

export function expireUploadIntent(intent: UploadLifecycle, input: { expectedRevision: number; now: Date }): ExpiredUpload {
  assertRevision(intent.revision, input.expectedRevision);
  if (intent.status !== "issued" || input.now.getTime() < Date.parse(intent.expiresAt)) {
    throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "Only an elapsed, unused upload intent can expire.", 409);
  }
  return Object.freeze({ ...intent, status: "expired", revision: intent.revision + 1, expiredAt: canonicalInstant(input.now) });
}

/**
 * Persistence adapters MUST use this revision as the condition in one atomic
 * compare-and-swap. Pure transitions prevent sequential replay; CAS prevents
 * two workers from consuming the same revision concurrently.
 */
export interface UploadStateRepository {
  load(tenantId: TenantId, id: UploadIntentId): Promise<UploadLifecycle | null>;
  compareAndSwap(tenantId: TenantId, id: UploadIntentId, expectedRevision: number, next: UploadLifecycle): Promise<boolean>;
}
