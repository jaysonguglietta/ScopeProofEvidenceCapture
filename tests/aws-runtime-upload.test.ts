import assert from "node:assert/strict";
import test from "node:test";

import {
  asResourceId,
  asSha256,
  asTenantId,
  asUploadIntentId,
  asUserId,
  buildUploadKeys,
  completeUploadValidation,
  exactObjectKey,
  issueUploadIntent,
  promoteValidatedUpload,
  recordQuarantinedUpload,
  TenantSecurityError,
  type IssuedUpload,
  type PromotionReceipt,
  type QuarantineReceipt,
  type ValidationReport,
} from "../lib/aws-runtime/index.ts";

const TENANT_A = asTenantId(`ten_${"a".repeat(32)}`);
const TENANT_B = asTenantId(`ten_${"b".repeat(32)}`);
const USER_A = asUserId(`usr_${"1".repeat(32)}`);
const INTENT_ID = asUploadIntentId(`upl_${"2".repeat(32)}`);
const RESOURCE_ID = asResourceId(`evd_${"3".repeat(32)}`);
const SHA = asSha256("4".repeat(64));
const OTHER_SHA = asSha256("5".repeat(64));
const SCANNER_SHA = asSha256("6".repeat(64));
const NONCE = "N".repeat(43);
const ISSUED_AT = new Date("2026-08-27T16:00:00.000Z");
const RECEIVED_AT = new Date("2026-08-27T16:01:00.000Z");
const VALIDATED_AT = new Date("2026-08-27T16:02:00.000Z");
const KMS_ARN = "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function hasCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof TenantSecurityError);
    assert.equal(error.code, code);
    return true;
  };
}

async function issued(): Promise<IssuedUpload> {
  return issueUploadIntent({
    id: INTENT_ID,
    tenantId: TENANT_A,
    requestedBy: USER_A,
    resourceId: RESOURCE_ID,
    expectedSha256: SHA,
    expectedSize: 1_024,
    contentType: "image/png",
    nonce: NONCE,
    issuedAt: ISSUED_AT,
    expiresAt: new Date("2026-08-27T16:05:00.000Z"),
    requiredRetentionUntil: new Date("2027-08-27T16:05:00.000Z"),
  });
}

function quarantineReceipt(intent: IssuedUpload, overrides: Partial<QuarantineReceipt> = {}): QuarantineReceipt {
  return {
    tenantId: intent.tenantId,
    key: intent.quarantineKey,
    versionId: "version-0001",
    sha256: intent.expectedSha256,
    byteSize: intent.expectedSize,
    contentType: intent.contentType,
    receivedAt: RECEIVED_AT.toISOString(),
    providerRequestId: "s3-request-0001",
    ...overrides,
  };
}

function validationReport(intent: Awaited<ReturnType<typeof recordQuarantinedUpload>>, overrides: Partial<ValidationReport> = {}): ValidationReport {
  return {
    tenantId: intent.tenantId,
    key: intent.quarantineKey,
    versionId: intent.quarantineReceipt.versionId,
    sha256: intent.expectedSha256,
    byteSize: intent.expectedSize,
    contentType: intent.contentType,
    safe: true,
    scannerPolicy: "clamav-and-structure-v1",
    scannerDigest: SCANNER_SHA,
    ...overrides,
  };
}

function promotionReceipt(intent: ReturnType<typeof completeUploadValidation> & { status: "validated" }, overrides: Partial<PromotionReceipt> = {}): PromotionReceipt {
  return {
    tenantId: intent.tenantId,
    sourceKey: intent.quarantineKey,
    sourceVersionId: intent.quarantineReceipt.versionId,
    finalKey: intent.finalKey,
    finalVersionId: "version-0002",
    sha256: intent.expectedSha256,
    byteSize: intent.expectedSize,
    contentType: intent.contentType,
    kmsKeyArn: KMS_ARN,
    objectLockMode: "COMPLIANCE",
    retainUntil: "2027-08-27T16:05:00.000Z",
    promotedAt: "2026-08-27T16:03:00.000Z",
    providerRequestId: "s3-request-0002",
    ...overrides,
  };
}

test("object keys are exact, canonical, and traversal-resistant", () => {
  const keys = buildUploadKeys(TENANT_A, INTENT_ID, RESOURCE_ID, "image/png");
  assert.equal(keys.quarantineKey, `tenants/${TENANT_A}/quarantine/${INTENT_ID}.upload`);
  assert.equal(keys.finalKey, `tenants/${TENANT_A}/evidence/${RESOURCE_ID}.png`);

  for (const key of [
    "../evidence.png",
    `tenants/${TENANT_A}/../${TENANT_B}/evidence/a.png`,
    `tenants/${TENANT_A}/evidence/%2e%2e/secret`,
    `tenants/${TENANT_A}/evidence\\secret.png`,
    `tenants//${TENANT_A}/evidence/secret.png`,
    `/tenants/${TENANT_A}/evidence/secret.png`,
    `tenants/${TENANT_A}/evidence/./secret.png`,
  ]) {
    assert.throws(() => exactObjectKey(key), hasCode("INVALID_OBJECT_KEY"));
  }
});

test("upload intent enforces canonical digest, size, TTL, retention, and requester", async () => {
  const base = {
    id: INTENT_ID,
    tenantId: TENANT_A,
    requestedBy: USER_A,
    resourceId: RESOURCE_ID,
    expectedSha256: SHA,
    expectedSize: 1_024,
    contentType: "image/png",
    nonce: NONCE,
    issuedAt: ISSUED_AT,
    expiresAt: new Date("2026-08-27T16:05:00.000Z"),
    requiredRetentionUntil: new Date("2027-08-27T16:05:00.000Z"),
  };
  await assert.rejects(issueUploadIntent({ ...base, expectedSha256: "A".repeat(64) }), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(issueUploadIntent({ ...base, expectedSize: 0 }), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(issueUploadIntent({ ...base, expiresAt: new Date("2026-08-27T16:11:00.000Z") }), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(issueUploadIntent({ ...base, requiredRetentionUntil: new Date("2026-08-27T16:04:00.000Z") }), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(issueUploadIntent({ ...base, requestedBy: `usr_${"z".repeat(32)}` as typeof USER_A }), hasCode("INVALID_IDENTIFIER"));
  await assert.rejects(issueUploadIntent({ ...base, nonce: ` ${NONCE}` }), hasCode("INVALID_UPLOAD_INTENT"));
});

test("quarantine receipt rejects tenant, key, nonce, time, checksum, size, and MIME mismatches", async () => {
  const intent = await issued();
  await assert.rejects(recordQuarantinedUpload(intent, { expectedRevision: 0, nonce: "X".repeat(43), now: RECEIVED_AT, receipt: quarantineReceipt(intent) }), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(recordQuarantinedUpload(intent, { expectedRevision: 0, nonce: NONCE, now: RECEIVED_AT, receipt: quarantineReceipt(intent, { tenantId: TENANT_B }) }), hasCode("UPLOAD_MISMATCH"));
  await assert.rejects(recordQuarantinedUpload(intent, { expectedRevision: 0, nonce: NONCE, now: RECEIVED_AT, receipt: quarantineReceipt(intent, { key: intent.finalKey }) }), hasCode("UPLOAD_MISMATCH"));
  await assert.rejects(recordQuarantinedUpload(intent, { expectedRevision: 0, nonce: NONCE, now: RECEIVED_AT, receipt: quarantineReceipt(intent, { sha256: OTHER_SHA }) }), hasCode("UPLOAD_MISMATCH"));
  await assert.rejects(recordQuarantinedUpload(intent, { expectedRevision: 0, nonce: NONCE, now: RECEIVED_AT, receipt: quarantineReceipt(intent, { byteSize: 1_023 }) }), hasCode("UPLOAD_MISMATCH"));
  await assert.rejects(recordQuarantinedUpload(intent, { expectedRevision: 0, nonce: NONCE, now: RECEIVED_AT, receipt: quarantineReceipt(intent, { contentType: "application/json" }) }), hasCode("UPLOAD_MISMATCH"));
  await assert.rejects(recordQuarantinedUpload(intent, { expectedRevision: 0, nonce: NONCE, now: RECEIVED_AT, receipt: quarantineReceipt(intent, { receivedAt: "2026-08-27T16:04:00.000Z" }) }), hasCode("UPLOAD_MISMATCH"));
  await assert.rejects(recordQuarantinedUpload(intent, { expectedRevision: 0, nonce: NONCE, now: new Date("2026-08-27T16:05:00.000Z"), receipt: quarantineReceipt(intent) }), hasCode("UPLOAD_INTENT_EXPIRED"));
});

test("a consumed upload intent cannot be replayed and revisions require CAS", async () => {
  const intent = await issued();
  const quarantined = await recordQuarantinedUpload(intent, { expectedRevision: 0, nonce: NONCE, now: RECEIVED_AT, receipt: quarantineReceipt(intent) });
  assert.equal(quarantined.status, "quarantined");
  assert.equal(quarantined.revision, 1);
  await assert.rejects(recordQuarantinedUpload(quarantined, { expectedRevision: 1, nonce: NONCE, now: RECEIVED_AT, receipt: quarantineReceipt(intent) }), hasCode("UPLOAD_INTENT_REPLAYED"));
  assert.throws(() => completeUploadValidation(quarantined, { expectedRevision: 0, now: VALIDATED_AT, report: validationReport(quarantined) }), hasCode("CONCURRENT_MODIFICATION"));
});

test("validation fails closed on unsafe or changed content", async () => {
  const intent = await issued();
  const quarantined = await recordQuarantinedUpload(intent, { expectedRevision: 0, nonce: NONCE, now: RECEIVED_AT, receipt: quarantineReceipt(intent) });
  const checksumRejected = completeUploadValidation(quarantined, { expectedRevision: 1, now: VALIDATED_AT, report: validationReport(quarantined, { sha256: OTHER_SHA }) });
  assert.equal(checksumRejected.status, "rejected");
  assert.equal(checksumRejected.rejectionCode, "checksum_mismatch");
  assert.throws(() => promoteValidatedUpload(checksumRejected, {
    expectedRevision: 2,
    expectedKmsKeyArn: KMS_ARN,
    expectedObjectLockMode: "COMPLIANCE",
    receipt: {} as PromotionReceipt,
  }), hasCode("ILLEGAL_STATE_TRANSITION"));

  const sizeRejected = completeUploadValidation(quarantined, { expectedRevision: 1, now: VALIDATED_AT, report: validationReport(quarantined, { byteSize: 1_025 }) });
  assert.equal(sizeRejected.status, "rejected");
  assert.equal(sizeRejected.rejectionCode, "size_mismatch");
  const unsafeRejected = completeUploadValidation(quarantined, { expectedRevision: 1, now: VALIDATED_AT, report: validationReport(quarantined, { safe: false }) });
  assert.equal(unsafeRejected.status, "rejected");
  assert.equal(unsafeRejected.rejectionCode, "unsafe_content");
});

test("only the validated exact version can be promoted with configured KMS and Object Lock", async () => {
  const intent = await issued();
  const quarantined = await recordQuarantinedUpload(intent, { expectedRevision: 0, nonce: NONCE, now: RECEIVED_AT, receipt: quarantineReceipt(intent) });
  const validated = completeUploadValidation(quarantined, { expectedRevision: 1, now: VALIDATED_AT, report: validationReport(quarantined) });
  assert.equal(validated.status, "validated");
  if (validated.status !== "validated") return;

  assert.throws(() => promoteValidatedUpload(validated, {
    expectedRevision: 2,
    expectedKmsKeyArn: "arn:aws:kms:us-east-1:111111111111:key/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    expectedObjectLockMode: "COMPLIANCE",
    receipt: promotionReceipt(validated),
  }), hasCode("UPLOAD_MISMATCH"));
  assert.throws(() => promoteValidatedUpload(validated, {
    expectedRevision: 2,
    expectedKmsKeyArn: KMS_ARN,
    expectedObjectLockMode: "COMPLIANCE",
    receipt: promotionReceipt(validated, { finalKey: exactObjectKey(`tenants/${TENANT_B}/evidence/${RESOURCE_ID}.png`) }),
  }), hasCode("UPLOAD_MISMATCH"));
  assert.throws(() => promoteValidatedUpload(validated, {
    expectedRevision: 2,
    expectedKmsKeyArn: KMS_ARN,
    expectedObjectLockMode: "COMPLIANCE",
    receipt: promotionReceipt(validated, { sourceVersionId: "version-attacker" }),
  }), hasCode("UPLOAD_MISMATCH"));
  assert.throws(() => promoteValidatedUpload(validated, {
    expectedRevision: 2,
    expectedKmsKeyArn: KMS_ARN,
    expectedObjectLockMode: "COMPLIANCE",
    receipt: promotionReceipt(validated, { objectLockMode: "GOVERNANCE" }),
  }), hasCode("RETENTION_VIOLATION"));

  const promoted = promoteValidatedUpload(validated, {
    expectedRevision: 2,
    expectedKmsKeyArn: KMS_ARN,
    expectedObjectLockMode: "COMPLIANCE",
    receipt: promotionReceipt(validated),
  });
  assert.equal(promoted.status, "promoted");
  assert.equal(promoted.revision, 3);
  assert.throws(() => promoteValidatedUpload(promoted, {
    expectedRevision: 3,
    expectedKmsKeyArn: KMS_ARN,
    expectedObjectLockMode: "COMPLIANCE",
    receipt: promotionReceipt(validated),
  }), hasCode("ILLEGAL_STATE_TRANSITION"));
});
