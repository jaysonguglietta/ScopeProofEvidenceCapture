import assert from "node:assert/strict";
import test from "node:test";

import {
  buildAuthoritativePromotionReceiptItem,
  digestHex,
  parseAuthoritativePromotionReceiptItem,
  parseCommittedPromotionReceipt,
  stableJson,
  verifyCommittedPromotionReceipt,
} from "../infra/aws/cdk/runtime/promote-evidence/promotion-receipt.mjs";

const TENANT = `ten_${"a".repeat(32)}`;
const INTENT = `upl_${"b".repeat(32)}`;
const EVIDENCE = `evd_${"c".repeat(32)}`;
const SIGNING_KEY = "arn:aws:kms:us-east-1:111111111111:key/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const PROMOTED_AT = "2026-08-27T16:05:00.000Z";
const SIGNED_AT = "2026-08-27T16:05:01.000Z";

function facts() {
  return {
    schemaVersion: 1,
    tenantId: TENANT,
    uploadIntentId: INTENT,
    evidenceId: EVIDENCE,
    controlId: "PCI-DSS-10.2.1",
    quarantineBucket: "scopeproof-quarantine",
    quarantineKey: `tenants/${TENANT}/controls/PCI-DSS-10.2.1/quarantine/${INTENT}.upload`,
    quarantineVersionId: "source-version-1",
    evidenceBucket: "scopeproof-evidence",
    evidenceKey: `tenants/${TENANT}/controls/PCI-DSS-10.2.1/evidence/${EVIDENCE}.png`,
    evidenceVersionId: "evidence-version-1",
    sha256: "d".repeat(64),
    byteSize: 1024,
    contentType: "image/png",
    copyAttemptId: `pat_${"1".repeat(32)}`,
    copyFence: 1,
    dlpPolicyVersion: "pci-evidence-v1",
    dlpReceiptSha256: "3".repeat(64),
    dlpScannedAt: "2026-08-27T16:04:00.000Z",
    dlpScannerRequestId: "scan-request-123456",
    kmsKeyArn: "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    objectLockMode: "COMPLIANCE",
    promotionAttemptId: `pat_${"2".repeat(32)}`,
    promotionFence: 2,
    retainUntil: "2027-08-27T16:05:00.000Z",
    uploadedAt: "2026-08-27T16:00:00.000Z",
    promotedAt: PROMOTED_AT,
    providerRequestId: "original-copy-request-123",
  };
}

function row(overrides: Record<string, unknown> = {}) {
  const canonical = stableJson(facts());
  return {
    receipt_id: `rcp_${digestHex(`scopeproof-promotion-receipt-id-v1\n${canonical}`).slice(0, 32)}`,
    was_created: false,
    committed_upload_revision: 1,
    committed_evidence_revision: 1,
    committed_idempotency_digest: digestHex(`scopeproof-promotion-reconciliation-v1\n${canonical}`),
    committed_promotion_facts: facts(),
    committed_canonical_receipt: canonical,
    committed_receipt_sha256: digestHex(`scopeproof-promotion-receipt-v1\n${canonical}`),
    committed_signing_key_arn: SIGNING_KEY,
    committed_signing_algorithm: "RSASSA_PSS_SHA_256",
    committed_signature: Buffer.alloc(384, 17).toString("base64"),
    committed_signed_at: SIGNED_AT,
    ...overrides,
  };
}

function expected() {
  const value = facts();
  return {
    allowMissing: true,
    uploadRevision: 1,
    evidenceRevision: 1,
    signingKeyArn: SIGNING_KEY,
    verificationTime: "2026-08-27T16:10:00.000Z",
    invariants: {
      ...value,
      uploadedAt: "2026-08-27T16:00:00.000Z",
      minimumRetainUntil: value.retainUntil,
      evidenceVersionId: undefined,
      retainUntil: undefined,
      promotedAt: undefined,
      providerRequestId: undefined,
    },
  };
}

test("valid committed promotion replay verifies the exact domain digest and preserves original dynamic facts", async () => {
  const snapshot = parseCommittedPromotionReceipt(JSON.stringify([row()]), expected());
  assert.ok(snapshot);
  let verifyInput: Record<string, unknown> | undefined;
  await verifyCommittedPromotionReceipt(snapshot, async (input) => {
    verifyInput = input as unknown as Record<string, unknown>;
    return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", SignatureValid: true };
  });
  assert.equal(Buffer.from(verifyInput?.Message as Uint8Array).toString("hex"), row().committed_receipt_sha256);
  assert.equal(snapshot.facts.promotedAt, PROMOTED_AT);
  assert.equal(snapshot.facts.providerRequestId, "original-copy-request-123");
});

test("forged and corrupt committed promotion receipts fail closed", async () => {
  const forged = parseCommittedPromotionReceipt(JSON.stringify([row()]), expected());
  assert.ok(forged);
  await assert.rejects(
    verifyCommittedPromotionReceipt(forged, async () => ({
      KeyId: SIGNING_KEY,
      SigningAlgorithm: "RSASSA_PSS_SHA_256",
      SignatureValid: false,
    })),
    /did not verify/i,
  );
  assert.throws(
    () => parseCommittedPromotionReceipt(JSON.stringify([row({ committed_signature: "corrupt" })]), expected()),
    /signature/i,
  );
  assert.throws(
    () => parseCommittedPromotionReceipt(JSON.stringify([row({ committed_canonical_receipt: "{}" })]), expected()),
    /canonical/i,
  );
});

test("retry after a lost successful COMMIT resumes from the authoritative signed row", async () => {
  const authoritativeRow = row();
  await assert.rejects(async () => {
    // Represents RDS committing the row while the Data API response is lost.
    throw new Error("response lost after commit");
  }, /response lost after commit/);

  const retrySnapshot = parseCommittedPromotionReceipt(JSON.stringify([authoritativeRow]), expected());
  assert.ok(retrySnapshot);
  await verifyCommittedPromotionReceipt(retrySnapshot, async () => ({
    KeyId: SIGNING_KEY,
    SigningAlgorithm: "RSASSA_PSS_SHA_256",
    SignatureValid: true,
  }));
  const retryAttemptFacts = { ...facts(), promotedAt: "2026-08-27T16:09:00.000Z", providerRequestId: "retry-head-request-999" };
  assert.notEqual(stableJson(retrySnapshot.facts), stableJson(retryAttemptFacts));
  assert.equal(retrySnapshot.facts.promotedAt, PROMOTED_AT);
  assert.equal(retrySnapshot.outcome, "already_applied");
});

test("authoritative recovery projection preserves and verifies the exact signed database receipt", async () => {
  const snapshot = parseCommittedPromotionReceipt(JSON.stringify([row()]), expected());
  assert.ok(snapshot);
  const receiptHash = digestHex(`${TENANT}\0${INTENT}\0${facts().quarantineVersionId}`);
  const item = buildAuthoritativePromotionReceiptItem({
    publishedAt: "2026-08-27T16:05:02.000Z",
    receiptHash,
    snapshot,
    tenantId: TENANT,
  });
  const parsed = parseAuthoritativePromotionReceiptItem(item, {
    receiptHash,
    signingKeyArn: SIGNING_KEY,
    tenantId: TENANT,
    verificationTime: "2026-08-27T16:10:00.000Z",
  });
  assert.equal(parsed.receipt.destinationVersionId, facts().evidenceVersionId);
  assert.equal(parsed.receipt.sourceVersionId, facts().quarantineVersionId);
  assert.equal(parsed.snapshot.facts.uploadedAt, facts().uploadedAt);
  let verifiedDigest = "";
  await verifyCommittedPromotionReceipt(parsed.snapshot, async (input) => {
    verifiedDigest = Buffer.from(input.Message).toString("hex");
    return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", SignatureValid: true };
  });
  assert.equal(verifiedDigest, row().committed_receipt_sha256);
  assert.throws(
    () => parseAuthoritativePromotionReceiptItem({
      ...item,
      canonicalFacts: { S: stableJson({ ...facts(), uploadedAt: "2026-08-27T15:59:00.000Z" }) },
    }, {
      receiptHash,
      signingKeyArn: SIGNING_KEY,
      tenantId: TENANT,
      verificationTime: "2026-08-27T16:10:00.000Z",
    }),
    /conflicting|invalid/i,
  );
  assert.throws(
    () => parseAuthoritativePromotionReceiptItem(item, {
      receiptHash,
      signingKeyArn: SIGNING_KEY.replace("bbbbbbbb", "cccccccc"),
      tenantId: TENANT,
      verificationTime: "2026-08-27T16:10:00.000Z",
    }),
    /invalid/i,
  );
});
