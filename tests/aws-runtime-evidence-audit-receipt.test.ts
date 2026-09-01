import assert from "node:assert/strict";
import test from "node:test";

import { createTenantAuditEvent, type TenantAuditEvent } from "../lib/aws-runtime/audit.ts";
import {
  asMembershipId,
  asResourceId,
  asTenantId,
  asUserId,
  TenantSecurityError,
} from "../lib/aws-runtime/contracts.ts";
import {
  AUDIT_RECEIPT_DOMAIN,
  auditReceiptDigest,
  signTenantAuditReceipt,
  verifyTenantAuditReceipt,
  type KmsAsymmetricSigningClient,
  type KmsSignInput,
  type KmsSignOutput,
  type KmsVerifyInput,
  type KmsVerifyOutput,
  type KmsSignedAuditReceipt,
} from "../lib/aws-runtime/evidence/index.ts";

const TENANT = asTenantId(`ten_${"a".repeat(32)}`);
const OTHER_TENANT = asTenantId(`ten_${"b".repeat(32)}`);
const USER = asUserId(`usr_${"c".repeat(32)}`);
const MEMBERSHIP = asMembershipId(`mem_${"d".repeat(32)}`);
const EVIDENCE = asResourceId(`evd_${"e".repeat(32)}`);
const KMS_ARN = "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function hasCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof TenantSecurityError);
    assert.equal(error.code, code);
    return true;
  };
}

class RecordingKms implements KmsAsymmetricSigningClient {
  signInputs: KmsSignInput[] = [];
  verifyInputs: KmsVerifyInput[] = [];
  valid = true;

  async sign(input: KmsSignInput): Promise<KmsSignOutput> {
    this.signInputs.push(input);
    return {
      KeyId: input.KeyId,
      SigningAlgorithm: input.SigningAlgorithm,
      Signature: new Uint8Array(64).fill(7),
    };
  }

  async verify(input: KmsVerifyInput): Promise<KmsVerifyOutput> {
    this.verifyInputs.push(input);
    return {
      KeyId: input.KeyId,
      SigningAlgorithm: input.SigningAlgorithm,
      SignatureValid: this.valid && input.Signature.every((byte) => byte === 7),
    };
  }
}

async function event(): Promise<TenantAuditEvent> {
  return createTenantAuditEvent({
    tenantId: TENANT,
    sequence: 1,
    id: `evt_${"f".repeat(32)}`,
    occurredAt: "2026-08-27T16:00:00.000Z",
    actor: { type: "user", userId: USER, membershipId: MEMBERSHIP },
    action: "evidence.promoted",
    resourceType: "evidence",
    resourceId: EVIDENCE,
    requestId: "request-0001",
    outcome: "succeeded",
    details: { objectVersion: "version-0001", checksumSha256: "1".repeat(64) },
    previousHash: "GENESIS",
  });
}

test("audit receipts are canonical, domain-separated, and KMS-signed as SHA-256 digests", async () => {
  const kms = new RecordingKms();
  const auditEvent = await event();
  const receipt = await signTenantAuditReceipt({
    client: kms,
    event: auditEvent,
    keyArn: KMS_ARN,
    signingAlgorithm: "ECDSA_SHA_256",
    signedAt: "2026-08-27T16:00:01.000Z",
  });
  assert.equal(receipt.payload.domain, AUDIT_RECEIPT_DOMAIN);
  assert.equal(receipt.payload.eventHash, auditEvent.eventHash);
  assert.equal(receipt.payloadSha256, await auditReceiptDigest(receipt.payload));
  assert.equal(kms.signInputs.length, 1);
  assert.equal(kms.signInputs[0].MessageType, "DIGEST");
  assert.equal(kms.signInputs[0].Message.byteLength, 32);
  assert.equal(receipt.signature, "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBw==");

  await verifyTenantAuditReceipt({ client: kms, receipt, expectedEvent: auditEvent, expectedKeyArn: KMS_ARN, expectedTenantId: TENANT });
  assert.equal(kms.verifyInputs.length, 1);
  assert.deepEqual(kms.verifyInputs[0].Message, kms.signInputs[0].Message);
  assert.deepEqual(kms.verifyInputs[0].Signature, new Uint8Array(64).fill(7));
});

test("tampered payloads, signatures, keys, tenants, and algorithms fail closed", async () => {
  const kms = new RecordingKms();
  const auditEvent = await event();
  const receipt = await signTenantAuditReceipt({
    client: kms,
    event: auditEvent,
    keyArn: KMS_ARN,
    signingAlgorithm: "ECDSA_SHA_256",
    signedAt: "2026-08-27T16:00:01.000Z",
  });
  const changedAction = {
    ...receipt,
    payload: { ...receipt.payload, action: "evidence.deleted" },
  } as KmsSignedAuditReceipt;
  await assert.rejects(verifyTenantAuditReceipt({ client: kms, receipt: changedAction, expectedEvent: auditEvent, expectedKeyArn: KMS_ARN, expectedTenantId: TENANT }), hasCode("INVALID_AUDIT_EVENT"));

  const changedSignature = { ...receipt, signature: receipt.signature.replace(/^B/, "C") };
  await assert.rejects(verifyTenantAuditReceipt({ client: kms, receipt: changedSignature, expectedEvent: auditEvent, expectedKeyArn: KMS_ARN, expectedTenantId: TENANT }), hasCode("INVALID_AUDIT_EVENT"));
  await assert.rejects(verifyTenantAuditReceipt({ client: kms, receipt, expectedEvent: auditEvent, expectedKeyArn: KMS_ARN, expectedTenantId: OTHER_TENANT }), hasCode("RESOURCE_NOT_FOUND"));
  await assert.rejects(verifyTenantAuditReceipt({
    client: kms,
    receipt: { ...receipt, signingAlgorithm: "RSASSA_PKCS1_V1_5_SHA_256" as never },
    expectedEvent: auditEvent,
    expectedKeyArn: KMS_ARN,
    expectedTenantId: TENANT,
  }), hasCode("INVALID_AUDIT_EVENT"));
});

test("KMS response substitution and negative verification are rejected", async () => {
  const wrongKeyClient: KmsAsymmetricSigningClient = {
    async sign(input): Promise<KmsSignOutput> {
      return { ...input, KeyId: "arn:aws:kms:us-east-1:111111111111:key/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", Signature: new Uint8Array(64) };
    },
    async verify(): Promise<KmsVerifyOutput> {
      return { SignatureValid: false };
    },
  };
  await assert.rejects(signTenantAuditReceipt({
    client: wrongKeyClient,
    event: await event(),
    keyArn: KMS_ARN,
    signingAlgorithm: "ECDSA_SHA_256",
    signedAt: "2026-08-27T16:00:01.000Z",
  }), hasCode("INVALID_AUDIT_EVENT"));

  const kms = new RecordingKms();
  const auditEvent = await event();
  const receipt = await signTenantAuditReceipt({
    client: kms,
    event: auditEvent,
    keyArn: KMS_ARN,
    signingAlgorithm: "RSASSA_PSS_SHA_256",
    signedAt: "2026-08-27T16:00:01.000Z",
  });
  kms.valid = false;
  await assert.rejects(verifyTenantAuditReceipt({ client: kms, receipt, expectedEvent: auditEvent, expectedKeyArn: KMS_ARN, expectedTenantId: TENANT }), hasCode("INVALID_AUDIT_EVENT"));
});

test("signing rejects forged event hashes and receipt timestamps before the event", async () => {
  const kms = new RecordingKms();
  const auditEvent = await event();
  await assert.rejects(signTenantAuditReceipt({
    client: kms,
    event: { ...auditEvent, eventHash: "0".repeat(64) as TenantAuditEvent["eventHash"] },
    keyArn: KMS_ARN,
    signingAlgorithm: "ECDSA_SHA_256",
    signedAt: "2026-08-27T16:00:01.000Z",
  }), hasCode("INVALID_AUDIT_EVENT"));
  await assert.rejects(signTenantAuditReceipt({
    client: kms,
    event: auditEvent,
    keyArn: KMS_ARN,
    signingAlgorithm: "ECDSA_SHA_256",
    signedAt: "2026-08-27T15:59:59.000Z",
  }), hasCode("INVALID_AUDIT_EVENT"));
  assert.equal(kms.signInputs.length, 0);
});
