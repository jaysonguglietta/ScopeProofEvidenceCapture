import assert from "node:assert/strict";
import test from "node:test";

import { TenantSecurityError } from "../lib/aws-runtime/contracts.ts";
import {
  reconcileEvidencePromotion,
  type AtomicPromotionCommand,
  type AtomicPromotionResult,
  type AtomicPromotionStore,
  type CommittedPromotionSnapshot,
  type PromotionReconciliationRequest,
} from "../lib/aws-runtime/evidence/index.ts";

const TENANT = `ten_${"a".repeat(32)}`;
const OTHER_TENANT = `ten_${"b".repeat(32)}`;
const INTENT = `upl_${"c".repeat(32)}`;
const EVIDENCE = `evd_${"d".repeat(32)}`;
const RECEIPT = `rcp_${"e".repeat(32)}`;
const CONTROL = "PCI-DSS-10.2.1";
const QUARANTINE_BUCKET = "scopeproof-quarantine";
const EVIDENCE_BUCKET = "scopeproof-evidence";
const KMS_ARN = "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

function hasCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof TenantSecurityError);
    assert.equal(error.code, code);
    return true;
  };
}

function request(overrides: Partial<PromotionReconciliationRequest> = {}): PromotionReconciliationRequest {
  return {
    tenantId: TENANT,
    uploadIntentId: INTENT,
    evidenceId: EVIDENCE,
    controlId: CONTROL,
    quarantineBucket: QUARANTINE_BUCKET,
    quarantineKey: `tenants/${TENANT}/controls/${CONTROL}/quarantine/${INTENT}.upload`,
    quarantineVersionId: "quarantine-version-1",
    evidenceBucket: EVIDENCE_BUCKET,
    evidenceKey: `tenants/${TENANT}/controls/${CONTROL}/evidence/${EVIDENCE}.png`,
    evidenceVersionId: "evidence-version-1",
    sha256: "f".repeat(64),
    byteSize: 4_096,
    contentType: "image/png",
    copyAttemptId: `pat_${"1".repeat(32)}`,
    copyFence: 1,
    kmsKeyArn: KMS_ARN,
    objectLockMode: "COMPLIANCE",
    retainUntil: "2027-08-27T16:05:00.000Z",
    uploadedAt: "2026-08-27T16:00:00.000Z",
    promotedAt: "2026-08-27T16:05:00.000Z",
    providerRequestId: "s3-request-0001",
    promotionAttemptId: `pat_${"2".repeat(32)}`,
    promotionFence: 2,
    promotionLeaseExpiresAt: "2026-08-27T16:10:00.000Z",
    receiptId: RECEIPT,
    expectedUploadRevision: 2,
    expectedEvidenceRevision: 4,
    requiredRetentionUntil: "2027-08-27T16:05:00.000Z",
    ...overrides,
  };
}

const policy = {
  quarantineBucket: QUARANTINE_BUCKET,
  evidenceBucket: EVIDENCE_BUCKET,
  evidenceKmsKeyArn: KMS_ARN,
  objectLockMode: "COMPLIANCE" as const,
};

function snapshot(command: AtomicPromotionCommand, overrides: Partial<CommittedPromotionSnapshot> = {}): CommittedPromotionSnapshot {
  return {
    receiptId: command.receiptId,
    idempotencyDigest: command.idempotencyDigest,
    uploadRevision: command.expectedUploadRevision + 1,
    evidenceRevision: command.expectedEvidenceRevision + 1,
    facts: command.facts,
    ...overrides,
  };
}

test("promotion reconciliation atomically persists exact immutable storage facts", async () => {
  let observed: AtomicPromotionCommand | undefined;
  const store: AtomicPromotionStore = {
    async transactPromotion(command): Promise<AtomicPromotionResult> {
      observed = command;
      return { outcome: "applied", committed: true, snapshot: snapshot(command) };
    },
  };
  const result = await reconcileEvidencePromotion(store, request(), policy);
  assert.equal(result.outcome, "applied");
  assert.equal(result.uploadRevision, 3);
  assert.equal(result.evidenceRevision, 5);
  assert.match(result.idempotencyDigest, /^[a-f0-9]{64}$/);
  assert.equal(observed?.facts.evidenceVersionId, "evidence-version-1");
  assert.equal(observed?.facts.kmsKeyArn, KMS_ARN);
  assert.equal(observed?.facts.retainUntil, "2027-08-27T16:05:00.000Z");
});

test("identical partial retries are idempotent but conflicting versions fail closed", async () => {
  let committed: CommittedPromotionSnapshot | undefined;
  const store: AtomicPromotionStore = {
    async transactPromotion(command): Promise<AtomicPromotionResult> {
      if (!committed) {
        committed = snapshot(command);
        return { outcome: "applied", committed: true, snapshot: committed };
      }
      return { outcome: "already_applied", committed: true, snapshot: committed };
    },
  };
  const first = await reconcileEvidencePromotion(store, request(), policy);
  const retry = await reconcileEvidencePromotion(store, request(), policy);
  assert.equal(first.idempotencyDigest, retry.idempotencyDigest);
  assert.equal(retry.outcome, "already_applied");

  await assert.rejects(
    reconcileEvidencePromotion(store, request({ evidenceVersionId: "evidence-version-attacker" }), policy),
    hasCode("UPLOAD_MISMATCH"),
  );
});

test("reconciliation rejects tenant crossing, path substitution, checksum, KMS, lock, and bucket drift", async () => {
  const shouldNotRun: AtomicPromotionStore = {
    async transactPromotion(): Promise<AtomicPromotionResult> {
      assert.fail("invalid facts must not reach the database");
    },
  };
  await assert.rejects(reconcileEvidencePromotion(shouldNotRun, request({
    evidenceKey: `tenants/${OTHER_TENANT}/controls/${CONTROL}/evidence/${EVIDENCE}.png`,
  }), policy), hasCode("UPLOAD_MISMATCH"));
  await assert.rejects(reconcileEvidencePromotion(shouldNotRun, request({
    quarantineKey: `tenants/${TENANT}/controls/${CONTROL}/quarantine/${INTENT}.upload/../victim`,
  }), policy), hasCode("UPLOAD_MISMATCH"));
  await assert.rejects(reconcileEvidencePromotion(shouldNotRun, request({ sha256: "A".repeat(64) }), policy), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(reconcileEvidencePromotion(shouldNotRun, request({
    kmsKeyArn: "arn:aws:kms:us-east-1:111111111111:key/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
  }), policy), hasCode("UPLOAD_MISMATCH"));
  await assert.rejects(reconcileEvidencePromotion(shouldNotRun, request({ objectLockMode: "GOVERNANCE" }), policy), hasCode("RETENTION_VIOLATION"));
  await assert.rejects(reconcileEvidencePromotion(shouldNotRun, request({
    requiredRetentionUntil: "2028-08-27T16:05:00.000Z",
  }), policy), hasCode("RETENTION_VIOLATION"));
  await assert.rejects(reconcileEvidencePromotion(shouldNotRun, request({ evidenceBucket: "attacker-evidence" }), policy), hasCode("UPLOAD_MISMATCH"));
});

test("CAS, idempotency conflicts, transaction failures, and partial snapshots never report success", async () => {
  const conditionStore: AtomicPromotionStore = {
    async transactPromotion(): Promise<AtomicPromotionResult> {
      return { outcome: "condition_failed", committed: false, reason: "revision_changed" };
    },
  };
  await assert.rejects(reconcileEvidencePromotion(conditionStore, request(), policy), hasCode("CONCURRENT_MODIFICATION"));

  const conflictStore: AtomicPromotionStore = {
    async transactPromotion(): Promise<AtomicPromotionResult> {
      return { outcome: "condition_failed", committed: false, reason: "idempotency_conflict" };
    },
  };
  await assert.rejects(reconcileEvidencePromotion(conflictStore, request(), policy), hasCode("UPLOAD_MISMATCH"));

  const rollbackStore: AtomicPromotionStore = {
    async transactPromotion(): Promise<AtomicPromotionResult> {
      throw new Error("transaction rolled back after receipt insert");
    },
  };
  await assert.rejects(reconcileEvidencePromotion(rollbackStore, request(), policy), /transaction rolled back/);

  const partialStore: AtomicPromotionStore = {
    async transactPromotion(command): Promise<AtomicPromotionResult> {
      return {
        outcome: "applied",
        committed: true,
        snapshot: snapshot(command, { evidenceRevision: command.expectedEvidenceRevision }),
      };
    },
  };
  await assert.rejects(reconcileEvidencePromotion(partialStore, request(), policy), hasCode("UPLOAD_MISMATCH"));
});
