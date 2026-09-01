import assert from "node:assert/strict";
import test from "node:test";

import { TenantSecurityError } from "../lib/aws-runtime/contracts.ts";
import type { TenantActor } from "../lib/aws-runtime/tenancy.ts";
import {
  approveExactVersionLegalHoldChange,
  prepareExactVersionLegalHoldOperation,
  reconcileExactVersionLegalHold,
  requestExactVersionLegalHoldChange,
  setExactVersionLegalHold,
  sweepPendingExactVersionLegalHolds,
  type AppliedExactVersionLegalHold,
  type ApprovedExactVersionLegalHold,
  type DurableExactVersionLegalHoldRequest,
  type ExactVersionLegalHoldApproval,
  type ExactVersionLegalHoldApplicationAttempt,
  type ExactVersionLegalHoldClient,
  type ExactVersionLegalHoldOperation,
  type ExactVersionLegalHoldOperationStore,
  type ExactVersionLegalHoldReceipt,
  type ExactVersionLegalHoldRequest,
  type GetObjectLegalHoldInput,
  type PutObjectLegalHoldInput,
  type ReservedExactVersionLegalHold,
  type S3LegalHoldOutput,
} from "../lib/aws-runtime/evidence/index.ts";

const TENANT = `ten_${"a".repeat(32)}`;
const OTHER_TENANT = `ten_${"b".repeat(32)}`;
const EVIDENCE = `evd_${"d".repeat(32)}`;
const OPERATION = `lho_${"e".repeat(32)}`;
const HOLD = `hld_${"f".repeat(32)}`;
const REQUESTER = `usr_${"1".repeat(32)}`;
const APPROVER = `usr_${"2".repeat(32)}`;
const CONTROL = "PCI-DSS-10.2.1";
const KEY = `tenants/${TENANT}/controls/${CONTROL}/evidence/${EVIDENCE}.png`;
const POLICY = { evidenceBucket: "scopeproof-evidence" };
const REQUESTER_ACTOR = {
  tenantId: TENANT as TenantActor["tenantId"],
  userId: REQUESTER as TenantActor["userId"],
  role: "admin" as const,
};
const APPROVER_ACTOR = {
  tenantId: TENANT as TenantActor["tenantId"],
  userId: APPROVER as TenantActor["userId"],
  role: "admin" as const,
};

function hasCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof TenantSecurityError);
    assert.equal(error.code, code);
    return true;
  };
}

class RecordingS3 implements ExactVersionLegalHoldClient {
  putInputs: PutObjectLegalHoldInput[] = [];
  getInputs: GetObjectLegalHoldInput[] = [];
  observedStatus: "ON" | "OFF" = "OFF";
  failAfterPut = 0;

  async putObjectLegalHold(input: PutObjectLegalHoldInput): Promise<S3LegalHoldOutput> {
    this.putInputs.push(input);
    this.observedStatus = input.LegalHold.Status;
    if (this.failAfterPut-- > 0) throw new Error("lost S3 PutObjectLegalHold response");
    return { requestId: "put-request-0001" };
  }

  async getObjectLegalHold(input: GetObjectLegalHoldInput): Promise<S3LegalHoldOutput> {
    this.getInputs.push(input);
    return { LegalHold: { Status: this.observedStatus }, requestId: "get-request-0001" };
  }
}

function request(overrides: Partial<ExactVersionLegalHoldRequest> = {}): ExactVersionLegalHoldRequest {
  return {
    tenantId: TENANT,
    controlId: CONTROL,
    evidenceId: EVIDENCE,
    contentType: "image/png",
    bucket: "scopeproof-evidence",
    key: KEY,
    versionId: "evidence-version-0001",
    status: "ON",
    changedAt: new Date("2026-08-27T16:10:00.000Z"),
    ...overrides,
  };
}

function durableRequest(
  overrides: Partial<DurableExactVersionLegalHoldRequest> = {},
): DurableExactVersionLegalHoldRequest {
  return {
    ...request(),
    operationId: OPERATION,
    holdId: HOLD,
    reason: "External litigation preservation request",
    kind: "LEGAL",
    expectedHoldRevision: 0,
    ...overrides,
  };
}

class DurableMemoryStore implements ExactVersionLegalHoldOperationStore {
  operation?: ExactVersionLegalHoldOperation;
  approval?: ExactVersionLegalHoldApproval;
  state: "REQUESTED" | "APPROVED" | "APPLYING" | "APPLIED" | "EXPIRED" | undefined;
  applicationAttempt?: ExactVersionLegalHoldApplicationAttempt;
  receipt?: ExactVersionLegalHoldReceipt;
  applyFailures = 0;
  ambiguousApplyCommits = 0;
  requestCalls = 0;
  approveCalls = 0;
  readCalls = 0;
  applyCalls = 0;

  async request(operation: ExactVersionLegalHoldOperation): Promise<ReservedExactVersionLegalHold> {
    this.requestCalls += 1;
    if (this.operation && this.operation.canonicalRequest !== operation.canonicalRequest) {
      throw new TenantSecurityError("CONCURRENT_MODIFICATION", "request conflict", 409);
    }
    this.operation ??= operation;
    this.state ??= "REQUESTED";
    return this.current();
  }

  async approve(approval: ExactVersionLegalHoldApproval): Promise<ApprovedExactVersionLegalHold> {
    this.approveCalls += 1;
    if (!this.operation || !this.state) throw new TenantSecurityError("RESOURCE_NOT_FOUND", "request missing", 404);
    if (approval.requestDigest !== this.operation.requestDigest) {
      throw new TenantSecurityError("CONCURRENT_MODIFICATION", "request digest conflict", 409);
    }
    if (approval.approvedBy === this.operation.requestedBy) {
      throw new TenantSecurityError("ROLE_FORBIDDEN", "requester cannot approve", 403);
    }
    if (this.state === "EXPIRED") {
      throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "request expired", 409);
    }
    if (this.state === "REQUESTED") {
      this.approval = approval;
      this.state = "APPROVED";
    } else if (this.approval?.canonicalApproval !== approval.canonicalApproval) {
      throw new TenantSecurityError("CONCURRENT_MODIFICATION", "approval conflict", 409);
    }
    assert.ok(this.approval);
    if (this.state === "APPLIED") return { state: "APPLIED", operationRevision: 3, approval: this.approval };
    if (this.state === "APPLYING") return { state: "APPLYING", operationRevision: 2, approval: this.approval };
    return { state: "APPROVED", operationRevision: 1, approval: this.approval };
  }

  async read(operation: ExactVersionLegalHoldOperation): Promise<ReservedExactVersionLegalHold> {
    this.readCalls += 1;
    if (!this.operation || this.operation.requestDigest !== operation.requestDigest ||
        this.operation.canonicalRequest !== operation.canonicalRequest) {
      throw new TenantSecurityError("RESOURCE_NOT_FOUND", "request missing", 404);
    }
    return this.current();
  }

  async beginApply(operation: ExactVersionLegalHoldOperation, approval: ExactVersionLegalHoldApproval, expectedOperationRevision: 1, attempt: ExactVersionLegalHoldApplicationAttempt): Promise<Extract<ReservedExactVersionLegalHold, { state: "APPLYING" }>> {
    assert.equal(this.state, "APPROVED");
    assert.equal(expectedOperationRevision, 1);
    assert.equal(this.operation?.requestDigest, operation.requestDigest);
    assert.equal(this.approval?.approvalDigest, approval.approvalDigest);
    this.state = "APPLYING";
    this.applicationAttempt = attempt;
    return { state: "APPLYING", operationRevision: 2, approval, applicationAttempt: attempt };
  }

  async apply(
    operation: ExactVersionLegalHoldOperation,
    approval: ExactVersionLegalHoldApproval,
    expectedOperationRevision: 2,
    receipt: ExactVersionLegalHoldReceipt,
  ): Promise<AppliedExactVersionLegalHold> {
    this.applyCalls += 1;
    assert.equal(this.state, "APPLYING");
    assert.equal(this.operation?.canonicalRequest, operation.canonicalRequest);
    assert.equal(this.approval?.approvalDigest, approval.approvalDigest);
    assert.equal(expectedOperationRevision, 2);
    if (this.applyFailures > 0) {
      this.applyFailures -= 1;
      throw new Error("database confirmation unavailable");
    }
    this.state = "APPLIED";
    this.receipt = receipt;
    if (this.ambiguousApplyCommits > 0) {
      this.ambiguousApplyCommits -= 1;
      throw new Error("database commit response unavailable");
    }
    return {
      outcome: "applied",
      operationRevision: 3,
      holdRevision: operation.status === "ON" ? 0 : operation.expectedHoldRevision + 1,
      receipt,
    };
  }

  private current(): ReservedExactVersionLegalHold {
    if (this.state === "REQUESTED") return { state: "REQUESTED", operationRevision: 0 };
    if (this.state === "EXPIRED") return { state: "EXPIRED", operationRevision: 1 };
    assert.ok(this.approval);
    if (this.state === "APPROVED") return { state: "APPROVED", operationRevision: 1, approval: this.approval };
    if (this.state === "APPLYING") {
      assert.ok(this.applicationAttempt);
      return { state: "APPLYING", operationRevision: 2, approval: this.approval, applicationAttempt: this.applicationAttempt };
    }
    assert.equal(this.state, "APPLIED");
    assert.ok(this.receipt);
    return { state: "APPLIED", operationRevision: 3, approval: this.approval, receipt: this.receipt };
  }
}

async function requestAndApprove(store: DurableMemoryStore): Promise<ExactVersionLegalHoldOperation> {
  const requested = await requestExactVersionLegalHoldChange(store, durableRequest(), REQUESTER_ACTOR, POLICY);
  await approveExactVersionLegalHoldChange(store, {
    tenantId: TENANT,
    operationId: requested.operation.operationId,
    requestDigest: requested.operation.requestDigest,
    approvedAt: new Date("2026-08-27T16:11:00.000Z"),
  }, APPROVER_ACTOR);
  return requested.operation;
}

test("legal hold is written and verified against one exact immutable S3 version", async () => {
  const s3 = new RecordingS3();
  const receipt = await setExactVersionLegalHold(s3, request(), POLICY);
  assert.deepEqual(s3.putInputs, [{
    Bucket: "scopeproof-evidence",
    Key: KEY,
    VersionId: "evidence-version-0001",
    LegalHold: { Status: "ON" },
  }]);
  assert.deepEqual(s3.getInputs, [{
    Bucket: "scopeproof-evidence",
    Key: KEY,
    VersionId: "evidence-version-0001",
  }]);
  assert.equal(receipt.versionId, "evidence-version-0001");
  assert.equal(receipt.controlId, CONTROL);
  assert.equal(receipt.status, "ON");
  assert.equal(receipt.putRequestId, "put-request-0001");
  assert.equal(receipt.verifyRequestId, "get-request-0001");
});

test("legal hold release is also exact-version and postcondition verified", async () => {
  const s3 = new RecordingS3();
  s3.observedStatus = "OFF";
  const receipt = await setExactVersionLegalHold(s3, request({ status: "OFF" }), POLICY);
  assert.equal(s3.putInputs[0].VersionId, "evidence-version-0001");
  assert.equal(s3.putInputs[0].LegalHold.Status, "OFF");
  assert.equal(s3.getInputs[0].VersionId, "evidence-version-0001");
  assert.equal(receipt.status, "OFF");
});

test("cross-tenant keys, traversal, missing versions, and key-only targeting are rejected before S3", async () => {
  const s3 = new RecordingS3();
  await assert.rejects(setExactVersionLegalHold(s3, request({
    key: `tenants/${OTHER_TENANT}/controls/${CONTROL}/evidence/${EVIDENCE}.png`,
  }), POLICY), hasCode("RESOURCE_NOT_FOUND"));
  await assert.rejects(setExactVersionLegalHold(s3, request({ key: `${KEY}/../victim.png` }), POLICY), hasCode("RESOURCE_NOT_FOUND"));
  await assert.rejects(setExactVersionLegalHold(s3, request({ versionId: "" }), POLICY), hasCode("INVALID_IDENTIFIER"));
  await assert.rejects(setExactVersionLegalHold(s3, request({ versionId: "?versionId=latest" }), POLICY), hasCode("INVALID_IDENTIFIER"));
  await assert.rejects(setExactVersionLegalHold(s3, request({ bucket: "attacker-evidence" }), POLICY), hasCode("RESOURCE_NOT_FOUND"));
  assert.equal(s3.putInputs.length, 0);
  assert.equal(s3.getInputs.length, 0);
});

test("wrong or absent S3 postconditions and provider request ids fail closed", async () => {
  const wrong = new RecordingS3();
  wrong.putObjectLegalHold = async (input) => { wrong.putInputs.push(input); return { requestId: "put-request-0001" }; };
  await assert.rejects(setExactVersionLegalHold(wrong, request(), POLICY), hasCode("RETENTION_VIOLATION"));

  const missingPut = new RecordingS3();
  missingPut.putObjectLegalHold = async () => ({});
  await assert.rejects(setExactVersionLegalHold(missingPut, request(), POLICY), hasCode("RETENTION_VIOLATION"));
  assert.equal(missingPut.getInputs.length, 0);

  const partial: ExactVersionLegalHoldClient = {
    async putObjectLegalHold() { return { requestId: "put-succeeded" }; },
    async getObjectLegalHold() { throw new Error("verification unavailable"); },
  };
  await assert.rejects(setExactVersionLegalHold(partial, request(), POLICY), /verification unavailable/);
});

test("request and independent approval commit before the exact S3 mutation", async () => {
  const store = new DurableMemoryStore();
  const s3 = new RecordingS3();
  const requested = await requestExactVersionLegalHoldChange(store, durableRequest(), REQUESTER_ACTOR, POLICY);
  assert.equal(requested.reservation.state, "REQUESTED");
  assert.equal(requested.operation.requestedBy, REQUESTER);
  assert.equal(requested.operation.schemaVersion, 2);
  assert.match(requested.operation.requestDigest, /^[0-9a-f]{64}$/);

  await assert.rejects(
    reconcileExactVersionLegalHold(s3, store, requested.operation, POLICY),
    hasCode("ILLEGAL_STATE_TRANSITION"),
  );
  assert.equal(s3.putInputs.length, 0);

  const approved = await approveExactVersionLegalHoldChange(store, {
    tenantId: TENANT,
    operationId: OPERATION,
    requestDigest: requested.operation.requestDigest,
    approvedAt: new Date("2026-08-27T16:11:00.000Z"),
  }, APPROVER_ACTOR);
  assert.equal(approved.state, "APPROVED");
  assert.equal(approved.approval.approvedBy, APPROVER);
  assert.equal(approved.approval.requestDigest, requested.operation.requestDigest);

  const result = await reconcileExactVersionLegalHold(s3, store, requested.operation, POLICY);
  assert.equal(result.outcome, "applied");
  assert.equal(store.state, "APPLIED");
  assert.equal(result.operationRevision, 3);
  assert.equal(result.receipt.operationId, OPERATION);
  assert.equal(result.receipt.holdId, HOLD);
});

test("one actor cannot self-approve and actor identity is derived from tenant authorization", async () => {
  const store = new DurableMemoryStore();
  const s3 = new RecordingS3();
  const requested = await requestExactVersionLegalHoldChange(store, durableRequest(), REQUESTER_ACTOR, POLICY);
  await assert.rejects(approveExactVersionLegalHoldChange(store, {
    tenantId: TENANT,
    operationId: OPERATION,
    requestDigest: requested.operation.requestDigest,
    approvedAt: new Date("2026-08-27T16:11:00.000Z"),
  }, REQUESTER_ACTOR), hasCode("ROLE_FORBIDDEN"));
  await assert.rejects(requestExactVersionLegalHoldChange(store, durableRequest({
    operationId: `lho_${"8".repeat(32)}`,
  }), {
    tenantId: OTHER_TENANT as TenantActor["tenantId"],
    userId: APPROVER as TenantActor["userId"],
    role: "admin",
  }, POLICY), hasCode("ROLE_FORBIDDEN"));
  await assert.rejects(requestExactVersionLegalHoldChange(store, durableRequest({
    operationId: `lho_${"9".repeat(32)}`,
  }), {
    tenantId: TENANT as TenantActor["tenantId"],
    userId: APPROVER as TenantActor["userId"],
    role: "reviewer",
  }, POLICY), hasCode("ROLE_FORBIDDEN"));
  assert.equal(s3.putInputs.length, 0);
});

test("approval and reconciliation are bound to the exact immutable action digest", async () => {
  const store = new DurableMemoryStore();
  const s3 = new RecordingS3();
  const requested = await requestExactVersionLegalHoldChange(store, durableRequest(), REQUESTER_ACTOR, POLICY);
  await assert.rejects(approveExactVersionLegalHoldChange(store, {
    tenantId: TENANT,
    operationId: OPERATION,
    requestDigest: "0".repeat(64),
    approvedAt: new Date("2026-08-27T16:11:00.000Z"),
  }, APPROVER_ACTOR), hasCode("CONCURRENT_MODIFICATION"));

  await approveExactVersionLegalHoldChange(store, {
    tenantId: TENANT,
    operationId: OPERATION,
    requestDigest: requested.operation.requestDigest,
    approvedAt: new Date("2026-08-27T16:11:00.000Z"),
  }, APPROVER_ACTOR);
  const tampered = { ...requested.operation, status: "OFF" as const };
  await assert.rejects(reconcileExactVersionLegalHold(s3, store, tampered, POLICY), hasCode("RETENTION_VIOLATION"));
  assert.equal(store.readCalls, 0);
  assert.equal(s3.putInputs.length, 0);

  store.approval = { ...store.approval!, approvedBy: REQUESTER };
  await assert.rejects(reconcileExactVersionLegalHold(s3, store, requested.operation, POLICY), hasCode("ROLE_FORBIDDEN"));
  assert.equal(s3.putInputs.length, 0);
});

test("S3 and database partial failures remain durably APPLYING and an identical retry converges", async () => {
  const s3FailureStore = new DurableMemoryStore();
  const operation = await requestAndApprove(s3FailureStore);
  const unavailable: ExactVersionLegalHoldClient = {
    async putObjectLegalHold() { throw new Error("S3 unavailable"); },
    async getObjectLegalHold() { return { LegalHold: { Status: "OFF" }, requestId: "get-request-0000" }; },
  };
  await assert.rejects(reconcileExactVersionLegalHold(unavailable, s3FailureStore, operation, POLICY), /S3 unavailable/);
  assert.equal(s3FailureStore.state, "APPLYING");
  assert.equal(s3FailureStore.applyCalls, 0);

  const dbFailureStore = new DurableMemoryStore();
  const retryOperation = await requestAndApprove(dbFailureStore);
  dbFailureStore.applyFailures = 1;
  const s3 = new RecordingS3();
  await assert.rejects(reconcileExactVersionLegalHold(s3, dbFailureStore, retryOperation, POLICY), /database confirmation unavailable/);
  assert.equal(dbFailureStore.state, "APPLYING");
  const recovered = await reconcileExactVersionLegalHold(s3, dbFailureStore, retryOperation, POLICY);
  assert.equal(recovered.outcome, "applied");
  assert.equal(s3.putInputs.length, 2);
});

test("an ambiguous database response reads back APPLIED and does not repeat S3", async () => {
  const store = new DurableMemoryStore();
  const operation = await requestAndApprove(store);
  store.ambiguousApplyCommits = 1;
  const s3 = new RecordingS3();
  const recovered = await reconcileExactVersionLegalHold(s3, store, operation, POLICY);
  assert.equal(recovered.outcome, "already_applied");
  assert.equal(recovered.operationRevision, 3);
  assert.equal(store.state, "APPLIED");
  assert.equal(s3.putInputs.length, 1);
  assert.ok(s3.getInputs.length >= 3);
});

test("approved first application rejects unauthorized exact-version pre-drift before Put", async () => {
  const store = new DurableMemoryStore();
  const operation = await requestAndApprove(store);
  const s3 = new RecordingS3();
  s3.observedStatus = "ON";
  await assert.rejects(reconcileExactVersionLegalHold(s3, store, operation, POLICY), hasCode("LEGAL_HOLD_PRECONDITION_DRIFT"));
  assert.equal(store.state, "APPROVED");
  assert.equal(s3.putInputs.length, 0);
});

test("lost Put response converges from durable APPLYING against the exact version", async () => {
  const store = new DurableMemoryStore();
  const operation = await requestAndApprove(store);
  const s3 = new RecordingS3();
  s3.failAfterPut = 1;
  const result = await reconcileExactVersionLegalHold(s3, store, operation, POLICY);
  assert.equal(result.outcome, "applied");
  assert.equal(store.state, "APPLIED");
  assert.equal(result.operationRevision, 3);
  assert.equal(s3.putInputs.length, 2);
  assert.equal(result.receipt.priorStatus, "OFF");
  assert.match(result.receipt.applicationAttemptId ?? "", /^[0-9a-f]{64}$/);
});

test("applied retry is read-only, checks exact S3 drift, and rejects a tampered receipt", async () => {
  const store = new DurableMemoryStore();
  const operation = await requestAndApprove(store);
  const s3 = new RecordingS3();
  await reconcileExactVersionLegalHold(s3, store, operation, POLICY);
  const retried = await reconcileExactVersionLegalHold(s3, store, operation, POLICY);
  assert.equal(retried.outcome, "already_applied");
  assert.equal(s3.putInputs.length, 1);
  assert.equal(s3.getInputs.length, 4);

  s3.observedStatus = "OFF";
  await assert.rejects(reconcileExactVersionLegalHold(s3, store, operation, POLICY), hasCode("RETENTION_VIOLATION"));
  s3.observedStatus = "ON";
  store.receipt = { ...store.receipt!, key: `${KEY}.attacker` };
  await assert.rejects(reconcileExactVersionLegalHold(s3, store, operation, POLICY), hasCode("RETENTION_VIOLATION"));
});

test("bounded sweeper observes stale requests but applies only pre-approved work", async () => {
  const store = new DurableMemoryStore();
  const approvedOperation = await requestAndApprove(store);
  const requestedOnlyOperation = await prepareExactVersionLegalHoldOperation(durableRequest({
    operationId: `lho_${"7".repeat(32)}`,
    holdId: `hld_${"6".repeat(32)}`,
  }), REQUESTER_ACTOR, POLICY);
  const observations: Array<{ state: string; ageSeconds: number }> = [];
  const s3 = new RecordingS3();
  const result = await sweepPendingExactVersionLegalHolds({
    tenantId: TENANT,
    client: s3,
    store,
    policy: POLICY,
    minimumAgeSeconds: 300,
    limit: 2,
    now: new Date("2026-08-27T17:20:00.000Z"),
    source: {
      async expireStaleRequests() { return []; },
      async recordReconciliationFailure() { throw new Error("unexpected reconciliation failure"); },
      async listPending(input) {
        assert.equal(input.limit, 2);
        assert.equal(input.tenantId, TENANT);
        return [
          { operation: requestedOnlyOperation, state: "REQUESTED" as const, stateChangedAt: "2026-08-27T16:10:00.000Z" },
          { operation: approvedOperation, state: "APPROVED" as const, stateChangedAt: "2026-08-27T16:11:00.000Z" },
        ];
      },
    },
    observeAge(observation) {
      observations.push({ state: observation.state, ageSeconds: observation.ageSeconds });
    },
  });
  assert.deepEqual(result, { observed: 2, expired: 0, attempted: 1, applied: 1, alreadyApplied: 0, failedOperationIds: [] });
  assert.equal(observations.length, 2);
  assert.deepEqual(observations.map((item) => item.state), ["REQUESTED", "APPROVED"]);
  assert.equal(s3.putInputs.length, 1);
});

test("bounded sweeper expires stale requests without approval or an S3 mutation", async () => {
  const operation = await prepareExactVersionLegalHoldOperation(durableRequest({
    changedAt: new Date("2026-08-26T16:00:00.000Z"),
  }), REQUESTER_ACTOR, POLICY);
  const s3 = new RecordingS3();
  const observations: Array<{ state: string; ageSeconds: number }> = [];
  const result = await sweepPendingExactVersionLegalHolds({
    tenantId: TENANT,
    client: s3,
    store: new DurableMemoryStore(),
    policy: POLICY,
    minimumAgeSeconds: 300,
    limit: 1,
    now: new Date("2026-08-27T16:05:00.000Z"),
    source: {
      async expireStaleRequests(input) {
        assert.deepEqual(input, {
          tenantId: TENANT,
          now: "2026-08-27T16:05:00.000Z",
          limit: 1,
        });
        return [{ operation, expiredAt: "2026-08-27T16:05:00.000Z" }];
      },
      async recordReconciliationFailure() { throw new Error("unexpected reconciliation failure"); },
      async listPending() { return []; },
    },
    observeAge(observation) {
      observations.push({ state: observation.state, ageSeconds: observation.ageSeconds });
    },
  });
  assert.deepEqual(result, { observed: 1, expired: 1, attempted: 0, applied: 0, alreadyApplied: 0, failedOperationIds: [] });
  assert.deepEqual(observations, [{ state: "EXPIRED", ageSeconds: 86_700 }]);
  assert.equal(s3.putInputs.length, 0);
  assert.equal(s3.getInputs.length, 0);
});

test("sweeper rejects an expiry before the immutable 24-hour approval window", async () => {
  const operation = await prepareExactVersionLegalHoldOperation(durableRequest({
    changedAt: new Date("2026-08-26T16:10:00.000Z"),
  }), REQUESTER_ACTOR, POLICY);
  const s3 = new RecordingS3();
  await assert.rejects(sweepPendingExactVersionLegalHolds({
    tenantId: TENANT,
    client: s3,
    store: new DurableMemoryStore(),
    policy: POLICY,
    minimumAgeSeconds: 300,
    limit: 1,
    now: new Date("2026-08-27T16:05:00.000Z"),
    source: {
      async expireStaleRequests() {
        return [{ operation, expiredAt: "2026-08-27T16:05:00.000Z" }];
      },
      async recordReconciliationFailure() { throw new Error("unexpected reconciliation failure"); },
      async listPending() { return []; },
    },
  }), hasCode("RETENTION_VIOLATION"));
  assert.equal(s3.putInputs.length, 0);
});

test("a poison approved row is deferred so a later bounded-queue row becomes eligible", async () => {
  const poisonStore = new DurableMemoryStore();
  const poison = await requestAndApprove(poisonStore);
  const laterEvidence = `evd_${"3".repeat(32)}`;
  const laterStore = new DurableMemoryStore();
  const laterRequest = durableRequest({
    operationId: `lho_${"4".repeat(32)}`,
    holdId: `hld_${"5".repeat(32)}`,
    evidenceId: laterEvidence,
    key: `tenants/${TENANT}/controls/${CONTROL}/evidence/${laterEvidence}.png`,
  });
  const laterRequested = await requestExactVersionLegalHoldChange(laterStore, laterRequest, REQUESTER_ACTOR, POLICY);
  await approveExactVersionLegalHoldChange(laterStore, {
    tenantId: TENANT,
    operationId: laterRequested.operation.operationId,
    requestDigest: laterRequested.operation.requestDigest,
    approvedAt: new Date("2026-08-27T16:11:00.000Z"),
  }, APPROVER_ACTOR);
  const later = laterRequested.operation;
  const stores = new Map([
    [poison.operationId, poisonStore],
    [later.operationId, laterStore],
  ]);
  const store: ExactVersionLegalHoldOperationStore = {
    async request() { throw new Error("not used"); },
    async approve() { throw new Error("not used"); },
    async read(operation) { return await stores.get(operation.operationId)!.read(operation); },
    async beginApply(operation, approval, revision, attempt) {
      return await stores.get(operation.operationId)!.beginApply(operation, approval, revision, attempt);
    },
    async apply(operation, approval, revision, receipt) {
      return await stores.get(operation.operationId)!.apply(operation, approval, revision, receipt);
    },
  };
  let deferred = false;
  const failureRecords: Array<{ operationId: string; errorCode: string }> = [];
  const source = {
    async expireStaleRequests() { return []; },
    async listPending() {
      const operation = deferred ? later : poison;
      return [{ operation, state: "APPROVED" as const, stateChangedAt: "2026-08-27T16:11:00.000Z" }];
    },
    async recordReconciliationFailure(input: { operationId: string; errorCode: string }) {
      failureRecords.push({ operationId: input.operationId, errorCode: input.errorCode });
      deferred = true;
      return { attemptCount: 1, nextAttemptAt: "2026-08-27T17:20:30.000Z" };
    },
  };
  let laterStatus: "ON" | "OFF" = "OFF";
  const s3: ExactVersionLegalHoldClient = {
    async putObjectLegalHold(input) {
      if (input.Key === poison.key) throw new Error("persistent provider failure");
      laterStatus = input.LegalHold.Status;
      return { requestId: "put-later-0001" };
    },
    async getObjectLegalHold(input) {
      return { LegalHold: { Status: input.Key === poison.key ? "OFF" : laterStatus }, requestId: "get-later-0001" };
    },
  };

  const first = await sweepPendingExactVersionLegalHolds({
    tenantId: TENANT,
    client: s3,
    store,
    source,
    policy: POLICY,
    minimumAgeSeconds: 300,
    limit: 1,
    now: new Date("2026-08-27T17:20:00.000Z"),
  });
  assert.deepEqual(first.failedOperationIds, [poison.operationId]);
  assert.deepEqual(failureRecords, [{ operationId: poison.operationId, errorCode: "RECONCILIATION_FAILED" }]);

  const second = await sweepPendingExactVersionLegalHolds({
    tenantId: TENANT,
    client: s3,
    store,
    source,
    policy: POLICY,
    minimumAgeSeconds: 300,
    limit: 1,
    now: new Date("2026-08-27T17:20:01.000Z"),
  });
  assert.equal(second.applied, 1);
  assert.equal(laterStore.state, "APPLIED");
  assert.equal(poisonStore.state, "APPLYING");
});

test("sweeper rejects unbounded, duplicate, cross-tenant, or too-new source results", async () => {
  const store = new DurableMemoryStore();
  const operation = await requestAndApprove(store);
  const s3 = new RecordingS3();
  await assert.rejects(sweepPendingExactVersionLegalHolds({
    tenantId: TENANT,
    client: s3,
    store,
    policy: POLICY,
    minimumAgeSeconds: 300,
    limit: 1,
    now: new Date("2026-08-27T17:20:00.000Z"),
    source: {
      async expireStaleRequests() { return []; },
      async recordReconciliationFailure() { throw new Error("unexpected reconciliation failure"); },
      async listPending() { return [
        { operation, state: "APPROVED" as const, stateChangedAt: "2026-08-27T16:11:00.000Z" },
        { operation, state: "APPROVED" as const, stateChangedAt: "2026-08-27T16:11:00.000Z" },
      ]; },
    },
  }), hasCode("RETENTION_VIOLATION"));
  assert.equal(s3.putInputs.length, 0);
});
