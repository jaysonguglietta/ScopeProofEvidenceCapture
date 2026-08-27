import assert from "node:assert/strict";
import test from "node:test";

import {
  asMembershipId,
  asResourceId,
  asTenantId,
  asUserId,
  assertAuditContinuation,
  assertJobEnvelope,
  cancelTenantJob,
  completeTenantJob,
  confirmExactVersionDeleted,
  createEvidenceRetention,
  createTenantAuditEvent,
  evaluateDeletionEligibility,
  extendRetention,
  failTenantJob,
  jobEnvelope,
  leaseTenantJob,
  placeLegalHold,
  queueTenantJob,
  redriveDeadLetter,
  releaseLegalHold,
  requestExactVersionDeletion,
  TenantSecurityError,
  type TenantActor,
} from "../lib/aws-runtime/index.ts";

const TENANT_A = asTenantId(`ten_${"a".repeat(32)}`);
const TENANT_B = asTenantId(`ten_${"b".repeat(32)}`);
const USER_A = asUserId(`usr_${"1".repeat(32)}`);
const USER_B = asUserId(`usr_${"2".repeat(32)}`);
const MEMBER_A = asMembershipId(`mem_${"3".repeat(32)}`);
const RESOURCE = asResourceId(`evd_${"4".repeat(32)}`);
const OBJECT_KEY = `tenants/${TENANT_A}/evidence/${RESOURCE}.png`;

function hasCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof TenantSecurityError);
    assert.equal(error.code, code);
    return true;
  };
}

function actor(tenantId = TENANT_A, role: TenantActor["role"] = "admin"): TenantActor {
  return {
    tenantId,
    tenantHostname: `${tenantId === TENANT_A ? "acme" : "bravo"}.jsontechology.com` as TenantActor["tenantHostname"],
    userId: USER_A,
    membershipId: MEMBER_A,
    subject: "cognito:test-user",
    role,
  };
}

test("audit events are tenant-chained, deterministic, and secret-safe", async () => {
  const first = await createTenantAuditEvent({
    tenantId: TENANT_A,
    sequence: 1,
    id: `evt_${"5".repeat(32)}`,
    occurredAt: "2026-08-27T16:00:00.000Z",
    actor: { type: "user", userId: USER_A, membershipId: MEMBER_A },
    action: "evidence.created",
    resourceType: "evidence",
    resourceId: RESOURCE,
    requestId: "request-0001",
    outcome: "succeeded",
    details: { byteSize: 1_024, contentType: "image/png" },
    previousHash: "GENESIS",
  });
  const second = await createTenantAuditEvent({
    tenantId: TENANT_A,
    sequence: 2,
    id: `evt_${"6".repeat(32)}`,
    occurredAt: "2026-08-27T16:01:00.000Z",
    actor: { type: "system", service: "evidence-promoter" },
    action: "evidence.promoted",
    resourceType: "evidence",
    resourceId: RESOURCE,
    requestId: "request-0002",
    outcome: "succeeded",
    details: { objectVersion: "version-0002" },
    previousHash: first.eventHash,
  });
  assertAuditContinuation(first, second);
  assert.equal(first.eventHash.length, 64);

  const crossTenant = await createTenantAuditEvent({ ...second, tenantId: TENANT_B, id: `evt_${"7".repeat(32)}` });
  assert.throws(() => assertAuditContinuation(first, crossTenant), hasCode("INVALID_AUDIT_EVENT"));
  await assert.rejects(createTenantAuditEvent({ ...first, id: `evt_${"8".repeat(32)}`, details: { apiKey: "must-not-be-logged" } }), hasCode("INVALID_AUDIT_EVENT"));
  await assert.rejects(createTenantAuditEvent({ ...first, id: `evt_${"9".repeat(32)}`, details: JSON.parse('{"__proto__":{"polluted":true}}') }), hasCode("INVALID_AUDIT_EVENT"));
});

test("jobs enforce exact tenant envelopes, leases, retries, DLQ, and privileged redrive", () => {
  const queued = queueTenantJob({
    id: `job_${"a".repeat(32)}`,
    tenantId: TENANT_A,
    kind: "evidence.validate",
    idempotencyKey: "evidence-scan-0001",
    resourceId: RESOURCE,
    requestedBy: USER_A,
    now: new Date("2026-08-27T16:00:00.000Z"),
    maxAttempts: 2,
  });
  assert.throws(() => completeTenantJob(queued, { expectedRevision: 0, leaseId: "lease-01", workerId: "worker-01", now: new Date("2026-08-27T16:00:01.000Z") }), hasCode("ILLEGAL_STATE_TRANSITION"));
  assert.throws(() => queueTenantJob({
    id: `job_${"f".repeat(32)}`, tenantId: TENANT_A, kind: "attacker.execute" as "evidence.validate",
    idempotencyKey: "invalid-job-kind-0001", resourceId: RESOURCE, requestedBy: USER_A,
    now: new Date("2026-08-27T16:00:00.000Z"),
  }), hasCode("INVALID_JOB"));
  assert.throws(() => assertJobEnvelope(queued, { ...jobEnvelope(queued), tenantId: TENANT_B }), hasCode("RESOURCE_NOT_FOUND"));
  assert.throws(() => assertJobEnvelope(queued, { ...jobEnvelope(queued), idempotencyKey: "attacker-replay" }), hasCode("RESOURCE_NOT_FOUND"));

  const leased = leaseTenantJob(queued, { expectedRevision: 0, workerId: "worker-01", leaseId: "lease-01", now: new Date("2026-08-27T16:00:01.000Z"), leaseDurationMs: 60_000 });
  assert.equal(leased.status, "leased");
  assert.throws(() => completeTenantJob(leased, { expectedRevision: 1, leaseId: "lease-01", workerId: "worker-01", now: new Date("2026-08-27T16:00:00.000Z") }), hasCode("ILLEGAL_STATE_TRANSITION"));
  assert.throws(() => completeTenantJob(leased, { expectedRevision: 1, leaseId: "lease-01", workerId: "worker-attacker", now: new Date("2026-08-27T16:00:02.000Z") }), hasCode("ILLEGAL_STATE_TRANSITION"));

  const retry = failTenantJob(leased, { expectedRevision: 1, leaseId: "lease-01", workerId: "worker-01", now: new Date("2026-08-27T16:00:10.000Z"), retryable: true, errorCode: "scanner_failure" });
  assert.equal(retry.status, "retry_scheduled");
  assert.throws(() => leaseTenantJob(retry, { expectedRevision: 2, workerId: "worker-02", leaseId: "lease-02", now: new Date("2026-08-27T16:01:00.000Z"), leaseDurationMs: 60_000 }), hasCode("ILLEGAL_STATE_TRANSITION"));

  const leasedAgain = leaseTenantJob(retry, { expectedRevision: 2, workerId: "worker-02", leaseId: "lease-02", now: new Date("2026-08-27T16:02:11.000Z"), leaseDurationMs: 60_000 });
  const deadLettered = failTenantJob(leasedAgain, { expectedRevision: 3, leaseId: "lease-02", workerId: "worker-02", now: new Date("2026-08-27T16:02:12.000Z"), retryable: true, errorCode: "scanner_failure" });
  assert.equal(deadLettered.status, "dead_lettered");
  assert.throws(() => completeTenantJob(deadLettered, { expectedRevision: 4, leaseId: "lease-02", workerId: "worker-02", now: new Date("2026-08-27T16:02:13.000Z") }), hasCode("ILLEGAL_STATE_TRANSITION"));
  assert.throws(() => redriveDeadLetter(deadLettered, { expectedRevision: 4, actor: actor(TENANT_A, "auditor"), now: new Date("2026-08-27T16:03:00.000Z") }), hasCode("ROLE_FORBIDDEN"));
  assert.throws(() => redriveDeadLetter(deadLettered, { expectedRevision: 4, actor: actor(TENANT_B), now: new Date("2026-08-27T16:03:00.000Z") }), hasCode("RESOURCE_NOT_FOUND"));
  const redriven = redriveDeadLetter(deadLettered, { expectedRevision: 4, actor: actor(), now: new Date("2026-08-27T16:03:00.000Z") });
  assert.equal(redriven.status, "queued");
  assert.equal(redriven.attempt, 0);
  const cancelled = cancelTenantJob(redriven, { expectedRevision: 5, actor: actor(), now: new Date("2026-08-27T16:03:01.000Z") });
  assert.equal(cancelled.status, "cancelled");
  assert.throws(() => cancelTenantJob(cancelled, { expectedRevision: 6, actor: actor(), now: new Date("2026-08-27T16:03:02.000Z") }), hasCode("ILLEGAL_STATE_TRANSITION"));
});

test("retention and legal hold prevent early, ambiguous, or single-party deletion", () => {
  const original = createEvidenceRetention({
    tenantId: TENANT_A,
    resourceId: RESOURCE,
    objectKey: OBJECT_KEY,
    versionId: "version-0002",
    lockMode: "COMPLIANCE",
    retainUntil: new Date("2027-08-27T16:00:00.000Z"),
    now: new Date("2026-08-27T16:00:00.000Z"),
  });
  assert.throws(() => evaluateDeletionEligibility(original, { expectedRevision: 0, now: new Date("2027-08-27T15:59:59.000Z") }), hasCode("RETENTION_VIOLATION"));
  assert.throws(() => extendRetention(original, { expectedRevision: 0, retainUntil: new Date("2027-01-01T00:00:00.000Z") }), hasCode("RETENTION_VIOLATION"));

  const held = placeLegalHold(original, {
    expectedRevision: 0,
    holdId: "legal-hold-001",
    actor: USER_A,
    reason: "External auditor preservation request",
    now: new Date("2026-09-01T00:00:00.000Z"),
  });
  assert.throws(() => evaluateDeletionEligibility(held, { expectedRevision: 1, now: new Date("2028-01-01T00:00:00.000Z") }), hasCode("LEGAL_HOLD_ACTIVE"));
  assert.throws(() => releaseLegalHold(held, { expectedRevision: 1, holdId: "wrong-hold", actor: USER_B, reason: "Authorized release after case closure" }), hasCode("LEGAL_HOLD_ACTIVE"));
  assert.throws(() => releaseLegalHold(held, { expectedRevision: 1, holdId: "legal-hold-001", actor: USER_A, reason: "Authorized release after case closure" }), hasCode("LEGAL_HOLD_ACTIVE"));

  const released = releaseLegalHold(held, { expectedRevision: 1, holdId: "legal-hold-001", actor: USER_B, reason: "Authorized release after case closure" });
  const eligible = evaluateDeletionEligibility(released, { expectedRevision: 2, now: new Date("2028-01-01T00:00:00.000Z") });
  assert.equal(eligible.status, "deletion_eligible");
  assert.throws(() => requestExactVersionDeletion(eligible, { expectedRevision: 3, now: new Date("2028-01-01T00:00:01.000Z"), objectKey: OBJECT_KEY, versionId: "version-attacker", requestId: "delete-001" }), hasCode("RESOURCE_NOT_FOUND"));

  const pending = requestExactVersionDeletion(eligible, { expectedRevision: 3, now: new Date("2028-01-01T00:00:01.000Z"), objectKey: OBJECT_KEY, versionId: "version-0002", requestId: "delete-001" });
  assert.equal(pending.status, "deletion_pending");
  assert.throws(() => confirmExactVersionDeleted(pending, { expectedRevision: 4, now: new Date("2028-01-01T00:00:02.000Z"), objectKey: OBJECT_KEY, versionId: "version-0002", requestId: "delete-001", exactVersionAbsent: false }), hasCode("RETENTION_VIOLATION"));
  const deleted = confirmExactVersionDeleted(pending, { expectedRevision: 4, now: new Date("2028-01-01T00:00:02.000Z"), objectKey: OBJECT_KEY, versionId: "version-0002", requestId: "delete-001", exactVersionAbsent: true });
  assert.equal(deleted.status, "deleted");
  assert.throws(() => placeLegalHold(deleted, { expectedRevision: 5, holdId: "late-hold", actor: USER_A, reason: "This hold arrives after verified deletion", now: new Date("2028-01-01T00:00:03.000Z") }), hasCode("ILLEGAL_STATE_TRANSITION"));
});

test("retention records bind the tenant, resource, key, and exact object version", () => {
  assert.throws(() => createEvidenceRetention({
    tenantId: TENANT_A,
    resourceId: RESOURCE,
    objectKey: `tenants/${TENANT_B}/evidence/${RESOURCE}.png`,
    versionId: "version-0002",
    lockMode: "COMPLIANCE",
    retainUntil: new Date("2027-08-27T16:00:00.000Z"),
    now: new Date("2026-08-27T16:00:00.000Z"),
  }), hasCode("RETENTION_VIOLATION"));
  assert.throws(() => createEvidenceRetention({
    tenantId: TENANT_A,
    resourceId: RESOURCE,
    objectKey: `tenants/${TENANT_A}/evidence/evd_${"f".repeat(32)}.png`,
    versionId: "version-0002",
    lockMode: "COMPLIANCE",
    retainUntil: new Date("2027-08-27T16:00:00.000Z"),
    now: new Date("2026-08-27T16:00:00.000Z"),
  }), hasCode("RETENTION_VIOLATION"));
});
