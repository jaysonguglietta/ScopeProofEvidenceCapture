import assert from "node:assert/strict";
import test from "node:test";
import {
  MalformedUploadLifecycleBackfillAuthorityError,
  planUploadLifecycleBackfill,
} from "../infra/aws/cdk/runtime/shared-jobs/upload-lifecycle-backfill-contract.mjs";

const tableName = "scopeproof-control-plane";
const tenantId = `ten_${"a".repeat(32)}`;
const uploadId = `upl_${"b".repeat(32)}`;
const digest = (character: string) => character.repeat(64);
const expiresAt = "2026-09-01T00:10:00.000Z";
const legacyTtl = Math.floor(Date.parse(expiresAt) / 1_000) + 7 * 24 * 60 * 60;
const currentTtl = Math.floor(Date.parse(expiresAt) / 1_000) + 22 * 24 * 60 * 60;
const instant = (value: string) => ({ S: value });
const number = (value: number) => ({ N: String(value) });
const idempotencyDigest = digest("c");
const requestFingerprint = digest("d");
const evidenceProjectionDigest = digest("e");
const leaseExpiresAt = "2026-09-01T00:05:00.000Z";
const issuedDue = "2026-09-08T00:10:00.000Z";
const leaseDue = "2026-09-01T00:20:00.000Z";

function validation() {
  return {
    M: {
      byteSize: number(1_024),
      completedAt: instant("2026-09-01T00:04:00.000Z"),
      contentType: { S: "image/png" },
      key: { S: `tenants/${tenantId}/controls/PCI-DSS-10.2.1/quarantine/${uploadId}.upload` },
      safe: { BOOL: true },
      scannerDigest: { S: digest("f") },
      scannerPolicy: { S: "aws-guardduty-s3-malware-protection-v1" },
      sha256: { S: digest("1") },
      tenantId: { S: tenantId },
      versionId: { S: "version-1" },
    },
  };
}

function lifecycle(status: "issued" | "quarantined" | "validated", options: { current?: boolean; indexedLegacy?: boolean } = {}) {
  const revision = { issued: 0, quarantined: 1, validated: 2 }[status];
  const item: Record<string, unknown> = {
    PK: { S: `TENANT#${tenantId}` },
    SK: { S: `UPLOAD#${uploadId}` },
    evidenceProjectionDigest: { S: evidenceProjectionDigest },
    expiresAt: instant(expiresAt),
    id: { S: uploadId },
    idempotencyDigest: { S: idempotencyDigest },
    kind: { S: "UploadLifecycle" },
    requestFingerprint: { S: requestFingerprint },
    revision: number(revision),
    schemaVersion: number(1),
    status: { S: status },
    tenantId: { S: tenantId },
    ttlEpochSeconds: number(options.current ? currentTtl : legacyTtl),
  };
  if (status !== "issued") {
    item.consumedAt = instant("2026-09-01T00:00:00.000Z");
    item.promotionLeaseId = { S: digest("2") };
    item.promotionLeaseExpiresAt = instant(leaseExpiresAt);
  }
  if (status === "validated") item.validation = validation();
  if (options.current || options.indexedLegacy) {
    item.GSI1PK = { S: `MAINTENANCE#UPLOAD#${tenantId}` };
    item.GSI1SK = { S: `${status === "issued" ? issuedDue : leaseDue}#${uploadId}` };
  }
  return item;
}

function requestReservation(current = false) {
  return {
    PK: { S: `TENANT#${tenantId}` },
    SK: { S: `UPLOAD_REQUEST#${idempotencyDigest}` },
    evidenceProjectionDigest: { S: evidenceProjectionDigest },
    idempotencyDigest: { S: idempotencyDigest },
    intentId: { S: uploadId },
    kind: { S: "UploadIdempotencyReservation" },
    requestFingerprint: { S: requestFingerprint },
    tenantId: { S: tenantId },
    ttlEpochSeconds: number(current ? currentTtl : legacyTtl),
  };
}

test("legacy issued lifecycle produces one exact atomic lifecycle/request upgrade", () => {
  const result = planUploadLifecycleBackfill({
    lifecycle: lifecycle("issued"),
    requestReservation: requestReservation(),
    tableName,
  });
  assert.equal(result.outcome, "upgrade");
  assert.equal(result.status, "issued");
  assert.match(result.transaction.ClientRequestToken, /^[a-f0-9]{36}$/);
  assert.equal(result.transaction.TransactItems.length, 2);
  const lifecycleUpdate = result.transaction.TransactItems[0].Update;
  const requestUpdate = result.transaction.TransactItems[1].Update;
  assert.equal(lifecycleUpdate.UpdateExpression, "SET GSI1PK = :indexPk, GSI1SK = :indexSk, ttlEpochSeconds = :newTtl");
  assert.equal(lifecycleUpdate.ExpressionAttributeValues[":newTtl"].N, String(currentTtl));
  assert.equal(lifecycleUpdate.ExpressionAttributeValues[":indexSk"].S, `${issuedDue}#${uploadId}`);
  assert.match(lifecycleUpdate.ConditionExpression, /attribute_not_exists\(GSI1PK\) AND attribute_not_exists\(GSI1SK\)/);
  assert.equal(requestUpdate.UpdateExpression, "SET ttlEpochSeconds = :newTtl");
  assert.equal(requestUpdate.ExpressionAttributeValues[":newTtl"].N, String(currentTtl));
});

test("legacy quarantined and validated lifecycle due authority is lease-bound", () => {
  for (const status of ["quarantined", "validated"] as const) {
    const result = planUploadLifecycleBackfill({
      lifecycle: lifecycle(status),
      requestReservation: requestReservation(),
      tableName,
    });
    assert.equal(result.outcome, "upgrade");
    const update = result.transaction.TransactItems[0].Update;
    assert.equal(update.ExpressionAttributeValues[":indexSk"].S, `${leaseDue}#${uploadId}`);
    assert.equal(update.ExpressionAttributeValues[":leaseExpiresAt"].S, leaseExpiresAt);
    assert.match(update.ConditionExpression, /promotionLeaseId = :leaseId AND promotionLeaseExpiresAt = :leaseExpiresAt/);
    if (status === "validated") {
      assert.match(update.ConditionExpression, /validation\.completedAt = :validationCompletedAt/);
    } else {
      assert.match(update.ConditionExpression, /attribute_not_exists\(validation\)/);
    }
  }
});

test("an exact indexed legacy lifecycle can have only its paired TTL authority upgraded", () => {
  const result = planUploadLifecycleBackfill({
    lifecycle: lifecycle("quarantined", { indexedLegacy: true }),
    requestReservation: requestReservation(),
    tableName,
  });
  assert.equal(result.outcome, "upgrade");
  assert.match(result.transaction.TransactItems[0].Update.ConditionExpression, /GSI1PK = :indexPk AND GSI1SK = :indexSk/);
});

test("already-current lifecycle and request reservation are an idempotent no-op", () => {
  const input = {
    lifecycle: lifecycle("validated", { current: true }),
    requestReservation: requestReservation(true),
    tableName,
  };
  assert.deepEqual(planUploadLifecycleBackfill(input), {
    outcome: "current",
    status: "validated",
    tenantId,
    uploadId,
  });
  assert.deepEqual(planUploadLifecycleBackfill(input), planUploadLifecycleBackfill(input));
});

test("strict terminal lifecycle is classified without requiring or mutating its expired pair", () => {
  const promoted = {
    ...lifecycle("validated", { current: true }),
    status: { S: "promoted" },
    revision: number(3),
    GSI1PK: undefined,
    GSI1SK: undefined,
  };
  assert.deepEqual(planUploadLifecycleBackfill({ lifecycle: promoted, tableName }), {
    outcome: "terminal",
    status: "promoted",
    tenantId,
    uploadId,
  });
  const expired = {
    ...lifecycle("issued"),
    status: { S: "expired" },
    revision: number(1),
  };
  assert.equal(planUploadLifecycleBackfill({ lifecycle: expired, tableName }).outcome, "terminal");
});

test("malformed, mismatched, and half-upgraded authority fails closed", () => {
  const malformed = (lifecycleItem: Record<string, unknown>, requestItem = requestReservation()) => assert.throws(
    () => planUploadLifecycleBackfill({ lifecycle: lifecycleItem, requestReservation: requestItem, tableName }),
    MalformedUploadLifecycleBackfillAuthorityError,
  );
  malformed({ ...lifecycle("issued"), tenantId: { S: `ten_${"9".repeat(32)}` } });
  malformed({ ...lifecycle("issued"), ttlEpochSeconds: number(legacyTtl + 1) });
  malformed({ ...lifecycle("issued"), GSI1PK: { S: `MAINTENANCE#UPLOAD#${tenantId}` } });
  malformed({ ...lifecycle("validated"), validation: { ...validation(), S: "forged" } });
  malformed(lifecycle("issued"), { ...requestReservation(), intentId: { S: `upl_${"9".repeat(32)}` } });
  malformed(lifecycle("issued", { current: true }), requestReservation());
  malformed(lifecycle("issued"), requestReservation(true));
});

test("transaction CAS binds every race-sensitive active and paired-request fact", () => {
  const first = planUploadLifecycleBackfill({
    lifecycle: lifecycle("validated"),
    requestReservation: requestReservation(),
    tableName,
  });
  const second = planUploadLifecycleBackfill({
    lifecycle: lifecycle("validated"),
    requestReservation: requestReservation(),
    tableName,
  });
  assert.equal(first.outcome, "upgrade");
  assert.equal(second.outcome, "upgrade");
  if (first.outcome !== "upgrade" || second.outcome !== "upgrade") {
    throw new Error("validated legacy lifecycle should require an exact backfill transaction");
  }
  assert.equal(first.transaction.ClientRequestToken, second.transaction.ClientRequestToken);
  const lifecycleCondition = first.transaction.TransactItems[0].Update.ConditionExpression;
  for (const predicate of [
    "#status = :status",
    "#revision = :revision",
    "expiresAt = :expiresAt",
    "ttlEpochSeconds = :legacyTtl",
    "idempotencyDigest = :idempotencyDigest",
    "requestFingerprint = :fingerprint",
    "evidenceProjectionDigest = :evidenceProjectionDigest",
    "promotionLeaseId = :leaseId",
    "promotionLeaseExpiresAt = :leaseExpiresAt",
    "validation.completedAt = :validationCompletedAt",
    "attribute_not_exists(reconciliationDisposition)",
  ]) assert.match(lifecycleCondition, new RegExp(predicate.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  const requestCondition = first.transaction.TransactItems[1].Update.ConditionExpression;
  assert.match(requestCondition, /intentId = :id/);
  assert.match(requestCondition, /ttlEpochSeconds = :legacyTtl/);

  const transitioned = {
    ...lifecycle("validated"),
    status: { S: "promoted" },
    revision: number(3),
  };
  assert.equal(planUploadLifecycleBackfill({ lifecycle: transitioned, tableName }).outcome, "terminal");
});

test("manual backfill invocation is exact, tenant-bound, and page-bounded", async () => {
  const previous = {
    region: process.env.AWS_REGION,
    table: process.env.CONTROL_TABLE_NAME,
    maximum: process.env.MAXIMUM_BACKFILL_ITEMS,
  };
  process.env.AWS_REGION = "us-east-1";
  process.env.CONTROL_TABLE_NAME = tableName;
  process.env.MAXIMUM_BACKFILL_ITEMS = "100";
  try {
    const { parseUploadLifecycleBackfillEvent } = await import(
      "../infra/aws/cdk/runtime/shared-jobs/upload-lifecycle-backfill.mjs"
    );
    const exact = {
      limit: 100,
      mode: "APPLY_EXACT_CAS",
      schemaVersion: 1,
      tenantId,
      type: "scopeproof.upload-lifecycle.backfill",
    };
    assert.deepEqual(parseUploadLifecycleBackfillEvent(exact), {
      cursor: undefined,
      limit: 100,
      tenantId,
    });
    assert.deepEqual(parseUploadLifecycleBackfillEvent({
      ...exact,
      cursor: {
        partitionKey: `TENANT#${tenantId}`,
        sortKey: `UPLOAD#${uploadId}`,
      },
    }).cursor, {
      partitionKey: `TENANT#${tenantId}`,
      sortKey: `UPLOAD#${uploadId}`,
    });
    assert.throws(() => parseUploadLifecycleBackfillEvent({ ...exact, limit: 101 }), /event is invalid/);
    assert.throws(() => parseUploadLifecycleBackfillEvent({ ...exact, unexpected: true }), /event is invalid/);
    assert.throws(() => parseUploadLifecycleBackfillEvent({
      ...exact,
      cursor: {
        partitionKey: `TENANT#ten_${"9".repeat(32)}`,
        sortKey: `UPLOAD#${uploadId}`,
      },
    }), /cursor is invalid/);
  } finally {
    if (previous.region === undefined) delete process.env.AWS_REGION;
    else process.env.AWS_REGION = previous.region;
    if (previous.table === undefined) delete process.env.CONTROL_TABLE_NAME;
    else process.env.CONTROL_TABLE_NAME = previous.table;
    if (previous.maximum === undefined) delete process.env.MAXIMUM_BACKFILL_ITEMS;
    else process.env.MAXIMUM_BACKFILL_ITEMS = previous.maximum;
  }
});
