import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  decideUploadReconciliation,
  exactCursor,
  parseActiveUploadLifecycle,
  parseMaintenanceEnvelope,
  parseTenantDirectoryEntry,
} from "../infra/aws/cdk/runtime/shared-jobs/reconciliation-contract.mjs";

const tenantId = `ten_${"a".repeat(32)}`;
const uploadId = `upl_${"b".repeat(32)}`;
const instant = (value: string) => ({ S: value });
const number = (value: number) => ({ N: String(value) });
const lifecycleTtl = (expiresAt: string) => number(
  Math.floor(Date.parse(expiresAt) / 1_000) + (22 * 24 * 60 * 60),
);
const maintenanceDue = (value: string) => ({ S: `${value}#${uploadId}` });
const leaseMaintenanceDue = (leaseExpiresAt: string) => maintenanceDue(
  new Date(Date.parse(leaseExpiresAt) + 15 * 60_000).toISOString(),
);
const digest = "c".repeat(64);
const validation = (overrides: Record<string, unknown> = {}) => ({
  M: {
    byteSize: number(1_024),
    completedAt: instant("2026-09-01T00:00:00.000Z"),
    contentType: { S: "image/png" },
    key: { S: `tenants/${tenantId}/controls/PCI-DSS-10.2.1/quarantine/${uploadId}.upload` },
    safe: { BOOL: true },
    scannerDigest: { S: digest },
    scannerPolicy: { S: "aws-guardduty-s3-malware-protection-v1" },
    sha256: { S: digest },
    tenantId: { S: tenantId },
    versionId: { S: "version-1" },
    ...overrides,
  },
});
const base = {
  PK: { S: `TENANT#${tenantId}` },
  SK: { S: `UPLOAD#${uploadId}` },
  GSI1PK: { S: `MAINTENANCE#UPLOAD#${tenantId}` },
  GSI1SK: maintenanceDue("2026-09-08T00:10:00.000Z"),
  expiresAt: instant("2026-09-01T00:10:00.000Z"),
  id: { S: uploadId },
  kind: { S: "UploadLifecycle" },
  schemaVersion: number(1),
  tenantId: { S: tenantId },
  ttlEpochSeconds: lifecycleTtl("2026-09-01T00:10:00.000Z"),
};

test("shared maintenance accepts only the exact scheduled envelope", () => {
  assert.deepEqual(parseMaintenanceEnvelope({ schemaVersion: 1, type: "scopeproof.maintenance.sweep" }), {
    schemaVersion: 1,
    type: "scopeproof.maintenance.sweep",
  });
  assert.throws(() => parseMaintenanceEnvelope({ schemaVersion: 1, type: "scopeproof.maintenance.sweep", tenantId }), /invalid/);
  assert.throws(() => parseMaintenanceEnvelope({ schemaVersion: 2, type: "scopeproof.maintenance.sweep" }), /invalid/);
});

test("issued upload remains recoverable for delayed scan events until the exact seven-day deadline", () => {
  const intent = parseActiveUploadLifecycle({ ...base, revision: number(0), status: { S: "issued" } });
  assert.deepEqual(decideUploadReconciliation(intent, new Date("2026-09-01T00:10:00.000Z"), 900), {
    action: "none",
    ageSeconds: 0,
  });
  assert.deepEqual(decideUploadReconciliation(intent, new Date("2026-09-08T00:09:59.999Z"), 900), {
    action: "none",
    ageSeconds: 0,
  });
  assert.deepEqual(decideUploadReconciliation(intent, new Date("2026-09-08T00:10:00.000Z"), 900), {
    action: "expire",
    ageSeconds: 0,
  });
  assert.throws(() => parseActiveUploadLifecycle({ ...base, revision: number(1), status: { S: "issued" } }), {
    name: "MalformedUploadLifecycleError",
  });
  assert.throws(() => parseActiveUploadLifecycle({
    ...base,
    revision: number(0),
    status: { S: "issued" },
    ttlEpochSeconds: number(Number(base.ttlEpochSeconds.N) - 1),
  }), { name: "MalformedUploadLifecycleError" });
});

test("stale promotion work is flagged without inventing a promotion result", () => {
  const quarantined = parseActiveUploadLifecycle({
    ...base,
    consumedAt: instant("2026-09-01T00:00:00.000Z"),
    GSI1SK: leaseMaintenanceDue("2026-09-01T00:05:00.000Z"),
    promotionLeaseId: { S: "d".repeat(64) },
    promotionLeaseExpiresAt: instant("2026-09-01T00:05:00.000Z"),
    revision: number(1),
    status: { S: "quarantined" },
  });
  assert.deepEqual(decideUploadReconciliation(quarantined, new Date("2026-09-01T00:20:00.000Z"), 900), {
    action: "flag_action_required",
    ageSeconds: 900,
    reason: "STALE_PROMOTION_LEASE",
    staleBase: "2026-09-01T00:05:00.000Z",
    staleField: "promotionLeaseExpiresAt",
  });

  assert.throws(() => parseActiveUploadLifecycle({
    ...base,
    consumedAt: instant("2026-09-01T00:00:00.000Z"),
    GSI1SK: leaseMaintenanceDue("2026-09-01T00:05:00.000Z"),
    promotionLeaseId: { S: "d".repeat(64) },
    promotionLeaseExpiresAt: instant("2026-09-01T00:05:00.000Z"),
    reconciliationDisposition: { S: "ACTION_REQUIRED" },
    revision: number(1),
    status: { S: "quarantined" },
  }), { name: "MalformedUploadLifecycleError" });
});

test("validated upload accepts the real exact markValidated authority shape", () => {
  const validated = parseActiveUploadLifecycle({
    ...base,
    consumedAt: instant("2026-09-01T00:00:00.000Z"),
    GSI1SK: leaseMaintenanceDue("2026-09-01T00:05:00.000Z"),
    promotionLeaseId: { S: "d".repeat(64) },
    promotionLeaseExpiresAt: instant("2026-09-01T00:05:00.000Z"),
    revision: number(2),
    status: { S: "validated" },
    validation: validation(),
  });
  assert.equal(validated.validationCompletedAt, "2026-09-01T00:00:00.000Z");
  assert.equal(decideUploadReconciliation(validated, new Date("2026-09-01T00:19:59.999Z"), 900).action, "none");
  assert.equal(decideUploadReconciliation(validated, new Date("2026-09-01T00:20:00.000Z"), 900).action, "flag_action_required");
  assert.throws(() => parseActiveUploadLifecycle({
    ...base,
    consumedAt: instant("2026-09-01T00:00:00.000Z"),
    GSI1SK: leaseMaintenanceDue("2026-09-01T00:05:00.000Z"),
    promotionLeaseId: { S: "d".repeat(64) },
    promotionLeaseExpiresAt: instant("2026-09-01T00:05:00.000Z"),
    revision: number(2),
    status: { S: "validated" },
    validation: validation({ completedAt: instant("2026-09-01 00:00:00") }),
  }), { name: "MalformedUploadLifecycleError" });
});

test("validated upload rejects incomplete or malformed DynamoDB validation authority", () => {
  const validated = {
    ...base,
    consumedAt: instant("2026-09-01T00:00:00.000Z"),
    GSI1SK: leaseMaintenanceDue("2026-09-01T00:05:00.000Z"),
    promotionLeaseId: { S: "d".repeat(64) },
    promotionLeaseExpiresAt: instant("2026-09-01T00:05:00.000Z"),
    revision: number(2),
    status: { S: "validated" },
  };
  assert.throws(() => parseActiveUploadLifecycle(validated), { name: "MalformedUploadLifecycleError" });
  assert.throws(() => parseActiveUploadLifecycle({
    ...validated,
    validation: { ...validation(), S: "forged" },
  }), { name: "MalformedUploadLifecycleError" });
  assert.throws(() => parseActiveUploadLifecycle({
    ...validated,
    validation: validation({ completedAt: { S: "2026-09-01T00:00:00.000Z", N: "0" } }),
  }), { name: "MalformedUploadLifecycleError" });
  assert.throws(() => parseActiveUploadLifecycle({
    ...validated,
    validation: validation({ safe: { BOOL: false } }),
  }), { name: "MalformedUploadLifecycleError" });
  assert.throws(() => parseActiveUploadLifecycle({
    ...validated,
    validation: validation({ unexpected: { S: "field" } }),
  }), { name: "MalformedUploadLifecycleError" });
});

test("tenant directory and its persisted pagination cursor are exact", () => {
  const directory = {
    PK: { S: "MAINTENANCE#TENANT_DIRECTORY" },
    SK: { S: `TENANT#${tenantId}` },
    kind: { S: "TenantMaintenanceRegistration" },
    schemaVersion: number(1),
    status: { S: "REGISTERED" },
    tenantId: { S: tenantId },
  };
  assert.deepEqual(parseTenantDirectoryEntry(directory), { active: true, tenantId });
  assert.deepEqual(exactCursor({
    cursorPk: directory.PK,
    cursorSk: directory.SK,
  }), {
    PK: directory.PK,
    SK: directory.SK,
  });
  assert.throws(() => exactCursor({ cursorPk: directory.PK }), /malformed/);
  assert.throws(() => parseTenantDirectoryEntry({ ...directory, tenantId: { S: `ten_${"f".repeat(32)}` } }), /malformed/);
});

test("worker source preserves bounded leased CAS semantics and never deletes evidence", async () => {
  const source = await readFile(new URL("../infra/aws/cdk/runtime/shared-jobs/index.mjs", import.meta.url), "utf8");
  assert.match(source, /records\.length < 1 \|\| records\.length > 1/);
  assert.match(source, /ConsistentRead: true/);
  assert.match(source, /lastCompletedMessageId/);
  assert.match(source, /leaseExpiresAt <= :now/);
  assert.match(source, /new QueryCommand/);
  assert.match(source, /TENANT_MAINTENANCE_DIRECTORY_KEY/);
  assert.match(source, /UploadLifecycleByTenantV2/);
  assert.match(source, /Limit: perTenantLimit/);
  assert.match(source, /const actionObservationBudget =/);
  assert.match(source, /const lifecycleBudget = maximumEvaluatedItems - actionObservationBudget/);
  assert.match(source, /counters\.examined \+= outstanding\.examined/);
  assert.doesNotMatch(source, /ScanCommand|FilterExpression/);
  assert.match(source, /#revision = :revision/);
  assert.match(source, /ttlEpochSeconds = :ttl/);
  assert.match(source, /attribute_not_exists\(reconciliationDisposition\)/);
  assert.match(source, /ACTION_REQUIRED/);
  assert.match(source, /error instanceof MalformedUploadLifecycleError/);
  assert.match(source, /if \(!\(error instanceof MalformedUploadLifecycleError\)\) throw error/);
  assert.match(source, /MAINTENANCE#ACTION_REQUIRED#/);
  assert.match(source, /OutstandingActionRequired/);
  assert.match(source, /error\.CancellationReasons/);
  assert.doesNotMatch(source, /DeleteItemCommand|BatchWriteItemCommand|s3:Delete|deleteObject/i);
});

test("malformed tenant work is isolated without losing durable operator visibility", async () => {
  const source = await readFile(new URL("../infra/aws/cdk/runtime/shared-jobs/index.mjs", import.meta.url), "utf8");
  const malformedLifecycle = source.slice(
    source.indexOf("async function quarantineMalformedLifecycle"),
    source.indexOf("async function observeOutstandingActions"),
  );
  assert.match(malformedLifecycle, /ConditionExpression: "GSI1SK = :indexSk"/);
  assert.match(malformedLifecycle, /REMOVE GSI1PK, GSI1SK/);
  assert.doesNotMatch(malformedLifecycle, /attribute_not_exists\(reconciliationDisposition\)/);
  assert.match(source, /sourcePkSha256/);
  assert.match(source, /sourceSkSha256/);
  assert.match(source, /sourceIndexSkSha256/);
  assert.match(source, /ProjectionExpression: "PK, SK, GSI1SK, detectedAt, id, #kind, reason, schemaVersion, sourceRevision, #status, tenantId"/);
  assert.match(source, /exactDynamoNumber\(item, "sourceRevision"\)/);

  const outstandingObserver = source.slice(
    source.indexOf("async function observeOutstandingActions"),
    source.indexOf("async function completeLease"),
  );
  assert.match(outstandingObserver, /count \+= 1/);
  assert.match(outstandingObserver, /failures \+= 1/);
  assert.match(outstandingObserver, /scopeproof_shared_maintenance_action_ledger_failed/);
  assert.doesNotMatch(outstandingObserver, /catch \(error\)[\s\S]*?throw error/);
});

test("promotion and terminal rejection resolve the exact durable action ledger", async () => {
  const promoter = await readFile(new URL("../infra/aws/cdk/runtime/promote-evidence/index.mjs", import.meta.url), "utf8");
  const rejected = await readFile(new URL("../infra/aws/cdk/runtime/reconcile-rejected-evidence/index.mjs", import.meta.url), "utf8");
  for (const source of [promoter, rejected]) {
    assert.match(source, /MAINTENANCE#ACTION_REQUIRED#/);
    assert.match(source, /function maintenanceActionResolution/);
    assert.match(source, /#status = :outstanding/);
    assert.match(source, /sourceRevision = :sourceRevision/);
    assert.match(source, /SET #status = :resolved, resolvedAt = :resolvedAt REMOVE GSI1SK/);
  }
  assert.match(promoter, /intent\.reconciliationDisposition = undefined/);
  const completion = promoter.slice(
    promoter.indexOf("async function completePromotion"),
    promoter.indexOf("function maintenanceActionResolution"),
  );
  assert.match(completion, /const hasMaintenanceAction = input\.intent\.reconciliationDisposition === "ACTION_REQUIRED"/);
  assert.match(completion, /reconciliationDisposition = :action AND reconciliationActionKey = :actionKey AND reconciliationDetectedAt = :actionDetected AND reconciliationReason = :actionReason/);
  assert.match(completion, /attribute_not_exists\(reconciliationDisposition\) AND attribute_not_exists\(reconciliationActionKey\) AND attribute_not_exists\(reconciliationDetectedAt\) AND attribute_not_exists\(reconciliationReason\)/);
  assert.match(completion, /quarantineReceipt\.versionId = :sourceVersion",\s+reconciliationCondition/);
  assert.match(rejected, /hasMaintenanceAction \? \[maintenanceActionResolution\(intent, rejectedAt\)\] : \[\]/);
});
