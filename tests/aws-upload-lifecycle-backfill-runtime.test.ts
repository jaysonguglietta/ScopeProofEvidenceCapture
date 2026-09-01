import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

process.env.AWS_REGION = "us-east-1";
process.env.CONTROL_TABLE_NAME = "scopeproof-control-plane";
process.env.MAXIMUM_BACKFILL_ITEMS = "25";

const { parseUploadLifecycleBackfillEvent } = await import(
  "../infra/aws/cdk/runtime/shared-jobs/upload-lifecycle-backfill.mjs"
);

const tenantId = `ten_${"a".repeat(32)}`;
const uploadId = `upl_${"b".repeat(32)}`;
const base = {
  limit: 25,
  mode: "APPLY_EXACT_CAS",
  schemaVersion: 1,
  tenantId,
  type: "scopeproof.upload-lifecycle.backfill",
};

test("manual lifecycle backfill event is exact, bounded, and tenant-cursor scoped", () => {
  assert.deepEqual(parseUploadLifecycleBackfillEvent(base, 25), {
    cursor: undefined,
    limit: 25,
    tenantId,
  });
  assert.deepEqual(parseUploadLifecycleBackfillEvent({
    ...base,
    cursor: {
      partitionKey: `TENANT#${tenantId}`,
      sortKey: `UPLOAD#${uploadId}`,
    },
  }, 25), {
    cursor: {
      partitionKey: `TENANT#${tenantId}`,
      sortKey: `UPLOAD#${uploadId}`,
    },
    limit: 25,
    tenantId,
  });
  assert.throws(() => parseUploadLifecycleBackfillEvent({ ...base, limit: 26 }, 25), /invalid/);
  assert.throws(() => parseUploadLifecycleBackfillEvent({ ...base, mode: "DRY_RUN" }, 25), /invalid/);
  assert.throws(() => parseUploadLifecycleBackfillEvent({ ...base, unexpected: true }, 25), /invalid/);
  assert.throws(() => parseUploadLifecycleBackfillEvent({
    ...base,
    cursor: {
      partitionKey: `TENANT#ten_${"9".repeat(32)}`,
      sortKey: `UPLOAD#${uploadId}`,
    },
  }, 25), /cursor is invalid/);
});

test("manual runtime source uses one bounded strong tenant query and never scans or logs raw identity", async () => {
  const source = await readFile(
    new URL("../infra/aws/cdk/runtime/shared-jobs/upload-lifecycle-backfill.mjs", import.meta.url),
    "utf8",
  );
  assert.match(source, /new QueryCommand/);
  assert.match(source, /ConsistentRead: true/);
  assert.match(source, /KeyConditionExpression: "#pk = :tenant AND begins_with\(#sk, :upload\)"/);
  assert.match(source, /Limit: request\.limit/);
  assert.match(source, /ProjectionExpression: "#pk, #sk, GSI1PK, GSI1SK,/);
  assert.match(source, /ProjectionExpression: "PK, SK, evidenceProjectionDigest, idempotencyDigest, intentId, #kind,/);
  assert.match(source, /new GetItemCommand/);
  assert.match(source, /planUploadLifecycleBackfill/);
  assert.match(source, /new TransactWriteItemsCommand\(plan\.transaction\)/);
  assert.doesNotMatch(source, /ScanCommand|while\s*\(|do\s*\{/);
  const successLog = source.slice(
    source.indexOf("console.info"),
    source.indexOf("return result"),
  );
  assert.match(successLog, /tenantIdSha256/);
  assert.doesNotMatch(successLog, /tenantId:/);
});
