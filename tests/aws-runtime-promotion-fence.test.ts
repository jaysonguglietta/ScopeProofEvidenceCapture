import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  assertActivePromotionLease,
  buildPromotionCopyAttemptItem,
  createOrAdoptImmutableDestination,
  derivePromotionLease,
  promotionCopyMetadata,
} from "../infra/aws/cdk/runtime/promote-evidence/promotion-fence.mjs";

const tenantId = `ten_${"a".repeat(32)}`;
const intentId = `upl_${"b".repeat(32)}`;
const receiptHash = "c".repeat(64);
const sourceVersionId = "source-version-1";

test("a delayed worker cannot pass a newer monotonic promotion fence", () => {
  const first = derivePromotionLease({
    tenantId,
    intentId,
    leaseId: "1".repeat(64),
    sourceVersionId,
    now: "2026-08-27T16:00:00.000Z",
  });
  const second = derivePromotionLease({
    tenantId,
    intentId,
    leaseId: "2".repeat(64),
    sourceVersionId,
    currentFence: first.fence,
    now: first.leaseExpiresAt,
  });
  assert.equal(first.fence, 1);
  assert.equal(second.fence, 2);
  assert.notEqual(first.attemptId, second.attemptId);

  const authoritative = {
    leaseId: "2".repeat(64),
    attemptId: second.attemptId,
    fence: second.fence,
    leaseExpiresAt: second.leaseExpiresAt,
  };
  assert.throws(
    () => assertActivePromotionLease(authoritative, {
      leaseId: "1".repeat(64),
      attemptId: first.attemptId,
      fence: first.fence,
    }, "2026-08-27T16:05:00.001Z"),
    /active promotion fence/,
  );
  assert.equal(assertActivePromotionLease(authoritative, {
    leaseId: "2".repeat(64),
    attemptId: second.attemptId,
    fence: second.fence,
  }, "2026-08-27T16:05:00.001Z").fence, 2);
});

test("a copy permission is durable before the irreversible Object-Locked write", () => {
  const lease = derivePromotionLease({
    tenantId,
    intentId,
    leaseId: "3".repeat(64),
    sourceVersionId,
    now: "2026-08-27T16:00:00.000Z",
  });
  const attempt = buildPromotionCopyAttemptItem({
    tenantId,
    intentId,
    receiptHash,
    attemptId: lease.attemptId,
    leaseId: "3".repeat(64),
    sourceVersionId,
    expectedSha256: "d".repeat(64),
    sourceBucket: "scopeproof-quarantine",
    sourceKey: `tenants/${tenantId}/controls/PCI-DSS-10.2.1/quarantine/${intentId}.upload`,
    destinationBucket: "scopeproof-evidence",
    destinationKey: `tenants/${tenantId}/controls/PCI-DSS-10.2.1/evidence/evd_${"e".repeat(32)}.png`,
    fence: lease.fence,
    permittedAt: lease.now,
    leaseExpiresAt: lease.leaseExpiresAt,
  });
  assert.equal(attempt.status.S, "COPY_PERMITTED");
  assert.equal(attempt.fence.N, "1");
  assert.match(attempt.SK.S ?? "", /^PROMOTION_ATTEMPT#[a-f0-9]{64}#0{15}1$/);
  assert.deepEqual(promotionCopyMetadata(lease), {
    "promotion-attempt-id": lease.attemptId,
    "promotion-fence": "1",
  });
});

test("A permitted then paused, B takeover, and A resume can create only one destination version", async () => {
  const a = derivePromotionLease({
    tenantId, intentId, leaseId: "4".repeat(64), sourceVersionId,
    now: "2026-08-27T16:00:00.000Z",
  });
  const aAttempt = buildPromotionCopyAttemptItem({
    tenantId, intentId, receiptHash, attemptId: a.attemptId, leaseId: "4".repeat(64),
    sourceVersionId, expectedSha256: "d".repeat(64), sourceBucket: "scopeproof-quarantine",
    sourceKey: `tenants/${tenantId}/controls/PCI-DSS-10.2.1/quarantine/${intentId}.upload`,
    destinationBucket: "scopeproof-evidence",
    destinationKey: `tenants/${tenantId}/controls/PCI-DSS-10.2.1/evidence/evd_${"e".repeat(32)}.png`,
    fence: a.fence, permittedAt: a.now, leaseExpiresAt: a.leaseExpiresAt,
  });
  assert.equal(aAttempt.status.S, "COPY_PERMITTED");

  const versions: Array<{ attemptId: string; fence: number; versionId: string }> = [];
  let announceAPaused!: () => void;
  let resumeA!: () => void;
  const aPaused = new Promise<void>((resolve) => { announceAPaused = resolve; });
  const aMayResume = new Promise<void>((resolve) => { resumeA = resolve; });
  const conditionalPut = async (lease: { attemptId: string; fence: number }, pause = false) => {
    if (pause) {
      announceAPaused();
      await aMayResume;
    }
    if (versions.length !== 0) {
      throw Object.assign(new Error("conditional write lost"), { $metadata: { httpStatusCode: 412 } });
    }
    const created = { attemptId: lease.attemptId, fence: lease.fence, versionId: "exact-version-1" };
    versions.push(created);
    return created;
  };
  const isConflict = (error: unknown) =>
    (error as { $metadata?: { httpStatusCode?: number } })?.$metadata?.httpStatusCode === 412;
  const readWinner = async () => versions[0];

  // Worker A has a durable COPY_PERMITTED record and is suspended immediately
  // before the production conditional-create orchestration invokes S3.
  const aWrite = createOrAdoptImmutableDestination({
    createDestination: () => conditionalPut(a, true),
    isConditionalConflict: isConflict,
    readWinner,
  });
  await aPaused;

  // Its Dynamo lease expires, worker B atomically advances the fence, and B
  // creates the destination while A's earlier permit is still unresolved.
  const b = derivePromotionLease({
    tenantId, intentId, leaseId: "5".repeat(64), sourceVersionId,
    currentFence: a.fence, now: a.leaseExpiresAt,
  });
  const bWrite = await createOrAdoptImmutableDestination({
    createDestination: () => conditionalPut(b),
    isConditionalConflict: isConflict,
    readWinner,
  });
  assert.equal(bWrite.created, true);

  // A resumes after takeover. The same helper used by the Lambda converts the
  // 412 into adoption of B's winner; no second Object-Locked version exists.
  resumeA();
  const aResult = await aWrite;
  assert.equal(aResult.created, false);
  assert.deepEqual(aResult.destination, bWrite.result);
  assert.equal(versions.length, 1);
  assert.equal(versions[0].fence, 2);
  assert.throws(() => assertActivePromotionLease({
    leaseId: "5".repeat(64), attemptId: b.attemptId, fence: b.fence, leaseExpiresAt: b.leaseExpiresAt,
  }, { leaseId: "4".repeat(64), attemptId: a.attemptId, fence: a.fence }, "2026-08-27T16:05:00.001Z"));
  assert.ok(b.fence > a.fence, "the reconciliation fence supersedes the paused writer");

  const runtime = await readFile(new URL(
    "../infra/aws/cdk/runtime/promote-evidence/index.mjs",
    import.meta.url,
  ), "utf8");
  assert.match(runtime, /new PutObjectCommand\(\{/);
  assert.match(runtime, /createOrAdoptImmutableDestination\(\{/);
  assert.match(runtime, /IfNoneMatch: "\*"/);
  assert.match(runtime, /new GetObjectCommand\(\{[\s\S]*VersionId: versionId/);
  assert.match(runtime, /new QueryCommand\(\{[\s\S]*Limit: 100/);
  assert.match(runtime, /Promotion orphan recovery exceeded its bounded attempt limit/);
  assert.doesNotMatch(runtime, /CopyObjectCommand/);
});
