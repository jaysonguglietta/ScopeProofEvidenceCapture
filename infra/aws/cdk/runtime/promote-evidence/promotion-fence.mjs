import { createHash } from "node:crypto";

export const promotionLeaseDurationMilliseconds = 5 * 60_000;

const tenantPattern = /^ten_[a-f0-9]{32}$/;
const intentPattern = /^upl_[a-f0-9]{32}$/;
const attemptPattern = /^pat_[a-f0-9]{32}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const versionPattern = /^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/;

/**
 * Derive the next monotonically increasing promotion fence. DynamoDB still
 * performs the authoritative compare-and-swap; this helper makes the token
 * and attempt identity deterministic and independently testable.
 */
export function derivePromotionLease(input) {
  const tenantId = String(input?.tenantId ?? "");
  const intentId = String(input?.intentId ?? "");
  const leaseId = String(input?.leaseId ?? "");
  const sourceVersionId = String(input?.sourceVersionId ?? "");
  const now = canonicalInstant(input?.now, "Promotion lease time");
  const currentFence = input?.currentFence;
  if (
    !tenantPattern.test(tenantId) || !intentPattern.test(intentId) ||
    !digestPattern.test(leaseId) || !versionPattern.test(sourceVersionId) ||
    (currentFence !== undefined && (!Number.isSafeInteger(currentFence) || currentFence < 1))
  ) {
    throw new Error("Promotion lease input is invalid.");
  }
  const fence = currentFence === undefined ? 1 : currentFence + 1;
  if (!Number.isSafeInteger(fence)) throw new Error("Promotion fence is exhausted.");
  const attemptId = `pat_${digestHex([
    "scopeproof-promotion-attempt-v1", tenantId, intentId, sourceVersionId, String(fence), leaseId,
  ].join("\n")).slice(0, 32)}`;
  return Object.freeze({
    attemptId,
    fence,
    leaseExpiresAt: new Date(Date.parse(now) + promotionLeaseDurationMilliseconds).toISOString(),
    now,
  });
}

export function assertActivePromotionLease(snapshot, expected, nowValue) {
  const now = canonicalInstant(nowValue, "Promotion lease verification time");
  if (
    !snapshot || typeof snapshot !== "object" ||
    snapshot.leaseId !== expected?.leaseId ||
    snapshot.attemptId !== expected?.attemptId ||
    snapshot.fence !== expected?.fence ||
    !digestPattern.test(String(snapshot.leaseId ?? "")) ||
    !attemptPattern.test(String(snapshot.attemptId ?? "")) ||
    !Number.isSafeInteger(snapshot.fence) || snapshot.fence < 1 ||
    Date.parse(canonicalInstant(snapshot.leaseExpiresAt, "Promotion lease expiry")) <= Date.parse(now)
  ) {
    throw new Error("An active promotion fence is required.");
  }
  return Object.freeze({
    attemptId: snapshot.attemptId,
    fence: snapshot.fence,
    leaseExpiresAt: snapshot.leaseExpiresAt,
    leaseId: snapshot.leaseId,
  });
}

/**
 * The attempt record is inserted atomically with the final lease renewal and
 * before the conditional destination PutObject. It deliberately exists even if the worker
 * is suspended or crashes after S3 accepts an Object-Locked version.
 */
export function buildPromotionCopyAttemptItem(input) {
  const tenantId = String(input?.tenantId ?? "");
  const intentId = String(input?.intentId ?? "");
  const receiptHash = String(input?.receiptHash ?? "");
  const attemptId = String(input?.attemptId ?? "");
  const leaseId = String(input?.leaseId ?? "");
  const sourceVersionId = String(input?.sourceVersionId ?? "");
  const expectedSha256 = String(input?.expectedSha256 ?? "");
  const sourceBucket = String(input?.sourceBucket ?? "");
  const sourceKey = String(input?.sourceKey ?? "");
  const destinationBucket = String(input?.destinationBucket ?? "");
  const destinationKey = String(input?.destinationKey ?? "");
  const permittedAt = canonicalInstant(input?.permittedAt, "Promotion copy permit time");
  const leaseExpiresAt = canonicalInstant(input?.leaseExpiresAt, "Promotion copy permit expiry");
  const fence = input?.fence;
  if (
    !tenantPattern.test(tenantId) || !intentPattern.test(intentId) ||
    !digestPattern.test(receiptHash) || !attemptPattern.test(attemptId) ||
    !digestPattern.test(leaseId) || !digestPattern.test(expectedSha256) ||
    !versionPattern.test(sourceVersionId) || !Number.isSafeInteger(fence) || fence < 1 ||
    !validBucket(sourceBucket) || !validBucket(destinationBucket) ||
    !sourceKey.startsWith(`tenants/${tenantId}/controls/`) ||
    !destinationKey.startsWith(`tenants/${tenantId}/controls/`) ||
    sourceKey.length > 1_024 || destinationKey.length > 1_024 ||
    Date.parse(leaseExpiresAt) <= Date.parse(permittedAt)
  ) {
    throw new Error("Promotion copy attempt is invalid.");
  }
  return Object.freeze({
    PK: { S: `TENANT#${tenantId}` },
    SK: { S: promotionCopyAttemptSortKey(receiptHash, fence) },
    attemptId: { S: attemptId },
    destinationBucket: { S: destinationBucket },
    destinationKey: { S: destinationKey },
    expectedSha256: { S: expectedSha256 },
    fence: { N: String(fence) },
    intentId: { S: intentId },
    kind: { S: "EvidencePromotionCopyAttempt" },
    leaseExpiresAt: { S: leaseExpiresAt },
    leaseId: { S: leaseId },
    permittedAt: { S: permittedAt },
    receiptHash: { S: receiptHash },
    sourceBucket: { S: sourceBucket },
    sourceKey: { S: sourceKey },
    sourceVersionId: { S: sourceVersionId },
    status: { S: "COPY_PERMITTED" },
    tenantId: { S: tenantId },
  });
}

export function promotionCopyAttemptSortKey(receiptHash, fence) {
  if (!digestPattern.test(String(receiptHash ?? "")) || !Number.isSafeInteger(fence) || fence < 1) {
    throw new Error("Promotion copy attempt key is invalid.");
  }
  return `PROMOTION_ATTEMPT#${receiptHash}#${String(fence).padStart(16, "0")}`;
}

export function promotionCopyMetadata(input) {
  const attemptId = String(input?.attemptId ?? "");
  const fence = input?.fence;
  if (!attemptPattern.test(attemptId) || !Number.isSafeInteger(fence) || fence < 1) {
    throw new Error("Promotion copy metadata is invalid.");
  }
  return Object.freeze({
    "promotion-attempt-id": attemptId,
    "promotion-fence": String(fence),
  });
}

/**
 * Execute the only operation allowed to create the immutable destination.
 * S3's If-None-Match precondition is the ultimate creation fence: the
 * monotonic lease prevents stale reconciliation, while this function lets a
 * losing worker adopt the one winner without replaying an unconditional PUT.
 */
export async function createOrAdoptImmutableDestination(input) {
  if (
    typeof input?.createDestination !== "function" ||
    typeof input?.isConditionalConflict !== "function" ||
    typeof input?.readWinner !== "function"
  ) {
    throw new Error("Conditional promotion write callbacks are invalid.");
  }
  try {
    return Object.freeze({
      created: true,
      destination: undefined,
      result: await input.createDestination(),
    });
  } catch (error) {
    if (!input.isConditionalConflict(error)) throw error;
    const destination = await input.readWinner();
    if (!destination) {
      throw new Error("The conditional promotion winner could not be recovered.");
    }
    return Object.freeze({ created: false, destination, result: undefined });
  }
}

function canonicalInstant(value, label) {
  if (typeof value !== "string") throw new Error(`${label} is invalid.`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}

function validBucket(value) {
  return /^(?=.{3,63}$)(?!xn--)(?!.*\.\.)(?!.*-$)[a-z0-9][a-z0-9.-]*[a-z0-9]$/.test(value);
}

function digestHex(value) {
  return createHash("sha256").update(value).digest("hex");
}
