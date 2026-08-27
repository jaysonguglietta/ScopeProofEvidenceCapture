const millisecondsPerDay = 86_400_000;

/**
 * S3 must preserve evidence through both policy boundaries:
 * - the logical evidence boundary derived by the API from capturedAt; and
 * - a full tenant retention period after S3 accepted the exact source version.
 *
 * The second boundary prevents a stale or backdated capture assertion from
 * shortening immutable storage. The logical catalog can expire earlier while
 * Object Lock intentionally remains in force.
 */
export function derivePromotionRetention(input) {
  const requiredRetentionUntil = canonicalInstant(
    input?.requiredRetentionUntil,
    "Required retention time",
  );
  const uploadedAt = canonicalInstant(input?.uploadedAt, "Source upload time");
  const retentionDays = input?.retentionDays;
  if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 3650) {
    throw new Error("Invalid evidence retention period.");
  }
  const uploadBoundaryMilliseconds = Date.parse(uploadedAt) + retentionDays * millisecondsPerDay;
  if (!Number.isSafeInteger(uploadBoundaryMilliseconds)) {
    throw new Error("Evidence retention boundary is invalid.");
  }
  const retainUntilMilliseconds = Math.max(
    Date.parse(requiredRetentionUntil),
    uploadBoundaryMilliseconds,
  );
  return Object.freeze({
    retainUntil: new Date(retainUntilMilliseconds),
    requiredRetentionUntil,
    uploadedAt,
    uploadRetentionUntil: new Date(uploadBoundaryMilliseconds).toISOString(),
  });
}

function canonicalInstant(value, label) {
  if (typeof value !== "string") throw new Error(`${label} is invalid.`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error(`${label} is invalid.`);
  }
  return value;
}
