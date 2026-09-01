import { canonicalInstant, TenantSecurityError } from "../contracts.ts";

const MAXIMUM_CAPTURE_CLOCK_SKEW_MS = 5 * 60 * 1_000;
// Ordinary capture uploads are deliberately not an unrestricted historical
// import mechanism. A separate, reviewed migration workflow should be used for
// older evidence so a stolen device credential cannot back-fill arbitrary data.
export const MAXIMUM_CAPTURE_AGE_MS = 30 * 24 * 60 * 60 * 1_000;

export interface ServerManagedUploadRetention {
  readonly capturedAt: string;
  readonly artifactExpiresAt: string;
  readonly requiredRetentionUntil: Date;
}

/**
 * Converts the tenant's immutable retention-days policy into the only accepted
 * upload retention boundary. Client timestamps are assertions, never policy.
 * Deriving from capturedAt keeps exact idempotent retries deterministic.
 */
export function deriveServerManagedUploadRetention(input: Readonly<{
  capturedAt: Date | string;
  retentionDays: number;
  now: Date;
}>): ServerManagedUploadRetention {
  if (!(input.now instanceof Date) || !Number.isFinite(input.now.getTime())) {
    throw new Error("Upload retention clock is invalid.");
  }
  if (!Number.isSafeInteger(input.retentionDays) || input.retentionDays < 1 || input.retentionDays > 3_650) {
    throw new Error("Tenant evidence retention period is invalid.");
  }
  const capturedAt = canonicalInstant(input.capturedAt, "Evidence capture time");
  if (Date.parse(capturedAt) > input.now.getTime() + MAXIMUM_CAPTURE_CLOCK_SKEW_MS) {
    throw new TenantSecurityError(
      "RETENTION_VIOLATION",
      "Evidence capture time exceeds the allowed clock skew.",
      409,
    );
  }
  if (Date.parse(capturedAt) < input.now.getTime() - MAXIMUM_CAPTURE_AGE_MS) {
    throw new TenantSecurityError(
      "RETENTION_VIOLATION",
      "Evidence capture time is older than the 30-day collection window.",
      409,
    );
  }
  const policyMilliseconds = Date.parse(capturedAt) + input.retentionDays * 24 * 60 * 60 * 1_000;
  if (!Number.isSafeInteger(policyMilliseconds)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Evidence retention time is invalid.", 409);
  }
  const policyRetentionUntil = new Date(policyMilliseconds).toISOString();
  return Object.freeze({
    capturedAt,
    artifactExpiresAt: policyRetentionUntil,
    requiredRetentionUntil: new Date(policyRetentionUntil),
  });
}
