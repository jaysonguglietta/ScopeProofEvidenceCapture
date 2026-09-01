import assert from "node:assert/strict";
import test from "node:test";

import { deriveServerManagedUploadRetention } from "../lib/aws-runtime/evidence/upload-retention-policy.ts";

test("upload retention is exactly derived from the tenant policy and stable capture time", () => {
  const result = deriveServerManagedUploadRetention({
    capturedAt: "2026-08-27T16:00:00.000Z",
    retentionDays: 365,
    now: new Date("2026-08-27T16:04:59.999Z"),
  });
  assert.equal(result.capturedAt, "2026-08-27T16:00:00.000Z");
  assert.equal(result.artifactExpiresAt, "2027-08-27T16:00:00.000Z");
  assert.equal(result.requiredRetentionUntil.toISOString(), "2027-08-27T16:00:00.000Z");
});

test("collectors cannot control retention or future-date capture", () => {
  const base = {
    capturedAt: "2026-08-27T16:00:00.000Z",
    retentionDays: 365,
    now: new Date("2026-08-27T16:00:00.000Z"),
  } as const;
  assert.throws(
    () => deriveServerManagedUploadRetention({
      ...base,
      capturedAt: "2026-08-27T16:05:00.001Z",
    }),
    /clock skew/,
  );
  assert.throws(
    () => deriveServerManagedUploadRetention({
      ...base,
      capturedAt: "2026-07-28T15:59:59.999Z",
    }),
    /30-day collection window/,
  );
  assert.throws(
    () => deriveServerManagedUploadRetention({ ...base, retentionDays: 3_651 }),
    /retention period/,
  );
});
