import assert from "node:assert/strict";
import test from "node:test";

import { derivePromotionRetention } from "../infra/aws/cdk/runtime/promote-evidence/retention-contract.mjs";

test("promotion retention preserves a full tenant period after upload", () => {
  const result = derivePromotionRetention({
    requiredRetentionUntil: "2027-08-27T15:55:00.000Z",
    uploadedAt: "2026-08-27T16:00:00.000Z",
    retentionDays: 365,
  });
  assert.equal(result.uploadRetentionUntil, "2027-08-27T16:00:00.000Z");
  assert.equal(result.retainUntil.toISOString(), "2027-08-27T16:00:00.000Z");
});

test("promotion retention never shortens a later server-derived capture boundary", () => {
  const result = derivePromotionRetention({
    requiredRetentionUntil: "2027-08-27T16:04:59.999Z",
    uploadedAt: "2026-08-27T16:00:00.000Z",
    retentionDays: 365,
  });
  assert.equal(result.retainUntil.toISOString(), "2027-08-27T16:04:59.999Z");
});

test("promotion retention rejects noncanonical times and unsafe policy values", () => {
  const base = {
    requiredRetentionUntil: "2027-08-27T16:00:00.000Z",
    uploadedAt: "2026-08-27T16:00:00.000Z",
    retentionDays: 365,
  } as const;
  assert.throws(() => derivePromotionRetention({ ...base, uploadedAt: "2026-08-27T16:00:00Z" }), /invalid/);
  assert.throws(() => derivePromotionRetention({ ...base, retentionDays: 0 }), /retention period/);
  assert.throws(() => derivePromotionRetention({ ...base, retentionDays: 3_651 }), /retention period/);
});
