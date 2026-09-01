import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { classifyObjectRotation, jiraRotationReachedActiveState, MAX_ROTATION_ATTEMPT_COUNT, nextRotationFailureState } from "../lib/server/key-rotation-reconciliation.ts";

const read = (path: string) => readFile(new URL(`../${path}`, import.meta.url), "utf8");
const expected = { nextKey: "evidence/current.rekey-new", nextEncryptionKeyId: "evidence-v2" } as const;

test("authoritative object rotation state preserves every referenced new ciphertext", () => {
  assert.equal(classifyObjectRotation({
    currentKey: expected.nextKey,
    encryptionKeyId: expected.nextEncryptionKeyId,
    pendingKey: null,
    previousKey: "evidence/old",
  }, expected), "committed");
  assert.equal(classifyObjectRotation({
    currentKey: "evidence/old",
    encryptionKeyId: "evidence-v1",
    pendingKey: expected.nextKey,
    previousKey: null,
  }, expected), "still_referenced");
  assert.equal(classifyObjectRotation({
    currentKey: expected.nextKey,
    encryptionKeyId: "unexpected-key-id",
    pendingKey: null,
    previousKey: null,
  }, expected), "still_referenced");
});

test("only an authoritative state with no reference proves a rotation object is a loser", () => {
  assert.equal(classifyObjectRotation({
    currentKey: "evidence/other",
    encryptionKeyId: "evidence-v2",
    pendingKey: null,
    previousKey: "evidence/old",
  }, expected), "proven_loser");
  assert.equal(classifyObjectRotation(null, expected), "proven_loser");
});

test("Jira ambiguous commits require the active key and a monotonic version advance", () => {
  assert.equal(jiraRotationReachedActiveState({ tokenKeyId: "jira-v2", tokenVersion: 8 }, "jira-v2", 8), true);
  assert.equal(jiraRotationReachedActiveState({ tokenKeyId: "jira-v2", tokenVersion: 9 }, "jira-v2", 8), true);
  assert.equal(jiraRotationReachedActiveState({ tokenKeyId: "jira-v1", tokenVersion: 8 }, "jira-v2", 8), false);
  assert.equal(jiraRotationReachedActiveState({ tokenKeyId: "jira-v2", tokenVersion: 7 }, "jira-v2", 8), false);
});

test("concurrent failure retries advance a bounded monotonic state", () => {
  const first = nextRotationFailureState(null, Date.parse("2026-09-01T00:00:00.000Z"), 5);
  assert.deepEqual(first, { attemptCount: 1, status: "retrying", nextAttemptAt: "2026-09-01T00:10:00.000Z" });
  // A loser of the insert CAS must reread the peer's unique attempt ID before
  // deriving its own transition; it therefore records attempt two, not one.
  const second = nextRotationFailureState({ ...first, lastAttemptId: "peer-attempt" }, Date.parse("2026-09-01T00:00:01.000Z"), 5);
  assert.deepEqual(second, { attemptCount: 2, status: "retrying", nextAttemptAt: "2026-09-01T00:20:01.000Z" });
  const actionRequired = nextRotationFailureState({ attemptCount: 4, status: "retrying", lastAttemptId: "attempt-four" }, Date.parse("2026-09-01T00:00:00.000Z"), 5);
  assert.equal(actionRequired.status, "action_required");
  assert.equal(nextRotationFailureState({ attemptCount: 99, status: "resolved", lastAttemptId: "resolved" }, 0, 5).attemptCount, 1);
  assert.equal(nextRotationFailureState({ attemptCount: MAX_ROTATION_ATTEMPT_COUNT, status: "action_required", lastAttemptId: "max" }, 0, 5).attemptCount, MAX_ROTATION_ATTEMPT_COUNT);
});

test("rotation error paths reconcile before deleting and readiness fails action-required state", async () => {
  const [operations, readiness, migration, verifier] = await Promise.all([
    read("lib/server/key-operations.ts"),
    read("lib/server/readiness.ts"),
    read("drizzle/0026_omniscient_scarlet_witch.sql"),
    read("Scripts/verify_migrations.sh"),
  ]);
  assert.match(operations, /deleteOnlyProvenRotationLoser/);
  assert.match(operations, /if \(disposition === "committed"\) return true;/);
  assert.match(operations, /if \(disposition === "proven_loser"\) await getEnv\(\)\.EVIDENCE_BUCKET\.delete\(nextKey\)/);
  assert.equal((operations.match(/rotation_lease_expires_at > \?/g) || []).length, 2, "both object switches must reject an expired original lease");
  assert.equal((operations.match(/SET rotation_lease_id = \?, rotation_lease_expires_at = \?[\s\S]*?r2_key = \? AND rotation_pending_r2_key IS \? AND rotation_previous_r2_key IS \?/g) || []).length, 2,
    "each garbage reconciler must CAS-claim the exact current/pending/previous state");
  const firstGarbageDelete = operations.indexOf("for (const key of garbage) await env.EVIDENCE_BUCKET.delete(key)");
  const firstCleanupClaim = operations.indexOf("const claim = await env.DB.prepare(`UPDATE evidence_artifacts SET rotation_lease_id");
  assert.ok(firstCleanupClaim >= 0 && firstCleanupClaim < firstGarbageDelete, "reconciliation must claim the row before deleting any candidate");
  assert.match(operations, /scopeproof_key_rotation_recovery_tracking_failed/);
  assert.match(operations, /ON CONFLICT\(resource_type, resource_id\) DO NOTHING/);
  assert.match(operations, /attempt_count = \? AND status = \? AND last_attempt_id = \?/);
  assert.match(operations, /current\?\.last_attempt_id !== attemptId/);
  assert.match(operations, /status = 'resolved'[\s\S]*resolved_at = \?[\s\S]*last_attempt_id = \?/);
  assert.match(operations, /keyRotationRetrySummary/);
  assert.match(readiness, /retries\.actionRequired > 0 \? "fail"/);
  assert.match(migration, /key_rotation_resource_type_allowlist/);
  assert.match(migration, /key_rotation_error_code_allowlist/);
  assert.match(migration, /`last_attempt_id` text NOT NULL/);
  assert.match(migration, /key_rotation_attempt_count_bounded/);
  assert.match(verifier, /unknown key-rotation resource type bypassed/);
  assert.match(verifier, /unknown key-rotation error code bypassed/);
  assert.match(verifier, /unbounded key-rotation attempt count bypassed/);
});
