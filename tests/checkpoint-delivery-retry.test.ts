import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import {
  CHECKPOINT_DELIVERY_CLAIM_SQL,
  CHECKPOINT_DELIVERY_MAX_ATTEMPTS,
  checkpointDeliveryBackoffMs,
  classifyCheckpointDelivery,
  type CheckpointDeliveryAttemptState,
  type ExpectedCheckpointDelivery,
} from "../lib/server/checkpoint-delivery-retry.ts";

const read = (path: string) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

async function checkpointRetryDatabase(): Promise<DatabaseSync> {
  const [attemptMigration, retryMigration] = await Promise.all([
    read("drizzle/0025_pink_malice.sql"),
    read("drizzle/0027_lonely_guardian.sql"),
  ]);
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE audit_checkpoints (
    id TEXT PRIMARY KEY NOT NULL, sequence INTEGER NOT NULL, event_hash TEXT NOT NULL, event_count INTEGER NOT NULL,
    hmac_key_id TEXT NOT NULL, checkpoint_sha256 TEXT NOT NULL, signature TEXT NOT NULL,
    public_key_fingerprint TEXT NOT NULL, r2_key TEXT NOT NULL, external_status TEXT NOT NULL,
    external_receipt TEXT, external_receipt_sha256 TEXT, external_receipt_signature TEXT,
    external_receipt_r2_key TEXT, created_at TEXT NOT NULL
  );`);
  db.exec(attemptMigration);
  db.exec(retryMigration);
  return db;
}

function insertCheckpoint(db: DatabaseSync, id: string, sequence: number): void {
  db.prepare(`INSERT INTO audit_checkpoints
    (id, sequence, event_hash, event_count, hmac_key_id, checkpoint_sha256, signature,
     public_key_fingerprint, r2_key, external_status, created_at)
    VALUES (?, ?, 'event-hash', 1, 'audit-v1', ?, 'signature', 'fingerprint', ?, 'not_configured', '2026-09-01T00:00:00.000Z')`)
    .run(id, sequence, `${id}-sha`, `audit-checkpoints/${id}.json`);
}

function claimRetry(
  db: DatabaseSync,
  checkpointId: string,
  priorAttemptCount: number,
  attemptId: string,
  leaseId: string,
  now: string,
  leaseExpiresAt: string,
  nextAttemptAt: string,
): number {
  return Number(db.prepare(CHECKPOINT_DELIVERY_CLAIM_SQL).run(
    nextAttemptAt, leaseId, leaseExpiresAt, "https://witness.example", attemptId, now, now,
    checkpointId, `${checkpointId}-sha`, priorAttemptCount, CHECKPOINT_DELIVERY_MAX_ATTEMPTS, now,
  ).changes);
}

test("independent checkpoint delivery retries preserve the immutable checkpoint", async () => {
  const [checkpoints, schema] = await Promise.all([
    read("lib/server/checkpoints.ts"),
    read("db/schema.ts"),
  ]);

  assert.match(checkpoints, /if \(existing\)[\s\S]*attemptCheckpointDelivery\(existing, now\)/);
  assert.match(checkpoints, /INSERT INTO audit_checkpoints[\s\S]*'not_configured'/);
  assert.doesNotMatch(checkpoints, /UPDATE audit_checkpoints/);
  assert.match(schema, /auditCheckpointDeliveryAttempts = sqliteTable\("audit_checkpoint_delivery_attempts"/);
  assert.match(schema, /auditCheckpointDeliveryRetryState = sqliteTable\("audit_checkpoint_delivery_retry_state"/);
  assert.match(schema, /idx_checkpoint_delivery_attempts_delivered[\s\S]*where\(sql`\$\{table\.status\} = 'delivered'`\)/);
  assert.match(schema, /checkpoint_delivery_attempt_shape/);
  assert.match(schema, /checkpoint_delivery_retry_attempt_count_bounded/);
  assert.match(schema, /checkpoint_delivery_retry_state_shape/);
});

test("checkpoint delivery retry is head-bound, single-winner, and cleans up race objects", async () => {
  const checkpoints = await read("lib/server/checkpoints.ts");

  assert.match(checkpoints, /currentHeadMatchesCheckpoint\(row\)/);
  assert.ok(checkpoints.indexOf("claimCheckpointDelivery(row") < checkpoints.indexOf("deliverCheckpoint(endpoint.url"));
  assert.match(checkpoints, /CHECKPOINT_DELIVERY_CLAIM_SQL/);
  assert.doesNotMatch(checkpoints, /SELECT COUNT\(\*\) AS failure_count, MAX\(attempted_at\)/);
  assert.match(checkpoints, /"idempotency-key": checkpointSha256/);
  assert.match(checkpoints, /c\.sequence = \(SELECT sequence FROM audit_events ORDER BY sequence DESC LIMIT 1\)/);
  assert.match(checkpoints, /c\.event_hash = \(SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1\)/);
  assert.match(checkpoints, /c\.event_count = \(SELECT COUNT\(\*\) FROM audit_events WHERE sequence <= c\.sequence\)/);
  assert.match(checkpoints, /NOT EXISTS \(SELECT 1 FROM audit_checkpoint_delivery_attempts d WHERE d\.checkpoint_id = c\.id AND d\.status = 'delivered'\)/);
  assert.match(checkpoints, /disposition === "proven_loser"[\s\S]*await deleteAttemptObject\(externalReceiptR2Key\)/);
  assert.match(checkpoints, /if \(!responseCertain \|\| changes !== 0\) return;/);
  assert.match(checkpoints, /failed === "committed"\) await deleteAttemptObject/);
  assert.match(checkpoints, /const ownCommittedRow = String\(winner\.id\) === id[\s\S]*if \(!ownCommittedRow\) await env\.EVIDENCE_BUCKET\.delete\(r2Key\)/);
});

test("retry receipts are exact R2 objects and verification fails closed", async () => {
  const checkpoints = await read("lib/server/checkpoints.ts");

  assert.match(checkpoints, /\.external-receipts\/\$\{attemptId\}\.json/);
  for (const binding of ["deliveryAttemptId", "checkpointId", "checkpointSha256", "externalReceiptSha256", "sequence"]) {
    assert.match(checkpoints, new RegExp(`metadata\\.${binding}`));
  }
  assert.match(checkpoints, /hasExactKeys\(metadata, \["deliveryAttemptId", "checkpointId", "checkpointSha256", "externalReceiptSha256", "sequence"\]\)/);
  assert.match(checkpoints, /external_receipt_object_metadata_mismatch/);
  assert.match(checkpoints, /external_receipt_digest_mismatch/);
  assert.match(checkpoints, /checkpoint_delivery_attempt_mismatch/);
  assert.match(checkpoints, /verifyP256Signature\(publicKey, String\(receiptEnvelope\.signature/);
  assert.doesNotMatch(checkpoints, /error instanceof Error \? error\.message : String\(error\)/);
});

test("checkpoint delivery attempts are append-only and migration replay covers their constraints", async () => {
  const [migration, retryMigration, verifier] = await Promise.all([
    read("drizzle/0025_pink_malice.sql"),
    read("drizzle/0027_lonely_guardian.sql"),
    read("Scripts/verify_migrations.sh"),
  ]);

  assert.match(migration, /CREATE TABLE `audit_checkpoint_delivery_attempts`/);
  assert.match(migration, /checkpoint_delivery_attempt_shape/);
  assert.match(migration, /CREATE UNIQUE INDEX `idx_checkpoint_delivery_attempts_delivered`[\s\S]*WHERE .*status.* = 'delivered'/);
  assert.match(migration, /CREATE TRIGGER `audit_checkpoint_delivery_attempts_no_update`/);
  assert.match(migration, /CREATE TRIGGER `audit_checkpoint_delivery_attempts_no_delete`/);
  assert.match(retryMigration, /CREATE TABLE `audit_checkpoint_delivery_retry_state`/);
  assert.match(retryMigration, /CREATE TRIGGER `audit_checkpoint_delivery_attempts_require_active_claim`/);
  assert.match(retryMigration, /CREATE TRIGGER `audit_checkpoint_delivery_attempts_complete_claim`/);
  assert.match(retryMigration, /CREATE TRIGGER `audit_checkpoint_delivery_retry_state_no_delete`/);
  assert.match(verifier, /drizzle\/0025_pink_malice\.sql/);
  assert.match(verifier, /drizzle\/0027_lonely_guardian\.sql/);
  assert.match(verifier, /A checkpoint accepted more than one delivered attempt/);
  assert.match(verifier, /A checkpoint delivery attempt was mutable/);
  assert.match(verifier, /A malformed checkpoint delivery attempt bypassed the shape constraint/);
});

test("a due checkpoint has one atomic claimant and no request is issued before the durable due time", async () => {
  const db = await checkpointRetryDatabase();
  insertCheckpoint(db, "checkpoint_due", 1);
  db.prepare(`INSERT INTO audit_checkpoint_delivery_retry_state
    (checkpoint_id, checkpoint_sha256, status, attempt_count, next_attempt_at, created_at, updated_at)
    VALUES (?, ?, 'retrying', 0, ?, ?, ?)`)
    .run("checkpoint_due", "checkpoint_due-sha", "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z");
  let outboundRequests = 0;
  outboundRequests += claimRetry(db, "checkpoint_due", 0, "attempt-a", "lease-a", "2026-09-01T00:00:01.000Z", "2026-09-01T00:02:01.000Z", "2026-09-01T00:01:01.000Z");
  outboundRequests += claimRetry(db, "checkpoint_due", 0, "attempt-b", "lease-b", "2026-09-01T00:00:01.000Z", "2026-09-01T00:02:01.000Z", "2026-09-01T00:01:01.000Z");
  assert.equal(outboundRequests, 1);
  assert.deepEqual({ ...db.prepare(`SELECT status, attempt_count AS attemptCount, lease_id AS leaseId, last_attempt_id AS lastAttemptId
    FROM audit_checkpoint_delivery_retry_state WHERE checkpoint_id = 'checkpoint_due'`).get() },
  { status: "claimed", attemptCount: 1, leaseId: "lease-a", lastAttemptId: "attempt-a" });

  insertCheckpoint(db, "checkpoint_future", 2);
  db.prepare(`INSERT INTO audit_checkpoint_delivery_retry_state
    (checkpoint_id, checkpoint_sha256, status, attempt_count, next_attempt_at, created_at, updated_at)
    VALUES (?, ?, 'retrying', 0, ?, ?, ?)`)
    .run("checkpoint_future", "checkpoint_future-sha", "2026-09-01T00:10:00.000Z", "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z");
  assert.equal(claimRetry(db, "checkpoint_future", 0, "too-early", "lease-early", "2026-09-01T00:09:59.999Z", "2026-09-01T00:11:59.999Z", "2026-09-01T00:10:59.999Z"), 0);
  assert.equal(checkpointDeliveryBackoffMs(1), 60_000);
  assert.equal(checkpointDeliveryBackoffMs(10), 6 * 60 * 60_000);
  db.close();
});

test("an expired claim becomes immutable failure evidence before one later claimant can recover it", async () => {
  const db = await checkpointRetryDatabase();
  insertCheckpoint(db, "checkpoint_stale", 3);
  db.prepare(`INSERT INTO audit_checkpoint_delivery_retry_state
    (checkpoint_id, checkpoint_sha256, status, attempt_count, next_attempt_at, lease_id, lease_expires_at,
     endpoint_origin, last_attempt_id, last_attempt_at, created_at, updated_at)
    VALUES (?, ?, 'claimed', 1, ?, 'lease-stale', ?, 'https://witness.example', 'attempt-stale', ?, ?, ?)`)
    .run("checkpoint_stale", "checkpoint_stale-sha", "2026-09-01T00:01:00.000Z", "2026-09-01T00:02:00.000Z",
      "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z");
  db.prepare(`INSERT INTO audit_checkpoint_delivery_attempts
    (id, checkpoint_id, checkpoint_sha256, sequence, endpoint_origin, attempted_at, status, failure_code, created_at)
    VALUES ('attempt-stale', 'checkpoint_stale', 'checkpoint_stale-sha', 3, 'https://witness.example',
      '2026-09-01T00:00:00.000Z', 'failed', 'DELIVERY_CLAIM_EXPIRED', '2026-09-01T00:02:00.001Z')`).run();
  assert.deepEqual({ ...db.prepare(`SELECT status, attempt_count AS attemptCount, lease_id AS leaseId, last_failure_code AS lastFailureCode
    FROM audit_checkpoint_delivery_retry_state WHERE checkpoint_id = 'checkpoint_stale'`).get() },
  { status: "retrying", attemptCount: 1, leaseId: null, lastFailureCode: "DELIVERY_CLAIM_EXPIRED" });
  assert.equal(claimRetry(db, "checkpoint_stale", 1, "attempt-recovered", "lease-recovered", "2026-09-01T00:02:01.000Z", "2026-09-01T00:04:01.000Z", "2026-09-01T00:04:01.000Z"), 1);
  assert.throws(() => db.prepare(`INSERT INTO audit_checkpoint_delivery_attempts
    (id, checkpoint_id, checkpoint_sha256, sequence, endpoint_origin, attempted_at, status, failure_code, created_at)
    VALUES ('stale-non-owner', 'checkpoint_stale', 'checkpoint_stale-sha', 3, 'https://witness.example',
      '2026-09-01T00:00:00.000Z', 'failed', 'DELIVERY_REQUEST_FAILED', '2026-09-01T00:02:02.000Z')`).run(),
  /does not own the active claim/);
  db.close();
});

test("the tenth claimed failure becomes action-required and cannot be claimed again", async () => {
  const db = await checkpointRetryDatabase();
  insertCheckpoint(db, "checkpoint_cap", 4);
  db.prepare(`INSERT INTO audit_checkpoint_delivery_retry_state
    (checkpoint_id, checkpoint_sha256, status, attempt_count, next_attempt_at, lease_id, lease_expires_at,
     endpoint_origin, last_attempt_id, last_attempt_at, last_failure_code, created_at, updated_at)
    VALUES (?, ?, 'claimed', 10, ?, 'lease-ten', ?, 'https://witness.example', 'attempt-ten', ?,
      'DELIVERY_REQUEST_FAILED', ?, ?)`)
    .run("checkpoint_cap", "checkpoint_cap-sha", "2026-09-01T06:00:00.000Z", "2026-09-01T00:02:00.000Z",
      "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z");
  db.prepare(`INSERT INTO audit_checkpoint_delivery_attempts
    (id, checkpoint_id, checkpoint_sha256, sequence, endpoint_origin, attempted_at, status, failure_code, created_at)
    VALUES ('attempt-ten', 'checkpoint_cap', 'checkpoint_cap-sha', 4, 'https://witness.example',
      '2026-09-01T00:00:00.000Z', 'failed', 'DELIVERY_REQUEST_FAILED', '2026-09-01T00:00:01.000Z')`).run();
  assert.deepEqual({ ...db.prepare(`SELECT status, attempt_count AS attemptCount, next_attempt_at AS nextAttemptAt,
    lease_id AS leaseId FROM audit_checkpoint_delivery_retry_state WHERE checkpoint_id = 'checkpoint_cap'`).get() },
  { status: "action_required", attemptCount: 10, nextAttemptAt: null, leaseId: null });
  assert.equal(claimRetry(db, "checkpoint_cap", 10, "attempt-eleven", "lease-eleven", "2026-09-02T00:00:00.000Z", "2026-09-02T00:02:00.000Z", "2026-09-02T06:00:00.000Z"), 0);
  db.close();
});

test("authoritative readback preserves an ambiguous winning receipt and deletes only a proven race loser", async () => {
  const db = await checkpointRetryDatabase();
  insertCheckpoint(db, "checkpoint_commit", 5);
  db.prepare(`INSERT INTO audit_checkpoint_delivery_retry_state
    (checkpoint_id, checkpoint_sha256, status, attempt_count, next_attempt_at, lease_id, lease_expires_at,
     endpoint_origin, last_attempt_id, last_attempt_at, created_at, updated_at)
    VALUES (?, ?, 'claimed', 1, ?, 'lease-commit', ?, 'https://witness.example', 'attempt-commit', ?, ?, ?)`)
    .run("checkpoint_commit", "checkpoint_commit-sha", "2026-09-01T00:01:00.000Z", "2026-09-01T00:02:00.000Z",
      "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z", "2026-09-01T00:00:00.000Z");
  const expected: ExpectedCheckpointDelivery = {
    attemptId: "attempt-commit", checkpointId: "checkpoint_commit", checkpointSha256: "checkpoint_commit-sha", sequence: 5,
    endpointOrigin: "https://witness.example", attemptedAt: "2026-09-01T00:00:00.000Z", externalReceipt: "{}",
    externalReceiptSha256: "receipt-sha", externalReceiptSignature: "receipt-signature",
    externalReceiptR2Key: "audit-checkpoints/checkpoint_commit.external-receipt.json", createdAt: "2026-09-01T00:00:01.000Z",
  };
  db.prepare(`INSERT INTO audit_checkpoint_delivery_attempts
    (id, checkpoint_id, checkpoint_sha256, sequence, endpoint_origin, attempted_at, status, external_receipt,
     external_receipt_sha256, external_receipt_signature, external_receipt_r2_key, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 'delivered', ?, ?, ?, ?, ?)`)
    .run(expected.attemptId, expected.checkpointId, expected.checkpointSha256, expected.sequence, expected.endpointOrigin,
      expected.attemptedAt, expected.externalReceipt, expected.externalReceiptSha256, expected.externalReceiptSignature,
      expected.externalReceiptR2Key, expected.createdAt);
  const winner = db.prepare(`SELECT id, checkpoint_id AS checkpointId, checkpoint_sha256 AS checkpointSha256,
    sequence, endpoint_origin AS endpointOrigin, attempted_at AS attemptedAt, status, external_receipt AS externalReceipt,
    external_receipt_sha256 AS externalReceiptSha256, external_receipt_signature AS externalReceiptSignature,
    external_receipt_r2_key AS externalReceiptR2Key, failure_code AS failureCode, created_at AS createdAt
    FROM audit_checkpoint_delivery_attempts WHERE checkpoint_id = ? AND status = 'delivered'`).get(expected.checkpointId) as CheckpointDeliveryAttemptState;
  assert.equal(classifyCheckpointDelivery(winner, expected), "committed");
  assert.equal(classifyCheckpointDelivery(null, expected), "uncertain");
  assert.equal(classifyCheckpointDelivery({ ...winner, id: "other-winner", externalReceiptR2Key: "other.json" }, expected), "proven_loser");
  assert.equal(classifyCheckpointDelivery({ ...winner, id: "other-winner" }, expected), "uncertain");
  db.close();
});

test("successful retry invalidates a cached checkpoint-verification failure", async () => {
  const audit = await read("lib/server/audit.ts");

  assert.match(audit, /LEFT JOIN audit_checkpoint_delivery_attempts d ON d\.checkpoint_id = c\.id AND d\.status = 'delivered'/);
  assert.match(audit, /delivery_attempt_id/);
  assert.match(audit, /delivery_attempt_receipt_sha256/);
  assert.match(audit, /checkpoint\?\.delivery_attempt_id \|\| "NONE"/);
  assert.match(audit, /checkpoint\?\.delivery_attempt_receipt_sha256 \|\| "NONE"/);
});

test("operational health reports append-only checkpoint delivery outcomes", async () => {
  const monitoring = await read("lib/server/monitoring.ts");
  assert.match(monitoring, /FROM audit_checkpoint_delivery_attempts delivered/);
  assert.match(monitoring, /delivered\.checkpoint_id = c\.id AND delivered\.status = 'delivered'/);
  assert.match(monitoring, /FROM audit_checkpoint_delivery_attempts failed/);
  assert.match(monitoring, /END AS effective_external_status/);
  assert.match(monitoring, /externalStatus: checkpoint\.effective_external_status/);
});
