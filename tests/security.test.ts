import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { redactText } from "../lib/server/redaction.ts";

test("redacts Luhn-valid PANs while preserving invalid numeric identifiers", () => {
  const result = redactText("card=4111 1111 1111 1111 order=4111111111111112");
  assert.match(result.value, /\[REDACTED\]-PAN-1111/);
  assert.match(result.value, /order=4111111111111112/);
  assert.deepEqual(result.findings, [{ kind: "pan", count: 1 }]);
});

test("redacts high-confidence credentials and private keys", () => {
  const result = redactText([
    "aws=AKIAIOSFODNN7EXAMPLE",
    "authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue",
    "api_token=very-sensitive-token-value-12345",
    "-----BEGIN PRIVATE KEY-----\nabc123\n-----END PRIVATE KEY-----",
  ].join("\n"));
  assert.ok(result.total >= 4);
  assert.doesNotMatch(result.value, /AKIAIOSFODNN7EXAMPLE|very-sensitive-token-value|BEGIN PRIVATE KEY/);
});

test("migration makes audit events append-only at the database layer", async () => {
  const migration = await readFile(new URL("../drizzle/0000_curvy_risque.sql", import.meta.url), "utf8");
  assert.match(migration, /CREATE TRIGGER `audit_events_no_update`/);
  assert.match(migration, /CREATE TRIGGER `audit_events_no_delete`/);
  assert.match(migration, /CREATE TRIGGER `audit_events_chain_guard`/);
  assert.match(migration, /RAISE\(ABORT, 'audit_events are immutable'\)/);
});

test("native capture migration stores revocable device identities and chain-of-custody metadata", async () => {
  const migration = await readFile(new URL("../drizzle/0001_sloppy_stark_industries.sql", import.meta.url), "utf8");
  assert.match(migration, /CREATE TABLE `capture_devices`/);
  assert.match(migration, /CREATE UNIQUE INDEX `idx_capture_devices_token_hash`/);
  assert.match(migration, /CREATE TABLE `capture_sessions`/);
  assert.match(migration, /ADD `manifest_sha256` text/);
  assert.match(migration, /ADD `chain_previous_hash` text/);
  assert.match(migration, /ADD `chain_event_hash` text/);
  assert.match(migration, /ADD `timestamp_token` text/);
});

test("native upload route enforces image integrity and local safety review", async () => {
  const source = await readFile(new URL("../app/api/native/evidence/route.ts", import.meta.url), "utf8");
  assert.match(source, /manifest\.sha256 !== imageDigest/);
  assert.match(source, /\["passed", "redacted"\]\.includes\(safetyStatus\)/);
  assert.match(source, /Only PNG capture evidence is accepted/);
  assert.match(source, /requireCaptureDevice/);
});

test("assessor metadata migration and package preserve framework organization", async () => {
  const [migration, packageSource] = await Promise.all([
    readFile(new URL("../drizzle/0003_fine_wonder_man.sql", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/packages.ts", import.meta.url), "utf8"),
  ]);
  for (const column of ["framework", "catalog_version", "assessment_period", "evidence_owner", "tags_json", "mapped_controls_json", "manual_redactions"]) {
    assert.ok(migration.includes(`ADD \`${column}\``));
  }
  assert.match(packageSource, /evidence\/\$\{safeName\(String\(row\.framework/);
  assert.match(packageSource, /01-Evidence-Index\.csv/);
  assert.match(packageSource, /ECDSA-P256-SHA256/);
});
