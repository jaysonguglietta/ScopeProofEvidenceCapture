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

test("native upload route derives metadata from a signed manifest and strictly decodes PNG", async () => {
  const [source, devices, client] = await Promise.all([
    readFile(new URL("../app/api/native/evidence/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/devices.ts", import.meta.url), "utf8"),
    readFile(new URL("../macos/ScopeproofCapture/Sources/ScopeproofCapture/UploadService.swift", import.meta.url), "utf8"),
  ]);
  assert.match(source, /manifest\.sha256 !== imageDigest/);
  assert.match(source, /parseNativeManifest/);
  assert.match(source, /validatePng/);
  assert.match(source, /verifyUploadSignature/);
  assert.match(source, /metadata must come only from the signed manifest/);
  assert.match(source, /clientSafetyClaim/);
  assert.match(source, /requireCaptureDevice/);
  assert.match(devices, /scopeproof-native-upload-v1/);
  assert.match(client, /HMAC<SHA256>/);
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

test("Jira handoff metadata is migrated, searchable, and packaged with safe instructions", async () => {
  const [migration, evidenceSource, packageSource] = await Promise.all([
    readFile(new URL("../drizzle/0003_cooing_rhino.sql", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/evidence.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/packages.ts", import.meta.url), "utf8"),
  ]);
  assert.match(migration, /ADD `jira_issue_key` text/);
  assert.match(migration, /ADD `jira_issue_url` text/);
  assert.match(migration, /idx_evidence_jira_issue/);
  assert.match(evidenceSource, /jira_issue_key, jira_issue_url/);
  assert.match(packageSource, /02-Jira-Handoff\.txt/);
  assert.match(packageSource, /DO NOT ATTACH/);
});

test("Jira Cloud OAuth and attachment upload enforce trust boundaries", async () => {
  const [migration, provenanceMigration, concurrencyMigration, jiraSource, uploadRoute, nativeEvidenceRoute] = await Promise.all([
    readFile(new URL("../drizzle/0004_cheerful_tombstone.sql", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0005_nappy_alice.sql", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0006_first_madelyne_pryor.sql", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/jira.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/native/jira/upload/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/native/evidence/route.ts", import.meta.url), "utf8"),
  ]);
  assert.match(migration, /CREATE TABLE `jira_connections`/);
  assert.match(migration, /CREATE TABLE `jira_oauth_states`/);
  assert.match(migration, /CREATE TABLE `jira_upload_receipts`/);
  assert.match(migration, /jira_upload_receipts_no_update/);
  assert.match(migration, /jira_upload_receipts_no_delete/);
  assert.match(provenanceMigration, /CREATE TABLE `native_evidence_manifests`/);
  assert.match(concurrencyMigration, /CREATE TABLE `jira_upload_operations`/);
  assert.match(concurrencyMigration, /ADD `token_version` integer/);
  assert.match(concurrencyMigration, /ADD `refresh_lease_id` text/);
  assert.match(jiraSource, /https:\/\/auth\.atlassian\.com\/authorize/);
  assert.match(jiraSource, /https:\/\/api\.atlassian\.com/);
  assert.match(jiraSource, /JIRA_OAUTH_TOKEN_ENCRYPTION_KEY/);
  assert.match(jiraSource, /stateHash = await sha256\(state\)/);
  assert.match(jiraSource, /host\.endsWith\("\.atlassian\.net"\)/);
  assert.match(jiraSource, /is not in this connection's allowlist/);
  assert.match(jiraSource, /Atlassian did not grant the required Jira read and write scopes/);
  assert.match(jiraSource, /Reviewer access is required for Jira Cloud evidence disclosure/);
  assert.match(jiraSource, /X-Atlassian-Token/);
  assert.match(jiraSource, /status = 'uploading'/);
  assert.match(jiraSource, /status = 'unknown'/);
  assert.match(jiraSource, /token_version = token_version \+ 1/);
  assert.match(jiraSource, /refresh_lease_id = \?/);
  assert.match(uploadRoute, /Screenshot integrity does not match its immutable manifest/);
  assert.match(uploadRoute, /valid hash-chained Approved lifecycle record/);
  assert.match(uploadRoute, /e\.created_by = \?/);
  assert.match(uploadRoute, /e\.sha256 = n\.image_sha256/);
  assert.match(uploadRoute, /authenticated Scopeproof reviewer must approve/);
  assert.match(uploadRoute, /new File\(\[hosted\.timestamp_token\]/);
  assert.match(nativeEvidenceRoute, /Matching evidence already exists under different hosted provenance/);
  assert.match(uploadRoute, /requireCaptureDevice/);
  assert.match(uploadRoute, /verifyUploadSignature/);
});
