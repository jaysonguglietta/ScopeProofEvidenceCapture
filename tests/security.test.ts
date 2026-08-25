import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { redactText } from "../lib/server/redaction.ts";
import { csvCell } from "../lib/server/csv.ts";
import { configuredMacRelease, releaseSigningPayload } from "../lib/server/releases.ts";
import type { ScopeproofEnv } from "../lib/server/env.ts";

test("neutralizes spreadsheet formulas in every server CSV cell", () => {
  for (const value of ["=1+1", "+cmd|' /C calc'!A0", "-42", "@SUM(A1:A2)", " \t=HYPERLINK(\"https://evil\")", "\u0000@payload"]) {
    assert.ok(csvCell(value).startsWith("\"'"));
  }
  assert.equal(csvCell('safe "quoted" value'), '"safe ""quoted"" value"');
});

test("strictly validates signed release envelopes and approved download hosts", () => {
  const now = new Date("2026-08-11T12:00:00Z");
  const manifest = { schemaVersion: 1 as const, version: "2.0.0", sequence: 20, downloadUrl: "https://downloads.example.test/Scopeproof-Capture.zip", sha256: "a".repeat(64), byteSize: 1024, publishedAt: "2026-08-11T11:00:00.000Z", expiresAt: "2026-09-01T12:00:00.000Z", minimumSystemVersion: "14.0", teamIdentifier: "ABCDE12345", designatedRequirement: 'identifier "com.scopeproof.capture" and anchor apple generic', keyId: "release-2026", notes: "Security release" };
  const env = { MACOS_RELEASE_MANIFEST_JSON: JSON.stringify(manifest), MACOS_RELEASE_SIGNATURE_DER_BASE64: "A".repeat(96), MACOS_RELEASE_ALLOWED_HOSTS: "downloads.example.test" } as ScopeproofEnv;
  assert.deepEqual(configuredMacRelease(env, now).manifest, manifest);
  assert.match(releaseSigningPayload(manifest), /^scopeproof-update-manifest-v1\n1\n2\.0\.0\n20\n/);
  assert.throws(() => configuredMacRelease({ ...env, MACOS_RELEASE_ALLOWED_HOSTS: "other.example.test" }, now));
});

test("production hardening bounds abuse, claims jobs atomically, and enforces retention", async () => {
  const [rateLimit, jobs, collectors, outbound, retention, evidence, packages, migration, backend, updater, releaseRoute] = await Promise.all([
    readFile(new URL("../lib/server/rate-limit.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/jobs.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/collectors.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/outbound.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/retention.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/evidence.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/packages.ts", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0009_chubby_martin_li.sql", import.meta.url), "utf8"),
    readFile(new URL("../macos/ScopeproofCapture/Sources/ScopeproofCapture/BackendTrust.swift", import.meta.url), "utf8"),
    readFile(new URL("../macos/ScopeproofCapture/Sources/ScopeproofCapture/UpdateService.swift", import.meta.url), "utf8"),
    readFile(new URL("../app/api/native/releases/latest/route.ts", import.meta.url), "utf8"),
  ]);
  assert.match(rateLimit, /principal:/); assert.match(rateLimit, /address:/); assert.match(rateLimit, /Content-Length header is required/);
  assert.match(jobs, /lease_id = \?/); assert.match(jobs, /LEASE_LOST/); assert.match(jobs, /lease_expires_at < \?/);
  assert.match(collectors, /AbortSignal\.timeout\(60_000\)/); assert.match(collectors, /PROVIDER_RESPONSE_TOO_LARGE/); assert.match(collectors, /redirect: "error"/);
  assert.match(outbound, /allowedOrigins/); assert.match(outbound, /maximumBytes/); assert.match(outbound, /redirect: "error"/);
  assert.match(retention, /retention\.purge_started/); assert.match(retention, /evidence\.purged/); assert.match(retention, /retention_holds/);
  assert.match(evidence, /This evidence has expired/); assert.match(evidence, /Expired evidence cannot be approved/);
  assert.match(packages, /status = 'approved' AND expires_at > \?/); assert.match(packages, /csvCell/);
  for (const table of ["rate_limit_buckets", "retention_holds"]) assert.ok(migration.includes(`CREATE TABLE \`${table}\``));
  assert.match(backend, /productionOrigins/); assert.match(backend, /completionHandler\(nil\)/); assert.match(backend, /sameOrigin/);
  assert.match(updater, /isValidSignature/); assert.match(updater, /codesign/); assert.match(updater, /TeamIdentifier/); assert.match(updater, /stapler/); assert.match(updater, /highestUpdateSequence/);
  assert.match(releaseRoute, /configuredMacRelease/);
});

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

test("screenshot pipelines scan the exact persisted pixels and fail closed", async () => {
  const [capture, scanner, sourceUrl, collectors, evidence, nativeRoute, migration] = await Promise.all([
    readFile(new URL("../macos/ScopeproofCapture/Sources/ScopeproofCapture/CaptureService.swift", import.meta.url), "utf8"),
    readFile(new URL("../macos/ScopeproofCapture/Sources/ScopeproofCapture/SensitiveDataScanner.swift", import.meta.url), "utf8"),
    readFile(new URL("../macos/ScopeproofCapture/Sources/ScopeproofCapture/EvidenceSourceURL.swift", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/collectors.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/evidence.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/native/evidence/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../drizzle/0008_real_nebula.sql", import.meta.url), "utf8"),
  ]);
  assert.doesNotMatch(capture, /scopeproof-(?:window|display)-/);
  assert.match(capture, /let imageData = try pngData\(review\.image\)/);
  assert.match(capture, /let exactScan = try requiredSafetyScan\(exactImage\)/);
  assert.ok(capture.indexOf("let exactScan") < capture.indexOf("imageData.write(to: imageURL"));
  assert.match(capture, /safetyScanSha256: digest/);
  assert.match(capture, /LIVE MAC MENU BAR PIXELS INCLUDED/);
  assert.match(capture, /menuBarFormatter\.string\(from: now\)/);
  assert.match(capture, /liveMenuBarImage/);
  assert.match(capture, /configuration\.sourceRect = sourceRect/);
  assert.match(capture, /displayBounds\.width - sourceWidth/);
  assert.match(capture, /evidenceImageWithMenuBar/);
  assert.match(capture, /captureDate: pixels\.capturedAt/);
  assert.match(capture, /let liveMenuBar = try await liveMenuBarPixels/);
  assert.ok(capture.indexOf("let composite = try scrollingComposite") < capture.indexOf("let liveMenuBar = try await liveMenuBarPixels"));
  assert.match(capture, /FULL URL/);
  assert.match(sourceUrl, /components\.user = nil/);
  assert.match(sourceUrl, /components\.password = nil/);
  assert.match(sourceUrl, /value: "REDACTED"/);
  assert.match(scanner, /vision-ocr-sensitive-patterns-v1/);
  assert.doesNotMatch(collectors, /\/content`/);
  assert.match(collectors, /scanExactBrowserPixels/);
  assert.match(collectors, /result\.sha256 !== digest/);
  assert.match(collectors, /BROWSER_OCR_ALLOWED_HOSTS/);
  assert.match(evidence, /Safety scan digest does not match the evidence artifact/);
  assert.match(nativeRoute, /manifest\.safetyScanSha256 !== imageDigest/);
  for (const column of ["safety_scan_sha256", "safety_scan_policy", "safety_scan_completed_at"]) assert.ok(migration.includes(column));
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
  assert.match(jiraSource, /assertPermission\(actor, "manage_jira"\)/);
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

test("identity bootstrap and independent approval fail closed", async () => {
  const [migration, auth, evidence, route, config, consoleSource] = await Promise.all([
    readFile(new URL("../drizzle/0007_greedy_nextwave.sql", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/auth.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/evidence.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/evidence/[id]/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../next.config.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/evidence-console.tsx", import.meta.url), "utf8"),
  ]);
  assert.match(migration, /CREATE TABLE `security_invariants`/);
  assert.match(migration, /security_invariants_no_update/);
  assert.match(migration, /users_preserve_last_admin/);
  assert.match(migration, /users_preserve_last_admin_delete/);
  assert.match(auth, /Administrator bootstrap allowlist is not safely configured/);
  assert.match(auth, /NOT EXISTS \(SELECT 1 FROM security_invariants WHERE key = 'admin_bootstrap'\)/);
  assert.match(auth, /user\.bootstrap_admin_granted/);
  assert.match(auth, /TRUSTED_APP_ORIGINS/);
  assert.match(auth, /This origin is not authorized for Scopeproof identity headers/);
  assert.match(auth, /Same-origin mutation proof is required/);
  assert.match(evidence, /Collectors and uploaders cannot approve their own evidence/);
  assert.match(evidence, /created_by != \?/);
  assert.match(route, /confirmedActualArtifact/);
  assert.match(route, /x-scopeproof-sha256/);
  assert.match(config, /frame-ancestors 'none'/);
  assert.match(config, /X-Frame-Options/);
  assert.match(consoleSource, /Independent review attestation/);
  assert.match(consoleSource, /actual decrypted, digest-verified artifact|Decrypting and verifying the actual artifact/);
});

test("security mutations are atomic with audit events and timestamps require pinned verification", async () => {
  const [audit, evidence, devices, jobs, jira, users, collectors, packages, timestamp, lifecycle, exporter, keychain] = await Promise.all([
    readFile(new URL("../lib/server/audit.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/evidence.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/devices.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/jobs.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/jira.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/users/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/collectors/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/packages.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/server/timestamp.ts", import.meta.url), "utf8"),
    readFile(new URL("../macos/ScopeproofCapture/Sources/ScopeproofCapture/EvidenceLifecycle.swift", import.meta.url), "utf8"),
    readFile(new URL("../macos/ScopeproofCapture/Sources/ScopeproofCapture/AssessorPackageExporter.swift", import.meta.url), "utf8"),
    readFile(new URL("../macos/ScopeproofCapture/Sources/ScopeproofCapture/KeychainStore.swift", import.meta.url), "utf8"),
  ]);
  assert.match(audit, /executeAuditedBatch/);
  assert.match(audit, /env\.DB\.batch\(\[/);
  assert.match(audit, /scopeproof_audited_batch_failure/);
  for (const source of [evidence, devices, jobs, jira, users, collectors, packages]) assert.match(source, /executeAuditedBatch/);
  assert.doesNotMatch(jira, /await appendAuditEvent/);
  assert.match(timestamp, /verification\.nonceHex !== request\.nonceHex/);
  assert.match(timestamp, /verification\.digestSha256 !== digestSha256/);
  assert.match(timestamp, /verification\.tokenSha256 !== tokenSha256/);
  assert.match(timestamp, /tsaExtendedKeyUsage/);
  assert.match(timestamp, /revocationStatus/);
  assert.match(timestamp, /RFC3161_TSA_TRUST_ANCHOR_SHA256/);
  assert.match(timestamp, /crypto\.subtle\.verify/);
  assert.doesNotMatch(lifecycle, /var status: EvidenceReviewStatus\s*=/);
  assert.match(lifecycle, /var status: EvidenceReviewStatus \{ events\.last\?\.status/);
  assert.match(lifecycle, /artifactSha256/);
  assert.match(lifecycle, /policyVersion/);
  assert.match(exporter, /verify\(entry\.lifecycle, artifactSha256:/);
  assert.match(keychain, /SecAccessControlCreateWithFlags/);
  assert.match(keychain, /userPresence/);
});
