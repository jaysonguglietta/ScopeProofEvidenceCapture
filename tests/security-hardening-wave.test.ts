import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("legacy membership is invitation-only after one explicit bootstrap", async () => {
  const [auth, users, migration] = await Promise.all([
    read("lib/server/auth.ts"),
    read("app/api/users/route.ts"),
    read("drizzle/0014_loving_plazm.sql"),
  ]);
  assert.match(auth, /An active Scopeproof invitation is required/);
  assert.match(auth, /security_invariants WHERE key = 'admin_bootstrap'/);
  assert.match(auth, /user\.invitation_accepted/);
  assert.match(auth, /status !== "active"/);
  assert.match(users, /user\.invited/);
  assert.match(users, /user\.membership_changed/);
  assert.match(users, /final administrator cannot be demoted/);
  assert.match(migration, /WHERE "user_invitations"\."status" = 'pending'/);
});

test("legacy identity headers are confined to one acknowledged canonical origin", async () => {
  const [auth, identityConfig, readiness, example] = await Promise.all([
    read("lib/server/auth.ts"),
    read("lib/server/identity-config.ts"),
    read("lib/server/readiness.ts"),
    read(".env.example"),
  ]);
  assert.match(identityConfig, /values\.length !== 1/);
  assert.match(auth, /LEGACY_SINGLE_TENANT_ACKNOWLEDGEMENT !== "single-tenant-only"/);
  assert.match(readiness, /single_tenant_boundary/);
  assert.match(example, /LEGACY_SINGLE_TENANT_ACKNOWLEDGEMENT=single-tenant-only/);
});

test("deduplicated bytes retain auditable collection occurrences", async () => {
  const [schema, migration, evidence] = await Promise.all([
    read("db/schema.ts"),
    read("drizzle/0013_light_toad_men.sql"),
    read("lib/server/evidence.ts"),
  ]);
  assert.match(schema, /evidenceOccurrences/);
  assert.match(migration, /CREATE TABLE `evidence_occurrences`/);
  assert.match(evidence, /evidence\.occurrence_recorded/);
  assert.match(evidence, /INSERT OR IGNORE INTO evidence_occurrences/);
  assert.match(evidence, /occurrence_count/);
  assert.match(evidence, /last_observed_at/);
  assert.match(evidence, /assessment_id IS \?/);
  assert.match(evidence, /stableJson\(\{ artifactId, replayKey \}\)/);
  assert.match(evidence, /exactOccurrenceReplay/);
  assert.match(evidence, /audit\.action = 'evidence\.occurrence_recorded'/);
  assert.ok(
    evidence.indexOf("if (exactOccurrenceReplay)") < evidence.indexOf("executeAuditedBatch(input.createdBy, \"evidence.occurrence_recorded\""),
    "an exact committed retry must return before any freshness or audit mutation",
  );
  assert.doesNotMatch(evidence, /return storeEvidence\(input\)/);
  assert.match(schema, /idx_evidence_dedupe_nnn/);
  assert.match(schema, /idx_evidence_dedupe_aep/);
});

test("expired invitations can be replaced and device expiry uses normalized timestamps", async () => {
  const [users, devices] = await Promise.all([read("app/api/users/route.ts"), read("lib/server/devices.ts")]);
  assert.match(users, /SET status = 'expired'.*status = 'pending'.*expires_at <= \?/);
  assert.match(devices, /unixepoch\(token_expires_at\) <= unixepoch\('now'\)/);
});

test("native Jira disclosure compares evidence expiry using canonical ISO timestamps", async () => {
  const route = await read("app/api/native/jira/upload/route.ts");
  assert.match(route, /e\.expires_at > \?/);
  assert.match(route, /actor\.id, new Date\(\)\.toISOString\(\)/);
  assert.doesNotMatch(route, /actor\.id, Date\.now\(\)/);
});

test("queued collectors and SBOM retries re-authorize their requester", async () => {
  const [jobs, sbom] = await Promise.all([read("lib/server/jobs.ts"), read("lib/server/sbom.ts")]);
  assert.match(jobs, /loadActiveUser/);
  assert.match(jobs, /AUTHORIZATION_REVOKED/);
  assert.match(jobs, /assertPermission\(current, "collect_evidence"\)/);
  assert.match(sbom, /loadActiveUser/);
  assert.match(sbom, /assertPermission\(currentActor, "generate_sbom"\)/);
  assert.match(sbom, /sbom\.authorization_revoked/);
});

test("checkpoint verification uses the configured key, actual audit anchor, and independent delivery", async () => {
  const [checkpoint, readiness] = await Promise.all([read("lib/server/checkpoints.ts"), read("lib/server/readiness.ts")]);
  assert.match(checkpoint, /checkpoint_not_independently_delivered/);
  assert.match(checkpoint, /checkpoint_audit_anchor_mismatch/);
  assert.match(checkpoint, /PACKAGE_SIGNING_PUBLIC_KEY/);
  assert.match(checkpoint, /untrusted_checkpoint_signing_key/);
  assert.match(checkpoint, /validateAuditCheckpointConfiguration/);
  assert.match(readiness, /independent_checkpoint_boundary/);
});

test("native evidence stays quarantined until its immutable signed chain link is finalized", async () => {
  const [evidence, devices, packages, jira, migration] = await Promise.all([
    read("lib/server/evidence.ts"),
    read("lib/server/devices.ts"),
    read("lib/server/packages.ts"),
    read("app/api/native/jira/upload/route.ts"),
    read("drizzle/0022_native_provenance_quarantine.sql"),
  ]);
  for (const source of [evidence, packages, jira]) {
    assert.match(source, /n\.chain_sequence IS NOT NULL AND n\.chain_sequence > 0/);
    assert.match(source, /d\.provenance_key_id = n\.provenance_key_id/);
    assert.match(source, /d\.chain_sequence >= n\.chain_sequence/);
  }
  assert.match(evidence, /Native provenance finalization is pending/);
  assert.match(evidence, /Unapproved native evidence is restricted to authorized internal reviewers/);
  assert.match(packages, /signed device-chain link is not finalized/);
  assert.match(devices, /chain_sequence, chain_event_hash, provenance_key_id/);
  assert.match(devices, /n\.chain_sequence = \?/);
  assert.match(migration, /idx_native_manifest_device_sequence/);
  assert.match(migration, /native_evidence_manifests_no_update/);
  assert.match(migration, /native_evidence_manifests_no_delete/);
});

test("trusted timestamps are mandatory for production readiness", async () => {
  const [readiness, nativeUpload] = await Promise.all([
    read("lib/server/readiness.ts"),
    read("app/api/native/evidence/route.ts"),
  ]);
  assert.match(readiness, /trusted_timestamp_policy[\s\S]*status: timestampFlagValid && timestampRequired \? "pass" : "fail"/);
  assert.match(readiness, /production readiness cannot be asserted/);
  assert.match(readiness, /trusted_timestamp[\s\S]*timestampConfigured && timestampConfiguration \? "pass" : "fail"/);
  assert.match(readiness, /validateTrustedTimestampConfiguration\(env\)/);
  for (const setting of ["RFC3161_TSA_URL", "RFC3161_VERIFIER_URL", "RFC3161_VERIFIER_TOKEN", "RFC3161_VERIFIER_ALLOWED_HOSTS", "RFC3161_TSA_TRUST_ANCHOR_SHA256", "RFC3161_VERIFIER_PUBLIC_KEYS"]) {
    assert.match(readiness, new RegExp(`timestampConfigured[\\s\\S]*env\\.${setting}`));
  }
  assert.match(nativeUpload, /Independent trusted timestamping is required and currently unavailable\. The capture was not stored/);
});

test("hosted screenshots require an independent server safety receipt before persistence or disclosure", async () => {
  const [scanner, nativeUpload, evidence, packages, jira, readiness, migration] = await Promise.all([
    read("lib/server/image-safety.ts"),
    read("app/api/native/evidence/route.ts"),
    read("lib/server/evidence.ts"),
    read("lib/server/packages.ts"),
    read("app/api/native/jira/upload/route.ts"),
    read("lib/server/readiness.ts"),
    read("drizzle/0023_independent_image_safety.sql"),
  ]);
  assert.match(scanner, /scanExactEvidencePixels/);
  assert.match(scanner, /result\.sha256 !== digest/);
  assert.match(scanner, /SENSITIVE_CONTENT/);
  assert.match(scanner, /redirect: "error"|boundedFetch/);
  assert.match(nativeUpload, /scanExactEvidencePixels\(image, getEnv\(\)\)/);
  assert.match(nativeUpload, /serverSafetyScan/);
  assert.match(evidence, /Screenshot evidence requires an independent digest-bound server safety receipt/);
  assert.match(evidence, /await evidenceSafetyReceiptSha256\(receiptFields\)/);
  assert.match(evidence, /row\.type === "screenshot"/);
  assert.match(evidence, /e\.type != 'screenshot' OR/);
  assert.match(evidence, /server_safety_scan_sha256 = e\.sha256/);
  assert.match(packages, /pending_safety/);
  assert.match(packages, /e\.type != 'screenshot' OR/);
  assert.match(packages, /e\.server_safety_scan_sha256 = e\.sha256/);
  assert.match(jira, /await evidenceSafetyReceiptSha256/);
  assert.match(jira, /hostedSafetyReceipt !== hosted\.server_safety_receipt_sha256/);
  assert.match(readiness, /independent_image_safety/);
  for (const column of ["server_safety_scan_sha256", "server_safety_scan_policy", "server_safety_scan_completed_at", "server_safety_scanner_origin", "server_safety_receipt_sha256"]) assert.match(migration, new RegExp(column));
});

test("provider pagination cannot forward credentials cross-origin and AWS requires STS", async () => {
  const collectors = await read("lib/server/collectors.ts");
  assert.match(collectors, /candidate\.origin !== allowedOrigin/);
  assert.match(collectors, /UNSAFE_PROVIDER_PAGINATION/);
  assert.match(collectors, /configured\(env\.AWS_SESSION_TOKEN, "AWS_SESSION_TOKEN"\)/);
  assert.doesNotMatch(collectors, /returned \$\{bounded\.status\}: \$\{text\}/);
});

test("active assessments and explicit holds prevent physical evidence purge", async () => {
  const retention = await read("lib/server/retention.ts");
  const evidence = await read("lib/server/evidence.ts");
  assert.match(retention, /a\.status IN \('draft', 'active'\)/);
  assert.match(evidence, /UNION ALL SELECT 1 FROM assessments/);
  assert.match(evidence, /Evidence capture time is too far in the future/);
});

test("retention hold creation is conditionally committed against live evidence state", async () => {
  const route = await read("app/api/evidence/[id]/retention/route.ts");
  assert.match(route, /INSERT INTO retention_holds[\s\S]*SELECT \?, \?, \?, \? WHERE EXISTS/);
  assert.match(route, /status NOT IN \('expired', 'purged'\) AND expires_at > \?/);
  assert.match(route, /if \(!result\.meta\.changes\)[\s\S]*became non-retainable/);
});

test("operator UI exposes real invitations, device rotation, occurrences, and audit events", async () => {
  const consoleSource = await read("app/evidence-console.tsx");
  assert.match(consoleSource, /Create invitation/);
  assert.match(consoleSource, /Device token rotated/);
  assert.match(consoleSource, /collection occurrence/);
  assert.match(consoleSource, /newest 250 material actions/i);
  assert.doesNotMatch(consoleSource, /Reviewer notifications/);
  assert.doesNotMatch(consoleSource, /Default evidence validity[\s\S]{0,100}<select/);
});
