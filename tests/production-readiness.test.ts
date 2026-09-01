import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import {
  PACKAGE_ELIGIBILITY_COUNTS_SQL,
  PACKAGE_ELIGIBILITY_PUBLISH_FENCE_SQL,
  packageEligibilityBindings,
  packageEligibilityPublishFenceBindings,
} from "../lib/server/package-eligibility.ts";
import { parseGitHubRepositoryUrl, validateOneTimeGitHubToken } from "../lib/server/sbom-input.ts";
import { decodeXmlText } from "../lib/server/xml.ts";

const read = (path: string) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("AWS pagination token XML decoding is single-pass", () => {
  assert.equal(decodeXmlText("a&amp;b&lt;c&#x2f;d"), "a&b<c/d");
  assert.equal(decodeXmlText("&amp;lt;script&amp;gt;"), "&lt;script&gt;");
});

test("production console fails closed without demo compliance claims", async () => {
  const consoleSource = await read("app/evidence-console.tsx");
  assert.doesNotMatch(consoleSource, /seedEvidence|seedRuns|requirementCoverage|findings\s*[,}]/);
  assert.match(consoleSource, /Authoritative data is hidden/);
  assert.match(consoleSource, /setEvidenceItems\(\[\]\)/);
  assert.match(consoleSource, /setRunItems\(\[\]\)/);
});

test("collectors paginate and persist explicit coverage provenance", async () => {
  const collectors = await read("lib/server/collectors.ts");
  const jobs = await read("lib/server/jobs.ts");
  const evidence = await read("lib/server/evidence.ts");
  assert.match(collectors, /collectLinkedJson/);
  assert.match(collectors, /MAX_PROVIDER_PAGES/);
  assert.match(collectors, /coverage\("github"/);
  assert.match(collectors, /coverage\("okta"/);
  assert.match(collectors, /coverage\("cloudflare"/);
  assert.match(collectors, /coverage\("aws"/);
  assert.match(jobs, /coverage_status = \?/);
  assert.match(evidence, /Partial collector evidence cannot be approved/);
  assert.match(collectors, /page\.length > remaining/);
  assert.match(collectors, /!next && !truncatedWithinPage/);
});

test("assessment boundaries survive deduplication, UI selection, and lifecycle changes", async () => {
  const evidence = await read("lib/server/evidence.ts");
  const consoleSource = await read("app/evidence-console.tsx");
  const assessments = await read("lib/server/assessments.ts");
  const migration = await read("drizzle/0010_tearful_goblin_queen.sql");
  assert.match(evidence, /control_id = \? AND framework = \? AND system = \? AND environment IS \? AND assessment_period IS \? AND assessment_id IS \?/);
  assert.match(migration, /idx_evidence_sha_source_control_assessment/);
  assert.match(consoleSource, /item\.assessmentId === selectedAssessmentId/);
  assert.match(consoleSource, /method: "PATCH"/);
  assert.match(assessments, /assessment\.scope_narrowed/);
  assert.match(assessments, /Closed assessments are immutable/);
});

test("package preflight and build share one eligibility policy", async () => {
  const packages = await read("lib/server/packages.ts");
  assert.equal(packages.match(/packageEligibilityCounts\(assessmentId,/g)?.length, 2);
});

test("only a newer usable complete recollection clears a partial-coverage blocker", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE evidence_artifacts (
    id TEXT PRIMARY KEY, assessment_id TEXT NOT NULL, control_id TEXT NOT NULL, source TEXT NOT NULL, system TEXT NOT NULL,
    framework TEXT NOT NULL DEFAULT 'PCI DSS 4.0.1', environment TEXT DEFAULT 'production',
    assessment_period TEXT DEFAULT '2026', collector_id TEXT DEFAULT 'collector-a',
    coverage_status TEXT NOT NULL, captured_at TEXT NOT NULL, status TEXT NOT NULL, expires_at TEXT NOT NULL,
    type TEXT NOT NULL DEFAULT 'report', sha256 TEXT NOT NULL DEFAULT 'digest', device_id TEXT, manifest_sha256 TEXT,
    chain_event_hash TEXT, server_safety_scan_sha256 TEXT, server_safety_scan_policy TEXT,
    server_safety_scan_completed_at TEXT, server_safety_scanner_origin TEXT, server_safety_receipt_sha256 TEXT
  );
  CREATE TABLE evidence_occurrences (
    id TEXT PRIMARY KEY, artifact_id TEXT NOT NULL, captured_at TEXT NOT NULL, received_at TEXT NOT NULL,
    expires_at TEXT NOT NULL, status TEXT NOT NULL, coverage_status TEXT NOT NULL
  );
  CREATE TABLE native_evidence_manifests (artifact_id TEXT, device_id TEXT, image_sha256 TEXT, manifest_sha256 TEXT, chain_sequence INTEGER, chain_event_hash TEXT, provenance_key_id TEXT);
  CREATE TABLE capture_devices (id TEXT PRIMARY KEY, provenance_key_id TEXT, chain_sequence INTEGER);`);
  const insertArtifactRow = db.prepare(`INSERT INTO evidence_artifacts
    (id, assessment_id, control_id, source, system, coverage_status, captured_at, status, expires_at)
    VALUES (?, ?, '6.3.2', 'github', 'production', ?, ?, ?, ?)`);
  const insertOccurrence = db.prepare(`INSERT INTO evidence_occurrences
    (id, artifact_id, captured_at, received_at, expires_at, status, coverage_status)
    VALUES (?, ?, ?, ?, ?, ?, ?)`);
  const future = "2030-01-01T00:00:00.000Z";
  const past = "2020-01-01T00:00:00.000Z";
  const at = "2026-09-01T00:00:00.000Z";
  const insert = (id: string, assessment: string, coverage: string, occurrenceCapturedAt: string, status: string, expiresAt: string, artifactCapturedAt = occurrenceCapturedAt) => {
    insertArtifactRow.run(id, assessment, coverage, artifactCapturedAt, status, expiresAt);
    insertOccurrence.run(`${id}_occurrence`, id, occurrenceCapturedAt, occurrenceCapturedAt, expiresAt, status, coverage);
  };
  const addPartial = (assessment: string, capturedAt = "2026-01-01T00:00:00.000Z") => insert(`${assessment}_partial`, assessment, "partial", capturedAt, "needs_review", future);
  addPartial("asm_replaced");
  insert("complete", "asm_replaced", "complete", "2026-02-01T00:00:00.000Z", "approved", future);
  for (const status of ["needs_review", "rejected", "returned", "superseded"] as const) {
    const assessment = `asm_${status}`;
    addPartial(assessment);
    insert(`${assessment}_replacement`, assessment, "complete", "2026-02-01T00:00:00.000Z", status, future);
  }
  addPartial("asm_expiring");
  insert("asm_expiring_replacement", "asm_expiring", "complete", "2026-02-01T00:00:00.000Z", "needs_review", future);
  db.prepare("UPDATE evidence_artifacts SET status = 'expiring' WHERE id = 'asm_expiring_replacement'").run();
  addPartial("asm_expired");
  insert("expired_replacement", "asm_expired", "complete", "2026-02-01T00:00:00.000Z", "approved", past);
  addPartial("asm_unreplaced");
  addPartial("asm_unscanned");
  insert("unscanned_replacement", "asm_unscanned", "complete", "2026-02-01T00:00:00.000Z", "approved", future);
  db.prepare("UPDATE evidence_artifacts SET type = 'screenshot' WHERE id = 'unscanned_replacement'").run();
  addPartial("asm_unproven");
  insert("unproven_replacement", "asm_unproven", "complete", "2026-02-01T00:00:00.000Z", "approved", future);
  db.prepare("UPDATE evidence_artifacts SET device_id = 'device-a', manifest_sha256 = 'manifest', chain_event_hash = 'chain' WHERE id = 'unproven_replacement'").run();
  for (const [column, value] of [["environment", "staging"], ["assessment_period", "2027"], ["collector_id", "collector-b"]] as const) {
    const assessment = `asm_mismatch_${column}`;
    addPartial(assessment);
    const replacementId = `${assessment}_replacement`;
    insert(replacementId, assessment, "complete", "2026-02-01T00:00:00.000Z", "approved", future);
    db.prepare(`UPDATE evidence_artifacts SET ${column} = ? WHERE id = ?`).run(value, replacementId);
  }
  addPartial("asm_occurrence_recency", "2026-02-01T00:00:00.000Z");
  insert("occurrence_replacement", "asm_occurrence_recency", "complete", "2026-03-01T00:00:00.000Z", "approved", future, "2025-01-01T00:00:00.000Z");
  const counts = (assessment: string) => db.prepare(PACKAGE_ELIGIBILITY_COUNTS_SQL)
    .get(...packageEligibilityBindings(assessment, at)) as { total: number; partial: number; eligible: number; pending_safety: number; pending_native: number };
  const replaced = counts("asm_replaced") as { total: number; eligible: number; pending_safety: number; pending_native: number; partial: number };
  assert.equal(replaced.total, 2);
  assert.equal(replaced.eligible, 1);
  assert.equal(replaced.pending_safety, 0);
  assert.equal(replaced.pending_native, 0);
  assert.equal(replaced.partial, 0);
  for (const assessment of ["asm_needs_review", "asm_expiring", "asm_rejected", "asm_returned", "asm_superseded", "asm_expired", "asm_unreplaced", "asm_unscanned", "asm_unproven", "asm_mismatch_environment", "asm_mismatch_assessment_period", "asm_mismatch_collector_id"]) {
    assert.equal(counts(assessment).partial, 1, assessment);
  }
  assert.equal(counts("asm_unscanned").pending_safety, 1);
  assert.equal(counts("asm_unproven").pending_native, 1);
  assert.equal(counts("asm_occurrence_recency").partial, 0, "latest occurrence time, not the deduplicated artifact's original capture time, controls recollection recency");

  const publishFence = (assessment: string, total: number, eligible: number) => Number((db.prepare(`SELECT ${PACKAGE_ELIGIBILITY_PUBLISH_FENCE_SQL} AS allowed`)
    .get(...packageEligibilityPublishFenceBindings(assessment, at, total, eligible) as Array<string | number>) as { allowed: number }).allowed);
  assert.equal(publishFence("asm_replaced", replaced.total, replaced.eligible), 1);
  db.prepare("UPDATE evidence_occurrences SET status = 'needs_review' WHERE artifact_id = 'complete'").run();
  assert.equal(publishFence("asm_replaced", replaced.total, replaced.eligible), 0, "a post-selection eligibility change must fail the final publication fence");
  db.close();
});

test("assessor exports are assessment-scoped and never silently truncated", async () => {
  const packages = await read("lib/server/packages.ts");
  const migration = await read("drizzle/0010_tearful_goblin_queen.sql");
  assert.match(packages, /WHERE e\.assessment_id = \?/);
  assert.match(packages, /truncation: "forbidden"/);
  assert.match(packages, /exceeding the 100-artifact package limit/);
  assert.doesNotMatch(packages, /assessment_id = \?[\s\S]{0,200}LIMIT 100/);
  assert.match(migration, /CREATE TABLE `assessments`/);
  assert.match(migration, /`coverage_status`/);
  assert.match(migration, /`selection_json`/);
});

test("encrypted and signed records retain versioned key identifiers", async () => {
  const cryptoSource = await read("lib/server/crypto.ts");
  const evidence = await read("lib/server/evidence.ts");
  const jira = await read("lib/server/jira.ts");
  const migration = await read("drizzle/0011_easy_vision.sql");
  assert.match(cryptoSource, /active key .* is not present in the retained keyring/);
  assert.match(evidence, /encryption_key_id/);
  assert.match(jira, /token_key_id = excluded\.token_key_id/);
  assert.match(jira, /hmac_key_id\) VALUES/);
  assert.match(migration, /`encryption_key_id`/);
  assert.match(migration, /`hmac_key_id`/);
  assert.match(migration, /`token_key_id`/);
});

test("key rotation uses copy-switch-delete and refuses missing retained keys", async () => {
  const operations = await read("lib/server/key-operations.ts");
  assert.match(operations, /\.rekey-/);
  assert.match(operations, /executeAuditedBatch\(actor, "key\.evidence_rotated"/);
  assert.match(operations, /EVIDENCE_BUCKET\.delete\(row\.r2_key\)/);
  assert.match(operations, /validateRetainedKeyReferences/);
  assert.match(operations, /Jira OAuth token key .* is unavailable during rotation/);
});

test("maintenance failures are isolated and poisoned rotations durably back off", async () => {
  const [jobs, operations, migration] = await Promise.all([
    read("lib/server/jobs.ts"),
    read("lib/server/key-operations.ts"),
    read("drizzle/0026_omniscient_scarlet_witch.sql"),
  ]);
  assert.match(jobs, /const isolate = async/);
  for (const stage of ["evidence_retention", "rate_limit_retention", "collection_retries", "sbom_jobs", "scheduled_collectors", "key_rotation", "audit_checkpoint", "operational_health"]) {
    assert.match(jobs, new RegExp(`isolate\\("${stage}"`));
  }
  assert.ok(jobs.indexOf('isolate("audit_checkpoint"') < jobs.indexOf('isolate("operational_health"'));
  assert.match(jobs, /isolatedFailures \+= 1/);
  assert.match(jobs, /throw new AggregateError\(\[\]/);
  assert.ok(jobs.indexOf('isolate("operational_health"') < jobs.indexOf("throw new AggregateError"));
  assert.match(operations, /rotateIsolated/);
  assert.match(operations, /ROTATION_ACTION_REQUIRED_AFTER = 5/);
  assert.match(operations, /key\.rotation_retry_scheduled/);
  assert.match(operations, /key\.rotation_action_required/);
  assert.match(operations, /key\.rotation_recovered/);
  assert.match(operations, /NOT EXISTS \(SELECT 1 FROM key_rotation_attempts/);
  assert.match(operations, /authoritativeObjectRotationDisposition/);
  assert.match(operations, /jiraRotationReachedActiveState/);
  assert.match(operations, /keyRotationRetrySummary/);
  assert.match(migration, /PRIMARY KEY\(`resource_type`, `resource_id`\)/);
  assert.match(migration, /key_rotation_attempt_state_shape/);
  assert.match(migration, /key_rotation_resource_type_allowlist/);
  assert.match(migration, /key_rotation_error_code_allowlist/);
});

test("audit checkpoints are independently signed, stored, and host allowlisted", async () => {
  const checkpoints = await read("lib/server/checkpoints.ts");
  const trustConfiguration = await read("lib/server/external-trust-config.ts");
  const jobs = await read("lib/server/jobs.ts");
  assert.match(checkpoints, /signPackage\(canonical\)/);
  assert.match(checkpoints, /audit-checkpoints\/\$\{month\}/);
  assert.match(trustConfiguration, /AUDIT_CHECKPOINT_ALLOWED_HOSTS/);
  assert.match(trustConfiguration, /AUDIT_CHECKPOINT_TOKEN is malformed/);
  assert.match(checkpoints, /allowedOrigins: \[url\.origin\]/);
  assert.match(jobs, /createAuditCheckpoint\(now\)/);
});

test("release and operations controls are executable and fail closed", async () => {
  const workflow = await read(".github/workflows/security.yml");
  const productionRelease = await read(".github/workflows/macos-production-release.yml");
  const monitoring = await read("lib/server/monitoring.ts");
  const trustConfiguration = await read("lib/server/external-trust-config.ts");
  const operations = await read("docs/PRODUCTION_OPERATIONS.md");
  assert.doesNotMatch(workflow, /uses: actions\/(checkout|setup-node|upload-artifact)@v\d/);
  assert.match(workflow, /working-directory: macos\/ScopeproofCapture/);
  assert.match(workflow, /verify_migrations\.sh/);
  assert.doesNotMatch(workflow, /attestations:\s*write|id-token:\s*write/);
  assert.match(productionRelease, /actions\/attest@[a-f0-9]{40}/);
  assert.match(productionRelease, /environment: production-release/);
  assert.match(trustConfiguration, /SECURITY_EVENT_ALLOWED_HOSTS/);
  assert.match(trustConfiguration, /SECURITY_EVENT_TOKEN is missing or malformed/);
  assert.match(monitoring, /x-scopeproof-signature/);
  assert.match(operations, /Quarterly recovery drill/);
  assert.match(operations, /single-tenant/);
  assert.match(operations, /Launch authorization checklist/);
});

test("repository SBOM generation is immutable, non-executing, bounded, and assessment scoped", async () => {
  const sbom = await read("lib/server/sbom.ts");
  const route = await read("app/api/sboms/route.ts");
  const jobs = await read("lib/server/jobs.ts");
  const migration = await read("drizzle/0012_opposite_rachel_grey.sql");
  assert.match(sbom, /commits\/\$\{encodeURIComponent\(String\(job\.requested_ref\)\)\}/);
  assert.match(sbom, /zipball\/\$\{commit\}/);
  assert.match(sbom, /\["api\.github\.com", "codeload\.github\.com"\]/);
  assert.match(sbom, /MAX_ARCHIVE_BYTES = 20 \* 1024 \* 1024/);
  assert.match(sbom, /MAX_ARCHIVE_ENTRIES = 5_000/);
  assert.match(sbom, /MAX_COMPONENTS = 5_000/);
  assert.match(sbom, /unzipSync\(bytes, \{ filter:/);
  assert.match(sbom, /controlId: "6\.3\.2"/);
  assert.match(sbom, /coverageStatus: "complete"/);
  assert.doesNotMatch(sbom, /child_process|execSync|spawnSync|npm install|yarn install|pnpm install/);
  assert.match(route, /requireApiPermission\(request, "generate_sbom"\)/);
  assert.match(route, /enforceRateLimit\(request, user\.id, "sbom:generate", 10, 3_600\)/);
  assert.match(jobs, /processDueSbomWork\(now\)/);
  assert.match(migration, /CREATE TABLE `sbom_jobs`/);
  assert.match(migration, /`resolved_commit_sha` text/);
  assert.match(migration, /`source_archive_sha256` text/);
  assert.match(migration, /`artifact_sha256` text/);
});

test("one-time SBOM credentials are exact-host, ephemeral, and non-retryable", async () => {
  assert.deepEqual(parseGitHubRepositoryUrl("https://github.com/openai/example.git"), { owner: "openai", repository: "example" });
  for (const value of ["http://github.com/openai/example", "https://gitlab.com/openai/example", "https://github.com/openai/example/issues", "https://github.com/openai/example?token=secret", "https://user:secret@github.com/openai/example", "https://github.com/openai%2Fexample/repo"]) assert.throws(() => parseGitHubRepositoryUrl(value));
  assert.equal(validateOneTimeGitHubToken("x".repeat(40)), "x".repeat(40));
  for (const value of ["short", ` ${"x".repeat(40)}`, `${"x".repeat(20)}\n${"y".repeat(20)}`]) assert.throws(() => validateOneTimeGitHubToken(value));

  const route = await read("app/api/sboms/route.ts");
  const sbom = await read("lib/server/sbom.ts");
  const schema = await read("db/schema.ts");
  const consoleSource = await read("app/evidence-console.tsx");
  const nativeService = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/RepositorySBOMService.swift");
  const nativeMenu = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/AppDelegate.swift");
  assert.match(route, /sourceMode === "one_time"/);
  assert.match(route, /no-store, max-age=0/);
  assert.match(route, /One-time generation remains available|managedError/);
  assert.match(sbom, /credentialMode === "one_time" \? 1 : 3/);
  assert.match(sbom, /attempt < max_attempts/);
  assert.doesNotMatch(schema, /githubToken|github_token/);
  assert.match(consoleSource, /name="githubToken" type="password"/);
  assert.match(consoleSource, /tokenInput\.value = ""/);
  assert.doesNotMatch(consoleSource, /localStorage|sessionStorage/);
  assert.match(nativeMenu, /Generate Repository SBOM…/);
  assert.match(nativeMenu, /NSSecureTextField/);
  assert.match(nativeMenu, /token\.stringValue = ""/);
  assert.match(nativeMenu, /grid\.frame = NSRect\(x: 0, y: 0, width: 590, height: 210\)/);
  assert.match(nativeService, /URLSessionConfiguration\.ephemeral/);
  assert.match(nativeService, /urlCredentialStorage = nil/);
  assert.match(nativeService, /github-git-data-api-static/);
  assert.doesNotMatch(nativeService, /Keychain|UserDefaults|Process|NSTask|\/usr\/bin/);
});

test("SBOM evidence is reviewable, downloadable, comparable, and documented for auditors", async () => {
  const consoleSource = await read("app/evidence-console.tsx");
  const packageSource = await read("lib/server/packages.ts");
  const guide = await read("docs/SBOM_GUIDE.md");
  const operatorGuide = await read("docs/OPERATOR_GUIDE.md");
  const assessorGuide = await read("docs/ASSESSOR_GUIDE.md");
  const architecture = await read("docs/ARCHITECTURE.md");
  const securityGuide = await read("docs/SECURITY.md");
  const deploymentGuide = await read("docs/DEPLOYMENT.md");
  const operationsGuide = await read("docs/PRODUCTION_OPERATIONS.md");
  assert.match(consoleSource, /"SBOMs"/);
  assert.match(consoleSource, /CycloneDX 1\.6 JSON/);
  assert.match(consoleSource, /SPDX 2\.3 JSON/);
  assert.match(consoleSource, /Since prior/);
  assert.match(consoleSource, /\/api\/evidence\/\$\{encodeURIComponent\(item\.evidence_id\)\}/);
  assert.match(packageSource, /FROM evidence_artifacts e JOIN evidence_occurrences o/);
  assert.match(packageSource, /o\.status = 'approved'/);
  assert.match(packageSource, /n\.chain_sequence IS NOT NULL AND n\.chain_sequence > 0/);
  assert.match(guide, /does not clone a repository or execute repository code/);
  assert.match(guide, /Metadata: read/);
  assert.match(guide, /Contents: read/);
  assert.match(operatorGuide, /Generate a repository SBOM/);
  assert.match(assessorGuide, /Repository SBOM review/);
  assert.match(architecture, /Repository SBOM data flow/);
  assert.match(securityGuide, /Repository archives are untrusted/);
  assert.match(deploymentGuide, /GitHub and repository SBOM setup/);
  assert.match(operationsGuide, /For repository SBOM operations/);
});

test("native S3 evidence storage is destination-bound, integrity-checked, encrypted, and Keychain-backed", async () => {
  const s3 = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/S3StorageService.swift");
  const artifactLoader = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/ValidatedEvidenceArtifact.swift");
  const s3Models = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/S3SecurityModels.swift");
  const keychain = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/KeychainStore.swift");
  const preferences = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/Preferences.swift");
  const menu = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/AppDelegate.swift");
  const browser = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/S3ObjectBrowserController.swift");
  const guide = await read("docs/S3_STORAGE.md");
  const monitoring = await read("infra/aws/scopeproof-s3-observability.yaml");
  assert.match(s3, /AWS4-HMAC-SHA256/);
  assert.match(s3, /host\.hasSuffix\("\.amazonaws\.com"\)/);
  assert.match(s3, /S3RejectRedirectDelegate/);
  assert.match(s3, /urlCredentialStorage = nil/);
  assert.match(s3, /x-amz-server-side-encryption/);
  assert.match(s3, /x-amz-checksum-sha256/);
  assert.match(s3, /x-amz-version-id/);
  assert.match(s3, /x-amz-expected-bucket-owner/);
  assert.match(s3, /ListObjectVersions|listObjectVersionsEndpoint/);
  assert.match(s3, /ValidatedEvidenceArtifact\.load\(capture\)/);
  assert.match(artifactLoader, /sha256\(imageData\) == manifest\.sha256/);
  assert.match(artifactLoader, /maximumImageBytes = 50 \* 1024 \* 1024/);
  assert.match(artifactLoader, /O_NOFOLLOW/);
  assert.doesNotMatch(s3, /Process|NSTask|aws s3|AWS_SECRET_ACCESS_KEY/);
  assert.match(keychain, /aws-s3-evidence-credentials-v1/);
  assert.match(keychain, /aws-s3-verified-destination-v1/);
  assert.match(keychain, /kSecAttrAccessibleWhenUnlockedThisDeviceOnly/);
  assert.doesNotMatch(preferences, /secretAccessKey|accessKeyID|sessionToken/);
  assert.match(menu, /AWS S3 Storage…/);
  assert.match(menu, /Create & Harden Bucket/);
  assert.match(menu, /irreversible S3 Object Lock/);
  assert.match(menu, /Browse S3 Evidence…/);
  assert.match(menu, /Upload Pending Evidence to S3/);
  assert.match(s3, /BlockPublicAcls>true/);
  assert.match(s3, /RestrictPublicBuckets>true/);
  assert.match(s3, /VersioningConfiguration/);
  assert.match(s3, /ObjectLockConfiguration/);
  assert.match(s3, /BucketOwnerEnforced/);
  assert.match(s3, /ScopeproofDenyInsecureTransport/);
  assert.match(s3, /temporaryCredentialsRequired/);
  assert.match(s3Models, /securityBindingDigest/);
  assert.match(s3, /s3ErrorCode\(createResponseData\) == "BucketAlreadyOwnedByYou"/);
  assert.match(guide, /s3:ListBucket/);
  assert.match(guide, /s3:PutObject/);
  assert.match(guide, /s3:GetObjectVersion/);
  assert.match(guide, /Dedicated IAM user for Compatible S3/);
  assert.match(guide, /kms:ViaService/);
  assert.match(guide, /kms:EncryptionContext:aws:s3:arn/);
  assert.match(guide, /permissions boundary/);
  assert.match(guide, /Block Public Access/);
  assert.match(s3, /maximumBrowsableObjects = 5_000/);
  assert.match(s3, /maximumDownloadBytes: Int64 = 250 \* 1024 \* 1024/);
  assert.match(s3, /ifMatch: object\.eTag/);
  assert.match(s3, /\.posixPermissions: 0o600/);
  assert.match(s3, /response\.expectedContentLength != object\.size/);
  assert.match(browser, /NSSavePanel/);
  assert.match(browser, /Download Selected…/);
  assert.match(s3, /quarantineProperties/);
  assert.match(monitoring, /AWS::CloudTrail::Trail/);
  assert.match(monitoring, /DeleteObject/);
  assert.match(monitoring, /DisableKey/);
  assert.doesNotMatch(browser, /S3Credentials\s*[=:]/);
});

test("native Local Console merges local and S3 screenshots without moving AWS trust into browser code", async () => {
  const server = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/LocalConsoleServer.swift");
  const library = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/EvidenceLibrary.swift");
  const assets = await read("macos/ScopeproofCapture/Sources/ScopeproofCapture/LocalConsoleAssets.swift");
  assert.match(server, /credentialProvider\.credentials\(for: settings, binding: binding\)/);
  assert.match(server, /binding\.matches\(settings\)/);
  assert.match(server, /screenshot\.size <= 40 \* 1024 \* 1024/);
  assert.match(server, /s3Service\.downloadObject/);
  assert.match(server, /screenshot\.manifestObject/);
  assert.match(server, /manifestDownload\.sha256/);
  assert.match(server, /ValidatedEvidenceArtifact\.readBoundedRegularFile/);
  assert.match(server, /ValidatedEvidenceArtifact\.validateDownloaded/);
  assert.match(server, /imageDownload\.sha256 == artifact\.manifest\.sha256/);
  assert.match(server, /removeItem\(at: previewDirectory\)/);
  assert.match(library, /components\.count == 4/);
  assert.match(library, /\^EV-\[A-Z0-9\]\+\$/);
  assert.match(library, /verifiedReceiptBindings/);
  assert.match(library, /receipt\.versionIDs\[imageKey\]/);
  assert.match(library, /receiptBinding\?\.imageSHA256 == item\.sha256/);
  assert.match(library, /lifecycleValid: false/);
  assert.match(library, /storageLocation: s3 == nil \? \.local : \.localAndS3/);
  assert.match(assets, /Load secure preview/);
  assert.match(assets, /storage-location/);
  assert.doesNotMatch(assets, /secretAccessKey|sessionToken|versionID|eTag|\.key\b/);
});

test("native evidence writes to Documents while legacy Pictures evidence remains bounded", async () => {
  const [capture, history, installation, operatorGuide, architecture, securityGuide] = await Promise.all([
    read("macos/ScopeproofCapture/Sources/ScopeproofCapture/CaptureService.swift"),
    read("macos/ScopeproofCapture/Sources/ScopeproofCapture/CaptureHistory.swift"),
    read("docs/MACOS_INSTALLATION.md"),
    read("docs/OPERATOR_GUIDE.md"),
    read("docs/ARCHITECTURE.md"),
    read("docs/SECURITY.md"),
  ]);
  assert.match(capture, /CaptureHistory\.defaultEvidenceRoot/);
  assert.match(history, /appendingPathComponent\("Documents"/);
  assert.match(history, /appendingPathComponent\("Pictures"/);
  assert.match(history, /resolvingSymlinksInPath/);
  assert.match(history, /seenEvidenceIDs/);
  assert.match(installation, /~\/Documents\/Scopeproof Evidence/);
  assert.match(operatorGuide, /iCloud Drive/);
  assert.match(architecture, /new writes never target the legacy root/);
  assert.match(securityGuide, /prevent unapproved iCloud Drive/);
});
