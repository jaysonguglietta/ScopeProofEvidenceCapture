import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
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

test("superseded partial coverage does not permanently block export", async () => {
  const packages = await read("lib/server/packages.ts");
  assert.match(packages, /newer\.coverage_status != 'partial'/);
  assert.match(packages, /newer\.captured_at > e\.captured_at/);
  assert.match(packages, /e\.status IN \('needs_review','expiring'\)/);
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
