import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
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
  assert.match(evidence, /control_id = \? AND assessment_id = \?/);
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
  assert.match(packages, /WHERE assessment_id = \?/);
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
  const jobs = await read("lib/server/jobs.ts");
  assert.match(checkpoints, /signPackage\(canonical\)/);
  assert.match(checkpoints, /audit-checkpoints\/\$\{month\}/);
  assert.match(checkpoints, /AUDIT_CHECKPOINT_ALLOWED_HOSTS/);
  assert.match(checkpoints, /allowedOrigins: \[url\.origin\]/);
  assert.match(jobs, /createAuditCheckpoint\(now\)/);
});

test("release and operations controls are executable and fail closed", async () => {
  const workflow = await read(".github/workflows/security.yml");
  const monitoring = await read("lib/server/monitoring.ts");
  const operations = await read("docs/PRODUCTION_OPERATIONS.md");
  assert.doesNotMatch(workflow, /uses: actions\/(checkout|setup-node|upload-artifact)@v\d/);
  assert.match(workflow, /working-directory: macos\/ScopeproofCapture/);
  assert.match(workflow, /verify_migrations\.sh/);
  assert.match(workflow, /actions\/attest@[a-f0-9]{40}/);
  assert.match(monitoring, /SECURITY_EVENT_ALLOWED_HOSTS/);
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

test("SBOM evidence is reviewable, downloadable, comparable, and documented for auditors", async () => {
  const consoleSource = await read("app/evidence-console.tsx");
  const packageSource = await read("lib/server/packages.ts");
  const guide = await read("docs/SBOM_GUIDE.md");
  assert.match(consoleSource, /"SBOMs"/);
  assert.match(consoleSource, /CycloneDX 1\.6 JSON/);
  assert.match(consoleSource, /SPDX 2\.3 JSON/);
  assert.match(consoleSource, /Since prior/);
  assert.match(consoleSource, /\/api\/evidence\/\$\{encodeURIComponent\(item\.evidence_id\)\}/);
  assert.match(packageSource, /FROM evidence_artifacts WHERE assessment_id = \? AND status = 'approved'/);
  assert.match(guide, /does not clone a repository or execute repository code/);
  assert.match(guide, /Metadata: read/);
  assert.match(guide, /Contents: read/);
});
