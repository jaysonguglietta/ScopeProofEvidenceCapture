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
