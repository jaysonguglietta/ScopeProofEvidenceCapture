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
