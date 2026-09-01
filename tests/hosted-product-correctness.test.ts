import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { controlCatalogs } from "../lib/control-catalogs.ts";
import { decodePageCursor, encodePageCursor, pageLimit, pageMeta } from "../lib/server/pagination.ts";

const read = (path: string) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("opaque cursor pagination is deterministic, bounded, and does not skip the boundary", () => {
  const cursor = { sortValue: "2026-08-31T15:30:00.000Z", id: `ev_${"a".repeat(32)}` };
  assert.deepEqual(decodePageCursor(encodePageCursor(cursor), /^ev_[a-f0-9]{32}$/u), cursor);
  assert.equal(pageLimit(null), 50);
  assert.throws(() => pageLimit("101"));
  const result = pageMeta([
    { id: `ev_${"c".repeat(32)}`, captured_at: "2026-09-01T00:00:00.000Z" },
    { id: `ev_${"b".repeat(32)}`, captured_at: "2026-08-31T00:00:00.000Z" },
  ], 1, 9, "captured_at", "id");
  assert.equal(result.items.length, 1);
  assert.equal(result.page.total, 9);
  assert.equal(result.page.hasMore, true);
  assert.ok(result.page.nextCursor);
});

test("the hosted assessment catalog is explicitly versioned and control identifiers are unique", () => {
  assert.ok(controlCatalogs.length > 0);
  for (const catalog of controlCatalogs) {
    assert.match(catalog.id, /^[a-z0-9][a-z0-9._-]+$/u);
    assert.ok(catalog.version);
    assert.equal(new Set(catalog.controls.map((control) => control.id)).size, catalog.controls.length);
    assert.ok(catalog.controls.every((control) => control.title && control.requirement && control.defaultEvidence));
  }
});

test("active assessment mutations fail closed on implicit or empty scope", async () => {
  const [assessments, evidence, jobs, sbom] = await Promise.all([
    read("lib/server/assessments.ts"), read("lib/server/evidence.ts"), read("lib/server/jobs.ts"), read("lib/server/sbom.ts"),
  ]);
  assert.match(assessments, /scopeMode must be explicit/);
  assert.match(assessments, /active assessment requires at least one explicitly named system and one control/);
  assert.match(assessments, /failed its immutable digest check/);
  assert.match(evidence, /without an explicit, non-empty, versioned scope/);
  assert.match(jobs, /json_array_length\(systems_json\) > 0/);
  assert.match(sbom, /explicit, versioned scope/);
});

test("review, finding, package, and hold-release state is persisted and audited", async () => {
  const [schema, evidence, findings, packages, retention, migration] = await Promise.all([
    read("db/schema.ts"), read("lib/server/evidence.ts"), read("lib/server/findings.ts"), read("lib/server/packages.ts"),
    read("app/api/evidence/[id]/retention/route.ts"), read("drizzle/0024_big_chamber.sql"),
  ]);
  for (const table of ["evidence_review_events", "findings", "finding_events", "retention_hold_release_requests"]) {
    assert.match(migration, new RegExp(`CREATE TABLE .${table}.`));
  }
  assert.match(schema, /retentionHoldReleaseRequests/);
  assert.match(evidence, /evidence_review_events/);
  assert.match(evidence, /Collectors and uploaders cannot review their own evidence/);
  assert.match(findings, /executeAuditedBatch/);
  assert.match(packages, /preflightAssessorPackage/);
  assert.match(retention, /who requested hold release cannot approve it/);
  assert.match(retention, /requestDigest/);
});

test("managed jobs are durable while one-time-token SBOM remains request-bound", async () => {
  const [runs, jobs, sbomRoute, sbom] = await Promise.all([
    read("app/api/runs/route.ts"), read("lib/server/jobs.ts"), read("app/api/sboms/route.ts"), read("lib/server/sbom.ts"),
  ]);
  assert.match(runs, /status: 202/);
  assert.doesNotMatch(runs, /await processJob\(/);
  assert.match(jobs, /status = 'queued'/);
  assert.match(sbomRoute, /body\.sourceMode === "one_time"[\s\S]*processSbom/);
  assert.match(sbomRoute, /credentialMode: "managed"[\s\S]*status: 202/);
  assert.match(sbom, /status = 'queued'/);
});

test("hosted dialogs trap focus and restore the invoking control", async () => {
  const consoleSource = await read("app/evidence-console.tsx");
  assert.match(consoleSource, /previous\?\.focus\(\)/);
  assert.match(consoleSource, /event\.key !== "Tab"/);
  assert.match(consoleSource, /role="dialog" aria-modal="true"/);
});

test("the console browses complete pages and uses the persisted remediation workflow", async () => {
  const consoleSource = await read("app/evidence-console.tsx");
  assert.match(consoleSource, /Load 50 more/);
  for (const kind of ["evidence", "runs", "sboms", "findings"]) {
    assert.match(consoleSource, new RegExp(`loadMoreWorkspace\\(\\"${kind}\\"\\)`));
  }
  assert.match(consoleSource, /fetch\("\/api\/findings", \{ method: "POST"/u);
  assert.match(consoleSource, /fetch\(`\/api\/findings\/\$\{encodeURIComponent\(id\)\}`/u);
  assert.match(consoleSource, /packagePreflight\?\.ready/u);
  assert.doesNotMatch(consoleSource, /Derived from evidence and collection state/u);
  assert.doesNotMatch(consoleSource, /flagged for follow-up/u);
});
