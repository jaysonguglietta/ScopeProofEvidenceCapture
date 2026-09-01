import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(new URL(`../${path}`, import.meta.url), "utf8");
const compact = (source: string) => source.replace(/\s+/gu, " ");

test("finding disposition is separated from ordinary reviewer maintenance", async () => {
  const [authSource, findingsSource] = await Promise.all([read("lib/server/auth.ts"), read("lib/server/findings.ts")]);
  const auth = compact(authSource);
  const findings = compact(findingsSource);
  const reviewerPermissions = auth.match(/reviewer: new Set\(\[(.*?)\]\)/u)?.[1] || "";
  const leadPermissions = auth.match(/compliance_lead: new Set\(\[(.*?)\]\)/u)?.[1] || "";
  const administratorPermissions = auth.match(/admin: new Set\(\[(.*?)\]\)/u)?.[1] || "";

  assert.match(reviewerPermissions, /"manage_findings"/u);
  assert.doesNotMatch(reviewerPermissions, /"dispose_findings"/u);
  assert.match(leadPermissions, /"dispose_findings"/u);
  assert.match(administratorPermissions, /"dispose_findings"/u);
  assert.match(findings, /\["accepted", "closed"\]\.includes\(status\)[\s\S]*assertPermission\(actor, "dispose_findings"\)/u);
});

test("hold-release approval is bound to immutable hold facts and hold replacement invalidates pending approval", async () => {
  const [routeSource, schemaSource, migrationSource, snapshotSource] = await Promise.all([
    read("app/api/evidence/[id]/retention/route.ts"),
    read("db/schema.ts"),
    read("drizzle/0024_big_chamber.sql"),
    read("drizzle/meta/0024_snapshot.json"),
  ]);
  const route = compact(routeSource);

  for (const column of ["hold_owner_id", "hold_reason", "hold_expires_at"]) {
    assert.match(migrationSource, new RegExp("`" + column + "` text NOT NULL", "u"));
  }
  assert.match(schemaSource, /holdOwnerId: text\("hold_owner_id"\)\.notNull\(\)/u);
  assert.match(schemaSource, /holdReason: text\("hold_reason"\)\.notNull\(\)/u);
  assert.match(schemaSource, /holdExpiresAt: text\("hold_expires_at"\)\.notNull\(\)/u);

  const snapshot = JSON.parse(snapshotSource) as { tables: Record<string, { columns: Record<string, { notNull: boolean }> }> };
  const releaseColumns = snapshot.tables.retention_hold_release_requests.columns;
  assert.equal(releaseColumns.hold_owner_id.notNull, true);
  assert.equal(releaseColumns.hold_reason.notNull, true);
  assert.equal(releaseColumns.hold_expires_at.notNull, true);

  assert.match(route, /UPDATE retention_hold_release_requests SET status = 'cancelled' WHERE evidence_id = \? AND status = 'pending'/u);
  assert.match(route, /hold_owner_id != \? OR hold_reason != \? OR hold_expires_at != \?/u);
  assert.match(route, /schemaVersion: 2[\s\S]*\.\.\.holdFacts/u);
  assert.match(route, /expectedRequestDigest = await sha256\(stableJson\([\s\S]*holdOwnerId: pending\.hold_owner_id[\s\S]*requestedAt: pending\.requested_at/u);
  assert.match(route, /persisted hold-release request failed its immutable digest check/u);
  assert.match(route, /INSERT INTO retention_hold_release_requests \(id, evidence_id, requested_by, reason, request_digest, hold_owner_id, hold_reason, hold_expires_at/u);
  assert.match(route, /h\.owner_id = retention_hold_release_requests\.hold_owner_id/u);
  assert.match(route, /h\.reason = retention_hold_release_requests\.hold_reason/u);
  assert.match(route, /h\.expires_at = retention_hold_release_requests\.hold_expires_at/u);
  assert.match(route, /UPDATE retention_holds SET expires_at = \?, updated_at = CURRENT_TIMESTAMP WHERE evidence_id = \? AND owner_id = \? AND reason = \? AND expires_at = \?/u);
});

test("review events are emitted only by the CAS winner", async () => {
  const [evidenceSource, schemaSource, migrationSource, snapshotSource] = await Promise.all([
    read("lib/server/evidence.ts"),
    read("db/schema.ts"),
    read("drizzle/0024_big_chamber.sql"),
    read("drizzle/meta/0024_snapshot.json"),
  ]);

  assert.match(schemaSource, /lastReviewEventId: text\("last_review_event_id"\)/u);
  assert.match(migrationSource, /ALTER TABLE `evidence_occurrences` ADD `last_review_event_id` text/u);
  const snapshot = JSON.parse(snapshotSource) as { tables: Record<string, { columns: Record<string, { notNull: boolean }> }> };
  assert.equal(snapshot.tables.evidence_occurrences.columns.last_review_event_id.notNull, false);

  const eventTokenPredicates = evidenceSource.match(/last_review_event_id = \?/gu) || [];
  assert.equal(eventTokenPredicates.length, 4, "both approval and general transitions must write and verify their unique event token");
  assert.match(evidenceSource, /approved_at = \?, last_review_event_id = \?[\s\S]*\.bind\(actor\.id, approvedAt, reviewEventId/u);
  assert.match(evidenceSource, /approved_at = \?, last_review_event_id = \?[\s\S]*\.bind\(transition\.to, approvedBy, approvedAt, reviewEventId/u);
  assert.match(evidenceSource, /status = 'approved'[\s\S]*approved_at = \? AND last_review_event_id = \?/u);
  assert.match(evidenceSource, /status = \? AND last_review_event_id = \?/u);
});
