import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { partitionEvidence, exclusionReason, PACKAGE_PLAN_SNAPSHOT_FENCE_SQL, type PackageSnapshotRow } from "../lib/server/package-partitions.ts";
import { PACKAGE_MAXIMUM_EVIDENCE_BYTES, PACKAGE_PARTITION_PUBLISH_FENCE_SQL } from "../lib/server/package-eligibility.ts";

const item = (n: number, bytes = 1): PackageSnapshotRow => ({ id: `ev_${String(n).padStart(32, "0")}`, occurrenceId: `occ_${n}`, sha256: "a".repeat(64), bytes, status: "approved", coverage: "complete", expiresAt: "2030-01-01", eligible: true });
test("package plans cover every eligible artifact exactly once within both byte and count bounds", () => {
  const snapshot = Array.from({ length: 203 }, (_, i) => item(i));
  snapshot.push({ ...item(999), eligible: false, status: "rejected" });
  const parts = partitionEvidence(snapshot);
  assert.deepEqual(parts.map((part) => part.evidenceIds.length), [100, 100, 3]);
  assert.equal(new Set(parts.flatMap((part) => part.evidenceIds)).size, 203);
  assert.deepEqual(partitionEvidence([...snapshot].reverse()), parts);
  assert.equal(exclusionReason(snapshot.at(-1)!), "review_status:rejected");
  assert.deepEqual(partitionEvidence([item(1, PACKAGE_MAXIMUM_EVIDENCE_BYTES), item(2, 1)]).map((part) => part.bytes), [PACKAGE_MAXIMUM_EVIDENCE_BYTES, 1]);
  for (const bad of [[item(1), item(1)], [item(1, PACKAGE_MAXIMUM_EVIDENCE_BYTES + 1)], [item(1, -1)], Array.from({ length: 1001 }, (_, i) => item(i))]) assert.throws(() => partitionEvidence(bad));
});

test("partition publication retains whole-assessment integrity fences rather than treating a part as the full scope", () => {
  assert.match(PACKAGE_PARTITION_PUBLISH_FENCE_SQL, /pending_safety/);
  assert.match(PACKAGE_PARTITION_PUBLISH_FENCE_SQL, /pending_native/);
  assert.match(PACKAGE_PARTITION_PUBLISH_FENCE_SQL, /package_eligibility\.total/);
  assert.doesNotMatch(PACKAGE_PARTITION_PUBLISH_FENCE_SQL, /eligible_bytes, 0\) <=/);
  const builder = readFileSync(new URL("../lib/server/packages.ts", import.meta.url), "utf8");
  assert.match(builder, /assignedToOtherParts: eligibleCount - rows\.length/);
  assert.match(builder, /NOT A COMPLETE ASSESSMENT PACKAGE BY ITSELF/);
  assert.match(builder, /plan\?\.digest !== partition\.digest/);
  assert.match(builder, /packagePublicationQuery\(/);
  const publication = readFileSync(new URL("../lib/server/package-publication.ts", import.meta.url), "utf8");
  assert.match(publication, /packageEligibilityPublishFenceBindings\(assessmentId, publication\.completedAt, totalCount, eligibleCount\)/);
});

test("SQLite snapshot identity rejects mutations in other parts and duplicate occurrence swaps", () => {
  const db = new DatabaseSync(":memory:");
  const journal = JSON.parse(readFileSync(new URL("../drizzle/meta/_journal.json", import.meta.url), "utf8")) as { entries: Array<{ tag: string }> };
  for (const entry of journal.entries) db.exec(readFileSync(new URL(`../drizzle/${entry.tag}.sql`, import.meta.url), "utf8"));
  db.exec(`INSERT INTO users(id,email,display_name,role,status) VALUES ('owner','owner@example.test','Owner','compliance_lead','active');
    INSERT INTO assessments(id,name,framework,period_start,period_end,systems_json,controls_json,catalog_id,scope_mode,owner_id,status)
    VALUES ('assessment','Audit','PCI DSS 4.0.1','2026-01-01','2026-12-31','["A"]','["1.2.5"]','catalog','explicit','owner','active');`);
  const rows = [item(1), { ...item(2), sha256: "b".repeat(64) }];
  for (const row of rows) {
    db.prepare(`INSERT INTO evidence_artifacts(id,control_id,title,type,source,system,r2_key,content_type,byte_size,sha256,encryption_iv,captured_at,expires_at,created_by,assessment_id)
      VALUES (?,'1.2.5','Evidence','report','manual','A',?,'text/plain',?,?,'iv','2026-01-01','2030-01-01','collector','assessment')`).run(row.id, row.id, row.bytes, row.sha256);
    db.prepare(`INSERT INTO evidence_occurrences(id,artifact_id,created_by,captured_at,received_at,expires_at,status,coverage_status)
      VALUES (?,?,'collector','2026-01-01','2026-01-01','2030-01-01','approved','complete')`).run(row.occurrenceId, row.id);
  }
  const check = db.prepare(`SELECT ${PACKAGE_PLAN_SNAPSHOT_FENCE_SQL} AS valid`);
  const allowed = () => check.get(JSON.stringify(rows), "assessment", "2026-09-08")!.valid;
  assert.equal(allowed(), 1);
  db.prepare("UPDATE evidence_occurrences SET status='superseded' WHERE id=?").run(rows[1].occurrenceId);
  assert.equal(allowed(), 0);
  db.prepare("UPDATE evidence_occurrences SET status='approved' WHERE id=?").run(rows[1].occurrenceId);
  assert.equal(allowed(), 1);
  db.prepare("UPDATE evidence_artifacts SET system='outside-scope' WHERE id=?").run(rows[1].id);
  assert.equal(allowed(), 0);
  db.close();
});
