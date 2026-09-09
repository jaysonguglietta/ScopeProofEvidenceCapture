import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { packagePublicationQuery } from "../lib/server/package-publication.ts";
import type { PackageSnapshotRow } from "../lib/server/package-partitions.ts";

const at = "2026-09-08T12:00:00.000Z";
const updatedAt = "2026-09-01T00:00:00.000Z";
const publication = { r2Key: "exports/pkg_test.zip.enc", sha256: "f".repeat(64), signature: "signature", evidenceCount: 100, excludedCount: 0, encryptionKeyId: "key-v2", byteSize: 4096, completedAt: at, expiresAt: "2026-09-15T12:00:00.000Z" };

function fixture(count: number) {
  const db = new DatabaseSync(":memory:");
  const journal = JSON.parse(readFileSync(new URL("../drizzle/meta/_journal.json", import.meta.url), "utf8")) as { entries: Array<{ tag: string }> };
  for (const entry of journal.entries) db.exec(readFileSync(new URL(`../drizzle/${entry.tag}.sql`, import.meta.url), "utf8"));
  db.exec(`INSERT INTO users(id,email,display_name,role,status) VALUES ('owner','owner@example.test','Owner','compliance_lead','active');
    INSERT INTO assessments(id,name,framework,period_start,period_end,systems_json,controls_json,catalog_id,scope_mode,owner_id,status,updated_at)
    VALUES ('assessment','Audit','PCI DSS 4.0.1','2026-01-01','2026-12-31','["A"]','["1.2.5"]','catalog','explicit','owner','active','${updatedAt}');
    INSERT INTO export_packages(id,requested_by,assessment_id,status) VALUES ('pkg_test','owner','assessment','building');`);
  const snapshot: PackageSnapshotRow[] = [];
  const artifact = db.prepare(`INSERT INTO evidence_artifacts(id,control_id,title,type,source,system,r2_key,content_type,byte_size,sha256,encryption_iv,captured_at,expires_at,created_by,assessment_id)
    VALUES (?,'1.2.5','Evidence','report','manual','A',?,'text/plain',1,?,'iv','2026-01-01','2030-01-01','collector','assessment')`);
  const occurrence = db.prepare(`INSERT INTO evidence_occurrences(id,artifact_id,created_by,captured_at,received_at,expires_at,status,coverage_status)
    VALUES (?,?,'collector','2026-01-01','2026-01-01','2030-01-01','approved','complete')`);
  db.exec("BEGIN");
  for (let i = 0; i < count; i++) {
    const row: PackageSnapshotRow = { id: `ev_${i.toString(16).padStart(32, "0")}`, occurrenceId: `occ_${i}`, sha256: i.toString(16).padStart(64, "0"), bytes: 1, status: "approved", coverage: "complete", expiresAt: "2030-01-01", eligible: true };
    artifact.run(row.id, row.id, row.sha256); occurrence.run(row.occurrenceId, row.id); snapshot.push(row);
  }
  db.exec("COMMIT");
  return { db, snapshot };
}

function query(snapshot: PackageSnapshotRow[], partitioned = false, selected = snapshot.slice(0, 100)) {
  return packagePublicationQuery({ id: "pkg_test", assessmentId: "assessment", assessmentStatus: "active", assessmentUpdatedAt: updatedAt,
    publication: { ...publication, evidenceCount: selected.length }, totalCount: snapshot.length, eligibleCount: snapshot.length,
    occurrences: selected.map((row) => ({ artifactId: row.id, occurrenceId: row.occurrenceId })),
    ...(partitioned ? { snapshotJson: JSON.stringify(snapshot) } : {}),
  });
}

function assertD1Limits(statement: ReturnType<typeof query>) {
  assert.ok(statement.bindings.length <= 100, `D1 binding limit exceeded: ${statement.bindings.length}`);
  assert.equal((statement.sql.match(/\?/gu) || []).length, statement.bindings.length);
  assert.ok(Buffer.byteLength(statement.sql) <= 100_000, "D1 statement byte limit exceeded");
  for (const binding of statement.bindings) if (typeof binding === "string") assert.ok(Buffer.byteLength(binding) <= 2_000_000, "D1 value byte limit exceeded");
}

test("actual SQLite publication handles 100 normal artifacts and 100-item parts of a 1,000-item plan within D1 limits", () => {
  for (const partitioned of [false, true]) {
    const { db, snapshot } = fixture(partitioned ? 1000 : 100);
    try {
      const statement = query(snapshot, partitioned);
      assertD1Limits(statement);
      assert.equal(statement.bindings.length, partitioned ? 27 : 24, "binding count is constant, independent of artifact count");
      const single = query(snapshot, partitioned, snapshot.slice(0, 1));
      assert.equal(single.sql, statement.sql);
      assert.equal(single.bindings.length, statement.bindings.length);
      assert.equal(db.prepare(statement.sql).run(...statement.bindings).changes, 1);
      const stored = db.prepare("SELECT status,evidence_count,sha256,r2_key FROM export_packages WHERE id='pkg_test'").get();
      assert.equal(stored?.status, "ready"); assert.equal(stored?.evidence_count, 100); assert.equal(stored?.sha256, publication.sha256); assert.equal(stored?.r2_key, publication.r2Key);
    } finally { db.close(); }
  }
});

test("bounded publication keeps latest-occurrence, scope, approval, safety, provenance, and concurrent snapshot fences", () => {
  const { db, snapshot } = fixture(1000);
  const statement = query(snapshot, true);
  try {
    const rejects = (mutate: () => void, label: string) => {
      db.exec("SAVEPOINT mutation");
      try {
        mutate();
        assert.equal(db.prepare(statement.sql).run(...statement.bindings).changes, 0, label);
        assert.equal(db.prepare("SELECT status FROM export_packages WHERE id='pkg_test'").get()?.status, "building", "failed fences never publish");
      } finally { db.exec("ROLLBACK TO mutation; RELEASE mutation"); }
    };
    const selected = snapshot[0];
    const otherPart = snapshot[999];
    rejects(() => db.prepare("UPDATE evidence_occurrences SET status='needs_review' WHERE id=?").run(selected.occurrenceId), "selected review changed");
    rejects(() => db.prepare("UPDATE evidence_occurrences SET coverage_status='partial' WHERE id=?").run(selected.occurrenceId), "selected partial coverage");
    rejects(() => db.prepare("UPDATE evidence_occurrences SET expires_at=? WHERE id=?").run(at, selected.occurrenceId), "selected evidence expired");
    rejects(() => db.prepare("UPDATE evidence_artifacts SET system='outside-scope' WHERE id=?").run(selected.id), "selected system left authoritative scope");
    rejects(() => db.prepare("UPDATE evidence_artifacts SET type='screenshot' WHERE id=?").run(selected.id), "selected screenshot has no server receipt");
    rejects(() => db.prepare("UPDATE evidence_artifacts SET device_id='unenrolled-device' WHERE id=?").run(selected.id), "selected native evidence has no device provenance");
    rejects(() => db.prepare("UPDATE assessments SET updated_at='2026-09-08T11:00:00Z' WHERE id='assessment'").run(), "assessment CAS changed");
    for (const row of [selected, otherPart]) {
      rejects(() => db.prepare(`INSERT INTO evidence_occurrences(id,artifact_id,created_by,captured_at,received_at,expires_at,status,coverage_status)
        VALUES ('occ_replacement',?,'collector','2026-01-02','2026-01-02','2030-01-01','approved','complete')`).run(row.id), "new approved occurrence preserves counts but invalidates selected/other-part identity");
    }
    const swapped = snapshot.slice(0, 100).map((row, index) => ({ ...row, occurrenceId: snapshot[(index + 1) % 100].occurrenceId }));
    const mismatch = query(snapshot, true, swapped);
    assert.equal(db.prepare(mismatch.sql).run(...mismatch.bindings).changes, 0, "an occurrence must belong to its selected artifact");
    assert.equal(db.prepare(statement.sql).run(...statement.bindings).changes, 1, "unaltered snapshot still publishes");
  } finally { db.close(); }
});

test("publication rejects empty, oversized, duplicate, or count-inconsistent selected sets", () => {
  const base = { id: "pkg_test", assessmentId: "assessment", assessmentStatus: "active", assessmentUpdatedAt: updatedAt, publication, totalCount: 100, eligibleCount: 100 };
  const rows = Array.from({ length: 101 }, (_, i) => ({ artifactId: `ev_${i}`, occurrenceId: `occ_${i}` }));
  for (const occurrences of [[], rows, [rows[0], rows[0]], rows.slice(0, 99), rows.slice(0, 100).map((row) => ({ ...row, occurrenceId: "same" }))]) assert.throws(() => packagePublicationQuery({ ...base, occurrences }));
});
