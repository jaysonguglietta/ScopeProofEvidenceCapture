import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import {
  classifyPackagePublication,
  type ExpectedPackagePublication,
  type PackagePublicationState,
} from "../lib/server/package-publication-reconciliation.ts";

const expected: ExpectedPackagePublication = {
  r2Key: "exports/pkg_test.zip.enc",
  sha256: "sha256",
  signature: "signature",
  evidenceCount: 4,
  excludedCount: 1,
  encryptionKeyId: "evidence-v2",
  byteSize: 4096,
  completedAt: "2026-09-01T12:00:00.000Z",
  expiresAt: "2026-09-08T12:00:00.000Z",
};

function readyState(overrides: Partial<PackagePublicationState> = {}): PackagePublicationState {
  return {
    status: "ready",
    r2Key: expected.r2Key,
    sha256: expected.sha256,
    signature: expected.signature,
    evidenceCount: expected.evidenceCount,
    excludedCount: expected.excludedCount,
    encryptionKeyId: expected.encryptionKeyId,
    byteSize: expected.byteSize,
    completedAt: expected.completedAt,
    expiresAt: expected.expiresAt,
    ...overrides,
  };
}

test("an exact authoritative package publication is recognized after an ambiguous commit", () => {
  assert.equal(classifyPackagePublication(readyState(), expected.r2Key, expected), "committed");
  for (const state of [
    readyState({ status: "failed" }),
    readyState({ sha256: "different" }),
    readyState({ signature: "different" }),
    readyState({ evidenceCount: 3 }),
    readyState({ excludedCount: 2 }),
    readyState({ encryptionKeyId: "other-key" }),
    readyState({ byteSize: 1 }),
    readyState({ completedAt: "2026-09-01T12:00:01.000Z" }),
    readyState({ expiresAt: "2026-09-08T12:00:01.000Z" }),
  ]) {
    assert.equal(classifyPackagePublication(state, expected.r2Key, expected), "referenced", "a row that names the candidate is never deletion proof");
  }
});

test("the publication/failure CAS race has one authoritative winner and only a proven loser is deletable", () => {
  const runRace = (publicationWins: boolean) => {
    const db = new DatabaseSync(":memory:");
    db.exec(`CREATE TABLE export_packages (
      id TEXT PRIMARY KEY, status TEXT NOT NULL, r2_key TEXT, sha256 TEXT, signature TEXT,
      evidence_count INTEGER NOT NULL DEFAULT 0, excluded_count INTEGER NOT NULL DEFAULT 0,
      encryption_key_id TEXT NOT NULL DEFAULT 'legacy-v1', byte_size INTEGER NOT NULL DEFAULT 0,
      completed_at TEXT, expires_at TEXT NOT NULL DEFAULT ''
    ); INSERT INTO export_packages (id, status) VALUES ('pkg_test', 'building');`);
    const publish = db.prepare(`UPDATE export_packages SET status = 'ready', r2_key = ?, sha256 = ?, signature = ?,
      evidence_count = ?, excluded_count = ?, encryption_key_id = ?, byte_size = ?, completed_at = ?, expires_at = ?
      WHERE id = 'pkg_test' AND status = 'building'`);
    const fail = db.prepare("UPDATE export_packages SET status = 'failed', completed_at = ? WHERE id = 'pkg_test' AND status = 'building'");
    const publishArgs = [expected.r2Key, expected.sha256, expected.signature, expected.evidenceCount, expected.excludedCount,
      expected.encryptionKeyId, expected.byteSize, expected.completedAt, expected.expiresAt] as const;
    const first = publicationWins ? publish.run(...publishArgs) : fail.run(expected.completedAt);
    const second = publicationWins ? fail.run(expected.completedAt) : publish.run(...publishArgs);
    assert.equal(first.changes, 1);
    assert.equal(second.changes, 0);
    const row = db.prepare(`SELECT status, r2_key AS r2Key, sha256, signature, evidence_count AS evidenceCount,
      excluded_count AS excludedCount, encryption_key_id AS encryptionKeyId, byte_size AS byteSize,
      completed_at AS completedAt, expires_at AS expiresAt FROM export_packages WHERE id = 'pkg_test'`).get() as PackagePublicationState;
    const disposition = classifyPackagePublication(row, expected.r2Key, expected);
    const deletionProof = db.prepare("SELECT 1 FROM export_packages WHERE id = 'pkg_test' AND status = 'failed' AND r2_key IS NOT ?")
      .get(expected.r2Key);
    db.close();
    return { disposition, deletionProof: Boolean(deletionProof) };
  };

  assert.deepEqual(runRace(true), { disposition: "committed", deletionProof: false });
  assert.deepEqual(runRace(false), { disposition: "unreferenced", deletionProof: true });
});

test("runtime cleanup preserves uncertain or referenced candidates and re-proves the failed loser", async () => {
  const source = await readFile(new URL("../lib/server/packages.ts", import.meta.url), "utf8");
  const catchStart = source.indexOf("} catch (error) {");
  const failureCas = source.indexOf("SET status = 'failed'", catchStart);
  const authoritativeRead = source.indexOf("authoritativePackagePublicationDisposition", failureCas);
  const unreferencedBranch = source.indexOf('disposition === "unreferenced"', authoritativeRead);
  const deletionProof = source.indexOf("status = 'failed' AND r2_key IS NOT ?", unreferencedBranch);
  const deleteCandidate = source.indexOf("EVIDENCE_BUCKET.delete(pendingR2Key)", deletionProof);
  assert.ok(catchStart >= 0 && catchStart < failureCas);
  assert.ok(failureCas < authoritativeRead);
  assert.ok(authoritativeRead < unreferencedBranch);
  assert.ok(unreferencedBranch < deletionProof);
  assert.ok(deletionProof < deleteCandidate);
  assert.match(source, /return "unavailable"/);
  assert.doesNotMatch(source.slice(authoritativeRead, unreferencedBranch), /EVIDENCE_BUCKET\.delete/);
  assert.match(source, /disposition === "committed" && completedResult/);
  assert.doesNotMatch(source, /error instanceof Error \? error\.message/);
});
