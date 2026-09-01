import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const read = (path: string) => readFile(new URL(`../${path}`, import.meta.url), "utf8");

test("native provenance reconciliation has explicit small work and age bounds", async () => {
  const [source, contract] = await Promise.all([
    read("lib/server/native-provenance-reconciliation.ts"),
    read("lib/server/native-provenance-contract.ts"),
  ]);
  assert.match(source, /NATIVE_RECONCILIATION_MAXIMUM_ITEMS = 25/);
  assert.match(contract, /NATIVE_ORPHAN_GRACE_MS = 10 \* 60_000/);
  assert.match(source, /maximumItems > 100/);
});

test("expired native reservations finalize only exact chain and safety authority", async () => {
  const source = await read("lib/server/native-provenance-reconciliation.ts");
  assert.match(source, /unixepoch\(d\.chain_pending_expires_at\) <= unixepoch\(\?\)/);
  assert.match(source, /loadExpiredReservationPage\(observedCursors\.pending, nowIso, maximumItems\)/);
  assert.match(source, /unixepoch\(d\.chain_pending_expires_at\) > \?/);
  assert.match(source, /unixepoch\(d\.chain_pending_expires_at\) = \? AND d\.id > \?/);
  assert.match(source, /unixepoch\(d\.chain_pending_expires_at\) < \?/);
  assert.match(source, /unixepoch\(d\.chain_pending_expires_at\) = \? AND d\.id <= \?/);
  assert.match(source, /limit - rows\.length/);
  assert.match(source, /pendingSequence !== pending\.chainSequence \+ 1/);
  assert.match(source, /previousHash !== pending\.chainEventHash/);
  assert.match(source, /await sha256\(publicKey\) !== pending\.provenanceKeyId/);
  assert.match(source, /row\.safety_scan_sha256 !== imageSha256/);
  assert.match(source, /row\.server_safety_scan_sha256 !== imageSha256/);
  assert.match(source, /native_provenance\.reconciled/);
  assert.match(source, /chain_pending_lease_id = \?/);
  assert.match(source, /chain_pending_sequence = \?/);
  assert.match(source, /chain_pending_previous_hash = \?/);
  assert.match(source, /chain_pending_event_hash = \?/);
  assert.match(source, /chain_pending_evidence_id = \?/);
  assert.match(source, /chain_pending_expires_at = \?/);
  assert.match(source, /u\.id = capture_devices\.owner_id/);
  assert.match(source, /u\.status = 'active'/);
  assert.match(source, /u\.role IN \('admin', 'compliance_lead'\)/);
});

test("independent durable keysets isolate poison rows and orphan work", async () => {
  const source = await read("lib/server/native-provenance-reconciliation.ts");
  assert.doesNotMatch(source, /COUNT\(\*\)|pendingOffset|orphanOffset|\bOFFSET\b/);
  assert.match(source, /native_provenance_reconciliation_state WHERE id = 'native_provenance'/);
  assert.match(source, /pending_cursor_expires_epoch IS \? AND pending_cursor_device_id IS \?/);
  assert.match(source, /orphan_cursor_due_epoch IS \? AND orphan_cursor_artifact_id IS \?/);
  assert.match(source, /native_provenance\.cursors_advanced/);
  assert.match(source, /WHERE id = 'native_provenance' AND revision = \?/);
  assert.match(source, /loadOrphanCandidatePage\(observedCursors\.orphan, nowIso, maximumItems\)/);
  assert.match(source, /FROM native_provenance_reconciliation_queue q/);
  assert.match(source, /LEFT JOIN evidence_artifacts e ON e\.id = q\.artifact_id/);
  assert.match(source, /ORDER BY unixepoch\(q\.due_at\), q\.artifact_id LIMIT \?/);
  assert.doesNotMatch(source, /FROM evidence_artifacts e`;\s*\/\/ Page the indexed base population/);
  assert.match(source, /has_finalized_manifest/);
  assert.match(source, /has_pending_reservation/);
  assert.match(source, /maximumItems\);\n\n {2}for \(const row of pendingRows\)/);
  assert.match(source, /maximumItems\);\n {2}for \(const row of orphanRows\)/);
  assert.ok(source.indexOf("advanceReconciliationCursors(") < source.indexOf("if (result.failures > 0)"));
});

test("migration installs a protected singleton and both keyset indexes", async () => {
  const [migration, schema, journal, verifier] = await Promise.all([
    read("drizzle/0028_native_reconciliation_cursor.sql"),
    read("db/schema.ts"),
    read("drizzle/meta/_journal.json"),
    read("Scripts/verify_migrations.sh"),
  ]);
  assert.match(migration, /CREATE TABLE `native_provenance_reconciliation_state`/);
  assert.match(migration, /CREATE TABLE `native_provenance_reconciliation_queue`/);
  assert.match(migration, /VALUES \('native_provenance', 0, NULL, NULL, NULL, NULL\)/);
  assert.match(migration, /idx_capture_devices_pending_reconciliation_cursor/);
  assert.match(migration, /idx_native_reconciliation_queue_due/);
  assert.match(migration, /INSERT INTO `native_provenance_reconciliation_queue`/);
  assert.match(migration, /NOT EXISTS \(SELECT 1 FROM native_evidence_manifests/);
  assert.match(migration, /native_provenance_reconciliation_state_revision_cas/);
  assert.match(migration, /NEW\.revision <> OLD\.revision \+ 1/);
  assert.match(migration, /native_provenance_reconciliation_state_no_delete/);
  assert.match(schema, /nativeProvenanceReconciliationState/);
  assert.match(journal, /0028_native_reconciliation_cursor/);
  assert.match(verifier, /drizzle\/0028_native_reconciliation_cursor\.sql/);
  assert.match(verifier, /Native reconciliation cursor accepted a partial keyset/);
  assert.match(verifier, /Native reconciliation queue accepted an invalid due time/);
});

test("native queue authority is created and atomically removed from every terminal path", async () => {
  const [evidence, devices, reconciliation] = await Promise.all([
    read("lib/server/evidence.ts"),
    read("lib/server/devices.ts"),
    read("lib/server/native-provenance-reconciliation.ts"),
  ]);
  assert.match(evidence, /INSERT INTO native_provenance_reconciliation_queue/);
  assert.match(evidence, /receivedAt\.getTime\(\) \+ NATIVE_ORPHAN_GRACE_MS/);

  const normalFinalize = devices.slice(
    devices.indexOf("export async function finalizeCaptureDeviceChain"),
    devices.indexOf("export async function requireCaptureDevice"),
  );
  assert.match(normalFinalize, /DELETE FROM native_provenance_reconciliation_queue WHERE artifact_id = \?/);
  assert.match(normalFinalize, /NOT EXISTS \(SELECT 1 FROM native_provenance_reconciliation_queue WHERE artifact_id = \?\)/);
  assert.match(normalFinalize, /FINALIZED_REPLAY/);

  const recoveryFinalize = reconciliation.slice(
    reconciliation.indexOf("async function finalizeExactCandidate"),
    reconciliation.indexOf("async function releaseExpiredReservation"),
  );
  assert.match(recoveryFinalize, /DELETE FROM native_provenance_reconciliation_queue WHERE artifact_id = \?/);
  assert.match(recoveryFinalize, /NOT EXISTS \(SELECT 1 FROM native_provenance_reconciliation_queue WHERE artifact_id = \?\)/);

  const quarantine = reconciliation.slice(
    reconciliation.indexOf("async function quarantineOrphanArtifact"),
    reconciliation.indexOf("function exactPattern"),
  );
  assert.match(quarantine, /DELETE FROM native_provenance_reconciliation_queue/);
  assert.match(quarantine, /queue authority/);
});

test("owner suspension or collection-role demotion loses the finalization CAS", async () => {
  const source = await read("lib/server/native-provenance-reconciliation.ts");
  const finalizeStart = source.indexOf("async function finalizeExactCandidate");
  const finalizeEnd = source.indexOf("async function releaseExpiredReservation");
  const finalize = source.slice(finalizeStart, finalizeEnd);
  assert.ok((finalize.match(/status = 'active'/g) ?? []).length >= 2);
  assert.equal((finalize.match(/role IN \('admin', 'compliance_lead'\)/g) ?? []).length, 2);
  assert.match(finalize, /pending\.leaseExpiresAt, pending\.ownerId/);
  assert.match(finalize, /pending\.pendingSequence, pending\.eventHash, pending\.ownerId/);
  assert.doesNotMatch(finalize, /'reviewer'|'auditor'/);
});

test("concurrent artifact return, expiry, or safety mutation loses the finalization CAS", async () => {
  const source = await read("lib/server/native-provenance-reconciliation.ts");
  const finalizeStart = source.indexOf("async function finalizeExactCandidate");
  const finalizeEnd = source.indexOf("async function releaseExpiredReservation");
  const finalize = source.slice(finalizeStart, finalizeEnd);
  assert.equal((finalize.match(/exactArtifactAuthoritySql/g) ?? []).length, 2);
  assert.equal((finalize.match(/exactArtifactAuthorityBindings\(artifact, nowIso\)/g) ?? []).length, 2);
  for (const authority of [
    "e.status = ?", "e.expires_at = ?", "unixepoch(e.expires_at) > unixepoch(?)",
    "e.created_by = ?", "e.source = ?", "e.sha256 = ?", "e.manifest_sha256 = ?",
    "e.safety_scan_sha256 = ?", "e.server_safety_receipt_sha256 = ?", "e.timestamp_token = ?",
  ]) assert.match(source, new RegExp(authority.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
});

test("unresolved native state is audit-quarantined without deleting stored bytes or advancing the chain", async () => {
  const source = await read("lib/server/native-provenance-reconciliation.ts");
  assert.match(source, /native_provenance\.reservation_released/);
  assert.match(source, /native_provenance\.artifact_quarantined/);
  assert.match(source, /SET status = 'returned', approved_by = NULL, approved_at = NULL/);
  assert.match(source, /NOT EXISTS \(SELECT 1 FROM native_evidence_manifests/);
  assert.doesNotMatch(source, /EVIDENCE_BUCKET\.delete|\.delete\(r2|DELETE FROM evidence_artifacts/);

  const releaseStart = source.indexOf("async function releaseExpiredReservation");
  const releaseEnd = source.indexOf("async function quarantineOrphanArtifact");
  const release = source.slice(releaseStart, releaseEnd);
  assert.doesNotMatch(release, /SET chain_sequence|SET chain_event_hash/);
  assert.match(release, /owner_id = \? AND chain_sequence = \?/);
  assert.match(release, /status = \? AND provenance_key_id IS \? AND provenance_public_key IS \?/);
  assert.match(release, /activeMembership/);
  assert.match(release, /matchingChain/);
  assert.match(release, /DEVICE_OR_OWNER_REVOKED/);
  assert.match(release, /CHAIN_AUTHORITY_MISMATCH/);
  assert.match(release, /PINNED_KEY_INVALID/);

  const artifactMissingStart = release.indexOf('if (reason === "ARTIFACT_NOT_FOUND")');
  const revokedStart = release.indexOf('if (reason === "DEVICE_OR_OWNER_REVOKED")');
  const artifactMissing = release.slice(artifactMissingStart, revokedStart);
  assert.match(artifactMissing, /NOT EXISTS \(SELECT 1 FROM evidence_artifacts e/);
  assert.equal((artifactMissing.match(/\$\{absence\}/g) ?? []).length, 2);
  assert.match(artifactMissing, /activeMembershipPostcondition/);
});

test("every pending reservation preserves its artifact for a later reconciliation retry", async () => {
  const source = await read("lib/server/native-provenance-reconciliation.ts");
  const orphanSelectionStart = source.indexOf("async function loadOrphanCandidatePage");
  const orphanSelectionEnd = source.indexOf("function cursorFromPendingRow");
  const orphanSelection = source.slice(orphanSelectionStart, orphanSelectionEnd);
  assert.match(orphanSelection, /d\.chain_pending_lease_id IS NOT NULL\)/);
  assert.doesNotMatch(orphanSelection, /chain_pending_expires_at/);
  assert.doesNotMatch(orphanSelection, /NOT EXISTS/);

  const quarantineStart = source.indexOf("async function quarantineOrphanArtifact");
  const quarantineEnd = source.indexOf("function exactPattern", quarantineStart);
  const quarantine = source.slice(quarantineStart, quarantineEnd);
  assert.match(quarantine, /d\.chain_pending_lease_id IS NOT NULL\)/);
  assert.doesNotMatch(quarantine, /chain_pending_expires_at/);
  assert.match(quarantine, /created_at = \? AND unixepoch\(created_at\) <= unixepoch\(\?\)/);
  assert.match(quarantine, /exactBoundedText\(row\.created_at, 32, "orphan creation time"\)/);
  assert.doesNotMatch(quarantine, /canonicalTextInstant\(row\.created_at/);
  assert.equal((quarantine.match(/NOT EXISTS \(SELECT 1 FROM capture_devices/g) ?? []).length, 2);
});

test("the scheduled worker isolates the native reconciliation domain", async () => {
  const jobs = await read("lib/server/jobs.ts");
  assert.match(jobs, /reconcileNativeProvenanceOrphans/);
  assert.match(jobs, /isolate\("native_provenance_reconciliation"/);
  assert.ok(jobs.indexOf("native_provenance_reconciliation") < jobs.indexOf("audit_checkpoint"));
});
