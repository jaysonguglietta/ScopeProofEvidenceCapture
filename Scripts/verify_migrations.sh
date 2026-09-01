#!/bin/sh
set -eu

database="$(mktemp "${TMPDIR:-/tmp}/scopeproof-migrations.XXXXXX")"
trap 'rm -f "$database"' EXIT HUP INT TERM

for migration in \
  drizzle/0000_curvy_risque.sql \
  drizzle/0001_sloppy_stark_industries.sql \
  drizzle/0003_fine_wonder_man.sql \
  drizzle/0003_cooing_rhino.sql \
  drizzle/0004_cheerful_tombstone.sql \
  drizzle/0005_nappy_alice.sql \
  drizzle/0006_first_madelyne_pryor.sql \
  drizzle/0007_greedy_nextwave.sql \
  drizzle/0008_real_nebula.sql \
  drizzle/0009_chubby_martin_li.sql \
  drizzle/0010_tearful_goblin_queen.sql \
  drizzle/0011_easy_vision.sql \
  drizzle/0012_opposite_rachel_grey.sql
do
  test -f "$migration"
  sqlite3 "$database" ".read $migration"
done

# Exercise the production upgrade path, not only an empty database. SQLite
# rejects several otherwise-valid-looking ALTER defaults once rows exist, and
# legacy NULL assessment scopes legitimately permit the same digest in two
# systems.
sqlite3 "$database" <<'SQL'
INSERT INTO users (id, email, display_name, role) VALUES ('usr_upgrade', 'upgrade@example.invalid', 'Upgrade Fixture', 'admin');
INSERT INTO capture_devices (id, display_name, token_hash, owner_id, created_at)
VALUES ('dev_upgrade', 'Existing Mac', 'fixture-token-hash', 'usr_upgrade', '2026-01-01T00:00:00.000Z');
INSERT INTO evidence_artifacts
  (id, control_id, title, type, source, system, r2_key, content_type, byte_size, sha256, encryption_iv,
   captured_at, expires_at, created_by, assessment_id, framework)
VALUES
  ('ev_upgrade_a', '8.3.1', 'System A evidence', 'report', 'fixture', 'system-a', 'fixture/a',
   'application/json', 2, 'same-digest', 'fixture-iv', '2026-01-01T00:00:00.000Z', '2027-01-01T00:00:00.000Z',
   'usr_upgrade', NULL, 'PCI DSS 4.0.1'),
  ('ev_upgrade_b', '8.3.1', 'System B evidence', 'report', 'fixture', 'system-b', 'fixture/b',
   'application/json', 2, 'same-digest', 'fixture-iv', '2026-01-01T00:00:00.000Z', '2027-01-01T00:00:00.000Z',
   'usr_upgrade', NULL, 'PCI DSS 4.0.1');
SQL

for migration in \
  drizzle/0013_light_toad_men.sql \
  drizzle/0014_loving_plazm.sql \
  drizzle/0015_flat_magus.sql \
  drizzle/0016_loose_owl.sql \
  drizzle/0017_demonic_firedrake.sql \
  drizzle/0018_stale_freak.sql \
  drizzle/0019_audited_cas_guard.sql \
  drizzle/0020_native_device_chain.sql \
  drizzle/0021_immutable_checkpoint_receipts.sql \
  drizzle/0022_native_provenance_quarantine.sql \
  drizzle/0023_independent_image_safety.sql \
  drizzle/0024_big_chamber.sql
do
  test -f "$migration"
  sqlite3 "$database" ".read $migration"
done

test "$(sqlite3 "$database" 'PRAGMA integrity_check;')" = "ok"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('assessments','audit_batch_guards','audit_checkpoints','control_catalogs','evidence_artifacts','evidence_occurrences','evidence_review_events','findings','finding_events','retention_hold_release_requests','sbom_jobs');")" = "11"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM capture_devices WHERE id = 'dev_upgrade' AND token_issued_at IS NOT NULL AND token_expires_at > token_issued_at;")" = "1"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM capture_devices WHERE id = 'dev_upgrade' AND chain_sequence = 0 AND chain_event_hash = 'GENESIS' AND provenance_key_id IS NULL;")" = "1"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM evidence_artifacts WHERE id IN ('ev_upgrade_a','ev_upgrade_b') AND status = 'needs_review';")" = "2"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM evidence_occurrences WHERE artifact_id IN ('ev_upgrade_a','ev_upgrade_b');")" = "2"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('evidence_occurrences') WHERE name = 'last_review_event_id';")" = "1"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('retention_hold_release_requests') WHERE name IN ('hold_owner_id','hold_reason','hold_expires_at') AND \"notnull\" = 1;")" = "3"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM audit_batch_guards;")" = "0"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('audit_checkpoints_no_update','audit_checkpoints_no_delete');")" = "2"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('native_evidence_manifests_no_update','native_evidence_manifests_no_delete');")" = "2"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('native_evidence_manifests') WHERE name IN ('chain_sequence','chain_event_hash','provenance_key_id');")" = "3"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('evidence_artifacts') WHERE name IN ('server_safety_scan_sha256','server_safety_scan_policy','server_safety_scan_completed_at','server_safety_scanner_origin','server_safety_receipt_sha256');")" = "5"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM control_catalogs WHERE id = 'pci-dss-4.0.1-scopeproof-operations-v1' AND digest_sha256 = 'dd51b71a3ccbc0ddbcdb12a519ee8c1d5b9f6728323b3b621cbc165aa5c50abd';")" = "1"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('assessments') WHERE name IN ('catalog_id','scope_mode');")" = "2"
echo "Populated migration replay and integrity check passed."
