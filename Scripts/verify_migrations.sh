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
  drizzle/0024_big_chamber.sql \
  drizzle/0025_pink_malice.sql \
  drizzle/0026_omniscient_scarlet_witch.sql \
  drizzle/0027_lonely_guardian.sql
do
  test -f "$migration"
  sqlite3 "$database" ".read $migration"
done

test "$(sqlite3 "$database" 'PRAGMA integrity_check;')" = "ok"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('assessments','audit_batch_guards','audit_checkpoint_delivery_attempts','audit_checkpoint_delivery_retry_state','audit_checkpoints','control_catalogs','evidence_artifacts','evidence_occurrences','evidence_review_events','findings','finding_events','key_rotation_attempts','retention_hold_release_requests','sbom_jobs');")" = "14"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM capture_devices WHERE id = 'dev_upgrade' AND token_issued_at IS NOT NULL AND token_expires_at > token_issued_at;")" = "1"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM capture_devices WHERE id = 'dev_upgrade' AND chain_sequence = 0 AND chain_event_hash = 'GENESIS' AND provenance_key_id IS NULL;")" = "1"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM evidence_artifacts WHERE id IN ('ev_upgrade_a','ev_upgrade_b') AND status = 'needs_review';")" = "2"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM evidence_occurrences WHERE artifact_id IN ('ev_upgrade_a','ev_upgrade_b');")" = "2"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('evidence_occurrences') WHERE name = 'last_review_event_id';")" = "1"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('retention_hold_release_requests') WHERE name IN ('hold_owner_id','hold_reason','hold_expires_at') AND \"notnull\" = 1;")" = "3"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM audit_batch_guards;")" = "0"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('audit_checkpoints_no_update','audit_checkpoints_no_delete');")" = "2"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('audit_checkpoint_delivery_attempts_no_update','audit_checkpoint_delivery_attempts_no_delete');")" = "2"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('native_evidence_manifests_no_update','native_evidence_manifests_no_delete');")" = "2"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('native_evidence_manifests') WHERE name IN ('chain_sequence','chain_event_hash','provenance_key_id');")" = "3"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('evidence_artifacts') WHERE name IN ('server_safety_scan_sha256','server_safety_scan_policy','server_safety_scan_completed_at','server_safety_scanner_origin','server_safety_receipt_sha256');")" = "5"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM control_catalogs WHERE id = 'pci-dss-4.0.1-scopeproof-operations-v1' AND digest_sha256 = 'dd51b71a3ccbc0ddbcdb12a519ee8c1d5b9f6728323b3b621cbc165aa5c50abd';")" = "1"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('assessments') WHERE name IN ('catalog_id','scope_mode');")" = "2"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('key_rotation_attempts') WHERE name IN ('resource_type','resource_id','attempt_count','status','next_attempt_at','last_error_code','first_failed_at','last_attempt_at','last_attempt_id','resolved_at');")" = "10"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM pragma_table_info('audit_checkpoint_delivery_retry_state') WHERE name IN ('checkpoint_id','checkpoint_sha256','status','attempt_count','next_attempt_at','lease_id','lease_expires_at','endpoint_origin','last_attempt_id','last_attempt_at','last_failure_code','delivered_attempt_id','created_at','updated_at');")" = "14"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name IN ('audit_checkpoint_delivery_retry_state_checkpoint_binding','audit_checkpoint_delivery_retry_state_identity_immutable','audit_checkpoint_delivery_retry_state_delivered_terminal','audit_checkpoint_delivery_retry_state_no_delete','audit_checkpoint_delivery_attempts_require_active_claim','audit_checkpoint_delivery_attempts_complete_claim');")" = "6"

sqlite3 "$database" <<'SQL'
INSERT INTO audit_checkpoints
  (id, sequence, event_hash, event_count, hmac_key_id, checkpoint_sha256, signature, public_key_fingerprint, r2_key, external_status, created_at)
VALUES
  ('checkpoint_retry_fixture', 9001, 'event-hash', 1, 'audit-v1', 'checkpoint-sha', 'signature', 'key-fingerprint', 'audit-checkpoints/fixture.json', 'not_configured', '2026-01-01T00:00:00.000Z');
INSERT INTO audit_checkpoint_delivery_retry_state
  (checkpoint_id, checkpoint_sha256, status, attempt_count, next_attempt_at, lease_id, lease_expires_at,
   endpoint_origin, last_attempt_id, last_attempt_at, created_at, updated_at)
VALUES
  ('checkpoint_retry_fixture', 'checkpoint-sha', 'claimed', 1, '2026-01-01T00:02:00.000Z', 'lease-1',
   '2026-01-01T00:01:30.000Z', 'https://witness.example', 'checkpoint_delivery_failed_fixture',
   '2026-01-01T00:01:00.000Z', '2026-01-01T00:00:00.000Z', '2026-01-01T00:01:00.000Z');
INSERT INTO audit_checkpoint_delivery_attempts
  (id, checkpoint_id, checkpoint_sha256, sequence, endpoint_origin, attempted_at, status, failure_code, created_at)
VALUES
  ('checkpoint_delivery_failed_fixture', 'checkpoint_retry_fixture', 'checkpoint-sha', 9001, 'https://witness.example', '2026-01-01T00:01:00.000Z', 'failed', 'DELIVERY_REQUEST_FAILED', '2026-01-01T00:01:01.000Z');
UPDATE audit_checkpoint_delivery_retry_state
SET status = 'claimed', attempt_count = 2, next_attempt_at = '2026-01-01T00:04:00.000Z', lease_id = 'lease-2',
  lease_expires_at = '2026-01-01T00:03:30.000Z', endpoint_origin = 'https://witness.example',
  last_attempt_id = 'checkpoint_delivery_success_fixture', last_attempt_at = '2026-01-01T00:02:00.000Z',
  updated_at = '2026-01-01T00:02:00.000Z'
WHERE checkpoint_id = 'checkpoint_retry_fixture' AND status = 'retrying' AND attempt_count = 1;
INSERT INTO audit_checkpoint_delivery_attempts
  (id, checkpoint_id, checkpoint_sha256, sequence, endpoint_origin, attempted_at, status, external_receipt, external_receipt_sha256, external_receipt_signature, external_receipt_r2_key, created_at)
VALUES
  ('checkpoint_delivery_success_fixture', 'checkpoint_retry_fixture', 'checkpoint-sha', 9001, 'https://witness.example', '2026-01-01T00:02:00.000Z', 'delivered', '{}', 'receipt-sha', 'receipt-signature', 'audit-checkpoints/fixture.external-receipt.json', '2026-01-01T00:02:01.000Z');
SQL

test "$(sqlite3 "$database" "SELECT COUNT(*) FROM audit_checkpoint_delivery_attempts WHERE checkpoint_id = 'checkpoint_retry_fixture' AND status = 'failed';")" = "1"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM audit_checkpoint_delivery_attempts WHERE checkpoint_id = 'checkpoint_retry_fixture' AND status = 'delivered';")" = "1"
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM audit_checkpoint_delivery_retry_state WHERE checkpoint_id = 'checkpoint_retry_fixture' AND status = 'delivered' AND attempt_count = 2 AND delivered_attempt_id = 'checkpoint_delivery_success_fixture' AND lease_id IS NULL;")" = "1"
if sqlite3 "$database" "INSERT INTO audit_checkpoint_delivery_attempts (id, checkpoint_id, checkpoint_sha256, sequence, endpoint_origin, attempted_at, status, external_receipt, external_receipt_sha256, external_receipt_signature, external_receipt_r2_key) VALUES ('checkpoint_delivery_duplicate', 'checkpoint_retry_fixture', 'checkpoint-sha', 9001, 'https://witness.example', '2026-01-01T00:03:00.000Z', 'delivered', '{}', 'receipt-sha-2', 'receipt-signature-2', 'audit-checkpoints/fixture-2.external-receipt.json');" 2>/dev/null; then
  echo "A checkpoint accepted more than one delivered attempt." >&2
  exit 1
fi
if sqlite3 "$database" "UPDATE audit_checkpoint_delivery_attempts SET failure_code = 'CHANGED' WHERE id = 'checkpoint_delivery_failed_fixture';" 2>/dev/null; then
  echo "A checkpoint delivery attempt was mutable." >&2
  exit 1
fi
if sqlite3 "$database" "DELETE FROM audit_checkpoint_delivery_attempts WHERE id = 'checkpoint_delivery_failed_fixture';" 2>/dev/null; then
  echo "A checkpoint delivery attempt was deletable." >&2
  exit 1
fi
if sqlite3 "$database" "INSERT INTO audit_checkpoint_delivery_attempts (id, checkpoint_id, checkpoint_sha256, sequence, endpoint_origin, attempted_at, status, failure_code, external_receipt) VALUES ('checkpoint_delivery_bad_shape', 'checkpoint_retry_fixture', 'checkpoint-sha', 9001, 'https://witness.example', '2026-01-01T00:04:00.000Z', 'failed', 'DELIVERY_REQUEST_FAILED', '{}');" 2>/dev/null; then
  echo "A malformed checkpoint delivery attempt bypassed the shape constraint." >&2
  exit 1
fi
if sqlite3 "$database" "DELETE FROM audit_checkpoint_delivery_retry_state WHERE checkpoint_id = 'checkpoint_retry_fixture';" 2>/dev/null; then
  echo "Checkpoint delivery retry state was deletable." >&2
  exit 1
fi
if sqlite3 "$database" "UPDATE audit_checkpoint_delivery_retry_state SET checkpoint_sha256 = 'changed' WHERE checkpoint_id = 'checkpoint_retry_fixture';" 2>/dev/null; then
  echo "Checkpoint delivery retry identity was mutable." >&2
  exit 1
fi

sqlite3 "$database" <<'SQL'
INSERT INTO key_rotation_attempts
  (resource_type, resource_id, attempt_count, status, next_attempt_at, last_error_code, first_failed_at, last_attempt_at, last_attempt_id)
VALUES
  ('evidence', 'ev_upgrade_a', 1, 'retrying', '2026-01-01T00:10:00.000Z', 'MISSING_OBJECT', '2026-01-01T00:00:00.000Z', '2026-01-01T00:00:00.000Z', 'attempt_fixture_1');
UPDATE key_rotation_attempts
SET attempt_count = 5, status = 'action_required', next_attempt_at = '2026-01-02T00:00:00.000Z', last_attempt_at = '2026-01-01T01:00:00.000Z', last_attempt_id = 'attempt_fixture_5'
WHERE resource_type = 'evidence' AND resource_id = 'ev_upgrade_a';
UPDATE key_rotation_attempts
SET status = 'resolved', next_attempt_at = NULL, resolved_at = '2026-01-01T02:00:00.000Z', last_attempt_at = '2026-01-01T02:00:00.000Z'
WHERE resource_type = 'evidence' AND resource_id = 'ev_upgrade_a';
SQL
test "$(sqlite3 "$database" "SELECT COUNT(*) FROM key_rotation_attempts WHERE resource_type = 'evidence' AND resource_id = 'ev_upgrade_a' AND attempt_count = 5 AND status = 'resolved' AND next_attempt_at IS NULL AND resolved_at IS NOT NULL;")" = "1"
if sqlite3 "$database" "INSERT INTO key_rotation_attempts (resource_type, resource_id, attempt_count, status, next_attempt_at, last_error_code, first_failed_at, last_attempt_at, last_attempt_id) VALUES ('package', 'bad', 0, 'retrying', NULL, 'MISSING_OBJECT', '2026-01-01', '2026-01-01', 'bad_attempt');" 2>/dev/null; then
  echo "Malformed key-rotation retry state bypassed its constraints." >&2
  exit 1
fi
if sqlite3 "$database" "INSERT INTO key_rotation_attempts (resource_type, resource_id, attempt_count, status, next_attempt_at, last_error_code, first_failed_at, last_attempt_at, last_attempt_id) VALUES ('package', 'unbounded', 1000001, 'action_required', '2026-01-02', 'MISSING_OBJECT', '2026-01-01', '2026-01-01', 'unbounded_attempt');" 2>/dev/null; then
  echo "An unbounded key-rotation attempt count bypassed its constraint." >&2
  exit 1
fi
if sqlite3 "$database" "INSERT INTO key_rotation_attempts (resource_type, resource_id, attempt_count, status, next_attempt_at, last_error_code, first_failed_at, last_attempt_at, last_attempt_id) VALUES ('unknown', 'bad_type', 1, 'retrying', '2026-01-02', 'MISSING_OBJECT', '2026-01-01', '2026-01-01', 'bad_type_attempt');" 2>/dev/null; then
  echo "An unknown key-rotation resource type bypassed its allowlist." >&2
  exit 1
fi
if sqlite3 "$database" "INSERT INTO key_rotation_attempts (resource_type, resource_id, attempt_count, status, next_attempt_at, last_error_code, first_failed_at, last_attempt_at, last_attempt_id) VALUES ('package', 'bad_error', 1, 'retrying', '2026-01-02', 'RAW_PROVIDER_MESSAGE', '2026-01-01', '2026-01-01', 'bad_error_attempt');" 2>/dev/null; then
  echo "An unknown key-rotation error code bypassed its allowlist." >&2
  exit 1
fi
echo "Populated migration replay and integrity check passed."
