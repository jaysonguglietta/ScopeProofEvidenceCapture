import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const schemaPath = new URL("../infra/aws/database/001_tenant_schema.sql", import.meta.url);
const grantsPath = new URL("../infra/aws/database/002_runtime_role.sql", import.meta.url);

function tableBody(sql: string, table: string): string {
  const match = sql.match(new RegExp(`CREATE TABLE scopeproof\\.${table} \\(([\\s\\S]*?)\\n\\);`));
  assert.ok(match, `missing ${table} table`);
  return match[1];
}

test("AWS PostgreSQL schema has a per-database tenant guard and forced RLS", async () => {
  const sql = await readFile(schemaPath, "utf8");
  const tenantTables = [
    "principals", "memberships", "tenant_domains", "device_enrollments",
    "assessments", "integrations", "jobs", "upload_intents",
    "evidence_artifacts", "ingest_receipts", "retention_holds",
    "audit_heads", "audit_events", "export_receipts", "support_access_grants",
  ];

  for (const table of tenantTables) {
    assert.match(tableBody(sql, table), /tenant_id scopeproof\.tenant_identifier NOT NULL/);
    assert.match(sql, new RegExp(`'${table}'`), `${table} must be in the policy/trigger list`);
  }
  assert.match(sql, /ALTER TABLE scopeproof\.%I ENABLE ROW LEVEL SECURITY/);
  assert.match(sql, /ALTER TABLE scopeproof\.%I FORCE ROW LEVEL SECURITY/);
  assert.match(sql, /FOREIGN KEY \(tenant_id\) REFERENCES scopeproof\.tenant_identity \(tenant_id\) ON DELETE RESTRICT/);
  assert.match(sql, /tenant_id = scopeproof\.current_tenant_id\(\)/);
  assert.match(sql, /CREATE TRIGGER enforce_database_tenant/);
  assert.match(sql, /SELECT tenant_id, quarantine_bucket, evidence_bucket, evidence_kms_key_arn, retention_mode[\s\S]*INTO STRICT expected_tenant[\s\S]*FROM scopeproof\.tenant_identity[\s\S]*WHERE singleton/);
  assert.match(sql, /RAISE EXCEPTION 'tenant boundary violation'/);
  assert.match(sql, /RAISE EXCEPTION 'quarantine destination violation'/);
  assert.match(sql, /RAISE EXCEPTION 'evidence destination violation'/);
  assert.match(sql, /RAISE EXCEPTION 'receipt encryption key violation'/);
  assert.match(sql, /CREATE TABLE scopeproof\.schema_migrations/);
  assert.match(sql, /VALUES \(1, 'tenant_security_baseline'\)/);
});

test("tenant relationships and uniqueness include tenant identity", async () => {
  const sql = await readFile(schemaPath, "utf8");
  assert.match(tableBody(sql, "memberships"), /FOREIGN KEY \(tenant_id, principal_id\)/);
  assert.match(tableBody(sql, "memberships"), /role IN \('admin', 'compliance_lead', 'reviewer', 'auditor', 'collector'\)/);
  assert.match(tableBody(sql, "jobs"), /UNIQUE \(tenant_id, idempotency_key\)/);
  assert.match(tableBody(sql, "jobs"), /revision integer NOT NULL DEFAULT 0/);
  assert.match(tableBody(sql, "jobs"), /status = 'leased'/);
  assert.match(tableBody(sql, "jobs"), /available_at timestamptz NOT NULL/);
  assert.match(tableBody(sql, "evidence_artifacts"), /UNIQUE \(tenant_id, assessment_id, checksum_sha256, source, control_id\)/);
  assert.match(tableBody(sql, "upload_intents"), /UNIQUE \(tenant_id, nonce_digest\)/);
  assert.match(tableBody(sql, "upload_intents"), /UNIQUE \(tenant_id, object_key\)/);
  assert.match(tableBody(sql, "ingest_receipts"), /UNIQUE \(tenant_id, upload_intent_id\)/);
});

test("upload and immutable-evidence constraints fail closed", async () => {
  const sql = await readFile(schemaPath, "utf8");
  const intents = tableBody(sql, "upload_intents");
  const evidence = tableBody(sql, "evidence_artifacts");
  const receipts = tableBody(sql, "ingest_receipts");
  assert.match(intents, /content_length BETWEEN 1 AND 26214400/);
  assert.match(intents, /checksum_sha256 ~ '\^\[0-9a-f\]\{64\}\$'/);
  assert.match(intents, /expires_at <= created_at \+ interval '10 minutes'/);
  assert.match(intents, /required_retention_until > expires_at/);
  assert.match(intents, /status IN \('issued', 'quarantined', 'validated', 'promoted', 'rejected', 'expired'\)/);
  assert.match(intents, /revision integer NOT NULL DEFAULT 0/);
  assert.match(intents, /object_key ~ '\^tenants\/ten_/);
  assert.match(evidence, /object_version_id IS NOT NULL/);
  assert.match(evidence, /object_lock_mode IS NOT NULL/);
  assert.match(evidence, /retain_until IS NOT NULL/);
  assert.match(evidence, /retain_until IS NULL OR retain_until >= expires_at/);
  assert.match(evidence, /approved_by IS NULL OR approved_by <> created_by/);
  assert.match(receipts, /malware_status = 'CLEAN'/);
  assert.match(receipts, /receipt_sha256/);
  assert.match(receipts, /signature text NOT NULL/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.protect_immutable_security_fields/);
  assert.match(sql, /upload intent immutable field violation/);
  assert.match(sql, /evidence metadata immutable field violation/);
  assert.match(sql, /upload intent state transition violation/);
  assert.match(sql, /job state transition violation/);
  assert.match(sql, /evidence state transition violation/);
  assert.match(sql, /CREATE TRIGGER protect_immutable_fields BEFORE UPDATE/);
});

test("legal/support access requires dual control and expires quickly", async () => {
  const sql = await readFile(schemaPath, "utf8");
  assert.match(tableBody(sql, "retention_holds"), /created_by <> approved_by/);
  assert.match(tableBody(sql, "support_access_grants"), /expires_at <= starts_at \+ interval '4 hours'/);
  assert.match(tableBody(sql, "support_access_grants"), /ticket_reference/);
  assert.match(tableBody(sql, "support_access_grants"), /approved_by/);
});

test("audit persistence matches the canonical hash-chain contract", async () => {
  const sql = await readFile(schemaPath, "utf8");
  const audit = tableBody(sql, "audit_events");
  const head = tableBody(sql, "audit_heads");
  assert.match(audit, /sequence bigint NOT NULL CHECK \(sequence > 0\)/);
  assert.doesNotMatch(audit, /IDENTITY|SERIAL/i);
  assert.match(audit, /request_id text NOT NULL/);
  assert.match(audit, /outcome IN \('succeeded', 'denied', 'failed'\)/);
  assert.match(audit, /previous_hash = 'GENESIS'/);
  assert.match(audit, /\(sequence = 1\) = \(previous_hash = 'GENESIS'\)/);
  assert.match(audit, /kms_signature text NOT NULL/);
  assert.match(head, /sequence bigint NOT NULL DEFAULT 0/);
  assert.match(head, /event_hash text NOT NULL DEFAULT 'GENESIS'/);
  assert.match(head, /\(sequence = 0\) = \(event_hash = 'GENESIS'\)/);
  assert.match(sql, /SELECT sequence, event_hash[\s\S]*FROM scopeproof\.audit_heads[\s\S]*FOR UPDATE/);
  assert.match(sql, /NEW\.sequence IS DISTINCT FROM current_sequence \+ 1/);
  assert.match(sql, /NEW\.previous_hash IS DISTINCT FROM current_hash/);
  assert.match(sql, /CREATE TRIGGER append_audit_chain/);
});

test("runtime database role is non-owner, forced-RLS, and has no destructive grants", async () => {
  const [sql, schema] = await Promise.all([
    readFile(grantsPath, "utf8"),
    readFile(schemaPath, "utf8"),
  ]);
  assert.match(sql, /rolsuper/);
  assert.match(sql, /rolbypassrls/);
  assert.match(sql, /ALTER ROLE %I SET row_security = on/);
  assert.match(sql, /statement_timeout/);
  assert.match(sql, /idle_in_transaction_session_timeout/);
  assert.doesNotMatch(sql, /GRANT[^;]*\bDELETE\b/i);
  assert.doesNotMatch(sql, /GRANT[^;]*\bTRUNCATE\b/i);
  assert.doesNotMatch(sql, /GRANT[^;]*UPDATE[^;]*audit_heads/i);
  assert.doesNotMatch(sql, /GRANT[^;]*UPDATE[^;]*ingest_receipts/i);
  assert.doesNotMatch(sql, /GRANT[^;]*tenant_identity[^;]*(?:INSERT|UPDATE)/i);
  assert.match(schema, /REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof FROM PUBLIC/);
});
