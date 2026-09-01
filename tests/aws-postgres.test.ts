import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const schemaPath = new URL("../infra/aws/database/001_tenant_schema.sql", import.meta.url);
const grantsPath = new URL("../infra/aws/database/002_runtime_role.sql", import.meta.url);
const ingestGrantsPath = new URL("../infra/aws/database/003_ingest_role.sql", import.meta.url);
const controlGrantsPath = new URL("../infra/aws/database/004_evidence_control_role.sql", import.meta.url);
const legalApiGrantsPath = new URL("../infra/aws/database/005_legal_hold_api_role.sql", import.meta.url);
const readGrantsPath = new URL("../infra/aws/database/007_evidence_read_role.sql", import.meta.url);
const apiAuditSignerGrantsPath = new URL("../infra/aws/database/008_api_audit_signer_role.sql", import.meta.url);
const evidenceAccessPath = new URL("../infra/aws/database/006_evidence_access_api.sql", import.meta.url);
const runtimeHardeningPath = new URL("../infra/aws/database/009_runtime_hardening.sql", import.meta.url);
const rejectionReconcilerPath = new URL("../infra/aws/cdk/runtime/reconcile-rejected-evidence/index.mjs", import.meta.url);
const tenantStackPath = new URL("../infra/aws/cdk/lib/tenant-stack.ts", import.meta.url);

function tableBody(sql: string, table: string): string {
  const match = sql.match(new RegExp(`CREATE TABLE scopeproof\\.${table} \\(([\\s\\S]*?)\\n\\);`));
  assert.ok(match, `missing ${table} table`);
  return match[1];
}

function functionBody(sql: string, name: string): string {
  const match = sql.match(new RegExp(`CREATE FUNCTION scopeproof\\.${name}\\([\\s\\S]*?\\n\\$\\$;`));
  assert.ok(match, `missing ${name} function`);
  return match[0];
}

test("AWS PostgreSQL schema has a per-database tenant guard and forced RLS", async () => {
  const sql = await readFile(schemaPath, "utf8");
  const tenantTables = [
    "principals", "memberships", "tenant_domains", "device_enrollments",
    "assessments", "integrations", "jobs", "upload_intents",
    "evidence_artifacts", "ingest_receipts", "retention_holds", "legal_hold_operations",
    "audit_heads", "audit_events", "api_audit_outbox", "api_audit_outbox_work",
    "export_receipts", "support_access_grants",
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
  assert.match(sql, /SELECT tenant_id, quarantine_bucket, evidence_bucket, evidence_kms_key_arn, audit_signing_key_arn, retention_mode[\s\S]*INTO STRICT expected_tenant[\s\S]*FROM scopeproof\.tenant_identity[\s\S]*WHERE singleton/);
  assert.match(sql, /RAISE EXCEPTION 'tenant boundary violation'/);
  assert.match(sql, /RAISE EXCEPTION 'quarantine destination violation'/);
  assert.match(sql, /RAISE EXCEPTION 'evidence destination violation'/);
  assert.match(sql, /RAISE EXCEPTION 'receipt encryption key violation'/);
  assert.match(sql, /RAISE EXCEPTION 'audit signing key violation'/);
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
  assert.match(receipts, /canonical_receipt text NOT NULL/);
  assert.match(receipts, /signing_key_arn text NOT NULL/);
  assert.match(receipts, /signing_algorithm text NOT NULL CHECK \(signing_algorithm = 'RSASSA_PSS_SHA_256'\)/);
  assert.match(receipts, /signature text NOT NULL/);
  assert.match(receipts, /char_length\(signature\) = 512/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.protect_immutable_security_fields/);
  assert.match(sql, /upload intent immutable field violation/);
  assert.match(sql, /evidence metadata immutable field violation/);
  assert.match(sql, /promotion receipt immutable field violation/);
  assert.match(sql, /upload intent state transition violation/);
  assert.match(sql, /job state transition violation/);
  assert.match(sql, /evidence state transition violation/);
  assert.match(sql, /CREATE TRIGGER protect_immutable_fields BEFORE UPDATE/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.create_upload_intent/);
  assert.match(sql, /p_captured_at \+ make_interval\(days => configured_retention_days\)/);
  assert.match(sql, /closed assessments cannot accept evidence/);
  assert.match(sql, /jsonb_array_length\(assessment_controls\) = 0/);
  assert.match(sql, /assessment_controls \? p_control_id/);
  assert.match(sql, /FOR SHARE/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.reconcile_promoted_evidence/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.claim_promotion_fence/);
  assert.match(sql, /p_promotion_fence IS NULL OR p_promotion_fence < 1/);
  assert.match(sql, /\(p_promotion_facts ->> 'copyFence'\) IS NULL/);
  assert.match(sql, /\(p_promotion_facts ->> 'promotionFence'\) IS NULL/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.read_promoted_evidence_receipt/);
  assert.match(sql, /committed_canonical_receipt[\s\S]*committed_receipt_sha256[\s\S]*committed_signature[\s\S]*committed_signed_at/);
  assert.match(sql, /scopeproof-promotion-receipt-v1'[\s\S]*p_canonical_receipt[\s\S]*p_receipt_sha256/);
  assert.match(sql, /promotion reconciliation idempotency conflict/);
  assert.match(sql, /FOR UPDATE/);
  assert.match(tableBody(sql, "device_enrollments"), /last_upload_sequence bigint NOT NULL DEFAULT 0 CHECK \(last_upload_sequence >= 0\)/);
  assert.match(sql, /p_captured_at < clock_timestamp\(\) - interval '30 days'/);
  assert.match(sql, /device_proof := p_metadata -> 'scopeproofDeviceProof'/);
  assert.match(sql, /device_sequence <= device_last_upload_sequence/);
  assert.match(sql, /SET last_upload_sequence = device_sequence/);
});

test("rejected evidence reconciliation recovers a DynamoDB-first partial commit after 24 hours", async () => {
  const [sql, reconciler, tenantStack] = await Promise.all([
    readFile(runtimeHardeningPath, "utf8"),
    readFile(rejectionReconcilerPath, "utf8"),
    readFile(tenantStackPath, "utf8"),
  ]);
  const reconcile = functionBody(sql, "reconcile_rejected_evidence");
  const existingReceiptLookup = reconcile.indexOf("SELECT * INTO existing FROM scopeproof.rejected_ingest_receipts");
  const exactReplayReturn = reconcile.indexOf("RETURN QUERY SELECT existing.id, false");
  const recoveryAgeGate = reconcile.indexOf("p_rejected_at < clock_timestamp() - interval '14 days'");

  assert.ok(existingReceiptLookup >= 0 && exactReplayReturn > existingReceiptLookup);
  assert.ok(
    recoveryAgeGate > exactReplayReturn,
    "an exact durable receipt replay must be resolved before applying the new-commit age gate",
  );
  assert.match(reconcile, /p_canonical_receipt::jsonb IS DISTINCT FROM p_rejection_facts/);
  assert.match(reconcile, /scopeproof-ingest-rejection-v1/);
  assert.match(reconcile, /\(p_rejection_facts ->> 'rejectedAt'\)::timestamptz IS DISTINCT FROM p_rejected_at/);
  assert.match(reconcile, /existing\.rejected_at IS DISTINCT FROM p_rejected_at/);
  assert.doesNotMatch(reconcile, /interval '24 hours'/);
  assert.match(reconciler, /const rejectedAt = intent\.rejectionReceipt\?\.rejectedAt \?\? new Date\(\)\.toISOString\(\)/);
  assert.match(reconciler, /assertSameReceipt\(intent\.rejectionReceipt/);
  assert.match(tenantStack, /"IngestDeadLetterQueue"[\s\S]*?retentionPeriod: Duration\.days\(14\)/);
  assert.match(
    tenantStack,
    /"RejectedEvidenceQueue"[\s\S]*?deadLetterQueue: \{ maxReceiveCount: 5, queue: this\.ingestDeadLetterQueue \}/,
  );

  const recoveryDays = Number(
    reconcile.match(/p_rejected_at < clock_timestamp\(\) - interval '(\d+) days'/)?.[1],
  );
  const partialCommitReplayDelayMilliseconds = 25 * 60 * 60 * 1_000;
  assert.ok(partialCommitReplayDelayMilliseconds > 24 * 60 * 60 * 1_000);
  assert.ok(
    partialCommitReplayDelayMilliseconds < recoveryDays * 24 * 60 * 60 * 1_000,
    "a 25-hour durable partial-commit replay must remain within the database recovery window",
  );
});

test("public API audit events are actor-bound, idempotent, and immutable", async () => {
  const sql = await readFile(schemaPath, "utf8");
  const outbox = tableBody(sql, "api_audit_outbox");
  const record = functionBody(sql, "record_api_audit_event");
  assert.match(outbox, /membership_id scopeproof\.resource_identifier NOT NULL CHECK \(membership_id LIKE 'mem/);
  assert.match(outbox, /UNIQUE \(tenant_id, idempotency_key\)/);
  assert.match(outbox, /event_digest char\(64\) NOT NULL/);
  assert.match(record, /membership\.principal_id = p_actor_user_id/);
  assert.match(record, /membership\.status = 'ACTIVE'/);
  assert.match(record, /API audit idempotency key conflicts with different facts/);
  assert.match(record, /scopeproof-api-audit-outbox-v1/);
  assert.match(sql, /CREATE TRIGGER protect_api_audit_outbox[\s\S]*BEFORE UPDATE OR DELETE/);
  const work = tableBody(sql, "api_audit_outbox_work");
  assert.match(work, /attempt_count integer NOT NULL DEFAULT 0 CHECK \(attempt_count BETWEEN 0 AND 8\)/);
  assert.match(work, /CHECK \(\(lease_token IS NULL\) = \(lease_expires_at IS NULL\)\)/);
  assert.match(work, /dead_lettered_at timestamptz/);
  assert.match(work, /completed_at timestamptz/);
  assert.match(record, /INSERT INTO scopeproof\.api_audit_outbox_work/);
  const claim = functionBody(sql, "claim_next_api_audit_event");
  const fail = functionBody(sql, "record_api_audit_outbox_failure");
  const append = functionBody(sql, "append_signed_api_audit_event");
  const health = functionBody(sql, "read_api_audit_outbox_health");
  assert.match(claim, /FOR UPDATE OF work SKIP LOCKED/);
  assert.match(claim, /work\.attempt_count < 8/);
  assert.match(claim, /work\.lease_expires_at <= p_claimed_at/);
  assert.match(fail, /next_attempt_count >= 8/);
  assert.match(fail, /power\(2, least\(work\.attempt_count, 10\)\)/);
  assert.match(append, /expected_outbox_id := \('aob_' \|\| substr\(expected_outbox_digest, 1, 32\)\)/);
  assert.match(append, /queued\.id IS DISTINCT FROM expected_outbox_id/);
  assert.match(append, /signed API audit event does not match its immutable outbox row/);
  assert.match(append, /scopeproof\.append_signed_audit_event/);
  assert.match(append, /scopeproofMembershipId/);
  assert.match(append, /audit_event_id = p_event_id/);
  assert.match(health, /work\.completed_at IS NULL/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.requeue_dead_lettered_api_audit_event/);
});

test("legal/support access requires dual control and expires quickly", async () => {
  const sql = await readFile(schemaPath, "utf8");
  const holds = tableBody(sql, "retention_holds");
  const operations = tableBody(sql, "legal_hold_operations");
  assert.match(holds, /created_by <> approved_by/);
  assert.match(holds, /release_requested_by <> release_approved_by/);
  assert.match(holds, /provider_verify_request_id text NOT NULL/);
  assert.match(holds, /evidence_bucket text NOT NULL/);
  assert.match(holds, /object_version_id text NOT NULL/);
  assert.match(sql, /CREATE UNIQUE INDEX active_retention_holds/);
  assert.match(sql, /an active retention hold already protects this exact version/);
  assert.match(operations, /operation_state IN \('REQUESTED', 'APPROVED', 'APPLYING', 'APPLIED', 'EXPIRED'\)/);
  assert.match(operations, /approved_by IS NULL OR requested_by <> approved_by/);
  assert.match(operations, /canonical_request text NOT NULL/);
  assert.match(operations, /request_digest char\(64\) NOT NULL/);
  assert.match(operations, /canonical_approval text/);
  assert.match(operations, /approval_digest char\(64\)/);
  assert.match(operations, /operation_state = 'REQUESTED' AND revision = 0/);
  assert.match(operations, /operation_state = 'APPROVED' AND revision = 1/);
  assert.match(operations, /operation_state = 'APPLYING' AND revision = 2/);
  assert.match(operations, /operation_state = 'APPLIED' AND revision = 3/);
  assert.match(operations, /operation_state = 'EXPIRED' AND revision = 1/);
  assert.match(operations, /expired_at >= changed_at \+ interval '24 hours'/);
  assert.match(operations, /reconciliation_attempt_count integer NOT NULL DEFAULT 0/);
  assert.match(operations, /reconciliation_next_attempt_at timestamptz/);
  assert.match(operations, /reconciliation_last_error_code text/);
  assert.match(operations, /canonical_receipt text/);
  assert.match(operations, /provider_verify_request_id text/);
  assert.match(sql, /CREATE UNIQUE INDEX one_pending_legal_hold_operation_per_version/);
  assert.match(sql, /WHERE operation_state IN \('REQUESTED', 'APPROVED', 'APPLYING'\)/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.reserve_exact_version_legal_hold/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.reserve_exact_version_legal_hold_with_audit/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.resolve_active_membership/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.approve_exact_version_legal_hold/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.approve_exact_version_legal_hold_with_audit/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.read_exact_version_legal_hold_operation/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.begin_exact_version_legal_hold_application/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.confirm_exact_version_legal_hold/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.expire_stale_exact_version_legal_hold_requests/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.list_unaudited_expired_legal_holds/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.record_exact_version_legal_hold_reconciliation_failure/);
  assert.match(sql, /scopeproof-legal-hold-request-v2/);
  assert.match(sql, /scopeproof-legal-hold-approval-v1/);
  assert.match(sql, /scopeproof-legal-hold-receipt-v1/);
  assert.match(sql, /S3 legal hold may be disabled only for the last active exact-version hold/);
  assert.match(sql, /PERFORM scopeproof\.assert_actor_permission\(p_requested_by, 'retention:manage'\)/);
  assert.match(sql, /PERFORM scopeproof\.assert_actor_permission\(p_approved_by, 'retention:manage'\)/);
  assert.match(sql, /requester cannot approve the same legal hold request/);
  assert.match(sql, /legal hold approval transition violation/);
  assert.match(sql, /legal hold expiry transition violation/);
  assert.match(sql, /operation_state = 'APPROVED'/);
  assert.match(sql, /legal hold operation transition violation/);
  assert.match(tableBody(sql, "support_access_grants"), /expires_at <= starts_at \+ interval '4 hours'/);
  assert.match(tableBody(sql, "support_access_grants"), /ticket_reference/);
  assert.match(tableBody(sql, "support_access_grants"), /approved_by/);
});

test("exact-version legal holds require durable, independently authorized request and approval phases", async () => {
  const sql = await readFile(schemaPath, "utf8");
  const reserve = functionBody(sql, "reserve_exact_version_legal_hold");
  const approve = functionBody(sql, "approve_exact_version_legal_hold");
  const auditedReserve = functionBody(sql, "reserve_exact_version_legal_hold_with_audit");
  const auditedApprove = functionBody(sql, "approve_exact_version_legal_hold_with_audit");
  const read = functionBody(sql, "read_exact_version_legal_hold_operation");
  const confirm = functionBody(sql, "confirm_exact_version_legal_hold");
  const expire = functionBody(sql, "expire_stale_exact_version_legal_hold_requests");
  const unauditedExpired = functionBody(sql, "list_unaudited_expired_legal_holds");
  const unauditedApplied = functionBody(sql, "list_unaudited_applied_legal_holds");
  const acknowledgeRecovery = functionBody(sql, "acknowledge_legal_hold_recovery_publication");
  const pending = functionBody(sql, "list_pending_exact_version_legal_holds");
  const retry = functionBody(sql, "record_exact_version_legal_hold_reconciliation_failure");

  assert.doesNotMatch(reserve, /p_approved_by/);
  assert.match(reserve, /PERFORM scopeproof\.assert_actor_permission\(p_requested_by, 'retention:manage'\)/);
  assert.match(reserve, /p_changed_at < clock_timestamp\(\) - interval '5 minutes'/);
  assert.ok(
    reserve.indexOf("IF FOUND THEN") < reserve.indexOf("p_changed_at < clock_timestamp() - interval '5 minutes'"),
    "exact durable request replay must be evaluated before new-transition clock skew",
  );
  assert.match(reserve, /'REQUESTED'/);
  assert.match(reserve, /scopeproof-legal-hold-request-v2/);
  assert.match(approve, /PERFORM scopeproof\.assert_actor_permission\(p_approved_by, 'retention:manage'\)/);
  assert.match(approve, /p_approved_by = requested_operation\.requested_by/);
  assert.match(approve, /p_approved_at < clock_timestamp\(\) - interval '5 minutes'/);
  assert.ok(
    approve.indexOf("requested_operation.operation_state IN ('APPROVED', 'APPLYING', 'APPLIED')") <
      approve.indexOf("p_approved_at < clock_timestamp() - interval '5 minutes'"),
    "exact durable approval replay must be evaluated before new-transition clock skew",
  );
  assert.match(approve, /requested_operation\.request_digest IS DISTINCT FROM p_request_digest/);
  assert.match(approve, /scopeproof-legal-hold-approval-v1/);
  assert.match(approve, /operation_state = 'APPROVED'/);
  assert.ok(
    auditedReserve.indexOf("scopeproof.reserve_exact_version_legal_hold(") <
      auditedReserve.indexOf("scopeproof.record_api_audit_event("),
    "the request transition must be followed by its audit record in one wrapper transaction",
  );
  assert.match(auditedReserve, /'evidence\.legal_hold_requested'/);
  assert.match(auditedReserve, /'legal-hold-request:' \|\| p_operation_id/);
  assert.ok(
    auditedApprove.indexOf("scopeproof.approve_exact_version_legal_hold(") <
      auditedApprove.indexOf("scopeproof.record_api_audit_event("),
    "the approval transition must be followed by its audit record in one wrapper transaction",
  );
  assert.match(auditedApprove, /'evidence\.legal_hold_approved'/);
  assert.match(auditedApprove, /'legal-hold-approval:' \|\| p_operation_id/);
  assert.doesNotMatch(read, /INSERT|UPDATE|DELETE/i);
  assert.match(read, /operation\.tenant_id = active_tenant/);
  assert.match(read, /operation\.request_digest = p_request_digest/);
  assert.match(confirm, /pending_operation\.approval_digest IS DISTINCT FROM p_approval_digest/);
  assert.match(confirm, /pending_operation\.operation_state <> 'APPLYING'/);
  assert.match(confirm, /operation_state = 'APPLYING'/);
  assert.doesNotMatch(confirm, /assert_actor_permission/);
  assert.match(expire, /operation\.operation_state = 'REQUESTED'/);
  assert.match(expire, /operation\.changed_at \+ interval '24 hours' <= p_now/);
  assert.match(expire, /FOR UPDATE SKIP LOCKED/);
  assert.match(expire, /LIMIT p_limit/);
  assert.doesNotMatch(expire, /APPROVED|APPLIED/);
  assert.match(unauditedExpired, /operation\.operation_state = 'EXPIRED'/);
  assert.match(unauditedExpired, /event\.action = 'evidence\.legal_hold_request_expired'/);
  assert.match(unauditedExpired, /NOT EXISTS/);
  assert.match(unauditedApplied, /operation\.recovery_published_at IS NULL/);
  assert.doesNotMatch(unauditedApplied, /NOT EXISTS[\s\S]*audit_events/);
  assert.match(acknowledgeRecovery, /operation\.operation_state = 'APPLIED'/);
  assert.match(acknowledgeRecovery, /scopeproof\.audit_events/);
  assert.match(acknowledgeRecovery, /operation\.recovery_published_at IS NULL/);
  assert.match(pending, /operation\.reconciliation_next_attempt_at <= clock_timestamp\(\)/);
  assert.match(retry, /operation\.operation_state IN \('APPROVED', 'APPLYING'\)/);
  assert.match(retry, /reconciliation_attempt_count = operation\.reconciliation_attempt_count \+ 1/);
  assert.match(retry, /power\(2, least\(operation\.reconciliation_attempt_count, 10\)\)/);
  assert.match(retry, /p_error_code !~ '\^\[A-Z\]\[A-Z0-9_\]\{2,63\}\$'/);
  assert.doesNotMatch(retry, /operation_state\s*=\s*'REQUESTED'|operation_state\s*=\s*'APPLIED'/);
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
  assert.match(audit, /signing_key_arn text NOT NULL/);
  assert.match(audit, /signing_algorithm text NOT NULL/);
  assert.match(audit, /action ~ '\^\[a-z0-9_\.:-\]/);
  assert.match(audit, /resource_type ~ '\^\[a-z0-9_\.:-\]/);
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
  assert.doesNotMatch(sql, /GRANT[^;]*INSERT[^;]*ingest_receipts/i);
  assert.doesNotMatch(sql, /GRANT[^;]*INSERT[^;]*audit_events/i);
  assert.doesNotMatch(sql, /GRANT[^;]*(?:INSERT|UPDATE)[^;]*retention_holds/i);
  assert.doesNotMatch(sql, /GRANT[^;]*(?:INSERT|UPDATE)[^;]*legal_hold_operations/i);
  assert.doesNotMatch(sql, /GRANT SELECT ON[^;]*legal_hold_operations/i);
  assert.doesNotMatch(sql, /GRANT[^;]*(?:INSERT|UPDATE)[^;]*memberships/i);
  assert.doesNotMatch(sql, /GRANT[^;]*tenant_identity[^;]*(?:INSERT|UPDATE)/i);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.create_upload_intent/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.resolve_active_membership/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.(?:list_accessible_evidence|read_accessible_evidence)/);
  assert.match(sql, /REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof/);
  assert.doesNotMatch(sql, /GRANT SELECT ON scopeproof\./);
  assert.doesNotMatch(sql, /GRANT (?:INSERT|UPDATE) ON scopeproof\./);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.append_signed_audit_event/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.reserve_exact_version_legal_hold/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.approve_exact_version_legal_hold/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.read_exact_version_legal_hold_operation/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.confirm_exact_version_legal_hold/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.reconcile_promoted_evidence/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.read_promoted_evidence_receipt/);
  assert.match(schema, /REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof FROM PUBLIC/);
});

test("evidence-read database role has only membership and exact evidence read procedures", async () => {
  const sql = await readFile(readGrantsPath, "utf8");
  assert.match(sql, /REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof/);
  assert.match(sql, /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scopeproof/);
  assert.match(sql, /ALTER ROLE %I SET row_security = on/);
  assert.doesNotMatch(sql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE) ON/i);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.(?:create_upload_intent|reserve_exact_version_legal_hold|approve_exact_version_legal_hold|append_signed_audit_event)/);
  const grants = [...sql.matchAll(/GRANT EXECUTE ON FUNCTION scopeproof\.([a-z_]+)/g)]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(grants, [
    "current_tenant_id",
    "list_accessible_evidence",
    "read_accessible_evidence",
    "record_api_audit_event",
    "resolve_active_membership",
  ]);
});

test("auditor evidence reads are DB-enforced as approved and currently retained", async () => {
  const [baseline, hardening] = await Promise.all([
    readFile(evidenceAccessPath, "utf8"),
    readFile(runtimeHardeningPath, "utf8"),
  ]);
  for (const name of ["list_accessible_evidence", "read_accessible_evidence"]) {
    const body = functionBody(baseline, name);
    assert.match(body, /PERFORM scopeproof\.assert_actor_permission\(p_requested_by, 'evidence:read'\)/);
    assert.match(body, /artifact\.retain_until IS NOT NULL/);
  }
  assert.match(hardening, /CREATE OR REPLACE FUNCTION scopeproof\.evidence_reader_role/);
  assert.match(hardening, /new_authorize CONSTANT text := ' {2}actor_role := scopeproof\.evidence_reader_role\(p_requested_by\);'/);
  assert.match(hardening, /actor_role <> ''auditor''/);
  assert.match(hardening, /artifact\.status = 'APPROVED'/);
  assert.match(hardening, /artifact\.retain_until > clock_timestamp\(\)/);
  assert.match(hardening, /unexpected evidence-read function lineage/);
  assert.match(hardening, /REVOKE ALL ON FUNCTION scopeproof\.evidence_reader_role/);
});

test("evidence-control database role can only reconcile approved legal holds and append receipts", async () => {
  const sql = await readFile(controlGrantsPath, "utf8");
  assert.match(sql, /rolsuper/);
  assert.match(sql, /rolbypassrls/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.append_signed_audit_event/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.reserve_exact_version_legal_hold/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.approve_exact_version_legal_hold/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.read_exact_version_legal_hold_operation/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.confirm_exact_version_legal_hold/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.expire_stale_exact_version_legal_hold_requests/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.acknowledge_legal_hold_recovery_publication/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.list_unaudited_expired_legal_holds/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.record_exact_version_legal_hold_reconciliation_failure/);
  assert.match(sql, /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scopeproof/);
  assert.match(sql, /ALTER ROLE %I SET row_security = on/);
  assert.doesNotMatch(sql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE) ON/i);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.create_upload_intent/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.reconcile_promoted_evidence/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.read_promoted_evidence_receipt/);
  assert.doesNotMatch(sql, /\bTRUNCATE\b/);
  const grants = [...sql.matchAll(/GRANT EXECUTE ON FUNCTION scopeproof\.([a-z_]+)/g)]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(grants, [
    "acknowledge_legal_hold_recovery_publication",
    "append_signed_audit_event",
    "begin_exact_version_legal_hold_application",
    "confirm_exact_version_legal_hold",
    "current_tenant_id",
    "expire_stale_exact_version_legal_hold_requests",
    "list_pending_exact_version_legal_holds",
    "list_unaudited_applied_legal_holds",
    "list_unaudited_expired_legal_holds",
    "read_exact_version_legal_hold_operation",
    "read_tenant_audit_head",
    "record_exact_version_legal_hold_reconciliation_failure",
  ]);
});

test("legal-hold API database role is an execute-only authentication/request/approval allow list", async () => {
  const sql = await readFile(legalApiGrantsPath, "utf8");
  assert.match(sql, /REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof/);
  assert.match(sql, /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scopeproof/);
  assert.doesNotMatch(sql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE) ON/i);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.(?:acknowledge_legal_hold_recovery_publication|append_signed_audit_event|read_exact_version_legal_hold_operation|confirm_exact_version_legal_hold|expire_stale_exact_version_legal_hold_requests|list_pending_exact_version_legal_holds|list_unaudited_applied_legal_holds|list_unaudited_expired_legal_holds|record_exact_version_legal_hold_reconciliation_failure|read_tenant_audit_head)/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.record_api_audit_event\(/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.reserve_exact_version_legal_hold\(/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.approve_exact_version_legal_hold\(/);
  const grants = [...sql.matchAll(/GRANT EXECUTE ON FUNCTION scopeproof\.([a-z_]+)/g)]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(grants, [
    "approve_exact_version_legal_hold_with_audit",
    "current_tenant_id",
    "reserve_exact_version_legal_hold_with_audit",
    "resolve_active_membership",
  ]);
});

test("ingest database role can only execute exact reconciliation", async () => {
  const sql = await readFile(ingestGrantsPath, "utf8");
  assert.match(sql, /rolsuper/);
  assert.match(sql, /rolbypassrls/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.reconcile_promoted_evidence/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.claim_promotion_fence/);
  assert.match(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.read_promoted_evidence_receipt/);
  assert.match(sql, /ALTER ROLE %I SET row_security = on/);
  assert.match(sql, /REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof/);
  assert.match(sql, /REVOKE ALL ON ALL SEQUENCES IN SCHEMA scopeproof/);
  assert.match(sql, /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scopeproof/);
  assert.doesNotMatch(sql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE) ON/i);
  assert.doesNotMatch(sql, /\bDELETE\b/);
  assert.doesNotMatch(sql, /\bTRUNCATE\b/);
});

test("API audit signer database role can only lease, sign, retry, and observe outbox work", async () => {
  const sql = await readFile(apiAuditSignerGrantsPath, "utf8");
  assert.match(sql, /REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof/);
  assert.match(sql, /REVOKE ALL ON ALL SEQUENCES IN SCHEMA scopeproof/);
  assert.match(sql, /REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scopeproof/);
  assert.doesNotMatch(sql, /GRANT (?:SELECT|INSERT|UPDATE|DELETE) ON/i);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.append_signed_audit_event\(/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.requeue_dead_lettered_api_audit_event/);
  assert.doesNotMatch(sql, /GRANT EXECUTE ON FUNCTION scopeproof\.(?:.*legal_hold|create_upload_intent|read_accessible_evidence)/);
  const grants = [...sql.matchAll(/GRANT EXECUTE ON FUNCTION scopeproof\.([a-z_]+)/g)]
    .map((match) => match[1])
    .sort();
  assert.deepEqual(grants, [
    "append_signed_api_audit_event",
    "claim_next_api_audit_event",
    "current_tenant_id",
    "read_api_audit_outbox_health",
    "read_tenant_audit_head",
    "record_api_audit_outbox_failure",
  ]);
});
