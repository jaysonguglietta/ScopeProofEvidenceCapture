import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { executableHistoricalBaseline, validateInstalledFunctionsSql } from "../../infra/aws/database/bootstrap-baseline.mjs";

/** Real embedded PostgreSQL; no server, credentials, production data, or SQL rewrites. */
export async function createTenantPostgres() {
  const db = new PGlite();
  const directory = new URL("../../infra/aws/database/", import.meta.url);
  try {
    await db.exec(executableHistoricalBaseline(await readFile(new URL("001_tenant_schema.sql", directory), "utf8")));
    for (const name of ["006_evidence_access_api.sql", "009_runtime_hardening.sql", "010_session_and_repair_security.sql", "011_customer_runtime.sql"]) await db.exec(await readFile(new URL(name, directory), "utf8"));
    await db.exec(validateInstalledFunctionsSql);
    return db;
  } catch (error) { await db.close(); throw error; }
}

/** Runs the actual parameterized RDS adapter statements against PostgreSQL. */
export class PostgresDataApiExecutor {
  constructor(db, role) { this.db = db; this.role = role; this.open = false; }
  async beginTransaction() {
    if (this.open) throw new Error("Fixture only permits one serial transaction per connection.");
    await this.db.exec("BEGIN"); this.open = true;
    if (this.role) {
      if (!/^scopeproof_test_[a-z]+$/.test(this.role)) throw new Error("Invalid isolated test role.");
      await this.db.exec(`SET LOCAL ROLE ${this.role}`);
    }
    return { transactionId: "synthetic-transaction-12345678" };
  }
  async executeStatement(input) {
    const values = []; const positions = new Map();
    const sql = input.sql.replace(/(?<!:):([a-z_]+)/g, (_, name) => {
      if (!positions.has(name)) {
        const parameter = input.parameters.find((item) => item.name === name);
        if (!parameter) throw new Error(`Missing bound parameter ${name}`);
        values.push(parameter.value.stringValue); positions.set(name, values.length);
      }
      return `$${positions.get(name)}`;
    });
    let result;
    try { result = await this.db.query(sql, values); } catch (error) { this.lastError = { code: error.code, message: error.message, where: error.where }; throw error; }
    return { formattedRecords: JSON.stringify(result.rows) };
  }
  async commitTransaction() { await this.db.exec("COMMIT"); this.open = false; }
  async rollbackTransaction() { await this.db.exec("ROLLBACK"); this.open = false; }
}

export const syntheticIds = { tenant: `ten_${"a".repeat(32)}`, user: `usr_${"b".repeat(32)}`, member: `mem_${"c".repeat(32)}`, device: `dev_${"d".repeat(32)}`, evidence: `evd_${"e".repeat(32)}` };
export async function seedCustomerTenant(db, tenant = syntheticIds.tenant) {
  await db.query("SELECT set_config('scopeproof.tenant_id',$1,false)", [tenant]);
  await db.query(`INSERT INTO scopeproof.tenant_identity(tenant_id,slug,display_name,status,canonical_hostname,retention_days,retention_mode,aws_account_id,aws_region,quarantine_bucket,evidence_bucket,evidence_kms_key_arn,audit_signing_key_arn)
    VALUES($1,'test','Synthetic tenant','ACTIVE','test.example.com',365,'COMPLIANCE','111111111111','us-east-1','scopeproof-test-quarantine','scopeproof-test-evidence','arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','arn:aws:kms:us-east-1:111111111111:key/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb')`, [tenant]);
  await db.query("INSERT INTO scopeproof.principals(tenant_id,id,cognito_sub,email,display_name) VALUES($1,$2,'synthetic-admin-subject','admin@example.com','Synthetic admin')", [tenant, syntheticIds.user]);
  await db.query("INSERT INTO scopeproof.memberships(tenant_id,id,principal_id,role,status) VALUES($1,$2,$3,'admin','ACTIVE')", [tenant, syntheticIds.member, syntheticIds.user]);
  await db.exec(`CREATE ROLE scopeproof_test_runtime NOLOGIN; CREATE ROLE scopeproof_test_legal NOLOGIN;
    GRANT USAGE ON SCHEMA scopeproof TO scopeproof_test_runtime,scopeproof_test_legal;
    GRANT EXECUTE ON FUNCTION scopeproof.customer_read(text,timestamptz,text,jsonb),scopeproof.customer_mutate(text,timestamptz,text,jsonb,text),scopeproof.customer_accept_invitation(text,timestamptz,text) TO scopeproof_test_runtime;
    GRANT EXECUTE ON FUNCTION scopeproof.customer_legal_hold_target(text,timestamptz,scopeproof.resource_identifier,integer),scopeproof.customer_legal_hold_status(text,timestamptz,scopeproof.resource_identifier) TO scopeproof_test_legal;`);
}

/** Owner fixture models already promoted bytes; it does not claim S3/KMS execution. */
export async function seedPromotedEvidence(db, { tenant, assessmentId, creatorId, evidenceId = syntheticIds.evidence, controlId = "6.3.2", systemName = "payments", receipt = true }) {
  await db.query(`INSERT INTO scopeproof.evidence_artifacts(tenant_id,id,assessment_id,control_id,title,evidence_type,source,system_name,status,revision,content_type,byte_size,checksum_sha256,evidence_bucket,object_key,object_version_id,kms_key_arn,object_lock_mode,retain_until,captured_at,expires_at,created_by)
    VALUES($1,$2,$3,$4,'Synthetic promoted evidence','REPORT','synthetic',$5,'NEEDS_REVIEW',1,'application/json',128,$6,'scopeproof-test-evidence',$7,'synthetic-version-1','arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','COMPLIANCE',clock_timestamp()+interval '366 days',clock_timestamp(),clock_timestamp()+interval '365 days',$8)`, [tenant, evidenceId, assessmentId, controlId, systemName, evidenceId.slice(4).repeat(2), `tenants/${tenant}/controls/${controlId}/evidence/${evidenceId}.json`, creatorId]);
  if (!receipt) return;
  const uploadId = `upl_${evidenceId.slice(4)}`;
  await db.query(`INSERT INTO scopeproof.upload_intents(tenant_id,id,nonce_digest,requested_by,assessment_id,evidence_id,control_id,quarantine_bucket,object_key,final_object_key,content_type,content_length,checksum_sha256,expires_at,required_retention_until)
    VALUES($1,$2,$3,$4,$5,$6,$7,'scopeproof-test-quarantine',$8,$9,'application/json',128,$3,clock_timestamp()+interval '5 minutes',clock_timestamp()+interval '366 days')`, [tenant, uploadId, evidenceId.slice(4).repeat(2), creatorId, assessmentId, evidenceId, controlId, `tenants/${tenant}/controls/${controlId}/quarantine/${uploadId}.upload`, `tenants/${tenant}/controls/${controlId}/evidence/${evidenceId}.json`]);
  await db.query(`INSERT INTO scopeproof.ingest_receipts(tenant_id,id,upload_intent_id,evidence_id,quarantine_version_id,evidence_version_id,checksum_sha256,kms_key_arn,object_lock_mode,retain_until,malware_status,upload_revision,evidence_revision,promotion_fence,promotion_attempt_id,idempotency_digest,promotion_facts,receipt_sha256,canonical_receipt,signing_key_arn,signing_algorithm,signature,signed_at)
    VALUES($1,$2,$3,$4,'synthetic-quarantine-1','synthetic-version-1',$5,'arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','COMPLIANCE',clock_timestamp()+interval '366 days','CLEAN',1,1,1,$6,$5,'{}',$5,repeat('x',64),'arn:aws:kms:us-east-1:111111111111:key/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','RSASSA_PSS_SHA_256',repeat('A',512),clock_timestamp())`, [tenant, `rcp_${evidenceId.slice(4)}`, uploadId, evidenceId, evidenceId.slice(4).repeat(2), `pat_${evidenceId.slice(4)}`]);
}
