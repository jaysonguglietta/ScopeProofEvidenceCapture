import assert from "node:assert/strict";
import test from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { readFile } from "node:fs/promises";

import { renderTenantSql, validateTenantSqlOptions } from "../Scripts/render_aws_tenant_sql.mjs";

const valid = {
  tenantId: "ten_0123456789abcdef0123456789abcdef",
  slug: "acme",
  displayName: "Acme Corporation",
  hostname: "acme.example.com",
  retentionDays: 365,
  retentionMode: "GOVERNANCE",
  runtimeRole: "tenant_acme_runtime",
  ingestRole: "tenant_acme_ingest",
  controlRole: "tenant_acme_control",
  legalApiRole: "tenant_acme_legal_api",
  readRole: "tenant_acme_read",
  apiAuditRole: "tenant_acme_audit_signer",
  awsAccountId: "123456789012",
  awsRegion: "us-east-1",
  quarantineBucket: "scopeproof-acme-quarantine",
  evidenceBucket: "scopeproof-acme-evidence",
  kmsKeyArn: "arn:aws:kms:us-east-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef",
  signingKeyArn: "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
};

test("tenant SQL renderer emits a complete, non-secret bootstrap bundle", async () => {
  const sql = await renderTenantSql(valid);
  assert.match(sql, /CREATE TABLE scopeproof\.tenant_identity/);
  assert.match(sql, /set_config\('scopeproof\.tenant_id', 'ten_0123456789abcdef0123456789abcdef', true\)/);
  assert.match(sql, /'scopeproof-acme-quarantine', 'scopeproof-acme-evidence', 'arn:aws:kms:us-east-1:123456789012:key\/01234567-89ab-cdef-0123-456789abcdef', 'arn:aws:kms:us-east-1:123456789012:key\/11111111-2222-3333-4444-555555555555'/);
  assert.match(sql, /runtime_role CONSTANT text := 'tenant_acme_runtime'/);
  assert.match(sql, /GRANT USAGE ON SCHEMA scopeproof TO %I/);
  assert.match(sql, /reconcile_promoted_evidence/);
  assert.doesNotMatch(sql, /__SCOPEPROOF_RUNTIME_ROLE__/);
  assert.doesNotMatch(sql, /__SCOPEPROOF_INGEST_ROLE__/);
  assert.match(sql, /control_role CONSTANT text := 'tenant_acme_control'/);
  assert.doesNotMatch(sql, /__SCOPEPROOF_CONTROL_ROLE__/);
  assert.match(sql, /legal_api_role CONSTANT text := 'tenant_acme_legal_api'/);
  assert.doesNotMatch(sql, /__SCOPEPROOF_LEGAL_API_ROLE__/);
  assert.match(sql, /read_role CONSTANT text := 'tenant_acme_read'/);
  assert.doesNotMatch(sql, /__SCOPEPROOF_EVIDENCE_READ_ROLE__/);
  assert.doesNotMatch(sql, /__SCOPEPROOF_API_AUDIT_SIGNER_ROLE__/);
  assert.match(sql, /signer_role CONSTANT text := 'tenant_acme_audit_signer'/);
  assert.ok(sql.indexOf("$validate_scopeproof$") < sql.indexOf("runtime_role CONSTANT text"));
  assert.doesNotMatch(sql, /password|secret_access_key|client_secret/i);
});

test("tenant SQL renderer safely quotes display names", async () => {
  const sql = await renderTenantSql({ ...valid, displayName: "Auditor's Example" });
  assert.match(sql, /'Auditor''s Example'/);
});

test("tenant SQL renderer rejects identifier and hostname injection", () => {
  for (const candidate of [
    { ...valid, tenantId: "tenant_x'; DROP DATABASE postgres;--" },
    { ...valid, slug: "acme.example.com" },
    { ...valid, hostname: "acme.example.com@evil.test" },
    { ...valid, hostname: "other.example.com" },
    { ...valid, runtimeRole: "tenant_acme_runtime;GRANT ALL" },
    { ...valid, ingestRole: "tenant_acme_ingest;GRANT ALL" },
    { ...valid, controlRole: "tenant_acme_control;GRANT ALL" },
    { ...valid, controlRole: valid.runtimeRole },
    { ...valid, legalApiRole: "tenant_acme_legal_api;GRANT ALL" },
    { ...valid, legalApiRole: valid.controlRole },
    { ...valid, readRole: "tenant_acme_read;GRANT ALL" },
    { ...valid, readRole: valid.runtimeRole },
    { ...valid, apiAuditRole: "tenant_acme_audit_signer;GRANT ALL" },
    { ...valid, apiAuditRole: valid.readRole },
    { ...valid, awsAccountId: "123" },
    { ...valid, evidenceBucket: "scopeproof-acme-quarantine" },
    { ...valid, evidenceBucket: "scopeproof..evidence" },
    { ...valid, evidenceBucket: "scopeproof-evidence--ol-s3" },
    { ...valid, kmsKeyArn: "arn:aws:kms:us-west-2:123456789012:key/01234567-89ab-cdef-0123-456789abcdef" },
    { ...valid, signingKeyArn: "arn:aws:kms:us-west-2:123456789012:key/11111111-2222-3333-4444-555555555555" },
    { ...valid, signingKeyArn: valid.kmsKeyArn },
  ]) {
    assert.throws(() => validateTenantSqlOptions(candidate));
  }
});

test("rendered production SQL executes in real PostgreSQL with exact catalogs and execute-only grants", async () => {
  const pg = new PGlite();
  try {
    for (const role of [valid.runtimeRole, valid.ingestRole, valid.controlRole, valid.legalApiRole, valid.readRole, valid.apiAuditRole]) await pg.exec(`CREATE ROLE ${role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS`);
    await pg.exec("CREATE ROLE scopeproof_test_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; CREATE ROLE scopeproof_test_provisioner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; GRANT scopeproof_test_owner TO scopeproof_test_provisioner WITH ADMIN FALSE, INHERIT FALSE, SET TRUE; ALTER DATABASE postgres OWNER TO scopeproof_test_owner; SET SESSION AUTHORIZATION scopeproof_test_provisioner; SET ROLE scopeproof_test_owner;");
    await pg.exec(await renderTenantSql(valid));
    assert.deepEqual((await pg.query("SELECT version FROM scopeproof.schema_migrations ORDER BY version")).rows, [1, 2, 3, 4, 5].map((version) => ({ version })));
    const source = await readFile(new URL("../infra/aws/cdk/runtime/provision-tenant/index.mjs", import.meta.url), "utf8");
    const functionNames = [...source.match(/const baselineFunctions = Object.freeze\(\[([\s\S]*?)\]\);/)![1].matchAll(/"([a-z_]+)"/g)].map((m) => m[1]).sort();
    const actualFunctions = (await pg.query<{ proname: string }>("SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='scopeproof' ORDER BY p.proname")).rows.map((r) => r.proname);
    assert.deepEqual(actualFunctions, functionNames, "production verifier must inventory every installed function");
    assert.equal((await pg.query<{ count: number }>("SELECT count(*)::integer FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='scopeproof' AND pg_get_userbyid(p.proowner)<>'scopeproof_test_owner'")).rows[0].count, 0);
    const triggers = (await pg.query<{ count: number }>("SELECT count(*)::integer FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='scopeproof' AND NOT t.tgisinternal")).rows[0].count;
    assert.equal(triggers, 29);
    await pg.exec("RESET SESSION AUTHORIZATION");
    for (const [role, count] of [[valid.runtimeRole, 9], [valid.legalApiRole, 7], [valid.ingestRole, 6], [valid.readRole, 6], [valid.apiAuditRole, 6]] as const) {
      const grants = (await pg.query<{ count: number }>("SELECT count(*)::integer FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='scopeproof' AND has_function_privilege($1,p.oid,'EXECUTE')", [role])).rows[0].count;
      assert.equal(grants, count, role);
      await pg.exec(`SET SESSION AUTHORIZATION ${role}`);
      for (const table of ["tenant_identity", "memberships", "evidence_artifacts", "customer_control_catalogs", "schema_migrations"]) await assert.rejects(pg.query(`SELECT * FROM scopeproof.${table}`));
      await pg.exec("RESET SESSION AUTHORIZATION");
    }
  } finally { await pg.close(); }
});

test("tenant SQL renderer rejects unsafe retention values", () => {
  assert.throws(() => validateTenantSqlOptions({ ...valid, retentionDays: 0 }));
  assert.throws(() => validateTenantSqlOptions({ ...valid, retentionDays: 3651 }));
  assert.throws(() => validateTenantSqlOptions({ ...valid, retentionMode: "NONE" }));
});
