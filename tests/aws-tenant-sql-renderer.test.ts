import assert from "node:assert/strict";
import test from "node:test";

import { renderTenantSql, validateTenantSqlOptions } from "../Scripts/render_aws_tenant_sql.mjs";

const valid = {
  tenantId: "ten_0123456789abcdef0123456789abcdef",
  slug: "acme",
  displayName: "Acme Corporation",
  hostname: "acme.example.com",
  retentionDays: 365,
  retentionMode: "GOVERNANCE",
  runtimeRole: "tenant_acme_runtime",
  awsAccountId: "123456789012",
  awsRegion: "us-east-1",
  quarantineBucket: "scopeproof-acme-quarantine",
  evidenceBucket: "scopeproof-acme-evidence",
  kmsKeyArn: "arn:aws:kms:us-east-1:123456789012:key/01234567-89ab-cdef-0123-456789abcdef",
};

test("tenant SQL renderer emits a complete, non-secret bootstrap bundle", async () => {
  const sql = await renderTenantSql(valid);
  assert.match(sql, /CREATE TABLE scopeproof\.tenant_identity/);
  assert.match(sql, /set_config\('scopeproof\.tenant_id', 'ten_0123456789abcdef0123456789abcdef', true\)/);
  assert.match(sql, /'scopeproof-acme-quarantine', 'scopeproof-acme-evidence', 'arn:aws:kms:us-east-1:123456789012:key\/01234567-89ab-cdef-0123-456789abcdef'/);
  assert.match(sql, /runtime_role CONSTANT text := 'tenant_acme_runtime'/);
  assert.match(sql, /GRANT USAGE ON SCHEMA scopeproof TO %I/);
  assert.doesNotMatch(sql, /__SCOPEPROOF_RUNTIME_ROLE__/);
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
    { ...valid, awsAccountId: "123" },
    { ...valid, evidenceBucket: "scopeproof-acme-quarantine" },
    { ...valid, evidenceBucket: "scopeproof..evidence" },
    { ...valid, evidenceBucket: "scopeproof-evidence--ol-s3" },
    { ...valid, kmsKeyArn: "arn:aws:kms:us-west-2:123456789012:key/01234567-89ab-cdef-0123-456789abcdef" },
  ]) {
    assert.throws(() => validateTenantSqlOptions(candidate));
  }
});

test("tenant SQL renderer rejects unsafe retention values", () => {
  assert.throws(() => validateTenantSqlOptions({ ...valid, retentionDays: 0 }));
  assert.throws(() => validateTenantSqlOptions({ ...valid, retentionDays: 3651 }));
  assert.throws(() => validateTenantSqlOptions({ ...valid, retentionMode: "NONE" }));
});
