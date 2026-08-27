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
  ingestRole: "tenant_acme_ingest",
  controlRole: "tenant_acme_control",
  legalApiRole: "tenant_acme_legal_api",
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

test("tenant SQL renderer rejects unsafe retention values", () => {
  assert.throws(() => validateTenantSqlOptions({ ...valid, retentionDays: 0 }));
  assert.throws(() => validateTenantSqlOptions({ ...valid, retentionDays: 3651 }));
  assert.throws(() => validateTenantSqlOptions({ ...valid, retentionMode: "NONE" }));
});
