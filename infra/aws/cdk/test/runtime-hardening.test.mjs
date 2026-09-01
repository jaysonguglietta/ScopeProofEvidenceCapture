import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { validateCustomerActivationApproval } from "../runtime/provision-tenant/customer-activation.mjs";

const tenantId = "ten_0123456789abcdef0123456789abcdef";
const executionId = "arn:aws:states:us-east-1:123456789012:execution:tenant-provision:run_12345678";
const now = Date.parse("2026-09-01T16:00:00.000Z");
function approval(overrides = {}) {
  const approvedAt = "2026-09-01T15:59:00.000Z";
  const expiresAt = "2026-09-01T16:59:00.000Z";
  return {
    PK: { S: `TENANT#${tenantId}` }, SK: { S: "CUSTOMER_ENABLED" },
    approvedAt: { S: approvedAt }, decision: { S: "CUSTOMER_ENABLED" },
    executionId: { S: executionId }, expiresAt: { S: expiresAt },
    kind: { S: "CustomerActivationApproval" }, schemaVersion: { N: "1" },
    tenantId: { S: tenantId }, ttlEpochSeconds: { N: String(Math.floor(Date.parse(expiresAt) / 1000)) },
    ...overrides,
  };
}

test("CUSTOMER_ENABLED approval is exact, current, and bound to one execution", () => {
  const input = { executionId, nowMilliseconds: now, tenantId };
  assert.equal(validateCustomerActivationApproval(approval(), input), true);
  assert.equal(validateCustomerActivationApproval(approval({ executionId: { S: `${executionId}-replay` } }), input), false);
  assert.equal(validateCustomerActivationApproval(approval({ unexpected: { S: "field" } }), input), false);
  assert.equal(validateCustomerActivationApproval(approval({ expiresAt: { S: "2026-09-01T15:00:00.000Z" } }), input), false);
});

test("forward migration owns rejection receipts and version 3", () => {
  const sql = readFileSync(new URL("../../database/009_runtime_hardening.sql", import.meta.url), "utf8");
  assert.match(sql, /CREATE TABLE scopeproof\.rejected_ingest_receipts/);
  assert.match(sql, /CREATE FUNCTION scopeproof\.reconcile_rejected_evidence/);
  assert.match(sql, /rejected ingest receipts are append-only/);
  assert.match(sql, /VALUES \(3, 'runtime_hardening'\)/);
  assert.match(sql, /dlpReceiptSha256/);
  assert.match(sql, /actor_role <> 'auditor'/);
});

test("rejected events are queued for reconciliation as well as alerted", () => {
  const source = readFileSync(new URL("../lib/tenant-stack.ts", import.meta.url), "utf8");
  assert.match(source, /new eventTargets\.SqsQueue\(rejectedEvidenceQueue\)/);
  assert.match(source, /reconcile-rejected-evidence/);
  assert.match(source, /UploadProjectionRepairSchedule/);
});
