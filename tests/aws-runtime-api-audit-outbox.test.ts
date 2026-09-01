import assert from "node:assert/strict";
import test from "node:test";

import { RdsDataApiAuditOutbox } from "../lib/aws-runtime/http/audit-outbox.ts";
import type { RdsDataApiExecutor } from "../lib/aws-runtime/http/membership.ts";
import type { TenantActor } from "../lib/aws-runtime/tenancy.ts";

const TENANT = `ten_${"a".repeat(32)}`;
const USER = `usr_${"b".repeat(32)}`;
const MEMBERSHIP = `mem_${"c".repeat(32)}`;
const EVIDENCE = `evd_${"d".repeat(32)}`;

function actor(): TenantActor {
  return {
    tenantId: TENANT as TenantActor["tenantId"],
    tenantHostname: "api-acme.evidence.example.com" as TenantActor["tenantHostname"],
    userId: USER as TenantActor["userId"],
    membershipId: MEMBERSHIP as TenantActor["membershipId"],
    subject: "cognito-subject-12345678",
    role: "auditor",
  };
}

test("RDS API audit outbox binds actor, tenant, action, resource, and safe details in one transaction", async () => {
  const calls: Array<{ kind: string; input: Record<string, unknown> }> = [];
  const executor: RdsDataApiExecutor = {
    async beginTransaction(input) { calls.push({ kind: "begin", input }); return { transactionId: "transaction-12345678" }; },
    async executeStatement(input) {
      calls.push({ kind: "execute", input: input as unknown as Record<string, unknown> });
      if (input.sql.includes("record_api_audit_event")) {
        return { formattedRecords: JSON.stringify([{
          outbox_id: `aob_${"e".repeat(32)}`,
          was_created: true,
          committed_event_digest: "f".repeat(64),
        }]) };
      }
      return {};
    },
    async commitTransaction(input) { calls.push({ kind: "commit", input }); },
    async rollbackTransaction(input) { calls.push({ kind: "rollback", input }); },
  };
  const outbox = new RdsDataApiAuditOutbox({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:tenant-read-AbCd",
    database: "scopeproof_acme",
  });
  const result = await outbox.record({
    actor: actor(),
    action: "evidence.download_intent_issued",
    requestId: "request-12345678",
    resourceType: "evidence",
    resourceId: EVIDENCE,
    idempotencyKey: "evidence-download:request-12345678",
    details: { revision: 4, checksumSha256: "1".repeat(64), expectedSize: 4096 },
  });
  assert.deepEqual(result, { outboxId: `aob_${"e".repeat(32)}`, wasCreated: true, eventDigest: "f".repeat(64) });
  assert.deepEqual(calls.map((call) => call.kind), ["begin", "execute", "execute", "commit"]);
  const statement = calls[2].input;
  assert.match(String(statement.sql), /scopeproof\.record_api_audit_event/);
  assert.doesNotMatch(String(statement.sql), new RegExp(TENANT));
  const parameters = Object.fromEntries((statement.parameters as Array<{ name: string; value: { stringValue: string } }>).map((entry) => [entry.name, entry.value.stringValue]));
  assert.equal(parameters.actor_user_id, USER);
  assert.equal(parameters.membership_id, MEMBERSHIP);
  assert.equal(parameters.action, "evidence.download_intent_issued");
  assert.equal(parameters.resource_id, EVIDENCE);
  assert.deepEqual(JSON.parse(parameters.details), { checksumSha256: "1".repeat(64), expectedSize: 4096, revision: 4 });
});

test("RDS API audit outbox rejects cross-resource actions and secret-bearing details before I/O", async () => {
  let calls = 0;
  const executor: RdsDataApiExecutor = {
    async beginTransaction() { calls += 1; return { transactionId: "transaction-12345678" }; },
    async executeStatement() { return {}; },
    async commitTransaction() {},
    async rollbackTransaction() {},
  };
  const outbox = new RdsDataApiAuditOutbox({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:tenant-read-AbCd",
    database: "scopeproof_acme",
  });
  await assert.rejects(outbox.record({
    actor: actor(),
    action: "evidence.search_performed",
    requestId: "request-12345678",
    resourceType: "evidence",
    resourceId: EVIDENCE,
    idempotencyKey: "evidence-search:request-12345678",
    details: {},
  }), /resource binding/);
  await assert.rejects(outbox.record({
    actor: actor(),
    action: "evidence.download_intent_issued",
    requestId: "request-12345678",
    resourceType: "evidence",
    resourceId: EVIDENCE,
    idempotencyKey: "evidence-download:request-12345678",
    details: { accessToken: "must-never-persist" },
  }), /forbidden field/);
  assert.equal(calls, 0);
});
