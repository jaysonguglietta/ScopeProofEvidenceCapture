import assert from "node:assert/strict";
import test from "node:test";

import {
  AwsSdkV3RdsDataApiExecutor,
  DynamoEdgeReplayNonceStore,
  DynamoTenantAuthorityResolver,
} from "../lib/aws-runtime/http/aws.ts";
import { TenantSecurityError } from "../lib/aws-runtime/contracts.ts";

class Command<T> {
  readonly input: T;
  constructor(input: T) {
    this.input = input;
  }
}

class BeginTransactionCommand<T> extends Command<T> {}
class ExecuteStatementCommand<T> extends Command<T> {}
class CommitTransactionCommand<T> extends Command<T> {}
class RollbackTransactionCommand<T> extends Command<T> {}
class PutItemCommand<T> extends Command<T> {}
class GetItemCommand<T> extends Command<T> {}

const TENANT_ID = `ten_${"a".repeat(32)}`;
const HOSTNAME = "acme.jsontechology.com";

function activeDomainItem(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    PK: { S: `DOMAIN#${HOSTNAME}` },
    SK: { S: "METADATA" },
    kind: { S: "TenantDomain" },
    schemaVersion: { N: "2" },
    tenantId: { S: TENANT_ID },
    hostname: { S: HOSTNAME },
    slug: { S: "acme" },
    displayName: { S: "Acme Compliance" },
    appClientId: { S: "scopeproof-client-123" },
    appClientIds: { SS: ["scopeproof-client-123", "scopeproof-native-456"] },
    status: { S: "ACTIVE" },
    canonical: { BOOL: true },
    ...overrides,
  };
}

test("Dynamo tenant resolver performs one exact strongly consistent authority read", async () => {
  const seen: Array<GetItemCommand<Record<string, unknown>>> = [];
  const resolver = new DynamoTenantAuthorityResolver({
    client: { async send(command: unknown) { seen.push(command as GetItemCommand<Record<string, unknown>>); return { Item: activeDomainItem() }; } },
    commands: { GetItemCommand },
    tableName: "scopeproof-control",
  });
  const resolved = await resolver.resolve({ source: "direct", host: HOSTNAME });
  assert.equal(resolved.tenant.id, TENANT_ID);
  assert.equal(resolved.tenant.slug, "acme");
  assert.equal(resolved.tenant.appClientId, "scopeproof-client-123");
  assert.deepEqual(resolved.tenant.appClientIds, ["scopeproof-client-123", "scopeproof-native-456"]);
  assert.equal(resolved.domain.hostname, HOSTNAME);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].input.ConsistentRead, true);
  assert.deepEqual(seen[0].input.Key, { PK: { S: `DOMAIN#${HOSTNAME}` }, SK: { S: "METADATA" } });
  assert.match(String(seen[0].input.ProjectionExpression), /#client/);
  assert.ok(!JSON.stringify(seen[0].input).includes("x-forwarded-host"));
});

test("Dynamo tenant resolver fails closed for inactive and unknown domains", async () => {
  for (const Item of [activeDomainItem({ status: { S: "SUSPENDED" } }), undefined]) {
    const resolver = new DynamoTenantAuthorityResolver({
      client: { async send() { return { Item }; } },
      commands: { GetItemCommand },
      tableName: "scopeproof-control",
    });
    await assert.rejects(resolver.resolve({ source: "direct", host: HOSTNAME }), (error: unknown) =>
      error instanceof TenantSecurityError && error.code === "TENANT_NOT_FOUND" &&
        error.safeStatus === 404 && error.message === "Tenant not found.");
  }
});

test("Dynamo tenant resolver rejects malformed active records without disclosing fields", async () => {
  for (const Item of [
    activeDomainItem({ status: { S: " active " } }),
    activeDomainItem({ schemaVersion: { N: "1" } }),
    activeDomainItem({ hostname: { S: "bravo.jsontechology.com" } }),
    activeDomainItem({ tenantId: { S: "ten_invalid" } }),
    activeDomainItem({ canonical: { BOOL: false } }),
    activeDomainItem({ appClientId: { S: "bad client" } }),
    activeDomainItem({ appClientIds: { SS: ["scopeproof-client-123", "scopeproof-client-123"] } }),
    activeDomainItem({ appClientIds: { SS: ["scopeproof-native-456"] } }),
    activeDomainItem({ unexpectedSecret: { S: "must-not-be-returned" } }),
  ]) {
    const resolver = new DynamoTenantAuthorityResolver({
      client: { async send() { return { Item }; } },
      commands: { GetItemCommand },
      tableName: "scopeproof-control",
    });
    await assert.rejects(resolver.resolve({ source: "direct", host: HOSTNAME }), (error: unknown) =>
      error instanceof TenantSecurityError && error.safeStatus === 500 && !error.message.includes("must-not-be-returned") && !error.message.includes("ten_invalid"));
  }
});

test("Dynamo tenant resolver rejects unproved edge authority before AWS", async () => {
  let calls = 0;
  const resolver = new DynamoTenantAuthorityResolver({
    client: { async send() { calls += 1; return { Item: activeDomainItem() }; } },
    commands: { GetItemCommand },
    tableName: "scopeproof-control",
  });
  await assert.rejects(resolver.resolve({ source: "trusted_edge", viewerHost: HOSTNAME, edgeProofVerified: false } as never), (error: unknown) =>
    error instanceof TenantSecurityError && error.code === "UNTRUSTED_HOST_SOURCE");
  assert.equal(calls, 0);
});

test("AWS SDK RDS bridge constructs only the requested Data API commands", async () => {
  const seen: unknown[] = [];
  const client = {
    async send(command: unknown) {
      seen.push(command);
      if (command instanceof BeginTransactionCommand) return { transactionId: "transaction-12345678" };
      if (command instanceof ExecuteStatementCommand) return { formattedRecords: "[]" };
      return {};
    },
  };
  const executor = new AwsSdkV3RdsDataApiExecutor(client, {
    BeginTransactionCommand,
    ExecuteStatementCommand,
    CommitTransactionCommand,
    RollbackTransactionCommand,
  });
  const connection = {
    resourceArn: "arn:aws:rds:us-east-1:123456789012:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:tenant",
    database: "scopeproof_acme",
  };
  const transaction = await executor.beginTransaction(connection);
  assert.equal(transaction.transactionId, "transaction-12345678");
  await executor.executeStatement({
    ...connection,
    transactionId: "transaction-12345678",
    sql: "SELECT :tenant_id",
    parameters: [{ name: "tenant_id", value: { stringValue: "ten_0123456789abcdef0123456789abcdef" } }],
  });
  await executor.commitTransaction({ resourceArn: connection.resourceArn, secretArn: connection.secretArn, transactionId: "transaction-12345678" });
  await executor.rollbackTransaction({ resourceArn: connection.resourceArn, secretArn: connection.secretArn, transactionId: "transaction-12345678" });
  assert.deepEqual(seen.map((value) => (value as object).constructor.name), [
    "BeginTransactionCommand",
    "ExecuteStatementCommand",
    "CommitTransactionCommand",
    "RollbackTransactionCommand",
  ]);
});

test("Dynamo replay store hashes nonces and fails closed on duplicate conditional writes", async () => {
  const seen: Array<PutItemCommand<Record<string, unknown>>> = [];
  let duplicate = false;
  const client = {
    async send(command: unknown) {
      seen.push(command as PutItemCommand<Record<string, unknown>>);
      if (duplicate) throw Object.assign(new Error("duplicate"), { name: "ConditionalCheckFailedException" });
      duplicate = true;
      return {};
    },
  };
  const store = new DynamoEdgeReplayNonceStore({
    client,
    commands: { PutItemCommand },
    tableName: "scopeproof-control",
    namespace: "EDGE",
    now: () => new Date("2026-08-27T12:00:00.000Z"),
  });
  const nonce = "nonce_abcdefghijklmnopqrstuvwxyz0123456789";
  const expiry = Math.floor(Date.parse("2026-08-27T12:01:00.000Z") / 1_000);
  assert.equal(await store.consume(nonce, expiry), true);
  assert.equal(await store.consume(nonce, expiry), false);
  const item = seen[0].input.Item as Record<string, { S?: string; N?: string }>;
  assert.equal(item.PK.S, "EDGE_REPLAY#EDGE");
  assert.match(item.SK.S || "", /^NONCE#[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(item).includes(nonce));
  assert.equal(item.ttlEpochSeconds.N, String(expiry));
  assert.equal(seen[0].input.ConditionExpression, "attribute_not_exists(#pk) AND attribute_not_exists(#sk)");
});

test("Dynamo replay store rejects stale and unbounded expirations before AWS", async () => {
  const store = new DynamoEdgeReplayNonceStore({
    client: { async send() { throw new Error("must not call AWS"); } },
    commands: { PutItemCommand },
    tableName: "scopeproof-control",
    now: () => new Date("2026-08-27T12:00:00.000Z"),
  });
  const now = Math.floor(Date.parse("2026-08-27T12:00:00.000Z") / 1_000);
  await assert.rejects(store.consume("nonce_abcdefghijklmnopqrstuvwxyz0123456789", now));
  await assert.rejects(store.consume("nonce_abcdefghijklmnopqrstuvwxyz0123456789", now + 601));
});
