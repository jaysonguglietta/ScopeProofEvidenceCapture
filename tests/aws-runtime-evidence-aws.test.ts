import assert from "node:assert/strict";
import test from "node:test";

import { sha256Hex, stableJson } from "../lib/aws-runtime/contracts.ts";

import {
  AwsSdkV3ExactPutObjectPresigner,
  AwsSdkV3ExactVersionLegalHoldClient,
  AwsSdkV3KmsAsymmetricSigningClient,
  DynamoConditionalUploadIntentStore,
  DynamoTenantRouteRateLimiter,
  DynamoUploadRequestRateLimiter,
  RdsDataAtomicPromotionStore,
  RdsDataExactVersionLegalHoldOperationStore,
  RdsDataLegalHoldReconciliationSource,
  prepareExactVersionLegalHoldApproval,
  prepareExactVersionLegalHoldOperation,
  type AtomicPromotionCommand,
  type ControlledUploadIntent,
  type PromotionFacts,
} from "../lib/aws-runtime/evidence/index.ts";
import type { RdsDataApiExecutor } from "../lib/aws-runtime/http/membership.ts";
import type { TenantActor } from "../lib/aws-runtime/tenancy.ts";

const TENANT = `ten_${"a".repeat(32)}`;
const USER = `usr_${"b".repeat(32)}`;
const MEMBERSHIP = `mem_${"5".repeat(32)}`;
const INTENT = `upl_${"c".repeat(32)}`;
const EVIDENCE = `evd_${"d".repeat(32)}`;
const RECEIPT = `rcp_${"e".repeat(32)}`;
const HOLD_OPERATION = `lho_${"8".repeat(32)}`;
const HOLD = `hld_${"7".repeat(32)}`;
const APPROVER = `usr_${"6".repeat(32)}`;
const CONTROL = "PCI-DSS-10.2.1";
const EVIDENCE_KEY = "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const SIGNING_KEY = "arn:aws:kms:us-east-1:111111111111:key/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

class Command<T> {
  readonly input: T;
  constructor(input: T) { this.input = input; }
}

class TransactWriteItemsCommand<T> extends Command<T> {}
class GetItemCommand<T> extends Command<T> {}
class PutObjectCommand<T> extends Command<T> {}
class SignCommand<T> extends Command<T> {}
class VerifyCommand<T> extends Command<T> {}
class PutObjectLegalHoldCommand<T> extends Command<T> {}
class GetObjectLegalHoldCommand<T> extends Command<T> {}

function intent(): ControlledUploadIntent {
  return {
    schemaVersion: 1,
    id: INTENT as ControlledUploadIntent["id"],
    tenantId: TENANT as ControlledUploadIntent["tenantId"],
    requestedBy: USER as ControlledUploadIntent["requestedBy"],
    resourceId: EVIDENCE as ControlledUploadIntent["resourceId"],
    controlId: CONTROL,
    expectedSha256: "f".repeat(64) as ControlledUploadIntent["expectedSha256"],
    expectedSize: 1024,
    contentType: "image/png",
    nonceDigest: "1".repeat(64) as ControlledUploadIntent["nonceDigest"],
    quarantineBucket: "scopeproof-quarantine",
    quarantineKmsKeyArn: EVIDENCE_KEY,
    quarantineKey: `tenants/${TENANT}/controls/${CONTROL}/quarantine/${INTENT}.upload` as ControlledUploadIntent["quarantineKey"],
    finalKey: `tenants/${TENANT}/controls/${CONTROL}/evidence/${EVIDENCE}.png` as ControlledUploadIntent["finalKey"],
    issuedAt: "2026-08-27T16:00:00.000Z",
    expiresAt: "2026-08-27T16:05:00.000Z",
    requiredRetentionUntil: "2027-08-27T16:05:00.000Z",
    idempotencyDigest: "2".repeat(64) as ControlledUploadIntent["idempotencyDigest"],
    requestFingerprint: "3".repeat(64) as ControlledUploadIntent["requestFingerprint"],
    revision: 0,
    status: "issued",
  };
}

async function recoveryProjection() {
  const canonicalEvidenceProjection = stableJson({
    schemaVersion: 1,
    deviceId: `dev_${"4".repeat(32)}`,
    assessmentId: `asm_${"5".repeat(32)}`,
    title: "Quarterly access review",
    description: "Redacted evidence",
    evidenceType: "SCREENSHOT",
    source: "Scopeproof Capture",
    systemName: "Production identity provider",
    capturedAt: "2026-08-27T15:59:30.000Z",
    artifactExpiresAt: "2027-08-27T16:00:00.000Z",
    metadata: { catalogVersion: "pci-dss-v4.0.1" },
  });
  return {
    canonicalEvidenceProjection,
    evidenceProjectionDigest: await sha256Hex(`scopeproof-upload-evidence-projection-v1\n${canonicalEvidenceProjection}`),
  };
}

test("Dynamo upload store reserves lifecycle and nonce atomically without overwrites", async () => {
  const seen: Array<TransactWriteItemsCommand<Record<string, unknown>>> = [];
  const gets: Array<GetItemCommand<Record<string, unknown>>> = [];
  const store = new DynamoConditionalUploadIntentStore({
    client: {
      async send(command) {
        if (command instanceof GetItemCommand) gets.push(command as typeof gets[number]);
        else seen.push(command as typeof seen[number]);
        return {};
      },
    },
    TransactWriteItemsCommand,
    GetItemCommand,
    tableName: "scopeproof-control",
  });
  assert.equal((await store.reserve(intent(), await recoveryProjection())).outcome, "created");
  assert.equal(seen.length, 1);
  assert.equal(gets.length, 1);
  assert.equal(gets[0].input.ConsistentRead, true);
  const input = seen[0].input as { TransactItems: Array<{
    Put?: { Item: Record<string, { S?: string; N?: string }>; ConditionExpression: string };
    Update?: { Key: Record<string, { S?: string }>; ConditionExpression: string; UpdateExpression: string };
  }> };
  assert.equal(input.TransactItems.length, 5);
  assert.equal(input.TransactItems[0].Put!.Item.SK.S, `UPLOAD#${INTENT}`);
  assert.equal(input.TransactItems[1].Put!.Item.SK.S, `UPLOAD_NONCE#${"1".repeat(64)}`);
  assert.equal(input.TransactItems[2].Put!.Item.SK.S, `UPLOAD_REQUEST#${"2".repeat(64)}`);
  assert.equal(input.TransactItems[3].Update!.Key.SK.S, "RATE#UPLOAD_NEW#DAY#2026-08-27#TENANT");
  assert.equal(input.TransactItems[4].Update!.Key.SK.S, `RATE#UPLOAD_NEW#DAY#2026-08-27#PRINCIPAL#${USER}`);
  assert.match(input.TransactItems[3].Update!.UpdateExpression, /ADD #count :one/);
  assert.equal(input.TransactItems[0].Put!.Item.expiresAt.S, "2026-08-27T16:05:00.000Z");
  assert.equal(
    input.TransactItems[0].Put!.Item.ttlEpochSeconds.N,
    String((Date.parse("2026-08-27T16:05:00.000Z") / 1_000) + (22 * 24 * 60 * 60)),
  );
  assert.equal(input.TransactItems[0].Put!.Item.GSI1PK.S, `MAINTENANCE#UPLOAD#${TENANT}`);
  assert.equal(
    input.TransactItems[0].Put!.Item.GSI1SK.S,
    `2026-09-03T16:05:00.000Z#${INTENT}`,
  );
  assert.equal(
    input.TransactItems[1].Put!.Item.ttlEpochSeconds.N,
    String(Date.parse("2026-08-27T16:05:00.000Z") / 1_000),
  );
  assert.ok(input.TransactItems.every((entry) => (entry.Put ?? entry.Update)!.ConditionExpression.includes("attribute_not_exists")));
  assert.ok(!JSON.stringify(input).includes("raw-upload-nonce"));
  assert.ok(!JSON.stringify(input).includes("raw-idempotency-key"));
});

test("Dynamo upload store strongly reads and returns only an exact existing reservation", async () => {
  const persisted = new Map<string, Record<string, { S?: string; N?: string }>>();
  const seenGets: Array<GetItemCommand<Record<string, unknown>>> = [];
  let writes = 0;
  const store = new DynamoConditionalUploadIntentStore({
    client: {
      async send(command) {
        if (command instanceof GetItemCommand) {
          seenGets.push(command as typeof seenGets[number]);
          const key = command.input.Key as Record<string, { S?: string }>;
          return { Item: persisted.get(key.SK.S ?? "") };
        }
        const transaction = command as TransactWriteItemsCommand<{
          TransactItems: Array<{ Put?: { Item: Record<string, { S?: string; N?: string }> } }>;
        }>;
        writes += 1;
        for (const entry of transaction.input.TransactItems) {
          if (entry.Put) persisted.set(entry.Put.Item.SK.S ?? "", entry.Put.Item);
        }
        return {};
      },
    },
    TransactWriteItemsCommand,
    GetItemCommand,
    tableName: "scopeproof-control",
  });
  const recovery = await recoveryProjection();
  assert.equal((await store.reserve(intent(), recovery)).outcome, "created");
  const recovered = await store.recoverExact(
    { ...intent(), issuedAt: "2026-08-27T16:01:00.000Z", expiresAt: "2026-08-27T16:06:00.000Z" },
    recovery,
  );
  assert.equal(recovered?.outcome, "existing");
  assert.equal(recovered?.intent.issuedAt, "2026-08-27T16:00:00.000Z");
  assert.equal(writes, 1, "strong recovery must not issue a Dynamo write");
  const existing = await store.reserve({ ...intent(), issuedAt: "2026-08-27T16:02:00.000Z", expiresAt: "2026-08-27T16:07:00.000Z" }, recovery);
  assert.equal(existing.outcome, "existing");
  assert.equal(existing.intent.issuedAt, "2026-08-27T16:00:00.000Z");
  assert.equal(existing.intent.expiresAt, "2026-08-27T16:05:00.000Z");
  assert.equal(seenGets.length, 7);
  assert.ok(seenGets.every((command) => command.input.ConsistentRead === true));

  await assert.rejects(
    store.reserve({ ...intent(), requestFingerprint: "9".repeat(64) as ControlledUploadIntent["requestFingerprint"] }, recovery),
    /different or malformed upload facts/,
  );

  const lifecycle = { ...persisted.get(`UPLOAD#${INTENT}`)! };
  delete lifecycle.requestFingerprint;
  persisted.set(`UPLOAD#${INTENT}`, lifecycle);
  await assert.rejects(store.reserve(intent(), recovery), /malformed upload facts|malformed/);
});

test("Dynamo upload recovery exact-CAS upgrades a legacy lifecycle before returning it", async () => {
  const persisted = new Map<string, Record<string, { S?: string; N?: string }>>();
  const transactions: Array<TransactWriteItemsCommand<Record<string, unknown>>> = [];
  const store = new DynamoConditionalUploadIntentStore({
    client: {
      async send(command) {
        if (command instanceof GetItemCommand) {
          const key = command.input.Key as Record<string, { S?: string }>;
          return { Item: persisted.get(key.SK.S ?? "") };
        }
        const transaction = command as TransactWriteItemsCommand<{
          TransactItems: Array<{
            Put?: { Item: Record<string, { S?: string; N?: string }> };
            Update?: {
              Key: Record<string, { S?: string }>;
              ExpressionAttributeValues: Record<string, { S?: string; N?: string }>;
            };
          }>;
        }>;
        transactions.push(transaction as TransactWriteItemsCommand<Record<string, unknown>>);
        for (const entry of transaction.input.TransactItems) {
          if (entry.Put) persisted.set(entry.Put.Item.SK.S ?? "", entry.Put.Item);
          if (entry.Update) {
            const sortKey = entry.Update.Key.SK.S ?? "";
            const row = persisted.get(sortKey);
            if (!row) continue;
            const values = entry.Update.ExpressionAttributeValues;
            persisted.set(sortKey, {
              ...row,
              ...(sortKey.startsWith("UPLOAD#") ? {
                GSI1PK: values[":maintenancePk"],
                GSI1SK: values[":maintenanceSk"],
              } : {}),
              ttlEpochSeconds: values[":newTtl"],
            });
          }
        }
        return {};
      },
    },
    TransactWriteItemsCommand,
    GetItemCommand,
    tableName: "scopeproof-control",
  });
  const recovery = await recoveryProjection();
  assert.equal((await store.reserve(intent(), recovery)).outcome, "created");
  const legacyTtl = String((Date.parse(intent().expiresAt) / 1_000) + (7 * 24 * 60 * 60));
  const lifecycleKey = `UPLOAD#${INTENT}`;
  const requestKey = `UPLOAD_REQUEST#${"2".repeat(64)}`;
  const lifecycle: Record<string, { S?: string; N?: string }> = {
    ...persisted.get(lifecycleKey)!,
    ttlEpochSeconds: { N: legacyTtl },
  };
  delete lifecycle.GSI1PK;
  delete lifecycle.GSI1SK;
  persisted.set(lifecycleKey, lifecycle);
  persisted.set(requestKey, { ...persisted.get(requestKey)!, ttlEpochSeconds: { N: legacyTtl } });

  const recovered = await store.recoverExact(intent(), recovery);
  assert.equal(recovered?.outcome, "existing");
  assert.equal(transactions.length, 2, "one exact legacy upgrade transaction is required");
  const upgrade = transactions[1].input as {
    ClientRequestToken: string;
    TransactItems: Array<{ Update: { ConditionExpression: string; UpdateExpression: string } }>;
  };
  assert.equal(upgrade.TransactItems.length, 2);
  assert.match(upgrade.TransactItems[0].Update.ConditionExpression, /attribute_not_exists\(GSI1PK\)/);
  assert.match(upgrade.TransactItems[0].Update.UpdateExpression, /GSI1PK = :maintenancePk/);
  assert.match(upgrade.TransactItems[1].Update.UpdateExpression, /ttlEpochSeconds = :newTtl/);
  assert.equal(upgrade.ClientRequestToken.length, 36);
  assert.equal(persisted.get(lifecycleKey)?.GSI1PK?.S, `MAINTENANCE#UPLOAD#${TENANT}`);
  assert.equal(persisted.get(lifecycleKey)?.GSI1SK?.S, `2026-09-03T16:05:00.000Z#${INTENT}`);
  assert.equal(
    persisted.get(requestKey)?.ttlEpochSeconds?.N,
    String((Date.parse(intent().expiresAt) / 1_000) + (22 * 24 * 60 * 60)),
  );
});

test("Dynamo legacy lifecycle upgrade fails closed after one conflicting CAS", async () => {
  const persisted = new Map<string, Record<string, { S?: string; N?: string }>>();
  let getCount = 0;
  let transactionCount = 0;
  const store = new DynamoConditionalUploadIntentStore({
    client: {
      async send(command) {
        if (command instanceof GetItemCommand) {
          getCount += 1;
          const key = command.input.Key as Record<string, { S?: string }>;
          return { Item: persisted.get(key.SK.S ?? "") };
        }
        transactionCount += 1;
        const transaction = command as TransactWriteItemsCommand<{
          TransactItems: Array<{ Put?: { Item: Record<string, { S?: string; N?: string }> } }>;
        }>;
        if (transactionCount === 1) {
          for (const entry of transaction.input.TransactItems) {
            if (entry.Put) persisted.set(entry.Put.Item.SK.S ?? "", entry.Put.Item);
          }
          return {};
        }
        throw Object.assign(new Error("conditional conflict"), {
          name: "TransactionCanceledException",
          CancellationReasons: [{ Code: "ConditionalCheckFailed" }, { Code: "None" }],
        });
      },
    },
    TransactWriteItemsCommand,
    GetItemCommand,
    tableName: "scopeproof-control",
  });
  const recovery = await recoveryProjection();
  assert.equal((await store.reserve(intent(), recovery)).outcome, "created");
  const legacyTtl = String((Date.parse(intent().expiresAt) / 1_000) + (7 * 24 * 60 * 60));
  const lifecycleKey = `UPLOAD#${INTENT}`;
  const requestKey = `UPLOAD_REQUEST#${"2".repeat(64)}`;
  const lifecycle: Record<string, { S?: string; N?: string }> = {
    ...persisted.get(lifecycleKey)!,
    ttlEpochSeconds: { N: legacyTtl },
  };
  delete lifecycle.GSI1PK;
  delete lifecycle.GSI1SK;
  persisted.set(lifecycleKey, lifecycle);
  persisted.set(requestKey, { ...persisted.get(requestKey)!, ttlEpochSeconds: { N: legacyTtl } });

  await assert.rejects(
    store.recoverExact(intent(), recovery),
    /maintenance authority changed while it was being upgraded/,
  );
  assert.equal(transactionCount, 2, "the conflicting migration must not retry recursively");
  assert.equal(getCount, 7, "the migration performs exactly one initial read and one proof re-read");
});

test("Dynamo write attempt tokens change with issuance facts to avoid IdempotentParameterMismatch", async () => {
  const clientTokens: string[] = [];
  const store = new DynamoConditionalUploadIntentStore({
    client: {
      async send(command) {
        if (command instanceof GetItemCommand) return {};
        const token = (command as TransactWriteItemsCommand<{ ClientRequestToken: string }>).input.ClientRequestToken;
        if (clientTokens.length > 0 && token === clientTokens[0]) {
          throw Object.assign(new Error("same token with changed write"), { name: "IdempotentParameterMismatchException" });
        }
        clientTokens.push(token);
        return {};
      },
    },
    TransactWriteItemsCommand,
    GetItemCommand,
    tableName: "scopeproof-control",
  });
  const recovery = await recoveryProjection();
  await store.reserve(intent(), recovery);
  await store.reserve({ ...intent(), issuedAt: "2026-08-27T16:02:00.000Z", expiresAt: "2026-08-27T16:07:00.000Z" }, recovery);
  assert.equal(clientTokens.length, 2);
  assert.notEqual(clientTokens[0], clientTokens[1]);
});

test("Dynamo upload store treats only proven conditional cancellation as recoverable", async () => {
  const recovery = await recoveryProjection();
  const collision = new DynamoConditionalUploadIntentStore({
    client: {
      async send(command) {
        if (command instanceof GetItemCommand) return {};
        throw Object.assign(new Error("duplicate"), {
          name: "TransactionCanceledException",
          CancellationReasons: [
            { Code: "None" }, { Code: "ConditionalCheckFailed" }, { Code: "None" },
            { Code: "None" }, { Code: "None" },
          ],
        });
      },
    },
    TransactWriteItemsCommand,
    GetItemCommand,
    tableName: "scopeproof-control",
  });
  await assert.rejects(collision.reserve(intent(), recovery), /conflicts with another request/);

  const outage = new DynamoConditionalUploadIntentStore({
    client: { async send() { throw Object.assign(new Error("throttled"), { name: "TransactionCanceledException" }); } },
    TransactWriteItemsCommand,
    GetItemCommand,
    tableName: "scopeproof-control",
  });
  await assert.rejects(outage.reserve(intent(), recovery), /throttled/);
});

test("Dynamo upload creation quota fails closed and minute limits bind tenant plus principal", async () => {
  const recovery = await recoveryProjection();
  const creationLimited = new DynamoConditionalUploadIntentStore({
    client: {
      async send(command) {
        if (command instanceof GetItemCommand) return {};
        throw Object.assign(new Error("daily quota"), {
          name: "TransactionCanceledException",
          CancellationReasons: [
            { Code: "None" }, { Code: "None" }, { Code: "None" },
            { Code: "ConditionalCheckFailed" }, { Code: "None" },
          ],
        });
      },
    },
    TransactWriteItemsCommand,
    GetItemCommand,
    tableName: "scopeproof-control",
    maximumNewUploadsPerPrincipalDay: 1,
    maximumNewUploadsPerTenantDay: 1,
  });
  await assert.rejects(
    creationLimited.reserve(intent(), recovery),
    (error: unknown) => error instanceof Error && (error as { safeStatus?: number }).safeStatus === 429,
  );

  let transaction: TransactWriteItemsCommand<Record<string, unknown>> | undefined;
  const limiter = new DynamoUploadRequestRateLimiter({
    client: { async send(command) { transaction = command as typeof transaction; return {}; } },
    TransactWriteItemsCommand,
    tableName: "scopeproof-control",
    maximumRequestsPerPrincipalMinute: 2,
    maximumRequestsPerTenantMinute: 3,
  });
  await limiter.consume({ tenantId: TENANT, requestedBy: USER, now: new Date("2026-08-27T16:04:59.999Z") });
  const input = transaction!.input as { TransactItems: Array<{ Update: { Key: Record<string, { S?: string }>; ExpressionAttributeValues: Record<string, { N?: string }> } }> };
  assert.equal(input.TransactItems.length, 2);
  assert.equal(input.TransactItems[0].Update.Key.SK.S, "RATE#UPLOAD_REQUEST#MINUTE#2026-08-27T16:04#TENANT");
  assert.equal(input.TransactItems[1].Update.Key.SK.S, `RATE#UPLOAD_REQUEST#MINUTE#2026-08-27T16:04#PRINCIPAL#${USER}`);
  assert.equal(input.TransactItems[0].Update.ExpressionAttributeValues[":limit"].N, "3");
  assert.equal(input.TransactItems[1].Update.ExpressionAttributeValues[":limit"].N, "2");

  const limited = new DynamoUploadRequestRateLimiter({
    client: {
      async send() {
        throw Object.assign(new Error("minute quota"), {
          name: "TransactionCanceledException",
          CancellationReasons: [{ Code: "None" }, { Code: "ConditionalCheckFailed" }],
        });
      },
    },
    TransactWriteItemsCommand,
    tableName: "scopeproof-control",
  });
  await assert.rejects(
    limited.consume({ tenantId: TENANT, requestedBy: USER, now: new Date("2026-08-27T16:04:59.999Z") }),
    (error: unknown) => error instanceof Error && (error as { safeStatus?: number }).safeStatus === 429,
  );
});

test("Dynamo route quotas isolate principal and tenant budgets by stable operation", async () => {
  let transaction: TransactWriteItemsCommand<Record<string, unknown>> | undefined;
  const limiter = new DynamoTenantRouteRateLimiter({
    client: { async send(command) { transaction = command as typeof transaction; return {}; } },
    TransactWriteItemsCommand,
    tableName: "scopeproof-control",
  });
  await limiter.consume({
    tenantId: TENANT,
    requestedBy: USER,
    route: "evidence.download",
    maximumRequestsPerPrincipalMinute: 60,
    maximumRequestsPerTenantMinute: 300,
    now: new Date("2026-08-27T16:04:59.999Z"),
  });
  const input = transaction!.input as { TransactItems: Array<{ Update: { Key: Record<string, { S?: string }>; ExpressionAttributeValues: Record<string, { N?: string; S?: string }> } }> };
  assert.equal(input.TransactItems.length, 2);
  assert.equal(input.TransactItems[0].Update.Key.SK.S, "RATE#EVIDENCE_DOWNLOAD#MINUTE#2026-08-27T16:04#TENANT");
  assert.equal(input.TransactItems[1].Update.Key.SK.S, `RATE#EVIDENCE_DOWNLOAD#MINUTE#2026-08-27T16:04#PRINCIPAL#${USER}`);
  assert.equal(input.TransactItems[0].Update.ExpressionAttributeValues[":limit"].N, "300");
  assert.equal(input.TransactItems[1].Update.ExpressionAttributeValues[":limit"].N, "60");
  assert.equal(input.TransactItems[1].Update.ExpressionAttributeValues[":subject"].S, `evidence.download:${USER}`);
  await assert.rejects(
    limiter.consume({
      tenantId: TENANT,
      requestedBy: USER,
      route: "../../../unbounded",
      maximumRequestsPerPrincipalMinute: 1,
      maximumRequestsPerTenantMinute: 1,
      now: new Date(),
    }),
    /route name is invalid/,
  );
});

test("Dynamo upload creation quota recovers an exact reservation committed at the limit", async () => {
  const recovery = await recoveryProjection();
  const persisted = new Map<string, Record<string, { S?: string; N?: string }>>();
  let writes = 0;
  const store = new DynamoConditionalUploadIntentStore({
    client: {
      async send(command) {
        if (command instanceof GetItemCommand) {
          const key = command.input.Key as Record<string, { S?: string }>;
          return { Item: persisted.get(key.SK.S ?? "") };
        }
        writes += 1;
        const transaction = command as TransactWriteItemsCommand<{
          TransactItems: Array<{ Put?: { Item: Record<string, { S?: string; N?: string }> } }>;
        }>;
        for (const entry of transaction.input.TransactItems) {
          if (entry.Put) persisted.set(entry.Put.Item.SK.S ?? "", entry.Put.Item);
        }
        throw Object.assign(new Error("commit response reported a quota collision"), {
          name: "TransactionCanceledException",
          CancellationReasons: [
            { Code: "ConditionalCheckFailed" }, { Code: "None" }, { Code: "None" },
            { Code: "ConditionalCheckFailed" }, { Code: "None" },
          ],
        });
      },
    },
    TransactWriteItemsCommand,
    GetItemCommand,
    tableName: "scopeproof-control",
    maximumNewUploadsPerPrincipalDay: 1,
    maximumNewUploadsPerTenantDay: 1,
  });

  const result = await store.reserve(intent(), recovery);
  assert.equal(result.outcome, "existing");
  assert.equal(result.intent.id, INTENT);
  assert.equal(writes, 1, "the exact retry must not consume a second daily creation slot");
});

test("AWS S3 presigner bridge makes all security headers unhoistable and exact", async () => {
  let command: PutObjectCommand<Record<string, unknown>> | undefined;
  let options: {
    expiresIn: number;
    signingDate: Date;
    signableHeaders: ReadonlySet<string>;
    unhoistableHeaders: ReadonlySet<string>;
  } | undefined;
  const headers = {
    "content-length": "1024",
    "content-type": "image/png",
    "x-amz-checksum-sha256": "ZmFrZQ==",
    "x-amz-meta-control-id": CONTROL,
    "x-amz-meta-evidence-id": EVIDENCE,
    "x-amz-meta-expected-sha256": "f".repeat(64),
    "x-amz-meta-tenant-id": TENANT,
    "x-amz-meta-upload-intent-id": INTENT,
    "x-amz-meta-upload-nonce-digest": "1".repeat(64),
    "x-amz-server-side-encryption": "aws:kms",
    "x-amz-server-side-encryption-aws-kms-key-id": EVIDENCE_KEY,
    "x-amz-server-side-encryption-context": "eyJ0ZXN0Ijp0cnVlfQ==",
  };
  const presigner = new AwsSdkV3ExactPutObjectPresigner({
    client: {},
    PutObjectCommand,
    async getSignedUrl(_client, value, received) {
      command = value as typeof command;
      options = received;
      return `https://scopeproof-quarantine.s3.us-east-1.amazonaws.com/${INTENT}`;
    },
  });
  const result = await presigner.presignPutObject({
    bucket: "scopeproof-quarantine",
    key: intent().quarantineKey,
    issuedAt: intent().issuedAt,
    signingAt: intent().issuedAt,
    expiresAt: intent().expiresAt,
    expiresInSeconds: 300,
    headers,
  });
  assert.deepEqual(result.requiredHeaders, headers);
  assert.equal(options?.expiresIn, 300);
  assert.equal(options?.signingDate.toISOString(), intent().issuedAt);
  assert.deepEqual([...options!.signableHeaders].sort(), Object.keys(headers).sort());
  assert.deepEqual([...options!.unhoistableHeaders].sort(), Object.keys(headers).sort());
  assert.equal(command?.input.SSEKMSKeyId, EVIDENCE_KEY);
  assert.equal((command?.input.Metadata as Record<string, string>)["control-id"], CONTROL);
  assert.equal((command?.input.Metadata as Record<string, string>)["upload-nonce-digest"], "1".repeat(64));
});

test("KMS and exact-version legal-hold bridges construct only approved commands", async () => {
  const seen: unknown[] = [];
  const client = {
    async send(command: unknown) {
      seen.push(command);
      if (command instanceof SignCommand) return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", Signature: new Uint8Array(384) };
      if (command instanceof VerifyCommand) return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", SignatureValid: true };
      if (command instanceof GetObjectLegalHoldCommand) return { LegalHold: { Status: "ON" }, $metadata: { requestId: "get-request" } };
      return { $metadata: { requestId: "put-request" } };
    },
  };
  const kms = new AwsSdkV3KmsAsymmetricSigningClient(client, { SignCommand, VerifyCommand });
  await kms.sign({ KeyId: SIGNING_KEY, Message: new Uint8Array(32), MessageType: "DIGEST", SigningAlgorithm: "RSASSA_PSS_SHA_256" });
  await kms.verify({ KeyId: SIGNING_KEY, Message: new Uint8Array(32), MessageType: "DIGEST", SigningAlgorithm: "RSASSA_PSS_SHA_256", Signature: new Uint8Array(384) });
  const holds = new AwsSdkV3ExactVersionLegalHoldClient(client, { PutObjectLegalHoldCommand, GetObjectLegalHoldCommand });
  const exact = { Bucket: "scopeproof-evidence", Key: intent().finalKey, VersionId: "version-123" };
  assert.equal((await holds.putObjectLegalHold({ ...exact, LegalHold: { Status: "ON" } })).requestId, "put-request");
  assert.equal((await holds.getObjectLegalHold(exact)).LegalHold?.Status, "ON");
  const holdCommands = seen.slice(2) as Array<Command<Record<string, unknown>>>;
  assert.ok(holdCommands.every((value) => value.input.VersionId === "version-123"));
});

test("RDS legal-hold store commits request and independent approval before CAS-confirming S3", async () => {
  const calls: Array<{ kind: string; input: Record<string, unknown> }> = [];
  let canonicalApproval = "";
  let approvalDigest = "";
  const executor: RdsDataApiExecutor = {
    async beginTransaction(input) {
      calls.push({ kind: "begin", input });
      return { transactionId: `transaction-${calls.length}-12345678` };
    },
    async executeStatement(input) {
      calls.push({ kind: "execute", input: input as unknown as Record<string, unknown> });
      if (input.sql.includes("reserve_exact_version_legal_hold")) {
        return { formattedRecords: JSON.stringify([{
          operation_state: "REQUESTED",
          operation_revision: 0,
          committed_canonical_approval: null,
          committed_approval_digest: null,
          committed_canonical_receipt: null,
          committed_receipt_sha256: null,
        }]) };
      }
      if (input.sql.includes("approve_exact_version_legal_hold")) {
        const parameters = Object.fromEntries(input.parameters.map((entry) => [entry.name, entry.value.stringValue]));
        canonicalApproval = parameters.canonical_approval;
        approvalDigest = parameters.approval_digest;
        return { formattedRecords: JSON.stringify([{
          operation_state: "APPROVED",
          operation_revision: 1,
          committed_canonical_approval: canonicalApproval,
          committed_approval_digest: approvalDigest,
        }]) };
      }
      if (input.sql.includes("read_exact_version_legal_hold_operation")) {
        return { formattedRecords: JSON.stringify([{
          operation_state: "APPROVED",
          operation_revision: 1,
          committed_canonical_approval: canonicalApproval,
          committed_approval_digest: approvalDigest,
          committed_canonical_receipt: null,
          committed_receipt_sha256: null,
        }]) };
      }
      if (input.sql.includes("begin_exact_version_legal_hold_application")) {
        const parameters = Object.fromEntries(input.parameters.map((entry) => [entry.name, entry.value.stringValue]));
        return { formattedRecords: JSON.stringify([{
          operation_state: "APPLYING", operation_revision: 2,
          application_attempt_id: parameters.attempt_id, application_prior_status: parameters.prior_status,
          application_observed_request_id: parameters.observed_request_id, application_started_at: parameters.started_at,
        }]) };
      }
      if (input.sql.includes("confirm_exact_version_legal_hold")) {
        const parameters = Object.fromEntries(input.parameters.map((entry) => [entry.name, entry.value.stringValue]));
        return { formattedRecords: JSON.stringify([{
          was_created: true,
          operation_revision: 3,
          hold_revision: 0,
          committed_canonical_receipt: parameters.canonical_receipt,
          committed_receipt_sha256: parameters.receipt_sha256,
        }]) };
      }
      return {};
    },
    async commitTransaction(input) { calls.push({ kind: "commit", input }); },
    async rollbackTransaction(input) { calls.push({ kind: "rollback", input }); },
  };
  const operation = await prepareExactVersionLegalHoldOperation({
    tenantId: TENANT,
    controlId: CONTROL,
    evidenceId: EVIDENCE,
    contentType: "image/png",
    bucket: "scopeproof-evidence",
    key: intent().finalKey,
    versionId: "evidence-version-1",
    status: "ON",
    changedAt: new Date("2026-08-27T16:10:00.000Z"),
    operationId: HOLD_OPERATION,
    holdId: HOLD,
    reason: "External litigation preservation request",
    kind: "LEGAL",
    expectedHoldRevision: 0,
  }, {
    tenantId: TENANT as TenantActor["tenantId"],
    userId: USER as TenantActor["userId"],
    role: "admin",
  }, { evidenceBucket: "scopeproof-evidence" });
  const store = new RdsDataExactVersionLegalHoldOperationStore({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:tenant-runtime-AbCd",
    database: "scopeproof_acme",
  });
  assert.deepEqual(await store.request(operation, {
    membershipId: MEMBERSHIP,
    requestId: "request-legal-hold-0001",
  }), { state: "REQUESTED", operationRevision: 0 });
  const approval = await prepareExactVersionLegalHoldApproval({
    tenantId: TENANT,
    operationId: HOLD_OPERATION,
    requestDigest: operation.requestDigest,
    approvedAt: new Date("2026-08-27T16:11:00.000Z"),
  }, {
    tenantId: TENANT as TenantActor["tenantId"],
    userId: APPROVER as TenantActor["userId"],
    role: "admin",
  });
  assert.equal((await store.approve(approval, {
    membershipId: MEMBERSHIP,
    requestId: "request-legal-hold-0002",
  })).state, "APPROVED");
  assert.equal((await store.read(operation)).state, "APPROVED");
  const receipt = {
    schemaVersion: 1 as const,
    operationId: HOLD_OPERATION,
    holdId: HOLD,
    tenantId: TENANT,
    controlId: CONTROL,
    evidenceId: EVIDENCE,
    bucket: "scopeproof-evidence",
    key: intent().finalKey,
    versionId: "evidence-version-1",
    status: "ON" as const,
    changedAt: "2026-08-27T16:10:00.000Z",
    applicationAttemptId: "a".repeat(64),
    priorStatus: "OFF" as const,
    putRequestId: "put-request-0001",
    verifyRequestId: "get-request-0001",
  };
  await store.beginApply(operation, approval, 1, {
    schemaVersion: 1, attemptId: "a".repeat(64), priorStatus: "OFF",
    observedRequestId: "get-request-0000", startedAt: "2026-08-27T16:12:00.000Z",
  });
  const applied = await store.apply(operation, approval, 2, receipt);
  assert.equal(applied.outcome, "applied");
  assert.equal(applied.operationRevision, 3);
  assert.equal(applied.holdRevision, 0);
  assert.deepEqual(calls.map((call) => call.kind), [
    "begin", "execute", "execute", "commit",
    "begin", "execute", "execute", "commit",
    "begin", "execute", "execute", "commit",
    "begin", "execute", "execute", "commit",
    "begin", "execute", "execute", "commit",
  ]);
  const reserveStatement = calls[2].input;
  const approvalStatement = calls[6].input;
  const readStatement = calls[10].input;
  const beginApplyStatement = calls[14].input;
  const applyStatement = calls[18].input;
  assert.match(String(reserveStatement.sql), /reserve_exact_version_legal_hold_with_audit/);
  assert.match(String(approvalStatement.sql), /approve_exact_version_legal_hold_with_audit/);
  assert.match(String(readStatement.sql), /read_exact_version_legal_hold_operation/);
  assert.match(String(beginApplyStatement.sql), /begin_exact_version_legal_hold_application/);
  assert.match(String(applyStatement.sql), /confirm_exact_version_legal_hold/);
  assert.doesNotMatch(String(reserveStatement.sql), new RegExp(TENANT));
  assert.equal(
    (reserveStatement.parameters as Array<{ name: string; value: { stringValue: string } }>).
      find((entry) => entry.name === "object_version_id")?.value.stringValue,
    "evidence-version-1",
  );
  assert.equal(
    (reserveStatement.parameters as Array<{ name: string; value: { stringValue: string } }>).
      find((entry) => entry.name === "membership_id")?.value.stringValue,
    MEMBERSHIP,
  );
  assert.equal(
    (approvalStatement.parameters as Array<{ name: string; value: { stringValue: string } }>).
      find((entry) => entry.name === "request_id")?.value.stringValue,
    "request-legal-hold-0002",
  );
  assert.deepEqual(await store.request(operation), { state: "REQUESTED", operationRevision: 0 });
  const internalReplayStatement = calls.at(-2)?.input;
  assert.match(String(internalReplayStatement?.sql), /reserve_exact_version_legal_hold\(/);
  assert.doesNotMatch(String(internalReplayStatement?.sql), /reserve_exact_version_legal_hold_with_audit/);
  assert.equal(
    (internalReplayStatement?.parameters as Array<{ name: string }>).some((entry) => entry.name === "membership_id"),
    false,
  );
});

test("RDS legal-hold source expires and audits only exact canonical tenant operations", async () => {
  const operation = await prepareExactVersionLegalHoldOperation({
    tenantId: TENANT,
    controlId: CONTROL,
    evidenceId: EVIDENCE,
    contentType: "image/png",
    bucket: "scopeproof-evidence",
    key: intent().finalKey,
    versionId: "evidence-version-1",
    status: "ON",
    changedAt: new Date("2026-08-26T16:00:00.000Z"),
    operationId: HOLD_OPERATION,
    holdId: HOLD,
    reason: "External litigation preservation request",
    kind: "LEGAL",
    expectedHoldRevision: 0,
  }, {
    tenantId: TENANT as TenantActor["tenantId"],
    userId: USER as TenantActor["userId"],
    role: "admin",
  }, { evidenceBucket: "scopeproof-evidence" });
  const calls: Array<Record<string, unknown>> = [];
  const executor: RdsDataApiExecutor = {
    async beginTransaction() { return { transactionId: `transaction-${calls.length}-12345678` }; },
    async executeStatement(input) {
      calls.push(input as unknown as Record<string, unknown>);
      if (input.sql.includes("expire_stale_exact_version_legal_hold_requests")) {
        return { formattedRecords: JSON.stringify([{
          operation_id: HOLD_OPERATION,
          canonical_request: operation.canonicalRequest,
          request_digest: operation.requestDigest,
          expired_at: "2026-08-27T16:05:00.000Z",
        }]) };
      }
      if (input.sql.includes("list_unaudited_expired_legal_holds")) {
        return { formattedRecords: JSON.stringify([{
          canonical_request: operation.canonicalRequest,
          request_digest: operation.requestDigest,
          expired_at: "2026-08-27T16:05:00.000Z",
        }]) };
      }
      if (input.sql.includes("record_exact_version_legal_hold_reconciliation_failure")) {
        return { formattedRecords: JSON.stringify([{
          attempt_count: 1,
          next_attempt_at: "2026-08-27T16:05:30.000Z",
        }]) };
      }
      if (input.sql.includes("acknowledge_legal_hold_recovery_publication")) {
        return { formattedRecords: JSON.stringify([{
          recovery_published_at: "2026-08-27T16:06:00.000Z",
        }]) };
      }
      return {};
    },
    async commitTransaction() {},
    async rollbackTransaction() {},
  };
  const source = new RdsDataLegalHoldReconciliationSource({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:tenant-control-AbCd",
    database: "scopeproof_acme",
  });
  assert.deepEqual(await source.expireStaleRequests({
    tenantId: TENANT,
    now: "2026-08-27T16:05:00.000Z",
    limit: 10,
  }), [{ operation, expiredAt: "2026-08-27T16:05:00.000Z" }]);
  assert.deepEqual(await source.listUnauditedExpired({ tenantId: TENANT, limit: 10 }), [{
    operation,
    expiredAt: "2026-08-27T16:05:00.000Z",
  }]);
  assert.deepEqual(await source.recordReconciliationFailure({
    tenantId: TENANT,
    operationId: HOLD_OPERATION,
    requestDigest: operation.requestDigest,
    errorCode: "RECONCILIATION_FAILED",
    failedAt: "2026-08-27T16:05:00.000Z",
  }), {
    attemptCount: 1,
    nextAttemptAt: "2026-08-27T16:05:30.000Z",
  });
  assert.equal(await source.acknowledgeRecoveryPublication({
    tenantId: TENANT,
    operationId: HOLD_OPERATION,
    requestDigest: operation.requestDigest,
    publishedAt: "2026-08-27T16:06:00.000Z",
  }), "2026-08-27T16:06:00.000Z");
  const statements = calls.filter((call) => String(call.sql).includes("scopeproof.") &&
    !String(call.sql).includes("set_config"));
  assert.match(String(statements[0].sql), /operation_id::text/);
  assert.match(String(statements[0].sql), /expire_stale_exact_version_legal_hold_requests/);
  assert.match(String(statements[1].sql), /list_unaudited_expired_legal_holds/);
  assert.match(String(statements[2].sql), /record_exact_version_legal_hold_reconciliation_failure/);
  assert.match(String(statements[3].sql), /acknowledge_legal_hold_recovery_publication/);
  assert.ok(statements.every((statement) => !String(statement.sql).includes(TENANT)));
});

test("RDS legal-hold store represents terminal EXPIRED rows without approval material", async () => {
  const operation = await prepareExactVersionLegalHoldOperation({
    tenantId: TENANT,
    controlId: CONTROL,
    evidenceId: EVIDENCE,
    contentType: "image/png",
    bucket: "scopeproof-evidence",
    key: intent().finalKey,
    versionId: "evidence-version-1",
    status: "ON",
    changedAt: new Date("2026-08-26T16:00:00.000Z"),
    operationId: HOLD_OPERATION,
    holdId: HOLD,
    reason: "External litigation preservation request",
    kind: "LEGAL",
    expectedHoldRevision: 0,
  }, {
    tenantId: TENANT as TenantActor["tenantId"],
    userId: USER as TenantActor["userId"],
    role: "admin",
  }, { evidenceBucket: "scopeproof-evidence" });
  const executor: RdsDataApiExecutor = {
    async beginTransaction() { return { transactionId: "transaction-expired-12345678" }; },
    async executeStatement(input) {
      if (!input.sql.includes("read_exact_version_legal_hold_operation")) return {};
      return { formattedRecords: JSON.stringify([{
        operation_state: "EXPIRED",
        operation_revision: 1,
        committed_canonical_approval: null,
        committed_approval_digest: null,
        committed_canonical_receipt: null,
        committed_receipt_sha256: null,
      }]) };
    },
    async commitTransaction() {},
    async rollbackTransaction() {},
  };
  const store = new RdsDataExactVersionLegalHoldOperationStore({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:tenant-control-AbCd",
    database: "scopeproof_acme",
  });
  assert.deepEqual(await store.read(operation), { state: "EXPIRED", operationRevision: 1 });
});

function facts(): PromotionFacts {
  return {
    schemaVersion: 1,
    tenantId: TENANT,
    uploadIntentId: INTENT,
    evidenceId: EVIDENCE,
    controlId: CONTROL,
    quarantineBucket: "scopeproof-quarantine",
    quarantineKey: intent().quarantineKey,
    quarantineVersionId: "quarantine-version-1",
    evidenceBucket: "scopeproof-evidence",
    evidenceKey: intent().finalKey,
    evidenceVersionId: "evidence-version-1",
    sha256: "f".repeat(64),
    byteSize: 1024,
    contentType: "image/png",
    copyAttemptId: `pat_${"1".repeat(32)}`,
    copyFence: 1,
    dlpPolicyVersion: "pci-evidence-v1",
    dlpReceiptSha256: "3".repeat(64),
    dlpScannedAt: "2026-08-27T16:04:00.000Z",
    dlpScannerRequestId: "scan-request-123456",
    kmsKeyArn: EVIDENCE_KEY,
    objectLockMode: "COMPLIANCE",
    promotionAttemptId: `pat_${"2".repeat(32)}`,
    promotionFence: 2,
    retainUntil: "2027-08-27T16:05:00.000Z",
    uploadedAt: "2026-08-27T16:00:00.000Z",
    promotedAt: "2026-08-27T16:05:00.000Z",
    providerRequestId: "s3-request-123",
  };
}

function promotionCommand(): AtomicPromotionCommand {
  return {
    tenantId: TENANT,
    receiptId: RECEIPT,
    expectedUploadRevision: 0,
    expectedEvidenceRevision: 0,
    idempotencyDigest: "9".repeat(64),
    promotionLeaseExpiresAt: "2026-08-27T16:10:00.000Z",
    requiredRetentionUntil: "2027-08-27T16:05:00.000Z",
    facts: facts(),
  };
}

class RecordingExecutor implements RdsDataApiExecutor {
  readonly calls: Array<{ kind: string; input: Record<string, unknown> }> = [];
  error?: Error & { databaseErrorCode?: string };
  promotionFactsAsString = false;
  promotionWasCreated = true;
  committedSignature?: string;
  committedSignedAt?: string;

  async beginTransaction(input: Record<string, string>) {
    this.calls.push({ kind: "begin", input });
    return { transactionId: "transaction-12345678" };
  }
  async executeStatement(input: Parameters<RdsDataApiExecutor["executeStatement"]>[0]) {
    this.calls.push({ kind: "execute", input: input as unknown as Record<string, unknown> });
    if (this.error && input.sql.includes("reconcile_promoted_evidence")) throw this.error;
    if (!input.sql.includes("reconcile_promoted_evidence")) return {};
    const parameters = Object.fromEntries(input.parameters.map((parameter) => [parameter.name, parameter.value.stringValue]));
    return { formattedRecords: JSON.stringify([{
      receipt_id: parameters.receipt_id,
      was_created: this.promotionWasCreated,
      committed_upload_revision: 1,
      committed_evidence_revision: 1,
      committed_idempotency_digest: parameters.idempotency_digest,
      committed_promotion_facts: this.promotionFactsAsString
        ? parameters.promotion_facts
        : JSON.parse(parameters.promotion_facts),
      committed_canonical_receipt: parameters.canonical_receipt,
      committed_receipt_sha256: parameters.receipt_sha256,
      committed_signing_key_arn: parameters.signing_key_arn,
      committed_signing_algorithm: parameters.signing_algorithm,
      committed_signature: this.committedSignature ?? parameters.signature,
      committed_signed_at: this.committedSignedAt ?? parameters.signed_at,
    }]) };
  }
  async commitTransaction(input: Record<string, string>) { this.calls.push({ kind: "commit", input }); }
  async rollbackTransaction(input: Record<string, string>) { this.calls.push({ kind: "rollback", input }); }
}

test("RDS promotion store signs facts and commits both CAS updates plus receipt through one procedure", async () => {
  const executor = new RecordingExecutor();
  const kms = {
    async sign(input: { KeyId: string }) {
      assert.equal(input.KeyId, SIGNING_KEY);
      return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", Signature: new Uint8Array(384).fill(7) };
    },
    async verify(input: { KeyId: string; Signature: Uint8Array }) {
      assert.equal(input.KeyId, SIGNING_KEY);
      assert.equal(input.Signature.byteLength, 384);
      return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", SignatureValid: true };
    },
  };
  const store = new RdsDataAtomicPromotionStore({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:tenant-ingest-AbCd",
    database: "scopeproof_acme",
    kms,
    signingKeyArn: SIGNING_KEY,
    clock: () => new Date("2026-08-27T16:05:01.000Z"),
  });
  const result = await store.transactPromotion(promotionCommand());
  assert.equal(result.outcome, "applied");
  assert.equal(result.committed, true);
  assert.deepEqual(executor.calls.map((call) => call.kind), ["begin", "execute", "execute", "execute", "commit"]);
  assert.match(String(executor.calls[2].input.sql), /claim_promotion_fence/);
  const statement = executor.calls[3].input;
  assert.match(String(statement.sql), /reconcile_promoted_evidence/);
  assert.doesNotMatch(String(statement.sql), new RegExp(TENANT));
  const parameters = statement.parameters as Array<{ name: string; value: { stringValue: string } }>;
  const signingKey = parameters.find((parameter) => parameter.name === "signing_key_arn")?.value.stringValue;
  assert.equal(signingKey, SIGNING_KEY);
  assert.equal(parameters.find((parameter) => parameter.name === "signature")?.value.stringValue.length, 512);
});

test("RDS promotion store rolls back and reports a proven CAS conflict", async () => {
  const executor = new RecordingExecutor();
  executor.error = Object.assign(new Error("revision changed"), { databaseErrorCode: "40001" });
  const store = new RdsDataAtomicPromotionStore({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:tenant-ingest-AbCd",
    database: "scopeproof_acme",
    kms: {
      async sign() { return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", Signature: new Uint8Array(384) }; },
      async verify() { return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", SignatureValid: true }; },
    },
    signingKeyArn: SIGNING_KEY,
    clock: () => new Date("2026-08-27T16:05:01.000Z"),
  });
  assert.deepEqual(await store.transactPromotion(promotionCommand()), {
    outcome: "condition_failed",
    committed: false,
    reason: "revision_changed",
  });
  assert.equal(executor.calls.at(-1)?.kind, "rollback");
});

test("RDS promotion store accepts the Data API JSON-string representation of jsonb facts", async () => {
  const executor = new RecordingExecutor();
  executor.promotionFactsAsString = true;
  const store = new RdsDataAtomicPromotionStore({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:tenant-ingest-AbCd",
    database: "scopeproof_acme",
    kms: {
      async sign() { return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", Signature: new Uint8Array(384) }; },
      async verify() { return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", SignatureValid: true }; },
    },
    signingKeyArn: SIGNING_KEY,
    clock: () => new Date("2026-08-27T16:05:01.000Z"),
  });
  const result = await store.transactPromotion(promotionCommand());
  assert.equal(result.outcome, "applied");
  assert.deepEqual(result.snapshot.facts, facts());
});

test("RDS promotion store verifies the exact committed signature before accepting a valid replay", async () => {
  const executor = new RecordingExecutor();
  executor.promotionWasCreated = false;
  executor.committedSignature = Buffer.alloc(384, 19).toString("base64");
  let verifiedSignature: Uint8Array | undefined;
  const store = new RdsDataAtomicPromotionStore({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:tenant-ingest-AbCd",
    database: "scopeproof_acme",
    kms: {
      async sign() { return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", Signature: new Uint8Array(384).fill(7) }; },
      async verify(input) {
        verifiedSignature = input.Signature;
        assert.deepEqual(input.Message, new Uint8Array(Buffer.from(await sha256Hex(
          `scopeproof-promotion-receipt-v1\n${stableJson(facts() as unknown as Parameters<typeof stableJson>[0])}`,
        ), "hex")));
        return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", SignatureValid: true };
      },
    },
    signingKeyArn: SIGNING_KEY,
    clock: () => new Date("2026-08-27T16:05:01.000Z"),
  });
  const result = await store.transactPromotion(promotionCommand());
  assert.equal(result.outcome, "already_applied");
  assert.deepEqual(verifiedSignature, new Uint8Array(384).fill(19));
  assert.equal(executor.calls.at(-1)?.kind, "commit");
});

test("RDS promotion store rejects forged or corrupt committed replay signatures and rolls back", async () => {
  for (const mode of ["forged", "corrupt"] as const) {
    const executor = new RecordingExecutor();
    executor.promotionWasCreated = false;
    executor.committedSignature = mode === "forged" ? Buffer.alloc(384, 23).toString("base64") : "not-base64";
    const store = new RdsDataAtomicPromotionStore({
      executor,
      resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
      secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:tenant-ingest-AbCd",
      database: "scopeproof_acme",
      kms: {
        async sign() { return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", Signature: new Uint8Array(384) }; },
        async verify() { return { KeyId: SIGNING_KEY, SigningAlgorithm: "RSASSA_PSS_SHA_256", SignatureValid: false }; },
      },
      signingKeyArn: SIGNING_KEY,
      clock: () => new Date("2026-08-27T16:05:01.000Z"),
    });
    await assert.rejects(store.transactPromotion(promotionCommand()), /signature|verify|conflicting/i);
    assert.equal(executor.calls.at(-1)?.kind, "rollback");
    assert.ok(!executor.calls.some((call) => call.kind === "commit"));
  }
});
