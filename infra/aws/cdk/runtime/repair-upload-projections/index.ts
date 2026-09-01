import { createHash } from "node:crypto";
import { DynamoDBClient, GetItemCommand, QueryCommand, UpdateItemCommand, type AttributeValue } from "@aws-sdk/client-dynamodb";
import {
  BeginTransactionCommand, CommitTransactionCommand, ExecuteStatementCommand,
  RDSDataClient, RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";
import { AwsSdkV3RdsDataApiExecutor, type RdsDataApiCommandConstructors } from "../../../../../lib/aws-runtime/http/index.ts";
import { RdsDataUploadIntentProjection, type ControlledUploadIntent, type UploadIntentEvidenceProjection } from "../../../../../lib/aws-runtime/evidence/index.ts";

const required = ["CONTROL_TABLE_NAME", "DATABASE_CLUSTER_ARN", "DATABASE_NAME", "DATABASE_SECRET_ARN", "TENANT_ID"] as const;
const env = Object.fromEntries(required.map((name) => {
  const value = String(process.env[name] ?? "");
  if (!value || value !== value.trim()) throw new Error(`Missing required environment variable ${name}.`);
  return [name, value];
})) as Record<typeof required[number], string>;
if (!/^ten_[a-f0-9]{32}$/.test(env.TENANT_ID) || !/^scopeproof_[a-z0-9_]{1,48}$/.test(env.DATABASE_NAME)) {
  throw new Error("Unsafe upload projection repair identity.");
}
const region = String(process.env.AWS_REGION ?? "");
if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region)) throw new Error("Unsafe AWS region.");
const dynamo = new DynamoDBClient({ region });
const rdsClient = new RDSDataClient({ region });
type Input<T> = T extends new(input: infer I) => unknown ? I : never;
const compatible = <I>(ctor: new(input: never) => unknown): new(input: I) => unknown => ctor as unknown as new(input: I) => unknown;
const executor = new AwsSdkV3RdsDataApiExecutor(rdsClient, {
  BeginTransactionCommand: compatible<Input<RdsDataApiCommandConstructors["BeginTransactionCommand"]>>(BeginTransactionCommand as never),
  ExecuteStatementCommand: compatible<Input<RdsDataApiCommandConstructors["ExecuteStatementCommand"]>>(ExecuteStatementCommand as never),
  CommitTransactionCommand: compatible<Input<RdsDataApiCommandConstructors["CommitTransactionCommand"]>>(CommitTransactionCommand as never),
  RollbackTransactionCommand: compatible<Input<RdsDataApiCommandConstructors["RollbackTransactionCommand"]>>(RollbackTransactionCommand as never),
});
const projection = new RdsDataUploadIntentProjection({
  executor, resourceArn: env.DATABASE_CLUSTER_ARN, secretArn: env.DATABASE_SECRET_ARN, database: env.DATABASE_NAME,
});

export async function handler(event: unknown): Promise<{ repaired: number; examined: number }> {
  assertScheduleMessage(event);
  const cursorKey = { PK: { S: `TENANT#${env.TENANT_ID}` }, SK: { S: "REPAIR#UPLOAD_PROJECTION_CURSOR" } };
  const cursor = (await dynamo.send(new GetItemCommand({ ConsistentRead: true, Key: cursorKey, TableName: env.CONTROL_TABLE_NAME }))).Item;
  const cursorSortKey = cursor?.lastEvaluatedSortKey?.S;
  if (cursor && (cursor.kind?.S !== "UploadProjectionRepairCursor" || cursor.tenantId?.S !== env.TENANT_ID ||
      (cursorSortKey !== "" && !/^UPLOAD#upl_[a-f0-9]{32}$/.test(cursorSortKey ?? "")))) {
    throw new Error("Upload projection repair cursor is malformed.");
  }
  let lastKey: Record<string, AttributeValue> | undefined = cursorSortKey
    ? { PK: { S: `TENANT#${env.TENANT_ID}` }, SK: { S: cursorSortKey } }
    : undefined;
  let examined = 0;
  let repaired = 0;
  do {
    const page = await dynamo.send(new QueryCommand({
      ConsistentRead: true,
      ExclusiveStartKey: lastKey,
      ExpressionAttributeNames: { "#pk": "PK", "#sk": "SK" },
      ExpressionAttributeValues: { ":pk": { S: `TENANT#${env.TENANT_ID}` }, ":upload": { S: "UPLOAD#" } },
      KeyConditionExpression: "#pk = :pk AND begins_with(#sk, :upload)",
      Limit: 100,
      TableName: env.CONTROL_TABLE_NAME,
    }));
    for (const item of page.Items ?? []) {
      examined += 1;
      if (item.databaseProjectionStatus?.S === "READY") continue;
      const parsed = parseLifecycle(item);
      if (!parsed) continue;
      await projection.project(parsed.intent, parsed.evidence);
      await dynamo.send(new UpdateItemCommand({
        ConditionExpression: "evidenceProjectionDigest = :digest AND #status = :status AND (attribute_not_exists(databaseProjectionStatus) OR databaseProjectionStatus <> :ready)",
        ExpressionAttributeNames: { "#status": "status" },
        ExpressionAttributeValues: {
          ":digest": { S: parsed.digest }, ":ready": { S: "READY" },
          ":status": { S: parsed.sourceStatus }, ":when": { S: new Date().toISOString() },
        },
        Key: { PK: item.PK!, SK: item.SK! },
        TableName: env.CONTROL_TABLE_NAME,
        UpdateExpression: "SET databaseProjectionStatus = :ready, databaseProjectedAt = :when",
      }));
      repaired += 1;
    }
    lastKey = page.LastEvaluatedKey;
    if (examined >= 1_000) break;
  } while (lastKey);
  await dynamo.send(new UpdateItemCommand({
    ExpressionAttributeValues: {
      ":kind": { S: "UploadProjectionRepairCursor" },
      ":last": { S: lastKey?.SK?.S ?? "" },
      ":tenant": { S: env.TENANT_ID },
      ":when": { S: new Date().toISOString() },
    },
    Key: cursorKey,
    TableName: env.CONTROL_TABLE_NAME,
    UpdateExpression: "SET #kind = :kind, tenantId = :tenant, lastEvaluatedSortKey = :last, updatedAt = :when",
    ExpressionAttributeNames: { "#kind": "kind" },
  }));
  return { repaired, examined };
}

function parseLifecycle(item: Record<string, AttributeValue>): { intent: ControlledUploadIntent; evidence: UploadIntentEvidenceProjection; digest: string; sourceStatus: string } | undefined {
  const sourceStatus = exactS(item, "status");
  if (!new Set(["issued", "quarantined", "validated"]).has(sourceStatus)) return undefined;
  if (exactS(item, "kind") !== "UploadLifecycle" || exactN(item, "schemaVersion") !== 1 || exactS(item, "tenantId") !== env.TENANT_ID ||
      exactN(item, "databaseUploadRevision") !== 0 || exactN(item, "databaseEvidenceRevision") !== 0) {
    throw new Error("Upload lifecycle projection authority is malformed.");
  }
  const canonical = exactS(item, "canonicalEvidenceProjection");
  const digest = exactS(item, "evidenceProjectionDigest");
  if (canonical.length > 131_072 || sha256(`scopeproof-upload-evidence-projection-v1\n${canonical}`) !== digest) {
    throw new Error("Upload lifecycle evidence projection digest is invalid.");
  }
  const evidence = JSON.parse(canonical) as Record<string, unknown>;
  if (!evidence || Array.isArray(evidence) || stableJson(evidence) !== canonical || evidence.schemaVersion !== 1) {
    throw new Error("Upload lifecycle evidence projection is not canonical.");
  }
  const intent = Object.freeze({
    schemaVersion: 1 as const, id: exactS(item, "id"), tenantId: env.TENANT_ID,
    requestedBy: exactS(item, "requestedBy"), resourceId: exactS(item, "resourceId"),
    expectedSha256: exactS(item, "expectedSha256"), expectedSize: exactN(item, "expectedSize"),
    contentType: exactS(item, "contentType"), nonceDigest: exactS(item, "nonceDigest"),
    quarantineKey: exactS(item, "quarantineKey"), finalKey: exactS(item, "finalKey"),
    issuedAt: exactS(item, "issuedAt"), expiresAt: exactS(item, "expiresAt"),
    requiredRetentionUntil: exactS(item, "requiredRetentionUntil"), revision: 0,
    status: "issued" as const, controlId: exactS(item, "controlId"),
    quarantineBucket: exactS(item, "quarantineBucket"), quarantineKmsKeyArn: exactS(item, "quarantineKmsKeyArn"),
    idempotencyDigest: exactS(item, "idempotencyDigest"), requestFingerprint: exactS(item, "requestFingerprint"),
  }) as ControlledUploadIntent;
  const exactKeys = ["artifactExpiresAt", "assessmentId", "capturedAt", "description", "deviceId", "evidenceType", "metadata", "schemaVersion", "source", "systemName", "title"];
  if (JSON.stringify(Object.keys(evidence).sort()) !== JSON.stringify(exactKeys.sort())) throw new Error("Evidence projection contains unexpected fields.");
  return { intent, evidence: evidence as unknown as UploadIntentEvidenceProjection, digest, sourceStatus };
}

function assertScheduleMessage(value: unknown): void {
  const record = value as Record<string, unknown>;
  if (!record || record.schemaVersion !== 1 || record.type !== "scopeproof.upload_projection.repair" ||
      record.tenantId !== env.TENANT_ID || JSON.stringify(Object.keys(record).sort()) !== JSON.stringify(["schemaVersion", "tenantId", "type"])) {
    throw new Error("Upload projection repair invocation is invalid.");
  }
}
function exactS(item: Record<string, AttributeValue>, name: string): string { const value = item[name]; if (!value || typeof value.S !== "string" || Object.keys(value).length !== 1) throw new Error(`Invalid lifecycle ${name}.`); return value.S; }
function exactN(item: Record<string, AttributeValue>, name: string): number { const raw = item[name]?.N; if (!raw || !/^(0|[1-9][0-9]*)$/.test(raw) || Object.keys(item[name]!).length !== 1) throw new Error(`Invalid lifecycle ${name}.`); const value = Number(raw); if (!Number.isSafeInteger(value)) throw new Error(`Invalid lifecycle ${name}.`); return value; }
function sha256(value: string): string { return createHash("sha256").update(value).digest("hex"); }
function stableJson(value: unknown): string { if (value === null || typeof value !== "object") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`; const object = value as Record<string, unknown>; return `{${Object.keys(object).sort().map((k) => `${JSON.stringify(k)}:${stableJson(object[k])}`).join(",")}}`; }
