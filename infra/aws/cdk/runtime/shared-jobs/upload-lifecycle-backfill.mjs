import { createHash } from "node:crypto";
import {
  DynamoDBClient,
  GetItemCommand,
  QueryCommand,
  TransactWriteItemsCommand,
} from "@aws-sdk/client-dynamodb";
import {
  MalformedUploadLifecycleBackfillAuthorityError,
  parseUploadLifecycleBackfillEvent,
  planUploadLifecycleBackfill,
} from "./upload-lifecycle-backfill-contract.mjs";

const uploadPattern = /^upl_[a-f0-9]{32}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const tableNamePattern = /^[A-Za-z0-9_.-]{3,255}$/;
const regionPattern = /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/;
const activeStatuses = new Set(["issued", "quarantined", "validated"]);
const terminalStatuses = new Set(["promoted", "rejected", "expired"]);

const tableName = String(process.env.CONTROL_TABLE_NAME ?? "");
const region = String(process.env.AWS_REGION ?? "");
const maximumItems = boundedInteger(process.env.MAXIMUM_BACKFILL_ITEMS, 1, 100, "MAXIMUM_BACKFILL_ITEMS");
if (!tableNamePattern.test(tableName) || !regionPattern.test(region)) {
  throw new Error("Upload lifecycle backfill runtime identity is invalid.");
}
const dynamo = new DynamoDBClient({ region });

/**
 * Manually backfill exactly one bounded page. The function is intentionally not
 * scheduled and does not loop over tenants or pagination cursors.
 */
export async function handler(event) {
  try {
    const request = parseUploadLifecycleBackfillEvent(event, maximumItems);
    const result = await backfillPage(request);
    console.info("scopeproof_upload_lifecycle_backfill_completed", {
      conflict: result.counts.conflict,
      current: result.counts.current,
      examined: result.counts.examined,
      malformed: result.counts.malformed,
      terminal: result.counts.terminal,
      tenantIdSha256: digestHex(request.tenantId),
      upgraded: result.counts.upgraded,
    });
    return result;
  } catch (error) {
    console.error("scopeproof_upload_lifecycle_backfill_failed", { errorClass: safeErrorClass(error) });
    throw new Error("Upload lifecycle backfill page failed.");
  }
}

async function backfillPage(request) {
  const partitionKey = `TENANT#${request.tenantId}`;
  const response = await dynamo.send(new QueryCommand({
    ConsistentRead: true,
    ExclusiveStartKey: request.cursor
      ? { PK: { S: request.cursor.partitionKey }, SK: { S: request.cursor.sortKey } }
      : undefined,
    ExpressionAttributeNames: {
      "#kind": "kind",
      "#pk": "PK",
      "#revision": "revision",
      "#sk": "SK",
      "#status": "status",
      "#validation": "validation",
    },
    ExpressionAttributeValues: {
      ":tenant": { S: partitionKey },
      ":upload": { S: "UPLOAD#" },
    },
    KeyConditionExpression: "#pk = :tenant AND begins_with(#sk, :upload)",
    Limit: request.limit,
    ProjectionExpression: "#pk, #sk, GSI1PK, GSI1SK, consumedAt, evidenceProjectionDigest, expiresAt, id, idempotencyDigest, #kind, promotionLeaseExpiresAt, promotionLeaseId, reconciliationActionKey, reconciliationDetectedAt, reconciliationDisposition, reconciliationReason, requestFingerprint, #revision, schemaVersion, #status, tenantId, ttlEpochSeconds, #validation",
    ScanIndexForward: true,
    TableName: tableName,
  }));
  const counts = { conflict: 0, current: 0, examined: 0, malformed: 0, terminal: 0, upgraded: 0 };
  for (const lifecycle of response.Items ?? []) {
    counts.examined += 1;
    try {
      const status = exactDynamoString(lifecycle, "status");
      let requestReservation;
      if (activeStatuses.has(status)) {
        const idempotencyDigest = exactDynamoDigest(lifecycle, "idempotencyDigest");
        requestReservation = (await dynamo.send(new GetItemCommand({
          ConsistentRead: true,
          ExpressionAttributeNames: { "#kind": "kind" },
          Key: {
            PK: { S: partitionKey },
            SK: { S: `UPLOAD_REQUEST#${idempotencyDigest}` },
          },
          ProjectionExpression: "PK, SK, evidenceProjectionDigest, idempotencyDigest, intentId, #kind, requestFingerprint, tenantId, ttlEpochSeconds",
          TableName: tableName,
        }))).Item;
      } else if (!terminalStatuses.has(status)) {
        throw new MalformedUploadLifecycleBackfillAuthorityError();
      }
      const plan = planUploadLifecycleBackfill({ lifecycle, requestReservation, tableName });
      if (plan.outcome === "current") {
        counts.current += 1;
      } else if (plan.outcome === "terminal") {
        counts.terminal += 1;
      } else {
        try {
          await dynamo.send(new TransactWriteItemsCommand(plan.transaction));
          counts.upgraded += 1;
        } catch (error) {
          if (!exactConditionalCancellation(error, plan.transaction.TransactItems.length)) throw error;
          counts.conflict += 1;
        }
      }
    } catch (error) {
      if (!(error instanceof MalformedUploadLifecycleBackfillAuthorityError)) throw error;
      counts.malformed += 1;
    }
  }
  const nextCursor = parseProviderCursor(response.LastEvaluatedKey, request.tenantId);
  return Object.freeze({
    counts: Object.freeze({ ...counts }),
    nextCursor,
    schemaVersion: 1,
    tenantIdSha256: digestHex(request.tenantId),
  });
}

function parseCursor(value, tenantId) {
  if (!isRecord(value) || !sameKeys(Object.keys(value), ["partitionKey", "sortKey"]) ||
      value.partitionKey !== `TENANT#${tenantId}` || typeof value.sortKey !== "string") {
    throw new Error("Upload lifecycle backfill cursor is invalid.");
  }
  const match = /^UPLOAD#(upl_[a-f0-9]{32})$/.exec(value.sortKey);
  if (!match || !uploadPattern.test(match[1])) throw new Error("Upload lifecycle backfill cursor is invalid.");
  return Object.freeze({ partitionKey: value.partitionKey, sortKey: value.sortKey });
}

function parseProviderCursor(value, tenantId) {
  if (value === undefined) return undefined;
  if (!isRecord(value) || !sameKeys(Object.keys(value), ["PK", "SK"])) {
    throw new Error("DynamoDB returned an invalid upload lifecycle backfill cursor.");
  }
  const partitionKey = exactDynamoString(value, "PK");
  const sortKey = exactDynamoString(value, "SK");
  return parseCursor({ partitionKey, sortKey }, tenantId);
}

function exactDynamoString(item, name) {
  const value = item?.[name];
  if (!isRecord(value) || !sameKeys(Object.keys(value), ["S"]) || typeof value.S !== "string" || value.S.length < 1) {
    throw new MalformedUploadLifecycleBackfillAuthorityError();
  }
  return value.S;
}

function exactDynamoDigest(item, name) {
  const value = exactDynamoString(item, name);
  if (!digestPattern.test(value)) throw new MalformedUploadLifecycleBackfillAuthorityError();
  return value;
}

function exactConditionalCancellation(error, expectedReasons) {
  if (!isRecord(error) || error.name !== "TransactionCanceledException" ||
      !Array.isArray(error.CancellationReasons) || error.CancellationReasons.length !== expectedReasons) return false;
  const codes = error.CancellationReasons.map((reason) => isRecord(reason) && typeof reason.Code === "string" ? reason.Code : "INVALID");
  return codes.some((code) => code === "ConditionalCheckFailed") &&
    codes.every((code) => code === "None" || code === "ConditionalCheckFailed");
}

function boundedInteger(value, minimum, maximum, name) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) throw new Error(`${name} is invalid.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error(`${name} is invalid.`);
  return parsed;
}

function safeErrorClass(error) {
  const name = isRecord(error) && typeof error.name === "string" ? error.name : "Error";
  return /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(name) ? name : "Error";
}

function sameKeys(actual, expected) {
  const left = [...actual].sort();
  const right = [...expected].sort();
  return left.length === right.length && left.every((key, index) => key === right[index]);
}

function digestHex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
