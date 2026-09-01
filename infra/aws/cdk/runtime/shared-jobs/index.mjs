import { createHash } from "node:crypto";
import { CloudWatchClient, PutMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import { DynamoDBClient, GetItemCommand, QueryCommand, TransactWriteItemsCommand, UpdateItemCommand } from "@aws-sdk/client-dynamodb";
import {
  decideUploadReconciliation,
  exactCursor,
  MalformedUploadLifecycleError,
  parseActiveUploadLifecycle,
  parseMaintenanceEnvelope,
  parseTenantDirectoryEntry,
  SHARED_MAINTENANCE_KIND,
  SHARED_MAINTENANCE_SCHEMA_VERSION,
  SHARED_MAINTENANCE_STATE_KEY,
  TENANT_MAINTENANCE_DIRECTORY_KEY,
} from "./reconciliation-contract.mjs";

const required = ["CONTROL_TABLE_NAME", "JOBS_QUEUE_ARN", "MAINTENANCE_INDEX_NAME"];
const config = Object.freeze(Object.fromEntries(required.map((name) => {
  const value = String(process.env[name] ?? "");
  if (!value || value !== value.trim()) throw new Error(`Missing required environment variable ${name}.`);
  return [name, value];
})));
const region = String(process.env.AWS_REGION ?? "");
const queueArn = /^arn:(aws|aws-us-gov|aws-cn):sqs:([a-z0-9-]+):(\d{12}):([A-Za-z0-9_-]{1,80})$/.exec(config.JOBS_QUEUE_ARN);
if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region) || !queueArn || queueArn[2] !== region) {
  throw new Error("Unsafe shared maintenance identity.");
}
if (config.MAINTENANCE_INDEX_NAME !== "UploadLifecycleByTenantV2") throw new Error("Unsafe shared maintenance index identity.");
const maximumEvaluatedItems = boundedInteger(process.env.MAXIMUM_EVALUATED_ITEMS ?? "250", 25, 1_000, "MAXIMUM_EVALUATED_ITEMS");
const maximumTenants = boundedInteger(process.env.MAXIMUM_TENANTS_PER_SWEEP ?? "25", 1, 100, "MAXIMUM_TENANTS_PER_SWEEP");
if (maximumEvaluatedItems < maximumTenants * 2) {
  throw new Error("Shared maintenance requires independent lifecycle and action-observation budgets for every tenant.");
}
const actionObservationBudget = Math.max(maximumTenants, Math.floor(maximumEvaluatedItems / 5));
const lifecycleBudget = maximumEvaluatedItems - actionObservationBudget;
const orphanGraceSeconds = boundedInteger(process.env.ORPHAN_GRACE_SECONDS ?? "900", 60, 86_400, "ORPHAN_GRACE_SECONDS");
if (orphanGraceSeconds !== 900) throw new Error("Shared maintenance orphan grace must match the lifecycle index contract.");
const leaseSeconds = boundedInteger(process.env.SWEEP_LEASE_SECONDS ?? "300", 60, 900, "SWEEP_LEASE_SECONDS");
const dynamo = new DynamoDBClient({ region });
const cloudwatch = new CloudWatchClient({ region });
const stateKey = Object.freeze({ PK: { S: SHARED_MAINTENANCE_STATE_KEY.PK }, SK: { S: SHARED_MAINTENANCE_STATE_KEY.SK } });

export async function handler(event) {
  const records = Array.isArray(event?.Records) ? event.Records : [];
  if (records.length < 1 || records.length > 1) throw new Error("Shared maintenance requires exactly one SQS record.");
  const record = assertSqsRecord(records[0]);
  try {
    await processSweep(record);
    return { batchItemFailures: [] };
  } catch (error) {
    console.error("scopeproof_shared_maintenance_failed", { errorClass: safeErrorClass(error) });
    // Throw a bounded replacement error so Lambda's native Errors metric and
    // the SQS redrive policy both observe whole-sweep failures without logging
    // the original provider response or customer-controlled message body.
    throw new Error("Shared maintenance sweep failed.");
  }
}

async function processSweep(record) {
  const envelope = parseMaintenanceEnvelope(JSON.parse(record.body));
  void envelope;
  const now = new Date();
  const nowIso = now.toISOString();
  const leaseId = digestHex(`scopeproof-shared-maintenance-lease-v1\n${record.messageId}`);
  const lease = await acquireLease(record.messageId, leaseId, nowIso);
  if (lease.replay) return;
  const counters = { actionRequired: 0, examined: 0, expired: 0, failures: 0, maxPendingAgeSeconds: 0 };
  const directoryPage = await dynamo.send(new QueryCommand({
    ExclusiveStartKey: lease.cursor,
    ExpressionAttributeNames: { "#pk": "PK", "#kind": "kind", "#status": "status" },
    ExpressionAttributeValues: { ":directory": { S: TENANT_MAINTENANCE_DIRECTORY_KEY } },
    KeyConditionExpression: "#pk = :directory",
    Limit: maximumTenants,
    ProjectionExpression: "PK, SK, #kind, schemaVersion, tenantId, #status",
    TableName: config.CONTROL_TABLE_NAME,
  }));
  const tenants = [];
  for (const item of directoryPage.Items ?? []) {
    try {
      const entry = parseTenantDirectoryEntry(item);
      if (entry.active) tenants.push(entry);
    } catch (error) {
      counters.failures += 1;
      console.error("scopeproof_shared_maintenance_directory_item_failed", {
        errorClass: safeErrorClass(error),
        identitySha256: directoryIdentityDigest(item),
      });
    }
  }
  const perTenantLimit = Math.max(1, Math.floor(lifecycleBudget / Math.max(1, tenants.length)));
  for (const tenant of tenants) {
    const duePage = await dynamo.send(new QueryCommand({
      ExpressionAttributeNames: { "#pk": "PK", "#gsiSk": "GSI1SK", "#kind": "kind", "#status": "status" },
      ExpressionAttributeValues: {
        ":due": { S: `${nowIso}#\uffff` },
        ":tenant": { S: `TENANT#${tenant.tenantId}` },
      },
      IndexName: config.MAINTENANCE_INDEX_NAME,
      KeyConditionExpression: "#pk = :tenant AND #gsiSk <= :due",
      Limit: perTenantLimit,
      ProjectionExpression: "PK, SK, GSI1PK, GSI1SK, #kind, schemaVersion, id, tenantId, #status, revision, expiresAt, ttlEpochSeconds, consumedAt, promotionLeaseId, promotionLeaseExpiresAt, validation, reconciliationDisposition",
      ScanIndexForward: true,
      TableName: config.CONTROL_TABLE_NAME,
    }));
    counters.examined += Number(duePage.Count ?? 0);
    for (const item of duePage.Items ?? []) {
      try {
        const intent = parseActiveUploadLifecycle(item);
        const decision = decideUploadReconciliation(intent, now, orphanGraceSeconds);
        counters.maxPendingAgeSeconds = Math.max(counters.maxPendingAgeSeconds, decision.ageSeconds);
        if (decision.action === "expire") {
          if (await expireIssuedIntent(intent, nowIso)) counters.expired += 1;
        } else if (decision.action === "flag_action_required") {
          if (await flagActionRequired(intent, decision, nowIso, now)) counters.actionRequired += 1;
        }
      } catch (error) {
        if (!(error instanceof MalformedUploadLifecycleError)) throw error;
        counters.failures += 1;
        if (await quarantineMalformedLifecycle(item, tenant.tenantId, nowIso)) counters.actionRequired += 1;
        console.error("scopeproof_shared_maintenance_item_failed", {
          errorClass: safeErrorClass(error),
          identitySha256: lifecycleIdentityDigest(item),
        });
      }
    }
  }
  const outstanding = await observeOutstandingActions(now, tenants);
  counters.examined += outstanding.examined;
  counters.failures += outstanding.failures;
  counters.outstandingActionRequired = outstanding.count;
  counters.oldestActionRequiredAgeSeconds = outstanding.oldestAgeSeconds;
  await publishMetrics(counters);
  await completeLease(record.messageId, leaseId, nowIso, directoryPage.LastEvaluatedKey, counters);
}

async function acquireLease(messageId, leaseId, nowIso) {
  const current = (await dynamo.send(new GetItemCommand({ ConsistentRead: true, Key: stateKey, TableName: config.CONTROL_TABLE_NAME }))).Item;
  if (current) {
    assertStateAuthority(current);
    if (current.lastCompletedMessageId?.S === messageId) return Object.freeze({ replay: true });
    if (current.lastStartedMessageId?.S === messageId && current.leaseId?.S === leaseId &&
        typeof current.leaseExpiresAt?.S === "string" && current.leaseExpiresAt.S > nowIso) {
      return Object.freeze({ cursor: exactCursor(current), replay: false });
    }
  }
  const leaseExpiresAt = new Date(Date.parse(nowIso) + leaseSeconds * 1_000).toISOString();
  try {
    const result = await dynamo.send(new UpdateItemCommand({
      ConditionExpression: "attribute_not_exists(PK) OR (#kind = :kind AND schemaVersion = :schema AND (attribute_not_exists(leaseExpiresAt) OR leaseExpiresAt <= :now))",
      ExpressionAttributeNames: { "#kind": "kind", "#revision": "revision", "#status": "status" },
      ExpressionAttributeValues: {
        ":kind": { S: SHARED_MAINTENANCE_KIND },
        ":lease": { S: leaseId },
        ":leaseExpires": { S: leaseExpiresAt },
        ":leased": { S: "LEASED" },
        ":message": { S: messageId },
        ":now": { S: nowIso },
        ":one": { N: "1" },
        ":schema": { N: String(SHARED_MAINTENANCE_SCHEMA_VERSION) },
      },
      Key: stateKey,
      ReturnValues: "ALL_NEW",
      TableName: config.CONTROL_TABLE_NAME,
      UpdateExpression: "SET #kind = :kind, schemaVersion = :schema, #status = :leased, leaseId = :lease, leaseExpiresAt = :leaseExpires, lastStartedMessageId = :message, startedAt = :now ADD #revision :one",
    }));
    assertStateAuthority(result.Attributes);
    return Object.freeze({ cursor: exactCursor(result.Attributes), replay: false });
  } catch (error) {
    if (conditionalConflict(error)) throw new Error("Another shared maintenance sweep owns the active lease.");
    throw error;
  }
}

async function expireIssuedIntent(intent, nowIso) {
  try {
    await dynamo.send(new UpdateItemCommand({
      ConditionExpression: "#kind = :kind AND schemaVersion = :schema AND tenantId = :tenant AND id = :id AND #status = :issued AND #revision = :revision AND expiresAt = :expires AND ttlEpochSeconds = :ttl AND GSI1PK = :indexPk AND GSI1SK = :indexSk AND attribute_not_exists(promotionLeaseId)",
      ExpressionAttributeNames: { "#kind": "kind", "#revision": "revision", "#status": "status" },
      ExpressionAttributeValues: {
        ":expired": { S: "expired" }, ":expiredAt": { S: nowIso }, ":expires": { S: intent.expiresAt },
        ":id": { S: intent.id }, ":issued": { S: "issued" }, ":kind": { S: "UploadLifecycle" },
        ":indexPk": { S: intent.maintenanceIndexPartition }, ":indexSk": { S: intent.maintenanceIndexSortKey },
        ":nextRevision": { N: String(intent.revision + 1) }, ":reason": { S: "INTENT_EXPIRED" },
        ":resolved": { S: "RESOLVED" }, ":revision": { N: String(intent.revision) }, ":schema": { N: "1" },
        ":tenant": { S: intent.tenantId }, ":ttl": { N: String(intent.ttlEpochSeconds) },
      },
      Key: { PK: { S: intent.partitionKey }, SK: { S: intent.sortKey } },
      TableName: config.CONTROL_TABLE_NAME,
      UpdateExpression: "SET #status = :expired, #revision = :nextRevision, expiredAt = :expiredAt, reconciliationDisposition = :resolved, reconciliationReason = :reason, reconciledAt = :expiredAt REMOVE promotionLeaseId, promotionLeaseExpiresAt, GSI1PK, GSI1SK",
    }));
    return true;
  } catch (error) {
    if (conditionalConflict(error)) return false;
    throw error;
  }
}

async function flagActionRequired(intent, decision, nowIso, now) {
  const cutoff = new Date(now.getTime() - orphanGraceSeconds * 1_000).toISOString();
  const staleCondition = decision.staleField === "promotionLeaseExpiresAt"
    ? "promotionLeaseExpiresAt = :staleBase AND promotionLeaseExpiresAt <= :cutoff"
    : decision.staleField === "validation.completedAt"
      ? "attribute_not_exists(promotionLeaseExpiresAt) AND validation.completedAt = :staleBase AND validation.completedAt <= :cutoff"
      : "attribute_not_exists(promotionLeaseExpiresAt) AND consumedAt = :staleBase AND consumedAt <= :cutoff";
  try {
    const ledger = actionLedger({
      detectedAt: nowIso,
      id: intent.id,
      indexSk: intent.maintenanceIndexSortKey,
      reason: decision.reason,
      revision: intent.revision,
      sourcePk: intent.partitionKey,
      sourceSk: intent.sortKey,
      tenantId: intent.tenantId,
    });
    await dynamo.send(new TransactWriteItemsCommand({
      ClientRequestToken: digestHex(`scopeproof-maintenance-action-v1\n${ledger.receiptSha256}`).slice(0, 36),
      TransactItems: [
        {
          Update: {
            ConditionExpression: `#kind = :kind AND schemaVersion = :schema AND tenantId = :tenant AND id = :id AND #status = :status AND #revision = :revision AND GSI1PK = :indexPk AND GSI1SK = :indexSk AND attribute_not_exists(reconciliationDisposition) AND ${staleCondition}`,
            ExpressionAttributeNames: { "#kind": "kind", "#revision": "revision", "#status": "status" },
            ExpressionAttributeValues: {
              ":action": { S: "ACTION_REQUIRED" }, ":actionKey": { S: ledger.sortKey },
              ":cutoff": { S: cutoff }, ":detected": { S: nowIso },
              ":id": { S: intent.id }, ":kind": { S: "UploadLifecycle" }, ":reason": { S: decision.reason },
              ":indexPk": { S: intent.maintenanceIndexPartition }, ":indexSk": { S: intent.maintenanceIndexSortKey },
              ":revision": { N: String(intent.revision) }, ":schema": { N: "1" }, ":staleBase": { S: decision.staleBase },
              ":status": { S: intent.status }, ":tenant": { S: intent.tenantId },
            },
            Key: { PK: { S: intent.partitionKey }, SK: { S: intent.sortKey } },
            TableName: config.CONTROL_TABLE_NAME,
            UpdateExpression: "SET reconciliationDisposition = :action, reconciliationReason = :reason, reconciliationDetectedAt = :detected, reconciliationActionKey = :actionKey REMOVE GSI1PK, GSI1SK",
          },
        },
        { Put: { ConditionExpression: "attribute_not_exists(PK) AND attribute_not_exists(SK)", Item: ledger.item, TableName: config.CONTROL_TABLE_NAME } },
      ],
    }));
    return true;
  } catch (error) {
    if (conditionalConflict(error)) return false;
    throw error;
  }
}

async function quarantineMalformedLifecycle(item, tenantId, nowIso) {
  const identity = malformedLifecycleIdentity(item, tenantId);
  const ledger = actionLedger({
    detectedAt: nowIso,
    id: identity.id,
    indexSk: identity.indexSk,
    reason: identity.reason,
    revision: identity.revision,
    sourcePk: identity.partitionKey,
    sourceSk: identity.sortKey,
    tenantId: identity.tenantId,
  });
  try {
    await dynamo.send(new TransactWriteItemsCommand({
      ClientRequestToken: digestHex(`scopeproof-maintenance-malformed-v1\n${ledger.receiptSha256}`).slice(0, 36),
      TransactItems: [
        {
          Update: {
            ConditionExpression: "GSI1SK = :indexSk",
            ExpressionAttributeValues: {
              ":action": { S: "ACTION_REQUIRED" }, ":actionKey": { S: ledger.sortKey },
              ":detected": { S: nowIso }, ":indexSk": { S: identity.indexSk },
              ":reason": { S: identity.reason },
            },
            Key: { PK: { S: identity.partitionKey }, SK: { S: identity.sortKey } },
            TableName: config.CONTROL_TABLE_NAME,
            UpdateExpression: "SET reconciliationDisposition = :action, reconciliationReason = :reason, reconciliationDetectedAt = :detected, reconciliationActionKey = :actionKey REMOVE GSI1PK, GSI1SK",
          },
        },
        { Put: { ConditionExpression: "attribute_not_exists(PK) AND attribute_not_exists(SK)", Item: ledger.item, TableName: config.CONTROL_TABLE_NAME } },
      ],
    }));
    return true;
  } catch (error) {
    if (conditionalConflict(error)) return false;
    throw error;
  }
}

async function observeOutstandingActions(now, tenants) {
  let count = 0;
  let examined = 0;
  let failures = 0;
  let oldestAgeSeconds = 0;
  const perTenantLimit = Math.max(1, Math.floor(actionObservationBudget / Math.max(1, tenants.length)));
  for (const tenant of tenants) {
    const response = await dynamo.send(new QueryCommand({
      ExpressionAttributeNames: { "#pk": "PK", "#kind": "kind", "#status": "status" },
      ExpressionAttributeValues: { ":action": { S: `MAINTENANCE#ACTION_REQUIRED#${tenant.tenantId}` } },
      IndexName: config.MAINTENANCE_INDEX_NAME,
      KeyConditionExpression: "#pk = :action",
      Limit: perTenantLimit,
      ProjectionExpression: "PK, SK, GSI1SK, detectedAt, id, #kind, reason, schemaVersion, sourceRevision, #status, tenantId",
      ScanIndexForward: true,
      TableName: config.CONTROL_TABLE_NAME,
    }));
    examined += Number(response.Count ?? 0);
    for (const item of response.Items ?? []) {
      try {
        const detectedAt = parseOutstandingAction(item);
        count += 1;
        oldestAgeSeconds = Math.max(oldestAgeSeconds, Math.floor((now.getTime() - Date.parse(detectedAt)) / 1_000));
      } catch (error) {
        // The action namespace is not writable by ordinary tenant runtimes,
        // but a compromised tenant-specific promotion/rejection worker must
        // still be unable to block every other tenant. Keep the malformed row
        // durably indexed, count it as outstanding, and emit a safe repeated
        // failure until an approved operator repair resolves the exact record.
        count += 1;
        failures += 1;
        console.error("scopeproof_shared_maintenance_action_ledger_failed", {
          errorClass: safeErrorClass(error),
          identitySha256: lifecycleIdentityDigest(item),
        });
      }
    }
  }
  return Object.freeze({ count, examined, failures, oldestAgeSeconds: Math.max(0, oldestAgeSeconds) });
}

async function completeLease(messageId, leaseId, nowIso, cursor, counters) {
  const names = { "#kind": "kind", "#revision": "revision", "#status": "status" };
  const values = {
    ":actionRequired": { N: String(counters.actionRequired) }, ":completed": { S: "IDLE" },
    ":examined": { N: String(counters.examined) }, ":expired": { N: String(counters.expired) },
    ":failures": { N: String(counters.failures) }, ":kind": { S: SHARED_MAINTENANCE_KIND },
    ":lease": { S: leaseId }, ":message": { S: messageId }, ":now": { S: nowIso },
    ":one": { N: "1" }, ":schema": { N: String(SHARED_MAINTENANCE_SCHEMA_VERSION) },
  };
  let expression = "SET #status = :completed, completedAt = :now, lastCompletedMessageId = :message, lastExamined = :examined, lastExpired = :expired, lastActionRequired = :actionRequired, lastFailures = :failures";
  const remove = ["leaseId", "leaseExpiresAt"];
  if (cursor?.PK?.S && cursor?.SK?.S) {
    values[":cursorPk"] = { S: cursor.PK.S };
    values[":cursorSk"] = { S: cursor.SK.S };
    expression += ", cursorPk = :cursorPk, cursorSk = :cursorSk";
  } else {
    remove.push("cursorPk", "cursorSk");
  }
  expression += ` REMOVE ${remove.join(", ")} ADD #revision :one`;
  await dynamo.send(new UpdateItemCommand({
    ConditionExpression: "#kind = :kind AND schemaVersion = :schema AND #status = :leased AND leaseId = :lease AND lastStartedMessageId = :message",
    ExpressionAttributeNames: names,
    ExpressionAttributeValues: { ...values, ":leased": { S: "LEASED" } },
    Key: stateKey,
    TableName: config.CONTROL_TABLE_NAME,
    UpdateExpression: expression,
  }));
}

async function publishMetrics(counters) {
  const dimension = [{ Name: "JobType", Value: "PendingOrphanReconciliation" }];
  await cloudwatch.send(new PutMetricDataCommand({
    Namespace: "Scopeproof/SharedJobs",
    MetricData: [
      { MetricName: "Invocations", Unit: "Count", Value: 1, Dimensions: dimension },
      { MetricName: "Examined", Unit: "Count", Value: counters.examined, Dimensions: dimension },
      { MetricName: "Expired", Unit: "Count", Value: counters.expired, Dimensions: dimension },
      { MetricName: "ActionRequired", Unit: "Count", Value: counters.actionRequired, Dimensions: dimension },
      { MetricName: "OutstandingActionRequired", Unit: "Count", Value: counters.outstandingActionRequired, Dimensions: dimension },
      { MetricName: "OldestActionRequiredAgeSeconds", Unit: "Seconds", Value: counters.oldestActionRequiredAgeSeconds, Dimensions: dimension },
      { MetricName: "Failures", Unit: "Count", Value: counters.failures, Dimensions: dimension },
      { MetricName: "MaxPendingAgeSeconds", Unit: "Seconds", Value: counters.maxPendingAgeSeconds, Dimensions: dimension },
    ],
  }));
}

function assertSqsRecord(record) {
  if (!record || typeof record !== "object" || record.eventSource !== "aws:sqs" || record.eventSourceARN !== config.JOBS_QUEUE_ARN ||
      record.awsRegion !== region || typeof record.body !== "string" || record.body.length < 2 || record.body.length > 1_024 ||
      typeof record.messageId !== "string" || !/^[A-Za-z0-9-]{16,128}$/.test(record.messageId)) {
    throw new Error("Shared maintenance SQS record is invalid.");
  }
  return record;
}

function assertStateAuthority(item) {
  if (!item || item.PK?.S !== SHARED_MAINTENANCE_STATE_KEY.PK || item.SK?.S !== SHARED_MAINTENANCE_STATE_KEY.SK ||
      item.kind?.S !== SHARED_MAINTENANCE_KIND || item.schemaVersion?.N !== String(SHARED_MAINTENANCE_SCHEMA_VERSION) ||
      !item.revision?.N || !/^[1-9][0-9]*$/.test(item.revision.N)) {
    throw new Error("Shared maintenance state is malformed.");
  }
  if (item.status?.S !== "IDLE" && item.status?.S !== "LEASED") throw new Error("Shared maintenance state is malformed.");
}

function boundedInteger(value, minimum, maximum, name) {
  if (!/^(0|[1-9][0-9]*)$/.test(String(value))) throw new Error(`${name} is invalid.`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) throw new Error(`${name} is invalid.`);
  return parsed;
}

function conditionalConflict(error) {
  if (!error || typeof error !== "object") return false;
  if (error.name === "ConditionalCheckFailedException") return true;
  if (error.name !== "TransactionCanceledException" || !Array.isArray(error.CancellationReasons) ||
      error.CancellationReasons.length === 0) return false;
  const codes = error.CancellationReasons.map((reason) => reason?.Code ?? "None");
  return codes.some((code) => code === "ConditionalCheckFailed") &&
    codes.every((code) => code === "None" || code === "ConditionalCheckFailed");
}

function actionLedger(input) {
  const partitionKey = `MAINTENANCE#ACTION_REQUIRED#${input.tenantId}`;
  const canonical = [
    "scopeproof-maintenance-action-receipt-v1", input.detectedAt, input.id,
    input.indexSk, input.reason, String(input.revision), input.sourcePk, input.sourceSk, input.tenantId,
  ].join("\n");
  const receiptSha256 = digestHex(canonical);
  const sortKey = `UPLOAD#${input.id}#REVISION#${input.revision}#EVENT#${receiptSha256.slice(0, 32)}`;
  return Object.freeze({
    item: {
      PK: { S: partitionKey },
      SK: { S: sortKey },
      GSI1SK: { S: `${input.detectedAt}#${input.tenantId}#${input.id}#${input.revision}` },
      detectedAt: { S: input.detectedAt },
      id: { S: input.id },
      kind: { S: "UploadMaintenanceAction" },
      reason: { S: input.reason },
      receiptSha256: { S: receiptSha256 },
      schemaVersion: { N: "1" },
      sourceIndexSkSha256: { S: digestHex(input.indexSk) },
      sourcePkSha256: { S: digestHex(input.sourcePk) },
      sourceRevision: { N: String(input.revision) },
      sourceSkSha256: { S: digestHex(input.sourceSk) },
      status: { S: "OUTSTANDING" },
      tenantId: { S: input.tenantId },
    },
    partitionKey,
    receiptSha256,
    sortKey,
  });
}

function malformedLifecycleIdentity(item, tenantId) {
  const partitionKey = exactDynamoString(item, "PK");
  const sortKey = exactDynamoString(item, "SK");
  const indexSk = exactDynamoString(item, "GSI1SK");
  const actualTenantMatch = /^TENANT#(ten_[a-f0-9]{32})$/.exec(partitionKey);
  if (!actualTenantMatch || actualTenantMatch[1] !== tenantId) {
    throw new Error("Malformed lifecycle index identity is unsafe to quarantine.");
  }
  const match = /^UPLOAD#(upl_[a-f0-9]{32})$/.exec(sortKey);
  const id = match?.[1] ?? `upl_${digestHex(`${partitionKey}\n${sortKey}`).slice(0, 32)}`;
  const revisionValue = item?.revision;
  const revision = revisionValue && typeof revisionValue.N === "string" &&
    Object.keys(revisionValue).length === 1 && /^(0|[1-9][0-9]*)$/.test(revisionValue.N) &&
    Number.isSafeInteger(Number(revisionValue.N)) ? Number(revisionValue.N) : 0;
  return Object.freeze({
    id,
    indexSk,
    partitionKey,
    reason: "MALFORMED_LIFECYCLE",
    revision,
    sortKey,
    tenantId: actualTenantMatch[1],
  });
}

function parseOutstandingAction(item) {
  const partitionKey = exactDynamoString(item, "PK");
  const sortKey = exactDynamoString(item, "SK");
  const indexSk = exactDynamoString(item, "GSI1SK");
  const detectedAt = exactDynamoString(item, "detectedAt");
  const tenantId = exactDynamoString(item, "tenantId");
  const id = exactDynamoString(item, "id");
  const schemaVersion = Number(exactDynamoNumber(item, "schemaVersion"));
  const sourceRevision = Number(exactDynamoNumber(item, "sourceRevision"));
  if (!/^ten_[a-f0-9]{32}$/.test(tenantId) || !/^upl_[a-f0-9]{32}$/.test(id) ||
      schemaVersion !== 1 || !Number.isSafeInteger(sourceRevision) || sourceRevision < 0 ||
      partitionKey !== `MAINTENANCE#ACTION_REQUIRED#${tenantId}` ||
      !new RegExp(`^UPLOAD#${id}#REVISION#${sourceRevision}#EVENT#[a-f0-9]{32}$`).test(sortKey) ||
      indexSk !== `${detectedAt}#${tenantId}#${id}#${sourceRevision}` || !canonicalInstant(detectedAt) ||
      exactDynamoString(item, "kind") !== "UploadMaintenanceAction" ||
      exactDynamoString(item, "status") !== "OUTSTANDING" ||
      !/^(STALE_PROMOTION_LEASE|MISSING_PROMOTION_LEASE|MALFORMED_LIFECYCLE)$/.test(exactDynamoString(item, "reason"))) {
    throw new Error("Outstanding maintenance action is malformed.");
  }
  return detectedAt;
}

function exactDynamoString(item, name) {
  const value = item?.[name];
  if (!value || typeof value.S !== "string" || value.S.length < 1 || Object.keys(value).length !== 1) {
    throw new Error("DynamoDB maintenance identity is malformed.");
  }
  return value.S;
}

function exactDynamoNumber(item, name) {
  const value = item?.[name];
  if (!value || typeof value.N !== "string" || !/^(0|[1-9][0-9]*)$/.test(value.N) || Object.keys(value).length !== 1) {
    throw new Error("DynamoDB maintenance identity is malformed.");
  }
  return value.N;
}

function canonicalInstant(value) {
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function directoryIdentityDigest(item) {
  return digestHex(`scopeproof-maintenance-directory-log-v1\n${String(item?.PK?.S ?? "INVALID")}\n${String(item?.SK?.S ?? "INVALID")}`);
}

function lifecycleIdentityDigest(item) {
  return digestHex(`scopeproof-maintenance-lifecycle-log-v1\n${String(item?.PK?.S ?? "INVALID")}\n${String(item?.SK?.S ?? "INVALID")}`);
}

function digestHex(value) { return createHash("sha256").update(value).digest("hex"); }

function safeErrorClass(error) {
  const name = error && typeof error === "object" && typeof error.name === "string" ? error.name : "Error";
  return /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(name) ? name : "Error";
}
