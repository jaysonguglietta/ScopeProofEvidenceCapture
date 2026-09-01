import { createHash } from "node:crypto";
import { DynamoDBClient, GetItemCommand, TransactWriteItemsCommand } from "@aws-sdk/client-dynamodb";
import {
  BeginTransactionCommand, CommitTransactionCommand, ExecuteStatementCommand,
  RDSDataClient, RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";
import { GetObjectTaggingCommand, S3Client } from "@aws-sdk/client-s3";

const required = [
  "AWS_ACCOUNT_ID_EXPECTED", "AWS_REGION_EXPECTED", "CONTROL_TABLE_NAME",
  "DATABASE_CLUSTER_ARN", "DATABASE_NAME", "INGEST_BUCKET_NAME",
  "INGEST_DATABASE_SECRET_ARN", "MALWARE_PROTECTION_PLAN_ARN", "TENANT_ID",
];
for (const name of required) if (!process.env[name]) throw new Error(`Missing required environment variable ${name}.`);
const config = Object.freeze({
  accountId: process.env.AWS_ACCOUNT_ID_EXPECTED,
  awsRegion: process.env.AWS_REGION_EXPECTED,
  clusterArn: process.env.DATABASE_CLUSTER_ARN,
  controlTable: process.env.CONTROL_TABLE_NAME,
  databaseName: process.env.DATABASE_NAME,
  ingestBucket: process.env.INGEST_BUCKET_NAME,
  ingestSecretArn: process.env.INGEST_DATABASE_SECRET_ARN,
  malwarePlanArn: process.env.MALWARE_PROTECTION_PLAN_ARN,
  tenantId: process.env.TENANT_ID,
});
if (!/^ten_[a-f0-9]{32}$/.test(config.tenantId) || !/^\d{12}$/.test(config.accountId) ||
    !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(config.awsRegion) ||
    !/^scopeproof_[a-z0-9_]{1,48}$/.test(config.databaseName)) {
  throw new Error("Unsafe rejection reconciler identity.");
}
const dynamo = new DynamoDBClient({});
const rds = new RDSDataClient({});
const s3 = new S3Client({});
const rejectedResults = new Set(["THREATS_FOUND", "UNSUPPORTED", "ACCESS_DENIED", "FAILED"]);

export async function handler(event) {
  const failures = [];
  for (const record of event?.Records ?? []) {
    try { await reconcileRecord(record); }
    catch (error) {
      console.error(JSON.stringify({
        event: "scopeproof.evidence_rejection_reconciliation_failed",
        errorName: safeName(error),
        messageIdSha256: sha256(String(record?.messageId ?? "unknown")).slice(0, 24),
        tenantId: config.tenantId,
      }));
      failures.push({ itemIdentifier: String(record?.messageId ?? "unknown") });
    }
  }
  return { batchItemFailures: failures };
}

async function reconcileRecord(record) {
  const messageId = String(record?.messageId ?? "");
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(messageId)) throw new Error("Invalid SQS message identifier.");
  const envelope = JSON.parse(String(record?.body ?? "{}"));
  const detail = envelope?.detail;
  const result = String(detail?.scanResultDetails?.scanResultStatus ?? "");
  if (envelope?.source !== "aws.guardduty" || envelope?.account !== config.accountId ||
      envelope?.region !== config.awsRegion || envelope?.["detail-type"] !== "GuardDuty Malware Protection Object Scan Result" ||
      !Array.isArray(envelope?.resources) || !envelope.resources.includes(config.malwarePlanArn) ||
      detail?.schemaVersion !== "1.0" || !rejectedResults.has(result)) {
    throw new Error("The queue message is not an accepted GuardDuty rejection event.");
  }
  const eventId = String(envelope.id ?? "");
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(eventId)) throw new Error("Invalid GuardDuty event identifier.");
  const source = detail?.s3ObjectDetails ?? {};
  const bucket = String(source.bucketName ?? "");
  const key = String(source.objectKey ?? "");
  const versionId = String(source.versionId ?? "");
  if (bucket !== config.ingestBucket || !validVersion(versionId)) throw new Error("Rejected scan omitted the exact ingest version.");
  const match = key.match(new RegExp(`^tenants/${config.tenantId}/controls/([A-Za-z0-9][A-Za-z0-9._-]{0,63})/quarantine/(upl_[a-f0-9]{32})\\.upload$`));
  if (!match) throw new Error("Rejected scan key is outside the tenant upload boundary.");
  const tags = await s3.send(new GetObjectTaggingCommand({ Bucket: bucket, Key: key, VersionId: versionId }));
  const guardDutyTag = tags.TagSet?.find((tag) => tag.Key === "GuardDutyMalwareScanStatus")?.Value;
  // GuardDuty can emit ACCESS_DENIED/FAILED precisely because it could not
  // complete tagging. Threat and unsupported outcomes must be independently
  // corroborated on the exact version; operational failures remain sourced
  // from the EventBridge->SQS resource-policy boundary and fail closed.
  if (guardDutyTag !== result && !(guardDutyTag === undefined && new Set(["ACCESS_DENIED", "FAILED"]).has(result))) {
    throw new Error("The exact rejected object does not carry GuardDuty's matching scan tag.");
  }
  const [, controlId, intentId] = match;
  const intentKey = { PK: { S: `TENANT#${config.tenantId}` }, SK: { S: `UPLOAD#${intentId}` } };
  let intent = parseIntent((await dynamo.send(new GetItemCommand({ ConsistentRead: true, Key: intentKey, TableName: config.controlTable }))).Item,
    { controlId, intentId, key });
  const rejectedAt = intent.rejectionReceipt?.rejectedAt ?? new Date().toISOString();
  const facts = {
    evidenceId: intent.resourceId, providerEventId: eventId, quarantineBucket: bucket,
    quarantineKey: key, quarantineVersionId: versionId, rejectedAt,
    scanResult: result, schemaVersion: 1, tenantId: config.tenantId, uploadIntentId: intentId,
  };
  const canonical = stableJson(facts);
  const receiptSha256 = sha256(`scopeproof-ingest-rejection-v1\n${canonical}`);
  const receiptId = `rej_${sha256(`scopeproof-ingest-rejection-id-v1\n${canonical}`).slice(0, 32)}`;
  if (intent.status !== "rejected") {
    const nextRevision = intent.revision + 1;
    const hasMaintenanceAction = intent.reconciliationDisposition === "ACTION_REQUIRED";
    await dynamo.send(new TransactWriteItemsCommand({
      ClientRequestToken: sha256(`${messageId}\0${receiptSha256}`).slice(0, 36),
      TransactItems: [{ Update: {
        ConditionExpression: [
          "#status = :status AND #revision = :revision AND quarantineKey = :key AND resourceId = :evidenceId AND databaseUploadRevision = :dbZero AND databaseEvidenceRevision = :dbZero",
          hasMaintenanceAction
            ? "reconciliationDisposition = :action AND reconciliationActionKey = :actionKey AND reconciliationDetectedAt = :actionDetected AND reconciliationReason = :actionReason"
            : "attribute_not_exists(reconciliationDisposition) AND attribute_not_exists(reconciliationActionKey)",
        ].join(" AND "),
        ExpressionAttributeNames: { "#revision": "revision", "#status": "status" },
        ExpressionAttributeValues: {
          ...(hasMaintenanceAction ? {
            ":action": { S: "ACTION_REQUIRED" }, ":actionDetected": { S: intent.reconciliationDetectedAt },
            ":actionKey": { S: intent.reconciliationActionKey }, ":actionReason": { S: intent.reconciliationReason },
          } : {}),
          ":dbZero": { N: "0" }, ":evidenceId": { S: intent.resourceId }, ":key": { S: key },
          ":next": { N: String(nextRevision) }, ":rejected": { S: "rejected" },
          ":rejectedAt": { S: rejectedAt },
          ":receipt": { M: rejectionReceiptAttributes({ ...facts, canonical, receiptId, receiptSha256 }) },
          ":revision": { N: String(intent.revision) }, ":status": { S: intent.status },
        },
        Key: intentKey, TableName: config.controlTable,
        UpdateExpression: "SET #status = :rejected, #revision = :next, rejectionReceipt = :receipt, consumedAt = :rejectedAt REMOVE promotionLeaseId, promotionLeaseExpiresAt, GSI1PK, GSI1SK, reconciliationDisposition, reconciliationReason, reconciliationDetectedAt, reconciliationActionKey",
      } }, ...(hasMaintenanceAction ? [maintenanceActionResolution(intent, rejectedAt)] : [])],
    }));
    intent = { ...intent, status: "rejected", revision: nextRevision, rejectionReceipt: { ...facts, canonical, receiptId, receiptSha256 } };
  } else {
    assertSameReceipt(intent.rejectionReceipt, { ...facts, canonical, receiptId, receiptSha256 });
  }
  const committed = await reconcileDatabase(intent, { ...facts, canonical, receiptId, receiptSha256 });
  await dynamo.send(new TransactWriteItemsCommand({
    ClientRequestToken: sha256(`${receiptSha256}\0database`).slice(0, 36),
    TransactItems: [{ Update: {
      ConditionExpression: "#status = :rejected AND rejectionReceipt.receiptSha256 = :digest AND (attribute_not_exists(databaseRejectionReceiptId) OR databaseRejectionReceiptId = :receiptId)",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: {
        ":digest": { S: receiptSha256 }, ":evidenceRevision": { N: String(committed.evidenceRevision) },
        ":rejected": { S: "rejected" }, ":receiptId": { S: receiptId },
        ":uploadRevision": { N: String(committed.uploadRevision) },
      },
      Key: intentKey, TableName: config.controlTable,
      UpdateExpression: "SET databaseRejectionReceiptId = :receiptId, databaseUploadRevision = :uploadRevision, databaseEvidenceRevision = :evidenceRevision",
    } }],
  }));
}

function parseIntent(item, expected) {
  if (!item) throw new Error("A strongly consistent upload intent is required.");
  const parsed = {
    databaseEvidenceRevision: number(item.databaseEvidenceRevision), databaseUploadRevision: number(item.databaseUploadRevision),
    id: item.id?.S, resourceId: item.resourceId?.S, revision: number(item.revision), status: item.status?.S,
    reconciliationActionKey: item.reconciliationActionKey?.S,
    reconciliationDetectedAt: item.reconciliationDetectedAt?.S,
    reconciliationDisposition: item.reconciliationDisposition?.S,
    reconciliationReason: item.reconciliationReason?.S,
    rejectionReceipt: item.rejectionReceipt?.M ? Object.fromEntries(Object.entries(item.rejectionReceipt.M).map(([k, v]) => [k, v.S ?? Number(v.N)])) : undefined,
  };
  const expectedRevision = { issued: 0, quarantined: 1, validated: 2 }[parsed.status];
  const actionValid = parsed.reconciliationDisposition === undefined
    ? parsed.reconciliationActionKey === undefined && parsed.reconciliationDetectedAt === undefined &&
      parsed.reconciliationReason === undefined
    : parsed.reconciliationDisposition === "ACTION_REQUIRED" &&
      new RegExp(`^UPLOAD#${parsed.id}#REVISION#${parsed.revision}#EVENT#[a-f0-9]{32}$`).test(parsed.reconciliationActionKey ?? "") &&
      validInstant(parsed.reconciliationDetectedAt) &&
      /^(STALE_PROMOTION_LEASE|MISSING_PROMOTION_LEASE)$/.test(parsed.reconciliationReason ?? "");
  if (item.kind?.S !== "UploadLifecycle" || item.schemaVersion?.N !== "1" || item.tenantId?.S !== config.tenantId ||
      parsed.id !== expected.intentId || item.controlId?.S !== expected.controlId || item.quarantineBucket?.S !== config.ingestBucket ||
      item.quarantineKey?.S !== expected.key || !/^evd_[a-f0-9]{32}$/.test(parsed.resourceId ?? "") ||
      ![0, 1].includes(parsed.databaseUploadRevision) || ![0, 1].includes(parsed.databaseEvidenceRevision) ||
      parsed.databaseUploadRevision !== parsed.databaseEvidenceRevision || !Number.isSafeInteger(parsed.revision) ||
      (parsed.status !== "rejected" && parsed.revision !== expectedRevision) ||
      !new Set(["issued", "quarantined", "validated", "rejected"]).has(parsed.status) || !actionValid) {
    throw new Error("The rejected upload intent failed its security contract.");
  }
  return parsed;
}

function validInstant(value) {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function maintenanceActionResolution(intent, resolvedAt) {
  return { Update: {
    ConditionExpression: "#status = :outstanding AND #kind = :kind AND schemaVersion = :schema AND tenantId = :tenantId AND id = :id AND sourceRevision = :sourceRevision AND detectedAt = :detected AND reason = :reason AND GSI1SK = :indexSk",
    ExpressionAttributeNames: { "#kind": "kind", "#status": "status" },
    ExpressionAttributeValues: {
      ":detected": { S: intent.reconciliationDetectedAt }, ":id": { S: intent.id },
      ":indexSk": { S: `${intent.reconciliationDetectedAt}#${config.tenantId}#${intent.id}#${intent.revision}` },
      ":kind": { S: "UploadMaintenanceAction" }, ":outstanding": { S: "OUTSTANDING" },
      ":reason": { S: intent.reconciliationReason }, ":resolved": { S: "RESOLVED" },
      ":resolvedAt": { S: resolvedAt }, ":schema": { N: "1" },
      ":sourceRevision": { N: String(intent.revision) }, ":tenantId": { S: config.tenantId },
    },
    Key: { PK: { S: `MAINTENANCE#ACTION_REQUIRED#${config.tenantId}` }, SK: { S: intent.reconciliationActionKey } },
    TableName: config.controlTable,
    UpdateExpression: "SET #status = :resolved, resolvedAt = :resolvedAt REMOVE GSI1SK",
  } };
}

async function reconcileDatabase(intent, receipt) {
  const tx = await rds.send(new BeginTransactionCommand({ database: config.databaseName, resourceArn: config.clusterArn, secretArn: config.ingestSecretArn }));
  if (!/^[A-Za-z0-9-]{8,256}$/.test(tx.transactionId ?? "")) throw new Error("RDS did not establish a rejection transaction.");
  try {
    await execute(tx.transactionId, "SELECT pg_catalog.set_config('scopeproof.tenant_id', :tenant, true)", [param("tenant", config.tenantId)]);
    const response = await execute(tx.transactionId, [
      "SELECT receipt_id::text, was_created, committed_upload_revision, committed_evidence_revision, committed_receipt_sha256",
      "FROM scopeproof.reconcile_rejected_evidence(CAST(:receipt AS scopeproof.resource_identifier), CAST(:intent AS scopeproof.resource_identifier),",
      "CAST(:evidence AS scopeproof.resource_identifier), :version, :result, :event, CAST(:ur AS integer), CAST(:er AS integer),",
      "CAST(:facts AS jsonb), :canonical, :digest, CAST(:at AS timestamptz))",
    ].join(" "), [
      param("receipt", receipt.receiptId), param("intent", intent.id), param("evidence", intent.resourceId),
      param("version", receipt.quarantineVersionId), param("result", receipt.scanResult), param("event", receipt.providerEventId),
      param("ur", String(intent.databaseUploadRevision)), param("er", String(intent.databaseEvidenceRevision)),
      param("facts", receipt.canonical), param("canonical", receipt.canonical), param("digest", receipt.receiptSha256), param("at", receipt.rejectedAt),
    ], "JSON");
    const rows = JSON.parse(response.formattedRecords ?? "[]");
    const row = rows[0];
    if (rows.length !== 1 || row?.receipt_id !== receipt.receiptId || row?.committed_receipt_sha256 !== receipt.receiptSha256 ||
        !Number.isSafeInteger(row?.committed_upload_revision) || !Number.isSafeInteger(row?.committed_evidence_revision)) {
      throw new Error("Database returned a conflicting rejection receipt.");
    }
    await rds.send(new CommitTransactionCommand({ resourceArn: config.clusterArn, secretArn: config.ingestSecretArn, transactionId: tx.transactionId }));
    return { uploadRevision: row.committed_upload_revision, evidenceRevision: row.committed_evidence_revision };
  } catch (error) {
    try {
      await rds.send(new RollbackTransactionCommand({ resourceArn: config.clusterArn, secretArn: config.ingestSecretArn, transactionId: tx.transactionId }));
    } catch {
      // Preserve the original reconciliation error; an unconfirmed rollback never reports success.
    }
    throw error;
  }
}

function execute(transactionId, sql, parameters, formatRecordsAs) {
  return rds.send(new ExecuteStatementCommand({ database: config.databaseName, formatRecordsAs, parameters, resourceArn: config.clusterArn, secretArn: config.ingestSecretArn, sql, transactionId }));
}
function rejectionReceiptAttributes(value) { return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, { S: String(v) }])); }
function assertSameReceipt(actual, expected) {
  const expectedKeys = Object.keys(expected).sort();
  if (!actual || JSON.stringify(Object.keys(actual).sort()) !== JSON.stringify(expectedKeys) ||
      expectedKeys.some((key) => String(actual[key]) !== String(expected[key]))) {
    throw new Error("Rejection receipt conflicts with the GuardDuty event.");
  }
}
function number(value) { const parsed = Number(value?.N ?? NaN); return Number.isSafeInteger(parsed) ? parsed : NaN; }
function param(name, value) { return { name, value: { stringValue: value } }; }
function sha256(value) { return createHash("sha256").update(value).digest("hex"); }
function stableJson(value) { if (value === null || typeof value !== "object") return JSON.stringify(value); if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`; return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${stableJson(value[k])}`).join(",")}}`; }
function validVersion(value) { return /^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/.test(value); }
function safeName(error) { const name = String(error?.name ?? "Error"); return /^[A-Za-z][A-Za-z0-9]{0,63}$/.test(name) ? name : "Error"; }
