import { createHash } from "node:crypto";
import { DynamoDBClient, GetItemCommand, TransactWriteItemsCommand } from "@aws-sdk/client-dynamodb";
import {
  CopyObjectCommand,
  DeleteObjectCommand,
  GetObjectTaggingCommand,
  HeadObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";

const required = [
  "AWS_ACCOUNT_ID_EXPECTED",
  "AWS_REGION_EXPECTED",
  "CONTROL_TABLE_NAME",
  "EVIDENCE_BUCKET_NAME",
  "EVIDENCE_KEY_ARN",
  "INGEST_BUCKET_NAME",
  "MALWARE_PROTECTION_PLAN_ARN",
  "MAX_OBJECT_BYTES",
  "RETENTION_DAYS",
  "RETENTION_MODE",
  "TENANT_ID",
];
for (const name of required) {
  if (!process.env[name]) throw new Error(`Missing required environment variable ${name}.`);
}

const config = Object.freeze({
  accountId: process.env.AWS_ACCOUNT_ID_EXPECTED,
  awsRegion: process.env.AWS_REGION_EXPECTED,
  controlTable: process.env.CONTROL_TABLE_NAME,
  evidenceBucket: process.env.EVIDENCE_BUCKET_NAME,
  evidenceKeyArn: process.env.EVIDENCE_KEY_ARN,
  ingestBucket: process.env.INGEST_BUCKET_NAME,
  malwarePlanArn: process.env.MALWARE_PROTECTION_PLAN_ARN,
  maxObjectBytes: Number(process.env.MAX_OBJECT_BYTES),
  retentionDays: Number(process.env.RETENTION_DAYS),
  retentionMode: process.env.RETENTION_MODE,
  tenantId: process.env.TENANT_ID,
});
if (!/^ten_[a-f0-9]{32}$/.test(config.tenantId)) throw new Error("Unsafe tenant identifier.");
if (!/^\d{12}$/.test(config.accountId) || !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(config.awsRegion)) {
  throw new Error("Unsafe AWS deployment identity.");
}
if (!Number.isInteger(config.maxObjectBytes) || config.maxObjectBytes !== 25 * 1024 * 1024) {
  throw new Error("Hosted evidence must use the 25 MiB upload contract.");
}
if (!Number.isInteger(config.retentionDays) || config.retentionDays < 1 || config.retentionDays > 3650) {
  throw new Error("Invalid evidence retention period.");
}
if (!new Set(["GOVERNANCE", "COMPLIANCE"]).has(config.retentionMode)) {
  throw new Error("Invalid Object Lock retention mode.");
}

const mimeExtensions = new Map([
  ["application/json", "json"],
  ["application/spdx+json", "spdx.json"],
  ["application/vnd.cyclonedx+json", "cdx.json"],
  ["image/png", "png"],
  ["text/csv", "csv"],
  ["text/plain", "txt"],
]);
const dynamo = new DynamoDBClient({});
const s3 = new S3Client({});

export async function handler(event) {
  const failures = [];
  for (const record of event?.Records ?? []) {
    try {
      await promoteRecord(record);
    } catch {
      failures.push({ itemIdentifier: String(record?.messageId ?? "unknown") });
    }
  }
  return { batchItemFailures: failures };
}

async function promoteRecord(record) {
  const messageId = String(record?.messageId ?? "");
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(messageId)) throw new Error("Invalid SQS message identifier.");
  const envelope = JSON.parse(String(record?.body ?? "{}"));
  const detail = envelope?.detail;
  if (
    envelope?.source !== "aws.guardduty" ||
    envelope?.account !== config.accountId ||
    envelope?.region !== config.awsRegion ||
    !Array.isArray(envelope?.resources) ||
    !envelope.resources.includes(config.malwarePlanArn) ||
    envelope?.["detail-type"] !== "GuardDuty Malware Protection Object Scan Result" ||
    detail?.schemaVersion !== "1.0" ||
    detail?.scanStatus !== "COMPLETED" ||
    detail?.scanResultDetails?.scanResultStatus !== "NO_THREATS_FOUND"
  ) {
    throw new Error("The queue message is not an accepted GuardDuty clean-scan event.");
  }

  const source = detail?.s3ObjectDetails ?? {};
  const bucket = String(source.bucketName ?? "");
  const key = String(source.objectKey ?? "");
  const versionId = String(source.versionId ?? "");
  if (bucket !== config.ingestBucket || !validVersionId(versionId)) {
    throw new Error("The scan result does not identify the configured versioned ingest object.");
  }
  const keyMatch = key.match(
    new RegExp(`^tenants/${config.tenantId}/quarantine/(upl_[a-f0-9]{32})\\.upload$`),
  );
  if (!keyMatch) throw new Error("The object key is not an opaque tenant upload key.");
  const intentId = keyMatch[1];
  const intentKey = {
    PK: { S: `TENANT#${config.tenantId}` },
    SK: { S: `UPLOAD#${intentId}` },
  };
  const intentResponse = await dynamo.send(
    new GetItemCommand({ ConsistentRead: true, Key: intentKey, TableName: config.controlTable }),
  );
  const intent = parseIntent(intentResponse.Item, intentId, key);
  if (intent.status === "promoted") {
    if (intent.sourceVersionId !== versionId) {
      throw new Error("A promoted upload intent cannot be replayed with another object version.");
    }
    await verifyCompletedPromotion(intent, intentId, versionId);
    return;
  }
  if (!new Set(["issued", "quarantined", "validated"]).has(intent.status)) {
    throw new Error("The upload intent is not eligible for validation and promotion.");
  }

  const head = await s3.send(
    new HeadObjectCommand({
      Bucket: bucket,
      ChecksumMode: "ENABLED",
      Key: key,
      VersionId: versionId,
    }),
  );
  validateHeadAgainstIntent(head, intent, source.eTag);
  const tags = await s3.send(
    new GetObjectTaggingCommand({ Bucket: bucket, Key: key, VersionId: versionId }),
  );
  if (!tags.TagSet?.some((tag) => tag.Key === "GuardDutyMalwareScanStatus" && tag.Value === "NO_THREATS_FOUND")) {
    throw new Error("GuardDuty's clean-scan object tag is absent.");
  }

  const receiptHash = digestHex(`${config.tenantId}\0${intentId}\0${versionId}`);
  const receiptKey = {
    PK: { S: `TENANT#${config.tenantId}` },
    SK: { S: `PROMOTION#${receiptHash}` },
  };
  const eventId = String(envelope.id ?? "");
  if (!/^[a-f0-9-]{16,64}$/i.test(eventId)) throw new Error("Invalid GuardDuty event identifier.");
  const leaseId = digestHex(`${eventId}\0${messageId}`);
  const now = new Date();
  const nowIso = now.toISOString();
  const leaseExpiresAt = new Date(now.getTime() + 5 * 60_000).toISOString();

  if (intent.status === "issued") {
    await claimIssuedIntent({
      eventId,
      intent,
      intentKey,
      leaseId,
      leaseExpiresAt,
      nowIso,
      receiptHash,
      receiptKey,
      versionId,
    });
    intent.status = "quarantined";
    intent.revision = 1;
    intent.sourceVersionId = versionId;
  } else {
    if (intent.sourceVersionId !== versionId) throw new Error("Upload intent source version mismatch.");
    await renewLease(intentKey, intent, leaseId, leaseExpiresAt, nowIso);
  }

  if (intent.status === "quarantined") {
    await markValidated(intentKey, intent, leaseId, head, nowIso, versionId);
    intent.status = "validated";
    intent.revision = 2;
  }

  const requiredRetention = new Date(intent.requiredRetentionUntil);
  const configuredRetention = new Date(now.getTime() + config.retentionDays * 86_400_000);
  const retainUntil = requiredRetention > configuredRetention ? requiredRetention : configuredRetention;
  const encryptionContext = Buffer.from(
    JSON.stringify({ scopeproofPurpose: "immutable-evidence", scopeproofTenantId: config.tenantId }),
  ).toString("base64");

  let destination = await findCompletedCopy(
    intent.finalKey,
    versionId,
    intent.expectedSha256,
    undefined,
    retainUntil,
  );
  let providerRequestId = destination?.providerRequestId;
  if (!destination) {
    const copy = await s3.send(
      new CopyObjectCommand({
        Bucket: config.evidenceBucket,
        ChecksumAlgorithm: "SHA256",
        ContentType: intent.contentType,
        CopySource: copySource(bucket, key, versionId),
        CopySourceIfMatch: head.ETag,
        Key: intent.finalKey,
        Metadata: {
          "intent-id": intentId,
          "resource-id": intent.resourceId,
          sha256: intent.expectedSha256,
          "source-version": versionId,
          "tenant-id": config.tenantId,
        },
        MetadataDirective: "REPLACE",
        ObjectLockMode: config.retentionMode,
        ObjectLockRetainUntilDate: retainUntil,
        ServerSideEncryption: "aws:kms",
        SSEKMSKeyId: config.evidenceKeyArn,
        SSEKMSEncryptionContext: encryptionContext,
        Tagging: new URLSearchParams({
          "malware-status": "NO_THREATS_FOUND",
          "tenant-id": config.tenantId,
        }).toString(),
        TaggingDirective: "REPLACE",
      }),
    );
    const expectedBase64 = Buffer.from(intent.expectedSha256, "hex").toString("base64");
    if (!copy.VersionId || copy.CopyObjectResult?.ChecksumSHA256 !== expectedBase64) {
      throw new Error("S3 did not attest the copied object's expected SHA-256 checksum and version.");
    }
    providerRequestId = copy.$metadata?.requestId;
    destination = await findCompletedCopy(
      intent.finalKey,
      versionId,
      intent.expectedSha256,
      copy.VersionId,
      retainUntil,
    );
    if (!destination) throw new Error("The immutable destination failed post-copy verification.");
  }

  await completePromotion({
    destinationVersionId: destination.versionId,
    intent,
    intentKey,
    leaseId,
    nowIso,
    providerRequestId: providerRequestId ?? "unknown",
    receiptKey,
    retainUntil,
    versionId,
  });
  await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key, VersionId: versionId }));
}

function parseIntent(item, expectedIntentId, expectedKey) {
  if (!item) throw new Error("A strongly consistent upload intent is required.");
  const intent = {
    contentType: item.contentType?.S,
    expectedSha256: item.expectedSha256?.S,
    expectedSize: item.expectedSize?.N === undefined ? NaN : Number(item.expectedSize.N),
    expiresAt: item.expiresAt?.S,
    finalKey: item.finalKey?.S,
    id: item.id?.S,
    issuedAt: item.issuedAt?.S,
    nonceDigest: item.nonceDigest?.S,
    promotionReceipt: {
      byteSize: item.promotionReceipt?.M?.byteSize?.N === undefined
        ? NaN
        : Number(item.promotionReceipt.M.byteSize.N),
      contentType: item.promotionReceipt?.M?.contentType?.S,
      finalKey: item.promotionReceipt?.M?.finalKey?.S,
      finalVersionId: item.promotionReceipt?.M?.finalVersionId?.S,
      kmsKeyArn: item.promotionReceipt?.M?.kmsKeyArn?.S,
      objectLockMode: item.promotionReceipt?.M?.objectLockMode?.S,
      retainUntil: item.promotionReceipt?.M?.retainUntil?.S,
      sha256: item.promotionReceipt?.M?.sha256?.S,
      sourceKey: item.promotionReceipt?.M?.sourceKey?.S,
      sourceVersionId: item.promotionReceipt?.M?.sourceVersionId?.S,
      tenantId: item.promotionReceipt?.M?.tenantId?.S,
    },
    quarantineKey: item.quarantineKey?.S,
    requiredRetentionUntil: item.requiredRetentionUntil?.S,
    resourceId: item.resourceId?.S,
    revision: item.revision?.N === undefined ? NaN : Number(item.revision.N),
    schemaVersion: item.schemaVersion?.N === undefined ? NaN : Number(item.schemaVersion.N),
    sourceVersionId: item.quarantineReceipt?.M?.versionId?.S,
    status: item.status?.S,
    tenantId: item.tenantId?.S,
  };
  const extension = mimeExtensions.get(intent.contentType);
  const expectedFinalPattern = new RegExp(
    `^tenants/${config.tenantId}/evidence/(evd_[a-f0-9]{32})\\.${escapeRegex(extension ?? "invalid")}$`,
  );
  const finalMatch = String(intent.finalKey ?? "").match(expectedFinalPattern);
  const expectedRevision = { issued: 0, quarantined: 1, validated: 2, promoted: 3 }[intent.status];
  const promotedReceiptValid = intent.status !== "promoted" || (
    intent.promotionReceipt.byteSize === intent.expectedSize &&
    intent.promotionReceipt.contentType === intent.contentType &&
    intent.promotionReceipt.finalKey === intent.finalKey &&
    validVersionId(intent.promotionReceipt.finalVersionId) &&
    intent.promotionReceipt.kmsKeyArn === config.evidenceKeyArn &&
    intent.promotionReceipt.objectLockMode === config.retentionMode &&
    validInstant(intent.promotionReceipt.retainUntil) &&
    Date.parse(intent.promotionReceipt.retainUntil) >= Date.parse(intent.requiredRetentionUntil) &&
    intent.promotionReceipt.sha256 === intent.expectedSha256 &&
    intent.promotionReceipt.sourceKey === intent.quarantineKey &&
    intent.promotionReceipt.sourceVersionId === intent.sourceVersionId &&
    intent.promotionReceipt.tenantId === config.tenantId
  );
  if (
    item.kind?.S !== "UploadLifecycle" ||
    intent.schemaVersion !== 1 ||
    intent.id !== expectedIntentId ||
    intent.tenantId !== config.tenantId ||
    intent.quarantineKey !== expectedKey ||
    !/^usr_[a-f0-9]{32}$/.test(item.requestedBy?.S ?? "") ||
    !/^evd_[a-f0-9]{32}$/.test(intent.resourceId ?? "") ||
    !/^[a-f0-9]{64}$/.test(intent.expectedSha256 ?? "") ||
    !Number.isSafeInteger(intent.expectedSize) ||
    intent.expectedSize < 1 ||
    intent.expectedSize > config.maxObjectBytes ||
    !extension ||
    !/^[a-f0-9]{64}$/.test(intent.nonceDigest ?? "") ||
    !finalMatch ||
    finalMatch[1] !== intent.resourceId ||
    !Number.isSafeInteger(intent.revision) ||
    intent.revision !== expectedRevision ||
    !promotedReceiptValid ||
    !validInstant(intent.issuedAt) ||
    !validInstant(intent.expiresAt) ||
    !validInstant(intent.requiredRetentionUntil) ||
    Date.parse(intent.issuedAt) > Date.now() ||
    Date.parse(intent.expiresAt) - Date.parse(intent.issuedAt) > 10 * 60_000 ||
    (intent.status === "issued" && Date.parse(intent.expiresAt) <= Date.now()) ||
    Date.parse(intent.requiredRetentionUntil) <= Date.parse(intent.expiresAt) ||
    Date.parse(intent.requiredRetentionUntil) > Date.now() + 3650 * 86_400_000
  ) {
    throw new Error("The authoritative upload intent failed its security contract.");
  }
  return intent;
}

async function verifyCompletedPromotion(intent, intentId, sourceVersionId) {
  const receiptHash = digestHex(`${config.tenantId}\0${intentId}\0${sourceVersionId}`);
  const receipt = await dynamo.send(
    new GetItemCommand({
      ConsistentRead: true,
      Key: {
        PK: { S: `TENANT#${config.tenantId}` },
        SK: { S: `PROMOTION#${receiptHash}` },
      },
      TableName: config.controlTable,
    }),
  );
  const item = receipt.Item;
  if (
    item?.kind?.S !== "EvidencePromotionReceipt" ||
    item?.tenantId?.S !== config.tenantId ||
    item?.intentId?.S !== intentId ||
    item?.receiptHash?.S !== receiptHash ||
    item?.status?.S !== "COMPLETE" ||
    item?.sourceBucket?.S !== config.ingestBucket ||
    item?.sourceKey?.S !== intent.quarantineKey ||
    item?.sourceVersionId?.S !== sourceVersionId ||
    item?.destinationBucket?.S !== config.evidenceBucket ||
    item?.destinationKey?.S !== intent.finalKey ||
    item?.destinationVersionId?.S !== intent.promotionReceipt.finalVersionId ||
    item?.sha256?.S !== intent.expectedSha256 ||
    item?.retainUntil?.S !== intent.promotionReceipt.retainUntil
  ) {
    throw new Error("The completed promotion receipt is absent or inconsistent.");
  }
  const destination = await findCompletedCopy(
    intent.finalKey,
    sourceVersionId,
    intent.expectedSha256,
    intent.promotionReceipt.finalVersionId,
    new Date(intent.promotionReceipt.retainUntil),
  );
  if (destination?.versionId !== intent.promotionReceipt.finalVersionId) {
    throw new Error("The recorded immutable evidence version failed revalidation.");
  }
}

function validateHeadAgainstIntent(head, intent, eventEtag) {
  if (head.ContentLength !== intent.expectedSize) throw new Error("Evidence size does not match the intent.");
  const contentType = String(head.ContentType ?? "").split(";", 1)[0].trim().toLowerCase();
  if (contentType !== intent.contentType) throw new Error("Evidence MIME type does not match the intent.");
  if (!head.ChecksumSHA256) throw new Error("A full-object SHA-256 checksum is required.");
  const actual = Buffer.from(head.ChecksumSHA256, "base64").toString("hex");
  if (actual !== intent.expectedSha256) throw new Error("Evidence SHA-256 does not match the intent.");
  if (normalizeEtag(eventEtag) !== normalizeEtag(head.ETag)) throw new Error("GuardDuty scanned a different ETag.");
}

async function claimIssuedIntent(input) {
  await dynamo.send(
    new TransactWriteItemsCommand({
      ClientRequestToken: token(`${input.leaseId}\0${input.nowIso}`, "claim"),
      TransactItems: [
        {
          Update: {
            ConditionExpression:
              "#status = :issued AND #revision = :zero AND #expiresAt > :now AND quarantineKey = :sourceKey AND finalKey = :finalKey AND expectedSha256 = :sha256 AND expectedSize = :size AND contentType = :contentType",
            ExpressionAttributeNames: { "#expiresAt": "expiresAt", "#revision": "revision", "#status": "status" },
            ExpressionAttributeValues: {
              ":contentType": { S: input.intent.contentType },
              ":consumedAt": { S: input.nowIso },
              ":leaseId": { S: input.leaseId },
              ":expires": { S: input.leaseExpiresAt },
              ":finalKey": { S: input.intent.finalKey },
              ":issued": { S: "issued" },
              ":now": { S: input.nowIso },
              ":one": { N: "1" },
              ":receipt": {
                M: {
                  byteSize: { N: String(input.intent.expectedSize) },
                  contentType: { S: input.intent.contentType },
                  key: { S: input.intent.quarantineKey },
                  providerRequestId: { S: input.eventId },
                  receivedAt: { S: input.nowIso },
                  sha256: { S: input.intent.expectedSha256 },
                  tenantId: { S: config.tenantId },
                  versionId: { S: input.versionId },
                },
              },
              ":sha256": { S: input.intent.expectedSha256 },
              ":size": { N: String(input.intent.expectedSize) },
              ":sourceKey": { S: input.intent.quarantineKey },
              ":status": { S: "quarantined" },
              ":zero": { N: "0" },
            },
            Key: input.intentKey,
            TableName: config.controlTable,
            UpdateExpression:
              "SET #status = :status, #revision = :one, consumedAt = :consumedAt, quarantineReceipt = :receipt, promotionLeaseId = :leaseId, promotionLeaseExpiresAt = :expires",
          },
        },
        {
          Put: {
            ConditionExpression: "attribute_not_exists(PK)",
            Item: {
              ...input.receiptKey,
              destinationBucket: { S: config.evidenceBucket },
              destinationKey: { S: input.intent.finalKey },
              intentId: { S: input.intent.id },
              kind: { S: "EvidencePromotionReceipt" },
              receiptHash: { S: input.receiptHash },
              sha256: { S: input.intent.expectedSha256 },
              sourceBucket: { S: config.ingestBucket },
              sourceKey: { S: input.intent.quarantineKey },
              sourceVersionId: { S: input.versionId },
              startedAt: { S: input.nowIso },
              status: { S: "COPYING" },
              tenantId: { S: config.tenantId },
            },
            TableName: config.controlTable,
          },
        },
      ],
    }),
  );
}

async function renewLease(intentKey, intent, leaseId, leaseExpiresAt, nowIso) {
  await dynamo.send(
    new TransactWriteItemsCommand({
      ClientRequestToken: token(`${leaseId}\0${nowIso}`, "renew"),
      TransactItems: [
        {
          Update: {
            ConditionExpression:
              "#status = :status AND #revision = :revision AND quarantineReceipt.versionId = :versionId AND (attribute_not_exists(promotionLeaseExpiresAt) OR promotionLeaseExpiresAt < :now)",
            ExpressionAttributeNames: { "#revision": "revision", "#status": "status" },
            ExpressionAttributeValues: {
              ":expires": { S: leaseExpiresAt },
              ":leaseId": { S: leaseId },
              ":now": { S: nowIso },
              ":revision": { N: String(intent.revision) },
              ":status": { S: intent.status },
              ":versionId": { S: intent.sourceVersionId },
            },
            Key: intentKey,
            TableName: config.controlTable,
            UpdateExpression: "SET promotionLeaseId = :leaseId, promotionLeaseExpiresAt = :expires",
          },
        },
      ],
    }),
  );
}

async function markValidated(intentKey, intent, leaseId, head, nowIso, versionId) {
  const scannerPolicy = "aws-guardduty-s3-malware-protection-v1";
  const scannerDigest = digestHex(`${scannerPolicy}\n${config.malwarePlanArn}`);
  const expectedBase64 = Buffer.from(intent.expectedSha256, "hex").toString("base64");
  if (head.ChecksumSHA256 !== expectedBase64) throw new Error("Checksum changed before validation was committed.");
  await dynamo.send(
    new TransactWriteItemsCommand({
      ClientRequestToken: token(`${leaseId}\0${nowIso}`, "validate"),
      TransactItems: [
        {
          Update: {
            ConditionExpression:
              "#status = :quarantined AND #revision = :one AND promotionLeaseId = :leaseId AND quarantineReceipt.versionId = :versionId",
            ExpressionAttributeNames: { "#revision": "revision", "#status": "status" },
            ExpressionAttributeValues: {
              ":leaseId": { S: leaseId },
              ":one": { N: "1" },
              ":quarantined": { S: "quarantined" },
              ":two": { N: "2" },
              ":validated": { S: "validated" },
              ":validation": {
                M: {
                  byteSize: { N: String(intent.expectedSize) },
                  completedAt: { S: nowIso },
                  contentType: { S: intent.contentType },
                  key: { S: intent.quarantineKey },
                  safe: { BOOL: true },
                  scannerDigest: { S: scannerDigest },
                  scannerPolicy: { S: scannerPolicy },
                  sha256: { S: intent.expectedSha256 },
                  tenantId: { S: config.tenantId },
                  versionId: { S: versionId },
                },
              },
              ":versionId": { S: versionId },
            },
            Key: intentKey,
            TableName: config.controlTable,
            UpdateExpression: "SET #status = :validated, #revision = :two, validation = :validation",
          },
        },
      ],
    }),
  );
}

async function findCompletedCopy(
  destinationKey,
  sourceVersionId,
  expectedSha256,
  exactVersionId,
  expectedRetainUntil,
) {
  try {
    const destination = await s3.send(
      new HeadObjectCommand({
        Bucket: config.evidenceBucket,
        ChecksumMode: "ENABLED",
        Key: destinationKey,
        VersionId: exactVersionId,
      }),
    );
    const checksum = destination.ChecksumSHA256
      ? Buffer.from(destination.ChecksumSHA256, "base64").toString("hex")
      : "";
    if (
      destination.Metadata?.["source-version"] !== sourceVersionId ||
      destination.Metadata?.sha256 !== expectedSha256 ||
      checksum !== expectedSha256 ||
      !destination.VersionId ||
      destination.ServerSideEncryption !== "aws:kms" ||
      destination.SSEKMSKeyId !== config.evidenceKeyArn ||
      destination.ObjectLockMode !== config.retentionMode ||
      !destination.ObjectLockRetainUntilDate ||
      destination.ObjectLockRetainUntilDate.getTime() < expectedRetainUntil.getTime()
    ) return undefined;
    return { providerRequestId: destination.$metadata?.requestId, versionId: destination.VersionId };
  } catch (error) {
    if (error?.name === "NotFound" || error?.$metadata?.httpStatusCode === 404) return undefined;
    throw error;
  }
}

async function completePromotion(input) {
  const promotionReceipt = {
    M: {
      byteSize: { N: String(input.intent.expectedSize) },
      contentType: { S: input.intent.contentType },
      finalKey: { S: input.intent.finalKey },
      finalVersionId: { S: input.destinationVersionId },
      kmsKeyArn: { S: config.evidenceKeyArn },
      objectLockMode: { S: config.retentionMode },
      promotedAt: { S: input.nowIso },
      providerRequestId: { S: input.providerRequestId },
      retainUntil: { S: input.retainUntil.toISOString() },
      sha256: { S: input.intent.expectedSha256 },
      sourceKey: { S: input.intent.quarantineKey },
      sourceVersionId: { S: input.versionId },
      tenantId: { S: config.tenantId },
    },
  };
  await dynamo.send(
    new TransactWriteItemsCommand({
      ClientRequestToken: token(`${input.leaseId}\0${input.nowIso}`, "complete"),
      TransactItems: [
        {
          Update: {
            ConditionExpression:
              "#status = :validated AND #revision = :two AND promotionLeaseId = :leaseId AND quarantineReceipt.versionId = :sourceVersion",
            ExpressionAttributeNames: { "#revision": "revision", "#status": "status" },
            ExpressionAttributeValues: {
              ":leaseId": { S: input.leaseId },
              ":promoted": { S: "promoted" },
              ":receipt": promotionReceipt,
              ":sourceVersion": { S: input.versionId },
              ":three": { N: "3" },
              ":two": { N: "2" },
              ":validated": { S: "validated" },
            },
            Key: input.intentKey,
            TableName: config.controlTable,
            UpdateExpression:
              "SET #status = :promoted, #revision = :three, promotionReceipt = :receipt REMOVE promotionLeaseId, promotionLeaseExpiresAt",
          },
        },
        {
          Update: {
            ConditionExpression:
              "#status = :copying AND tenantId = :tenantId AND intentId = :intentId AND receiptHash = :receiptHash AND sourceBucket = :sourceBucket AND sourceKey = :sourceKey AND sourceVersionId = :sourceVersion AND destinationBucket = :destinationBucket AND destinationKey = :destinationKey AND sha256 = :sha256",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: {
              ":complete": { S: "COMPLETE" },
              ":completedAt": { S: input.nowIso },
              ":copying": { S: "COPYING" },
              ":destinationBucket": { S: config.evidenceBucket },
              ":destinationKey": { S: input.intent.finalKey },
              ":destinationVersion": { S: input.destinationVersionId },
              ":intentId": { S: input.intent.id },
              ":receiptHash": { S: input.receiptKey.SK.S.slice("PROMOTION#".length) },
              ":retainUntil": { S: input.retainUntil.toISOString() },
              ":sha256": { S: input.intent.expectedSha256 },
              ":sourceBucket": { S: config.ingestBucket },
              ":sourceKey": { S: input.intent.quarantineKey },
              ":sourceVersion": { S: input.versionId },
              ":tenantId": { S: config.tenantId },
            },
            Key: input.receiptKey,
            TableName: config.controlTable,
            UpdateExpression:
              "SET #status = :complete, completedAt = :completedAt, destinationVersionId = :destinationVersion, retainUntil = :retainUntil",
          },
        },
      ],
    }),
  );
}

function validVersionId(value) {
  return /^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/.test(value);
}

function validInstant(value) {
  if (typeof value !== "string") return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && value === parsed.toISOString();
}

function normalizeEtag(value) {
  return String(value ?? "").replace(/^"|"$/g, "");
}

function digestHex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function token(eventId, operation) {
  return `sp-${operation}-${digestHex(`${eventId}\0${operation}`).slice(0, 20)}`.slice(0, 36);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function copySource(bucket, key, versionId) {
  const encodedKey = key.split("/").map(encodeURIComponent).join("/");
  return `/${bucket}/${encodedKey}?versionId=${encodeURIComponent(versionId)}`;
}
