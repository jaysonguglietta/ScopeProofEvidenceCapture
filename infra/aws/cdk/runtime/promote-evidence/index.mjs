import { createHash } from "node:crypto";
import { DynamoDBClient, GetItemCommand, QueryCommand, TransactWriteItemsCommand } from "@aws-sdk/client-dynamodb";
import { SignCommand, VerifyCommand, KMSClient } from "@aws-sdk/client-kms";
import {
  BeginTransactionCommand,
  CommitTransactionCommand,
  ExecuteStatementCommand,
  RDSDataClient,
  RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";
import {
  DeleteObjectCommand,
  GetObjectCommand,
  GetObjectTaggingCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import {
  buildAuthoritativePromotionReceiptItem,
  parseAuthoritativePromotionReceiptItem,
  parseCommittedPromotionReceipt,
  verifyCommittedPromotionReceipt,
} from "./promotion-receipt.mjs";
import { buildPromotionRecoveryChangeItem } from "../reconcile-recovery/change-ledger.mjs";
import { derivePromotionRetention } from "./retention-contract.mjs";
import { buildExactVersionDlpRequest, parseExactVersionDlpResponse } from "./dlp-contract.mjs";
import {
  buildPromotionCopyAttemptItem,
  createOrAdoptImmutableDestination,
  derivePromotionLease,
  promotionCopyAttemptSortKey,
  promotionCopyMetadata,
  promotionLeaseDurationMilliseconds,
} from "./promotion-fence.mjs";

const required = [
  "AWS_ACCOUNT_ID_EXPECTED",
  "AWS_REGION_EXPECTED",
  "AUDIT_SIGNING_KEY_ARN",
  "CONTROL_TABLE_NAME",
  "DATABASE_CLUSTER_ARN",
  "DATABASE_NAME",
  "DLP_MODE",
  "DLP_POLICY_VERSION",
  "DLP_SCANNER_ENDPOINT",
  "DLP_SCANNER_SECRET_ARN",
  "EVIDENCE_BUCKET_NAME",
  "EVIDENCE_KEY_ARN",
  "INGEST_BUCKET_NAME",
  "INGEST_DATABASE_SECRET_ARN",
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
  auditSigningKeyArn: process.env.AUDIT_SIGNING_KEY_ARN,
  controlTable: process.env.CONTROL_TABLE_NAME,
  databaseClusterArn: process.env.DATABASE_CLUSTER_ARN,
  databaseName: process.env.DATABASE_NAME,
  dlpMode: process.env.DLP_MODE,
  dlpPolicyVersion: process.env.DLP_POLICY_VERSION,
  dlpScannerEndpoint: process.env.DLP_SCANNER_ENDPOINT,
  dlpScannerSecretArn: process.env.DLP_SCANNER_SECRET_ARN,
  evidenceBucket: process.env.EVIDENCE_BUCKET_NAME,
  evidenceKeyArn: process.env.EVIDENCE_KEY_ARN,
  ingestBucket: process.env.INGEST_BUCKET_NAME,
  ingestDatabaseSecretArn: process.env.INGEST_DATABASE_SECRET_ARN,
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
const escapedRegion = config.awsRegion.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const escapedAccount = config.accountId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const kmsKeyArnPattern = new RegExp(`^arn:(aws|aws-us-gov|aws-cn):kms:${escapedRegion}:${escapedAccount}:key/[0-9a-f-]{36}$`);
const clusterArnPattern = new RegExp(`^arn:(aws|aws-us-gov|aws-cn):rds:${escapedRegion}:${escapedAccount}:cluster:[A-Za-z0-9-]{1,63}$`);
const secretArnPattern = new RegExp(`^arn:(aws|aws-us-gov|aws-cn):secretsmanager:${escapedRegion}:${escapedAccount}:secret:[A-Za-z0-9/_+=.@-]{1,512}$`);
if (
  !kmsKeyArnPattern.test(config.auditSigningKeyArn) ||
  !kmsKeyArnPattern.test(config.evidenceKeyArn) ||
  !clusterArnPattern.test(config.databaseClusterArn) ||
  !secretArnPattern.test(config.ingestDatabaseSecretArn) ||
  !/^scopeproof_[a-z0-9_]{1,48}$/.test(config.databaseName) ||
  config.auditSigningKeyArn === config.evidenceKeyArn
) {
  throw new Error("Unsafe evidence reconciliation identity.");
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
if (!new Set(["DISABLED", "ENFORCED"]).has(config.dlpMode)) throw new Error("Invalid exact-version DLP mode.");
if (config.dlpMode === "ENFORCED") {
  let endpoint;
  try { endpoint = new URL(config.dlpScannerEndpoint); } catch { throw new Error("Invalid DLP scanner endpoint."); }
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.search || endpoint.hash ||
      endpoint.port || endpoint.pathname === "/" || !/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(config.dlpPolicyVersion) ||
      !secretArnPattern.test(config.dlpScannerSecretArn)) {
    throw new Error("Unsafe exact-version DLP configuration.");
  }
} else if (config.dlpPolicyVersion !== "DISABLED" || config.dlpScannerEndpoint !== "DISABLED" || config.dlpScannerSecretArn !== "DISABLED") {
  throw new Error("Disabled DLP configuration must use the exact fail-closed sentinel.");
}

const mimeExtensions = new Map([
  ["application/json", "json"],
  ["application/spdx+json", "spdx.json"],
  ["application/vnd.cyclonedx+json", "cdx.json"],
  ["image/png", "png"],
  ["text/csv", "csv"],
  ["text/plain", "txt"],
]);
const scanReconciliationGraceMilliseconds = 7 * 24 * 60 * 60 * 1_000;
const dlpSigningAlgorithm = "RSASSA_PSS_SHA_256";
const dynamo = new DynamoDBClient({});
const kms = new KMSClient({});
const rds = new RDSDataClient({});
const secrets = new SecretsManagerClient({});
// Conditional PutObject is deliberately single-attempt. An ambiguous network
// result is recovered by exact-key HeadObject; SDK-level replay is unnecessary.
const s3 = new S3Client({ maxAttempts: 1 });

export async function handler(event) {
  const failures = [];
  for (const record of event?.Records ?? []) {
    try {
      await promoteRecord(record);
    } catch (error) {
      const rawMessageId = String(record?.messageId ?? "unknown");
      console.error(JSON.stringify({
        event: "scopeproof.evidence_promotion_failed",
        errorName: safeErrorName(error),
        messageIdSha256: digestHex(rawMessageId).slice(0, 24),
        tenantId: config.tenantId,
      }));
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
    new RegExp(`^tenants/${config.tenantId}/controls/([A-Za-z0-9][A-Za-z0-9._-]{0,63})/quarantine/(upl_[a-f0-9]{32})\\.upload$`),
  );
  if (!keyMatch) throw new Error("The object key is not an opaque tenant upload key.");
  const controlId = keyMatch[1];
  const intentId = keyMatch[2];
  const intentKey = {
    PK: { S: `TENANT#${config.tenantId}` },
    SK: { S: `UPLOAD#${intentId}` },
  };
  const intentResponse = await dynamo.send(
    new GetItemCommand({ ConsistentRead: true, Key: intentKey, TableName: config.controlTable }),
  );
  const intent = parseIntent(intentResponse.Item, intentId, controlId, key);
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
  const uploadedAt = validateHeadAgainstIntent(head, intent, source.eTag);
  const tags = await s3.send(
    new GetObjectTaggingCommand({ Bucket: bucket, Key: key, VersionId: versionId }),
  );
  if (!tags.TagSet?.some((tag) => tag.Key === "GuardDutyMalwareScanStatus" && tag.Value === "NO_THREATS_FOUND")) {
    throw new Error("GuardDuty's clean-scan object tag is absent.");
  }
  const dlp = await ensureExactVersionDlp(intentKey, intent, {
    bucket,
    byteSize: intent.expectedSize,
    contentType: intent.contentType,
    key,
    sha256: intent.expectedSha256,
    tenantId: config.tenantId,
    uploadedAt,
    versionId,
  });
  if (dlp.decision !== "CLEAN") {
    throw new Error("The exact quarantine object was blocked by the independent server DLP policy.");
  }

  const receiptHash = digestHex(`${config.tenantId}\0${intentId}\0${versionId}`);
  const receiptKey = {
    PK: { S: `TENANT#${config.tenantId}` },
    SK: { S: `PROMOTION#${receiptHash}` },
  };
  const committedReceipt = await readCommittedPromotionReceipt(intent, {
    uploadedAt,
    versionId,
  });
  if (committedReceipt) {
    if (intent.status !== "validated" || intent.revision !== 2) {
      throw new Error("A committed database promotion conflicts with the upload lifecycle state.");
    }
    const committedDestination = await findCompletedCopy(
      intent.finalKey,
      versionId,
      intent.expectedSha256,
      committedReceipt.facts.evidenceVersionId,
      new Date(committedReceipt.facts.retainUntil),
      committedReceipt.facts.uploadedAt,
      dlpFromFacts(committedReceipt.facts),
      committedReceipt.facts.copyAttemptId,
      committedReceipt.facts.copyFence,
    );
    if (
      committedDestination?.versionId !== committedReceipt.facts.evidenceVersionId ||
      committedDestination.retainUntil.toISOString() !== committedReceipt.facts.retainUntil
    ) {
      throw new Error("The signed database receipt does not match the exact immutable S3 version.");
    }
    await completePromotion({
      databaseReconciliation: committedReceipt,
      facts: committedReceipt.facts,
      intent,
      intentKey,
      nowIso: new Date().toISOString(),
      receiptKey,
      recovered: true,
      versionId,
    });
    await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key, VersionId: versionId }));
    return;
  }
  const eventId = String(envelope.id ?? "");
  if (!/^[a-f0-9-]{16,64}$/i.test(eventId)) throw new Error("Invalid GuardDuty event identifier.");
  const leaseId = digestHex(`${eventId}\0${messageId}`);
  const nowIso = new Date().toISOString();
  const lease = derivePromotionLease({
    currentFence: intent.promotionFence,
    intentId,
    leaseId,
    now: nowIso,
    sourceVersionId: versionId,
    tenantId: config.tenantId,
  });

  if (intent.status === "issued") {
    await claimIssuedIntent({
      attemptId: lease.attemptId,
      eventId,
      fence: lease.fence,
      intent,
      intentKey,
      leaseId,
      leaseExpiresAt: lease.leaseExpiresAt,
      nowIso,
      uploadedAt,
      receiptHash,
      receiptKey,
      versionId,
    });
    intent.status = "quarantined";
    intent.revision = 1;
    intent.sourceVersionId = versionId;
  } else {
    if (intent.sourceVersionId !== versionId) throw new Error("Upload intent source version mismatch.");
    await takeOverLease({
      attemptId: lease.attemptId,
      fence: lease.fence,
      intent,
      intentKey,
      leaseId,
      leaseExpiresAt: lease.leaseExpiresAt,
      nowIso,
      receiptHash,
      receiptKey,
    });
  }
  intent.promotionAttemptId = lease.attemptId;
  intent.promotionFence = lease.fence;
  intent.promotionLeaseExpiresAt = lease.leaseExpiresAt;
  intent.promotionLeaseId = leaseId;

  if (intent.status === "quarantined") {
    await markValidated(intentKey, intent, lease, leaseId, head, nowIso, versionId);
    intent.status = "validated";
    intent.revision = 2;
  }

  // Publish the Dynamo fencing token to the independent database boundary
  // before any irreversible S3 operation. A newer Dynamo lease advances this
  // row and makes every older worker fail database reconciliation.
  await claimPromotionFenceDatabase(intent, lease);

  let retainUntil = derivePromotionRetention({
    requiredRetentionUntil: intent.requiredRetentionUntil,
    retentionDays: config.retentionDays,
    uploadedAt,
  }).retainUntil;
  const encryptionContext = Buffer.from(
    JSON.stringify({ scopeproofPurpose: "immutable-evidence", scopeproofTenantId: config.tenantId }),
  ).toString("base64");

  const copyMetadata = promotionCopyMetadata(lease);
  let destination = await findCompletedCopy(
    intent.finalKey,
    versionId,
    intent.expectedSha256,
    undefined,
    retainUntil,
    uploadedAt,
    dlp,
  );
  if (destination) await ensureTrackedCopyOutcome(destination, receiptHash);
  let currentAttemptPermitted = false;
  let providerRequestId = destination?.providerRequestId;
  if (!destination) {
    await prepareCopyAttempt({
      intent,
      intentKey,
      lease,
      leaseId,
      receiptHash,
      receiptKey,
      versionId,
    });
    currentAttemptPermitted = true;
    const sourceObject = await s3.send(new GetObjectCommand({
      Bucket: bucket,
      ChecksumMode: "ENABLED",
      IfMatch: head.ETag,
      Key: key,
      VersionId: versionId,
    }));
    const expectedBase64 = Buffer.from(intent.expectedSha256, "hex").toString("base64");
    if (
      !sourceObject.Body || sourceObject.VersionId !== versionId ||
      sourceObject.ContentLength !== intent.expectedSize ||
      sourceObject.ChecksumSHA256 !== expectedBase64 ||
      normalizeEtag(sourceObject.ETag) !== normalizeEtag(head.ETag) ||
      !metadataMatchesIntent(sourceObject.Metadata, intent)
    ) {
      throw new Error("The exact quarantine stream changed before conditional promotion.");
    }
    const write = await createOrAdoptImmutableDestination({
      createDestination: () => s3.send(new PutObjectCommand({
        Bucket: config.evidenceBucket,
        Body: sourceObject.Body,
        ChecksumAlgorithm: "SHA256",
        ChecksumSHA256: expectedBase64,
        ContentLength: intent.expectedSize,
        ContentType: intent.contentType,
        IfNoneMatch: "*",
        Key: intent.finalKey,
        Metadata: {
          "control-id": intent.controlId,
          "intent-id": intentId,
          ...copyMetadata,
          "resource-id": intent.resourceId,
          sha256: intent.expectedSha256,
          "source-version": versionId,
          "tenant-id": config.tenantId,
          "uploaded-at": uploadedAt,
          "dlp-policy": dlp.policyVersion,
          "dlp-receipt-sha256": dlp.receiptDigest,
          "dlp-scanned-at": dlp.scannedAt,
          "dlp-scanner-request-id": dlp.scannerRequestId,
        },
        ObjectLockMode: config.retentionMode,
        ObjectLockRetainUntilDate: retainUntil,
        ServerSideEncryption: "aws:kms",
        SSEKMSKeyId: config.evidenceKeyArn,
        SSEKMSEncryptionContext: encryptionContext,
        Tagging: new URLSearchParams({
          "malware-status": "NO_THREATS_FOUND",
          "dlp-status": "CLEAN",
          "tenant-id": config.tenantId,
        }).toString(),
      })),
      isConditionalConflict: isConditionalWriteConflict,
      // Another fenced attempt may win the one-and-only destination write.
      // Recover its exact tracked version rather than creating another
      // Object-Locked version. The attempt ledger is reconciled below.
      readWinner: () => findCompletedCopy(
        intent.finalKey,
        versionId,
        intent.expectedSha256,
        undefined,
        retainUntil,
        uploadedAt,
        dlp,
      ),
    });
    const put = write.result;
    if (!write.created) {
      destination = write.destination;
      await ensureTrackedCopyOutcome(destination, receiptHash);
    }
    if (put && validVersionId(put.VersionId)) {
      await recordCopyOutcome({
        attemptId: lease.attemptId,
        completedAt: new Date().toISOString(),
        destinationVersionId: put.VersionId,
        fence: lease.fence,
        observedChecksumSha256: String(put.ChecksumSHA256 ?? ""),
        providerRequestId: String(put.$metadata?.requestId ?? ""),
        receiptHash,
      });
    }
    if (put && (!put.VersionId || put.ChecksumSHA256 !== expectedBase64)) {
      throw new Error("S3 did not attest the conditionally written object's expected SHA-256 checksum and version.");
    }
    if (put) {
      providerRequestId = put.$metadata?.requestId;
      destination = await findCompletedCopy(
        intent.finalKey,
        versionId,
        intent.expectedSha256,
        put.VersionId,
        retainUntil,
        uploadedAt,
        dlp,
        lease.attemptId,
        lease.fence,
      );
      if (!destination) throw new Error("The immutable destination failed post-write verification.");
      await ensureTrackedCopyOutcome(destination, receiptHash);
    } else {
      providerRequestId = destination?.providerRequestId;
    }
  }
  if (
    currentAttemptPermitted &&
    (destination.promotionFence !== lease.fence || destination.promotionAttemptId !== lease.attemptId)
  ) {
    await markCopyAttemptAdopted({
      adoptedAttemptId: destination.promotionAttemptId,
      adoptedFence: destination.promotionFence,
      adoptedVersionId: destination.versionId,
      attemptId: lease.attemptId,
      fence: lease.fence,
      receiptHash,
    });
  }
  await resolveOrphanedCopyAttempts(destination, receiptHash);
  retainUntil = destination.retainUntil;

  const exactProviderRequestId = providerRequestId ?? destination.providerRequestId;
  if (!validProviderRequestId(exactProviderRequestId)) {
    throw new Error("S3 did not return a valid promotion request identifier.");
  }
  const promotedAt = new Date().toISOString();
  const reconciliationLeaseExpiresAt = await renewActiveLease(intentKey, intent, lease, leaseId, promotedAt);
  const reconciliationLease = Object.freeze({ ...lease, leaseExpiresAt: reconciliationLeaseExpiresAt });
  // Re-claiming is idempotent for the exact attempt and rejects a worker whose
  // fence was superseded between S3 and RDS.
  await claimPromotionFenceDatabase(intent, reconciliationLease);
  const promotionFacts = buildPromotionFacts({
    copyAttemptId: destination.promotionAttemptId,
    copyFence: destination.promotionFence,
    destinationVersionId: destination.versionId,
    intent,
    nowIso: promotedAt,
    promotionAttemptId: lease.attemptId,
    promotionFence: lease.fence,
    providerRequestId: exactProviderRequestId,
    retainUntil,
    uploadedAt,
    versionId,
    dlp,
  });
  const databaseReconciliation = await reconcilePromotionDatabase(promotionFacts, intent, reconciliationLease);
  const completionTime = new Date().toISOString();
  await renewActiveLease(intentKey, intent, lease, leaseId, completionTime);
  await completePromotion({
    databaseReconciliation,
    facts: promotionFacts,
    intent,
    intentKey,
    lease,
    leaseId,
    nowIso: completionTime,
    receiptKey,
    recovered: false,
    versionId,
  });
  await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key, VersionId: versionId }));
}

function parseIntent(item, expectedIntentId, expectedControlId, expectedKey) {
  if (!item) throw new Error("A strongly consistent upload intent is required.");
  const intent = {
    contentType: item.contentType?.S,
    controlId: item.controlId?.S,
    databaseEvidenceRevision: item.databaseEvidenceRevision?.N === undefined
      ? NaN
      : Number(item.databaseEvidenceRevision.N),
    databaseUploadRevision: item.databaseUploadRevision?.N === undefined
      ? NaN
      : Number(item.databaseUploadRevision.N),
    expectedSha256: item.expectedSha256?.S,
    expectedSize: item.expectedSize?.N === undefined ? NaN : Number(item.expectedSize.N),
    expiresAt: item.expiresAt?.S,
    finalKey: item.finalKey?.S,
    id: item.id?.S,
    issuedAt: item.issuedAt?.S,
    dlpCanonicalReceipt: item.dlpReceipt?.M?.canonicalReceipt?.S,
    dlpPolicyVersion: item.dlpReceipt?.M?.policyVersion?.S,
    dlpReceiptDigest: item.dlpReceipt?.M?.receiptDigest?.S,
    dlpScannedAt: item.dlpReceipt?.M?.scannedAt?.S,
    dlpScannerRequestId: item.dlpReceipt?.M?.scannerRequestId?.S,
    dlpSignature: item.dlpReceipt?.M?.signature?.S,
    dlpSigningAlgorithm: item.dlpReceipt?.M?.signingAlgorithm?.S,
    dlpSigningKeyArn: item.dlpReceipt?.M?.signingKeyArn?.S,
    nonceDigest: item.nonceDigest?.S,
    promotionReceipt: {
      byteSize: item.promotionReceipt?.M?.byteSize?.N === undefined
        ? NaN
        : Number(item.promotionReceipt.M.byteSize.N),
      contentType: item.promotionReceipt?.M?.contentType?.S,
      copyAttemptId: item.promotionReceipt?.M?.copyAttemptId?.S,
      copyFence: item.promotionReceipt?.M?.copyFence?.N === undefined
        ? NaN
        : Number(item.promotionReceipt.M.copyFence.N),
      databaseEvidenceRevision: item.promotionReceipt?.M?.databaseEvidenceRevision?.N === undefined
        ? NaN
        : Number(item.promotionReceipt.M.databaseEvidenceRevision.N),
      databaseUploadRevision: item.promotionReceipt?.M?.databaseUploadRevision?.N === undefined
        ? NaN
        : Number(item.promotionReceipt.M.databaseUploadRevision.N),
      databaseReceiptId: item.promotionReceipt?.M?.databaseReceiptId?.S,
      databaseIdempotencyDigest: item.promotionReceipt?.M?.databaseIdempotencyDigest?.S,
      finalKey: item.promotionReceipt?.M?.finalKey?.S,
      finalVersionId: item.promotionReceipt?.M?.finalVersionId?.S,
      kmsKeyArn: item.promotionReceipt?.M?.kmsKeyArn?.S,
      objectLockMode: item.promotionReceipt?.M?.objectLockMode?.S,
      promotionAttemptId: item.promotionReceipt?.M?.promotionAttemptId?.S,
      promotionFence: item.promotionReceipt?.M?.promotionFence?.N === undefined
        ? NaN
        : Number(item.promotionReceipt.M.promotionFence.N),
      promotedAt: item.promotionReceipt?.M?.promotedAt?.S,
      providerRequestId: item.promotionReceipt?.M?.providerRequestId?.S,
      retainUntil: item.promotionReceipt?.M?.retainUntil?.S,
      sha256: item.promotionReceipt?.M?.sha256?.S,
      sourceKey: item.promotionReceipt?.M?.sourceKey?.S,
      sourceVersionId: item.promotionReceipt?.M?.sourceVersionId?.S,
      tenantId: item.promotionReceipt?.M?.tenantId?.S,
      uploadedAt: item.promotionReceipt?.M?.uploadedAt?.S,
    },
    quarantineKey: item.quarantineKey?.S,
    quarantineBucket: item.quarantineBucket?.S,
    quarantineKmsKeyArn: item.quarantineKmsKeyArn?.S,
    promotionAttemptId: item.promotionAttemptId?.S,
    promotionFence: item.promotionFence?.N === undefined ? undefined : Number(item.promotionFence.N),
    promotionLeaseExpiresAt: item.promotionLeaseExpiresAt?.S,
    promotionLeaseId: item.promotionLeaseId?.S,
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
    `^tenants/${config.tenantId}/controls/${escapeRegex(expectedControlId)}/evidence/(evd_[a-f0-9]{32})\\.${escapeRegex(extension ?? "invalid")}$`,
  );
  const finalMatch = String(intent.finalKey ?? "").match(expectedFinalPattern);
  const expectedRevision = { issued: 0, quarantined: 1, validated: 2, promoted: 3 }[intent.status];
  const promotedReceiptValid = intent.status !== "promoted" || (
    intent.promotionReceipt.byteSize === intent.expectedSize &&
    intent.promotionReceipt.contentType === intent.contentType &&
    /^pat_[a-f0-9]{32}$/.test(intent.promotionReceipt.copyAttemptId ?? "") &&
    Number.isSafeInteger(intent.promotionReceipt.copyFence) &&
    intent.promotionReceipt.copyFence >= 1 &&
    intent.promotionReceipt.databaseEvidenceRevision === intent.databaseEvidenceRevision + 1 &&
    intent.promotionReceipt.databaseUploadRevision === intent.databaseUploadRevision + 1 &&
    /^rcp_[a-f0-9]{32}$/.test(intent.promotionReceipt.databaseReceiptId ?? "") &&
    /^[a-f0-9]{64}$/.test(intent.promotionReceipt.databaseIdempotencyDigest ?? "") &&
    intent.promotionReceipt.finalKey === intent.finalKey &&
    validVersionId(intent.promotionReceipt.finalVersionId) &&
    intent.promotionReceipt.kmsKeyArn === config.evidenceKeyArn &&
    intent.promotionReceipt.objectLockMode === config.retentionMode &&
    /^pat_[a-f0-9]{32}$/.test(intent.promotionReceipt.promotionAttemptId ?? "") &&
    Number.isSafeInteger(intent.promotionReceipt.promotionFence) &&
    intent.promotionReceipt.promotionFence >= 1 &&
    validInstant(intent.promotionReceipt.promotedAt) &&
    validProviderRequestId(intent.promotionReceipt.providerRequestId) &&
    validInstant(intent.promotionReceipt.retainUntil) &&
    Date.parse(intent.promotionReceipt.retainUntil) >= Date.parse(intent.requiredRetentionUntil) &&
    intent.promotionReceipt.sha256 === intent.expectedSha256 &&
    intent.promotionReceipt.sourceKey === intent.quarantineKey &&
    intent.promotionReceipt.sourceVersionId === intent.sourceVersionId &&
    intent.promotionReceipt.tenantId === config.tenantId &&
    validInstant(intent.promotionReceipt.uploadedAt) &&
    Date.parse(intent.promotionReceipt.promotedAt) >= Date.parse(intent.promotionReceipt.uploadedAt)
  );
  const promotionCoordinationValid = intent.status === "issued"
    ? intent.promotionFence === undefined && intent.promotionAttemptId === undefined &&
      intent.promotionLeaseId === undefined && intent.promotionLeaseExpiresAt === undefined
    : Number.isSafeInteger(intent.promotionFence) && intent.promotionFence >= 1 &&
      /^pat_[a-f0-9]{32}$/.test(intent.promotionAttemptId ?? "") &&
      (intent.status === "promoted"
        ? intent.promotionLeaseId === undefined && intent.promotionLeaseExpiresAt === undefined
        : /^[a-f0-9]{64}$/.test(intent.promotionLeaseId ?? "") && validInstant(intent.promotionLeaseExpiresAt));
  if (
    item.kind?.S !== "UploadLifecycle" ||
    intent.schemaVersion !== 1 ||
    intent.id !== expectedIntentId ||
    intent.tenantId !== config.tenantId ||
    intent.controlId !== expectedControlId ||
    intent.quarantineBucket !== config.ingestBucket ||
    intent.quarantineKmsKeyArn !== config.evidenceKeyArn ||
    intent.quarantineKey !== expectedKey ||
    !/^usr_[a-f0-9]{32}$/.test(item.requestedBy?.S ?? "") ||
    !/^evd_[a-f0-9]{32}$/.test(intent.resourceId ?? "") ||
    !/^[a-f0-9]{64}$/.test(intent.expectedSha256 ?? "") ||
    !Number.isSafeInteger(intent.expectedSize) ||
    intent.databaseEvidenceRevision !== 0 ||
    intent.databaseUploadRevision !== 0 ||
    intent.expectedSize < 1 ||
    intent.expectedSize > config.maxObjectBytes ||
    !extension ||
    !/^[a-f0-9]{64}$/.test(intent.nonceDigest ?? "") ||
    !finalMatch ||
    finalMatch[1] !== intent.resourceId ||
    !Number.isSafeInteger(intent.revision) ||
    intent.revision !== expectedRevision ||
    !promotedReceiptValid ||
    !promotionCoordinationValid ||
    !validInstant(intent.issuedAt) ||
    !validInstant(intent.expiresAt) ||
    !validInstant(intent.requiredRetentionUntil) ||
    Date.parse(intent.issuedAt) > Date.now() ||
    Date.parse(intent.expiresAt) - Date.parse(intent.issuedAt) > 10 * 60_000 ||
    Date.parse(intent.expiresAt) + scanReconciliationGraceMilliseconds <= Date.now() ||
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
    item?.databaseReceiptId?.S !== intent.promotionReceipt.databaseReceiptId ||
    item?.databaseIdempotencyDigest?.S !== intent.promotionReceipt.databaseIdempotencyDigest ||
    item?.copyAttemptId?.S !== intent.promotionReceipt.copyAttemptId ||
    item?.copyFence?.N !== String(intent.promotionReceipt.copyFence) ||
    item?.promotionAttemptId?.S !== intent.promotionReceipt.promotionAttemptId ||
    item?.promotionFence?.N !== String(intent.promotionReceipt.promotionFence) ||
    item?.sha256?.S !== intent.expectedSha256 ||
    item?.retainUntil?.S !== intent.promotionReceipt.retainUntil
  ) {
    throw new Error("The completed promotion receipt is absent or inconsistent.");
  }
  const reconciliation = await readCommittedPromotionReceipt(intent, {
    uploadedAt: intent.promotionReceipt.uploadedAt,
    versionId: sourceVersionId,
  });
  if (
    !reconciliation ||
    reconciliation.uploadRevision !== intent.promotionReceipt.databaseUploadRevision ||
    reconciliation.evidenceRevision !== intent.promotionReceipt.databaseEvidenceRevision ||
    reconciliation.receiptId !== intent.promotionReceipt.databaseReceiptId ||
    reconciliation.idempotencyDigest !== intent.promotionReceipt.databaseIdempotencyDigest
  ) {
    throw new Error("The completed promotion database revisions are inconsistent.");
  }
  const destination = await findCompletedCopy(
    intent.finalKey,
    sourceVersionId,
    intent.expectedSha256,
    intent.promotionReceipt.finalVersionId,
    new Date(intent.promotionReceipt.retainUntil),
    intent.promotionReceipt.uploadedAt,
    dlpFromFacts(reconciliation.facts),
    intent.promotionReceipt.copyAttemptId,
    intent.promotionReceipt.copyFence,
  );
  if (destination?.versionId !== intent.promotionReceipt.finalVersionId) {
    throw new Error("The recorded immutable evidence version failed revalidation.");
  }
  await verifyAuthoritativeRecoveryReceipt(receiptHash, reconciliation);
}

async function verifyAuthoritativeRecoveryReceipt(receiptHash, databaseReceipt) {
  const response = await dynamo.send(new GetItemCommand({
    ConsistentRead: true,
    Key: {
      PK: { S: `RECOVERY#TENANT#${config.tenantId}` },
      SK: { S: `PROMOTION#${receiptHash}` },
    },
    TableName: config.controlTable,
  }));
  if (!response.Item) throw new Error("The authoritative recovery receipt is missing.");
  const parsed = parseAuthoritativePromotionReceiptItem(response.Item, {
    receiptHash,
    signingKeyArn: config.auditSigningKeyArn,
    tenantId: config.tenantId,
    verificationTime: new Date().toISOString(),
  });
  await verifyCommittedPromotionReceipt(parsed.snapshot, (verifyInput) => kms.send(new VerifyCommand(verifyInput)));
  if (
    parsed.snapshot.receiptId !== databaseReceipt.receiptId ||
    parsed.snapshot.idempotencyDigest !== databaseReceipt.idempotencyDigest ||
    parsed.snapshot.receiptDigest !== databaseReceipt.receiptDigest ||
    stableJson(parsed.snapshot.facts) !== stableJson(databaseReceipt.facts)
  ) {
    throw new Error("The authoritative recovery receipt conflicts with the signed database row.");
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
  if (!metadataMatchesIntent(head.Metadata, intent)) throw new Error("Evidence metadata does not match the signed upload intent.");
  if (head.ServerSideEncryption !== "aws:kms" || head.SSEKMSKeyId !== intent.quarantineKmsKeyArn) {
    throw new Error("Evidence encryption does not match the signed upload intent.");
  }
  if (!(head.LastModified instanceof Date) || !Number.isFinite(head.LastModified.getTime())) {
    throw new Error("S3 did not return the exact upload modification time.");
  }
  const uploadedAt = head.LastModified.getTime();
  if (
    uploadedAt < Date.parse(intent.issuedAt) - 60_000 ||
    uploadedAt > Date.parse(intent.expiresAt) + 1_000 ||
    uploadedAt > Date.now() + 60_000
  ) {
    throw new Error("The exact S3 version was not uploaded inside the signed intent window.");
  }
  return head.LastModified.toISOString();
}

function metadataMatchesIntent(metadata, intent) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return false;
  const expected = {
    "control-id": intent.controlId,
    "evidence-id": intent.resourceId,
    "expected-sha256": intent.expectedSha256,
    "tenant-id": config.tenantId,
    "upload-intent-id": intent.id,
    "upload-nonce-digest": intent.nonceDigest,
  };
  const keys = Object.keys(metadata).sort();
  const expectedKeys = Object.keys(expected).sort();
  return keys.length === expectedKeys.length && keys.every((key, index) => key === expectedKeys[index] && metadata[key] === expected[key]);
}

async function claimIssuedIntent(input) {
  await dynamo.send(
    new TransactWriteItemsCommand({
      ClientRequestToken: token(`${input.leaseId}\0${input.nowIso}`, "claim"),
      TransactItems: [
        {
          Update: {
            ConditionExpression:
              "#status = :issued AND #revision = :zero AND attribute_not_exists(promotionFence) AND attribute_not_exists(promotionAttemptId) AND quarantineKey = :sourceKey AND finalKey = :finalKey AND expectedSha256 = :sha256 AND expectedSize = :size AND contentType = :contentType",
            ExpressionAttributeNames: { "#revision": "revision", "#status": "status" },
            ExpressionAttributeValues: {
              ":contentType": { S: input.intent.contentType },
              ":consumedAt": { S: input.nowIso },
              ":leaseId": { S: input.leaseId },
              ":attemptId": { S: input.attemptId },
              ":expires": { S: input.leaseExpiresAt },
              ":fence": { N: String(input.fence) },
              ":finalKey": { S: input.intent.finalKey },
              ":issued": { S: "issued" },
              ":one": { N: "1" },
              ":receipt": {
                M: {
                  byteSize: { N: String(input.intent.expectedSize) },
                  contentType: { S: input.intent.contentType },
                  key: { S: input.intent.quarantineKey },
                  providerRequestId: { S: input.eventId },
                  receivedAt: { S: input.uploadedAt },
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
              "SET #status = :status, #revision = :one, consumedAt = :consumedAt, quarantineReceipt = :receipt, promotionLeaseId = :leaseId, promotionLeaseExpiresAt = :expires, promotionAttemptId = :attemptId, promotionFence = :fence",
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
              promotionAttemptId: { S: input.attemptId },
              promotionFence: { N: String(input.fence) },
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

async function takeOverLease(input) {
  await dynamo.send(
    new TransactWriteItemsCommand({
      ClientRequestToken: token(`${input.leaseId}\0${input.attemptId}\0${input.nowIso}`, "takeover"),
      TransactItems: [
        {
          Update: {
            ConditionExpression:
              "#status = :status AND #revision = :revision AND promotionFence = :currentFence AND promotionAttemptId = :currentAttemptId AND quarantineReceipt.versionId = :versionId AND promotionLeaseExpiresAt <= :now",
            ExpressionAttributeNames: { "#revision": "revision", "#status": "status" },
            ExpressionAttributeValues: {
              ":attemptId": { S: input.attemptId },
              ":currentAttemptId": { S: input.intent.promotionAttemptId },
              ":currentFence": { N: String(input.intent.promotionFence) },
              ":expires": { S: input.leaseExpiresAt },
              ":fence": { N: String(input.fence) },
              ":leaseId": { S: input.leaseId },
              ":now": { S: input.nowIso },
              ":revision": { N: String(input.intent.revision) },
              ":status": { S: input.intent.status },
              ":versionId": { S: input.intent.sourceVersionId },
            },
            Key: input.intentKey,
            TableName: config.controlTable,
            UpdateExpression: "SET promotionLeaseId = :leaseId, promotionLeaseExpiresAt = :expires, promotionAttemptId = :attemptId, promotionFence = :fence",
          },
        },
        {
          Update: {
            ConditionExpression:
              "#status = :copying AND tenantId = :tenantId AND intentId = :intentId AND receiptHash = :receiptHash AND promotionFence = :currentFence AND promotionAttemptId = :currentAttemptId",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: {
              ":attemptId": { S: input.attemptId },
              ":copying": { S: "COPYING" },
              ":currentAttemptId": { S: input.intent.promotionAttemptId },
              ":currentFence": { N: String(input.intent.promotionFence) },
              ":fence": { N: String(input.fence) },
              ":intentId": { S: input.intent.id },
              ":receiptHash": { S: input.receiptHash },
              ":tenantId": { S: config.tenantId },
            },
            Key: input.receiptKey,
            TableName: config.controlTable,
            UpdateExpression: "SET promotionAttemptId = :attemptId, promotionFence = :fence",
          },
        },
      ],
    }),
  );
}

async function markValidated(intentKey, intent, lease, leaseId, head, nowIso, versionId) {
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
              "#status = :quarantined AND #revision = :one AND promotionLeaseId = :leaseId AND promotionAttemptId = :attemptId AND promotionFence = :fence AND promotionLeaseExpiresAt > :now AND quarantineReceipt.versionId = :versionId",
            ExpressionAttributeNames: { "#revision": "revision", "#status": "status" },
            ExpressionAttributeValues: {
              ":attemptId": { S: lease.attemptId },
              ":fence": { N: String(lease.fence) },
              ":leaseId": { S: leaseId },
              ":now": { S: nowIso },
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

async function prepareCopyAttempt(input) {
  const permittedAt = new Date().toISOString();
  const leaseExpiresAt = new Date(Date.parse(permittedAt) + promotionLeaseDurationMilliseconds).toISOString();
  const attemptItem = buildPromotionCopyAttemptItem({
    attemptId: input.lease.attemptId,
    destinationBucket: config.evidenceBucket,
    destinationKey: input.intent.finalKey,
    expectedSha256: input.intent.expectedSha256,
    fence: input.lease.fence,
    intentId: input.intent.id,
    leaseExpiresAt,
    leaseId: input.leaseId,
    permittedAt,
    receiptHash: input.receiptHash,
    sourceBucket: config.ingestBucket,
    sourceKey: input.intent.quarantineKey,
    sourceVersionId: input.versionId,
    tenantId: config.tenantId,
  });
  await dynamo.send(new TransactWriteItemsCommand({
    ClientRequestToken: token(`${input.lease.attemptId}\0${permittedAt}`, "permit-copy"),
    TransactItems: [
      {
        Update: {
          ConditionExpression:
            "#status = :validated AND #revision = :two AND promotionLeaseId = :leaseId AND promotionAttemptId = :attemptId AND promotionFence = :fence AND promotionLeaseExpiresAt > :now AND quarantineReceipt.versionId = :versionId",
          ExpressionAttributeNames: { "#revision": "revision", "#status": "status" },
          ExpressionAttributeValues: {
            ":attemptId": { S: input.lease.attemptId },
            ":expires": { S: leaseExpiresAt },
            ":fence": { N: String(input.lease.fence) },
            ":leaseId": { S: input.leaseId },
            ":now": { S: permittedAt },
            ":two": { N: "2" },
            ":validated": { S: "validated" },
            ":versionId": { S: input.versionId },
          },
          Key: input.intentKey,
          TableName: config.controlTable,
          UpdateExpression: "SET promotionLeaseExpiresAt = :expires",
        },
      },
      {
        Update: {
          ConditionExpression:
            "#status = :copying AND tenantId = :tenantId AND intentId = :intentId AND receiptHash = :receiptHash AND promotionAttemptId = :attemptId AND promotionFence = :fence",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":attemptId": { S: input.lease.attemptId },
            ":copying": { S: "COPYING" },
            ":fence": { N: String(input.lease.fence) },
            ":intentId": { S: input.intent.id },
            ":permittedAt": { S: permittedAt },
            ":receiptHash": { S: input.receiptHash },
            ":tenantId": { S: config.tenantId },
          },
          Key: input.receiptKey,
          TableName: config.controlTable,
          UpdateExpression: "SET copyPermittedAt = :permittedAt",
        },
      },
      {
        Put: {
          ConditionExpression: "attribute_not_exists(PK) AND attribute_not_exists(SK)",
          Item: attemptItem,
          TableName: config.controlTable,
        },
      },
    ],
  }));
}

async function renewActiveLease(intentKey, intent, lease, leaseId, nowIso) {
  const leaseExpiresAt = new Date(Date.parse(nowIso) + promotionLeaseDurationMilliseconds).toISOString();
  await dynamo.send(new TransactWriteItemsCommand({
    ClientRequestToken: token(`${lease.attemptId}\0${nowIso}`, "assert-lease"),
    TransactItems: [{
      Update: {
        ConditionExpression:
          "#status = :validated AND #revision = :two AND promotionLeaseId = :leaseId AND promotionAttemptId = :attemptId AND promotionFence = :fence AND promotionLeaseExpiresAt > :now AND quarantineReceipt.versionId = :versionId",
        ExpressionAttributeNames: { "#revision": "revision", "#status": "status" },
        ExpressionAttributeValues: {
          ":attemptId": { S: lease.attemptId },
          ":expires": { S: leaseExpiresAt },
          ":fence": { N: String(lease.fence) },
          ":leaseId": { S: leaseId },
          ":now": { S: nowIso },
          ":two": { N: "2" },
          ":validated": { S: "validated" },
          ":versionId": { S: intent.sourceVersionId },
        },
        Key: intentKey,
        TableName: config.controlTable,
        UpdateExpression: "SET promotionLeaseExpiresAt = :expires",
      },
    }],
  }));
  return leaseExpiresAt;
}

async function recordCopyOutcome(input) {
  if (!validVersionId(input.destinationVersionId)) throw new Error("S3 did not return an exact destination version.");
  const checksum = /^[A-Za-z0-9+/]{43}=$/.test(input.observedChecksumSha256)
    ? input.observedChecksumSha256
    : "UNVERIFIED";
  try {
    await dynamo.send(new TransactWriteItemsCommand({
      ClientRequestToken: token(`${input.attemptId}\0${input.destinationVersionId}`, "record-copy"),
      TransactItems: [{
        Update: {
          ConditionExpression:
            "#status = :permitted AND attemptId = :attemptId AND fence = :fence AND receiptHash = :receiptHash AND attribute_not_exists(destinationVersionId)",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":attemptId": { S: input.attemptId },
            ":checksum": { S: checksum },
            ":completedAt": { S: input.completedAt },
            ":copied": { S: "COPIED" },
            ":destinationVersionId": { S: input.destinationVersionId },
            ":fence": { N: String(input.fence) },
            ":providerRequestIdSha256": { S: digestHex(input.providerRequestId) },
            ":receiptHash": { S: input.receiptHash },
            ":permitted": { S: "COPY_PERMITTED" },
          },
          Key: {
            PK: { S: `TENANT#${config.tenantId}` },
            SK: { S: promotionCopyAttemptSortKey(input.receiptHash, input.fence) },
          },
          TableName: config.controlTable,
          UpdateExpression:
            "SET #status = :copied, completedAt = :completedAt, destinationVersionId = :destinationVersionId, observedChecksumSha256 = :checksum, providerRequestIdSha256 = :providerRequestIdSha256",
        },
      }],
    }));
  } catch (error) {
    if (!isConditionalWriteConflict(error)) throw error;
  }
  await readTrackedCopyAttempt(input.receiptHash, input.fence, input.attemptId, input.destinationVersionId);
}

async function ensureTrackedCopyOutcome(destination, receiptHash) {
  const existing = await readTrackedCopyAttempt(
    receiptHash,
    destination.promotionFence,
    destination.promotionAttemptId,
    destination.versionId,
    true,
    destination,
  );
  if (existing.status === "COPY_PERMITTED") {
    await recordCopyOutcome({
      attemptId: destination.promotionAttemptId,
      completedAt: new Date().toISOString(),
      destinationVersionId: destination.versionId,
      fence: destination.promotionFence,
      observedChecksumSha256: Buffer.from(destination.checksumSha256, "hex").toString("base64"),
      providerRequestId: String(destination.providerRequestId ?? ""),
      receiptHash,
    });
  }
}

async function markCopyAttemptAdopted(input) {
  try {
    await dynamo.send(new TransactWriteItemsCommand({
      ClientRequestToken: token(`${input.attemptId}\0${input.adoptedVersionId}`, "adopt-copy"),
      TransactItems: [{
        Update: {
          ConditionExpression:
            "#status = :permitted AND attemptId = :attemptId AND fence = :fence AND receiptHash = :receiptHash AND attribute_not_exists(destinationVersionId)",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":adopted": { S: "ADOPTED" },
            ":adoptedAttemptId": { S: input.adoptedAttemptId },
            ":adoptedFence": { N: String(input.adoptedFence) },
            ":adoptedVersionId": { S: input.adoptedVersionId },
            ":attemptId": { S: input.attemptId },
            ":fence": { N: String(input.fence) },
            ":receiptHash": { S: input.receiptHash },
            ":permitted": { S: "COPY_PERMITTED" },
            ":resolvedAt": { S: new Date().toISOString() },
          },
          Key: {
            PK: { S: `TENANT#${config.tenantId}` },
            SK: { S: promotionCopyAttemptSortKey(input.receiptHash, input.fence) },
          },
          TableName: config.controlTable,
          UpdateExpression:
            "SET #status = :adopted, resolvedAt = :resolvedAt, adoptedAttemptId = :adoptedAttemptId, adoptedFence = :adoptedFence, adoptedVersionId = :adoptedVersionId",
        },
      }],
    }));
  } catch (error) {
    if (!isConditionalWriteConflict(error)) throw error;
  }
}

async function resolveOrphanedCopyAttempts(destination, receiptHash) {
  const response = await dynamo.send(new QueryCommand({
    ConsistentRead: true,
    ExpressionAttributeValues: {
      ":pk": { S: `TENANT#${config.tenantId}` },
      ":prefix": { S: `PROMOTION_ATTEMPT#${receiptHash}#` },
    },
    KeyConditionExpression: "PK = :pk AND begins_with(SK, :prefix)",
    Limit: 100,
    TableName: config.controlTable,
  }));
  if (response.LastEvaluatedKey) {
    throw new Error("Promotion orphan recovery exceeded its bounded attempt limit.");
  }
  for (const item of response.Items ?? []) {
    const fence = Number(item?.fence?.N);
    const attemptId = item?.attemptId?.S;
    if (
      item?.kind?.S !== "EvidencePromotionCopyAttempt" ||
      item?.tenantId?.S !== config.tenantId ||
      item?.receiptHash?.S !== receiptHash ||
      !Number.isSafeInteger(fence) || fence < 1 ||
      !/^pat_[a-f0-9]{32}$/.test(String(attemptId ?? ""))
    ) {
      throw new Error("Promotion orphan recovery found a malformed attempt.");
    }
    if (item.status?.S === "COPY_PERMITTED" &&
        (fence !== destination.promotionFence || attemptId !== destination.promotionAttemptId)) {
      await markCopyAttemptAdopted({
        adoptedAttemptId: destination.promotionAttemptId,
        adoptedFence: destination.promotionFence,
        adoptedVersionId: destination.versionId,
        attemptId,
        fence,
        receiptHash,
      });
    }
  }
}

async function readTrackedCopyAttempt(
  receiptHash,
  fence,
  attemptId,
  destinationVersionId,
  allowPermitted = false,
  expectedDestination,
) {
  const response = await dynamo.send(new GetItemCommand({
    ConsistentRead: true,
    Key: {
      PK: { S: `TENANT#${config.tenantId}` },
      SK: { S: promotionCopyAttemptSortKey(receiptHash, fence) },
    },
    TableName: config.controlTable,
  }));
  const item = response.Item;
  const status = item?.status?.S;
  const versionMatches = item?.destinationVersionId?.S === destinationVersionId;
  if (
    item?.kind?.S !== "EvidencePromotionCopyAttempt" ||
    item?.tenantId?.S !== config.tenantId ||
    item?.receiptHash?.S !== receiptHash ||
    item?.attemptId?.S !== attemptId ||
    item?.fence?.N !== String(fence) ||
    (expectedDestination !== undefined && (
      item?.destinationBucket?.S !== config.evidenceBucket ||
      item?.destinationKey?.S !== expectedDestination.destinationKey ||
      item?.expectedSha256?.S !== expectedDestination.checksumSha256 ||
      item?.sourceBucket?.S !== config.ingestBucket ||
      item?.sourceVersionId?.S !== expectedDestination.sourceVersionId
    )) ||
    !new Set(["COPY_PERMITTED", "COPIED", "RECONCILED"]).has(status) ||
    (status === "COPY_PERMITTED" ? (!allowPermitted || item?.destinationVersionId !== undefined) : !versionMatches)
  ) {
    throw new Error("The immutable destination does not have a durable promotion attempt.");
  }
  return Object.freeze({ status });
}

async function findCompletedCopy(
  destinationKey,
  sourceVersionId,
  expectedSha256,
  exactVersionId,
  expectedRetainUntil,
  expectedUploadedAt,
  expectedDlp,
  expectedPromotionAttemptId,
  expectedPromotionFence,
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
      destination.Metadata?.["uploaded-at"] !== expectedUploadedAt ||
      destination.Metadata?.["dlp-policy"] !== expectedDlp.policyVersion ||
      destination.Metadata?.["dlp-receipt-sha256"] !== expectedDlp.receiptDigest ||
      destination.Metadata?.["dlp-scanned-at"] !== expectedDlp.scannedAt ||
      destination.Metadata?.["dlp-scanner-request-id"] !== expectedDlp.scannerRequestId ||
      (expectedPromotionAttemptId !== undefined &&
        destination.Metadata?.["promotion-attempt-id"] !== expectedPromotionAttemptId) ||
      (expectedPromotionFence !== undefined &&
        destination.Metadata?.["promotion-fence"] !== String(expectedPromotionFence)) ||
      checksum !== expectedSha256 ||
      !destination.VersionId ||
      destination.ServerSideEncryption !== "aws:kms" ||
      destination.SSEKMSKeyId !== config.evidenceKeyArn ||
      destination.ObjectLockMode !== config.retentionMode ||
      !destination.ObjectLockRetainUntilDate ||
      destination.ObjectLockRetainUntilDate.getTime() < expectedRetainUntil.getTime()
    ) return undefined;
    const promotionAttemptId = destination.Metadata?.["promotion-attempt-id"];
    const promotionFence = Number(destination.Metadata?.["promotion-fence"]);
    if (!/^pat_[a-f0-9]{32}$/.test(String(promotionAttemptId ?? "")) ||
        !Number.isSafeInteger(promotionFence) || promotionFence < 1) return undefined;
    return {
      checksumSha256: checksum,
      destinationKey,
      promotionAttemptId,
      promotionFence,
      providerRequestId: destination.$metadata?.requestId,
      retainUntil: destination.ObjectLockRetainUntilDate,
      sourceVersionId,
      versionId: destination.VersionId,
    };
  } catch (error) {
    if (error?.name === "NotFound" || error?.$metadata?.httpStatusCode === 404) return undefined;
    throw error;
  }
}

function buildPromotionFacts(input) {
  return Object.freeze({
    schemaVersion: 1,
    tenantId: config.tenantId,
    uploadIntentId: input.intent.id,
    evidenceId: input.intent.resourceId,
    controlId: input.intent.controlId,
    quarantineBucket: config.ingestBucket,
    quarantineKey: input.intent.quarantineKey,
    quarantineVersionId: input.versionId,
    evidenceBucket: config.evidenceBucket,
    evidenceKey: input.intent.finalKey,
    evidenceVersionId: input.destinationVersionId,
    sha256: input.intent.expectedSha256,
    byteSize: input.intent.expectedSize,
    contentType: input.intent.contentType,
    copyAttemptId: input.copyAttemptId,
    copyFence: input.copyFence,
    kmsKeyArn: config.evidenceKeyArn,
    objectLockMode: config.retentionMode,
    promotionAttemptId: input.promotionAttemptId,
    promotionFence: input.promotionFence,
    retainUntil: input.retainUntil.toISOString(),
    uploadedAt: input.uploadedAt,
    promotedAt: input.nowIso,
    providerRequestId: input.providerRequestId,
    dlpPolicyVersion: input.dlp.policyVersion,
    dlpReceiptSha256: input.dlp.receiptDigest,
    dlpScannedAt: input.dlp.scannedAt,
    dlpScannerRequestId: input.dlp.scannerRequestId,
  });
}

function dlpFromFacts(facts) {
  const result = {
    policyVersion: facts?.dlpPolicyVersion,
    receiptDigest: facts?.dlpReceiptSha256,
    scannedAt: facts?.dlpScannedAt,
    scannerRequestId: facts?.dlpScannerRequestId,
  };
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(String(result.policyVersion ?? "")) ||
      !/^[a-f0-9]{64}$/.test(String(result.receiptDigest ?? "")) || !validInstant(result.scannedAt) ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(String(result.scannerRequestId ?? ""))) {
    throw new Error("The signed promotion receipt lacks valid exact-version DLP facts.");
  }
  return Object.freeze(result);
}

let dlpTokenCache;

async function ensureExactVersionDlp(intentKey, intent, source) {
  if (config.dlpMode !== "ENFORCED") {
    throw new Error("Exact-version server DLP is not configured; immutable promotion is disabled.");
  }
  const request = buildExactVersionDlpRequest({ ...source, policyVersion: config.dlpPolicyVersion });
  if (!validInstant(source.uploadedAt)) throw new Error("The DLP source upload time is invalid.");
  if (intent.dlpCanonicalReceipt) {
    const persisted = await parsePersistedDlp(intent, request);
    assertDlpAfterUpload(persisted, source.uploadedAt);
    return persisted;
  }
  const scanned = await callExactVersionDlp(request);
  assertDlpAfterUpload(scanned, source.uploadedAt);
  const signed = await signDlpReceipt(scanned);
  const receipt = {
    M: {
      canonicalReceipt: { S: scanned.canonicalReceipt },
      policyVersion: { S: scanned.policyVersion },
      receiptDigest: { S: scanned.receiptDigest },
      scannedAt: { S: scanned.scannedAt },
      scannerRequestId: { S: scanned.scannerRequestId },
      signature: { S: signed.signature },
      signingAlgorithm: { S: signed.signingAlgorithm },
      signingKeyArn: { S: signed.signingKeyArn },
    },
  };
  try {
    await dynamo.send(new TransactWriteItemsCommand({
      ClientRequestToken: token(`${intent.id}\0${scanned.receiptDigest}`, "dlp"),
      TransactItems: [{
        Update: {
          ConditionExpression: "attribute_not_exists(dlpReceipt) AND #status IN (:issued, :quarantined, :validated) AND quarantineKey = :key AND expectedSha256 = :sha256 AND expectedSize = :size AND contentType = :contentType",
          ExpressionAttributeNames: { "#status": "status" },
          ExpressionAttributeValues: {
            ":contentType": { S: intent.contentType },
            ":issued": { S: "issued" },
            ":key": { S: intent.quarantineKey },
            ":quarantined": { S: "quarantined" },
            ":receipt": receipt,
            ":sha256": { S: intent.expectedSha256 },
            ":size": { N: String(intent.expectedSize) },
            ":validated": { S: "validated" },
          },
          Key: intentKey,
          TableName: config.controlTable,
          UpdateExpression: "SET dlpReceipt = :receipt",
        },
      }],
    }));
    return scanned;
  } catch (error) {
    if (error?.name !== "TransactionCanceledException") throw error;
    const existing = await dynamo.send(new GetItemCommand({ ConsistentRead: true, Key: intentKey, TableName: config.controlTable }));
    const reparsed = parseIntent(existing.Item, intent.id, intent.controlId, intent.quarantineKey);
    const persisted = await parsePersistedDlp(reparsed, request);
    assertDlpAfterUpload(persisted, source.uploadedAt);
    return persisted;
  }
}

function assertDlpAfterUpload(receipt, uploadedAt) {
  if (Date.parse(receipt.scannedAt) < Date.parse(uploadedAt)) {
    throw new Error("The exact-version DLP receipt predates the source upload.");
  }
}

async function parsePersistedDlp(intent, request) {
  if (typeof intent.dlpCanonicalReceipt !== "string" || intent.dlpCanonicalReceipt.length > 16_384) {
    throw new Error("The durable DLP receipt is malformed.");
  }
  let payload;
  try { payload = JSON.parse(intent.dlpCanonicalReceipt); } catch { throw new Error("The durable DLP receipt is malformed."); }
  // A receipt persisted for this exact immutable quarantine version is safe to
  // reuse after a Lambda retry. Keep rejecting future timestamps, but do not
  // impose the network-response freshness window on a durable receipt.
  const parsed = parseExactVersionDlpResponse(payload, request, new Date(), {
    maximumAgeMilliseconds: null,
  });
  if (parsed.canonicalReceipt !== intent.dlpCanonicalReceipt || parsed.receiptDigest !== intent.dlpReceiptDigest ||
      parsed.policyVersion !== intent.dlpPolicyVersion || parsed.scannedAt !== intent.dlpScannedAt ||
      parsed.scannerRequestId !== intent.dlpScannerRequestId) {
    throw new Error("The durable DLP receipt failed canonical verification.");
  }
  const signature = canonicalRsa3072Signature(intent.dlpSignature, "DLP receipt signature");
  if (intent.dlpSigningKeyArn !== config.auditSigningKeyArn || intent.dlpSigningAlgorithm !== dlpSigningAlgorithm) {
    throw new Error("The durable DLP receipt has an invalid signing identity.");
  }
  const verification = await kms.send(new VerifyCommand({
    KeyId: config.auditSigningKeyArn,
    Message: Buffer.from(parsed.receiptDigest, "hex"),
    MessageType: "DIGEST",
    Signature: signature,
    SigningAlgorithm: dlpSigningAlgorithm,
  }));
  if (verification?.KeyId !== config.auditSigningKeyArn ||
      verification?.SigningAlgorithm !== dlpSigningAlgorithm || verification?.SignatureValid !== true) {
    throw new Error("The durable DLP receipt signature did not verify.");
  }
  return parsed;
}

async function signDlpReceipt(scanned) {
  const result = await kms.send(new SignCommand({
    KeyId: config.auditSigningKeyArn,
    Message: Buffer.from(scanned.receiptDigest, "hex"),
    MessageType: "DIGEST",
    SigningAlgorithm: dlpSigningAlgorithm,
  }));
  if (result?.KeyId !== config.auditSigningKeyArn || result?.SigningAlgorithm !== dlpSigningAlgorithm ||
      !(result?.Signature instanceof Uint8Array) || result.Signature.byteLength !== 384) {
    throw new Error("KMS did not return a valid DLP receipt signature.");
  }
  return Object.freeze({
    signature: Buffer.from(result.Signature).toString("base64"),
    signingAlgorithm: dlpSigningAlgorithm,
    signingKeyArn: config.auditSigningKeyArn,
  });
}

async function callExactVersionDlp(request) {
  const tokenValue = await loadDlpToken();
  const response = await fetch(config.dlpScannerEndpoint, {
    body: stableJson(request),
    headers: {
      accept: "application/json",
      authorization: `Bearer ${tokenValue}`,
      "content-type": "application/json",
    },
    method: "POST",
    redirect: "error",
    signal: AbortSignal.timeout(45_000),
  });
  if (!response.ok || response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    throw new Error("The exact-version DLP scanner did not return a successful JSON response.");
  }
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > 65_536) throw new Error("The exact-version DLP response is too large.");
  const bytes = await readBoundedResponseBody(response, 65_536);
  if (bytes.byteLength < 2 || bytes.byteLength > 65_536) throw new Error("The exact-version DLP response is invalid or too large.");
  let payload;
  try { payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new Error("The exact-version DLP response is not valid UTF-8 JSON."); }
  return parseExactVersionDlpResponse(payload, request);
}

async function loadDlpToken() {
  if (dlpTokenCache?.expiresAt > Date.now()) return dlpTokenCache.value;
  const response = await secrets.send(new GetSecretValueCommand({
    SecretId: config.dlpScannerSecretArn,
    VersionStage: "AWSCURRENT",
  }));
  const value = response?.SecretString;
  if (typeof value !== "string" || !/^[A-Za-z0-9._~-]{32,512}$/.test(value) ||
      !response.VersionStages?.includes("AWSCURRENT") || !/^[A-Za-z0-9-]{8,128}$/.test(String(response.VersionId ?? ""))) {
    throw new Error("The DLP scanner token secret is missing or unsafe.");
  }
  dlpTokenCache = Object.freeze({ expiresAt: Date.now() + 5 * 60_000, value });
  return value;
}

async function readBoundedResponseBody(response, maximumBytes) {
  if (!response.body) throw new Error("The exact-version DLP response has no body.");
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error("The exact-version DLP response stream is invalid.");
      total += value.byteLength;
      if (total > maximumBytes) throw new Error("The exact-version DLP response is too large.");
      chunks.push(value);
    }
  } catch (error) {
    await reader.cancel().catch(() => undefined);
    throw error;
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

async function claimPromotionFenceDatabase(intent, lease) {
  const transaction = await rds.send(new BeginTransactionCommand({
    database: config.databaseName,
    resourceArn: config.databaseClusterArn,
    secretArn: config.ingestDatabaseSecretArn,
  }));
  if (!transaction.transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transaction.transactionId)) {
    throw new Error("RDS Data API did not establish a promotion fence transaction.");
  }
  const transactionId = transaction.transactionId;
  try {
    await executePromotionStatement(transactionId, {
      sql: "SELECT pg_catalog.set_config('scopeproof.tenant_id', :tenant_id, true)",
      parameters: [stringParameter("tenant_id", config.tenantId)],
    });
    const response = await executePromotionStatement(transactionId, {
      formatRecordsAs: "JSON",
      sql: [
        "SELECT committed_fence, committed_attempt_id, committed_lease_expires_at",
        "FROM scopeproof.claim_promotion_fence(",
        "  CAST(:upload_intent_id AS scopeproof.resource_identifier), CAST(:promotion_fence AS bigint),",
        "  :promotion_attempt_id, CAST(:lease_expires_at AS timestamptz)",
        ")",
      ].join("\n"),
      parameters: [
        stringParameter("upload_intent_id", intent.id),
        stringParameter("promotion_fence", String(lease.fence)),
        stringParameter("promotion_attempt_id", lease.attemptId),
        stringParameter("lease_expires_at", lease.leaseExpiresAt),
      ],
    });
    let rows;
    try { rows = JSON.parse(response.formattedRecords ?? "[]"); } catch {
      throw new Error("The promotion fence database response is invalid.");
    }
    const committedLeaseExpiry = typeof rows?.[0]?.committed_lease_expires_at === "string"
      ? new Date(rows[0].committed_lease_expires_at)
      : undefined;
    if (
      !Array.isArray(rows) || rows.length !== 1 ||
      rows[0]?.committed_fence !== lease.fence ||
      rows[0]?.committed_attempt_id !== lease.attemptId ||
      !committedLeaseExpiry || !Number.isFinite(committedLeaseExpiry.getTime()) ||
      committedLeaseExpiry.toISOString() !== lease.leaseExpiresAt
    ) {
      throw new Error("The promotion fence database response is invalid.");
    }
    await rds.send(new CommitTransactionCommand({
      resourceArn: config.databaseClusterArn,
      secretArn: config.ingestDatabaseSecretArn,
      transactionId,
    }));
  } catch (error) {
    try {
      await rds.send(new RollbackTransactionCommand({
        resourceArn: config.databaseClusterArn,
        secretArn: config.ingestDatabaseSecretArn,
        transactionId,
      }));
    } catch {
      // Preserve the fence claim failure; an exact retry is idempotent.
    }
    throw error;
  }
}

async function readCommittedPromotionReceipt(intent, input) {
  const transaction = await rds.send(new BeginTransactionCommand({
    database: config.databaseName,
    resourceArn: config.databaseClusterArn,
    secretArn: config.ingestDatabaseSecretArn,
  }));
  if (!transaction.transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transaction.transactionId)) {
    throw new Error("RDS Data API did not establish a promotion receipt lookup transaction.");
  }
  const transactionId = transaction.transactionId;
  try {
    await executePromotionStatement(transactionId, {
      sql: "SELECT pg_catalog.set_config('scopeproof.tenant_id', :tenant_id, true)",
      parameters: [stringParameter("tenant_id", config.tenantId)],
    });
    const response = await executePromotionStatement(transactionId, {
      formatRecordsAs: "JSON",
      sql: [
        "SELECT receipt_id::text, committed_upload_revision, committed_evidence_revision,",
        "       committed_idempotency_digest, committed_promotion_facts, committed_canonical_receipt,",
        "       committed_receipt_sha256, committed_signing_key_arn, committed_signing_algorithm,",
        "       committed_signature, committed_signed_at",
        "FROM scopeproof.read_promoted_evidence_receipt(CAST(:upload_intent_id AS scopeproof.resource_identifier))",
      ].join("\n"),
      parameters: [stringParameter("upload_intent_id", intent.id)],
    });
    const snapshot = parseCommittedPromotionReceipt(response.formattedRecords ?? "[]", {
      allowMissing: true,
      evidenceRevision: intent.databaseEvidenceRevision + 1,
      invariants: {
        byteSize: intent.expectedSize,
        contentType: intent.contentType,
        controlId: intent.controlId,
        evidenceBucket: config.evidenceBucket,
        evidenceId: intent.resourceId,
        evidenceKey: intent.finalKey,
        kmsKeyArn: config.evidenceKeyArn,
        minimumRetainUntil: intent.requiredRetentionUntil,
        objectLockMode: config.retentionMode,
        quarantineBucket: config.ingestBucket,
        quarantineKey: intent.quarantineKey,
        quarantineVersionId: input.versionId,
        sha256: intent.expectedSha256,
        tenantId: config.tenantId,
        uploadIntentId: intent.id,
        uploadedAt: input.uploadedAt,
      },
      signingKeyArn: config.auditSigningKeyArn,
      uploadRevision: intent.databaseUploadRevision + 1,
      verificationTime: new Date().toISOString(),
    });
    if (snapshot) {
      await verifyCommittedPromotionReceipt(snapshot, (verifyInput) => kms.send(new VerifyCommand(verifyInput)));
    }
    await rds.send(new CommitTransactionCommand({
      resourceArn: config.databaseClusterArn,
      secretArn: config.ingestDatabaseSecretArn,
      transactionId,
    }));
    return snapshot;
  } catch (error) {
    try {
      await rds.send(new RollbackTransactionCommand({
        resourceArn: config.databaseClusterArn,
        secretArn: config.ingestDatabaseSecretArn,
        transactionId,
      }));
    } catch {
      // Preserve the authoritative lookup or KMS verification failure.
    }
    throw error;
  }
}

async function reconcilePromotionDatabase(facts, intent, lease) {
  if (
    facts.promotionFence !== lease?.fence ||
    facts.promotionAttemptId !== lease?.attemptId ||
    !Number.isSafeInteger(lease?.fence) || lease.fence < 1 ||
    !/^pat_[a-f0-9]{32}$/.test(String(lease?.attemptId ?? "")) ||
    !validInstant(lease?.leaseExpiresAt) ||
    Date.parse(lease.leaseExpiresAt) <= Date.now() ||
    Date.parse(lease.leaseExpiresAt) > Date.now() + 15 * 60_000
  ) {
    throw new Error("Promotion database reconciliation requires the active fencing attempt.");
  }
  const canonicalFacts = stableJson(facts);
  const idempotencyDigest = digestHex(`scopeproof-promotion-reconciliation-v1\n${canonicalFacts}`);
  const receiptDigest = digestHex(`scopeproof-promotion-receipt-v1\n${canonicalFacts}`);
  const receiptId = `rcp_${digestHex(`scopeproof-promotion-receipt-id-v1\n${canonicalFacts}`).slice(0, 32)}`;
  const signedAt = new Date().toISOString();
  if (Date.parse(signedAt) < Date.parse(facts.promotedAt)) {
    throw new Error("Promotion receipt time predates the immutable S3 copy.");
  }
  const signed = await kms.send(new SignCommand({
    KeyId: config.auditSigningKeyArn,
    Message: Buffer.from(receiptDigest, "hex"),
    MessageType: "DIGEST",
    SigningAlgorithm: "RSASSA_PSS_SHA_256",
  }));
  if (
    signed.KeyId !== config.auditSigningKeyArn ||
    signed.SigningAlgorithm !== "RSASSA_PSS_SHA_256" ||
    !(signed.Signature instanceof Uint8Array) ||
    signed.Signature.byteLength !== 384
  ) {
    throw new Error("KMS did not return the configured RSA-3072 promotion receipt signature.");
  }
  const transaction = await rds.send(new BeginTransactionCommand({
    database: config.databaseName,
    resourceArn: config.databaseClusterArn,
    secretArn: config.ingestDatabaseSecretArn,
  }));
  if (!transaction.transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transaction.transactionId)) {
    throw new Error("RDS Data API did not establish a promotion transaction.");
  }
  const transactionId = transaction.transactionId;
  try {
    await executePromotionStatement(transactionId, {
      sql: "SELECT pg_catalog.set_config('scopeproof.tenant_id', :tenant_id, true)",
      parameters: [stringParameter("tenant_id", config.tenantId)],
    });
    await executePromotionStatement(transactionId, {
      sql: [
        "SELECT committed_fence FROM scopeproof.claim_promotion_fence(",
        "  CAST(:upload_intent_id AS scopeproof.resource_identifier), CAST(:promotion_fence AS bigint),",
        "  :promotion_attempt_id, CAST(:lease_expires_at AS timestamptz)",
        ")",
      ].join("\n"),
      parameters: [
        stringParameter("upload_intent_id", intent.id),
        stringParameter("promotion_fence", String(lease.fence)),
        stringParameter("promotion_attempt_id", lease.attemptId),
        stringParameter("lease_expires_at", lease.leaseExpiresAt),
      ],
    });
    const response = await executePromotionStatement(transactionId, {
      formatRecordsAs: "JSON",
      sql: [
        "SELECT receipt_id::text, was_created, committed_upload_revision, committed_evidence_revision,",
        "       committed_idempotency_digest, committed_promotion_facts, committed_canonical_receipt,",
        "       committed_receipt_sha256, committed_signing_key_arn, committed_signing_algorithm,",
        "       committed_signature, committed_signed_at",
        "FROM scopeproof.reconcile_promoted_evidence(",
        "  CAST(:receipt_id AS scopeproof.resource_identifier), CAST(:upload_intent_id AS scopeproof.resource_identifier),",
        "  CAST(:evidence_id AS scopeproof.resource_identifier), :quarantine_version_id, :evidence_version_id, :checksum_sha256,",
        "  :kms_key_arn, :object_lock_mode, CAST(:retain_until AS timestamptz), CAST(:required_retention_until AS timestamptz),",
        "  CAST(:expected_upload_revision AS integer), CAST(:expected_evidence_revision AS integer), CAST(:promotion_fence AS bigint),",
        "  :promotion_attempt_id, :idempotency_digest,",
        "  CAST(:promotion_facts AS jsonb), :canonical_receipt, :receipt_sha256, :signing_key_arn, :signing_algorithm,",
        "  :signature, CAST(:signed_at AS timestamptz), CAST(:reconciled_at AS timestamptz)",
        ")",
      ].join("\n"),
      parameters: [
        stringParameter("receipt_id", receiptId),
        stringParameter("upload_intent_id", facts.uploadIntentId),
        stringParameter("evidence_id", facts.evidenceId),
        stringParameter("quarantine_version_id", facts.quarantineVersionId),
        stringParameter("evidence_version_id", facts.evidenceVersionId),
        stringParameter("checksum_sha256", facts.sha256),
        stringParameter("kms_key_arn", facts.kmsKeyArn),
        stringParameter("object_lock_mode", facts.objectLockMode),
        stringParameter("retain_until", facts.retainUntil),
        stringParameter("required_retention_until", intent.requiredRetentionUntil),
        stringParameter("expected_upload_revision", String(intent.databaseUploadRevision)),
        stringParameter("expected_evidence_revision", String(intent.databaseEvidenceRevision)),
        stringParameter("promotion_fence", String(lease.fence)),
        stringParameter("promotion_attempt_id", lease.attemptId),
        stringParameter("idempotency_digest", idempotencyDigest),
        stringParameter("promotion_facts", canonicalFacts),
        stringParameter("canonical_receipt", canonicalFacts),
        stringParameter("receipt_sha256", receiptDigest),
        stringParameter("signing_key_arn", config.auditSigningKeyArn),
        stringParameter("signing_algorithm", "RSASSA_PSS_SHA_256"),
        stringParameter("signature", Buffer.from(signed.Signature).toString("base64")),
        stringParameter("signed_at", signedAt),
        stringParameter("reconciled_at", facts.promotedAt),
      ],
    });
    const snapshot = parseCommittedPromotionReceipt(response.formattedRecords, {
      canonicalFacts,
      evidenceRevision: intent.databaseEvidenceRevision + 1,
      requireOutcome: true,
      signingKeyArn: config.auditSigningKeyArn,
      uploadRevision: intent.databaseUploadRevision + 1,
      verificationTime: signedAt,
    });
    if (
      snapshot.receiptId !== receiptId ||
      snapshot.idempotencyDigest !== idempotencyDigest
    ) {
      throw new Error("The promotion database returned a different deterministic receipt identity.");
    }
    await verifyCommittedPromotionReceipt(snapshot, (verifyInput) => kms.send(new VerifyCommand(verifyInput)));
    await rds.send(new CommitTransactionCommand({
      resourceArn: config.databaseClusterArn,
      secretArn: config.ingestDatabaseSecretArn,
      transactionId,
    }));
    return snapshot;
  } catch (error) {
    try {
      await rds.send(new RollbackTransactionCommand({
        resourceArn: config.databaseClusterArn,
        secretArn: config.ingestDatabaseSecretArn,
        transactionId,
      }));
    } catch {
      // Preserve the original reconciliation error for SQS retry and alerting.
    }
    throw error;
  }
}

function executePromotionStatement(transactionId, statement) {
  return rds.send(new ExecuteStatementCommand({
    database: config.databaseName,
    formatRecordsAs: statement.formatRecordsAs,
    parameters: statement.parameters,
    resourceArn: config.databaseClusterArn,
    secretArn: config.ingestDatabaseSecretArn,
    sql: statement.sql,
    transactionId,
  }));
}

function stableJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
}

function stringParameter(name, value) {
  return { name, value: { stringValue: value } };
}

async function completePromotion(input) {
  const facts = input.facts;
  const publishedAt = new Date().toISOString();
  const receiptHash = input.receiptKey.SK.S.slice("PROMOTION#".length);
  const authoritativeReceipt = buildAuthoritativePromotionReceiptItem({
    publishedAt,
    receiptHash,
    snapshot: input.databaseReconciliation,
    tenantId: config.tenantId,
  });
  const recoveryChange = buildPromotionRecoveryChangeItem({
    facts,
    publishedAt,
    receiptHash,
    tenantId: config.tenantId,
  });
  const promotionReceipt = {
    M: {
      byteSize: { N: String(facts.byteSize) },
      contentType: { S: facts.contentType },
      copyAttemptId: { S: facts.copyAttemptId },
      copyFence: { N: String(facts.copyFence) },
      databaseEvidenceRevision: { N: String(input.databaseReconciliation.evidenceRevision) },
      databaseIdempotencyDigest: { S: input.databaseReconciliation.idempotencyDigest },
      databaseReceiptId: { S: input.databaseReconciliation.receiptId },
      databaseUploadRevision: { N: String(input.databaseReconciliation.uploadRevision) },
      finalKey: { S: facts.evidenceKey },
      finalVersionId: { S: facts.evidenceVersionId },
      kmsKeyArn: { S: facts.kmsKeyArn },
      objectLockMode: { S: facts.objectLockMode },
      promotionAttemptId: { S: facts.promotionAttemptId },
      promotionFence: { N: String(facts.promotionFence) },
      promotedAt: { S: facts.promotedAt },
      providerRequestId: { S: facts.providerRequestId },
      retainUntil: { S: facts.retainUntil },
      sha256: { S: facts.sha256 },
      sourceKey: { S: facts.quarantineKey },
      sourceVersionId: { S: facts.quarantineVersionId },
      tenantId: { S: facts.tenantId },
      uploadedAt: { S: facts.uploadedAt },
    },
  };
  await dynamo.send(
    new TransactWriteItemsCommand({
      ClientRequestToken: token(`${input.leaseId ?? input.databaseReconciliation.receiptId}\0${input.nowIso}`, "complete"),
      TransactItems: [
        {
          Update: {
            ConditionExpression: [
              "#status = :validated AND #revision = :two",
              "databaseUploadRevision = :databaseUploadRevision",
              "databaseEvidenceRevision = :databaseEvidenceRevision",
              input.recovered ? undefined : "promotionLeaseId = :leaseId",
              input.recovered ? undefined : "promotionAttemptId = :attemptId",
              input.recovered ? undefined : "promotionFence = :fence",
              input.recovered ? undefined : "promotionLeaseExpiresAt > :completedAt",
              "quarantineReceipt.versionId = :sourceVersion",
            ].filter(Boolean).join(" AND "),
            ExpressionAttributeNames: { "#revision": "revision", "#status": "status" },
            ExpressionAttributeValues: {
              ...(input.recovered ? {} : {
                ":attemptId": { S: input.lease.attemptId },
                ":completedAt": { S: input.nowIso },
                ":fence": { N: String(input.lease.fence) },
                ":leaseId": { S: input.leaseId },
              }),
              ":databaseEvidenceRevision": { N: String(input.intent.databaseEvidenceRevision) },
              ":databaseUploadRevision": { N: String(input.intent.databaseUploadRevision) },
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
              ":copyAttemptId": { S: facts.copyAttemptId },
              ":copyFence": { N: String(facts.copyFence) },
              ":copying": { S: "COPYING" },
              ":destinationBucket": { S: config.evidenceBucket },
              ":destinationKey": { S: input.intent.finalKey },
              ":destinationVersion": { S: facts.evidenceVersionId },
              ":databaseIdempotencyDigest": { S: input.databaseReconciliation.idempotencyDigest },
              ":databaseReceiptId": { S: input.databaseReconciliation.receiptId },
              ":intentId": { S: input.intent.id },
              ":receiptHash": { S: receiptHash },
              ":promotionAttemptId": { S: facts.promotionAttemptId },
              ":promotionFence": { N: String(facts.promotionFence) },
              ":retainUntil": { S: facts.retainUntil },
              ":sha256": { S: input.intent.expectedSha256 },
              ":sourceBucket": { S: config.ingestBucket },
              ":sourceKey": { S: input.intent.quarantineKey },
              ":sourceVersion": { S: input.versionId },
              ":tenantId": { S: config.tenantId },
            },
            Key: input.receiptKey,
            TableName: config.controlTable,
            UpdateExpression:
              "SET #status = :complete, completedAt = :completedAt, destinationVersionId = :destinationVersion, retainUntil = :retainUntil, databaseReceiptId = :databaseReceiptId, databaseIdempotencyDigest = :databaseIdempotencyDigest, copyAttemptId = :copyAttemptId, copyFence = :copyFence, promotionAttemptId = :promotionAttemptId, promotionFence = :promotionFence",
          },
        },
        {
          Put: {
            ConditionExpression: "attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
            ExpressionAttributeNames: { "#pk": "PK", "#sk": "SK" },
            Item: authoritativeReceipt,
            TableName: config.controlTable,
          },
        },
        {
          Put: {
            ConditionExpression: "attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
            ExpressionAttributeNames: { "#pk": "PK", "#sk": "SK" },
            Item: recoveryChange,
            TableName: config.controlTable,
          },
        },
        {
          Update: {
            ConditionExpression:
              "#status = :copied AND attemptId = :attemptId AND fence = :fence AND receiptHash = :receiptHash AND destinationVersionId = :destinationVersion",
            ExpressionAttributeNames: { "#status": "status" },
            ExpressionAttributeValues: {
              ":attemptId": { S: facts.copyAttemptId },
              ":copied": { S: "COPIED" },
              ":databaseReceiptId": { S: input.databaseReconciliation.receiptId },
              ":destinationVersion": { S: facts.evidenceVersionId },
              ":fence": { N: String(facts.copyFence) },
              ":receiptHash": { S: receiptHash },
              ":reconciled": { S: "RECONCILED" },
              ":reconciledAt": { S: input.nowIso },
            },
            Key: {
              PK: { S: `TENANT#${config.tenantId}` },
              SK: { S: promotionCopyAttemptSortKey(receiptHash, facts.copyFence) },
            },
            TableName: config.controlTable,
            UpdateExpression:
              "SET #status = :reconciled, reconciledAt = :reconciledAt, databaseReceiptId = :databaseReceiptId",
          },
        },
      ],
    }),
  );
}

function validVersionId(value) {
  return /^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/.test(value);
}

function isConditionalWriteConflict(error) {
  if (!error || typeof error !== "object") return false;
  if (new Set(["ConditionalCheckFailedException", "ConditionalRequestConflict", "PreconditionFailed"])
    .has(error.name)) return true;
  if (error.$metadata?.httpStatusCode === 409 || error.$metadata?.httpStatusCode === 412) return true;
  return error.name === "TransactionCanceledException" &&
    Array.isArray(error.CancellationReasons) &&
    error.CancellationReasons.some((reason) => reason?.Code === "ConditionalCheckFailed");
}

function validProviderRequestId(value) {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9_.:+/-]{2,199}$/.test(value);
}

function validInstant(value) {
  if (typeof value !== "string") return false;
  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && value === parsed.toISOString();
}

function canonicalRsa3072Signature(value, label) {
  if (typeof value !== "string" ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`${label} is not canonical base64.`);
  }
  const signature = Buffer.from(value, "base64");
  if (signature.byteLength !== 384 || signature.toString("base64") !== value) {
    throw new Error(`${label} is not a canonical RSA-3072 signature.`);
  }
  return signature;
}

function normalizeEtag(value) {
  return String(value ?? "").replace(/^"|"$/g, "");
}

function digestHex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function safeErrorName(error) {
  const name = error && typeof error === "object" && "name" in error ? String(error.name) : "UnknownError";
  return /^[A-Za-z][A-Za-z0-9_.-]{0,79}$/.test(name) ? name : "UnknownError";
}

function token(eventId, operation) {
  return `sp-${operation}-${digestHex(`${eventId}\0${operation}`).slice(0, 20)}`.slice(0, 36);
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
