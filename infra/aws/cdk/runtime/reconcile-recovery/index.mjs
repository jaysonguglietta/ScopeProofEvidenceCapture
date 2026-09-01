import { createHash } from "node:crypto";
import { CloudWatchClient, PutMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  QueryCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";
import { KMSClient, VerifyCommand } from "@aws-sdk/client-kms";
import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import {
  CreateJobCommand,
  DescribeJobCommand,
  S3ControlClient,
} from "@aws-sdk/client-s3-control";
import {
  HeadObjectCommand,
  ListObjectVersionsCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import {
  assertDestinationVersionHasSource,
  assertReplicaMatches,
  buildCreateJobInput,
  destinationInventoryPageAtCutoff,
  evaluateBatchJob,
  legalHoldExpectationAtCutoff,
  parseRecoveryBackfillConfig,
  recoveryLedgerCutoff,
  shouldStartPeriodicVerification,
  shouldRotateRecoveryRepair,
} from "./backfill-contract.mjs";
import {
  legalHoldRecoveryCurrentKey,
  parseLegalHoldRecoveryCurrentItem,
  parseRecoveryChangeItem,
  recoveryChangeBounds,
  recoveryPartitionKey,
} from "./change-ledger.mjs";
import {
  parseAuthoritativePromotionReceiptItem,
  verifyCommittedPromotionReceipt,
} from "../promote-evidence/promotion-receipt.mjs";

const config = parseRecoveryBackfillConfig(process.env);
const dynamo = new DynamoDBClient({ region: config.region });
const s3 = new S3Client({ region: config.region });
const recoveryS3 = new S3Client({ region: config.recoveryRegion });
const s3Control = new S3ControlClient({ region: config.region });
const sns = new SNSClient({ region: config.region });
const cloudwatch = new CloudWatchClient({ region: config.region });
const kms = new KMSClient({ region: config.region });

export async function handler(event) {
  if (Array.isArray(event?.Records)) return await handleReplicationFailureEvent(event.Records);
  try {
    const invocationTime = new Date().toISOString();
    const safeCutoff = recoveryLedgerCutoff(invocationTime, config.ledgerSettleSeconds);
    let state = await readState();
    if (!state) {
      await reserveBackfill(safeCutoff);
      state = await readRequiredState();
    }
    if (shouldRotateRecoveryRepair(state)) {
      await rotateRepairGeneration(state);
      state = await readRequiredState();
    } else if (shouldStartPeriodicVerification(
      state,
      invocationTime,
      config.verificationIntervalSeconds,
    )) {
      await rotatePeriodicGeneration(state, invocationTime, safeCutoff);
      state = await readRequiredState();
    }
    if (!state.jobId) state = await ensureJob(state);
    if (state.verificationStatus === "VERIFIED") {
      return await monitoredResult("VERIFIED", state);
    }

    const described = await s3Control.send(new DescribeJobCommand({
      AccountId: config.accountId,
      JobId: state.jobId,
    }));
    const job = evaluateBatchJob({ Job: described.Job }, state.jobId);
    await recordJobProgress(state, job);
    if (job.outcome === "pending") return await monitoredResult("BATCH_PENDING", state, job);
    if (state.repairRequestedAt) {
      const terminalState = await readRequiredState();
      if (!shouldRotateRecoveryRepair(terminalState)) {
        throw recoveryFailure("REPAIR_GENERATION_NOT_READY");
      }
      await rotateRepairGeneration(terminalState);
      const repaired = await ensureJob(await readRequiredState());
      return await monitoredResult("REPAIR_BATCH_STARTED", repaired, job);
    }
    if (job.outcome === "failed") {
      throw recoveryFailure("BATCH_JOB_FAILED");
    }

    const verification = await verifyReplicaPage(state);
    return await monitoredResult(
      verification.complete ? "VERIFIED" : "VERIFYING",
      state,
      job,
      verification,
    );
  } catch (error) {
    const code = safeFailureCode(error);
    await Promise.allSettled([recordFailure(code), notifyFailure(code)]);
    console.error(JSON.stringify({
      contractDigest: config.contractDigest,
      errorCode: code,
      event: "scopeproof.recovery_backfill_failed",
      tenantId: config.tenantId,
    }));
    throw error;
  }
}

async function handleReplicationFailureEvent(records) {
  try {
    assertReplicationFailureNotification(records);
    const requestedAt = new Date().toISOString();
    await reserveBackfill(recoveryLedgerCutoff(requestedAt, config.ledgerSettleSeconds));
    await dynamo.send(new UpdateItemCommand({
      ConditionExpression: "contractDigest = :digest",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: {
        ":digest": { S: config.contractDigest },
        ":requested": { S: "REPAIR_REQUESTED" },
        ":requestedAt": { S: requestedAt },
      },
      Key: dynamoKey(),
      TableName: config.controlTable,
      UpdateExpression: "SET #status = :requested, repairRequestedAt = :requestedAt, updatedAt = :requestedAt",
    }));
    await notifyFailure("LIVE_REPLICATION_FAILED");
    return Object.freeze({
      contractDigest: config.contractDigest,
      status: "REPAIR_REQUESTED",
      tenantId: config.tenantId,
    });
  } catch (error) {
    const code = safeFailureCode(error);
    await Promise.allSettled([notifyFailure(code)]);
    throw error;
  }
}

async function rotateRepairGeneration(state) {
  if (!shouldRotateRecoveryRepair(state)) throw recoveryFailure("REPAIR_GENERATION_NOT_READY");
  await dynamo.send(new UpdateItemCommand({
    ConditionExpression: "contractDigest = :digest AND jobId = :jobId AND repairRequestedAt = :repair AND (verificationStatus = :verified OR batchStatus = :terminal)",
    ExpressionAttributeNames: { "#status": "status" },
    ExpressionAttributeValues: {
      ":creating": { S: "CREATING" },
      ":digest": { S: config.contractDigest },
      ":jobId": { S: state.jobId },
      ":one": { N: "1" },
      ":repair": { S: state.repairRequestedAt },
      ":source": { S: "SOURCE" },
      ":terminal": { S: state.batchStatus ?? "Complete" },
      ":updatedAt": { S: new Date().toISOString() },
      ":verified": { S: "VERIFIED" },
      ":zero": { N: "0" },
    },
    Key: dynamoKey(),
    TableName: config.controlTable,
    UpdateExpression: [
      "SET #status = :creating, cutoffIso = :repair, destinationVersionsVerified = :zero, generation = if_not_exists(generation, :zero) + :one, updatedAt = :updatedAt, verificationPhase = :source, versionsVerified = :zero",
      "REMOVE batchStatus, jobId, lastErrorCode, nextChangeKey, nextDestinationKeyMarker, nextDestinationVersionIdMarker, nextKeyMarker, nextVersionIdMarker, repairRequestedAt, tasksFailed, tasksSucceeded, tasksTotal, verificationAfter, verificationStatus",
    ].join(" "),
  }));
}

async function rotatePeriodicGeneration(state, nowIso, cutoffIso) {
  if (
    !shouldStartPeriodicVerification(state, nowIso, config.verificationIntervalSeconds) ||
    Date.parse(cutoffIso) <= Date.parse(state.verifiedThrough)
  ) {
    throw recoveryFailure("PERIODIC_GENERATION_NOT_READY");
  }
  await dynamo.send(new UpdateItemCommand({
    ConditionExpression: [
      "contractDigest = :digest",
      "jobId = :jobId",
      "verificationStatus = :verified",
      "verifiedThrough = :previous",
      "attribute_not_exists(repairRequestedAt)",
    ].join(" AND "),
    ExpressionAttributeNames: { "#status": "status" },
    ExpressionAttributeValues: {
      ":changes": { S: "CHANGES" },
      ":creating": { S: "CREATING" },
      ":cutoff": { S: cutoffIso },
      ":digest": { S: config.contractDigest },
      ":jobId": { S: state.jobId },
      ":one": { N: "1" },
      ":previous": { S: state.verifiedThrough },
      ":updatedAt": { S: nowIso },
      ":verified": { S: "VERIFIED" },
      ":zero": { N: "0" },
    },
    Key: dynamoKey(),
    TableName: config.controlTable,
    UpdateExpression: [
      "SET #status = :creating, cutoffIso = :cutoff, destinationVersionsVerified = :zero, verificationAfter = :previous, generation = if_not_exists(generation, :zero) + :one, updatedAt = :updatedAt, verificationPhase = :changes, versionsVerified = :zero",
      "REMOVE batchStatus, jobId, lastErrorCode, nextChangeKey, nextDestinationKeyMarker, nextDestinationVersionIdMarker, nextKeyMarker, nextVersionIdMarker, tasksFailed, tasksSucceeded, tasksTotal, verificationStatus",
    ].join(" "),
  }));
}

function assertReplicationFailureNotification(records) {
  if (records.length < 1 || records.length > 10) throw recoveryFailure("INVALID_REPLICATION_FAILURE_EVENT");
  for (const record of records) {
    const rawKey = String(record?.s3?.object?.key ?? "");
    let key = "";
    try {
      key = decodeURIComponent(rawKey.replaceAll("+", "%20"));
    } catch {
      throw recoveryFailure("INVALID_REPLICATION_FAILURE_EVENT");
    }
    const versionId = String(record?.s3?.object?.versionId ?? "");
    if (
      record?.eventSource !== "aws:s3" ||
      record?.eventName !== "Replication:OperationFailedReplication" ||
      record?.awsRegion !== config.region ||
      record?.s3?.bucket?.name !== config.sourceBucket ||
      !key.startsWith(config.prefix) || key.length > 1_024 ||
      !/^[A-Za-z0-9._~!$&'()*+,;=:@/-]{1,1024}$/.test(key) ||
      !/^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/.test(versionId)
    ) {
      throw recoveryFailure("INVALID_REPLICATION_FAILURE_EVENT");
    }
  }
}

async function reserveBackfill(cutoffIso) {
  try {
    await dynamo.send(new PutItemCommand({
      ConditionExpression: "attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
      ExpressionAttributeNames: { "#pk": "PK", "#sk": "SK" },
      Item: {
        PK: { S: config.stateKey.PK },
        SK: { S: config.stateKey.SK },
        contractDigest: { S: config.contractDigest },
        cutoffIso: { S: cutoffIso },
        createdAt: { S: cutoffIso },
        destinationBucket: { S: config.destinationBucket },
        destinationVersionsVerified: { N: "0" },
        kind: { S: "EvidenceRecoveryBackfill" },
        schemaVersion: { N: "1" },
        sourceBucket: { S: config.sourceBucket },
        status: { S: "CREATING" },
        tenantId: { S: config.tenantId },
        verificationPhase: { S: "SOURCE" },
      },
      TableName: config.controlTable,
    }));
  } catch (error) {
    if (error?.name !== "ConditionalCheckFailedException") throw error;
  }
}

async function ensureJob(state) {
  const response = await s3Control.send(new CreateJobCommand(
    buildCreateJobInput(config, state.cutoffIso),
  ));
  const jobId = String(response.JobId ?? "");
  if (!/^[A-Za-z0-9-]{10,128}$/.test(jobId)) throw recoveryFailure("INVALID_BATCH_JOB_ID");
  try {
    await dynamo.send(new UpdateItemCommand({
      ConditionExpression: "#status = :creating AND cutoffIso = :cutoff AND attribute_not_exists(jobId)",
      ExpressionAttributeNames: { "#status": "status" },
      ExpressionAttributeValues: {
        ":creating": { S: "CREATING" },
        ":cutoff": { S: state.cutoffIso },
        ":jobId": { S: jobId },
        ":started": { S: "BATCH_STARTED" },
        ":updatedAt": { S: new Date().toISOString() },
      },
      Key: dynamoKey(),
      TableName: config.controlTable,
      UpdateExpression: "SET jobId = :jobId, #status = :started, updatedAt = :updatedAt",
    }));
  } catch (error) {
    if (error?.name !== "ConditionalCheckFailedException") throw error;
    const existing = await readRequiredState();
    if (existing.jobId !== jobId) throw recoveryFailure("BATCH_JOB_STATE_CONFLICT");
    return existing;
  }
  return await readRequiredState();
}

async function recordJobProgress(state, progress) {
  await dynamo.send(new UpdateItemCommand({
    ConditionExpression: "jobId = :jobId AND contractDigest = :digest",
    ExpressionAttributeNames: { "#status": "status" },
    ExpressionAttributeValues: {
      ":batchStatus": { S: progress.status },
      ":digest": { S: config.contractDigest },
      ":failed": { N: String(progress.failed) },
      ":jobId": { S: state.jobId },
      ":status": { S: progress.outcome === "complete" ? "BATCH_COMPLETE" : progress.outcome === "failed" ? "FAILED" : "BATCH_PENDING" },
      ":succeeded": { N: String(progress.succeeded) },
      ":total": { N: String(progress.total) },
      ":updatedAt": { S: new Date().toISOString() },
    },
    Key: dynamoKey(),
    TableName: config.controlTable,
    UpdateExpression: "SET #status = :status, batchStatus = :batchStatus, tasksTotal = :total, tasksSucceeded = :succeeded, tasksFailed = :failed, updatedAt = :updatedAt",
  }));
}

async function verifyReplicaPage(state) {
  if (state.verificationPhase === "SOURCE") return await verifySourceVersionPage(state);
  if (state.verificationPhase === "CHANGES") return await verifyRecoveryChangePage(state);
  if (state.verificationPhase === "DESTINATION") return await verifyDestinationVersionPage(state);
  throw recoveryFailure("CORRUPT_RECOVERY_STATE");
}

async function verifySourceVersionPage(state) {
  const cutoff = Date.parse(state.cutoffIso);
  const page = await s3.send(new ListObjectVersionsCommand({
    Bucket: config.sourceBucket,
    ExpectedBucketOwner: config.accountId,
    KeyMarker: state.nextKeyMarker,
    MaxKeys: config.maxVersionsPerRun,
    Prefix: config.prefix,
    VersionIdMarker: state.nextVersionIdMarker,
  }));
  for (const marker of page.DeleteMarkers ?? []) {
    if (
      marker.Key?.startsWith(config.prefix) &&
      marker.LastModified &&
      marker.LastModified.getTime() <= cutoff
    ) {
      throw recoveryFailure("SOURCE_DELETE_MARKER_PRESENT");
    }
  }
  let verified = state.versionsVerified;
  for (const version of page.Versions ?? []) {
    if (!version.Key?.startsWith(config.prefix) || !version.VersionId || !version.LastModified) {
      throw recoveryFailure("INVALID_SOURCE_VERSION_LISTING");
    }
    if (version.LastModified.getTime() > cutoff) continue;
    const current = await readCurrentLegalHoldProjection(version.Key, version.VersionId);
    const expectation = legalHoldExpectationAtCutoff(current, state.cutoffIso);
    if (!expectation.deferred) {
      await verifyExactVersion(version.Key, version.VersionId, undefined, expectation.status);
    } else {
      // A later current projection was committed atomically with an immutable
      // change above this cutoff. The next generation will verify that exact
      // version against the later status instead of asserting historical mutable
      // S3 legal-hold state that HeadObject cannot reconstruct. Every other
      // immutable receipt/checksum/KMS/retention fact is still mandatory now.
      await verifyExactVersion(version.Key, version.VersionId);
    }
    verified += 1;
  }
  const complete = page.IsTruncated !== true;
  if (!complete && (!page.NextKeyMarker || !page.NextVersionIdMarker)) {
    throw recoveryFailure("INVALID_SOURCE_VERSION_CURSOR");
  }
  const values = {
    ":digest": { S: config.contractDigest },
    ":jobId": { S: state.jobId },
    ":source": { S: "SOURCE" },
    ":updatedAt": { S: new Date().toISOString() },
    ":verifying": { S: "VERIFYING" },
    ":verified": { N: String(verified) },
  };
  const names = { "#status": "status" };
  let expression = "SET #status = :verifying, verificationStatus = :verifying, verificationPhase = :source, versionsVerified = :verified, updatedAt = :updatedAt";
  if (complete) {
    values[":destination"] = { S: "DESTINATION" };
    expression = "SET #status = :verifying, verificationStatus = :verifying, verificationPhase = :destination, versionsVerified = :verified, updatedAt = :updatedAt REMOVE nextKeyMarker, nextVersionIdMarker";
  } else {
    values[":nextKey"] = { S: page.NextKeyMarker };
    values[":nextVersion"] = { S: page.NextVersionIdMarker };
    expression += ", nextKeyMarker = :nextKey, nextVersionIdMarker = :nextVersion";
  }
  await dynamo.send(new UpdateItemCommand({
    ConditionExpression: "jobId = :jobId AND contractDigest = :digest AND verificationPhase = :source",
    ExpressionAttributeNames: names,
    ExpressionAttributeValues: values,
    Key: dynamoKey(),
    TableName: config.controlTable,
    UpdateExpression: expression,
  }));
  return Object.freeze({
    complete: false,
    verificationPhase: complete ? "DESTINATION" : "SOURCE",
    verifiedThrough: state.verifiedThrough,
    versionsVerified: verified,
  });
}

async function verifyRecoveryChangePage(state) {
  const bounds = recoveryChangeBounds(state.verificationAfter, state.cutoffIso);
  const partition = recoveryPartitionKey(config.tenantId);
  const exclusiveStartKey = state.nextChangeKey === undefined
    ? undefined
    : { PK: { S: partition }, SK: { S: state.nextChangeKey } };
  const page = await dynamo.send(new QueryCommand({
    ConsistentRead: true,
    ExclusiveStartKey: exclusiveStartKey,
    ExpressionAttributeNames: { "#pk": "PK", "#sk": "SK" },
    ExpressionAttributeValues: {
      ":after": { S: bounds.after },
      ":cutoff": { S: bounds.cutoff },
      ":partition": { S: partition },
    },
    KeyConditionExpression: "#pk = :partition AND #sk > :after AND #sk < :cutoff",
    Limit: config.maxVersionsPerRun,
    ScanIndexForward: true,
    TableName: config.controlTable,
  }));
  let verified = state.versionsVerified;
  for (const item of page.Items ?? []) {
    const change = parseRecoveryChangeItem(item, {
      sourceBucket: config.sourceBucket,
      tenantId: config.tenantId,
    });
    if (change.changeType === "LEGAL_HOLD") {
      const expectation = await readCurrentLegalHoldExpectation(change, state.cutoffIso);
      if (!expectation.deferred) {
        await verifyExactVersion(change.key, change.versionId, undefined, expectation.status);
      } else {
        // Deferral applies only to mutable hold status, never to the immutable
        // evidence and receipt contract needed to advance the watermark.
        await verifyExactVersion(change.key, change.versionId);
      }
    } else {
      await verifyExactVersion(change.key, change.versionId, change.receiptHash);
    }
    verified += 1;
  }
  const cursor = page.LastEvaluatedKey;
  const complete = cursor === undefined;
  const nextChangeKey = cursor?.SK?.S;
  if (
    !complete &&
    (cursor?.PK?.S !== partition || typeof nextChangeKey !== "string" || !nextChangeKey.startsWith("CHANGE#"))
  ) {
    throw recoveryFailure("INVALID_RECOVERY_CHANGE_CURSOR");
  }
  const values = {
    ":changes": { S: "CHANGES" },
    ":cutoff": { S: state.cutoffIso },
    ":digest": { S: config.contractDigest },
    ":jobId": { S: state.jobId },
    ":updatedAt": { S: new Date().toISOString() },
    ":verifying": { S: "VERIFYING" },
    ":verified": { N: String(verified) },
  };
  let expression = "SET #status = :verifying, verificationStatus = :verifying, verificationPhase = :changes, versionsVerified = :verified, updatedAt = :updatedAt";
  if (complete) {
    values[":destination"] = { S: "DESTINATION" };
    expression = "SET #status = :verifying, verificationStatus = :verifying, verificationPhase = :destination, versionsVerified = :verified, updatedAt = :updatedAt REMOVE nextChangeKey";
  } else {
    values[":nextChangeKey"] = { S: nextChangeKey };
    expression += ", nextChangeKey = :nextChangeKey";
  }
  await dynamo.send(new UpdateItemCommand({
    ConditionExpression: "jobId = :jobId AND contractDigest = :digest AND cutoffIso = :cutoff AND verificationPhase = :changes",
    ExpressionAttributeNames: { "#status": "status" },
    ExpressionAttributeValues: values,
    Key: dynamoKey(),
    TableName: config.controlTable,
    UpdateExpression: expression,
  }));
  return Object.freeze({
    complete: false,
    verificationPhase: complete ? "DESTINATION" : "CHANGES",
    verifiedThrough: state.verifiedThrough,
    versionsVerified: verified,
  });
}

async function verifyDestinationVersionPage(state) {
  const rawPage = await recoveryS3.send(new ListObjectVersionsCommand({
    Bucket: config.destinationBucket,
    ExpectedBucketOwner: config.accountId,
    KeyMarker: state.nextDestinationKeyMarker,
    MaxKeys: config.maxVersionsPerRun,
    Prefix: config.prefix,
    VersionIdMarker: state.nextDestinationVersionIdMarker,
  }));
  let page;
  try {
    page = destinationInventoryPageAtCutoff(rawPage, state.cutoffIso, config.prefix);
  } catch (error) {
    if (error?.name === "DestinationDeleteMarkerPresent") {
      throw recoveryFailure("DESTINATION_DELETE_MARKER_PRESENT");
    }
    throw recoveryFailure("INVALID_DESTINATION_VERSION_LISTING");
  }
  let destinationVerified = state.destinationVersionsVerified;
  for (const version of page.versions) {
    let sourceHead;
    try {
      sourceHead = await s3.send(new HeadObjectCommand({
        Bucket: config.sourceBucket,
        ExpectedBucketOwner: config.accountId,
        Key: version.key,
        VersionId: version.versionId,
      }));
      assertDestinationVersionHasSource(version, sourceHead);
    } catch {
      throw recoveryFailure("DESTINATION_ORPHAN_VERSION_PRESENT");
    }
    destinationVerified += 1;
  }
  const values = {
    ":cutoff": { S: state.cutoffIso },
    ":destination": { S: "DESTINATION" },
    ":destinationVerified": { N: String(destinationVerified) },
    ":digest": { S: config.contractDigest },
    ":jobId": { S: state.jobId },
    ":updatedAt": { S: new Date().toISOString() },
  };
  let expression;
  if (!page.complete) {
    values[":nextKey"] = { S: page.nextKeyMarker };
    values[":nextVersion"] = { S: page.nextVersionIdMarker };
    values[":verifying"] = { S: "VERIFYING" };
    expression = "SET #status = :verifying, verificationStatus = :verifying, verificationPhase = :destination, destinationVersionsVerified = :destinationVerified, nextDestinationKeyMarker = :nextKey, nextDestinationVersionIdMarker = :nextVersion, updatedAt = :updatedAt";
  } else {
    values[":complete"] = { S: "COMPLETE" };
    values[":verified"] = { S: "VERIFIED" };
    expression = "SET #status = :verified, verificationStatus = :verified, verificationPhase = :complete, verifiedThrough = :cutoff, destinationVersionsVerified = :destinationVerified, updatedAt = :updatedAt REMOVE nextDestinationKeyMarker, nextDestinationVersionIdMarker, verificationAfter";
  }
  await dynamo.send(new UpdateItemCommand({
    ConditionExpression: "jobId = :jobId AND contractDigest = :digest AND cutoffIso = :cutoff AND verificationPhase = :destination",
    ExpressionAttributeNames: { "#status": "status" },
    ExpressionAttributeValues: values,
    Key: dynamoKey(),
    TableName: config.controlTable,
    UpdateExpression: expression,
  }));
  return Object.freeze({
    complete: page.complete,
    destinationVersionsVerified: destinationVerified,
    verificationPhase: page.complete ? "COMPLETE" : "DESTINATION",
    verifiedThrough: page.complete ? state.cutoffIso : state.verifiedThrough,
    versionsVerified: state.versionsVerified,
  });
}

async function readCurrentLegalHoldExpectation(change, cutoffIso) {
  const current = await readCurrentLegalHoldProjection(change.key, change.versionId);
  if (!current) throw recoveryFailure("LEGAL_HOLD_RECOVERY_STATE_MISSING");
  if (current.currentKey !== change.currentKey) {
    throw recoveryFailure("LEGAL_HOLD_RECOVERY_STATE_INVALID");
  }
  if (Date.parse(current.appliedAt) < Date.parse(change.appliedAt)) {
    throw recoveryFailure("LEGAL_HOLD_RECOVERY_STATE_STALE");
  }
  if (
    current.appliedAt === change.appliedAt &&
    (current.operationId !== change.operationId ||
      current.requestDigest !== change.requestDigest || current.status !== change.status)
  ) {
    throw recoveryFailure("LEGAL_HOLD_RECOVERY_STATE_INVALID");
  }
  return legalHoldExpectationAtCutoff(current, cutoffIso);
}

async function readCurrentLegalHoldProjection(key, versionId) {
  let currentKey;
  try {
    currentKey = legalHoldRecoveryCurrentKey({
      bucket: config.sourceBucket,
      key,
      tenantId: config.tenantId,
      versionId,
    });
  } catch {
    throw recoveryFailure("LEGAL_HOLD_RECOVERY_STATE_INVALID");
  }
  const response = await dynamo.send(new GetItemCommand({
    ConsistentRead: true,
    Key: {
      PK: { S: recoveryPartitionKey(config.tenantId) },
      SK: { S: currentKey },
    },
    TableName: config.controlTable,
  }));
  if (!response.Item) return undefined;
  let current;
  try {
    current = parseLegalHoldRecoveryCurrentItem(response.Item, {
      key,
      sourceBucket: config.sourceBucket,
      tenantId: config.tenantId,
      versionId,
    });
    if (current.audit.keyArn !== config.auditSigningKeyArn) {
      throw new Error("Unexpected legal-hold audit signing key.");
    }
    const verified = await kms.send(new VerifyCommand({
      KeyId: current.audit.keyArn,
      Message: Buffer.from(current.audit.payloadSha256, "hex"),
      MessageType: "DIGEST",
      Signature: Buffer.from(current.audit.signature, "base64"),
      SigningAlgorithm: current.audit.signingAlgorithm,
    }));
    if (verified.SignatureValid !== true || verified.KeyId !== current.audit.keyArn ||
        verified.SigningAlgorithm !== current.audit.signingAlgorithm) {
      throw new Error("Legal-hold audit signature is invalid.");
    }
  } catch {
    throw recoveryFailure("LEGAL_HOLD_AUDIT_RECEIPT_VERIFICATION_FAILED");
  }
  return current;
}

async function verifyExactVersion(key, versionId, expectedReceiptHash, expectedLegalHoldStatus) {
  const [source, replica] = await Promise.all([
    s3.send(new HeadObjectCommand({
      Bucket: config.sourceBucket,
      ChecksumMode: "ENABLED",
      ExpectedBucketOwner: config.accountId,
      Key: key,
      VersionId: versionId,
    })),
    recoveryS3.send(new HeadObjectCommand({
      Bucket: config.destinationBucket,
      ChecksumMode: "ENABLED",
      ExpectedBucketOwner: config.accountId,
      Key: key,
      VersionId: versionId,
    })),
  ]);
  if (source.ReplicationStatus !== "COMPLETED" || replica.ReplicationStatus !== "REPLICA") {
    throw recoveryFailure("REPLICA_STATUS_MISMATCH");
  }
  const sourceFacts = headFacts(key, versionId, source, false);
  const replicaFacts = headFacts(key, versionId, replica, true);
  const receipt = await readPromotionReceipt(sourceFacts, expectedReceiptHash);
  assertReplicaMatches(sourceFacts, replicaFacts, receipt, config, expectedLegalHoldStatus);
}

function headFacts(key, versionId, head, replica) {
  const length = Number(head.ContentLength);
  const contentType = String(head.ContentType ?? "").split(";", 1)[0].trim().toLowerCase();
  const retainUntil = head.ObjectLockRetainUntilDate?.toISOString();
  const metadata = head.Metadata ?? {};
  if (
    head.VersionId !== versionId ||
    !Number.isSafeInteger(length) || length < 0 ||
    !/^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$/.test(contentType) ||
    typeof head.ChecksumSHA256 !== "string" ||
    head.ChecksumType !== "FULL_OBJECT" ||
    head.ServerSideEncryption !== "aws:kms" ||
    !/^[a-f0-9]{64}$/.test(String(metadata.sha256 ?? "")) ||
    metadata["tenant-id"] !== config.tenantId ||
    !/^upl_[a-f0-9]{32}$/.test(String(metadata["intent-id"] ?? "")) ||
    !/^evd_[a-f0-9]{32}$/.test(String(metadata["resource-id"] ?? "")) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(String(metadata["control-id"] ?? "")) ||
    !/^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/.test(String(metadata["source-version"] ?? "")) ||
    !canonicalInstant(metadata["uploaded-at"]) ||
    !["GOVERNANCE", "COMPLIANCE"].includes(head.ObjectLockMode) ||
    !retainUntil || Date.parse(retainUntil) <= 0 ||
    ![undefined, "OFF", "ON"].includes(head.ObjectLockLegalHoldStatus) ||
    head.SSEKMSKeyId !== (replica ? config.destinationKmsKeyArn : config.sourceKmsKeyArn)
  ) {
    throw recoveryFailure("INVALID_VERSION_METADATA");
  }
  const facts = {
    checksumSha256: head.ChecksumSHA256,
    contentLength: length,
    contentType,
    key,
    legalHold: head.ObjectLockLegalHoldStatus ?? "OFF",
    metadata: Object.freeze({
      controlId: metadata["control-id"],
      intentId: metadata["intent-id"],
      resourceId: metadata["resource-id"],
      sha256: metadata.sha256,
      sourceVersionId: metadata["source-version"],
      tenantId: metadata["tenant-id"],
      uploadedAt: metadata["uploaded-at"],
    }),
    objectLockMode: head.ObjectLockMode,
    retainUntil,
    versionId,
  };
  return { ...facts, sseKmsKeyArn: head.SSEKMSKeyId };
}

async function readPromotionReceipt(source, expectedReceiptHash) {
  const intentId = source.metadata.intentId;
  const sourceVersionId = source.metadata.sourceVersionId;
  const receiptHash = createHash("sha256")
    .update(`${config.tenantId}\0${intentId}\0${sourceVersionId}`)
    .digest("hex");
  if (expectedReceiptHash !== undefined && expectedReceiptHash !== receiptHash) {
    throw recoveryFailure("PROMOTION_RECEIPT_IDENTITY_MISMATCH");
  }
  const response = await dynamo.send(new GetItemCommand({
    ConsistentRead: true,
    Key: {
      PK: { S: recoveryPartitionKey(config.tenantId) },
      SK: { S: `PROMOTION#${receiptHash}` },
    },
    TableName: config.controlTable,
  }));
  if (!response.Item) {
    throw recoveryFailure("PROMOTION_RECEIPT_MISSING");
  }
  let parsed;
  try {
    parsed = parseAuthoritativePromotionReceiptItem(response.Item, {
      receiptHash,
      signingKeyArn: config.auditSigningKeyArn,
      tenantId: config.tenantId,
      verificationTime: new Date().toISOString(),
    });
    await verifyCommittedPromotionReceipt(
      parsed.snapshot,
      (verifyInput) => kms.send(new VerifyCommand(verifyInput)),
    );
  } catch {
    throw recoveryFailure("PROMOTION_RECEIPT_VERIFICATION_FAILED");
  }
  return parsed.receipt;
}

async function readRequiredState() {
  const state = await readState();
  if (!state) throw recoveryFailure("RECOVERY_STATE_MISSING");
  return state;
}

async function readState() {
  const response = await dynamo.send(new GetItemCommand({
    ConsistentRead: true,
    Key: dynamoKey(),
    TableName: config.controlTable,
  }));
  if (!response.Item) return undefined;
  const item = response.Item;
  const required = {
    PK: config.stateKey.PK,
    SK: config.stateKey.SK,
    contractDigest: config.contractDigest,
    destinationBucket: config.destinationBucket,
    kind: "EvidenceRecoveryBackfill",
    sourceBucket: config.sourceBucket,
    tenantId: config.tenantId,
  };
  for (const [name, expected] of Object.entries(required)) {
    if (item[name]?.S !== expected || Object.keys(item[name] ?? {}).length !== 1) {
      throw recoveryFailure("CORRUPT_RECOVERY_STATE");
    }
  }
  if (item.schemaVersion?.N !== "1" || !canonicalInstant(item.cutoffIso?.S)) {
    throw recoveryFailure("CORRUPT_RECOVERY_STATE");
  }
  const jobId = item.jobId?.S;
  if (jobId !== undefined && !/^[A-Za-z0-9-]{10,128}$/.test(jobId)) {
    throw recoveryFailure("CORRUPT_RECOVERY_STATE");
  }
  const versionsVerified = item.versionsVerified?.N === undefined ? 0 : Number(item.versionsVerified.N);
  if (!Number.isSafeInteger(versionsVerified) || versionsVerified < 0) throw recoveryFailure("CORRUPT_RECOVERY_STATE");
  const destinationVersionsVerified = item.destinationVersionsVerified?.N === undefined
    ? 0
    : Number(item.destinationVersionsVerified.N);
  if (!Number.isSafeInteger(destinationVersionsVerified) || destinationVersionsVerified < 0) {
    throw recoveryFailure("CORRUPT_RECOVERY_STATE");
  }
  const marker = item.nextKeyMarker?.S;
  const versionMarker = item.nextVersionIdMarker?.S;
  const destinationMarker = item.nextDestinationKeyMarker?.S;
  const destinationVersionMarker = item.nextDestinationVersionIdMarker?.S;
  const nextChangeKey = item.nextChangeKey?.S;
  const repairRequestedAt = item.repairRequestedAt?.S;
  const batchStatus = item.batchStatus?.S;
  const verificationAfter = item.verificationAfter?.S;
  const verificationPhase = item.verificationPhase?.S;
  const verificationStatus = item.verificationStatus?.S;
  const verifiedThrough = item.verifiedThrough?.S;
  if (
    (marker === undefined) !== (versionMarker === undefined) ||
    (destinationMarker === undefined) !== (destinationVersionMarker === undefined) ||
    (marker?.length ?? 0) > 1_024 || (versionMarker?.length ?? 0) > 512 ||
    (destinationMarker !== undefined &&
      (!destinationMarker.startsWith(config.prefix) || destinationMarker.length > 1_024)) ||
    (destinationVersionMarker !== undefined &&
      !/^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/.test(destinationVersionMarker))
  ) {
    throw recoveryFailure("CORRUPT_RECOVERY_STATE");
  }
  if (repairRequestedAt !== undefined && !canonicalInstant(repairRequestedAt)) {
    throw recoveryFailure("CORRUPT_RECOVERY_STATE");
  }
  if (
    (verificationAfter !== undefined && !canonicalInstant(verificationAfter)) ||
    (verifiedThrough !== undefined && !canonicalInstant(verifiedThrough)) ||
    (verificationAfter !== undefined && Date.parse(verificationAfter) >= Date.parse(item.cutoffIso.S)) ||
    !["SOURCE", "CHANGES", "DESTINATION", "COMPLETE"].includes(verificationPhase) ||
    (verificationStatus !== undefined && !["VERIFYING", "VERIFIED"].includes(verificationStatus)) ||
    (verificationStatus === "VERIFIED" &&
      (verificationPhase !== "COMPLETE" || verifiedThrough !== item.cutoffIso.S)) ||
    (verificationPhase === "COMPLETE" && verificationStatus !== "VERIFIED") ||
    (nextChangeKey !== undefined &&
      (verificationAfter === undefined || nextChangeKey.length > 1_024 || !nextChangeKey.startsWith("CHANGE#"))) ||
    (verificationPhase === "SOURCE" &&
      (verificationAfter !== undefined || nextChangeKey !== undefined || destinationMarker !== undefined)) ||
    (verificationPhase === "CHANGES" &&
      (verificationAfter === undefined || marker !== undefined || destinationMarker !== undefined)) ||
    (verificationPhase === "DESTINATION" &&
      (verificationStatus !== "VERIFYING" || marker !== undefined || nextChangeKey !== undefined)) ||
    (verificationPhase === "COMPLETE" &&
      (marker !== undefined || nextChangeKey !== undefined || destinationMarker !== undefined || verificationAfter !== undefined))
  ) {
    throw recoveryFailure("CORRUPT_RECOVERY_STATE");
  }
  if (batchStatus !== undefined && !["Active", "Cancelling", "Cancelled", "Complete", "Completing", "Failed", "New", "Paused", "Pausing", "Preparing", "Ready", "Suspended"].includes(batchStatus)) {
    throw recoveryFailure("CORRUPT_RECOVERY_STATE");
  }
  return Object.freeze({
    batchStatus,
    cutoffIso: item.cutoffIso.S,
    destinationVersionsVerified,
    jobId,
    nextDestinationKeyMarker: destinationMarker,
    nextDestinationVersionIdMarker: destinationVersionMarker,
    nextKeyMarker: marker,
    nextChangeKey,
    nextVersionIdMarker: versionMarker,
    repairRequestedAt,
    status: item.status?.S,
    verificationAfter,
    verificationPhase,
    verificationStatus,
    verifiedThrough,
    versionsVerified,
  });
}

async function recordFailure(code) {
  await dynamo.send(new UpdateItemCommand({
    ConditionExpression: "contractDigest = :digest",
    ExpressionAttributeNames: { "#status": "status" },
    ExpressionAttributeValues: {
      ":code": { S: code },
      ":digest": { S: config.contractDigest },
      ":failed": { S: "FAILED" },
      ":updatedAt": { S: new Date().toISOString() },
    },
    Key: dynamoKey(),
    TableName: config.controlTable,
    UpdateExpression: "SET #status = :failed, lastErrorCode = :code, updatedAt = :updatedAt",
  }));
}

async function notifyFailure(code) {
  await sns.send(new PublishCommand({
    Message: JSON.stringify({
      contractDigest: config.contractDigest,
      errorCode: code,
      event: "scopeproof.recovery_backfill_failed",
      tenantId: config.tenantId,
    }),
    Subject: "Scopeproof evidence recovery requires intervention",
    TopicArn: config.operationsTopicArn,
  }));
}

function dynamoKey() {
  return { PK: { S: config.stateKey.PK }, SK: { S: config.stateKey.SK } };
}

function canonicalInstant(value) {
  if (typeof value !== "string") return false;
  const date = new Date(value);
  return Number.isFinite(date.getTime()) && date.toISOString() === value;
}

function recoveryFailure(code) {
  const error = new Error("Evidence recovery verification failed.");
  error.name = code;
  return error;
}

function safeFailureCode(error) {
  const code = String(error?.name ?? "RECOVERY_BACKFILL_FAILED");
  return /^[A-Z][A-Z0-9_]{2,63}$/.test(code) ? code : "RECOVERY_BACKFILL_FAILED";
}

function safeResult(status, state, job, verification) {
  return Object.freeze({
    contractDigest: config.contractDigest,
    destinationVersionsVerified: verification?.destinationVersionsVerified ?? state.destinationVersionsVerified,
    jobIdHash: state.jobId
      ? createHash("sha256").update(state.jobId).digest("hex").slice(0, 24)
      : undefined,
    progress: job ? Object.freeze({ failed: job.failed, succeeded: job.succeeded, total: job.total }) : undefined,
    status,
    tenantId: config.tenantId,
    verifiedThrough: verification?.verifiedThrough ?? state.verifiedThrough,
    versionsVerified: verification?.versionsVerified ?? state.versionsVerified,
  });
}

async function monitoredResult(status, state, job, verification) {
  const verifiedThrough = verification?.verifiedThrough ?? state.verifiedThrough;
  const metricData = [];
  if (canonicalInstant(verifiedThrough)) {
    metricData.push({
      Dimensions: [{ Name: "TenantId", Value: config.tenantId }],
      MetricName: "EvidenceVerificationFreshnessSeconds",
      Timestamp: new Date(),
      Unit: "Seconds",
      Value: Math.max(0, (Date.now() - Date.parse(verifiedThrough)) / 1_000),
    });
  }
  if (verification?.complete === true) {
    metricData.push({
      Dimensions: [{ Name: "TenantId", Value: config.tenantId }],
      MetricName: "EvidenceVerificationSuccess",
      Timestamp: new Date(),
      Unit: "Count",
      Value: 1,
    });
  }
  if (metricData.length > 0) {
    await cloudwatch.send(new PutMetricDataCommand({
      MetricData: metricData,
      Namespace: "Scopeproof/Recovery",
    }));
  }
  return safeResult(status, state, job, verification);
}
