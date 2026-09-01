import { createHash } from "node:crypto";

const tenantIdPattern = /^ten_[a-f0-9]{32}$/;
const bucketPattern = /^(?=.{3,63}$)(?!xn--)(?!.*\.\.)(?!.*-$)[a-z0-9][a-z0-9.-]*[a-z0-9]$/;
const roleArnPattern = /^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role\/scopeproof\/recovery\/[A-Za-z0-9+=,.@_-]{1,64}$/;
const topicArnPattern = /^arn:(aws|aws-us-gov|aws-cn):sns:([a-z]{2}(?:-gov)?-[a-z]+-\d):(\d{12}):[A-Za-z0-9_-]{1,256}$/;
const tablePattern = /^[A-Za-z0-9_.-]{3,255}$/;
const keyArnPattern = /^arn:(aws|aws-us-gov|aws-cn):kms:([a-z]{2}(?:-gov)?-[a-z]+-\d):(\d{12}):key\/(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|mrk-[0-9a-f]{32})$/;
const versionIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/;

function bounded(value, name, pattern) {
  const text = String(value ?? "");
  if (!pattern.test(text)) throw new Error(`Invalid ${name}.`);
  return text;
}

function exactKeys(value, expected, name) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`Invalid ${name}.`);
  const keys = Object.keys(value).sort();
  if (keys.length !== expected.length || keys.some((key, index) => key !== [...expected].sort()[index])) {
    throw new Error(`Invalid ${name}.`);
  }
}

function stableJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  throw new Error("Recovery contract contains a non-canonical value.");
}

export function parseRecoveryBackfillConfig(env) {
  const accountId = bounded(env.AWS_ACCOUNT_ID_EXPECTED, "AWS account", /^\d{12}$/);
  const region = bounded(env.AWS_REGION_EXPECTED, "AWS region", /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/);
  const recoveryRegion = bounded(env.RECOVERY_REGION_EXPECTED, "recovery region", /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/);
  const tenantId = bounded(env.TENANT_ID, "tenant id", tenantIdPattern);
  const sourceBucket = bounded(env.SOURCE_BUCKET_NAME, "source bucket", bucketPattern);
  const destinationBucket = bounded(env.DESTINATION_BUCKET_NAME, "destination bucket", bucketPattern);
  const reportBucket = bounded(env.REPORT_BUCKET_NAME, "report bucket", bucketPattern);
  const batchRoleArn = bounded(env.BATCH_ROLE_ARN, "Batch Operations role ARN", roleArnPattern);
  const destinationKmsKeyArn = bounded(env.DESTINATION_KMS_KEY_ARN, "destination KMS key ARN", keyArnPattern);
  const sourceKmsKeyArn = bounded(env.SOURCE_KMS_KEY_ARN, "source KMS key ARN", keyArnPattern);
  const auditSigningKeyArn = bounded(env.AUDIT_SIGNING_KEY_ARN, "audit signing key ARN", keyArnPattern);
  const operationsTopicArn = bounded(env.OPERATIONS_TOPIC_ARN, "operations topic ARN", topicArnPattern);
  const controlTable = bounded(env.CONTROL_TABLE_NAME, "control table", tablePattern);
  const maxVersionsPerRun = Number(env.MAX_VERSIONS_PER_RUN ?? 250);
  const verificationIntervalSeconds = Number(env.VERIFICATION_INTERVAL_SECONDS ?? 86_400);
  const ledgerSettleSeconds = Number(env.LEDGER_SETTLE_SECONDS ?? 900);
  const prefix = `tenants/${tenantId}/controls/`;
  const role = batchRoleArn.match(roleArnPattern);
  const kms = destinationKmsKeyArn.match(keyArnPattern);
  const auditKms = auditSigningKeyArn.match(keyArnPattern);
  const sourceKms = sourceKmsKeyArn.match(keyArnPattern);
  const topic = operationsTopicArn.match(topicArnPattern);
  if (
    sourceBucket === destinationBucket ||
    sourceBucket === reportBucket ||
    destinationBucket === reportBucket ||
    region === recoveryRegion ||
    !role || role[2] !== accountId ||
    !kms || kms[2] !== recoveryRegion || kms[3] !== accountId ||
    !auditKms || auditKms[2] !== region || auditKms[3] !== accountId ||
    !sourceKms || sourceKms[2] !== region || sourceKms[3] !== accountId ||
    !topic || topic[2] !== region || topic[3] !== accountId ||
    role[1] !== kms[1] || role[1] !== auditKms[1] || role[1] !== sourceKms[1] || role[1] !== topic[1] ||
    !Number.isInteger(maxVersionsPerRun) ||
    maxVersionsPerRun < 1 ||
    maxVersionsPerRun > 1_000 ||
    !Number.isInteger(verificationIntervalSeconds) ||
    verificationIntervalSeconds < 3_600 ||
    verificationIntervalSeconds > 604_800 ||
    !Number.isInteger(ledgerSettleSeconds) ||
    ledgerSettleSeconds < 900 ||
    ledgerSettleSeconds > 3_600
  ) {
    throw new Error("Recovery backfill resources are not safely bound.");
  }
  const facts = Object.freeze({
    accountId,
    auditSigningKeyArn,
    batchRoleArn,
    destinationBucket,
    destinationKmsKeyArn,
    prefix,
    reportBucket,
    sourceBucket,
    sourceKmsKeyArn,
    tenantId,
    ledgerSettleSeconds,
    verificationIntervalSeconds,
  });
  const contractDigest = createHash("sha256")
    .update(`scopeproof-recovery-backfill-v1\n${stableJson(facts)}`)
    .digest("hex");
  return Object.freeze({
    ...facts,
    contractDigest,
    controlTable,
    maxVersionsPerRun,
    operationsTopicArn,
    recoveryRegion,
    region,
    stateKey: Object.freeze({
      PK: `RECOVERY_STATE#TENANT#${tenantId}`,
      SK: `EVIDENCE_BACKFILL#${contractDigest}`,
    }),
  });
}

export function recoveryLedgerCutoff(nowIso, settleSeconds) {
  const now = new Date(nowIso);
  if (
    !Number.isFinite(now.getTime()) || now.toISOString() !== nowIso ||
    !Number.isInteger(settleSeconds) || settleSeconds < 900 || settleSeconds > 3_600
  ) {
    throw new Error("Recovery ledger cutoff inputs are invalid.");
  }
  return new Date(now.getTime() - settleSeconds * 1_000).toISOString();
}

export function legalHoldExpectationAtCutoff(current, cutoffIso) {
  const cutoff = new Date(cutoffIso);
  if (!Number.isFinite(cutoff.getTime()) || cutoff.toISOString() !== cutoffIso) {
    throw new Error("Legal-hold recovery cutoff is invalid.");
  }
  if (current === undefined) return Object.freeze({ deferred: false, status: "OFF" });
  if (!current || typeof current !== "object" || Array.isArray(current) ||
      !["ON", "OFF"].includes(current.status)) {
    throw new Error("Current legal-hold recovery state is invalid.");
  }
  const publishedAt = new Date(current.publishedAt);
  if (!Number.isFinite(publishedAt.getTime()) || publishedAt.toISOString() !== current.publishedAt) {
    throw new Error("Current legal-hold recovery state is invalid.");
  }
  return Date.parse(current.publishedAt) > Date.parse(cutoffIso)
    ? Object.freeze({ deferred: true })
    : Object.freeze({ deferred: false, status: current.status });
}

export function destinationInventoryPageAtCutoff(page, cutoffIso, prefix) {
  const cutoff = new Date(cutoffIso);
  if (
    !Number.isFinite(cutoff.getTime()) || cutoff.toISOString() !== cutoffIso ||
    typeof prefix !== "string" || prefix.length < 1 || prefix.length > 1_024
  ) {
    throw new Error("Destination inventory cutoff is invalid.");
  }
  if (!page || typeof page !== "object" || Array.isArray(page)) {
    throw new Error("Destination inventory page is invalid.");
  }
  const versions = [];
  const identities = new Set();
  for (const marker of page.DeleteMarkers ?? []) {
    const item = destinationInventoryIdentity(marker, prefix);
    if (item.lastModified.getTime() <= cutoff.getTime()) {
      const error = new Error("Destination delete marker prevents recovery verification.");
      error.name = "DestinationDeleteMarkerPresent";
      throw error;
    }
  }
  for (const version of page.Versions ?? []) {
    const item = destinationInventoryIdentity(version, prefix);
    const identity = `${item.key}\0${item.versionId}`;
    if (identities.has(identity)) throw new Error("Destination inventory page is invalid.");
    identities.add(identity);
    if (item.lastModified.getTime() <= cutoff.getTime()) {
      versions.push(Object.freeze({ key: item.key, versionId: item.versionId }));
    }
  }
  const complete = page.IsTruncated !== true;
  let nextKeyMarker;
  let nextVersionIdMarker;
  if (!complete) {
    nextKeyMarker = String(page.NextKeyMarker ?? "");
    nextVersionIdMarker = String(page.NextVersionIdMarker ?? "");
    if (
      !nextKeyMarker.startsWith(prefix) || nextKeyMarker.length > 1_024 ||
      !versionIdPattern.test(nextVersionIdMarker)
    ) {
      throw new Error("Destination inventory cursor is invalid.");
    }
  }
  return Object.freeze({
    complete,
    nextKeyMarker,
    nextVersionIdMarker,
    versions: Object.freeze(versions),
  });
}

function destinationInventoryIdentity(item, prefix) {
  if (!item || typeof item !== "object" || Array.isArray(item)) {
    throw new Error("Destination inventory entry is invalid.");
  }
  const key = String(item.Key ?? "");
  const versionId = String(item.VersionId ?? "");
  const lastModified = item.LastModified;
  if (
    !key.startsWith(prefix) || key.length > 1_024 ||
    !versionIdPattern.test(versionId) ||
    !(lastModified instanceof Date) || !Number.isFinite(lastModified.getTime())
  ) {
    throw new Error("Destination inventory entry is invalid.");
  }
  return Object.freeze({ key, lastModified, versionId });
}

export function assertDestinationVersionHasSource(destinationVersion, sourceHead) {
  const key = String(destinationVersion?.key ?? "");
  const versionId = String(destinationVersion?.versionId ?? "");
  if (
    key.length < 1 || key.length > 1_024 || !versionIdPattern.test(versionId) ||
    !sourceHead || typeof sourceHead !== "object" || Array.isArray(sourceHead) ||
    sourceHead.VersionId !== versionId ||
    !(sourceHead.LastModified instanceof Date) || !Number.isFinite(sourceHead.LastModified.getTime())
  ) {
    throw new Error("Destination object version is absent from the source namespace.");
  }
  return true;
}

export function buildCreateJobInput(config, cutoffIso) {
  const cutoff = new Date(cutoffIso);
  if (!Number.isFinite(cutoff.getTime()) || cutoff.toISOString() !== cutoffIso) {
    throw new Error("Recovery cutoff must be a canonical UTC instant.");
  }
  const clientRequestToken = createHash("sha256")
    .update(`scopeproof-recovery-backfill-job-v1\n${config.contractDigest}\n${cutoffIso}`)
    .digest("hex");
  return Object.freeze({
    AccountId: config.accountId,
    ClientRequestToken: clientRequestToken,
    ConfirmationRequired: false,
    Description: `Scopeproof immutable evidence backfill ${config.tenantId}`,
    ManifestGenerator: {
      S3JobManifestGenerator: {
        EnableManifestOutput: false,
        ExpectedBucketOwner: config.accountId,
        Filter: {
          CreatedBefore: cutoff,
          EligibleForReplication: true,
          KeyNameConstraint: { MatchAnyPrefix: [config.prefix] },
          ObjectReplicationStatuses: ["NONE", "FAILED"],
        },
        SourceBucket: `arn:aws:s3:::${config.sourceBucket}`,
      },
    },
    Operation: { S3ReplicateObject: {} },
    Priority: 10,
    Report: {
      Bucket: `arn:aws:s3:::${config.reportBucket}`,
      Enabled: true,
      Format: "Report_CSV_20180820",
      Prefix: `${config.tenantId}/${config.contractDigest}/`,
      ReportScope: "AllTasks",
    },
    RoleArn: config.batchRoleArn,
  });
}

export function evaluateBatchJob(details, expectedJobId) {
  exactKeys(details, ["Job"], "S3 Batch job response");
  const job = details.Job;
  if (!job || typeof job !== "object" || Array.isArray(job)) throw new Error("Invalid S3 Batch job.");
  if (job.JobId !== expectedJobId) throw new Error("S3 Batch returned another job.");
  const status = String(job.Status ?? "");
  if (!["Active", "Cancelling", "Cancelled", "Complete", "Completing", "Failed", "New", "Paused", "Pausing", "Preparing", "Ready", "Suspended"].includes(status)) {
    throw new Error("S3 Batch returned an unknown status.");
  }
  const summary = job.ProgressSummary ?? {};
  const total = Number(summary.TotalNumberOfTasks ?? 0);
  const succeeded = Number(summary.NumberOfTasksSucceeded ?? 0);
  const failed = Number(summary.NumberOfTasksFailed ?? 0);
  if (![total, succeeded, failed].every(Number.isSafeInteger) || [total, succeeded, failed].some((value) => value < 0) || succeeded + failed > total) {
    throw new Error("S3 Batch returned invalid progress counters.");
  }
  if (["Cancelled", "Failed", "Suspended"].includes(status)) {
    return Object.freeze({ failed, outcome: "failed", status, succeeded, total });
  }
  if (status === "Complete") {
    return Object.freeze({
      failed,
      outcome: failed === 0 && succeeded === total ? "complete" : "failed",
      status,
      succeeded,
      total,
    });
  }
  return Object.freeze({ failed, outcome: "pending", status, succeeded, total });
}

/**
 * A live-replication failure can arrive after the current Batch manifest was
 * generated. Once that job is terminal, the next generation must be allowed
 * to supersede it even when exact-version verification never reached
 * VERIFIED; otherwise a version that moved from PENDING to FAILED after
 * manifest generation can permanently strand repair.
 */
export function shouldRotateRecoveryRepair(state) {
  if (!state || typeof state !== "object" || Array.isArray(state)) return false;
  const terminalBatchStatuses = new Set(["Cancelled", "Complete", "Failed", "Suspended"]);
  return typeof state.repairRequestedAt === "string" &&
    typeof state.jobId === "string" &&
    (state.verificationStatus === "VERIFIED" || terminalBatchStatuses.has(state.batchStatus));
}

/**
 * VERIFIED is a point-in-time assertion, not a permanent terminal state. A
 * scheduled invocation advances the cutoff after the configured interval so
 * evidence promoted after the preceding cutoff is eventually covered by an
 * exact-version verification generation.
 */
export function shouldStartPeriodicVerification(state, nowIso, intervalSeconds) {
  if (!state || typeof state !== "object" || Array.isArray(state)) return false;
  const now = new Date(nowIso);
  const verifiedThrough = new Date(state.verifiedThrough);
  if (
    !Number.isFinite(now.getTime()) || now.toISOString() !== nowIso ||
    !Number.isFinite(verifiedThrough.getTime()) || verifiedThrough.toISOString() !== state.verifiedThrough ||
    !Number.isInteger(intervalSeconds) || intervalSeconds < 3_600 || intervalSeconds > 604_800 ||
    state.verificationStatus !== "VERIFIED" ||
    typeof state.jobId !== "string" ||
    state.repairRequestedAt !== undefined
  ) return false;
  return now.getTime() - verifiedThrough.getTime() >= intervalSeconds * 1_000;
}

export function sha256HexFromCanonicalBase64(value) {
  if (
    typeof value !== "string" ||
    !/^(?:[A-Za-z0-9+/]{4}){10}[A-Za-z0-9+/]{3}=$/.test(value)
  ) {
    throw new Error("Object SHA-256 checksum is not canonical base64.");
  }
  const digest = Buffer.from(value, "base64");
  if (digest.byteLength !== 32 || digest.toString("base64") !== value) {
    throw new Error("Object SHA-256 checksum is not canonical base64.");
  }
  return digest.toString("hex");
}

export function assertReplicaMatches(source, replica, receipt, config, expectedLegalHoldStatus) {
  exactKeys(source, ["checksumSha256", "contentLength", "contentType", "key", "legalHold", "metadata", "objectLockMode", "retainUntil", "sseKmsKeyArn", "versionId"], "source version facts");
  exactKeys(replica, ["checksumSha256", "contentLength", "contentType", "key", "legalHold", "metadata", "objectLockMode", "retainUntil", "sseKmsKeyArn", "versionId"], "replica version facts");
  exactKeys(receipt, [
    "byteSize", "contentType", "controlId", "databaseIdempotencyDigest", "databaseReceiptId",
    "destinationBucket", "destinationKey", "destinationVersionId", "evidenceId", "intentId",
    "kind", "kmsKeyArn", "objectLockMode", "receiptHash", "retainUntil", "sha256",
    "sourceVersionId", "status", "tenantId", "uploadedAt",
  ], "promotion receipt facts");
  const sourceChecksum = sha256HexFromCanonicalBase64(source.checksumSha256);
  const replicaChecksum = sha256HexFromCanonicalBase64(replica.checksumSha256);
  const expectedReceiptHash = createHash("sha256")
    .update(`${config.tenantId}\0${receipt.intentId}\0${receipt.sourceVersionId}`)
    .digest("hex");
  if (
    receipt.kind !== "EvidencePromotionReceipt" ||
    receipt.status !== "COMPLETE" ||
    receipt.tenantId !== config.tenantId ||
    receipt.receiptHash !== expectedReceiptHash ||
    receipt.destinationBucket !== config.sourceBucket ||
    receipt.destinationKey !== source.key ||
    receipt.destinationVersionId !== source.versionId ||
    receipt.byteSize !== source.contentLength ||
    receipt.contentType !== source.contentType ||
    receipt.controlId !== source.metadata?.controlId ||
    receipt.evidenceId !== source.metadata?.resourceId ||
    receipt.kmsKeyArn !== config.sourceKmsKeyArn ||
    receipt.objectLockMode !== source.objectLockMode ||
    receipt.retainUntil !== source.retainUntil ||
    !/^rcp_[a-f0-9]{32}$/.test(receipt.databaseReceiptId) ||
    !/^[a-f0-9]{64}$/.test(receipt.databaseIdempotencyDigest) ||
    !/^[a-f0-9]{64}$/.test(receipt.sha256) ||
    source.key !== replica.key ||
    source.versionId !== replica.versionId ||
    source.contentLength !== replica.contentLength ||
    source.contentType !== replica.contentType ||
    source.checksumSha256 !== replica.checksumSha256 ||
    sourceChecksum !== receipt.sha256 ||
    replicaChecksum !== receipt.sha256 ||
    source.metadata?.sha256 !== receipt.sha256 ||
    replica.metadata?.sha256 !== receipt.sha256 ||
    source.metadata?.tenantId !== config.tenantId ||
    replica.metadata?.tenantId !== config.tenantId ||
    source.metadata?.intentId !== receipt.intentId ||
    replica.metadata?.intentId !== receipt.intentId ||
    source.metadata?.sourceVersionId !== receipt.sourceVersionId ||
    replica.metadata?.sourceVersionId !== receipt.sourceVersionId ||
    source.metadata?.uploadedAt !== receipt.uploadedAt ||
    replica.metadata?.uploadedAt !== receipt.uploadedAt ||
    source.metadata?.controlId !== replica.metadata?.controlId ||
    source.metadata?.resourceId !== replica.metadata?.resourceId ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(String(source.metadata?.controlId ?? "")) ||
    !/^evd_[a-f0-9]{32}$/.test(String(source.metadata?.resourceId ?? "")) ||
    source.objectLockMode !== replica.objectLockMode ||
    source.retainUntil !== replica.retainUntil ||
    source.legalHold !== replica.legalHold ||
    source.sseKmsKeyArn !== config.sourceKmsKeyArn ||
    replica.sseKmsKeyArn !== config.destinationKmsKeyArn
  ) {
    throw new Error("Exact-version recovery replica verification failed.");
  }
  if (
    expectedLegalHoldStatus !== undefined &&
    (!new Set(["ON", "OFF"]).has(expectedLegalHoldStatus) ||
      source.legalHold !== expectedLegalHoldStatus || replica.legalHold !== expectedLegalHoldStatus)
  ) {
    throw new Error("Exact-version recovery legal-hold verification failed.");
  }
  return true;
}
