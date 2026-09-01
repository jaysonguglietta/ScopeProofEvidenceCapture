import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import {
  assertDestinationVersionHasSource,
  assertReplicaMatches,
  buildCreateJobInput,
  destinationInventoryPageAtCutoff,
  evaluateBatchJob,
  legalHoldExpectationAtCutoff,
  parseRecoveryBackfillConfig,
  recoveryLedgerCutoff,
  sha256HexFromCanonicalBase64,
  shouldStartPeriodicVerification,
  shouldRotateRecoveryRepair,
} from "../infra/aws/cdk/runtime/reconcile-recovery/backfill-contract.mjs";
import {
  buildPromotionRecoveryChangeItem,
  legalHoldRecoveryCurrentKey,
  parseLegalHoldRecoveryCurrentItem,
  parseRecoveryChangeItem,
  publishLegalHoldRecoveryChange,
  recoveryChangeBounds,
} from "../infra/aws/cdk/runtime/reconcile-recovery/change-ledger.mjs";
import { commitAuditBeforeRecovery } from "../infra/aws/cdk/runtime/reconcile-legal-holds/audit-before-recovery.mjs";
import { digestHex, stableJson } from "../infra/aws/cdk/runtime/promote-evidence/promotion-receipt.mjs";
import {
  latestCompletedRecoveryPointAge,
  parseAuroraFreshnessConfig,
} from "../infra/aws/cdk/runtime/monitor-aurora-recovery/freshness-contract.mjs";

const env = Object.freeze({
  AWS_ACCOUNT_ID_EXPECTED: "111111111111",
  AWS_REGION_EXPECTED: "us-east-1",
  AUDIT_SIGNING_KEY_ARN: "arn:aws:kms:us-east-1:111111111111:key/11111111-1111-4111-8111-111111111111",
  BATCH_ROLE_ARN: "arn:aws:iam::111111111111:role/scopeproof/recovery/sp-acme-evidence-batch",
  CONTROL_TABLE_NAME: "scopeproof-control",
  DESTINATION_BUCKET_NAME: "sp-recovery-evidence-acme",
  DESTINATION_KMS_KEY_ARN: "arn:aws:kms:us-west-2:111111111111:key/22222222-2222-4222-8222-222222222222",
  MAX_VERSIONS_PER_RUN: "250",
  LEDGER_SETTLE_SECONDS: "900",
  OPERATIONS_TOPIC_ARN: "arn:aws:sns:us-east-1:111111111111:scopeproof-operations",
  RECOVERY_REGION_EXPECTED: "us-west-2",
  REPORT_BUCKET_NAME: "sp-evidence-recovery-reports-acme",
  SOURCE_BUCKET_NAME: "sp-primary-evidence-acme",
  SOURCE_KMS_KEY_ARN: "arn:aws:kms:us-east-1:111111111111:key/33333333-3333-4333-8333-333333333333",
  TENANT_ID: "ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  VERIFICATION_INTERVAL_SECONDS: "86400",
});

test("recovery backfill contract is deterministic and source-region bound", () => {
  const first = parseRecoveryBackfillConfig(env);
  const second = parseRecoveryBackfillConfig({ ...env });
  assert.equal(first.contractDigest, second.contractDigest);
  assert.match(first.contractDigest, /^[a-f0-9]{64}$/);
  assert.equal(first.stateKey.PK, `RECOVERY_STATE#TENANT#${env.TENANT_ID}`);
  assert.equal(first.stateKey.SK, `EVIDENCE_BACKFILL#${first.contractDigest}`);
  assert.throws(
    () => parseRecoveryBackfillConfig({ ...env, RECOVERY_REGION_EXPECTED: "us-east-1" }),
    /not safely bound/,
  );
  assert.throws(
    () => parseRecoveryBackfillConfig({ ...env, AUDIT_SIGNING_KEY_ARN: env.AUDIT_SIGNING_KEY_ARN.replace("us-east-1", "us-west-2") }),
    /not safely bound/,
  );
  assert.throws(
    () => parseRecoveryBackfillConfig({ ...env, SOURCE_KMS_KEY_ARN: env.SOURCE_KMS_KEY_ARN.replace("us-east-1", "us-west-2") }),
    /not safely bound/,
  );
  assert.throws(
    () => parseRecoveryBackfillConfig({ ...env, LEDGER_SETTLE_SECONDS: "899" }),
    /not safely bound/,
  );
  assert.throws(
    () => parseRecoveryBackfillConfig({ ...env, DESTINATION_KMS_KEY_ARN: env.DESTINATION_KMS_KEY_ARN.replace("us-west-2", "us-east-1") }),
    /not safely bound/,
  );
  assert.throws(
    () => parseRecoveryBackfillConfig({ ...env, MAX_VERSIONS_PER_RUN: "1001" }),
    /not safely bound/,
  );
  assert.doesNotThrow(() => parseRecoveryBackfillConfig({
    ...env,
    DESTINATION_KMS_KEY_ARN: "arn:aws:kms:us-west-2:111111111111:key/mrk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  }));
});

test("recovery ledger cutoff is canonical and exceeds publisher timeout safety margin", () => {
  assert.equal(
    recoveryLedgerCutoff("2026-08-27T12:30:00.000Z", 900),
    "2026-08-27T12:15:00.000Z",
  );
  assert.deepEqual(
    recoveryChangeBounds("2026-08-26T12:15:00.000Z", "2026-08-27T12:15:00.000Z"),
    {
      after: "CHANGE#2026-08-26T12:15:00.000Z~",
      cutoff: "CHANGE#2026-08-27T12:15:00.000Z~",
    },
  );
  assert.throws(() => recoveryLedgerCutoff("2026-08-27", 900), /invalid/);
  assert.throws(
    () => recoveryChangeBounds("2026-08-27T12:15:00.000Z", "2026-08-27T12:15:00.000Z"),
    /interval/,
  );
});

test("bootstrap legal-hold expectations bind current state and defer a later ON-to-OFF transition", () => {
  const cutoff = "2026-08-27T12:15:00.000Z";
  assert.deepEqual(legalHoldExpectationAtCutoff(undefined, cutoff), {
    deferred: false,
    status: "OFF",
  });
  assert.deepEqual(legalHoldExpectationAtCutoff({
    publishedAt: "2026-08-27T12:14:59.999Z",
    status: "ON",
  }, cutoff), {
    deferred: false,
    status: "ON",
  });
  assert.deepEqual(legalHoldExpectationAtCutoff({
    publishedAt: "2026-08-27T12:16:00.000Z",
    status: "OFF",
  }, cutoff), { deferred: true });
  assert.deepEqual(legalHoldExpectationAtCutoff({
    publishedAt: "2026-08-27T12:16:00.000Z",
    status: "OFF",
  }, "2026-08-27T12:16:00.000Z"), {
    deferred: false,
    status: "OFF",
  });
  assert.throws(
    () => legalHoldExpectationAtCutoff({ publishedAt: cutoff, status: "INVALID" }, cutoff),
    /invalid/,
  );
});

test("destination inventory prevents VERIFIED on delete markers and orphan exact versions", () => {
  const prefix = `tenants/${env.TENANT_ID}/controls/`;
  const cutoff = "2026-08-27T12:15:00.000Z";
  const exact = {
    Key: `${prefix}PCI-1/evidence/evd_${"a".repeat(32)}.png`,
    LastModified: new Date("2026-08-27T12:14:00.000Z"),
    VersionId: "exact-version-1",
  };
  assert.throws(
    () => destinationInventoryPageAtCutoff({
      DeleteMarkers: [exact],
      IsTruncated: false,
      Versions: [],
    }, cutoff, prefix),
    /delete marker prevents recovery verification/,
  );
  const page = destinationInventoryPageAtCutoff({
    DeleteMarkers: [{ ...exact, LastModified: new Date("2026-08-27T12:16:00.000Z") }],
    IsTruncated: true,
    NextKeyMarker: exact.Key,
    NextVersionIdMarker: exact.VersionId,
    Versions: [
      exact,
      { ...exact, LastModified: new Date("2026-08-27T12:16:00.000Z"), VersionId: "future-version-2" },
    ],
  }, cutoff, prefix);
  assert.deepEqual(page, {
    complete: false,
    nextKeyMarker: exact.Key,
    nextVersionIdMarker: exact.VersionId,
    versions: [{ key: exact.Key, versionId: exact.VersionId }],
  });
  assert.equal(assertDestinationVersionHasSource(page.versions[0], {
    LastModified: new Date("2026-08-27T12:13:00.000Z"),
    VersionId: exact.VersionId,
  }), true);
  assert.throws(
    () => assertDestinationVersionHasSource(page.versions[0], undefined),
    /absent from the source namespace/,
  );
  assert.throws(
    () => assertDestinationVersionHasSource(page.versions[0], {
      LastModified: new Date("2026-08-27T12:13:00.000Z"),
      VersionId: "destination-only-version",
    }),
    /absent from the source namespace/,
  );
});

test("only a completed destination inventory can advance the durable recovery watermark", () => {
  const runtime = readFileSync(
    "infra/aws/cdk/runtime/reconcile-recovery/index.mjs",
    "utf8",
  );
  const sourceVerification = runtime.slice(
    runtime.indexOf("async function verifySourceVersionPage"),
    runtime.indexOf("async function verifyRecoveryChangePage"),
  );
  const changeVerification = runtime.slice(
    runtime.indexOf("async function verifyRecoveryChangePage"),
    runtime.indexOf("async function verifyDestinationVersionPage"),
  );
  const destinationVerification = runtime.slice(
    runtime.indexOf("async function verifyDestinationVersionPage"),
    runtime.indexOf("async function readCurrentLegalHoldExpectation"),
  );
  assert.doesNotMatch(sourceVerification, /verifiedThrough =/);
  assert.doesNotMatch(changeVerification, /verifiedThrough =/);
  assert.match(sourceVerification, /else \{[\s\S]*await verifyExactVersion\(version\.Key, version\.VersionId\);/);
  assert.match(changeVerification, /else \{[\s\S]*await verifyExactVersion\(change\.key, change\.versionId\);/);
  assert.match(destinationVerification, /DESTINATION_DELETE_MARKER_PRESENT/);
  assert.match(destinationVerification, /DESTINATION_ORPHAN_VERSION_PRESENT/);
  assert.match(destinationVerification, /verifiedThrough = :cutoff/);
  assert.ok(
    destinationVerification.indexOf("DESTINATION_ORPHAN_VERSION_PRESENT") <
      destinationVerification.indexOf("verifiedThrough = :cutoff"),
  );
});

test("S3 Batch request selects only exact pre-cutoff NONE and FAILED evidence versions", () => {
  const config = parseRecoveryBackfillConfig(env);
  const cutoff = "2026-08-27T12:34:56.789Z";
  const input = buildCreateJobInput(config, cutoff);
  assert.deepEqual(input.Operation, { S3ReplicateObject: {} });
  assert.match(input.ClientRequestToken, /^[a-f0-9]{64}$/);
  assert.notEqual(input.ClientRequestToken, config.contractDigest);
  assert.equal(
    input.ClientRequestToken,
    buildCreateJobInput(config, cutoff).ClientRequestToken,
  );
  assert.equal(input.ConfirmationRequired, false);
  assert.equal(input.RoleArn, env.BATCH_ROLE_ARN);
  assert.deepEqual(
    input.ManifestGenerator.S3JobManifestGenerator.Filter.ObjectReplicationStatuses,
    ["NONE", "FAILED"],
  );
  assert.equal(input.ManifestGenerator.S3JobManifestGenerator.Filter.EligibleForReplication, true);
  assert.deepEqual(
    input.ManifestGenerator.S3JobManifestGenerator.Filter.KeyNameConstraint.MatchAnyPrefix,
    [`tenants/${env.TENANT_ID}/controls/`],
  );
  assert.equal(input.ManifestGenerator.S3JobManifestGenerator.Filter.CreatedBefore.toISOString(), cutoff);
  assert.equal(input.Report.ReportScope, "AllTasks");
  assert.throws(() => buildCreateJobInput(config, "2026-08-27"), /canonical UTC instant/);
});

test("S3 Batch completion fails closed on terminal failures and inconsistent counters", () => {
  const jobId = "11111111-2222-4333-8444-555555555555";
  assert.equal(evaluateBatchJob({ Job: {
    JobId: jobId,
    ProgressSummary: { NumberOfTasksFailed: 0, NumberOfTasksSucceeded: 12, TotalNumberOfTasks: 12 },
    Status: "Complete",
  } }, jobId).outcome, "complete");
  assert.equal(evaluateBatchJob({ Job: {
    JobId: jobId,
    ProgressSummary: { NumberOfTasksFailed: 1, NumberOfTasksSucceeded: 11, TotalNumberOfTasks: 12 },
    Status: "Complete",
  } }, jobId).outcome, "failed");
  assert.equal(evaluateBatchJob({ Job: {
    JobId: jobId,
    ProgressSummary: { NumberOfTasksFailed: 0, NumberOfTasksSucceeded: 2, TotalNumberOfTasks: 12 },
    Status: "Active",
  } }, jobId).outcome, "pending");
  assert.throws(() => evaluateBatchJob({ Job: {
    JobId: jobId,
    ProgressSummary: { NumberOfTasksFailed: 1, NumberOfTasksSucceeded: 12, TotalNumberOfTasks: 12 },
    Status: "Active",
  } }, jobId), /invalid progress/);
  assert.throws(() => evaluateBatchJob({ Job: { JobId: "another-job", Status: "Complete" } }, jobId), /another job/);
});

test("a terminal manifest cannot strand a later live-replication repair", () => {
  const repair = {
    batchStatus: "Complete",
    jobId: "11111111-2222-4333-8444-555555555555",
    repairRequestedAt: "2026-08-27T12:35:56.789Z",
    verificationStatus: "VERIFYING",
  };
  assert.equal(shouldRotateRecoveryRepair(repair), true);
  assert.equal(shouldRotateRecoveryRepair({ ...repair, batchStatus: "Failed" }), true);
  assert.equal(shouldRotateRecoveryRepair({ ...repair, batchStatus: "Active" }), false);
  assert.equal(shouldRotateRecoveryRepair({ ...repair, batchStatus: "Active", verificationStatus: "VERIFIED" }), true);
  assert.equal(shouldRotateRecoveryRepair({ ...repair, repairRequestedAt: undefined }), false);
});

test("verified recovery rotates after a bounded interval and preserves repair priority", () => {
  const state = {
    jobId: "11111111-2222-4333-8444-555555555555",
    verificationStatus: "VERIFIED",
    verifiedThrough: "2026-08-27T00:00:00.000Z",
  };
  assert.equal(shouldStartPeriodicVerification(state, "2026-08-28T00:00:00.000Z", 86_400), true);
  assert.equal(shouldStartPeriodicVerification(state, "2026-08-27T23:59:59.999Z", 86_400), false);
  assert.equal(shouldStartPeriodicVerification({ ...state, repairRequestedAt: "2026-08-27T12:00:00.000Z" }, "2026-08-28T00:00:00.000Z", 86_400), false);
  assert.equal(shouldStartPeriodicVerification({ ...state, verifiedThrough: "not-an-instant" }, "2026-08-28T00:00:00.000Z", 86_400), false);
});

test("exact-version recovery binds canonical checksums to promotion receipt, metadata, lock, and KMS", () => {
  const config = parseRecoveryBackfillConfig(env);
  const sha256 = "a".repeat(64);
  const checksumSha256 = Buffer.from(sha256, "hex").toString("base64");
  const intentId = "upl_" + "b".repeat(32);
  const sourceVersionId = "q1.opaque-version";
  const versionId = "v1.opaque-version";
  const source = Object.freeze({
    checksumSha256,
    contentLength: 42,
    contentType: "image/png",
    key: `${config.prefix}PCI-1/evidence/evd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.png`,
    legalHold: "ON",
    metadata: {
      controlId: "PCI-1",
      intentId,
      resourceId: "evd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      sha256,
      sourceVersionId,
      tenantId: config.tenantId,
      uploadedAt: "2026-08-27T12:00:00.000Z",
    },
    objectLockMode: "COMPLIANCE",
    retainUntil: "2027-08-27T12:34:56.789Z",
    sseKmsKeyArn: config.sourceKmsKeyArn,
    versionId,
  });
  const replica = Object.freeze({
    ...source,
    sseKmsKeyArn: config.destinationKmsKeyArn,
  });
  const receiptHash = createHash("sha256")
    .update(`${config.tenantId}\0${intentId}\0${sourceVersionId}`)
    .digest("hex");
  const receipt = Object.freeze({
    byteSize: source.contentLength,
    contentType: source.contentType,
    controlId: source.metadata.controlId,
    databaseIdempotencyDigest: "c".repeat(64),
    databaseReceiptId: "rcp_" + "d".repeat(32),
    destinationBucket: config.sourceBucket,
    destinationKey: source.key,
    destinationVersionId: versionId,
    evidenceId: source.metadata.resourceId,
    intentId,
    kind: "EvidencePromotionReceipt",
    kmsKeyArn: config.sourceKmsKeyArn,
    objectLockMode: source.objectLockMode,
    receiptHash,
    retainUntil: source.retainUntil,
    sha256,
    sourceVersionId,
    status: "COMPLETE",
    tenantId: config.tenantId,
    uploadedAt: source.metadata.uploadedAt,
  });
  assert.equal(sha256HexFromCanonicalBase64(checksumSha256), sha256);
  assert.equal(assertReplicaMatches(source, replica, receipt, config), true);
  assert.equal(assertReplicaMatches(source, replica, receipt, config, "ON"), true);
  const bootstrapExpectation = legalHoldExpectationAtCutoff({
    publishedAt: "2026-08-27T12:14:59.999Z",
    status: "ON",
  }, "2026-08-27T12:15:00.000Z");
  assert.equal(bootstrapExpectation.deferred, false);
  assert.throws(
    () => assertReplicaMatches(
      { ...source, legalHold: "OFF" },
      { ...replica, legalHold: "OFF" },
      receipt,
      config,
      bootstrapExpectation.status,
    ),
    /legal-hold verification failed/,
  );
  assert.throws(
    () => assertReplicaMatches(source, { ...replica, versionId: "v2" }, receipt, config),
    /verification failed/,
  );
  assert.throws(
    () => assertReplicaMatches(source, { ...replica, legalHold: "OFF" }, receipt, config),
    /verification failed/,
  );
  assert.throws(
    () => assertReplicaMatches(source, { ...replica, sseKmsKeyArn: "arn:aws:kms:us-west-2:111111111111:key/33333333-3333-4333-8333-333333333333" }, receipt, config),
    /verification failed/,
  );
  assert.throws(
    () => assertReplicaMatches({ ...source, sseKmsKeyArn: config.destinationKmsKeyArn }, replica, receipt, config),
    /verification failed/,
  );
  assert.throws(
    () => assertReplicaMatches(source, replica, { ...receipt, kmsKeyArn: config.destinationKmsKeyArn }, config),
    /verification failed/,
  );
  assert.throws(
    () => assertReplicaMatches(source, { ...replica, checksumSha256: Buffer.from("b".repeat(64), "hex").toString("base64") }, receipt, config),
    /verification failed/,
  );
  assert.throws(() => sha256HexFromCanonicalBase64(checksumSha256.replace(/=$/, "")), /canonical base64/);
});

test("promotion and legal-hold changes are strict immutable time-ordered ledger records", async () => {
  const tenantId = env.TENANT_ID;
  const operationFacts = {
    bucket: env.SOURCE_BUCKET_NAME,
    changedAt: "2026-08-27T12:00:00.000Z",
    controlId: "PCI-1",
    evidenceId: `evd_${"a".repeat(32)}`,
    expectedHoldRevision: 0,
    holdId: `hld_${"b".repeat(32)}`,
    key: `tenants/${tenantId}/controls/PCI-1/evidence/evd_${"a".repeat(32)}.png`,
    kind: "LEGAL",
    operationId: `lho_${"c".repeat(32)}`,
    reason: "External auditor preservation request",
    requestedBy: `usr_${"d".repeat(32)}`,
    schemaVersion: 2,
    status: "ON",
    tenantId,
    versionId: "exact-version-1",
  } as const;
  const canonicalRequest = stableJson(operationFacts);
  const operation = Object.freeze({
    ...operationFacts,
    canonicalRequest,
    requestDigest: digestHex(`scopeproof-legal-hold-request-v2\n${canonicalRequest}`),
  });
  const auditProof = (operationId: string) => {
    const eventHash = "9".repeat(64);
    const occurredAt = "2026-08-27T12:05:00.000Z";
    const canonicalPayload = stableJson({
      action: "evidence.legal_hold_applied",
      domain: "scopeproof-audit-receipt-v1",
      eventHash,
      eventId: `evt_${digestHex(`scopeproof-legal-hold-audit-v1\0${operationId}`).slice(0, 32)}`,
      occurredAt,
      outcome: "succeeded",
      previousHash: "GENESIS",
      requestId: `legal-hold-${operationId}`,
      resourceId: operationId,
      resourceType: "legal_hold_operation",
      schemaVersion: 1,
      sequence: 1,
      signedAt: occurredAt,
      tenantId,
    });
    return Object.freeze({
      canonicalPayload,
      eventHash,
      keyArn: env.AUDIT_SIGNING_KEY_ARN,
      payloadSha256: digestHex(`scopeproof-audit-receipt-v1\0${canonicalPayload}`),
      signature: Buffer.alloc(384, 7).toString("base64"),
      signingAlgorithm: "RSASSA_PSS_SHA_256",
    });
  };

  class GetCommand {
    readonly input: Record<string, unknown>;
    constructor(input: Record<string, unknown>) { this.input = input; }
  }
  class TransactCommand {
    readonly input: Record<string, unknown>;
    constructor(input: Record<string, unknown>) { this.input = input; }
  }
  const items = new Map<string, Readonly<Record<string, { S?: string; N?: string }>>>();
  let loseFirstCommitResponse = true;
  const client = {
    async send(command: GetCommand | TransactCommand) {
      if (command instanceof GetCommand) {
        const key = command.input.Key as { PK: { S: string }; SK: { S: string } };
        return { Item: items.get(`${key.PK.S}\0${key.SK.S}`) };
      }
      const transaction = command.input.TransactItems as readonly {
        Put: { ConditionExpression: string; Item: Readonly<Record<string, { S?: string; N?: string }>> };
      }[];
      for (const entry of transaction) {
        const item = entry.Put.Item;
        const key = `${item.PK.S}\0${item.SK.S}`;
        if (items.has(key) && entry.Put.ConditionExpression.includes("attribute_not_exists")) {
          throw Object.assign(new Error("conflict"), { name: "TransactionCanceledException" });
        }
      }
      for (const entry of transaction) {
        const item = entry.Put.Item;
        items.set(`${item.PK.S}\0${item.SK.S}`, item);
      }
      if (loseFirstCommitResponse) {
        loseFirstCommitResponse = false;
        throw new Error("response lost after commit");
      }
      return {};
    },
  };
  const input = {
    audit: auditProof(operation.operationId),
    client,
    GetItemCommand: GetCommand,
    TransactWriteItemsCommand: TransactCommand,
    tableName: env.CONTROL_TABLE_NAME,
    tenantId,
    operation,
    appliedAt: "2026-08-27T12:05:00.000Z",
    now: new Date("2026-08-27T12:10:00.000Z"),
  };
  const first = await publishLegalHoldRecoveryChange(input);
  assert.equal(first.publishedAt, "2026-08-27T12:10:00.000Z");
  assert.equal(items.size, 3);
  const retried = await publishLegalHoldRecoveryChange({
    ...input,
    now: new Date("2026-08-27T12:20:00.000Z"),
  });
  assert.deepEqual(retried, first);
  assert.equal(items.size, 3);
  const legalItem = items.get(`RECOVERY#TENANT#${tenantId}\0${first.changeKey}`);
  assert.ok(legalItem);
  assert.deepEqual(parseRecoveryChangeItem(legalItem, {
    sourceBucket: env.SOURCE_BUCKET_NAME,
    tenantId,
  }), {
    appliedAt: "2026-08-27T12:05:00.000Z",
    audit: auditProof(operation.operationId),
    bucket: env.SOURCE_BUCKET_NAME,
    changeType: "LEGAL_HOLD",
    currentKey: legalHoldRecoveryCurrentKey(operation),
    key: operation.key,
    operationId: operation.operationId,
    publishedAt: first.publishedAt,
    requestDigest: operation.requestDigest,
    status: "ON",
    tenantId,
    versionId: operation.versionId,
  });
  const currentItem = items.get(`RECOVERY#TENANT#${tenantId}\0${legalHoldRecoveryCurrentKey(operation)}`);
  assert.ok(currentItem);
  assert.equal(parseLegalHoldRecoveryCurrentItem(currentItem, {
    key: operation.key,
    sourceBucket: env.SOURCE_BUCKET_NAME,
    tenantId,
    versionId: operation.versionId,
  }).status, "ON");
  assert.throws(
    () => parseLegalHoldRecoveryCurrentItem({ ...currentItem, status: { S: "OFF" } }, {
      key: operation.key,
      sourceBucket: env.SOURCE_BUCKET_NAME,
      tenantId,
      versionId: operation.versionId,
    }),
    /invalid/,
  );

  const releaseFacts = {
    ...operationFacts,
    changedAt: "2026-08-27T12:30:00.000Z",
    expectedHoldRevision: 1,
    operationId: `lho_${"f".repeat(32)}`,
    status: "OFF" as const,
  };
  const releaseCanonicalRequest = stableJson(releaseFacts);
  const release = Object.freeze({
    ...releaseFacts,
    canonicalRequest: releaseCanonicalRequest,
    requestDigest: digestHex(`scopeproof-legal-hold-request-v2\n${releaseCanonicalRequest}`),
  });
  const releasePublication = await publishLegalHoldRecoveryChange({
    ...input,
    audit: auditProof(release.operationId),
    operation: release,
    appliedAt: "2026-08-27T12:35:00.000Z",
    now: new Date("2026-08-27T12:40:00.000Z"),
  });
  assert.equal(items.size, 5);
  assert.notEqual(releasePublication.changeKey, first.changeKey);
  const releasedCurrent = items.get(`RECOVERY#TENANT#${tenantId}\0${legalHoldRecoveryCurrentKey(operation)}`);
  assert.ok(releasedCurrent);
  assert.equal(parseLegalHoldRecoveryCurrentItem(releasedCurrent, {
    key: operation.key,
    sourceBucket: env.SOURCE_BUCKET_NAME,
    tenantId,
    versionId: operation.versionId,
  }).status, "OFF");
  assert.deepEqual(await publishLegalHoldRecoveryChange({
    ...input,
    now: new Date("2026-08-27T12:45:00.000Z"),
  }), first);

  const receiptHash = "e".repeat(64);
  const promotion = buildPromotionRecoveryChangeItem({
    tenantId,
    receiptHash,
    publishedAt: "2026-08-27T12:11:00.000Z",
    facts: {
      tenantId,
      evidenceBucket: env.SOURCE_BUCKET_NAME,
      evidenceKey: operation.key,
      evidenceVersionId: operation.versionId,
    },
  });
  assert.equal(
    parseRecoveryChangeItem(promotion, { sourceBucket: env.SOURCE_BUCKET_NAME, tenantId }).receiptHash,
    receiptHash,
  );
  assert.throws(
    () => parseRecoveryChangeItem({ ...promotion, bucket: { S: "attacker-bucket" } }, {
      sourceBucket: env.SOURCE_BUCKET_NAME,
      tenantId,
    }),
    /invalid/,
  );
});

test("KMS or durable audit failure after S3 cannot publish legal-hold recovery state", async () => {
  let publications = 0;
  await assert.rejects(commitAuditBeforeRecovery({
    async commitAudit() { throw new Error("KMS signing unavailable after S3 application"); },
    async publishRecovery() { publications += 1; },
  }), /KMS signing unavailable/);
  assert.equal(publications, 0);

  await assert.rejects(commitAuditBeforeRecovery({
    async commitAudit() { throw new Error("signed audit database commit ambiguous"); },
    async publishRecovery() { publications += 1; },
  }), /audit database commit ambiguous/);
  assert.equal(publications, 0);
});

test("a recovery publication failure reuses the exact committed audit on the next sweep", async () => {
  const committed = { eventHash: "a".repeat(64), sequence: 7, receipt: { schemaVersion: 1 } };
  const advancedAuditHeadSequence = 8;
  let auditAttempts = 0;
  let publicationAttempts = 0;
  let recoveryAcknowledged = false;
  const runSweep = async () => {
    if (recoveryAcknowledged) return "NO_WORK";
    return await commitAuditBeforeRecovery({
    async commitAudit() {
      auditAttempts += 1;
      // The next sweep's audit head has advanced past this deterministic event.
      // It must replay sequence 7 rather than synthesize sequence 9 with the
      // same event ID, which Aurora correctly rejects as a conflict.
      assert.notEqual(committed.sequence, advancedAuditHeadSequence + 1);
      return committed;
    },
    async publishRecovery(audit) {
      assert.equal(audit, committed);
      publicationAttempts += 1;
      if (publicationAttempts === 1) throw new Error("DynamoDB publication unavailable");
      recoveryAcknowledged = true;
    },
    });
  };

  await assert.rejects(runSweep(), /DynamoDB publication unavailable/);
  assert.equal(auditAttempts, 1);
  assert.equal(publicationAttempts, 1);
  assert.equal(recoveryAcknowledged, false);
  assert.equal(await runSweep(), committed);
  assert.equal(auditAttempts, 2);
  assert.equal(publicationAttempts, 2);
  assert.equal(recoveryAcknowledged, true);
  assert.equal(await runSweep(), "NO_WORK");
});

test("Aurora recovery freshness requires exact completed points in both bound regions", () => {
  const config = parseAuroraFreshnessConfig({
    AWS_ACCOUNT_ID_EXPECTED: "111111111111",
    AWS_REGION_EXPECTED: "us-east-1",
    DATABASE_CLUSTER_ARN: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof-prod",
    DEPLOYMENT_ENVIRONMENT: "prod",
    PRIMARY_VAULT_NAME: "scopeproof-prod-primary",
    RECOVERY_REGION_EXPECTED: "us-west-2",
    RECOVERY_VAULT_NAME: "scopeproof-prod-recovery",
  });
  const latest = latestCompletedRecoveryPointAge([{
    CreationDate: new Date("2026-08-27T10:00:00.000Z"),
    ResourceArn: config.databaseClusterArn,
    ResourceType: "Aurora",
    Status: "COMPLETED",
  }], config, "2026-08-27T12:00:00.000Z");
  assert.equal(latest.ageSeconds, 7_200);
  assert.throws(() => latestCompletedRecoveryPointAge([], config, "2026-08-27T12:00:00.000Z"), /No completed/);
  assert.throws(() => parseAuroraFreshnessConfig({
    AWS_ACCOUNT_ID_EXPECTED: "111111111111",
    AWS_REGION_EXPECTED: "us-east-1",
    DATABASE_CLUSTER_ARN: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof-prod",
    DEPLOYMENT_ENVIRONMENT: "prod",
    PRIMARY_VAULT_NAME: "scopeproof-prod-primary",
    RECOVERY_REGION_EXPECTED: "us-east-1",
    RECOVERY_VAULT_NAME: "scopeproof-prod-recovery",
  }), /not safely bound/);
});
