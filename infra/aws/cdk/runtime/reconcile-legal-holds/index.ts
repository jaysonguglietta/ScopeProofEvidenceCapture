import {
  DynamoDBClient,
  GetItemCommand,
  TransactWriteItemsCommand,
} from "@aws-sdk/client-dynamodb";
import {
  KMSClient,
  SignCommand,
  VerifyCommand,
} from "@aws-sdk/client-kms";
import {
  BeginTransactionCommand,
  CommitTransactionCommand,
  ExecuteStatementCommand,
  RDSDataClient,
  RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";
import {
  GetObjectLegalHoldCommand,
  PutObjectLegalHoldCommand,
  S3Client,
} from "@aws-sdk/client-s3";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";

import { createTenantAuditEvent, type TenantAuditEvent } from "../../../../../lib/aws-runtime/audit.ts";
import { sha256Hex, stableJson, type JsonValue } from "../../../../../lib/aws-runtime/contracts.ts";
import {
  AwsSdkV3ExactVersionLegalHoldClient,
  AwsSdkV3KmsAsymmetricSigningClient,
  RdsDataExactVersionLegalHoldOperationStore,
  RdsDataLegalHoldReconciliationSource,
  RdsDataSignedAuditReceiptStore,
  assertPreparedOperation,
  signTenantAuditReceipt,
  sweepPendingExactVersionLegalHolds,
  type KmsCommandConstructors,
  type KmsSignedAuditReceipt,
  type S3LegalHoldCommandConstructors,
} from "../../../../../lib/aws-runtime/evidence/index.ts";
import {
  AwsSdkV3RdsDataApiExecutor,
  type RdsDataApiCommandConstructors,
} from "../../../../../lib/aws-runtime/http/index.ts";
import { publishLegalHoldRecoveryChange } from "../reconcile-recovery/change-ledger.mjs";
import { commitAuditBeforeRecovery } from "./audit-before-recovery.mjs";

const requiredEnvironment = [
  "AUDIT_SIGNING_KEY_ARN",
  "CONTROL_DATABASE_SECRET_ARN",
  "CONTROL_TABLE_NAME",
  "DATABASE_CLUSTER_ARN",
  "DATABASE_NAME",
  "EVIDENCE_BUCKET_NAME",
  "EVIDENCE_CONTROL_ROLE_ARN",
  "LEGAL_HOLD_MINIMUM_AGE_SECONDS",
  "LEGAL_HOLD_SWEEP_LIMIT",
  "TENANT_ID",
] as const;

type RequiredEnvironmentName = typeof requiredEnvironment[number];

function environment(): Readonly<Record<RequiredEnvironmentName, string>> {
  const result = {} as Record<RequiredEnvironmentName, string>;
  for (const name of requiredEnvironment) {
    const value = String(process.env[name] ?? "");
    if (!value || value !== value.trim() || /\p{Cc}/u.test(value)) {
      throw new Error(`Missing or invalid required environment variable ${name}.`);
    }
    result[name] = value;
  }
  if (!/^ten_[a-f0-9]{32}$/.test(result.TENANT_ID)) throw new Error("Legal-hold worker tenant identifier is invalid.");
  if (!/^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role\/scopeproof\/tenants\/sp-[a-z0-9-]{1,64}-evidence-control$/.test(result.EVIDENCE_CONTROL_ROLE_ARN)) {
    throw new Error("Legal-hold worker control role ARN is invalid.");
  }
  if (!/^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:\d{12}:key\/[0-9a-f-]{36}$/.test(result.AUDIT_SIGNING_KEY_ARN)) {
    throw new Error("Legal-hold worker signing key ARN is invalid.");
  }
  const minimumAge = Number(result.LEGAL_HOLD_MINIMUM_AGE_SECONDS);
  const limit = Number(result.LEGAL_HOLD_SWEEP_LIMIT);
  if (!Number.isSafeInteger(minimumAge) || minimumAge < 60 || minimumAge > 2_592_000 ||
      !Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new Error("Legal-hold worker bounds are invalid.");
  }
  return Object.freeze(result);
}

const config = environment();
const region = process.env.AWS_REGION;
if (!region || !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region)) throw new Error("Lambda AWS region is invalid.");
const sts = new STSClient({ region });

type CommandInput<T> = T extends new(input: infer Input) => unknown ? Input : never;

function compatibleAwsCommand<Input>(constructor: new(input: never) => unknown): new(input: Input) => unknown {
  return constructor as unknown as new(input: Input) => unknown;
}

function assumedCredentialProvider(requestId: string) {
  let inflight: ReturnType<typeof assume> | undefined;
  const sessionName = `scopeproof-legal-worker-${requestId.replace(/[^A-Za-z0-9+=,.@_-]/g, "").slice(0, 37)}`;
  async function assume() {
    const response = await sts.send(new AssumeRoleCommand({
      RoleArn: config.EVIDENCE_CONTROL_ROLE_ARN,
      RoleSessionName: sessionName,
      DurationSeconds: 900,
    }));
    const credentials = response.Credentials;
    const now = Date.now();
    if (!credentials ||
        typeof credentials.AccessKeyId !== "string" || !/^ASIA[A-Z0-9]{16}$/.test(credentials.AccessKeyId) ||
        typeof credentials.SecretAccessKey !== "string" || credentials.SecretAccessKey.length < 32 || credentials.SecretAccessKey.length > 128 ||
        typeof credentials.SessionToken !== "string" || credentials.SessionToken.length < 16 || credentials.SessionToken.length > 8_192 ||
        !(credentials.Expiration instanceof Date) ||
        credentials.Expiration.getTime() < now + 60_000 || credentials.Expiration.getTime() > now + 16 * 60_000) {
      throw new Error("STS returned an invalid legal-hold worker credential set.");
    }
    return Object.freeze({
      accessKeyId: credentials.AccessKeyId,
      secretAccessKey: credentials.SecretAccessKey,
      sessionToken: credentials.SessionToken,
      expiration: credentials.Expiration,
    });
  }
  return async () => {
    inflight ??= assume();
    return await inflight;
  };
}

function emitMetrics(input: Readonly<{
  observed: number;
  expired: number;
  attempted: number;
  applied: number;
  alreadyApplied: number;
  auditReceipts: number;
  appliedAuditReceipts: number;
  expiryAuditReceipts: number;
  failures: number;
  maxRequestedAgeSeconds: number;
  maxApprovedAgeSeconds: number;
}>): void {
  console.log(JSON.stringify({
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [{
        Namespace: "Scopeproof/LegalHold",
        Dimensions: [["TenantId"]],
        Metrics: [
          { Name: "Observed", Unit: "Count" },
          { Name: "Expired", Unit: "Count" },
          { Name: "Attempted", Unit: "Count" },
          { Name: "Applied", Unit: "Count" },
          { Name: "AlreadyApplied", Unit: "Count" },
          { Name: "AuditReceipts", Unit: "Count" },
          { Name: "AppliedAuditReceipts", Unit: "Count" },
          { Name: "ExpiryAuditReceipts", Unit: "Count" },
          { Name: "Failures", Unit: "Count" },
          { Name: "MaxRequestedAgeSeconds", Unit: "Seconds" },
          { Name: "MaxApprovedAgeSeconds", Unit: "Seconds" },
        ],
      }],
    },
    TenantId: config.TENANT_ID,
    Observed: input.observed,
    Expired: input.expired,
    Attempted: input.attempted,
    Applied: input.applied,
    AlreadyApplied: input.alreadyApplied,
    AuditReceipts: input.auditReceipts,
    AppliedAuditReceipts: input.appliedAuditReceipts,
    ExpiryAuditReceipts: input.expiryAuditReceipts,
    Failures: input.failures,
    MaxRequestedAgeSeconds: input.maxRequestedAgeSeconds,
    MaxApprovedAgeSeconds: input.maxApprovedAgeSeconds,
  }));
}

export async function handler(_event: unknown, context: Readonly<{ awsRequestId?: string }> = {}): Promise<Readonly<Record<string, number>>> {
  const requestId = typeof context.awsRequestId === "string" && /^[A-Za-z0-9-]{8,128}$/.test(context.awsRequestId)
    ? context.awsRequestId
    : crypto.randomUUID();
  const credentials = assumedCredentialProvider(requestId);
  const rdsClient = new RDSDataClient({ region, credentials });
  // Recovery-ledger access is intentionally held by the narrow Lambda
  // execution role, not by the assumed S3/KMS/database control role.
  const dynamo = new DynamoDBClient({ region });
  const executor = new AwsSdkV3RdsDataApiExecutor(rdsClient, {
    BeginTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["BeginTransactionCommand"]>>(BeginTransactionCommand as never),
    ExecuteStatementCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["ExecuteStatementCommand"]>>(ExecuteStatementCommand as never),
    CommitTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["CommitTransactionCommand"]>>(CommitTransactionCommand as never),
    RollbackTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["RollbackTransactionCommand"]>>(RollbackTransactionCommand as never),
  });
  const databaseOptions = {
    executor,
    resourceArn: config.DATABASE_CLUSTER_ARN,
    secretArn: config.CONTROL_DATABASE_SECRET_ARN,
    database: config.DATABASE_NAME,
  };
  const store = new RdsDataExactVersionLegalHoldOperationStore(databaseOptions);
  const source = new RdsDataLegalHoldReconciliationSource(databaseOptions);
  const s3 = new AwsSdkV3ExactVersionLegalHoldClient(new S3Client({ region, credentials }), {
    PutObjectLegalHoldCommand: compatibleAwsCommand<CommandInput<S3LegalHoldCommandConstructors["PutObjectLegalHoldCommand"]>>(PutObjectLegalHoldCommand as never),
    GetObjectLegalHoldCommand: compatibleAwsCommand<CommandInput<S3LegalHoldCommandConstructors["GetObjectLegalHoldCommand"]>>(GetObjectLegalHoldCommand as never),
  });
  const kms = new AwsSdkV3KmsAsymmetricSigningClient(new KMSClient({ region, credentials }), {
    SignCommand: compatibleAwsCommand<CommandInput<KmsCommandConstructors["SignCommand"]>>(SignCommand as never),
    VerifyCommand: compatibleAwsCommand<CommandInput<KmsCommandConstructors["VerifyCommand"]>>(VerifyCommand as never),
  });
  const auditStore = new RdsDataSignedAuditReceiptStore({
    ...databaseOptions,
    kms,
    signingKeyArn: config.AUDIT_SIGNING_KEY_ARN,
  });

  let maxRequestedAgeSeconds = 0;
  let maxApprovedAgeSeconds = 0;
  const sweep = await sweepPendingExactVersionLegalHolds({
    tenantId: config.TENANT_ID,
    client: s3,
    store,
    source,
    policy: { evidenceBucket: config.EVIDENCE_BUCKET_NAME },
    minimumAgeSeconds: Number(config.LEGAL_HOLD_MINIMUM_AGE_SECONDS),
    limit: Number(config.LEGAL_HOLD_SWEEP_LIMIT),
    observeAge(observation) {
      if (observation.state === "REQUESTED" || observation.state === "EXPIRED") {
        maxRequestedAgeSeconds = Math.max(maxRequestedAgeSeconds, observation.ageSeconds);
      }
      else maxApprovedAgeSeconds = Math.max(maxApprovedAgeSeconds, observation.ageSeconds);
    },
  });

  let appliedAuditReceipts = 0;
  let expiryAuditReceipts = 0;
  let auditFailures = 0;
  const unaudited = await source.listUnauditedApplied({
    tenantId: config.TENANT_ID,
    limit: Number(config.LEGAL_HOLD_SWEEP_LIMIT),
  });
  for (const item of unaudited) {
    try {
      await assertPreparedOperation(item.operation, { evidenceBucket: config.EVIDENCE_BUCKET_NAME });
      const state = await store.read(item.operation);
      if (state.state !== "APPLIED") throw new Error("Legal-hold audit outbox state changed unexpectedly.");
      let event: TenantAuditEvent;
      let receipt: KmsSignedAuditReceipt;
      if (item.committedAudit) {
        // A prior invocation may have committed the audit and failed before the
        // DynamoDB ledger write. Reuse that exact event/receipt; recomputing from
        // the advanced audit head would conflict with its deterministic event ID.
        event = item.committedAudit.event;
        receipt = item.committedAudit.receipt;
      } else {
        const head = await source.readAuditHead(config.TENANT_ID);
        const eventId = `evt_${(await sha256Hex(`scopeproof-legal-hold-audit-v1\0${item.operation.operationId}`)).slice(0, 32)}`;
        event = await createTenantAuditEvent({
          tenantId: config.TENANT_ID,
          sequence: head.sequence + 1,
          id: eventId,
          occurredAt: item.appliedAt,
          actor: { type: "system", service: "legal-hold-reconciler" },
          action: "evidence.legal_hold_applied",
          resourceType: "legal_hold_operation",
          resourceId: item.operation.operationId,
          requestId: `legal-hold-${item.operation.operationId}`,
          outcome: "succeeded",
          details: {
            approvalDigest: state.approval.approvalDigest,
            appliedAt: item.appliedAt,
            bucket: item.operation.bucket,
            evidenceId: item.operation.evidenceId,
            holdId: item.operation.holdId,
            holdRevision: item.operation.status === "ON" ? 0 : item.operation.expectedHoldRevision + 1,
            key: item.operation.key,
            operationRevision: state.operationRevision,
            provider: "aws.s3",
            providerOperation: "PutObjectLegalHold/GetObjectLegalHold",
            putRequestId: state.receipt.putRequestId,
            receiptDigest: await sha256Hex(`scopeproof-legal-hold-receipt-v1\n${stableJson(state.receipt as unknown as JsonValue)}`),
            receiptSchemaVersion: state.receipt.schemaVersion,
            requestDigest: item.operation.requestDigest,
            status: item.operation.status,
            verifyRequestId: state.receipt.verifyRequestId,
            versionId: item.operation.versionId,
          },
          previousHash: head.eventHash,
        });
        const now = new Date();
        const signedAt = now.getTime() < Date.parse(item.appliedAt) ? item.appliedAt : now.toISOString();
        receipt = await signTenantAuditReceipt({
          client: kms,
          event,
          keyArn: config.AUDIT_SIGNING_KEY_ARN,
          signingAlgorithm: "RSASSA_PSS_SHA_256",
          signedAt,
        });
      }
      // The committed receipt is authoritative on idempotent replay. Recovery
      // publication must never make an S3 mutation eligible for verification
      // before this independently KMS-verified receipt is durable in Aurora.
      await commitAuditBeforeRecovery({
        commitAudit: () => auditStore.append(event, receipt),
        publishRecovery: async (committedAudit) => {
          const publication = await publishLegalHoldRecoveryChange({
            client: dynamo,
            GetItemCommand,
            TransactWriteItemsCommand,
            tableName: config.CONTROL_TABLE_NAME,
            tenantId: config.TENANT_ID,
            operation: item.operation,
            appliedAt: item.appliedAt,
            now: new Date(),
            audit: {
              canonicalPayload: stableJson(committedAudit.receipt.payload as unknown as JsonValue),
              eventHash: committedAudit.eventHash,
              keyArn: committedAudit.receipt.keyArn,
              payloadSha256: committedAudit.receipt.payloadSha256,
              signature: committedAudit.receipt.signature,
              signingAlgorithm: "RSASSA_PSS_SHA_256",
            },
          });
          await source.acknowledgeRecoveryPublication({
            tenantId: config.TENANT_ID,
            operationId: item.operation.operationId,
            requestDigest: item.operation.requestDigest,
            publishedAt: publication.publishedAt,
          });
        },
      });
      appliedAuditReceipts += 1;
    } catch (error) {
      auditFailures += 1;
      console.error(JSON.stringify({
        level: "error",
        event: "legal_hold_audit_failure",
        requestId,
        operationId: item.operation.operationId,
        errorName: error instanceof Error ? error.name : "UnknownError",
      }));
    }
  }

  const unauditedExpired = await source.listUnauditedExpired({
    tenantId: config.TENANT_ID,
    limit: Number(config.LEGAL_HOLD_SWEEP_LIMIT),
  });
  for (const item of unauditedExpired) {
    try {
      await assertPreparedOperation(item.operation, { evidenceBucket: config.EVIDENCE_BUCKET_NAME });
      const state = await store.read(item.operation);
      if (state.state !== "EXPIRED") throw new Error("Legal-hold expiry audit outbox state changed unexpectedly.");
      const head = await source.readAuditHead(config.TENANT_ID);
      const eventId = `evt_${(await sha256Hex(`scopeproof-legal-hold-expiry-audit-v1\0${item.operation.operationId}`)).slice(0, 32)}`;
      const event = await createTenantAuditEvent({
        tenantId: config.TENANT_ID,
        sequence: head.sequence + 1,
        id: eventId,
        occurredAt: item.expiredAt,
        actor: { type: "system", service: "legal-hold-reconciler" },
        action: "evidence.legal_hold_request_expired",
        resourceType: "legal_hold_operation",
        resourceId: item.operation.operationId,
        requestId: `legal-hold-expiry-${item.operation.operationId}`,
        outcome: "succeeded",
        details: {
          approvalWindowSeconds: 86_400,
          bucket: item.operation.bucket,
          evidenceId: item.operation.evidenceId,
          expiredAt: item.expiredAt,
          holdId: item.operation.holdId,
          key: item.operation.key,
          operationRevision: state.operationRevision,
          requestDigest: item.operation.requestDigest,
          status: item.operation.status,
          versionId: item.operation.versionId,
        },
        previousHash: head.eventHash,
      });
      const now = new Date();
      const signedAt = now.getTime() < Date.parse(item.expiredAt) ? item.expiredAt : now.toISOString();
      const receipt = await signTenantAuditReceipt({
        client: kms,
        event,
        keyArn: config.AUDIT_SIGNING_KEY_ARN,
        signingAlgorithm: "RSASSA_PSS_SHA_256",
        signedAt,
      });
      await auditStore.append(event, receipt);
      expiryAuditReceipts += 1;
    } catch (error) {
      auditFailures += 1;
      console.error(JSON.stringify({
        level: "error",
        event: "legal_hold_expiry_audit_failure",
        requestId,
        operationId: item.operation.operationId,
        errorName: error instanceof Error ? error.name : "UnknownError",
      }));
    }
  }

  const failures = sweep.failedOperationIds.length + auditFailures;
  for (const operationId of sweep.failedOperationIds) {
    console.warn(JSON.stringify({
      level: "warn",
      event: "legal_hold_reconciliation_rejected",
      operationId,
      requestId,
      tenantId: config.TENANT_ID,
    }));
  }
  const auditReceipts = appliedAuditReceipts + expiryAuditReceipts;
  emitMetrics({
    observed: sweep.observed,
    expired: sweep.expired,
    attempted: sweep.attempted,
    applied: sweep.applied,
    alreadyApplied: sweep.alreadyApplied,
    auditReceipts,
    appliedAuditReceipts,
    expiryAuditReceipts,
    failures,
    maxRequestedAgeSeconds,
    maxApprovedAgeSeconds,
  });
  if (failures > 0) throw new Error("One or more legal-hold reconciliation operations failed.");
  return Object.freeze({
    observed: sweep.observed,
    expired: sweep.expired,
    attempted: sweep.attempted,
    applied: sweep.applied,
    alreadyApplied: sweep.alreadyApplied,
    auditReceipts,
    appliedAuditReceipts,
    expiryAuditReceipts,
  });
}
