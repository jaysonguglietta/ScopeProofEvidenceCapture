import { asResourceId, asTenantId, assertSafeJson, canonicalInstant, sha256Hex, stableJson, type JsonValue, type Sha256Hex, TenantSecurityError } from "../contracts.ts";
import type { TenantAuditEvent } from "../audit.ts";
import type { RdsDataApiExecutor } from "../http/membership.ts";
import type {
  ExactPresignedPutObject,
  ExactPutObjectPresignInput,
  ExactPutObjectPresigner,
  ConditionalUploadIntentStore,
  ControlledUploadIntent,
  RecoveredUploadIntentReservation,
  UploadIntentRecoveryProjection,
  UploadIntentReservation,
} from "./upload-intent-issuer.ts";
import type {
  AtomicPromotionCommand,
  AtomicPromotionResult,
  AtomicPromotionStore,
  PromotionFacts,
} from "./reconciliation.ts";
import type {
  AppliedExactVersionLegalHold,
  ApprovedExactVersionLegalHold,
  ExactVersionLegalHoldApproval,
  ExactVersionLegalHoldClient,
  ExactVersionLegalHoldOperation,
  ExactVersionLegalHoldOperationStore,
  ExactVersionLegalHoldReceipt,
  ExactVersionLegalHoldApplicationAttempt,
  GetObjectLegalHoldInput,
  PutObjectLegalHoldInput,
  ExpiredExactVersionLegalHoldSweepItem,
  PendingExactVersionLegalHoldSource,
  PendingExactVersionLegalHoldSweepItem,
  LegalHoldReconciliationRetry,
  ReservedExactVersionLegalHold,
  S3LegalHoldOutput,
} from "./exact-version-legal-hold.ts";
import { assertApprovalMatchesRequest, assertPreparedApproval, assertReceiptMatchesOperation } from "./exact-version-legal-hold.ts";
import type {
  KmsAsymmetricSigningClient,
  KmsSignInput,
  KmsSignOutput,
  KmsVerifyInput,
  KmsVerifyOutput,
  KmsSignedAuditReceipt,
} from "./signed-audit-receipt.ts";
import { verifyTenantAuditReceipt } from "./signed-audit-receipt.ts";
import { asKmsKeyArn, base64ToBytes, bytesToBase64, exactStringRecordEqual, hexToBytes } from "./primitives.ts";

interface AwsCommandClient {
  send(command: unknown): Promise<unknown>;
}

interface AwsCommandConstructor<Input> {
  new(input: Input): unknown;
}

type DynamoAttribute = Readonly<{
  S?: string;
  N?: string;
  M?: Readonly<Record<string, DynamoAttribute>>;
}>;

interface DynamoTransactWriteInput {
  readonly ClientRequestToken?: string;
  readonly TransactItems: readonly Readonly<{
    Put?: Readonly<{
      TableName: string;
      Item: Readonly<Record<string, DynamoAttribute>>;
      ConditionExpression: string;
      ExpressionAttributeNames: Readonly<Record<string, string>>;
    }>;
    Update?: Readonly<{
      TableName: string;
      Key: Readonly<Record<string, DynamoAttribute>>;
      ConditionExpression: string;
      UpdateExpression: string;
      ExpressionAttributeNames: Readonly<Record<string, string>>;
      ExpressionAttributeValues: Readonly<Record<string, DynamoAttribute>>;
    }>;
  }>[];
}

interface DynamoGetItemInput {
  readonly TableName: string;
  readonly Key: Readonly<Record<string, DynamoAttribute>>;
  readonly ConsistentRead: true;
}

interface DynamoGetItemOutput {
  readonly Item?: Readonly<Record<string, DynamoAttribute>>;
}

export interface DynamoUploadIntentStoreOptions {
  readonly client: AwsCommandClient;
  readonly TransactWriteItemsCommand: AwsCommandConstructor<DynamoTransactWriteInput>;
  readonly GetItemCommand: AwsCommandConstructor<DynamoGetItemInput>;
  readonly tableName: string;
  readonly maximumNewUploadsPerPrincipalDay?: number;
  readonly maximumNewUploadsPerTenantDay?: number;
}

const DEFAULT_MAXIMUM_NEW_UPLOADS_PER_PRINCIPAL_DAY = 500;
const DEFAULT_MAXIMUM_NEW_UPLOADS_PER_TENANT_DAY = 5_000;
const DEFAULT_MAXIMUM_UPLOAD_REQUESTS_PER_PRINCIPAL_MINUTE = 60;
const DEFAULT_MAXIMUM_UPLOAD_REQUESTS_PER_TENANT_MINUTE = 300;

interface UploadCounterLimits {
  readonly principal: number;
  readonly tenant: number;
}

/**
 * Persists the lifecycle row and a tenant-scoped nonce reservation in one
 * DynamoDB transaction. It never upserts and never stores the raw nonce.
 */
export class DynamoConditionalUploadIntentStore implements ConditionalUploadIntentStore {
  readonly #client: AwsCommandClient;
  readonly #TransactWriteItemsCommand: AwsCommandConstructor<DynamoTransactWriteInput>;
  readonly #GetItemCommand: AwsCommandConstructor<DynamoGetItemInput>;
  readonly #tableName: string;
  readonly #dailyLimits: UploadCounterLimits;

  constructor(options: DynamoUploadIntentStoreOptions) {
    if (!options.client || typeof options.client.send !== "function") throw new Error("DynamoDB client is required.");
    if (typeof options.TransactWriteItemsCommand !== "function" || typeof options.GetItemCommand !== "function") {
      throw new Error("DynamoDB upload reservation command constructors are required.");
    }
    if (!/^[A-Za-z0-9_.-]{3,255}$/.test(options.tableName)) throw new Error("DynamoDB table name is invalid.");
    this.#client = options.client;
    this.#TransactWriteItemsCommand = options.TransactWriteItemsCommand;
    this.#GetItemCommand = options.GetItemCommand;
    this.#tableName = options.tableName;
    this.#dailyLimits = Object.freeze({
      principal: exactQuotaLimit(
        options.maximumNewUploadsPerPrincipalDay ?? DEFAULT_MAXIMUM_NEW_UPLOADS_PER_PRINCIPAL_DAY,
        "Principal daily upload quota",
      ),
      tenant: exactQuotaLimit(
        options.maximumNewUploadsPerTenantDay ?? DEFAULT_MAXIMUM_NEW_UPLOADS_PER_TENANT_DAY,
        "Tenant daily upload quota",
      ),
    });
  }

  async recoverExact(
    intent: ControlledUploadIntent,
    recoveryProjection?: UploadIntentRecoveryProjection,
  ): Promise<RecoveredUploadIntentReservation | undefined> {
    const recovery = await normalizeRecoveryProjection(recoveryProjection);
    const prior = await this.#readExactExisting(intent, recovery, false);
    return prior ? Object.freeze({ outcome: "existing", intent: prior }) : undefined;
  }

  async reserve(
    intent: ControlledUploadIntent,
    recoveryProjection?: UploadIntentRecoveryProjection,
  ): Promise<UploadIntentReservation> {
    const recovery = await normalizeRecoveryProjection(recoveryProjection);
    // A logical retry normally resolves here. This avoids DynamoDB's ten-minute
    // transaction-token response cache and proves the exact durable state with
    // a strongly consistent read before any cross-service projection resumes.
    const prior = await this.#readExactExisting(intent, recovery, false);
    if (prior) return Object.freeze({ outcome: "existing", intent: prior });
    const nonceTtlEpochSeconds = Math.floor(Date.parse(intent.expiresAt) / 1_000);
    const lifecycleTtlEpochSeconds = nonceTtlEpochSeconds + (7 * 24 * 60 * 60);
    if (!Number.isSafeInteger(nonceTtlEpochSeconds) || !Number.isSafeInteger(lifecycleTtlEpochSeconds)) {
      throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload expiry is invalid.");
    }
    const tenantKey = `TENANT#${intent.tenantId}`;
    const absent = "attribute_not_exists(#pk) AND attribute_not_exists(#sk)";
    const names = Object.freeze({ "#pk": "PK", "#sk": "SK" });
    const lifecycle: Readonly<Record<string, DynamoAttribute>> = Object.freeze({
      PK: { S: tenantKey },
      SK: { S: `UPLOAD#${intent.id}` },
      kind: { S: "UploadLifecycle" },
      schemaVersion: { N: "1" },
      id: { S: intent.id },
      tenantId: { S: intent.tenantId },
      requestedBy: { S: intent.requestedBy },
      resourceId: { S: intent.resourceId },
      controlId: { S: intent.controlId },
      expectedSha256: { S: intent.expectedSha256 },
      expectedSize: { N: String(intent.expectedSize) },
      contentType: { S: intent.contentType },
      nonceDigest: { S: intent.nonceDigest },
      quarantineBucket: { S: intent.quarantineBucket },
      quarantineKmsKeyArn: { S: intent.quarantineKmsKeyArn },
      quarantineKey: { S: intent.quarantineKey },
      finalKey: { S: intent.finalKey },
      issuedAt: { S: intent.issuedAt },
      expiresAt: { S: intent.expiresAt },
      ttlEpochSeconds: { N: String(lifecycleTtlEpochSeconds) },
      requiredRetentionUntil: { S: intent.requiredRetentionUntil },
      databaseUploadRevision: { N: "0" },
      databaseEvidenceRevision: { N: "0" },
      revision: { N: "0" },
      status: { S: "issued" },
      idempotencyDigest: { S: intent.idempotencyDigest },
      requestFingerprint: { S: intent.requestFingerprint },
      canonicalEvidenceProjection: { S: recovery.canonicalEvidenceProjection },
      evidenceProjectionDigest: { S: recovery.evidenceProjectionDigest },
    });
    const nonceReservation: Readonly<Record<string, DynamoAttribute>> = Object.freeze({
      PK: { S: tenantKey },
      SK: { S: `UPLOAD_NONCE#${intent.nonceDigest}` },
      kind: { S: "UploadNonceReservation" },
      tenantId: { S: intent.tenantId },
      intentId: { S: intent.id },
      nonceDigest: { S: intent.nonceDigest },
      ttlEpochSeconds: { N: String(nonceTtlEpochSeconds) },
    });
    const requestReservation: Readonly<Record<string, DynamoAttribute>> = Object.freeze({
      PK: { S: tenantKey },
      SK: { S: `UPLOAD_REQUEST#${intent.idempotencyDigest}` },
      kind: { S: "UploadIdempotencyReservation" },
      tenantId: { S: intent.tenantId },
      intentId: { S: intent.id },
      idempotencyDigest: { S: intent.idempotencyDigest },
      requestFingerprint: { S: intent.requestFingerprint },
      evidenceProjectionDigest: { S: recovery.evidenceProjectionDigest },
      ttlEpochSeconds: { N: String(lifecycleTtlEpochSeconds) },
    });
    const dailyWindow = intent.issuedAt.slice(0, 10);
    const dailyCounterTtlEpochSeconds = Math.floor(Date.parse(`${dailyWindow}T00:00:00.000Z`) / 1_000) + (3 * 24 * 60 * 60);
    const tenantDailyCounter = uploadCounterUpdate({
      tableName: this.#tableName,
      tenantKey,
      sortKey: `RATE#UPLOAD_NEW#DAY#${dailyWindow}#TENANT`,
      kind: "UploadNewReservationTenantDailyRate",
      subject: "TENANT",
      tenantId: intent.tenantId,
      window: dailyWindow,
      ttlEpochSeconds: dailyCounterTtlEpochSeconds,
      limit: this.#dailyLimits.tenant,
    });
    const principalDailyCounter = uploadCounterUpdate({
      tableName: this.#tableName,
      tenantKey,
      sortKey: `RATE#UPLOAD_NEW#DAY#${dailyWindow}#PRINCIPAL#${intent.requestedBy}`,
      kind: "UploadNewReservationPrincipalDailyRate",
      subject: intent.requestedBy,
      tenantId: intent.tenantId,
      window: dailyWindow,
      ttlEpochSeconds: dailyCounterTtlEpochSeconds,
      limit: this.#dailyLimits.principal,
    });
    try {
      await this.#client.send(new this.#TransactWriteItemsCommand({
        // The token identifies this exact write attempt, including its issuance
        // window. A later logical retry deliberately receives a different token
        // so Dynamo evaluates the conditions instead of raising
        // IdempotentParameterMismatch for changed timestamps/TTLs.
        ClientRequestToken: await uploadReservationClientToken(intent, recovery, this.#dailyLimits),
        TransactItems: [
          { Put: { TableName: this.#tableName, Item: lifecycle, ConditionExpression: absent, ExpressionAttributeNames: names } },
          { Put: { TableName: this.#tableName, Item: nonceReservation, ConditionExpression: absent, ExpressionAttributeNames: names } },
          { Put: { TableName: this.#tableName, Item: requestReservation, ConditionExpression: absent, ExpressionAttributeNames: names } },
          { Update: tenantDailyCounter },
          { Update: principalDailyCounter },
        ],
      }));
      return Object.freeze({ outcome: "created", intent });
    } catch (error) {
      const cancellation = conditionalCancellationCodes(error, 5);
      if (cancellation) {
        // Always prove an exact lifecycle first. A retry racing the transaction
        // that reached the quota boundary must still recover its committed row.
        const existing = await this.#readExactExisting(intent, recovery, false);
        if (existing) return Object.freeze({ outcome: "existing", intent: existing });
        if (cancellation.slice(3).includes("ConditionalCheckFailed")) {
          throw new TenantSecurityError("RATE_LIMITED", "The upload creation quota is exhausted for this UTC day.", 429);
        }
        throw new TenantSecurityError("CONCURRENT_MODIFICATION", "The upload idempotency reservation conflicts with another request.", 409);
      }
      throw error;
    }
  }

  async #readExactExisting(
    candidate: ControlledUploadIntent,
    recovery: UploadIntentRecoveryProjection,
    missingIsConflict: boolean,
  ): Promise<ControlledUploadIntent | undefined> {
    const tenantKey = `TENANT#${candidate.tenantId}`;
    const item = await this.#getStronglyConsistent(tenantKey, `UPLOAD#${candidate.id}`);
    if (!item) {
      if (missingIsConflict) {
        throw new TenantSecurityError("CONCURRENT_MODIFICATION", "The upload idempotency reservation conflicts with another request.", 409);
      }
      return undefined;
    }
    const exactStrings: Readonly<Record<string, string>> = Object.freeze({
      PK: `TENANT#${candidate.tenantId}`,
      SK: `UPLOAD#${candidate.id}`,
      kind: "UploadLifecycle",
      id: candidate.id,
      tenantId: candidate.tenantId,
      requestedBy: candidate.requestedBy,
      resourceId: candidate.resourceId,
      controlId: candidate.controlId,
      expectedSha256: candidate.expectedSha256,
      contentType: candidate.contentType,
      nonceDigest: candidate.nonceDigest,
      quarantineBucket: candidate.quarantineBucket,
      quarantineKmsKeyArn: candidate.quarantineKmsKeyArn,
      quarantineKey: candidate.quarantineKey,
      finalKey: candidate.finalKey,
      requiredRetentionUntil: candidate.requiredRetentionUntil,
      status: "issued",
      idempotencyDigest: candidate.idempotencyDigest,
      requestFingerprint: candidate.requestFingerprint,
      canonicalEvidenceProjection: recovery.canonicalEvidenceProjection,
      evidenceProjectionDigest: recovery.evidenceProjectionDigest,
    });
    const stringMismatch = Object.entries(exactStrings).some(([name, expected]) => exactDynamoString(item, name) !== expected);
    const issuedAt = canonicalDynamoInstant(item, "issuedAt");
    const expiresAt = canonicalDynamoInstant(item, "expiresAt");
    const lifecycleTtlEpochSeconds = exactDynamoInteger(item, "ttlEpochSeconds");
    const expectedLifecycleTtl = Math.floor(Date.parse(expiresAt) / 1_000) + (7 * 24 * 60 * 60);
    const [nonceReservation, requestReservation] = await Promise.all([
      this.#getStronglyConsistent(tenantKey, `UPLOAD_NONCE#${candidate.nonceDigest}`),
      this.#getStronglyConsistent(tenantKey, `UPLOAD_REQUEST#${candidate.idempotencyDigest}`),
    ]);
    if (!nonceReservation || !requestReservation) {
      throw new TenantSecurityError("UPLOAD_MISMATCH", "Stored upload reservation is incomplete.", 409);
    }
    const nonceTtl = Math.floor(Date.parse(expiresAt) / 1_000);
    const nonceMismatch =
      exactDynamoString(nonceReservation, "PK") !== tenantKey ||
      exactDynamoString(nonceReservation, "SK") !== `UPLOAD_NONCE#${candidate.nonceDigest}` ||
      exactDynamoString(nonceReservation, "kind") !== "UploadNonceReservation" ||
      exactDynamoString(nonceReservation, "tenantId") !== candidate.tenantId ||
      exactDynamoString(nonceReservation, "intentId") !== candidate.id ||
      exactDynamoString(nonceReservation, "nonceDigest") !== candidate.nonceDigest ||
      exactDynamoInteger(nonceReservation, "ttlEpochSeconds") !== nonceTtl;
    const requestMismatch =
      exactDynamoString(requestReservation, "PK") !== tenantKey ||
      exactDynamoString(requestReservation, "SK") !== `UPLOAD_REQUEST#${candidate.idempotencyDigest}` ||
      exactDynamoString(requestReservation, "kind") !== "UploadIdempotencyReservation" ||
      exactDynamoString(requestReservation, "tenantId") !== candidate.tenantId ||
      exactDynamoString(requestReservation, "intentId") !== candidate.id ||
      exactDynamoString(requestReservation, "idempotencyDigest") !== candidate.idempotencyDigest ||
      exactDynamoString(requestReservation, "requestFingerprint") !== candidate.requestFingerprint ||
      exactDynamoString(requestReservation, "evidenceProjectionDigest") !== recovery.evidenceProjectionDigest ||
      exactDynamoInteger(requestReservation, "ttlEpochSeconds") !== expectedLifecycleTtl;
    if (
      stringMismatch ||
      nonceMismatch ||
      requestMismatch ||
      exactDynamoInteger(item, "schemaVersion") !== 1 ||
      exactDynamoInteger(item, "expectedSize") !== candidate.expectedSize ||
      exactDynamoInteger(item, "databaseUploadRevision") !== 0 ||
      exactDynamoInteger(item, "databaseEvidenceRevision") !== 0 ||
      exactDynamoInteger(item, "revision") !== 0 ||
      lifecycleTtlEpochSeconds !== expectedLifecycleTtl ||
      Date.parse(expiresAt) - Date.parse(issuedAt) !== Date.parse(candidate.expiresAt) - Date.parse(candidate.issuedAt)
    ) {
      throw new TenantSecurityError("UPLOAD_MISMATCH", "The idempotency key is already bound to different or malformed upload facts.", 409);
    }
    return Object.freeze({ ...candidate, issuedAt, expiresAt });
  }

  async #getStronglyConsistent(
    partitionKey: string,
    sortKey: string,
  ): Promise<Readonly<Record<string, DynamoAttribute>> | undefined> {
    const result = await this.#client.send(new this.#GetItemCommand({
      TableName: this.#tableName,
      Key: Object.freeze({ PK: { S: partitionKey }, SK: { S: sortKey } }),
      ConsistentRead: true,
    })) as DynamoGetItemOutput;
    return result?.Item;
  }
}

async function uploadReservationClientToken(
  intent: ControlledUploadIntent,
  recovery: UploadIntentRecoveryProjection,
  limits: UploadCounterLimits,
): Promise<string> {
  const transactionFacts: JsonValue = {
    schemaVersion: 1,
    id: intent.id,
    tenantId: intent.tenantId,
    requestedBy: intent.requestedBy,
    resourceId: intent.resourceId,
    controlId: intent.controlId,
    expectedSha256: intent.expectedSha256,
    expectedSize: intent.expectedSize,
    contentType: intent.contentType,
    nonceDigest: intent.nonceDigest,
    quarantineBucket: intent.quarantineBucket,
    quarantineKmsKeyArn: intent.quarantineKmsKeyArn,
    quarantineKey: intent.quarantineKey,
    finalKey: intent.finalKey,
    issuedAt: intent.issuedAt,
    expiresAt: intent.expiresAt,
    requiredRetentionUntil: intent.requiredRetentionUntil,
    idempotencyDigest: intent.idempotencyDigest,
    requestFingerprint: intent.requestFingerprint,
    evidenceProjectionDigest: recovery.evidenceProjectionDigest,
    maximumNewUploadsPerPrincipalDay: limits.principal,
    maximumNewUploadsPerTenantDay: limits.tenant,
  };
  return (await sha256Hex(`scopeproof-upload-reservation-transaction-v2\n${stableJson(transactionFacts)}`)).slice(0, 36);
}

function conditionalCancellationCodes(error: unknown, expectedLength: number): readonly string[] | undefined {
  if (!error || typeof error !== "object" || !("name" in error) || error.name !== "TransactionCanceledException") return undefined;
  const reasons = "CancellationReasons" in error ? error.CancellationReasons : undefined;
  if (!Array.isArray(reasons) || reasons.length !== expectedLength) return undefined;
  const codes = reasons.map((reason) => reason && typeof reason === "object" && "Code" in reason ? reason.Code : undefined);
  return codes.some((code) => code === "ConditionalCheckFailed") &&
    codes.every((code) => code === "ConditionalCheckFailed" || code === "None")
    ? codes as string[]
    : undefined;
}

function exactQuotaLimit(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 1_000_000) {
    throw new Error(`${label} must be an integer from 1 through 1000000.`);
  }
  return value;
}

function uploadCounterUpdate(input: Readonly<{
  tableName: string;
  tenantKey: string;
  sortKey: string;
  kind: string;
  subject: string;
  tenantId: string;
  window: string;
  ttlEpochSeconds: number;
  limit: number;
}>): NonNullable<DynamoTransactWriteInput["TransactItems"][number]["Update"]> {
  return Object.freeze({
    TableName: input.tableName,
    Key: Object.freeze({ PK: { S: input.tenantKey }, SK: { S: input.sortKey } }),
    ConditionExpression: [
      "(attribute_not_exists(#pk) AND attribute_not_exists(#sk))",
      "OR (#kind = :kind AND #tenant = :tenant AND #subject = :subject AND #window = :window AND #ttl = :ttl AND #count < :limit)",
    ].join(" "),
    UpdateExpression: "SET #kind = :kind, #tenant = :tenant, #subject = :subject, #window = :window, #ttl = :ttl ADD #count :one",
    ExpressionAttributeNames: Object.freeze({
      "#count": "count",
      "#kind": "kind",
      "#pk": "PK",
      "#sk": "SK",
      "#subject": "subject",
      "#tenant": "tenantId",
      "#ttl": "ttlEpochSeconds",
      "#window": "window",
    }),
    ExpressionAttributeValues: Object.freeze({
      ":kind": { S: input.kind },
      ":limit": { N: String(input.limit) },
      ":one": { N: "1" },
      ":subject": { S: input.subject },
      ":tenant": { S: input.tenantId },
      ":ttl": { N: String(input.ttlEpochSeconds) },
      ":window": { S: input.window },
    }),
  });
}

export interface DynamoUploadRequestRateLimiterOptions {
  readonly client: AwsCommandClient;
  readonly TransactWriteItemsCommand: AwsCommandConstructor<DynamoTransactWriteInput>;
  readonly tableName: string;
  readonly maximumRequestsPerPrincipalMinute?: number;
  readonly maximumRequestsPerTenantMinute?: number;
}

/** Atomically consumes tenant and principal request budgets before expensive upload work. */
export class DynamoUploadRequestRateLimiter {
  readonly #client: AwsCommandClient;
  readonly #TransactWriteItemsCommand: AwsCommandConstructor<DynamoTransactWriteInput>;
  readonly #tableName: string;
  readonly #limits: UploadCounterLimits;

  constructor(options: DynamoUploadRequestRateLimiterOptions) {
    if (!options.client || typeof options.client.send !== "function") throw new Error("DynamoDB rate-limit client is required.");
    if (typeof options.TransactWriteItemsCommand !== "function") throw new Error("DynamoDB rate-limit command constructor is required.");
    if (!/^[A-Za-z0-9_.-]{3,255}$/.test(options.tableName)) throw new Error("DynamoDB table name is invalid.");
    this.#client = options.client;
    this.#TransactWriteItemsCommand = options.TransactWriteItemsCommand;
    this.#tableName = options.tableName;
    this.#limits = Object.freeze({
      principal: exactQuotaLimit(
        options.maximumRequestsPerPrincipalMinute ?? DEFAULT_MAXIMUM_UPLOAD_REQUESTS_PER_PRINCIPAL_MINUTE,
        "Principal minute request quota",
      ),
      tenant: exactQuotaLimit(
        options.maximumRequestsPerTenantMinute ?? DEFAULT_MAXIMUM_UPLOAD_REQUESTS_PER_TENANT_MINUTE,
        "Tenant minute request quota",
      ),
    });
  }

  async consume(input: Readonly<{ tenantId: string; requestedBy: string; now: Date }>): Promise<void> {
    const tenantId = asTenantId(input.tenantId);
    const requestedBy = String(input.requestedBy || "");
    if (!/^usr_[a-f0-9]{32}$/.test(requestedBy)) throw new TenantSecurityError("INVALID_PRINCIPAL", "Upload principal is invalid.");
    if (!(input.now instanceof Date) || !Number.isFinite(input.now.getTime())) throw new Error("Upload rate-limit time is invalid.");
    const minuteWindow = input.now.toISOString().slice(0, 16);
    const minuteStart = Date.parse(`${minuteWindow}:00.000Z`);
    const ttlEpochSeconds = Math.floor(minuteStart / 1_000) + (2 * 60 * 60);
    const tenantKey = `TENANT#${tenantId}`;
    const counters = [
      uploadCounterUpdate({
        tableName: this.#tableName,
        tenantKey,
        sortKey: `RATE#UPLOAD_REQUEST#MINUTE#${minuteWindow}#TENANT`,
        kind: "UploadRequestTenantMinuteRate",
        subject: "TENANT",
        tenantId,
        window: minuteWindow,
        ttlEpochSeconds,
        limit: this.#limits.tenant,
      }),
      uploadCounterUpdate({
        tableName: this.#tableName,
        tenantKey,
        sortKey: `RATE#UPLOAD_REQUEST#MINUTE#${minuteWindow}#PRINCIPAL#${requestedBy}`,
        kind: "UploadRequestPrincipalMinuteRate",
        subject: requestedBy,
        tenantId,
        window: minuteWindow,
        ttlEpochSeconds,
        limit: this.#limits.principal,
      }),
    ];
    try {
      await this.#client.send(new this.#TransactWriteItemsCommand({
        TransactItems: counters.map((Update) => ({ Update })),
      }));
    } catch (error) {
      if (conditionalCancellationCodes(error, 2)) {
        throw new TenantSecurityError("RATE_LIMITED", "Too many upload requests were submitted in this minute.", 429);
      }
      throw error;
    }
  }
}

async function normalizeRecoveryProjection(
  value: UploadIntentRecoveryProjection | undefined,
): Promise<UploadIntentRecoveryProjection> {
  if (!value || typeof value.canonicalEvidenceProjection !== "string" || value.canonicalEvidenceProjection.length < 2 || value.canonicalEvidenceProjection.length > 131_072) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "A bounded evidence recovery projection is required.");
  }
  let parsed: JsonValue;
  try {
    parsed = assertSafeJson(JSON.parse(value.canonicalEvidenceProjection), "Evidence recovery projection");
  } catch (error) {
    if (error instanceof TenantSecurityError) throw error;
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Evidence recovery projection is invalid.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || stableJson(parsed) !== value.canonicalEvidenceProjection) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Evidence recovery projection must be a canonical JSON object.");
  }
  const digest = await sha256Hex(`scopeproof-upload-evidence-projection-v1\n${value.canonicalEvidenceProjection}`);
  if (digest !== value.evidenceProjectionDigest) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Evidence recovery projection digest is invalid.", 409);
  }
  return Object.freeze({
    canonicalEvidenceProjection: value.canonicalEvidenceProjection,
    evidenceProjectionDigest: digest,
  });
}

function exactDynamoString(item: Readonly<Record<string, DynamoAttribute>>, name: string): string {
  const attribute = item[name];
  if (!attribute || typeof attribute.S !== "string" || Object.keys(attribute).length !== 1) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Stored upload reservation is malformed.", 409);
  }
  return attribute.S;
}

function exactDynamoInteger(item: Readonly<Record<string, DynamoAttribute>>, name: string): number {
  const attribute = item[name];
  if (!attribute || typeof attribute.N !== "string" || Object.keys(attribute).length !== 1 || !/^(0|[1-9][0-9]*)$/.test(attribute.N)) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Stored upload reservation is malformed.", 409);
  }
  const value = Number(attribute.N);
  if (!Number.isSafeInteger(value)) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Stored upload reservation is malformed.", 409);
  }
  return value;
}

function canonicalDynamoInstant(item: Readonly<Record<string, DynamoAttribute>>, name: string): string {
  try {
    return canonicalInstant(exactDynamoString(item, name), `Stored upload ${name}`);
  } catch {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Stored upload reservation is malformed.", 409);
  }
}

interface PutObjectCommandInput {
  readonly Bucket: string;
  readonly Key: string;
  readonly ContentLength: number;
  readonly ContentType: string;
  readonly ChecksumSHA256: string;
  readonly Metadata: Readonly<Record<string, string>>;
  readonly ServerSideEncryption: "aws:kms";
  readonly SSEKMSKeyId: string;
  readonly SSEKMSEncryptionContext: string;
}

export interface AwsSdkV3PutObjectPresignerOptions {
  readonly client: unknown;
  readonly PutObjectCommand: AwsCommandConstructor<PutObjectCommandInput>;
  readonly getSignedUrl: (
    client: unknown,
    command: unknown,
    options: Readonly<{
      expiresIn: number;
      signingDate: Date;
      signableHeaders: ReadonlySet<string>;
      unhoistableHeaders: ReadonlySet<string>;
    }>,
  ) => Promise<string>;
}

/** AWS SDK v3 bridge that pins every security-relevant value into SigV4. */
export class AwsSdkV3ExactPutObjectPresigner implements ExactPutObjectPresigner {
  readonly #options: AwsSdkV3PutObjectPresignerOptions;

  constructor(options: AwsSdkV3PutObjectPresignerOptions) {
    if (!options.client || typeof options.getSignedUrl !== "function") throw new Error("S3 presigner dependencies are required.");
    this.#options = options;
  }

  async presignPutObject(input: ExactPutObjectPresignInput): Promise<ExactPresignedPutObject> {
    const headers = input.headers;
    const metadata = Object.freeze({
      "control-id": requiredHeader(headers, "x-amz-meta-control-id"),
      "evidence-id": requiredHeader(headers, "x-amz-meta-evidence-id"),
      "expected-sha256": requiredHeader(headers, "x-amz-meta-expected-sha256"),
      "tenant-id": requiredHeader(headers, "x-amz-meta-tenant-id"),
      "upload-intent-id": requiredHeader(headers, "x-amz-meta-upload-intent-id"),
    });
    const command = new this.#options.PutObjectCommand({
      Bucket: input.bucket,
      Key: input.key,
      ContentLength: Number(requiredHeader(headers, "content-length")),
      ContentType: requiredHeader(headers, "content-type"),
      ChecksumSHA256: requiredHeader(headers, "x-amz-checksum-sha256"),
      Metadata: metadata,
      ServerSideEncryption: "aws:kms",
      SSEKMSKeyId: requiredHeader(headers, "x-amz-server-side-encryption-aws-kms-key-id"),
      SSEKMSEncryptionContext: requiredHeader(headers, "x-amz-server-side-encryption-context"),
    });
    const signedHeaderNames = new Set(Object.keys(headers));
    const url = await this.#options.getSignedUrl(this.#options.client, command, {
      expiresIn: input.expiresInSeconds,
      // Sign with the current retry time and only the remaining lifetime. This
      // preserves the stable intent expiry without backdating newly refreshed
      // STS credentials to before those credentials existed.
      signingDate: new Date(input.signingAt),
      // The AWS signer intentionally excludes content-type unless it is
      // explicitly made signable. Both sets are required: signableHeaders
      // binds normally ignored headers, while unhoistableHeaders keeps every
      // x-amz value in the canonical request instead of moving it to the URL.
      signableHeaders: new Set(signedHeaderNames),
      unhoistableHeaders: new Set(signedHeaderNames),
    });
    return Object.freeze({
      method: "PUT",
      url,
      bucket: input.bucket,
      key: input.key,
      expiresAt: input.expiresAt,
      requiredHeaders: Object.freeze({ ...headers }),
    });
  }
}

function requiredHeader(headers: Readonly<Record<string, string>>, name: string): string {
  const value = headers[name];
  if (!value) throw new TenantSecurityError("INVALID_UPLOAD_INTENT", `Required signed header ${name} is absent.`);
  return value;
}

export interface KmsCommandConstructors {
  readonly SignCommand: AwsCommandConstructor<KmsSignInput>;
  readonly VerifyCommand: AwsCommandConstructor<KmsVerifyInput>;
}

export class AwsSdkV3KmsAsymmetricSigningClient implements KmsAsymmetricSigningClient {
  readonly #client: AwsCommandClient;
  readonly #commands: KmsCommandConstructors;

  constructor(client: AwsCommandClient, commands: KmsCommandConstructors) {
    if (!client || typeof client.send !== "function") throw new Error("KMS client is required.");
    this.#client = client;
    this.#commands = commands;
  }

  async sign(input: KmsSignInput): Promise<KmsSignOutput> {
    return await this.#client.send(new this.#commands.SignCommand(input)) as KmsSignOutput;
  }

  async verify(input: KmsVerifyInput): Promise<KmsVerifyOutput> {
    return await this.#client.send(new this.#commands.VerifyCommand(input)) as KmsVerifyOutput;
  }
}

export interface S3LegalHoldCommandConstructors {
  readonly PutObjectLegalHoldCommand: AwsCommandConstructor<PutObjectLegalHoldInput>;
  readonly GetObjectLegalHoldCommand: AwsCommandConstructor<GetObjectLegalHoldInput>;
}

export class AwsSdkV3ExactVersionLegalHoldClient implements ExactVersionLegalHoldClient {
  readonly #client: AwsCommandClient;
  readonly #commands: S3LegalHoldCommandConstructors;

  constructor(client: AwsCommandClient, commands: S3LegalHoldCommandConstructors) {
    if (!client || typeof client.send !== "function") throw new Error("S3 client is required.");
    this.#client = client;
    this.#commands = commands;
  }

  async putObjectLegalHold(input: PutObjectLegalHoldInput): Promise<S3LegalHoldOutput> {
    const result = await this.#client.send(new this.#commands.PutObjectLegalHoldCommand(input)) as Record<string, unknown>;
    return { requestId: awsRequestId(result) };
  }

  async getObjectLegalHold(input: GetObjectLegalHoldInput): Promise<S3LegalHoldOutput> {
    const result = await this.#client.send(new this.#commands.GetObjectLegalHoldCommand(input)) as Record<string, unknown>;
    const legalHold = result.LegalHold;
    return {
      LegalHold: legalHold && typeof legalHold === "object" && "Status" in legalHold
        ? { Status: String(legalHold.Status) }
        : undefined,
      requestId: awsRequestId(result),
    };
  }
}

function awsRequestId(result: Record<string, unknown>): string | undefined {
  const metadata = result.$metadata;
  if (!metadata || typeof metadata !== "object" || !("requestId" in metadata) || typeof metadata.requestId !== "string") return undefined;
  return metadata.requestId;
}

export interface RdsExactVersionLegalHoldStoreOptions {
  readonly executor: RdsDataApiExecutor;
  readonly resourceArn: string;
  readonly secretArn: string;
  readonly database: string;
}

const requestLegalHoldSql = [
  "SELECT operation_state, operation_revision, committed_canonical_approval, committed_approval_digest,",
  "       committed_canonical_receipt, committed_receipt_sha256, committed_application_attempt_id,",
  "       committed_application_prior_status, committed_application_observed_request_id, committed_application_started_at",
  "FROM scopeproof.reserve_exact_version_legal_hold(",
  "  CAST(:operation_id AS scopeproof.resource_identifier), CAST(:hold_id AS scopeproof.resource_identifier),",
  "  CAST(:evidence_id AS scopeproof.resource_identifier), :control_id, :evidence_bucket, :object_key, :object_version_id,",
  "  :desired_status, :hold_kind, :reason, CAST(:requested_by AS scopeproof.resource_identifier),",
  "  CAST(:expected_hold_revision AS integer), CAST(:changed_at AS timestamptz), :canonical_request, :request_digest",
  ")",
].join("\n");

const approveLegalHoldSql = [
  "SELECT operation_state, operation_revision, committed_canonical_approval, committed_approval_digest",
  "FROM scopeproof.approve_exact_version_legal_hold(",
  "  CAST(:operation_id AS scopeproof.resource_identifier), :request_digest,",
  "  CAST(:approved_by AS scopeproof.resource_identifier), CAST(:approved_at AS timestamptz),",
  "  :canonical_approval, :approval_digest",
  ")",
].join("\n");

const readLegalHoldSql = [
  "SELECT operation_state, operation_revision, committed_canonical_approval, committed_approval_digest,",
  "       committed_canonical_receipt, committed_receipt_sha256, committed_application_attempt_id,",
  "       committed_application_prior_status, committed_application_observed_request_id, committed_application_started_at",
  "FROM scopeproof.read_exact_version_legal_hold_operation(",
  "  CAST(:operation_id AS scopeproof.resource_identifier), :request_digest",
  ")",
].join("\n");

const beginApplyLegalHoldSql = [
  "SELECT operation_state, operation_revision, application_attempt_id, application_prior_status, application_observed_request_id, application_started_at",
  "FROM scopeproof.begin_exact_version_legal_hold_application(",
  " CAST(:operation_id AS scopeproof.resource_identifier), CAST(:expected_operation_revision AS integer), :request_digest, :approval_digest,",
  " :attempt_id, :prior_status, :observed_request_id, CAST(:started_at AS timestamptz))",
].join("\n");

const applyLegalHoldSql = [
  "SELECT was_created, operation_revision, hold_revision, committed_canonical_receipt, committed_receipt_sha256",
  "FROM scopeproof.confirm_exact_version_legal_hold(",
  "  CAST(:operation_id AS scopeproof.resource_identifier), CAST(:expected_operation_revision AS integer),",
  "  :request_digest, :approval_digest, CAST(:receipt AS jsonb), :canonical_receipt, :receipt_sha256,",
  "  :put_request_id, :verify_request_id",
  ")",
].join("\n");

/**
 * RDS Data API bridge for the durable legal-hold boundaries. Each method uses
 * its own transaction so REQUESTED and APPROVED commit before any S3 mutation.
 */
export class RdsDataExactVersionLegalHoldOperationStore implements ExactVersionLegalHoldOperationStore {
  readonly #options: RdsExactVersionLegalHoldStoreOptions;

  constructor(options: RdsExactVersionLegalHoldStoreOptions) {
    assertRdsConnection(options.resourceArn, options.secretArn, options.database);
    this.#options = options;
  }

  async request(operation: ExactVersionLegalHoldOperation): Promise<ReservedExactVersionLegalHold> {
    const response = await this.#execute(operation.tenantId, requestLegalHoldSql, [
      stringParameter("operation_id", operation.operationId),
      stringParameter("hold_id", operation.holdId),
      stringParameter("evidence_id", operation.evidenceId),
      stringParameter("control_id", operation.controlId),
      stringParameter("evidence_bucket", operation.bucket),
      stringParameter("object_key", operation.key),
      stringParameter("object_version_id", operation.versionId),
      stringParameter("desired_status", operation.status),
      stringParameter("hold_kind", operation.kind),
      stringParameter("reason", operation.reason),
      stringParameter("requested_by", operation.requestedBy),
      stringParameter("expected_hold_revision", String(operation.expectedHoldRevision)),
      stringParameter("changed_at", operation.changedAt),
      stringParameter("canonical_request", operation.canonicalRequest),
      stringParameter("request_digest", operation.requestDigest),
    ]);
    return await parseLegalHoldReservation(response.formattedRecords, operation);
  }

  async approve(approval: ExactVersionLegalHoldApproval): Promise<ApprovedExactVersionLegalHold> {
    const response = await this.#execute(approval.tenantId, approveLegalHoldSql, [
      stringParameter("operation_id", approval.operationId),
      stringParameter("request_digest", approval.requestDigest),
      stringParameter("approved_by", approval.approvedBy),
      stringParameter("approved_at", approval.approvedAt),
      stringParameter("canonical_approval", approval.canonicalApproval),
      stringParameter("approval_digest", approval.approvalDigest),
    ]);
    const row = parseSingleLegalHoldRow(response.formattedRecords);
    if ((row.operation_state !== "APPROVED" && row.operation_state !== "APPLYING" && row.operation_state !== "APPLIED") ||
        (row.operation_state === "APPROVED" && row.operation_revision !== 1) ||
        (row.operation_state === "APPLYING" && row.operation_revision !== 2) ||
        (row.operation_state === "APPLIED" && row.operation_revision !== 3)) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold approval returned invalid state.", 500);
    }
    const storedApproval = await parseStoredLegalHoldApproval(row, approval.operationId, approval.requestDigest);
    if (storedApproval.canonicalApproval !== approval.canonicalApproval || storedApproval.approvalDigest !== approval.approvalDigest) {
      throw new TenantSecurityError("CONCURRENT_MODIFICATION", "Legal-hold approval idempotency conflict.", 409);
    }
    return Object.freeze({
      state: row.operation_state,
      operationRevision: row.operation_revision as 1 | 2 | 3,
      approval: storedApproval,
    }) as ApprovedExactVersionLegalHold;
  }

  async read(operation: ExactVersionLegalHoldOperation): Promise<ReservedExactVersionLegalHold> {
    const response = await this.#execute(operation.tenantId, readLegalHoldSql, [
      stringParameter("operation_id", operation.operationId),
      stringParameter("request_digest", operation.requestDigest),
    ]);
    return await parseLegalHoldReservation(response.formattedRecords, operation);
  }

  async beginApply(operation: ExactVersionLegalHoldOperation, approval: ExactVersionLegalHoldApproval, expectedOperationRevision: 1, attempt: ExactVersionLegalHoldApplicationAttempt): Promise<Extract<ReservedExactVersionLegalHold, { state: "APPLYING" }>> {
    await assertPreparedApproval(approval, operation);
    const response = await this.#execute(operation.tenantId, beginApplyLegalHoldSql, [
      stringParameter("operation_id", operation.operationId), stringParameter("expected_operation_revision", String(expectedOperationRevision)),
      stringParameter("request_digest", operation.requestDigest), stringParameter("approval_digest", approval.approvalDigest),
      stringParameter("attempt_id", attempt.attemptId), stringParameter("prior_status", attempt.priorStatus),
      stringParameter("observed_request_id", attempt.observedRequestId), stringParameter("started_at", attempt.startedAt),
    ]);
    const row = parseSingleLegalHoldRow(response.formattedRecords);
    if (row.operation_state !== "APPLYING" || row.operation_revision !== 2 || row.application_attempt_id !== attempt.attemptId ||
        row.application_prior_status !== attempt.priorStatus || row.application_observed_request_id !== attempt.observedRequestId ||
        row.application_started_at !== attempt.startedAt) throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold application precondition was not durably recorded.", 500);
    return Object.freeze({ state: "APPLYING", operationRevision: 2, approval, applicationAttempt: attempt });
  }

  async apply(
    operation: ExactVersionLegalHoldOperation,
    approval: ExactVersionLegalHoldApproval,
    expectedOperationRevision: 2,
    receipt: ExactVersionLegalHoldReceipt,
  ): Promise<AppliedExactVersionLegalHold> {
    if (expectedOperationRevision !== 2) {
      throw new TenantSecurityError("CONCURRENT_MODIFICATION", "Legal-hold operation revision is invalid.", 409);
    }
    await assertPreparedApproval(approval, operation);
    assertReceiptMatchesOperation(receipt, operation);
    const canonicalReceipt = stableJson(receipt as unknown as JsonValue);
    const receiptSha256 = await sha256Hex(`scopeproof-legal-hold-receipt-v1\n${canonicalReceipt}`);
    const response = await this.#execute(operation.tenantId, applyLegalHoldSql, [
      stringParameter("operation_id", operation.operationId),
      stringParameter("expected_operation_revision", String(expectedOperationRevision)),
      stringParameter("request_digest", operation.requestDigest),
      stringParameter("approval_digest", approval.approvalDigest),
      stringParameter("receipt", canonicalReceipt),
      stringParameter("canonical_receipt", canonicalReceipt),
      stringParameter("receipt_sha256", receiptSha256),
      stringParameter("put_request_id", receipt.putRequestId),
      stringParameter("verify_request_id", receipt.verifyRequestId),
    ]);
    const row = parseSingleLegalHoldRow(response.formattedRecords);
    if (typeof row.was_created !== "boolean" || !Number.isSafeInteger(row.operation_revision) ||
        !Number.isSafeInteger(row.hold_revision) || (row.operation_revision as number) < 3 ||
        (row.hold_revision as number) < 0) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold confirmation returned invalid state.", 500);
    }
    const storedReceipt = await parseStoredLegalHoldReceipt(row, operation);
    return Object.freeze({
      outcome: row.was_created ? "applied" : "already_applied",
      operationRevision: row.operation_revision as number,
      holdRevision: row.hold_revision as number,
      receipt: storedReceipt,
    });
  }

  async #execute(
    tenantId: string,
    sql: string,
    parameters: readonly { name: string; value: { stringValue: string } }[],
  ): Promise<{ formattedRecords?: string }> {
    const connection = {
      resourceArn: this.#options.resourceArn,
      secretArn: this.#options.secretArn,
      database: this.#options.database,
    };
    const transaction = await this.#options.executor.beginTransaction(connection);
    const transactionId = transaction.transactionId;
    if (!transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transactionId)) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold database transaction could not be established.", 500);
    }
    try {
      await this.#options.executor.executeStatement({
        ...connection,
        transactionId,
        sql: setTenantSql,
        parameters: [stringParameter("tenant_id", tenantId)],
      });
      const response = await this.#options.executor.executeStatement({
        ...connection,
        transactionId,
        sql,
        parameters,
        formatRecordsAs: "JSON",
      });
      await this.#options.executor.commitTransaction({
        resourceArn: connection.resourceArn,
        secretArn: connection.secretArn,
        transactionId,
      });
      return response;
    } catch (error) {
      try {
        await this.#options.executor.rollbackTransaction({
          resourceArn: connection.resourceArn,
          secretArn: connection.secretArn,
          transactionId,
        });
      } catch {
        // Preserve the authoritative database failure.
      }
      throw error;
    }
  }
}

export interface UnauditedAppliedExactVersionLegalHold {
  readonly operation: ExactVersionLegalHoldOperation;
  readonly appliedAt: string;
  readonly committedAudit?: Readonly<{
    event: TenantAuditEvent;
    receipt: KmsSignedAuditReceipt;
  }>;
}

export interface UnauditedExpiredExactVersionLegalHold {
  readonly operation: ExactVersionLegalHoldOperation;
  readonly expiredAt: string;
}

export interface TenantAuditHead {
  readonly sequence: number;
  readonly eventHash: Sha256Hex | "GENESIS";
}

/**
 * Execute-only database outbox used by the bounded legal-hold worker. It can
 * enumerate already-created work, but cannot create or approve an operation.
 */
export class RdsDataLegalHoldReconciliationSource implements PendingExactVersionLegalHoldSource {
  readonly #options: RdsExactVersionLegalHoldStoreOptions;

  constructor(options: RdsExactVersionLegalHoldStoreOptions) {
    assertRdsConnection(options.resourceArn, options.secretArn, options.database);
    this.#options = options;
  }

  async expireStaleRequests(input: Readonly<{
    tenantId: string;
    now: string;
    limit: number;
  }>): Promise<readonly ExpiredExactVersionLegalHoldSweepItem[]> {
    const tenantId = asTenantId(input.tenantId);
    const now = canonicalInstant(input.now, "Legal-hold expiry time");
    if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 100) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold expiry bound is invalid.", 500);
    }
    const rows = await this.#query(tenantId, [
      "SELECT operation_id::text, canonical_request, request_digest, expired_at",
      "FROM scopeproof.expire_stale_exact_version_legal_hold_requests(",
      "  CAST(:now AS timestamptz), CAST(:result_limit AS integer)",
      ")",
    ].join("\n"), [
      stringParameter("now", now),
      stringParameter("result_limit", String(input.limit)),
    ]);
    return Object.freeze(rows.map((row) => {
      const operation = parseCanonicalLegalHoldOperation(row, tenantId);
      if (row.operation_id !== operation.operationId || typeof row.expired_at !== "string") {
        throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold expiry returned invalid work.", 500);
      }
      return Object.freeze({
        operation,
        expiredAt: canonicalInstant(row.expired_at, "Legal-hold expiry time"),
      });
    }));
  }

  async listPending(input: Readonly<{
    tenantId: string;
    stateChangedBefore: string;
    limit: number;
  }>): Promise<readonly PendingExactVersionLegalHoldSweepItem[]> {
    const tenantId = asTenantId(input.tenantId);
    const cutoff = canonicalInstant(input.stateChangedBefore, "Legal-hold sweep cutoff");
    if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 100) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold sweep bound is invalid.", 500);
    }
    const rows = await this.#query(tenantId, [
      "SELECT canonical_request, request_digest, operation_state, state_changed_at",
      "FROM scopeproof.list_pending_exact_version_legal_holds(",
      "  CAST(:state_changed_before AS timestamptz), CAST(:result_limit AS integer)",
      ")",
    ].join("\n"), [
      stringParameter("state_changed_before", cutoff),
      stringParameter("result_limit", String(input.limit)),
    ]);
    return Object.freeze(rows.map((row) => {
      if ((row.operation_state !== "REQUESTED" && row.operation_state !== "APPROVED" && row.operation_state !== "APPLYING") ||
          typeof row.state_changed_at !== "string") {
        throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold sweep returned invalid work.", 500);
      }
      return Object.freeze({
        operation: parseCanonicalLegalHoldOperation(row, tenantId),
        state: row.operation_state,
        stateChangedAt: canonicalInstant(row.state_changed_at, "Legal-hold state change time"),
      });
    }));
  }

  async recordReconciliationFailure(input: Readonly<{
    tenantId: string;
    operationId: string;
    requestDigest: string;
    errorCode: string;
    failedAt: string;
  }>): Promise<LegalHoldReconciliationRetry> {
    const tenantId = asTenantId(input.tenantId);
    const operationId = asResourceId(input.operationId, ["lho"]);
    if (!/^[0-9a-f]{64}$/.test(input.requestDigest) || !/^[A-Z][A-Z0-9_]{2,63}$/.test(input.errorCode)) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold reconciliation failure metadata is invalid.", 500);
    }
    const failedAt = canonicalInstant(input.failedAt, "Legal-hold reconciliation failure time");
    const rows = await this.#query(tenantId, [
      "SELECT attempt_count, next_attempt_at",
      "FROM scopeproof.record_exact_version_legal_hold_reconciliation_failure(",
      "  CAST(:operation_id AS scopeproof.resource_identifier), :request_digest, :error_code,",
      "  CAST(:failed_at AS timestamptz)",
      ")",
    ].join("\n"), [
      stringParameter("operation_id", operationId),
      stringParameter("request_digest", input.requestDigest),
      stringParameter("error_code", input.errorCode),
      stringParameter("failed_at", failedAt),
    ]);
    if (rows.length !== 1 || !Number.isSafeInteger(rows[0].attempt_count) ||
        (rows[0].attempt_count as number) < 1 || typeof rows[0].next_attempt_at !== "string") {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold reconciliation retry response is invalid.", 500);
    }
    const nextAttemptAt = canonicalInstant(rows[0].next_attempt_at, "Legal-hold next attempt time");
    const delay = Date.parse(nextAttemptAt) - Date.parse(failedAt);
    if (delay < 30_000 || delay > 21_600_000) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold reconciliation retry delay is invalid.", 500);
    }
    return Object.freeze({
      attemptCount: rows[0].attempt_count as number,
      nextAttemptAt,
    });
  }

  async listUnauditedApplied(input: Readonly<{
    tenantId: string;
    limit: number;
  }>): Promise<readonly UnauditedAppliedExactVersionLegalHold[]> {
    const tenantId = asTenantId(input.tenantId);
    if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 100) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Legal-hold audit sweep bound is invalid.", 500);
    }
    const rows = await this.#query(tenantId, [
      "SELECT canonical_request, request_digest, applied_at, audit_canonical_event, audit_canonical_receipt,",
      "       audit_receipt_payload_sha256, audit_signing_key_arn, audit_signing_algorithm, audit_signature",
      "FROM scopeproof.list_unaudited_applied_legal_holds(CAST(:result_limit AS integer))",
    ].join("\n"), [stringParameter("result_limit", String(input.limit))]);
    return Object.freeze(rows.map((row) => {
      if (typeof row.applied_at !== "string") {
        throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Legal-hold audit outbox returned invalid work.", 500);
      }
      const auditValues = [
        row.audit_canonical_event, row.audit_canonical_receipt, row.audit_receipt_payload_sha256,
        row.audit_signing_key_arn, row.audit_signing_algorithm, row.audit_signature,
      ];
      if (!auditValues.every((value) => value === null || value === undefined) &&
          !auditValues.every((value) => typeof value === "string")) {
        throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Legal-hold audit outbox returned partial committed audit state.", 500);
      }
      let committedAudit: UnauditedAppliedExactVersionLegalHold["committedAudit"];
      if (auditValues.every((value) => typeof value === "string")) {
        let event: unknown;
        let payload: unknown;
        try {
          event = JSON.parse(row.audit_canonical_event as string);
          payload = JSON.parse(row.audit_canonical_receipt as string);
        } catch {
          throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Stored legal-hold audit state is invalid.", 500);
        }
        if (!event || typeof event !== "object" || Array.isArray(event) ||
            !payload || typeof payload !== "object" || Array.isArray(payload) ||
            stableJson(event as JsonValue) !== row.audit_canonical_event ||
            stableJson(payload as JsonValue) !== row.audit_canonical_receipt) {
          throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Stored legal-hold audit state is non-canonical.", 500);
        }
        committedAudit = Object.freeze({
          event: Object.freeze(event) as TenantAuditEvent,
          receipt: Object.freeze({
            schemaVersion: 1,
            payload: Object.freeze(payload) as KmsSignedAuditReceipt["payload"],
            payloadSha256: row.audit_receipt_payload_sha256 as string,
            keyArn: row.audit_signing_key_arn as string,
            signingAlgorithm: row.audit_signing_algorithm as KmsSignedAuditReceipt["signingAlgorithm"],
            signature: row.audit_signature as string,
          }),
        });
      }
      return Object.freeze({
        operation: parseCanonicalLegalHoldOperation(row, tenantId),
        appliedAt: canonicalInstant(row.applied_at, "Legal-hold application time"),
        committedAudit,
      });
    }));
  }

  async acknowledgeRecoveryPublication(input: Readonly<{
    tenantId: string;
    operationId: string;
    requestDigest: string;
    publishedAt: string;
  }>): Promise<string> {
    const tenantId = asTenantId(input.tenantId);
    const operationId = asResourceId(input.operationId, ["lho"]);
    if (!/^[0-9a-f]{64}$/.test(input.requestDigest)) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Legal-hold recovery acknowledgement digest is invalid.", 500);
    }
    const publishedAt = canonicalInstant(input.publishedAt, "Legal-hold recovery publication time");
    const rows = await this.#query(tenantId, [
      "SELECT scopeproof.acknowledge_legal_hold_recovery_publication(",
      "  CAST(:operation_id AS scopeproof.resource_identifier), :request_digest,",
      "  CAST(:published_at AS timestamptz)",
      ") AS recovery_published_at",
    ].join("\n"), [
      stringParameter("operation_id", operationId),
      stringParameter("request_digest", input.requestDigest),
      stringParameter("published_at", publishedAt),
    ]);
    if (rows.length !== 1 || typeof rows[0].recovery_published_at !== "string" ||
        canonicalInstant(rows[0].recovery_published_at, "Legal-hold recovery acknowledgement time") !== publishedAt) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Legal-hold recovery acknowledgement failed.", 500);
    }
    return publishedAt;
  }

  async listUnauditedExpired(input: Readonly<{
    tenantId: string;
    limit: number;
  }>): Promise<readonly UnauditedExpiredExactVersionLegalHold[]> {
    const tenantId = asTenantId(input.tenantId);
    if (!Number.isSafeInteger(input.limit) || input.limit < 1 || input.limit > 100) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Legal-hold expiry audit sweep bound is invalid.", 500);
    }
    const rows = await this.#query(tenantId, [
      "SELECT canonical_request, request_digest, expired_at",
      "FROM scopeproof.list_unaudited_expired_legal_holds(CAST(:result_limit AS integer))",
    ].join("\n"), [stringParameter("result_limit", String(input.limit))]);
    return Object.freeze(rows.map((row) => {
      if (typeof row.expired_at !== "string") {
        throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Legal-hold expiry audit outbox returned invalid work.", 500);
      }
      return Object.freeze({
        operation: parseCanonicalLegalHoldOperation(row, tenantId),
        expiredAt: canonicalInstant(row.expired_at, "Legal-hold expiry time"),
      });
    }));
  }

  async readAuditHead(tenantIdValue: string): Promise<TenantAuditHead> {
    const tenantId = asTenantId(tenantIdValue);
    const rows = await this.#query(tenantId, [
      "SELECT current_sequence, current_event_hash",
      "FROM scopeproof.read_tenant_audit_head()",
    ].join("\n"), []);
    if (rows.length !== 1 || !Number.isSafeInteger(rows[0].current_sequence) ||
        (rows[0].current_sequence as number) < 0 || typeof rows[0].current_event_hash !== "string" ||
        !((rows[0].current_sequence === 0 && rows[0].current_event_hash === "GENESIS") ||
          ((rows[0].current_sequence as number) > 0 && /^[0-9a-f]{64}$/.test(rows[0].current_event_hash)))) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Tenant audit head is invalid.", 500);
    }
    return Object.freeze({
      sequence: rows[0].current_sequence as number,
      eventHash: rows[0].current_event_hash as Sha256Hex | "GENESIS",
    });
  }

  async #query(
    tenantId: string,
    sql: string,
    parameters: readonly { name: string; value: { stringValue: string } }[],
  ): Promise<readonly Record<string, unknown>[]> {
    const connection = {
      resourceArn: this.#options.resourceArn,
      secretArn: this.#options.secretArn,
      database: this.#options.database,
    };
    const transaction = await this.#options.executor.beginTransaction(connection);
    const transactionId = transaction.transactionId;
    if (!transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transactionId)) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold outbox transaction could not be established.", 500);
    }
    try {
      await this.#options.executor.executeStatement({
        ...connection,
        transactionId,
        sql: setTenantSql,
        parameters: [stringParameter("tenant_id", tenantId)],
      });
      const result = await this.#options.executor.executeStatement({
        ...connection,
        transactionId,
        sql,
        parameters,
        formatRecordsAs: "JSON",
      });
      const rows = parseBoundedRows(result.formattedRecords, 100);
      await this.#options.executor.commitTransaction({
        resourceArn: connection.resourceArn,
        secretArn: connection.secretArn,
        transactionId,
      });
      return rows;
    } catch (error) {
      try {
        await this.#options.executor.rollbackTransaction({
          resourceArn: connection.resourceArn,
          secretArn: connection.secretArn,
          transactionId,
        });
      } catch {
        // Preserve the authoritative query failure.
      }
      throw error;
    }
  }
}

function parseBoundedRows(value: string | undefined, maximumRows: number): readonly Record<string, unknown>[] {
  if (!value || value.length > 1_048_576) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold outbox response is invalid.", 500);
  }
  let rows: unknown;
  try { rows = JSON.parse(value); } catch {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold outbox response is invalid.", 500);
  }
  if (!Array.isArray(rows) || rows.length > maximumRows ||
      rows.some((row) => !row || typeof row !== "object" || Array.isArray(row))) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold outbox response is invalid.", 500);
  }
  return rows as readonly Record<string, unknown>[];
}

function parseCanonicalLegalHoldOperation(
  row: Readonly<Record<string, unknown>>,
  tenantId: string,
): ExactVersionLegalHoldOperation {
  if (typeof row.canonical_request !== "string" || row.canonical_request.length > 16_384 ||
      typeof row.request_digest !== "string" || !/^[0-9a-f]{64}$/.test(row.request_digest)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold outbox operation is invalid.", 500);
  }
  let value: JsonValue;
  try {
    value = assertSafeJson(JSON.parse(row.canonical_request), "Legal-hold outbox operation");
  } catch {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold outbox operation is invalid.", 500);
  }
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      stableJson(value) !== row.canonical_request || value.tenantId !== tenantId || value.schemaVersion !== 2) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold outbox operation is invalid.", 500);
  }
  return Object.freeze({
    ...(value as unknown as Omit<ExactVersionLegalHoldOperation, "canonicalRequest" | "requestDigest">),
    canonicalRequest: row.canonical_request,
    requestDigest: row.request_digest,
  });
}

interface LegalHoldResultRow {
  operation_state?: unknown;
  operation_revision?: unknown;
  was_created?: unknown;
  hold_revision?: unknown;
  committed_canonical_approval?: unknown;
  committed_approval_digest?: unknown;
  committed_canonical_receipt?: unknown;
  committed_receipt_sha256?: unknown;
  committed_application_attempt_id?: unknown;
  committed_application_prior_status?: unknown;
  committed_application_observed_request_id?: unknown;
  committed_application_started_at?: unknown;
  application_attempt_id?: unknown;
  application_prior_status?: unknown;
  application_observed_request_id?: unknown;
  application_started_at?: unknown;
}

async function parseLegalHoldReservation(
  formattedRecords: string | undefined,
  operation: ExactVersionLegalHoldOperation,
): Promise<ReservedExactVersionLegalHold> {
  const row = parseSingleLegalHoldRow(formattedRecords);
  if ((row.operation_state !== "REQUESTED" && row.operation_state !== "APPROVED" && row.operation_state !== "APPLYING" &&
       row.operation_state !== "APPLIED" && row.operation_state !== "EXPIRED") ||
      (row.operation_state === "REQUESTED" && row.operation_revision !== 0) ||
      (row.operation_state === "EXPIRED" && row.operation_revision !== 1) ||
      (row.operation_state === "APPROVED" && row.operation_revision !== 1) ||
      (row.operation_state === "APPLYING" && row.operation_revision !== 2) ||
      (row.operation_state === "APPLIED" && row.operation_revision !== 3)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold operation returned invalid state.", 500);
  }
  if (row.operation_state === "REQUESTED" || row.operation_state === "EXPIRED") {
    if (row.committed_canonical_approval != null || row.committed_approval_digest != null ||
        row.committed_canonical_receipt != null || row.committed_receipt_sha256 != null) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Unapproved legal-hold operation unexpectedly contains approval or receipt data.", 500);
    }
    return row.operation_state === "REQUESTED"
      ? Object.freeze({ state: "REQUESTED" as const, operationRevision: 0 as const })
      : Object.freeze({ state: "EXPIRED" as const, operationRevision: 1 as const });
  }
  const approval = await parseStoredLegalHoldApproval(row, operation.operationId, operation.requestDigest);
  if (row.operation_state === "APPROVED") {
    if (row.committed_canonical_receipt != null || row.committed_receipt_sha256 != null) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Approved legal-hold operation unexpectedly contains a receipt.", 500);
    }
    return Object.freeze({ state: "APPROVED", operationRevision: 1, approval });
  }
  if (row.operation_state === "APPLYING") {
    if (typeof row.committed_application_attempt_id !== "string" || !/^[0-9a-f]{64}$/.test(row.committed_application_attempt_id) ||
        (row.committed_application_prior_status !== "ON" && row.committed_application_prior_status !== "OFF") ||
        typeof row.committed_application_observed_request_id !== "string" || typeof row.committed_application_started_at !== "string") {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold application precondition is incomplete.", 500);
    }
    return Object.freeze({ state: "APPLYING", operationRevision: 2, approval, applicationAttempt: Object.freeze({
      schemaVersion: 1, attemptId: row.committed_application_attempt_id, priorStatus: row.committed_application_prior_status,
      observedRequestId: row.committed_application_observed_request_id, startedAt: row.committed_application_started_at,
    }) });
  }
  const receipt = await parseStoredLegalHoldReceipt(row, operation);
  return Object.freeze({ state: "APPLIED", operationRevision: 3, approval, receipt });
}

function parseSingleLegalHoldRow(formattedRecords: string | undefined): LegalHoldResultRow {
  if (!formattedRecords || formattedRecords.length > 32_768) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold database response is invalid.", 500);
  }
  let rows: unknown;
  try { rows = JSON.parse(formattedRecords); } catch {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold database response is invalid.", 500);
  }
  if (!Array.isArray(rows) || rows.length !== 1 || !rows[0] || typeof rows[0] !== "object" || Array.isArray(rows[0])) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold database response is invalid.", 500);
  }
  return rows[0] as LegalHoldResultRow;
}

async function parseStoredLegalHoldApproval(
  row: LegalHoldResultRow,
  operationId: string,
  requestDigest: string,
): Promise<ExactVersionLegalHoldApproval> {
  if (typeof row.committed_canonical_approval !== "string" || typeof row.committed_approval_digest !== "string") {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold approval is incomplete.", 500);
  }
  const digest = await sha256Hex(`scopeproof-legal-hold-approval-v1\n${row.committed_canonical_approval}`);
  if (digest !== row.committed_approval_digest) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold approval digest is invalid.", 500);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(row.committed_canonical_approval); } catch {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold approval is invalid.", 500);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) ||
      stableJson(parsed as JsonValue) !== row.committed_canonical_approval) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold approval is not canonical.", 500);
  }
  const approval = parsed as unknown as ExactVersionLegalHoldApproval;
  const complete = Object.freeze({ ...approval, canonicalApproval: row.committed_canonical_approval, approvalDigest: digest });
  assertApprovalMatchesRequest(complete, operationId, requestDigest);
  return complete;
}

async function parseStoredLegalHoldReceipt(
  row: LegalHoldResultRow,
  operation: ExactVersionLegalHoldOperation,
): Promise<ExactVersionLegalHoldReceipt> {
  if (typeof row.committed_canonical_receipt !== "string" || typeof row.committed_receipt_sha256 !== "string") {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold receipt is incomplete.", 500);
  }
  const digest = await sha256Hex(`scopeproof-legal-hold-receipt-v1\n${row.committed_canonical_receipt}`);
  if (digest !== row.committed_receipt_sha256) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold receipt digest is invalid.", 500);
  }
  let parsed: unknown;
  try { parsed = JSON.parse(row.committed_canonical_receipt); } catch {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold receipt is invalid.", 500);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) ||
      stableJson(parsed as JsonValue) !== row.committed_canonical_receipt) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold receipt is not canonical.", 500);
  }
  const receipt = parsed as unknown as ExactVersionLegalHoldReceipt;
  assertReceiptMatchesOperation(receipt, operation);
  return Object.freeze(receipt);
}

export interface RdsAtomicPromotionStoreOptions {
  readonly executor: RdsDataApiExecutor;
  readonly resourceArn: string;
  readonly secretArn: string;
  readonly database: string;
  readonly kms: KmsAsymmetricSigningClient;
  readonly signingKeyArn: string;
  readonly clock?: () => Date;
}

const setTenantSql = "SELECT pg_catalog.set_config('scopeproof.tenant_id', :tenant_id, true)";
const claimPromotionFenceSql = [
  "SELECT committed_fence FROM scopeproof.claim_promotion_fence(",
  "  CAST(:upload_intent_id AS scopeproof.resource_identifier), CAST(:promotion_fence AS bigint),",
  "  :promotion_attempt_id, CAST(:lease_expires_at AS timestamptz)",
  ")",
].join("\n");
const reconcileSql = [
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
].join("\n");

/**
 * RDS Data API implementation of the reconciliation boundary. The database
 * function performs both CAS updates and the receipt insert in one transaction.
 */
export class RdsDataAtomicPromotionStore implements AtomicPromotionStore {
  readonly #options: Required<Pick<RdsAtomicPromotionStoreOptions, "executor" | "resourceArn" | "secretArn" | "database" | "kms" | "signingKeyArn">> & { clock: () => Date };

  constructor(options: RdsAtomicPromotionStoreOptions) {
    assertRdsConnection(options.resourceArn, options.secretArn, options.database);
    this.#options = {
      executor: options.executor,
      resourceArn: options.resourceArn,
      secretArn: options.secretArn,
      database: options.database,
      kms: options.kms,
      signingKeyArn: asKmsKeyArn(options.signingKeyArn),
      clock: options.clock ?? (() => new Date()),
    };
  }

  async transactPromotion(command: AtomicPromotionCommand): Promise<AtomicPromotionResult> {
    const canonicalFacts = stableJson(command.facts as unknown as JsonValue);
    const receiptSha256 = await sha256Hex(`scopeproof-promotion-receipt-v1\n${canonicalFacts}`);
    const signedAt = canonicalInstant(this.#options.clock(), "Promotion receipt time");
    if (Date.parse(signedAt) < Date.parse(command.facts.promotedAt)) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Promotion receipt cannot predate S3 promotion.");
    }
    const signed = await this.#options.kms.sign({
      KeyId: this.#options.signingKeyArn,
      Message: hexToBytes(receiptSha256),
      MessageType: "DIGEST",
      SigningAlgorithm: "RSASSA_PSS_SHA_256",
    });
    if (
      signed.KeyId !== this.#options.signingKeyArn ||
      signed.SigningAlgorithm !== "RSASSA_PSS_SHA_256" ||
      !(signed.Signature instanceof Uint8Array) ||
      signed.Signature.byteLength !== 384
    ) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "KMS returned an invalid RSA-3072 promotion receipt signature.");
    }
    const signature = bytesToBase64(signed.Signature);
    const connection = {
      resourceArn: this.#options.resourceArn,
      secretArn: this.#options.secretArn,
      database: this.#options.database,
    };
    const transaction = await this.#options.executor.beginTransaction(connection);
    const transactionId = transaction.transactionId;
    if (!transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transactionId)) {
      throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion database transaction could not be established.", 500);
    }
    try {
      await this.#options.executor.executeStatement({
        ...connection,
        transactionId,
        sql: setTenantSql,
        parameters: [stringParameter("tenant_id", command.tenantId)],
      });
      await this.#options.executor.executeStatement({
        ...connection,
        transactionId,
        sql: claimPromotionFenceSql,
        parameters: [
          stringParameter("upload_intent_id", command.facts.uploadIntentId),
          stringParameter("promotion_fence", String(command.facts.promotionFence)),
          stringParameter("promotion_attempt_id", command.facts.promotionAttemptId),
          stringParameter("lease_expires_at", command.promotionLeaseExpiresAt),
        ],
      });
      const response = await this.#options.executor.executeStatement({
        ...connection,
        transactionId,
        sql: reconcileSql,
        parameters: promotionParameters(command, canonicalFacts, receiptSha256, signature, signedAt, this.#options.signingKeyArn),
        formatRecordsAs: "JSON",
      });
      const snapshot = parsePromotionResult(
        response.formattedRecords,
        command.facts,
        signedAt,
        receiptSha256,
        this.#options.signingKeyArn,
      );
      const committedSignature = base64ToBytes(snapshot.signature);
      if (committedSignature.byteLength !== 384) {
        throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Stored promotion receipt signature has an invalid RSA-3072 length.", 500);
      }
      const verification = await this.#options.kms.verify({
        KeyId: this.#options.signingKeyArn,
        Message: hexToBytes(receiptSha256),
        MessageType: "DIGEST",
        SigningAlgorithm: "RSASSA_PSS_SHA_256",
        Signature: committedSignature,
      });
      if (
        verification.KeyId !== this.#options.signingKeyArn ||
        verification.SigningAlgorithm !== "RSASSA_PSS_SHA_256" ||
        verification.SignatureValid !== true
      ) {
        throw new TenantSecurityError("INVALID_AUDIT_EVENT", "KMS did not verify the committed promotion receipt signature.", 409);
      }
      await this.#options.executor.commitTransaction({ resourceArn: connection.resourceArn, secretArn: connection.secretArn, transactionId });
      return {
        outcome: snapshot.wasCreated ? "applied" : "already_applied",
        committed: true,
        snapshot: {
          receiptId: snapshot.receiptId,
          idempotencyDigest: snapshot.idempotencyDigest,
          uploadRevision: snapshot.uploadRevision,
          evidenceRevision: snapshot.evidenceRevision,
          facts: snapshot.facts,
        },
      };
    } catch (error) {
      try {
        await this.#options.executor.rollbackTransaction({ resourceArn: connection.resourceArn, secretArn: connection.secretArn, transactionId });
      } catch {
        // Preserve the authoritative database failure; monitoring alerts on rollback errors.
      }
      const reason = promotionFailureReason(error);
      if (reason) return { outcome: "condition_failed", committed: false, reason };
      throw error;
    }
  }
}

export interface RdsSignedAuditReceiptStoreOptions {
  readonly executor: RdsDataApiExecutor;
  readonly resourceArn: string;
  readonly secretArn: string;
  readonly database: string;
  readonly kms: KmsAsymmetricSigningClient;
  readonly signingKeyArn: string;
}

export interface CommittedSignedAuditReceipt {
  readonly outcome: "applied" | "already_applied";
  readonly sequence: number;
  readonly eventHash: string;
  readonly receipt: KmsSignedAuditReceipt;
}

const appendAuditSql = [
  "SELECT committed_sequence, committed_event_hash, was_created, committed_canonical_receipt,",
  "       committed_receipt_payload_sha256, committed_signature, committed_signed_at",
  "FROM scopeproof.append_signed_audit_event(",
  "  CAST(:sequence AS bigint), CAST(:event_id AS scopeproof.resource_identifier), CAST(:occurred_at AS timestamptz),",
  "  CAST(:actor AS jsonb), :action, :resource_type, CAST(:resource_id AS scopeproof.resource_identifier),",
  "  :request_id, :outcome, CAST(:details AS jsonb), :previous_hash, :event_hash, :canonical_event,",
  "  CAST(:receipt_payload AS jsonb), :canonical_receipt, :receipt_payload_sha256, :signing_key_arn,",
  "  :signing_algorithm, :signature, CAST(:signed_at AS timestamptz)",
  ")",
].join("\n");

/** Persists one KMS-verified audit receipt through the database hash-chain CAS. */
export class RdsDataSignedAuditReceiptStore {
  readonly #options: RdsSignedAuditReceiptStoreOptions;

  constructor(options: RdsSignedAuditReceiptStoreOptions) {
    assertRdsConnection(options.resourceArn, options.secretArn, options.database);
    this.#options = { ...options, signingKeyArn: asKmsKeyArn(options.signingKeyArn) };
  }

  async append(event: TenantAuditEvent, receipt: KmsSignedAuditReceipt): Promise<CommittedSignedAuditReceipt> {
    if (receipt.signingAlgorithm !== "RSASSA_PSS_SHA_256" || receipt.keyArn !== this.#options.signingKeyArn) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Production audit receipts require the configured RSA-PSS KMS key.", 409);
    }
    await verifyTenantAuditReceipt({
      client: this.#options.kms,
      receipt,
      expectedEvent: event,
      expectedKeyArn: this.#options.signingKeyArn,
      expectedTenantId: event.tenantId,
    });
    const unsignedEvent = Object.fromEntries(
      Object.entries(event).filter(([key]) => key !== "eventHash"),
    );
    const canonicalEvent = stableJson(unsignedEvent as unknown as JsonValue);
    const canonicalReceipt = stableJson(receipt.payload as unknown as JsonValue);
    const connection = {
      resourceArn: this.#options.resourceArn,
      secretArn: this.#options.secretArn,
      database: this.#options.database,
    };
    const transaction = await this.#options.executor.beginTransaction(connection);
    const transactionId = transaction.transactionId;
    if (!transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transactionId)) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit database transaction could not be established.", 500);
    }
    let stored: ReturnType<typeof parseAuditResult>;
    try {
      await this.#options.executor.executeStatement({
        ...connection,
        transactionId,
        sql: setTenantSql,
        parameters: [stringParameter("tenant_id", event.tenantId)],
      });
      const response = await this.#options.executor.executeStatement({
        ...connection,
        transactionId,
        sql: appendAuditSql,
        parameters: [
          stringParameter("sequence", String(event.sequence)),
          stringParameter("event_id", event.id),
          stringParameter("occurred_at", event.occurredAt),
          stringParameter("actor", stableJson(event.actor as unknown as JsonValue)),
          stringParameter("action", event.action),
          stringParameter("resource_type", event.resourceType),
          stringParameter("resource_id", event.resourceId),
          stringParameter("request_id", event.requestId),
          stringParameter("outcome", event.outcome),
          stringParameter("details", stableJson(event.details)),
          stringParameter("previous_hash", event.previousHash),
          stringParameter("event_hash", event.eventHash),
          stringParameter("canonical_event", canonicalEvent),
          stringParameter("receipt_payload", canonicalReceipt),
          stringParameter("canonical_receipt", canonicalReceipt),
          stringParameter("receipt_payload_sha256", receipt.payloadSha256),
          stringParameter("signing_key_arn", receipt.keyArn),
          stringParameter("signing_algorithm", receipt.signingAlgorithm),
          stringParameter("signature", receipt.signature),
          stringParameter("signed_at", receipt.payload.signedAt),
        ],
        formatRecordsAs: "JSON",
      });
      stored = parseAuditResult(response.formattedRecords, event, receipt);
      await this.#options.executor.commitTransaction({
        resourceArn: connection.resourceArn,
        secretArn: connection.secretArn,
        transactionId,
      });
    } catch (error) {
      try {
        await this.#options.executor.rollbackTransaction({
          resourceArn: connection.resourceArn,
          secretArn: connection.secretArn,
          transactionId,
        });
      } catch {
        // Preserve the authoritative append failure.
      }
      throw error;
    }
    await verifyTenantAuditReceipt({
      client: this.#options.kms,
      receipt: stored.receipt,
      expectedEvent: event,
      expectedKeyArn: this.#options.signingKeyArn,
      expectedTenantId: event.tenantId,
    });
    return stored;
  }
}

interface AuditResultRow {
  committed_sequence?: unknown;
  committed_event_hash?: unknown;
  was_created?: unknown;
  committed_canonical_receipt?: unknown;
  committed_receipt_payload_sha256?: unknown;
  committed_signature?: unknown;
  committed_signed_at?: unknown;
}

function parseAuditResult(
  formattedRecords: string | undefined,
  event: TenantAuditEvent,
  submitted: KmsSignedAuditReceipt,
): CommittedSignedAuditReceipt {
  if (!formattedRecords || formattedRecords.length > 65_536) throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit transaction response is invalid.", 500);
  let rows: unknown;
  try { rows = JSON.parse(formattedRecords); } catch { throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit transaction response is invalid.", 500); }
  if (!Array.isArray(rows) || rows.length !== 1 || !rows[0] || typeof rows[0] !== "object" || Array.isArray(rows[0])) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit transaction response is invalid.", 500);
  }
  const row = rows[0] as AuditResultRow;
  if (
    row.committed_sequence !== event.sequence ||
    row.committed_event_hash !== event.eventHash ||
    typeof row.was_created !== "boolean" ||
    typeof row.committed_canonical_receipt !== "string" ||
    typeof row.committed_receipt_payload_sha256 !== "string" ||
    typeof row.committed_signature !== "string" ||
    typeof row.committed_signed_at !== "string"
  ) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit transaction returned conflicting state.", 409);
  }
  let payload: unknown;
  try { payload = JSON.parse(row.committed_canonical_receipt); } catch { throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Stored audit receipt is invalid.", 500); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Stored audit receipt is invalid.", 500);
  }
  if (!("signedAt" in payload) || payload.signedAt !== row.committed_signed_at) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Stored audit receipt timestamp is inconsistent.", 409);
  }
  const receipt: KmsSignedAuditReceipt = Object.freeze({
    schemaVersion: 1,
    payload: payload as KmsSignedAuditReceipt["payload"],
    payloadSha256: row.committed_receipt_payload_sha256,
    keyArn: submitted.keyArn,
    signingAlgorithm: submitted.signingAlgorithm,
    signature: row.committed_signature,
  });
  return Object.freeze({
    outcome: row.was_created ? "applied" : "already_applied",
    sequence: event.sequence,
    eventHash: event.eventHash,
    receipt,
  });
}

function assertRdsConnection(resourceArn: string, secretArn: string, database: string): void {
  const resource = /^arn:(aws|aws-us-gov|aws-cn):rds:([a-z0-9-]+):(\d{12}):cluster:[A-Za-z0-9-]{1,63}$/.exec(String(resourceArn || ""));
  const secret = /^arn:(aws|aws-us-gov|aws-cn):secretsmanager:([a-z0-9-]+):(\d{12}):secret:[A-Za-z0-9/_+=.@-]{1,512}$/.exec(String(secretArn || ""));
  if (!resource || !secret || resource[1] !== secret[1] || resource[2] !== secret[2] || resource[3] !== secret[3]) {
    throw new Error("RDS cluster and secret must use valid ARNs in the same partition, region, and account.");
  }
  if (!/^[A-Za-z][A-Za-z0-9_]{0,62}$/.test(String(database || ""))) throw new Error("Database name is invalid.");
}

function stringParameter(name: string, value: string): { name: string; value: { stringValue: string } } {
  return { name, value: { stringValue: value } };
}

function promotionParameters(
  command: AtomicPromotionCommand,
  canonicalFacts: string,
  receiptSha256: string,
  signature: string,
  signedAt: string,
  signingKeyArn: string,
): readonly { name: string; value: { stringValue: string } }[] {
  const facts = command.facts;
  return [
    stringParameter("receipt_id", command.receiptId),
    stringParameter("upload_intent_id", facts.uploadIntentId),
    stringParameter("evidence_id", facts.evidenceId),
    stringParameter("quarantine_version_id", facts.quarantineVersionId),
    stringParameter("evidence_version_id", facts.evidenceVersionId),
    stringParameter("checksum_sha256", facts.sha256),
    stringParameter("kms_key_arn", facts.kmsKeyArn),
    stringParameter("object_lock_mode", facts.objectLockMode),
    stringParameter("retain_until", facts.retainUntil),
    stringParameter("required_retention_until", command.requiredRetentionUntil),
    stringParameter("expected_upload_revision", String(command.expectedUploadRevision)),
    stringParameter("expected_evidence_revision", String(command.expectedEvidenceRevision)),
    stringParameter("promotion_fence", String(facts.promotionFence)),
    stringParameter("promotion_attempt_id", facts.promotionAttemptId),
    stringParameter("idempotency_digest", command.idempotencyDigest),
    stringParameter("promotion_facts", canonicalFacts),
    stringParameter("canonical_receipt", canonicalFacts),
    stringParameter("receipt_sha256", receiptSha256),
    stringParameter("signing_key_arn", signingKeyArn),
    stringParameter("signing_algorithm", "RSASSA_PSS_SHA_256"),
    stringParameter("signature", signature),
    stringParameter("signed_at", signedAt),
    stringParameter("reconciled_at", facts.promotedAt),
  ];
}

interface PromotionResultRow {
  receipt_id?: unknown;
  was_created?: unknown;
  committed_upload_revision?: unknown;
  committed_evidence_revision?: unknown;
  committed_idempotency_digest?: unknown;
  committed_promotion_facts?: unknown;
  committed_canonical_receipt?: unknown;
  committed_receipt_sha256?: unknown;
  committed_signing_key_arn?: unknown;
  committed_signing_algorithm?: unknown;
  committed_signature?: unknown;
  committed_signed_at?: unknown;
}

function parsePromotionResult(
  formattedRecords: string | undefined,
  expectedFacts: PromotionFacts,
  verificationTime: string,
  expectedReceiptSha256: string,
  expectedSigningKeyArn: string,
): {
  receiptId: string;
  wasCreated: boolean;
  uploadRevision: number;
  evidenceRevision: number;
  idempotencyDigest: string;
  facts: PromotionFacts;
  signature: string;
  signedAt: string;
} {
  if (!formattedRecords || formattedRecords.length > 65_536) throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion transaction response is invalid.", 500);
  let rows: unknown;
  try { rows = JSON.parse(formattedRecords); } catch { throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion transaction response is invalid.", 500); }
  if (!Array.isArray(rows) || rows.length !== 1 || !rows[0] || typeof rows[0] !== "object" || Array.isArray(rows[0])) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion transaction response is invalid.", 500);
  }
  const row = rows[0] as PromotionResultRow;
  const committedFacts = parseBoundedJsonObject(row.committed_promotion_facts, "Promotion transaction facts");
  const committedSignedAt = typeof row.committed_signed_at === "string"
    ? canonicalInstant(row.committed_signed_at, "Committed promotion receipt time")
    : "";
  if (
    typeof row.receipt_id !== "string" ||
    typeof row.was_created !== "boolean" ||
    !Number.isSafeInteger(row.committed_upload_revision) ||
    !Number.isSafeInteger(row.committed_evidence_revision) ||
    typeof row.committed_idempotency_digest !== "string" ||
    row.committed_canonical_receipt !== stableJson(expectedFacts as unknown as JsonValue) ||
    row.committed_receipt_sha256 !== expectedReceiptSha256 ||
    row.committed_signing_key_arn !== expectedSigningKeyArn ||
    row.committed_signing_algorithm !== "RSASSA_PSS_SHA_256" ||
    typeof row.committed_signature !== "string" ||
    row.committed_signature.length !== 512 ||
    committedSignedAt.length === 0 ||
    Date.parse(committedSignedAt) < Date.parse(expectedFacts.promotedAt) ||
    Date.parse(committedSignedAt) > Date.parse(verificationTime) + 5 * 60_000 ||
    !exactStringRecordEqual(
      { facts: stableJson(committedFacts as JsonValue) },
      { facts: stableJson(expectedFacts as unknown as JsonValue) },
    )
  ) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Promotion transaction returned conflicting facts.", 409);
  }
  return {
    receiptId: row.receipt_id,
    wasCreated: row.was_created,
    uploadRevision: row.committed_upload_revision as number,
    evidenceRevision: row.committed_evidence_revision as number,
    idempotencyDigest: row.committed_idempotency_digest,
    facts: committedFacts as unknown as PromotionFacts,
    signature: row.committed_signature,
    signedAt: committedSignedAt,
  };
}

function parseBoundedJsonObject(value: unknown, label: string): Record<string, JsonValue> {
  let parsed = value;
  if (typeof value === "string") {
    if (value.length === 0 || value.length > 32_768) {
      throw new TenantSecurityError("UPLOAD_MISMATCH", `${label} are invalid.`, 500);
    }
    try { parsed = JSON.parse(value); } catch {
      throw new TenantSecurityError("UPLOAD_MISMATCH", `${label} are invalid.`, 500);
    }
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", `${label} are invalid.`, 500);
  }
  return parsed as Record<string, JsonValue>;
}

function promotionFailureReason(error: unknown): "missing" | "wrong_state" | "revision_changed" | "idempotency_conflict" | null {
  if (!error || typeof error !== "object") return null;
  const code = "databaseErrorCode" in error ? String(error.databaseErrorCode) : "";
  const message = "message" in error ? String(error.message) : "";
  const combined = `${code} ${message}`;
  if (/23505|idempotency conflict/i.test(combined)) return "idempotency_conflict";
  if (/P0002|no rows? returned|not found/i.test(combined)) return "missing";
  if (/40001|revision|could not be atomically/i.test(combined)) return "revision_changed";
  if (/23514|promotion facts|not reconcilable|wrong state/i.test(combined)) return "wrong_state";
  return null;
}
