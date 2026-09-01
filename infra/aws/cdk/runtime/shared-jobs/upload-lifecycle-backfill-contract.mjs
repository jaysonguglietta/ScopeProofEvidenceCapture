import { createHash } from "node:crypto";

const tenantPattern = /^ten_[a-f0-9]{32}$/;
const uploadPattern = /^upl_[a-f0-9]{32}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const tableNamePattern = /^[A-Za-z0-9_.-]{3,255}$/;
const versionPattern = /^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/;
const activeRevisions = Object.freeze({ issued: 0, quarantined: 1, validated: 2 });
const terminalRevisions = Object.freeze({ promoted: new Set([3]), rejected: new Set([1, 2, 3]), expired: new Set([1]) });
const supportedMimeTypes = new Set([
  "image/png",
  "application/json",
  "application/spdx+json",
  "application/vnd.cyclonedx+json",
  "text/plain",
  "text/csv",
]);
const validationFields = Object.freeze([
  "byteSize",
  "completedAt",
  "contentType",
  "key",
  "safe",
  "scannerDigest",
  "scannerPolicy",
  "sha256",
  "tenantId",
  "versionId",
]);

export const UPLOAD_LIFECYCLE_BACKFILL_SCHEMA_VERSION = 1;
export const UPLOAD_LIFECYCLE_LEGACY_TTL_SECONDS = 7 * 24 * 60 * 60;
export const UPLOAD_LIFECYCLE_CURRENT_TTL_SECONDS = 22 * 24 * 60 * 60;
export const UPLOAD_LIFECYCLE_ORPHAN_GRACE_SECONDS = 15 * 60;

export class MalformedUploadLifecycleBackfillAuthorityError extends Error {
  constructor() {
    super("Upload lifecycle backfill authority is malformed.");
    this.name = "MalformedUploadLifecycleBackfillAuthorityError";
  }
}

/**
 * Build a provider-ready, exact-CAS DynamoDB transaction without performing I/O.
 *
 * Outcomes:
 * - `upgrade`: `transaction` atomically upgrades the lifecycle and its paired
 *   idempotency reservation.
 * - `current`: both rows already carry the exact current authority.
 * - `terminal`: a strict terminal lifecycle needs no index or TTL mutation.
 */
export function planUploadLifecycleBackfill(input) {
  try {
    if (!isRecord(input) || !tableNamePattern.test(String(input.tableName ?? ""))) malformed();
    const tableName = input.tableName;
    const lifecycle = parseLifecycleIdentity(input.lifecycle);
    if (lifecycle.terminal) {
      assertTerminalLifecycle(input.lifecycle, lifecycle);
      return Object.freeze({
        outcome: "terminal",
        status: lifecycle.status,
        tenantId: lifecycle.tenantId,
        uploadId: lifecycle.uploadId,
      });
    }

    const active = parseActiveLifecycle(input.lifecycle, lifecycle);
    const request = parseRequestReservation(input.requestReservation, active);
    if (active.current && request.current) {
      return Object.freeze({
        outcome: "current",
        status: active.status,
        tenantId: active.tenantId,
        uploadId: active.uploadId,
      });
    }
    // The two TTLs are written atomically. Any mixed old/current pair is not a
    // valid migration state and must be independently reconciled, not guessed.
    if (active.current || request.current) malformed();

    const lifecycleValues = {
      ":evidenceProjectionDigest": { S: active.evidenceProjectionDigest },
      ":expiresAt": { S: active.expiresAt },
      ":fingerprint": { S: active.requestFingerprint },
      ":id": { S: active.uploadId },
      ":idempotencyDigest": { S: active.idempotencyDigest },
      ":indexPk": { S: active.expectedIndexPartition },
      ":indexSk": { S: active.expectedIndexSort },
      ":kind": { S: "UploadLifecycle" },
      ":legacyTtl": { N: String(active.legacyTtl) },
      ":newTtl": { N: String(active.currentTtl) },
      ":revision": { N: String(active.revision) },
      ":schema": { N: String(UPLOAD_LIFECYCLE_BACKFILL_SCHEMA_VERSION) },
      ":status": { S: active.status },
      ":tenant": { S: active.tenantId },
      ...active.stateValues,
    };
    const indexCondition = active.legacyIndexPresent
      ? "GSI1PK = :indexPk AND GSI1SK = :indexSk"
      : "attribute_not_exists(GSI1PK) AND attribute_not_exists(GSI1SK)";
    const lifecycleCondition = [
      "#kind = :kind",
      "schemaVersion = :schema",
      "tenantId = :tenant",
      "id = :id",
      "#status = :status",
      "#revision = :revision",
      "expiresAt = :expiresAt",
      "ttlEpochSeconds = :legacyTtl",
      "idempotencyDigest = :idempotencyDigest",
      "requestFingerprint = :fingerprint",
      "evidenceProjectionDigest = :evidenceProjectionDigest",
      indexCondition,
      ...active.stateConditions,
      "attribute_not_exists(reconciliationDisposition)",
      "attribute_not_exists(reconciliationActionKey)",
      "attribute_not_exists(reconciliationDetectedAt)",
      "attribute_not_exists(reconciliationReason)",
    ].join(" AND ");
    const requestValues = {
      ":evidenceProjectionDigest": { S: request.evidenceProjectionDigest },
      ":fingerprint": { S: request.requestFingerprint },
      ":id": { S: request.uploadId },
      ":idempotencyDigest": { S: request.idempotencyDigest },
      ":kind": { S: "UploadIdempotencyReservation" },
      ":legacyTtl": { N: String(active.legacyTtl) },
      ":newTtl": { N: String(active.currentTtl) },
      ":tenant": { S: request.tenantId },
    };
    const transaction = Object.freeze({
      ClientRequestToken: backfillToken(active),
      TransactItems: Object.freeze([
        Object.freeze({
          Update: Object.freeze({
            ConditionExpression: lifecycleCondition,
            ExpressionAttributeNames: Object.freeze({ "#kind": "kind", "#revision": "revision", "#status": "status" }),
            ExpressionAttributeValues: freezeAttributeMap(lifecycleValues),
            Key: freezeAttributeMap({ PK: { S: active.partitionKey }, SK: { S: active.sortKey } }),
            TableName: tableName,
            UpdateExpression: "SET GSI1PK = :indexPk, GSI1SK = :indexSk, ttlEpochSeconds = :newTtl",
          }),
        }),
        Object.freeze({
          Update: Object.freeze({
            ConditionExpression: "#kind = :kind AND tenantId = :tenant AND intentId = :id AND idempotencyDigest = :idempotencyDigest AND requestFingerprint = :fingerprint AND evidenceProjectionDigest = :evidenceProjectionDigest AND ttlEpochSeconds = :legacyTtl",
            ExpressionAttributeNames: Object.freeze({ "#kind": "kind" }),
            ExpressionAttributeValues: freezeAttributeMap(requestValues),
            Key: freezeAttributeMap({ PK: { S: request.partitionKey }, SK: { S: request.sortKey } }),
            TableName: tableName,
            UpdateExpression: "SET ttlEpochSeconds = :newTtl",
          }),
        }),
      ]),
    });
    return Object.freeze({
      outcome: "upgrade",
      status: active.status,
      tenantId: active.tenantId,
      transaction,
      uploadId: active.uploadId,
    });
  } catch (error) {
    if (error instanceof MalformedUploadLifecycleBackfillAuthorityError) throw error;
    throw new MalformedUploadLifecycleBackfillAuthorityError();
  }
}

function parseLifecycleIdentity(item) {
  if (!isRecord(item)) malformed();
  const partitionKey = exactString(item, "PK");
  const sortKey = exactString(item, "SK");
  const tenantId = exactString(item, "tenantId");
  const uploadId = exactString(item, "id");
  const status = exactString(item, "status");
  const revision = exactInteger(item, "revision");
  if (!tenantPattern.test(tenantId) || !uploadPattern.test(uploadId) ||
      partitionKey !== `TENANT#${tenantId}` || sortKey !== `UPLOAD#${uploadId}` ||
      exactString(item, "kind") !== "UploadLifecycle" ||
      exactInteger(item, "schemaVersion") !== UPLOAD_LIFECYCLE_BACKFILL_SCHEMA_VERSION) malformed();
  const activeRevision = activeRevisions[status];
  if (activeRevision !== undefined) {
    if (revision !== activeRevision) malformed();
    return Object.freeze({ partitionKey, revision, sortKey, status, tenantId, terminal: false, uploadId });
  }
  const allowedTerminalRevisions = terminalRevisions[status];
  if (!allowedTerminalRevisions?.has(revision)) malformed();
  return Object.freeze({ partitionKey, revision, sortKey, status, tenantId, terminal: true, uploadId });
}

function parseActiveLifecycle(item, identity) {
  const expiresAt = exactInstant(item, "expiresAt");
  const legacyTtl = Math.floor(Date.parse(expiresAt) / 1_000) + UPLOAD_LIFECYCLE_LEGACY_TTL_SECONDS;
  const currentTtl = Math.floor(Date.parse(expiresAt) / 1_000) + UPLOAD_LIFECYCLE_CURRENT_TTL_SECONDS;
  const ttl = exactInteger(item, "ttlEpochSeconds");
  if (!Number.isSafeInteger(legacyTtl) || !Number.isSafeInteger(currentTtl) ||
      (ttl !== legacyTtl && ttl !== currentTtl)) malformed();
  const idempotencyDigest = exactDigest(item, "idempotencyDigest");
  const requestFingerprint = exactDigest(item, "requestFingerprint");
  const evidenceProjectionDigest = exactDigest(item, "evidenceProjectionDigest");
  const expectedIndexPartition = `MAINTENANCE#UPLOAD#${identity.tenantId}`;
  const stateConditions = [];
  const stateValues = {};
  let expectedDueAt;
  if (identity.status === "issued") {
    expectedDueAt = new Date(Date.parse(expiresAt) + UPLOAD_LIFECYCLE_LEGACY_TTL_SECONDS * 1_000).toISOString();
    assertAbsent(item, ["consumedAt", "promotionLeaseId", "promotionLeaseExpiresAt", "validation"]);
    stateConditions.push(
      "attribute_not_exists(consumedAt)",
      "attribute_not_exists(promotionLeaseId)",
      "attribute_not_exists(promotionLeaseExpiresAt)",
      "attribute_not_exists(validation)",
    );
  } else {
    const consumedAt = exactInstant(item, "consumedAt");
    const promotionLeaseId = exactDigest(item, "promotionLeaseId");
    const promotionLeaseExpiresAt = exactInstant(item, "promotionLeaseExpiresAt");
    expectedDueAt = new Date(Date.parse(promotionLeaseExpiresAt) + UPLOAD_LIFECYCLE_ORPHAN_GRACE_SECONDS * 1_000).toISOString();
    stateValues[":consumedAt"] = { S: consumedAt };
    stateValues[":leaseExpiresAt"] = { S: promotionLeaseExpiresAt };
    stateValues[":leaseId"] = { S: promotionLeaseId };
    stateConditions.push(
      "consumedAt = :consumedAt",
      "promotionLeaseId = :leaseId",
      "promotionLeaseExpiresAt = :leaseExpiresAt",
    );
    if (identity.status === "validated") {
      const validationCompletedAt = exactValidationCompletedAt(item, identity.tenantId);
      stateValues[":validationCompletedAt"] = { S: validationCompletedAt };
      stateConditions.push("validation.completedAt = :validationCompletedAt");
    } else {
      assertAbsent(item, ["validation"]);
      stateConditions.push("attribute_not_exists(validation)");
    }
  }
  const expectedIndexSort = `${expectedDueAt}#${identity.uploadId}`;
  const indexPk = optionalString(item, "GSI1PK");
  const indexSk = optionalString(item, "GSI1SK");
  const legacyIndexPresent = indexPk !== undefined || indexSk !== undefined;
  if (legacyIndexPresent && (indexPk !== expectedIndexPartition || indexSk !== expectedIndexSort)) malformed();
  const current = ttl === currentTtl;
  if (current && !legacyIndexPresent) malformed();
  return Object.freeze({
    ...identity,
    current,
    currentTtl,
    evidenceProjectionDigest,
    expectedIndexPartition,
    expectedIndexSort,
    expiresAt,
    idempotencyDigest,
    legacyIndexPresent,
    legacyTtl,
    requestFingerprint,
    stateConditions: Object.freeze(stateConditions),
    stateValues: freezeAttributeMap(stateValues),
  });
}

function parseRequestReservation(item, active) {
  if (!isRecord(item)) malformed();
  const partitionKey = exactString(item, "PK");
  const sortKey = exactString(item, "SK");
  const tenantId = exactString(item, "tenantId");
  const uploadId = exactString(item, "intentId");
  const idempotencyDigest = exactDigest(item, "idempotencyDigest");
  const requestFingerprint = exactDigest(item, "requestFingerprint");
  const evidenceProjectionDigest = exactDigest(item, "evidenceProjectionDigest");
  const ttl = exactInteger(item, "ttlEpochSeconds");
  if (partitionKey !== active.partitionKey || tenantId !== active.tenantId || uploadId !== active.uploadId ||
      sortKey !== `UPLOAD_REQUEST#${active.idempotencyDigest}` ||
      exactString(item, "kind") !== "UploadIdempotencyReservation" ||
      idempotencyDigest !== active.idempotencyDigest || requestFingerprint !== active.requestFingerprint ||
      evidenceProjectionDigest !== active.evidenceProjectionDigest ||
      (ttl !== active.legacyTtl && ttl !== active.currentTtl)) malformed();
  return Object.freeze({
    current: ttl === active.currentTtl,
    evidenceProjectionDigest,
    idempotencyDigest,
    partitionKey,
    requestFingerprint,
    sortKey,
    tenantId,
    uploadId,
  });
}

function assertTerminalLifecycle(item, identity) {
  exactInstant(item, "expiresAt");
  const ttl = exactInteger(item, "ttlEpochSeconds");
  const expiresAt = exactString(item, "expiresAt");
  const legacyTtl = Math.floor(Date.parse(expiresAt) / 1_000) + UPLOAD_LIFECYCLE_LEGACY_TTL_SECONDS;
  const currentTtl = Math.floor(Date.parse(expiresAt) / 1_000) + UPLOAD_LIFECYCLE_CURRENT_TTL_SECONDS;
  if ((ttl !== legacyTtl && ttl !== currentTtl) || item.GSI1PK !== undefined || item.GSI1SK !== undefined) malformed();
  if (identity.status === "promoted" && identity.revision !== 3) malformed();
}

function exactValidationCompletedAt(item, tenantId) {
  const value = item.validation;
  if (!isRecord(value) || !sameKeys(value, ["M"]) || !isRecord(value.M) || !sameKeys(value.M, validationFields)) malformed();
  const validation = value.M;
  const byteSize = exactInteger(validation, "byteSize");
  const completedAt = exactInstant(validation, "completedAt");
  const contentType = exactString(validation, "contentType");
  const key = exactString(validation, "key");
  const safe = exactBoolean(validation, "safe");
  const scannerDigest = exactDigest(validation, "scannerDigest");
  const scannerPolicy = exactString(validation, "scannerPolicy");
  const sha256 = exactDigest(validation, "sha256");
  const validationTenant = exactString(validation, "tenantId");
  const versionId = exactString(validation, "versionId");
  if (byteSize < 1 || byteSize > 25 * 1024 * 1024 || !supportedMimeTypes.has(contentType) ||
      !exactObjectKey(key) || safe !== true || scannerPolicy !== "aws-guardduty-s3-malware-protection-v1" ||
      !digestPattern.test(scannerDigest) || !digestPattern.test(sha256) || validationTenant !== tenantId ||
      !versionPattern.test(versionId)) malformed();
  return completedAt;
}

function backfillToken(active) {
  return createHash("sha256").update([
    "scopeproof-upload-lifecycle-backfill-v1",
    active.partitionKey,
    active.sortKey,
    active.status,
    String(active.revision),
    active.expiresAt,
    String(active.legacyTtl),
    String(active.currentTtl),
    active.expectedIndexSort,
  ].join("\n")).digest("hex").slice(0, 36);
}

function exactString(item, name) {
  const value = item?.[name];
  if (!isRecord(value) || !sameKeys(value, ["S"]) || typeof value.S !== "string" || value.S.length < 1) malformed();
  return value.S;
}

function optionalString(item, name) {
  if (item?.[name] === undefined) return undefined;
  return exactString(item, name);
}

function exactDigest(item, name) {
  const value = exactString(item, name);
  if (!digestPattern.test(value)) malformed();
  return value;
}

function exactInteger(item, name) {
  const value = item?.[name];
  if (!isRecord(value) || !sameKeys(value, ["N"]) || typeof value.N !== "string" ||
      !/^(0|[1-9][0-9]*)$/.test(value.N)) malformed();
  const parsed = Number(value.N);
  if (!Number.isSafeInteger(parsed)) malformed();
  return parsed;
}

function exactBoolean(item, name) {
  const value = item?.[name];
  if (!isRecord(value) || !sameKeys(value, ["BOOL"]) || typeof value.BOOL !== "boolean") malformed();
  return value.BOOL;
}

function exactInstant(item, name) {
  const value = exactString(item, name);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) malformed();
  return value;
}

function assertAbsent(item, fields) {
  if (fields.some((field) => item[field] !== undefined)) malformed();
}

function exactObjectKey(value) {
  if (!value || value.length > 512 || value.startsWith("/") || value.endsWith("/") || value.includes("//") ||
      value.includes("\\") || value.includes("%") || /(^|\/)\.\.?($|\/)/.test(value) || containsAsciiControl(value)) return false;
  return value.split("/").every((part) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(part));
}

function containsAsciiControl(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}

function freezeAttributeMap(value) {
  return Object.freeze(Object.fromEntries(Object.entries(value).map(([key, attribute]) => [key, Object.freeze({ ...attribute })])));
}

function sameKeys(value, expected) {
  const actual = Object.keys(value).sort();
  const orderedExpected = [...expected].sort();
  return actual.length === orderedExpected.length && actual.every((key, index) => key === orderedExpected[index]);
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function malformed() {
  throw new MalformedUploadLifecycleBackfillAuthorityError();
}
