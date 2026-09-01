const tenantPattern = /^ten_[a-f0-9]{32}$/;
const uploadPattern = /^upl_[a-f0-9]{32}$/;
const digestPattern = /^[a-f0-9]{64}$/;
const versionPattern = /^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/;
const activeStatuses = new Set(["issued", "quarantined", "validated"]);
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

export const UPLOAD_RECONCILIATION_GRACE_SECONDS = 7 * 24 * 60 * 60;
export const UPLOAD_LIFECYCLE_TTL_BUFFER_SECONDS = 15 * 24 * 60 * 60;
export const UPLOAD_ORPHAN_GRACE_SECONDS = 15 * 60;

export class MalformedUploadLifecycleError extends Error {
  constructor() {
    super("An indexed upload lifecycle failed its maintenance contract.");
    this.name = "MalformedUploadLifecycleError";
  }
}

export const SHARED_MAINTENANCE_KIND = "SharedPendingOrphanReconciliationState";
export const SHARED_MAINTENANCE_SCHEMA_VERSION = 1;
export const SHARED_MAINTENANCE_STATE_KEY = Object.freeze({
  PK: "MAINTENANCE#SHARED",
  SK: "PENDING_ORPHAN_RECONCILIATION",
});
export const TENANT_MAINTENANCE_DIRECTORY_KEY = "MAINTENANCE#TENANT_DIRECTORY";

export function parseMaintenanceEnvelope(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["schemaVersion", "type"]) ||
      value.schemaVersion !== 1 || value.type !== "scopeproof.maintenance.sweep") {
    throw new Error("Shared maintenance message is invalid.");
  }
  return Object.freeze({ schemaVersion: 1, type: "scopeproof.maintenance.sweep" });
}

export function parseActiveUploadLifecycle(item) {
  try {
    return parseActiveUploadLifecycleAuthority(item);
  } catch (error) {
    if (error instanceof MalformedUploadLifecycleError) throw error;
    throw new MalformedUploadLifecycleError();
  }
}

function parseActiveUploadLifecycleAuthority(item) {
  const tenantId = exactString(item, "tenantId");
  const id = exactString(item, "id");
  const status = exactString(item, "status");
  const revision = exactInteger(item, "revision");
  const schemaVersion = exactInteger(item, "schemaVersion");
  const expiresAt = exactInstant(item, "expiresAt");
  const ttlEpochSeconds = exactInteger(item, "ttlEpochSeconds");
  const kind = exactString(item, "kind");
  const partitionKey = exactString(item, "PK");
  const sortKey = exactString(item, "SK");
  const maintenanceIndexPartition = exactString(item, "GSI1PK");
  const maintenanceIndexSortKey = exactString(item, "GSI1SK");
  if (kind !== "UploadLifecycle" || schemaVersion !== 1 || !tenantPattern.test(tenantId) ||
      !uploadPattern.test(id) || partitionKey !== `TENANT#${tenantId}` || sortKey !== `UPLOAD#${id}` ||
      !activeStatuses.has(status) || revision !== expectedRevision(status)) {
    throw new Error("Active upload lifecycle authority is malformed.");
  }
  const expectedTtlEpochSeconds = Math.floor(Date.parse(expiresAt) / 1_000) +
    UPLOAD_RECONCILIATION_GRACE_SECONDS + UPLOAD_LIFECYCLE_TTL_BUFFER_SECONDS;
  if (ttlEpochSeconds !== expectedTtlEpochSeconds) {
    throw new Error("Active upload lifecycle reconciliation deadline is malformed.");
  }
  const reconciliationDeadline = new Date(
    Date.parse(expiresAt) + UPLOAD_RECONCILIATION_GRACE_SECONDS * 1_000,
  ).toISOString();
  const promotionLeaseExpiresAt = optionalInstant(item, "promotionLeaseExpiresAt");
  const promotionLeaseId = optionalString(item, "promotionLeaseId");
  const consumedAt = optionalInstant(item, "consumedAt");
  const validationCompletedAt = optionalValidationCompletedAt(item, tenantId);
  if ((status === "validated") !== Boolean(validationCompletedAt)) {
    throw new Error("Active upload lifecycle validation authority is malformed.");
  }
  const reconciliationDisposition = optionalString(item, "reconciliationDisposition");
  if (reconciliationDisposition !== undefined) {
    throw new Error("Upload lifecycle reconciliation disposition is malformed.");
  }
  if ((status === "issued" && (promotionLeaseId || promotionLeaseExpiresAt)) ||
      (status !== "issued" && (!promotionLeaseId || !digestPattern.test(promotionLeaseId) || !promotionLeaseExpiresAt))) {
    throw new Error("Upload lifecycle promotion lease authority is malformed.");
  }
  const maintenanceDueAt = status === "issued"
    ? reconciliationDeadline
    : promotionLeaseExpiresAt
      ? new Date(Date.parse(promotionLeaseExpiresAt) + UPLOAD_ORPHAN_GRACE_SECONDS * 1_000).toISOString()
      : undefined;
  if (!maintenanceDueAt || maintenanceIndexPartition !== `MAINTENANCE#UPLOAD#${tenantId}` ||
      maintenanceIndexSortKey !== `${maintenanceDueAt}#${id}`) {
    throw new Error("Upload lifecycle maintenance index authority is malformed.");
  }
  return Object.freeze({
    consumedAt,
    expiresAt,
    id,
    maintenanceIndexPartition,
    maintenanceIndexSortKey,
    partitionKey,
    promotionLeaseExpiresAt,
    reconciliationDisposition,
    reconciliationDeadline,
    revision,
    sortKey,
    status,
    tenantId,
    ttlEpochSeconds,
    validationCompletedAt,
  });
}

export function decideUploadReconciliation(intent, now, orphanGraceSeconds) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("Maintenance time is invalid.");
  if (!Number.isSafeInteger(orphanGraceSeconds) || orphanGraceSeconds < 60 || orphanGraceSeconds > 86_400) {
    throw new Error("Orphan grace period is invalid.");
  }
  if (intent.status === "issued") {
    return Date.parse(intent.reconciliationDeadline) <= now.getTime()
      ? Object.freeze({
          action: "expire",
          ageSeconds: Math.max(0, Math.floor((now.getTime() - Date.parse(intent.reconciliationDeadline)) / 1_000)),
        })
      : Object.freeze({ action: "none", ageSeconds: 0 });
  }
  const staleField = intent.promotionLeaseExpiresAt
    ? "promotionLeaseExpiresAt"
    : intent.validationCompletedAt
      ? "validation.completedAt"
      : "consumedAt";
  const staleBase = intent.promotionLeaseExpiresAt ?? intent.validationCompletedAt ?? intent.consumedAt;
  if (!staleBase) throw new MalformedUploadLifecycleError();
  const ageSeconds = Math.max(0, Math.floor((now.getTime() - Date.parse(staleBase)) / 1_000));
  if (ageSeconds < orphanGraceSeconds) return Object.freeze({ action: "none", ageSeconds });
  return Object.freeze({
    action: intent.reconciliationDisposition === "ACTION_REQUIRED" ? "observe_action_required" : "flag_action_required",
    ageSeconds,
    reason: intent.promotionLeaseExpiresAt ? "STALE_PROMOTION_LEASE" : "MISSING_PROMOTION_LEASE",
    staleBase,
    staleField,
  });
}

export function parseTenantDirectoryEntry(item) {
  const tenantId = exactString(item, "tenantId");
  const partitionKey = exactString(item, "PK");
  const sortKey = exactString(item, "SK");
  const kind = exactString(item, "kind");
  const schemaVersion = exactInteger(item, "schemaVersion");
  const status = exactString(item, "status");
  if (!tenantPattern.test(tenantId) || partitionKey !== TENANT_MAINTENANCE_DIRECTORY_KEY ||
      sortKey !== `TENANT#${tenantId}` || kind !== "TenantMaintenanceRegistration" ||
      schemaVersion !== 1 || status !== "REGISTERED") {
    throw new Error("Shared maintenance tenant directory entry is malformed.");
  }
  return Object.freeze({ active: true, tenantId });
}

export function exactCursor(item) {
  if (!item) return undefined;
  const partitionKey = optionalString(item, "cursorPk");
  const sortKey = optionalString(item, "cursorSk");
  if (!partitionKey && !sortKey) return undefined;
  const tenantId = typeof sortKey === "string" && sortKey.startsWith("TENANT#") ? sortKey.slice(7) : "";
  if (!partitionKey || !sortKey || partitionKey !== TENANT_MAINTENANCE_DIRECTORY_KEY ||
      !tenantPattern.test(tenantId) || containsAsciiControl(sortKey)) {
    throw new Error("Shared maintenance cursor is malformed.");
  }
  return Object.freeze({
    PK: { S: partitionKey },
    SK: { S: sortKey },
  });
}

function containsAsciiControl(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return true;
  }
  return false;
}

function expectedRevision(status) {
  if (status === "issued") return 0;
  if (status === "quarantined") return 1;
  return 2;
}

function exactString(item, name) {
  const value = item?.[name];
  if (!value || typeof value.S !== "string" || Object.keys(value).length !== 1 || value.S.length === 0) {
    throw new Error(`Invalid lifecycle ${name}.`);
  }
  return value.S;
}

function optionalString(item, name) {
  const value = item?.[name];
  if (value === undefined) return undefined;
  if (!value || typeof value.S !== "string" || Object.keys(value).length !== 1 || value.S.length === 0) {
    throw new Error(`Invalid lifecycle ${name}.`);
  }
  return value.S;
}

function exactInteger(item, name) {
  const value = item?.[name];
  if (!value || typeof value.N !== "string" || !/^(0|[1-9][0-9]*)$/.test(value.N) || Object.keys(value).length !== 1) {
    throw new Error(`Invalid lifecycle ${name}.`);
  }
  const parsed = Number(value.N);
  if (!Number.isSafeInteger(parsed)) throw new Error(`Invalid lifecycle ${name}.`);
  return parsed;
}

function exactInstant(item, name) {
  const value = exactString(item, name);
  return canonicalInstant(value, name);
}

function optionalInstant(item, name) {
  const value = optionalString(item, name);
  return value ? canonicalInstant(value, name) : undefined;
}

function optionalValidationCompletedAt(item, tenantId) {
  const value = item?.validation;
  if (value === undefined) return undefined;
  if (!isRecord(value) || Object.keys(value).length !== 1 || !isRecord(value.M)) {
    throw new Error("Invalid lifecycle validation.");
  }
  const validation = value.M;
  if (!sameKeys(validation, validationFields)) throw new Error("Invalid lifecycle validation.");

  const byteSize = exactInteger(validation, "byteSize");
  const completedAt = canonicalInstant(exactString(validation, "completedAt"), "validation.completedAt");
  const contentType = exactString(validation, "contentType");
  const key = exactString(validation, "key");
  const safe = exactBoolean(validation, "safe");
  const scannerDigest = exactString(validation, "scannerDigest");
  const scannerPolicy = exactString(validation, "scannerPolicy");
  const sha256 = exactString(validation, "sha256");
  const validationTenantId = exactString(validation, "tenantId");
  const versionId = exactString(validation, "versionId");
  if (byteSize < 1 || byteSize > 25 * 1024 * 1024 || !supportedMimeTypes.has(contentType) ||
      !exactObjectKey(key) || safe !== true || !digestPattern.test(scannerDigest) ||
      scannerPolicy !== "aws-guardduty-s3-malware-protection-v1" || !digestPattern.test(sha256) ||
      validationTenantId !== tenantId || !versionPattern.test(versionId)) {
    throw new Error("Invalid lifecycle validation.");
  }
  return completedAt;
}

function exactBoolean(item, name) {
  const value = item?.[name];
  if (!value || typeof value.BOOL !== "boolean" || Object.keys(value).length !== 1) {
    throw new Error(`Invalid lifecycle ${name}.`);
  }
  return value.BOOL;
}

function exactObjectKey(value) {
  if (!value || value.length > 512 || value.startsWith("/") || value.endsWith("/") || value.includes("//") ||
      value.includes("\\") || value.includes("%") || /(^|\/)\.\.?($|\/)/.test(value) || containsAsciiControl(value)) {
    return false;
  }
  return value.split("/").every((part) => /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(part));
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function sameKeys(value, expected) {
  const actual = Object.keys(value).sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function canonicalInstant(value, name) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new Error(`Invalid lifecycle ${name}.`);
  }
  return value;
}
