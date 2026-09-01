import { createHash } from "node:crypto";

export const DLP_RECEIPT_DOMAIN = "scopeproof-exact-version-dlp-receipt-v1";

const responseKeys = [
  "bucket", "byteSize", "contentType", "decision", "findingCount", "key",
  "policyVersion", "scannerRequestId", "scannedAt", "schemaVersion", "sha256",
  "tenantId", "versionId",
].sort();

export function buildExactVersionDlpRequest(input) {
  const request = Object.freeze({
    schemaVersion: 1,
    tenantId: exact(input?.tenantId, /^ten_[a-f0-9]{32}$/),
    bucket: exact(input?.bucket, /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/),
    key: bounded(input?.key, 32, 1024),
    versionId: bounded(input?.versionId, 1, 512),
    sha256: exact(input?.sha256, /^[a-f0-9]{64}$/),
    byteSize: positiveInteger(input?.byteSize, 26_214_400),
    contentType: exact(input?.contentType, /^(?:image\/png|application\/(?:json|spdx\+json|vnd\.cyclonedx\+json)|text\/(?:plain|csv))$/),
    policyVersion: exact(input?.policyVersion, /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/),
  });
  if (!request.key.startsWith(`tenants/${request.tenantId}/controls/`) || !request.key.includes("/quarantine/")) {
    throw new Error("The DLP request key is outside the exact tenant quarantine prefix.");
  }
  return request;
}

export function parseExactVersionDlpResponse(value, expected, now = new Date(), options = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      Object.keys(value).sort().join("\0") !== responseKeys.join("\0")) {
    throw new Error("The DLP scanner returned an invalid response contract.");
  }
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) throw new Error("The DLP verification clock is invalid.");
  const maximumAgeMilliseconds = options.maximumAgeMilliseconds === null
    ? null
    : options.maximumAgeMilliseconds ?? 15 * 60_000;
  if (maximumAgeMilliseconds !== null &&
      (!Number.isSafeInteger(maximumAgeMilliseconds) || maximumAgeMilliseconds < 60_000 || maximumAgeMilliseconds > 86_400_000)) {
    throw new Error("The DLP receipt age limit is invalid.");
  }
  const response = Object.freeze({
    schemaVersion: value.schemaVersion,
    tenantId: exact(value.tenantId, /^ten_[a-f0-9]{32}$/),
    bucket: exact(value.bucket, /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/),
    key: bounded(value.key, 32, 1024),
    versionId: bounded(value.versionId, 1, 512),
    sha256: exact(value.sha256, /^[a-f0-9]{64}$/),
    byteSize: positiveInteger(value.byteSize, 26_214_400),
    contentType: exact(value.contentType, /^(?:image\/png|application\/(?:json|spdx\+json|vnd\.cyclonedx\+json)|text\/(?:plain|csv))$/),
    policyVersion: exact(value.policyVersion, /^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/),
    decision: exact(value.decision, /^(?:CLEAN|BLOCKED)$/),
    findingCount: nonnegativeInteger(value.findingCount, 1_000_000),
    scannedAt: canonicalInstant(value.scannedAt),
    scannerRequestId: exact(value.scannerRequestId, /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/),
  });
  const request = buildExactVersionDlpRequest(expected);
  for (const name of ["tenantId", "bucket", "key", "versionId", "sha256", "byteSize", "contentType", "policyVersion"]) {
    if (response[name] !== request[name]) throw new Error("The DLP response is not bound to the exact requested object version.");
  }
  const scannedAtMilliseconds = Date.parse(response.scannedAt);
  if (response.schemaVersion !== 1 || scannedAtMilliseconds > now.getTime() + 60_000 ||
      (maximumAgeMilliseconds !== null && scannedAtMilliseconds < now.getTime() - maximumAgeMilliseconds)) {
    throw new Error("The DLP response version or timestamp is invalid.");
  }
  if ((response.decision === "CLEAN") !== (response.findingCount === 0)) {
    throw new Error("The DLP response decision conflicts with its finding count.");
  }
  const canonicalReceipt = stableJson(response);
  const receiptDigest = digestHex(`${DLP_RECEIPT_DOMAIN}\n${canonicalReceipt}`);
  return Object.freeze({ ...response, canonicalReceipt, receiptDigest });
}

function exact(value, pattern) {
  const text = typeof value === "string" ? value : "";
  if (!pattern.test(text)) throw new Error("The DLP contract contains an invalid field.");
  return text;
}

function bounded(value, minimum, maximum) {
  const text = typeof value === "string" ? value : "";
  if (text.length < minimum || text.length > maximum || text !== text.trim() || /[\p{Cc}\\]/u.test(text)) {
    throw new Error("The DLP contract contains an invalid bounded string.");
  }
  return text;
}

function positiveInteger(value, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) throw new Error("The DLP contract contains an invalid size.");
  return value;
}

function nonnegativeInteger(value, maximum) {
  if (!Number.isSafeInteger(value) || value < 0 || value > maximum) throw new Error("The DLP contract contains an invalid finding count.");
  return value;
}

function canonicalInstant(value) {
  if (typeof value !== "string") throw new Error("The DLP timestamp is invalid.");
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) throw new Error("The DLP timestamp is not canonical.");
  return value;
}

function stableJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "number") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
}

function digestHex(value) {
  return createHash("sha256").update(value, "utf8").digest("hex");
}
