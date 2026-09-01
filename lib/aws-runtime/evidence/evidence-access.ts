import {
  asResourceId,
  asSha256,
  asTenantId,
  asUserId,
  assertBoundedText,
  assertRevision,
  assertVersionId,
  canonicalInstant,
  stableJson,
  TenantSecurityError,
  type JsonValue,
  type Sha256Hex,
  type TenantId,
  type UserId,
} from "../contracts.ts";
import { assertTenantOwned, type TenantActor } from "../tenancy.ts";
import { asControlId, asEvidenceMimeType, buildControlledEvidenceObjectKey } from "./primitives.ts";

export type DownloadableEvidenceStatus = "NEEDS_REVIEW" | "APPROVED" | "EXPIRED";

export interface EvidenceArtifactAccessRecord {
  readonly tenantId: TenantId;
  readonly evidenceId: string;
  readonly controlId: string;
  readonly title: string;
  readonly description: string;
  readonly evidenceType: "SCREENSHOT" | "CODE" | "CONFIGURATION" | "REPORT" | "SBOM" | "EXPORT";
  readonly source: string;
  readonly systemName: string;
  readonly status: DownloadableEvidenceStatus;
  readonly revision: number;
  readonly contentType: string;
  readonly byteSize: number;
  readonly checksumSha256: Sha256Hex;
  readonly evidenceBucket: string;
  readonly objectKey: string;
  readonly objectVersionId: string;
  readonly capturedAt: string;
  readonly retainUntil: string;
  readonly createdAt: string;
}

export interface EvidencePageCursor {
  readonly capturedAt: string;
  readonly evidenceId: string;
}

export interface EvidenceAccessRepository {
  list(input: Readonly<{
    tenantId: TenantId;
    requestedBy: UserId;
    limit: number;
    cursor?: EvidencePageCursor;
  }>): Promise<readonly EvidenceArtifactAccessRecord[]>;

  readExact(input: Readonly<{
    tenantId: TenantId;
    requestedBy: UserId;
    evidenceId: string;
    expectedRevision: number;
  }>): Promise<EvidenceArtifactAccessRecord | null>;
}

export interface ExactGetObjectPresignInput {
  readonly bucket: string;
  readonly key: string;
  readonly versionId: string;
  readonly expectedBucketOwner: string;
  readonly signingAt: string;
  readonly expiresAt: string;
  readonly expiresInSeconds: number;
  readonly responseContentType: string;
  readonly responseContentDisposition: string;
  readonly requiredHeaders: Readonly<Record<string, string>>;
}

export interface ExactPresignedGetObject {
  readonly method: "GET";
  readonly url: string;
  readonly bucket: string;
  readonly key: string;
  readonly versionId: string;
  readonly expiresAt: string;
  readonly requiredHeaders: Readonly<Record<string, string>>;
}

export interface ExactGetObjectPresigner {
  presignGetObject(input: ExactGetObjectPresignInput): Promise<ExactPresignedGetObject>;
}

export interface EvidenceListPage {
  readonly items: readonly EvidenceArtifactAccessRecord[];
  readonly nextCursor?: string;
}

export interface IssuedEvidenceDownload {
  readonly evidence: EvidenceArtifactAccessRecord;
  readonly download: ExactPresignedGetObject;
}

const evidenceTypes = new Set(["SCREENSHOT", "CODE", "CONFIGURATION", "REPORT", "SBOM", "EXPORT"]);
const downloadableStatuses = new Set(["NEEDS_REVIEW", "APPROVED", "EXPIRED"]);
const bucketPattern = /^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;
const contentTypePattern = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$/;
const accountPattern = /^\d{12}$/;
const hostnamePattern = /^[a-z0-9](?:[a-z0-9.-]{1,251}[a-z0-9])$/;
const regionPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

export class HostedEvidenceAccessService {
  readonly #repository: EvidenceAccessRepository;
  readonly #presigner: ExactGetObjectPresigner;
  readonly #endpointHostname: string;
  readonly #signingRegion: string;
  readonly #expectedBucketOwner: string;
  readonly #clock: () => Date;
  readonly #downloadTtlSeconds: number;
  readonly #cursorSecrets: readonly Uint8Array<ArrayBuffer>[];
  readonly #cursorTtlSeconds: number;

  constructor(options: Readonly<{
    repository: EvidenceAccessRepository;
    presigner: ExactGetObjectPresigner;
    endpointHostname: string;
    signingRegion: string;
    expectedBucketOwner: string;
    clock?: () => Date;
    downloadTtlSeconds?: number;
    cursorSecret: Uint8Array;
    previousCursorSecrets?: readonly Uint8Array[];
    cursorTtlSeconds?: number;
  }>) {
    if (!options.repository || !options.presigner) throw new Error("Evidence access dependencies are required.");
    const endpointHostname = String(options.endpointHostname || "").toLowerCase();
    if (!hostnamePattern.test(endpointHostname) || endpointHostname.includes("..") || endpointHostname.endsWith(".")) {
      throw new Error("Evidence S3 endpoint hostname is invalid.");
    }
    const signingRegion = String(options.signingRegion || "").toLowerCase();
    if (!regionPattern.test(signingRegion) || signingRegion.includes("--")) {
      throw new Error("Evidence S3 signing region is invalid.");
    }
    const expectedBucketOwner = String(options.expectedBucketOwner || "");
    if (!accountPattern.test(expectedBucketOwner)) throw new Error("Evidence bucket owner account is invalid.");
    const ttl = options.downloadTtlSeconds ?? 60;
    if (!Number.isSafeInteger(ttl) || ttl < 30 || ttl > 300) throw new Error("Evidence download TTL must be between 30 seconds and five minutes.");
    if (!(options.cursorSecret instanceof Uint8Array) || options.cursorSecret.byteLength < 32 || options.cursorSecret.byteLength > 64) {
      throw new Error("Evidence cursor HMAC secret must contain 32 to 64 bytes.");
    }
    const previousCursorSecrets = options.previousCursorSecrets ?? [];
    if (!Array.isArray(previousCursorSecrets) || previousCursorSecrets.length > 2 || previousCursorSecrets.some((secret) =>
      !(secret instanceof Uint8Array) || secret.byteLength < 32 || secret.byteLength > 64
    )) {
      throw new Error("Previous evidence cursor HMAC secrets are invalid.");
    }
    const suppliedSecrets = [options.cursorSecret, ...previousCursorSecrets];
    if (suppliedSecrets.some((secret, index) => suppliedSecrets.slice(0, index).some((prior) => constantTimeBytesEqual(secret, prior)))) {
      throw new Error("Evidence cursor HMAC secrets must be distinct.");
    }
    const cursorTtlSeconds = options.cursorTtlSeconds ?? 900;
    if (!Number.isSafeInteger(cursorTtlSeconds) || cursorTtlSeconds < 60 || cursorTtlSeconds > 3_600) {
      throw new Error("Evidence cursor TTL must be between one minute and one hour.");
    }
    this.#repository = options.repository;
    this.#presigner = options.presigner;
    this.#endpointHostname = endpointHostname;
    this.#signingRegion = signingRegion;
    this.#expectedBucketOwner = expectedBucketOwner;
    this.#clock = options.clock ?? (() => new Date());
    this.#downloadTtlSeconds = ttl;
    this.#cursorSecrets = Object.freeze(suppliedSecrets.map((secret) => {
      const copy = new Uint8Array(secret.byteLength);
      copy.set(secret);
      return copy;
    }));
    this.#cursorTtlSeconds = cursorTtlSeconds;
  }

  async list(actor: TenantActor, input: Readonly<{ limit?: number; cursor?: string }>): Promise<EvidenceListPage> {
    const tenantId = asTenantId(actor.tenantId);
    const requestedBy = asUserId(actor.userId);
    const limit = input.limit ?? 50;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
      throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence page size must be between 1 and 100.");
    }
    const now = this.#clock();
    const cursor = input.cursor ? await decodeEvidenceCursorWithRotation(input.cursor, tenantId, this.#cursorSecrets, now) : undefined;
    const rows = await this.#repository.list({ tenantId, requestedBy, limit: limit + 1, cursor });
    if (!Array.isArray(rows) || rows.length > limit + 1) {
      throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence repository returned an invalid page.", 500);
    }
    const normalized = rows.map((row) => normalizeEvidenceRecord(row));
    normalized.forEach((row) => assertTenantOwned(actor, { tenantId: row.tenantId, id: row.evidenceId }));
    const hasMore = normalized.length > limit;
    const items = Object.freeze(normalized.slice(0, limit));
    const last = items.at(-1);
    return Object.freeze({
      items,
      ...(hasMore && last ? {
        nextCursor: await encodeEvidenceCursor(
          { capturedAt: last.capturedAt, evidenceId: last.evidenceId },
          tenantId,
          this.#cursorSecrets[0],
          now,
          this.#cursorTtlSeconds,
        ),
      } : {}),
    });
  }

  async issueDownload(actor: TenantActor, input: Readonly<{ evidenceId: string; expectedRevision: number }>): Promise<IssuedEvidenceDownload> {
    const tenantId = asTenantId(actor.tenantId);
    const requestedBy = asUserId(actor.userId);
    const evidenceId = String(asResourceId(input.evidenceId, ["evd"]));
    if (!Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0) {
      throw new TenantSecurityError("INVALID_IDENTIFIER", "Expected evidence revision is invalid.");
    }
    const found = await this.#repository.readExact({ tenantId, requestedBy, evidenceId, expectedRevision: input.expectedRevision });
    if (!found) throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Resource not found.", 404);
    assertTenantOwned(actor, { tenantId: found.tenantId, id: found.evidenceId });
    const evidence = normalizeEvidenceRecord(found);
    assertRevision(evidence.revision, input.expectedRevision);

    const signingAt = canonicalInstant(this.#clock(), "Download signing time");
    const expiresAt = new Date(Date.parse(signingAt) + this.#downloadTtlSeconds * 1_000).toISOString();
    const presignInput: ExactGetObjectPresignInput = Object.freeze({
      bucket: evidence.evidenceBucket,
      key: evidence.objectKey,
      versionId: evidence.objectVersionId,
      expectedBucketOwner: this.#expectedBucketOwner,
      signingAt,
      expiresAt,
      expiresInSeconds: this.#downloadTtlSeconds,
      responseContentType: evidence.contentType,
      responseContentDisposition: `attachment; filename="${safeDownloadFilename(evidence)}"`,
      requiredHeaders: Object.freeze({
        "x-amz-checksum-mode": "ENABLED",
        "x-amz-expected-bucket-owner": this.#expectedBucketOwner,
      }),
    });
    const download = await this.#presigner.presignGetObject(presignInput);
    assertExactDownload(presignInput, download, this.#endpointHostname, this.#signingRegion);
    return Object.freeze({
      evidence,
      download: Object.freeze({ ...download, requiredHeaders: Object.freeze({ ...download.requiredHeaders }) }),
    });
  }
}

export async function encodeEvidenceCursor(
  value: EvidencePageCursor,
  tenantIdValue: string,
  secret: Uint8Array,
  now: Date,
  ttlSeconds = 900,
): Promise<string> {
  const tenantId = asTenantId(tenantIdValue);
  const normalized = normalizeEvidenceCursor(value);
  const issuedAt = canonicalInstant(now, "Evidence cursor issue time");
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 60 || ttlSeconds > 3_600) throw new Error("Evidence cursor TTL is invalid.");
  const expiresAt = new Date(Date.parse(issuedAt) + ttlSeconds * 1_000).toISOString();
  const body = stableJson({ schemaVersion: 1, tenantId, ...normalized, issuedAt, expiresAt } as JsonValue);
  const signature = await cursorHmac(secret, body);
  return `${Buffer.from(body, "utf8").toString("base64url")}.${Buffer.from(signature).toString("base64url")}`;
}

export async function decodeEvidenceCursor(
  value: string,
  expectedTenantIdValue: string,
  secret: Uint8Array,
  now: Date,
): Promise<EvidencePageCursor> {
  const cursor = String(value || "");
  const expectedTenantId = asTenantId(expectedTenantIdValue);
  const parts = cursor.split(".");
  if (parts.length !== 2 || !/^[A-Za-z0-9_-]{80,1024}$/.test(parts[0]) || !/^[A-Za-z0-9_-]{43}$/.test(parts[1])) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence cursor is invalid.");
  }
  let decoded: string;
  let suppliedSignature: Uint8Array;
  try {
    const bytes = Buffer.from(parts[0], "base64url");
    suppliedSignature = new Uint8Array(Buffer.from(parts[1], "base64url"));
    decoded = bytes.toString("utf8");
    if (bytes.toString("base64url") !== parts[0] || Buffer.from(suppliedSignature).toString("base64url") !== parts[1] || bytes.byteLength > 768 || suppliedSignature.byteLength !== 32) {
      throw new Error("non-canonical cursor");
    }
  } catch {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence cursor is invalid.");
  }
  const expectedSignature = await cursorHmac(secret, decoded);
  if (!constantTimeBytesEqual(expectedSignature, suppliedSignature)) throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence cursor is invalid.");
  let parsed: unknown;
  try { parsed = JSON.parse(decoded); } catch { throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence cursor is invalid."); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || Object.keys(parsed).sort().join(",") !== "capturedAt,evidenceId,expiresAt,issuedAt,schemaVersion,tenantId") {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence cursor is invalid.");
  }
  const record = parsed as Record<string, unknown>;
  if (record.schemaVersion !== 1 || record.tenantId !== expectedTenantId || typeof record.capturedAt !== "string" || typeof record.evidenceId !== "string" ||
      typeof record.issuedAt !== "string" || typeof record.expiresAt !== "string") {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence cursor is invalid.");
  }
  const issuedAt = canonicalInstant(record.issuedAt, "Evidence cursor issue time");
  const expiresAt = canonicalInstant(record.expiresAt, "Evidence cursor expiry");
  const current = now.getTime();
  if (Date.parse(issuedAt) > current + 60_000 || Date.parse(expiresAt) <= current || Date.parse(expiresAt) - Date.parse(issuedAt) > 3_600_000) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence cursor has expired.", 410);
  }
  const normalized = normalizeEvidenceCursor({ capturedAt: record.capturedAt, evidenceId: record.evidenceId });
  const canonicalBody = stableJson({ schemaVersion: 1, tenantId: expectedTenantId, ...normalized, issuedAt, expiresAt } as JsonValue);
  if (canonicalBody !== decoded) throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence cursor is invalid.");
  return normalized;
}

async function decodeEvidenceCursorWithRotation(
  value: string,
  expectedTenantId: string,
  secrets: readonly Uint8Array[],
  now: Date,
): Promise<EvidencePageCursor> {
  let expired: TenantSecurityError | undefined;
  let lastFailure: unknown;
  for (const secret of secrets) {
    try { return await decodeEvidenceCursor(value, expectedTenantId, secret, now); }
    catch (error) {
      if (error instanceof TenantSecurityError && error.safeStatus === 410) expired = error;
      lastFailure = error;
    }
  }
  if (expired) throw expired;
  if (lastFailure instanceof TenantSecurityError) throw lastFailure;
  throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence cursor is invalid.");
}

export function normalizeEvidenceCursor(value: EvidencePageCursor): EvidencePageCursor {
  return Object.freeze({
    capturedAt: canonicalInstant(value.capturedAt, "Evidence cursor timestamp"),
    evidenceId: String(asResourceId(value.evidenceId, ["evd"])),
  });
}

export function normalizeEvidenceRecord(value: EvidenceArtifactAccessRecord): EvidenceArtifactAccessRecord {
  if (!value || typeof value !== "object") throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Resource not found.", 404);
  const tenantId = asTenantId(value.tenantId);
  const evidenceId = String(asResourceId(value.evidenceId, ["evd"]));
  const controlId = asControlId(value.controlId);
  const status = String(value.status || "");
  const evidenceType = String(value.evidenceType || "");
  if (!downloadableStatuses.has(status) || !evidenceTypes.has(evidenceType)) {
    throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Resource not found.", 404);
  }
  if (!Number.isSafeInteger(value.revision) || value.revision < 0 || !Number.isSafeInteger(value.byteSize) || value.byteSize < 1 || value.byteSize > 26_214_400) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence metadata is invalid.", 500);
  }
  const contentType = String(value.contentType || "").toLowerCase();
  const evidenceBucket = String(value.evidenceBucket || "");
  const objectKey = String(value.objectKey || "");
  let expectedObjectKey: string;
  try {
    expectedObjectKey = String(buildControlledEvidenceObjectKey({
      tenantId,
      controlId,
      evidenceId,
      contentType: asEvidenceMimeType(contentType),
    }).evidenceKey);
  } catch {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence storage metadata is invalid.", 500);
  }
  if (!contentTypePattern.test(contentType) || !bucketPattern.test(evidenceBucket) || objectKey !== expectedObjectKey || objectKey.length > 1_024) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence storage metadata is invalid.", 500);
  }
  const capturedAt = canonicalInstant(value.capturedAt, "Evidence capture time");
  const retainUntil = canonicalInstant(value.retainUntil, "Evidence retention time");
  const createdAt = canonicalInstant(value.createdAt, "Evidence creation time");
  if (Date.parse(retainUntil) < Date.parse(capturedAt) || Date.parse(createdAt) < Date.parse(capturedAt) - 86_400_000) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Evidence retention metadata is invalid.", 500);
  }
  return Object.freeze({
    tenantId,
    evidenceId,
    controlId,
    title: assertBoundedText(value.title, "Evidence title", 1, 240),
    description: assertBoundedText(value.description || "", "Evidence description", 0, 8_000),
    evidenceType: evidenceType as EvidenceArtifactAccessRecord["evidenceType"],
    source: assertBoundedText(value.source, "Evidence source", 1, 120),
    systemName: assertBoundedText(value.systemName, "Evidence system name", 1, 160),
    status: status as DownloadableEvidenceStatus,
    revision: value.revision,
    contentType,
    byteSize: value.byteSize,
    checksumSha256: asSha256(value.checksumSha256),
    evidenceBucket,
    objectKey,
    objectVersionId: assertVersionId(value.objectVersionId, "Evidence object version"),
    capturedAt,
    retainUntil,
    createdAt,
  });
}

function safeDownloadFilename(evidence: EvidenceArtifactAccessRecord): string {
  return evidence.objectKey.slice(evidence.objectKey.lastIndexOf("/") + 1);
}

function assertExactDownload(
  expected: ExactGetObjectPresignInput,
  actual: ExactPresignedGetObject,
  endpointHostname: string,
  signingRegion: string,
): void {
  let url: URL;
  try { url = new URL(String(actual?.url || "")); } catch { throw new TenantSecurityError("INVALID_IDENTIFIER", "S3 presigner returned an invalid download.", 500); }
  const expectedPath = `/${expected.key.split("/").map(encodeURIComponent).join("/")}`;
  const expectedDnsSuffix = signingRegion.startsWith("cn-") ? "amazonaws.com.cn" : "amazonaws.com";
  const expectedEndpointHostname = `${expected.bucket}.s3.${signingRegion}.${expectedDnsSuffix}`;
  if (
    actual.method !== "GET" || actual.bucket !== expected.bucket || actual.key !== expected.key || actual.versionId !== expected.versionId ||
    canonicalInstant(actual.expiresAt, "Presigned download expiry") !== expected.expiresAt || !exactStringRecordEqual(actual.requiredHeaders, expected.requiredHeaders) ||
    endpointHostname !== expectedEndpointHostname || url.protocol !== "https:" || url.hostname !== endpointHostname || url.port || url.username || url.password || url.hash ||
    url.pathname !== expectedPath || url.toString().length > 8_192 || url.searchParams.getAll("versionId").length !== 1 ||
    url.searchParams.get("versionId") !== expected.versionId || url.searchParams.get("response-content-type") !== expected.responseContentType ||
    url.searchParams.get("response-content-disposition") !== expected.responseContentDisposition
  ) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "S3 presigner weakened the exact-version download contract.", 500);
  }
  const requiredQueryParameters = [
    "X-Amz-Algorithm",
    "X-Amz-Content-Sha256",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-Security-Token",
    "X-Amz-Signature",
    "X-Amz-SignedHeaders",
    "response-content-disposition",
    "response-content-type",
    "versionId",
    "x-id",
  ] as const;
  const actualQueryNames = [...url.searchParams.keys()];
  const credentialParts = (url.searchParams.get("X-Amz-Credential") ?? "").split("/");
  const expectedSigV4Date = sigV4Instant(expected.signingAt);
  const expectedScopeDate = expectedSigV4Date.slice(0, 8);
  const expectedSignedHeaders = ["host", ...Object.keys(expected.requiredHeaders)].sort();
  const signedHeaders = (url.searchParams.get("X-Amz-SignedHeaders") ?? "").split(";");
  const sessionToken = url.searchParams.get("X-Amz-Security-Token") ?? "";
  if (
      actualQueryNames.length !== requiredQueryParameters.length ||
      actualQueryNames.some((name) => !requiredQueryParameters.includes(name as typeof requiredQueryParameters[number])) ||
      requiredQueryParameters.some((name) => url.searchParams.getAll(name).length !== 1) ||
      url.searchParams.get("X-Amz-Algorithm") !== "AWS4-HMAC-SHA256" ||
      url.searchParams.get("X-Amz-Content-Sha256") !== "UNSIGNED-PAYLOAD" ||
      url.searchParams.get("X-Amz-Date") !== expectedSigV4Date ||
      url.searchParams.get("X-Amz-Expires") !== String(expected.expiresInSeconds) ||
      url.searchParams.get("x-id") !== "GetObject" ||
      credentialParts.length !== 5 || !/^[A-Z0-9]{16,128}$/.test(credentialParts[0] ?? "") ||
      credentialParts[1] !== expectedScopeDate || credentialParts[2] !== signingRegion ||
      credentialParts[3] !== "s3" || credentialParts[4] !== "aws4_request" ||
      !/^[a-f0-9]{64}$/.test(url.searchParams.get("X-Amz-Signature") ?? "") ||
      !/^[A-Za-z0-9+/=_-]{16,4096}$/.test(sessionToken) ||
      signedHeaders.length !== expectedSignedHeaders.length ||
      !signedHeaders.every((header, index) => header === expectedSignedHeaders[index])) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "S3 presigner returned an invalid SigV4 download capability.", 500);
  }
}

function sigV4Instant(value: string): string {
  const date = new Date(canonicalInstant(value, "Download signing time"));
  const iso = date.toISOString();
  return `${iso.slice(0, 4)}${iso.slice(5, 7)}${iso.slice(8, 10)}T${iso.slice(11, 13)}${iso.slice(14, 16)}${iso.slice(17, 19)}Z`;
}

function exactStringRecordEqual(left: Readonly<Record<string, string>>, right: Readonly<Record<string, string>>): boolean {
  const leftKeys = Object.keys(left || {}).sort();
  const rightKeys = Object.keys(right || {}).sort();
  return leftKeys.length === rightKeys.length && leftKeys.every((key, index) => key === rightKeys[index] && left[key] === right[key]);
}

async function cursorHmac(secret: Uint8Array, value: string): Promise<Uint8Array> {
  if (!(secret instanceof Uint8Array) || secret.byteLength < 32 || secret.byteLength > 64) throw new Error("Evidence cursor HMAC secret is invalid.");
  const exact = secret.buffer.slice(secret.byteOffset, secret.byteOffset + secret.byteLength) as ArrayBuffer;
  const key = await crypto.subtle.importKey("raw", exact, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`scopeproof-evidence-cursor-v1\n${value}`)));
}

function constantTimeBytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  let difference = left.byteLength ^ right.byteLength;
  const length = Math.max(left.byteLength, right.byteLength);
  for (let index = 0; index < length; index += 1) difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  return difference === 0;
}
