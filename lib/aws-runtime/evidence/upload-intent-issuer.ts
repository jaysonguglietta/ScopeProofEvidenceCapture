import {
  asTenantId,
  asSha256,
  canonicalInstant,
  sha256Hex,
  stableJson,
  type ExactObjectKey,
  type JsonValue,
  type Sha256Hex,
  TenantSecurityError,
} from "../contracts.ts";
import {
  DEFAULT_MAXIMUM_UPLOAD_BYTES,
  MAXIMUM_UPLOAD_TTL_MS,
  issueUploadIntent,
  type EvidenceMimeType,
  type IssuedUpload,
} from "../upload.ts";
import {
  asBucketName,
  asControlId,
  asEvidenceMimeType,
  asKmsKeyArn,
  buildControlledEvidenceKeys,
  bytesToBase64,
  bytesToBase64Url,
  bytesToHex,
  exactStringRecordEqual,
  hexToBytes,
} from "./primitives.ts";

const MINIMUM_UPLOAD_TTL_MS = 30_000;
const DEFAULT_UPLOAD_TTL_MS = 5 * 60_000;
const MINIMUM_IDEMPOTENCY_SECRET_BYTES = 32;
const MAXIMUM_IDEMPOTENCY_SECRET_BYTES = 64;
const MAXIMUM_PROVIDED_PREVIOUS_SECRETS = 8;
const MAXIMUM_UNIQUE_PREVIOUS_SECRETS = 1;
const MINIMUM_REMAINING_CAPABILITY_MS = 1_000;

export interface ControlledUploadIntent extends IssuedUpload {
  readonly controlId: string;
  readonly quarantineBucket: string;
  readonly quarantineKmsKeyArn: string;
  /** Server-keyed digest of the client key. The raw key is never persisted. */
  readonly idempotencyDigest: Sha256Hex;
  /** Digest of every immutable request fact, excluding issuance timestamps. */
  readonly requestFingerprint: Sha256Hex;
}

export interface UploadIntentRecoveryProjection {
  readonly canonicalEvidenceProjection: string;
  readonly evidenceProjectionDigest: Sha256Hex;
}

export interface UploadIntentReservation {
  readonly outcome: "created" | "existing";
  readonly intent: ControlledUploadIntent;
}

export interface RecoveredUploadIntentReservation {
  readonly outcome: "existing";
  readonly intent: ControlledUploadIntent;
}

/** Implementations atomically create or return only an exact prior reservation. */
export interface ConditionalUploadIntentStore {
  /**
   * Strongly reads an exact prior reservation without creating one. Recovery
   * adapters may repair the matching RDS projection, but must never reserve a
   * new Dynamo lifecycle or return a non-exact record.
   */
  recoverExact(
    intent: ControlledUploadIntent,
    recoveryProjection?: UploadIntentRecoveryProjection,
  ): Promise<RecoveredUploadIntentReservation | undefined>;
  reserve(
    intent: ControlledUploadIntent,
    recoveryProjection?: UploadIntentRecoveryProjection,
  ): Promise<UploadIntentReservation>;
}

export interface SecureEntropySource {
  randomBytes(length: number): Uint8Array;
}

export const webCryptoEntropySource: SecureEntropySource = Object.freeze({
  randomBytes(length: number): Uint8Array {
    if (!Number.isSafeInteger(length) || length < 16 || length > 64) {
      throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Secure entropy request length is invalid.");
    }
    return crypto.getRandomValues(new Uint8Array(length));
  },
});

/** Generates the canonical 256-bit key a client uses for one logical request. */
export function generateUploadIdempotencyKey(source: SecureEntropySource = webCryptoEntropySource): string {
  const bytes = source.randomBytes(32);
  if (!(bytes instanceof Uint8Array) || bytes.byteLength !== 32) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Secure entropy source returned an invalid idempotency key.");
  }
  return bytesToBase64Url(new Uint8Array(bytes));
}

export interface ExactPutObjectPresignInput {
  readonly bucket: string;
  readonly key: ExactObjectKey;
  /** Stable upload-intent issuance time. */
  readonly issuedAt: string;
  /** Time this particular retry capability is signed. */
  readonly signingAt: string;
  readonly expiresAt: string;
  readonly expiresInSeconds: number;
  readonly headers: Readonly<Record<string, string>>;
}

export interface ExactPresignedPutObject {
  readonly method: "PUT";
  readonly url: string;
  readonly bucket: string;
  readonly key: ExactObjectKey;
  readonly expiresAt: string;
  readonly requiredHeaders: Readonly<Record<string, string>>;
}

/** A small facade over an AWS SDK S3 presigner so tests never require AWS. */
export interface ExactPutObjectPresigner {
  presignPutObject(input: ExactPutObjectPresignInput): Promise<ExactPresignedPutObject>;
}

export interface UploadIntentIssuerConfiguration {
  readonly quarantineBucket: string;
  readonly quarantineKmsKeyArn: string;
  readonly maximumBytes?: number;
  readonly defaultTtlMs?: number;
}

export interface UploadIntentRequest {
  /** A new, cryptographically random base64url value for each logical request. */
  readonly idempotencyKey: string;
  readonly tenantId: string;
  readonly requestedBy: string;
  readonly controlId: string;
  readonly evidenceId: string;
  readonly expectedSha256: string;
  readonly expectedSize: number;
  readonly contentType: string;
  readonly requiredRetentionUntil: Date;
  readonly ttlMs?: number;
}

export interface IssuedPresignedUpload {
  readonly intent: ControlledUploadIntent;
  /** Deterministically returned to the authenticated caller and never persisted. */
  readonly nonce: string;
  readonly upload: ExactPresignedPutObject;
}

export class UploadIntentIssuer {
  readonly #store: ConditionalUploadIntentStore;
  readonly #presigner: ExactPutObjectPresigner;
  readonly #idempotencySecret: Uint8Array<ArrayBuffer>;
  readonly #previousIdempotencySecrets: readonly Uint8Array<ArrayBuffer>[];
  readonly #clock: () => Date;
  readonly #configuration: {
    readonly quarantineBucket: string;
    readonly quarantineKmsKeyArn: string;
    readonly endpointHostname: string;
    readonly maximumBytes: number;
    readonly defaultTtlMs: number;
  };

  constructor(dependencies: {
    store: ConditionalUploadIntentStore;
    presigner: ExactPutObjectPresigner;
    /** Server-only HMAC key loaded from a secret manager, never from a client. */
    idempotencySecret: Uint8Array;
    /**
     * At most one distinct prior server key may be accepted for read-only
     * recovery during rotation. Duplicate/current-key entries are ignored.
     */
    previousIdempotencySecrets?: readonly Uint8Array[];
    clock: () => Date;
    configuration: UploadIntentIssuerConfiguration;
  }) {
    this.#store = dependencies.store;
    this.#presigner = dependencies.presigner;
    this.#idempotencySecret = exactIdempotencySecret(dependencies.idempotencySecret);
    this.#previousIdempotencySecrets = exactPreviousIdempotencySecrets(
      this.#idempotencySecret,
      dependencies.previousIdempotencySecrets,
    );
    this.#clock = dependencies.clock;
    const maximumBytes = dependencies.configuration.maximumBytes ?? DEFAULT_MAXIMUM_UPLOAD_BYTES;
    const defaultTtlMs = dependencies.configuration.defaultTtlMs ?? DEFAULT_UPLOAD_TTL_MS;
    assertMaximumBytes(maximumBytes);
    assertTtl(defaultTtlMs);
    const quarantineBucket = asBucketName(dependencies.configuration.quarantineBucket);
    const quarantineKmsKeyArn = asKmsKeyArn(dependencies.configuration.quarantineKmsKeyArn);
    this.#configuration = Object.freeze({
      quarantineBucket,
      quarantineKmsKeyArn,
      endpointHostname: s3EndpointHostname(quarantineBucket, quarantineKmsKeyArn),
      maximumBytes,
      defaultTtlMs,
    });
  }

  async issue(request: UploadIntentRequest): Promise<IssuedPresignedUpload> {
    const now = this.#clock();
    if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
      throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload issue time is invalid.");
    }
    const ttlMs = request.ttlMs ?? this.#configuration.defaultTtlMs;
    assertTtl(ttlMs);
    const expectedSha256 = asSha256(request.expectedSha256);
    const contentType = asEvidenceMimeType(request.contentType);
    const controlId = asControlId(request.controlId);
    const expiresAt = new Date(now.getTime() + ttlMs);
    const tenantId = asTenantId(request.tenantId);
    const idempotencyKey = asClientIdempotencyKey(request.idempotencyKey);

    // Previous keys are recovery-only. Each candidate is strongly read and
    // equality checked before the current key is allowed to create anything.
    // A mismatch, malformed prior record, or recovery outage fails closed.
    for (const previousSecret of this.#previousIdempotencySecrets) {
      const previous = await buildControlledUploadCandidate({
        secret: previousSecret,
        tenantId,
        idempotencyKey,
        request,
        now,
        expiresAt,
        ttlMs,
        expectedSha256,
        contentType,
        controlId,
        configuration: this.#configuration,
      });
      const recovered = await this.#store.recoverExact(previous.intent);
      if (recovered) {
        if (recovered.outcome !== "existing") {
          throw new TenantSecurityError("UPLOAD_MISMATCH", "Upload recovery returned invalid state.", 409);
        }
        return await this.#complete(previous.intent, recovered, previous.nonce);
      }
    }

    const current = await buildControlledUploadCandidate({
      secret: this.#idempotencySecret,
      tenantId,
      idempotencyKey,
      request,
      now,
      expiresAt,
      ttlMs,
      expectedSha256,
      contentType,
      controlId,
      configuration: this.#configuration,
    });

    // The store may return the exact record from a prior ambiguous cross-service
    // commit. It must also re-project that record into RDS before resolving.
    const reservation = await this.#store.reserve(current.intent);
    return await this.#complete(current.intent, reservation, current.nonce);
  }

  async #complete(
    candidate: ControlledUploadIntent,
    reservation: UploadIntentReservation,
    nonce: string,
  ): Promise<IssuedPresignedUpload> {
    const intent = assertExactReservation(candidate, reservation);
    const completionTime = this.#clock();
    if (!(completionTime instanceof Date) || !Number.isFinite(completionTime.getTime())) {
      throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload issue time is invalid.");
    }
    if (Date.parse(intent.expiresAt) - completionTime.getTime() < MINIMUM_REMAINING_CAPABILITY_MS) {
      throw new TenantSecurityError("UPLOAD_INTENT_EXPIRED", "The idempotent upload request has expired. Use a new idempotency key.", 410);
    }
    const presignInput = exactPresignInput(intent, completionTime);
    const upload = await this.#presigner.presignPutObject(presignInput);
    assertExactPresignResult(presignInput, upload, this.#configuration.endpointHostname);
    return Object.freeze({
      intent,
      nonce,
      upload: Object.freeze({ ...upload, requiredHeaders: Object.freeze({ ...upload.requiredHeaders }) }),
    });
  }
}

async function buildControlledUploadCandidate(input: {
  readonly secret: Uint8Array<ArrayBuffer>;
  readonly tenantId: ReturnType<typeof asTenantId>;
  readonly idempotencyKey: string;
  readonly request: UploadIntentRequest;
  readonly now: Date;
  readonly expiresAt: Date;
  readonly ttlMs: number;
  readonly expectedSha256: Sha256Hex;
  readonly contentType: EvidenceMimeType;
  readonly controlId: string;
  readonly configuration: {
    readonly quarantineBucket: string;
    readonly quarantineKmsKeyArn: string;
    readonly maximumBytes: number;
  };
}): Promise<Readonly<{ intent: ControlledUploadIntent; nonce: string }>> {
  const derived = await deriveIdempotencyMaterial(input.secret, input.tenantId, input.idempotencyKey);
  const id = `upl_${bytesToHex(derived.intentIdBytes)}`;
  const nonce = bytesToBase64Url(derived.nonceBytes);
  const base = await issueUploadIntent({
    id,
    tenantId: input.tenantId,
    requestedBy: input.request.requestedBy as IssuedUpload["requestedBy"],
    resourceId: input.request.evidenceId,
    expectedSha256: input.expectedSha256,
    expectedSize: input.request.expectedSize,
    contentType: input.contentType,
    nonce,
    issuedAt: input.now,
    expiresAt: input.expiresAt,
    requiredRetentionUntil: input.request.requiredRetentionUntil,
    maximumBytes: input.configuration.maximumBytes,
  });
  const keys = buildControlledEvidenceKeys({
    tenantId: base.tenantId,
    controlId: input.controlId,
    uploadIntentId: base.id,
    evidenceId: base.resourceId,
    contentType: input.contentType,
  });
  const requestFingerprint = await uploadRequestFingerprint({
    base,
    controlId: input.controlId,
    quarantineBucket: input.configuration.quarantineBucket,
    quarantineKmsKeyArn: input.configuration.quarantineKmsKeyArn,
    ttlMs: input.ttlMs,
  });
  const candidate: ControlledUploadIntent = Object.freeze({
    ...base,
    controlId: input.controlId,
    quarantineBucket: input.configuration.quarantineBucket,
    quarantineKmsKeyArn: input.configuration.quarantineKmsKeyArn,
    quarantineKey: keys.quarantineKey,
    finalKey: keys.evidenceKey,
    idempotencyDigest: derived.idempotencyDigest,
    requestFingerprint,
  });
  return Object.freeze({ intent: candidate, nonce });
}

async function deriveIdempotencyMaterial(
  secret: Uint8Array<ArrayBuffer>,
  tenantId: string,
  idempotencyKey: string,
): Promise<Readonly<{ intentIdBytes: Uint8Array; nonceBytes: Uint8Array; idempotencyDigest: Sha256Hex }>> {
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const context = `scopeproof-upload-idempotency-v1\n${tenantId}\n${idempotencyKey}`;
  const sign = async (label: string): Promise<Uint8Array> => new Uint8Array(await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(`${label}\n${context}`),
  ));
  const [intentIdMaterial, nonceBytes, digestBytes] = await Promise.all([
    sign("intent-id"),
    sign("upload-nonce"),
    sign("stored-idempotency-digest"),
  ]);
  return Object.freeze({
    intentIdBytes: intentIdMaterial.slice(0, 16),
    nonceBytes,
    idempotencyDigest: bytesToHex(digestBytes) as Sha256Hex,
  });
}

async function uploadRequestFingerprint(input: {
  readonly base: IssuedUpload;
  readonly controlId: string;
  readonly quarantineBucket: string;
  readonly quarantineKmsKeyArn: string;
  readonly ttlMs: number;
}): Promise<Sha256Hex> {
  const facts: JsonValue = {
    schemaVersion: 1,
    tenantId: input.base.tenantId,
    requestedBy: input.base.requestedBy,
    evidenceId: input.base.resourceId,
    controlId: input.controlId,
    expectedSha256: input.base.expectedSha256,
    expectedSize: input.base.expectedSize,
    contentType: input.base.contentType,
    requiredRetentionUntil: input.base.requiredRetentionUntil,
    ttlMilliseconds: input.ttlMs,
    quarantineBucket: input.quarantineBucket,
    quarantineKmsKeyArn: input.quarantineKmsKeyArn,
  };
  return await sha256Hex(`scopeproof-upload-request-fingerprint-v1\n${stableJson(facts)}`);
}

function assertExactReservation(candidate: ControlledUploadIntent, reservation: UploadIntentReservation): ControlledUploadIntent {
  if (!reservation || (reservation.outcome !== "created" && reservation.outcome !== "existing")) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Upload reservation returned invalid state.", 409);
  }
  const actual = reservation.intent;
  if (!actual || typeof actual !== "object") {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Upload reservation returned invalid state.", 409);
  }
  const exactFields: ReadonlyArray<keyof ControlledUploadIntent> = [
    "schemaVersion", "id", "tenantId", "requestedBy", "resourceId", "controlId",
    "expectedSha256", "expectedSize", "contentType", "nonceDigest", "quarantineBucket",
    "quarantineKmsKeyArn", "quarantineKey", "finalKey", "requiredRetentionUntil",
    "revision", "status", "idempotencyDigest", "requestFingerprint",
  ];
  if (exactFields.some((field) => actual[field] !== candidate[field])) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "The idempotency key is already bound to different upload facts.", 409);
  }
  const issuedAt = canonicalInstant(actual.issuedAt, "Stored upload issue time");
  const expiresAt = canonicalInstant(actual.expiresAt, "Stored upload expiry");
  const expectedTtl = Date.parse(candidate.expiresAt) - Date.parse(candidate.issuedAt);
  if (Date.parse(expiresAt) - Date.parse(issuedAt) !== expectedTtl) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Stored upload validity does not match the idempotent request.", 409);
  }
  if (reservation.outcome === "created" && (issuedAt !== candidate.issuedAt || expiresAt !== candidate.expiresAt)) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "New upload reservation changed the issuance contract.", 409);
  }
  return Object.freeze({ ...actual, issuedAt, expiresAt });
}

function exactIdempotencySecret(value: Uint8Array): Uint8Array<ArrayBuffer> {
  if (!(value instanceof Uint8Array) || value.byteLength < MINIMUM_IDEMPOTENCY_SECRET_BYTES || value.byteLength > MAXIMUM_IDEMPOTENCY_SECRET_BYTES) {
    throw new Error("Upload idempotency HMAC secret must contain 32 to 64 bytes.");
  }
  const copy = new Uint8Array(value.byteLength);
  copy.set(value);
  return copy;
}

function exactPreviousIdempotencySecrets(
  current: Uint8Array<ArrayBuffer>,
  values: readonly Uint8Array[] | undefined,
): readonly Uint8Array<ArrayBuffer>[] {
  if (values === undefined) return Object.freeze([]);
  if (!Array.isArray(values) || values.length > MAXIMUM_PROVIDED_PREVIOUS_SECRETS) {
    throw new Error(`At most ${MAXIMUM_PROVIDED_PREVIOUS_SECRETS} previous upload idempotency secrets may be provided.`);
  }
  const currentKey = bytesToHex(current);
  const unique = new Map<string, Uint8Array<ArrayBuffer>>();
  for (const value of values) {
    const secret = exactIdempotencySecret(value);
    const identity = bytesToHex(secret);
    if (identity !== currentKey && !unique.has(identity)) unique.set(identity, secret);
  }
  if (unique.size > MAXIMUM_UNIQUE_PREVIOUS_SECRETS) {
    throw new Error(`At most ${MAXIMUM_UNIQUE_PREVIOUS_SECRETS} distinct previous upload idempotency secret may be accepted.`);
  }
  return Object.freeze([...unique.values()]);
}

function asClientIdempotencyKey(value: string): string {
  const key = String(value || "");
  if (!/^[A-Za-z0-9_-]{43,128}$/.test(key)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "A high-entropy base64url idempotency key is required.");
  }
  const decoded = decodeBase64Url(key);
  if (decoded.byteLength < 32 || decoded.byteLength > 96 || bytesToBase64Url(decoded) !== key) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "A canonical high-entropy base64url idempotency key is required.");
  }
  return key;
}

function decodeBase64Url(value: string): Uint8Array {
  try {
    const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - normalized.length % 4) % 4);
    const binary = atob(padded);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "A canonical high-entropy base64url idempotency key is required.");
  }
}

function assertMaximumBytes(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > 5 * 1024 * 1024 * 1024) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Maximum upload size is invalid.");
  }
}

function assertTtl(value: number): void {
  if (!Number.isSafeInteger(value) || value < MINIMUM_UPLOAD_TTL_MS || value > MAXIMUM_UPLOAD_TTL_MS || value % 1_000 !== 0) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload TTL must be a whole number of seconds between 30 seconds and 10 minutes.");
  }
}

function exactPresignInput(intent: ControlledUploadIntent, signingTime: Date): ExactPutObjectPresignInput {
  const checksumBase64 = bytesToBase64(hexToBytes(intent.expectedSha256));
  const signingAt = canonicalInstant(signingTime, "Presigned upload signing time");
  const encryptionContext = bytesToBase64(new TextEncoder().encode(JSON.stringify({
    scopeproofPurpose: "quarantine",
    scopeproofTenantId: intent.tenantId,
  })));
  return Object.freeze({
    bucket: intent.quarantineBucket,
    key: intent.quarantineKey,
    issuedAt: intent.issuedAt,
    signingAt,
    expiresAt: intent.expiresAt,
    expiresInSeconds: Math.floor((Date.parse(intent.expiresAt) - Date.parse(signingAt)) / 1_000),
    headers: Object.freeze({
      "content-length": String(intent.expectedSize),
      "content-type": intent.contentType,
      "x-amz-checksum-sha256": checksumBase64,
      "x-amz-meta-control-id": intent.controlId,
      "x-amz-meta-evidence-id": intent.resourceId,
      "x-amz-meta-expected-sha256": intent.expectedSha256,
      "x-amz-meta-tenant-id": intent.tenantId,
      "x-amz-meta-upload-intent-id": intent.id,
      "x-amz-server-side-encryption": "aws:kms",
      "x-amz-server-side-encryption-aws-kms-key-id": intent.quarantineKmsKeyArn,
      "x-amz-server-side-encryption-context": encryptionContext,
    }),
  });
}

function assertExactPresignResult(expected: ExactPutObjectPresignInput, actual: ExactPresignedPutObject, endpointHostname: string): void {
  let url: URL;
  try {
    url = new URL(String(actual.url || ""));
  } catch {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "S3 presigner returned an invalid URL.");
  }
  if (
    actual.method !== "PUT" ||
    url.protocol !== "https:" ||
    Boolean(url.username || url.password || url.hash) ||
    url.toString().length > 8_192 ||
    url.hostname !== endpointHostname ||
    url.port !== "" ||
    url.pathname !== `/${expected.key.split("/").map(encodeURIComponent).join("/")}` ||
    actual.bucket !== expected.bucket ||
    actual.key !== expected.key ||
    canonicalInstant(actual.expiresAt, "Presigned upload expiry") !== expected.expiresAt ||
    !exactStringRecordEqual(expected.headers, actual.requiredHeaders)
  ) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "S3 presigner did not preserve the exact upload contract.");
  }
  assertSigV4Query(url, expected);
}

function assertSigV4Query(url: URL, expected: ExactPutObjectPresignInput): void {
  const singletonParameters = [
    "X-Amz-Algorithm",
    "X-Amz-Credential",
    "X-Amz-Date",
    "X-Amz-Expires",
    "X-Amz-Security-Token",
    "X-Amz-Signature",
    "X-Amz-SignedHeaders",
  ];
  if (singletonParameters.some((name) => url.searchParams.getAll(name).length !== 1)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "S3 presigner omitted or duplicated an AWS SigV4 parameter.");
  }
  const signature = url.searchParams.get("X-Amz-Signature") ?? "";
  const credential = url.searchParams.get("X-Amz-Credential") ?? "";
  const sessionToken = url.searchParams.get("X-Amz-Security-Token") ?? "";
  const signedHeaders = (url.searchParams.get("X-Amz-SignedHeaders") ?? "").split(";");
  const signedAt = parseSigV4Instant(url.searchParams.get("X-Amz-Date") ?? "");
  const signedExpiry = signedAt + expected.expiresInSeconds * 1_000;
  if (
    url.searchParams.get("X-Amz-Algorithm") !== "AWS4-HMAC-SHA256" ||
    url.searchParams.get("X-Amz-Expires") !== String(expected.expiresInSeconds) ||
    !/^[A-Z0-9]{8,128}\/[0-9]{8}\/[a-z0-9-]+\/s3\/aws4_request$/.test(credential) ||
    sessionToken.length < 16 ||
    sessionToken.length > 4_096 ||
    !/^[a-f0-9]{64}$/.test(signature) ||
    !signedHeaders.includes("host") ||
    !signedHeaders.every((header, index) => /^[a-z0-9-]+$/.test(header) && (index === 0 || header > signedHeaders[index - 1])) ||
    !Object.keys(expected.headers).every((header) => signedHeaders.includes(header)) ||
    signedAt < Date.parse(expected.signingAt) - 999 ||
    signedAt > Date.parse(expected.signingAt) + 999 ||
    signedExpiry > Date.parse(expected.expiresAt) + 999
  ) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "S3 presigner returned a weakened AWS SigV4 capability.");
  }
}

function parseSigV4Instant(value: string): number {
  const match = value.match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/);
  if (!match) return Number.NaN;
  const timestamp = Date.parse(`${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}.000Z`);
  return Number.isFinite(timestamp) ? timestamp : Number.NaN;
}

function s3EndpointHostname(bucket: string, kmsKeyArn: string): string {
  const parts = kmsKeyArn.split(":");
  const partition = parts[1];
  const region = parts[3];
  const dnsSuffix = partition === "aws-cn" ? "amazonaws.com.cn" : "amazonaws.com";
  return `${bucket}.s3.${region}.${dnsSuffix}`;
}

export function checksumHeaderValue(sha256: Sha256Hex): string {
  return bytesToBase64(hexToBytes(sha256));
}

export type { EvidenceMimeType };
