import {
  asResourceId,
  asSha256,
  asTenantId,
  asUserId,
  canonicalInstant,
  containsAsciiControlCharacters,
  sha256Hex,
  stableJson,
  TenantSecurityError,
} from "../contracts.ts";
import type { VerifiedCognitoAccessToken } from "../http/jwt.ts";
import type { TenantActor } from "../tenancy.ts";
import { asControlId, asEvidenceMimeType } from "./primitives.ts";

export interface DeviceUploadManifest {
  readonly schemaVersion: 1;
  readonly tenantId: string;
  readonly userId: string;
  readonly deviceId: string;
  readonly assessmentId: string;
  readonly controlId: string;
  readonly evidenceId: string;
  readonly expectedSha256: string;
  readonly expectedSize: number;
  readonly contentType: string;
  readonly capturedAt: string;
  /** The jti of the short-lived, issuer-signed Cognito access token. */
  readonly challenge: string;
  /** The request's high-entropy one-time idempotency value. */
  readonly nonce: string;
  /** Strictly increasing for each enrolled device. */
  readonly sequence: number;
  readonly signedAt: string;
}

export interface PersistedDeviceUploadProof {
  readonly schemaVersion: 1;
  readonly algorithm: "ECDSA_P256_SHA256";
  readonly canonicalManifest: string;
  readonly manifestDigest: string;
  readonly signature: string;
  readonly publicKeySha256: string;
  readonly challengeDigest: string;
  readonly nonceDigest: string;
  readonly sequence: number;
  readonly signedAt: string;
}

const manifestKeys = Object.freeze([
  "assessmentId", "capturedAt", "challenge", "contentType", "controlId", "deviceId",
  "evidenceId", "expectedSha256", "expectedSize", "nonce", "schemaVersion", "sequence",
  "signedAt", "tenantId", "userId",
] as const);
const maximumSignedClockSkewMs = 5 * 60 * 1_000;

/**
 * Verifies possession of the enrolled device key before any upload capability
 * is issued. The public-key digest is persisted and independently matched to
 * the actor-bound enrollment by the database procedure.
 */
export async function verifyDeviceUploadManifest(input: Readonly<{
  actor: TenantActor;
  identity: VerifiedCognitoAccessToken;
  manifest: unknown;
  publicKeySpki: string;
  signature: string;
  request: Readonly<{
    idempotencyKey: string;
    deviceId: string;
    assessmentId: string;
    controlId: string;
    evidenceId: string;
    expectedSha256: string;
    expectedSize: number;
    contentType: string;
    capturedAt: Date | string;
  }>;
  now: Date;
}>): Promise<PersistedDeviceUploadProof> {
  if (!(input.now instanceof Date) || !Number.isFinite(input.now.getTime())) throw new Error("Device-manifest clock is invalid.");
  if (!input.identity.jwtId) {
    throw new TenantSecurityError("INVALID_PRINCIPAL", "The access token is missing its device-upload challenge.", 401);
  }
  const manifest = exactManifest(input.manifest);
  const expected = Object.freeze({
    schemaVersion: 1 as const,
    tenantId: asTenantId(input.actor.tenantId),
    userId: asUserId(input.actor.userId),
    deviceId: asResourceId(input.request.deviceId, ["dev"]),
    assessmentId: asResourceId(input.request.assessmentId, ["asm"]),
    controlId: asControlId(input.request.controlId),
    evidenceId: asResourceId(input.request.evidenceId, ["evd"]),
    expectedSha256: asSha256(input.request.expectedSha256),
    expectedSize: exactPositiveInteger(input.request.expectedSize, 26_214_400, "Expected evidence size"),
    contentType: asEvidenceMimeType(input.request.contentType),
    capturedAt: canonicalInstant(input.request.capturedAt, "Evidence capture time"),
    challenge: exactText(input.identity.jwtId, "Device challenge", 8, 200),
    nonce: exactText(input.request.idempotencyKey, "Device nonce", 16, 200),
    sequence: exactPositiveInteger(manifest.sequence, Number.MAX_SAFE_INTEGER, "Device sequence"),
    signedAt: canonicalInstant(manifest.signedAt, "Device signature time"),
  });
  for (const key of manifestKeys) {
    if (manifest[key] !== expected[key]) {
      throw new TenantSecurityError("UPLOAD_MISMATCH", "Device manifest does not match the authenticated upload request.", 409);
    }
  }
  const signedAtMilliseconds = Date.parse(expected.signedAt);
  const authenticatedAtMilliseconds = Date.parse(input.identity.authenticatedAt);
  if (Math.abs(input.now.getTime() - signedAtMilliseconds) > maximumSignedClockSkewMs ||
      signedAtMilliseconds < authenticatedAtMilliseconds - maximumSignedClockSkewMs) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Device signature time is outside the allowed window.", 409);
  }

  const publicKeyBytes = decodeCanonicalBase64(input.publicKeySpki, 80, 160, "Device public key");
  const signatureBytes = decodeCanonicalBase64Url(input.signature, 64, 64, "Device signature");
  let publicKey: CryptoKey;
  try {
    publicKey = await crypto.subtle.importKey(
      "spki",
      exactArrayBuffer(publicKeyBytes),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Device public key is not a valid P-256 verification key.");
  }
  const canonicalManifest = stableJson(expected);
  if (new TextEncoder().encode(canonicalManifest).byteLength > 8_192) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Device manifest is too large.", 413);
  }
  const signedBytes = new TextEncoder().encode(`scopeproof-device-upload-manifest-v1\n${canonicalManifest}`);
  let verified = false;
  try {
    verified = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      exactArrayBuffer(signatureBytes),
      exactArrayBuffer(signedBytes),
    );
  } catch {
    verified = false;
  }
  if (!verified) throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Device upload signature is invalid.", 403);

  return Object.freeze({
    schemaVersion: 1,
    algorithm: "ECDSA_P256_SHA256",
    canonicalManifest,
    manifestDigest: await sha256Hex(`scopeproof-device-upload-manifest-v1\n${canonicalManifest}`),
    signature: input.signature,
    publicKeySha256: await sha256Hex(publicKeyBytes),
    challengeDigest: await sha256Hex(`scopeproof-device-token-challenge-v1\n${expected.challenge}`),
    nonceDigest: await sha256Hex(`scopeproof-device-upload-nonce-v1\n${expected.nonce}`),
    sequence: expected.sequence,
    signedAt: expected.signedAt,
  });
}

function exactManifest(value: unknown): DeviceUploadManifest {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw invalidManifest();
  const keys = Object.keys(value).sort();
  const expectedKeys = [...manifestKeys].sort();
  if (keys.length !== expectedKeys.length || keys.some((key, index) => key !== expectedKeys[index])) throw invalidManifest();
  const manifest = value as Record<typeof manifestKeys[number], unknown>;
  if (manifest.schemaVersion !== 1 || !Number.isSafeInteger(manifest.expectedSize) || !Number.isSafeInteger(manifest.sequence) ||
      manifestKeys.some((key) => key !== "schemaVersion" && key !== "expectedSize" && key !== "sequence" && typeof manifest[key] !== "string")) {
    throw invalidManifest();
  }
  return manifest as unknown as DeviceUploadManifest;
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function exactText(value: string, label: string, minimum: number, maximum: number): string {
  const exact = String(value ?? "");
  if (exact.length < minimum || exact.length > maximum || exact !== exact.trim() || containsAsciiControlCharacters(exact)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", `${label} is invalid.`);
  }
  return exact;
}

function exactPositiveInteger(value: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", `${label} is invalid.`);
  }
  return value;
}

function decodeCanonicalBase64(value: string, minimumBytes: number, maximumBytes: number, label: string): Uint8Array {
  const exact = exactText(value, label, 4, Math.ceil(maximumBytes * 4 / 3) + 4);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(exact)) throw invalidEncoding(label);
  let bytes: Uint8Array;
  try { bytes = Uint8Array.from(atob(exact), (character) => character.charCodeAt(0)); } catch { throw invalidEncoding(label); }
  if (bytes.byteLength < minimumBytes || bytes.byteLength > maximumBytes || bytesToBase64(bytes) !== exact) throw invalidEncoding(label);
  return bytes;
}

function decodeCanonicalBase64Url(value: string, minimumBytes: number, maximumBytes: number, label: string): Uint8Array {
  const exact = exactText(value, label, 4, Math.ceil(maximumBytes * 4 / 3) + 1);
  if (!/^[A-Za-z0-9_-]+$/.test(exact)) throw invalidEncoding(label);
  const padding = (4 - exact.length % 4) % 4;
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.from(atob(exact.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat(padding)), (character) => character.charCodeAt(0));
  } catch { throw invalidEncoding(label); }
  const canonical = bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  if (bytes.byteLength < minimumBytes || bytes.byteLength > maximumBytes || canonical !== exact) throw invalidEncoding(label);
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function invalidManifest(): TenantSecurityError {
  return new TenantSecurityError("INVALID_UPLOAD_INTENT", "Device manifest contains missing, malformed, or unexpected fields.");
}

function invalidEncoding(label: string): TenantSecurityError {
  return new TenantSecurityError("INVALID_UPLOAD_INTENT", `${label} encoding is invalid.`);
}
