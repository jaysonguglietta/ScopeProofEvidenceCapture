import {
  asResourceId,
  asTenantId,
  asUploadIntentId,
  assertBoundedText,
  assertVersionId,
  safeEqual,
  type ExactObjectKey,
  type ResourceId,
  type TenantId,
  TenantSecurityError,
  type UploadIntentId,
} from "../contracts.ts";
import { exactObjectKey, type EvidenceMimeType } from "../upload.ts";

const mimeExtensions: Readonly<Record<EvidenceMimeType, string>> = Object.freeze({
  "image/png": "png",
  "application/json": "json",
  "application/spdx+json": "spdx.json",
  "application/vnd.cyclonedx+json": "cdx.json",
  "text/plain": "txt",
  "text/csv": "csv",
});

const kmsKeyArnPattern = /^arn:(aws|aws-us-gov|aws-cn):kms:([a-z]{2}(?:-gov)?-[a-z]+-\d):([0-9]{12}):key\/([0-9A-Za-z-]{1,128})$/;
const bucketPattern = /^(?!xn--)(?!.*\.\.)[a-z0-9](?:[a-z0-9.-]{1,61})[a-z0-9]$/;

export interface ControlledEvidenceKeys {
  readonly tenantId: TenantId;
  readonly controlId: string;
  readonly uploadIntentId: UploadIntentId;
  readonly evidenceId: ResourceId;
  readonly quarantineKey: ExactObjectKey;
  readonly evidenceKey: ExactObjectKey;
}

export interface ControlledEvidenceObjectKey {
  readonly tenantId: TenantId;
  readonly controlId: string;
  readonly evidenceId: ResourceId;
  readonly evidenceKey: ExactObjectKey;
}

export function asControlId(value: string): string {
  const exact = assertBoundedText(value, "Control identifier", 1, 64);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(exact) || exact === "." || exact === "..") {
    throw new TenantSecurityError("INVALID_OBJECT_KEY", "Control identifier is not safe for an evidence namespace.");
  }
  return exact;
}

export function asEvidenceMimeType(value: string): EvidenceMimeType {
  if (!Object.hasOwn(mimeExtensions, value)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Evidence MIME type is not allowed.", 415);
  }
  return value as EvidenceMimeType;
}

export function buildControlledEvidenceKeys(input: {
  tenantId: string;
  controlId: string;
  uploadIntentId: string;
  evidenceId: string;
  contentType: string;
}): ControlledEvidenceKeys {
  const uploadIntentId = asUploadIntentId(input.uploadIntentId);
  const evidence = buildControlledEvidenceObjectKey(input);
  const root = `tenants/${evidence.tenantId}/controls/${evidence.controlId}`;
  return Object.freeze({
    tenantId: evidence.tenantId,
    controlId: evidence.controlId,
    uploadIntentId,
    evidenceId: evidence.evidenceId,
    quarantineKey: exactObjectKey(`${root}/quarantine/${uploadIntentId}.upload`),
    evidenceKey: evidence.evidenceKey,
  });
}

export function buildControlledEvidenceObjectKey(input: {
  tenantId: string;
  controlId: string;
  evidenceId: string;
  contentType: string;
}): ControlledEvidenceObjectKey {
  const tenantId = asTenantId(input.tenantId);
  const controlId = asControlId(input.controlId);
  const evidenceId = asResourceId(input.evidenceId, ["evd"]);
  const contentType = asEvidenceMimeType(input.contentType);
  return Object.freeze({
    tenantId,
    controlId,
    evidenceId,
    evidenceKey: exactObjectKey(`tenants/${tenantId}/controls/${controlId}/evidence/${evidenceId}.${mimeExtensions[contentType]}`),
  });
}

export function asBucketName(value: string): string {
  const bucket = String(value || "");
  if (
    !bucketPattern.test(bucket) ||
    /^\d{1,3}(?:\.\d{1,3}){3}$/.test(bucket) ||
    bucket.length < 3 ||
    bucket.length > 63 ||
    bucket.startsWith("sthree-") ||
    bucket.startsWith("amzn-s3-demo-") ||
    ["-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"].some((suffix) => bucket.endsWith(suffix))
  ) {
    throw new TenantSecurityError("INVALID_OBJECT_KEY", "S3 bucket name is invalid.");
  }
  return bucket;
}

export function asKmsKeyArn(value: string): string {
  const arn = String(value || "");
  if (!kmsKeyArnPattern.test(arn)) {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "A customer-managed KMS key ARN is required.");
  }
  return arn;
}

export function assertExactObjectVersion(value: string): string {
  return assertVersionId(value, "S3 object version");
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(value: string): Uint8Array {
  if (!/^[a-f0-9]+$/.test(value) || value.length % 2 !== 0) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Hexadecimal input is invalid.");
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function bytesToBase64(bytes: Uint8Array): string {
  let encoded = "";
  for (let offset = 0; offset < bytes.length; offset += 3) {
    const first = bytes[offset];
    const second = bytes[offset + 1];
    const third = bytes[offset + 2];
    const value = (first << 16) | ((second ?? 0) << 8) | (third ?? 0);
    encoded += base64Alphabet[(value >>> 18) & 63];
    encoded += base64Alphabet[(value >>> 12) & 63];
    encoded += second === undefined ? "=" : base64Alphabet[(value >>> 6) & 63];
    encoded += third === undefined ? "=" : base64Alphabet[value & 63];
  }
  return encoded;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function base64ToBytes(value: string): Uint8Array {
  const encoded = String(value || "");
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "KMS signature is not canonical base64.");
  }
  const result: number[] = [];
  for (let offset = 0; offset < encoded.length; offset += 4) {
    const block = encoded.slice(offset, offset + 4);
    const first = base64Alphabet.indexOf(block[0]);
    const second = base64Alphabet.indexOf(block[1]);
    const third = block[2] === "=" ? 0 : base64Alphabet.indexOf(block[2]);
    const fourth = block[3] === "=" ? 0 : base64Alphabet.indexOf(block[3]);
    const bits = (first << 18) | (second << 12) | (third << 6) | fourth;
    result.push((bits >>> 16) & 255);
    if (block[2] !== "=") result.push((bits >>> 8) & 255);
    if (block[3] !== "=") result.push(bits & 255);
  }
  const bytes = new Uint8Array(result);
  if (!safeEqual(bytesToBase64(bytes), encoded)) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "KMS signature is not canonical base64.");
  }
  return bytes;
}

export function exactStringRecordEqual(left: Readonly<Record<string, string>>, right: Readonly<Record<string, string>>): boolean {
  const leftKeys = Object.keys(left).sort();
  const rightKeys = Object.keys(right).sort();
  if (leftKeys.length !== rightKeys.length || leftKeys.some((key, index) => key !== rightKeys[index])) return false;
  return leftKeys.every((key) => safeEqual(left[key], right[key]));
}
