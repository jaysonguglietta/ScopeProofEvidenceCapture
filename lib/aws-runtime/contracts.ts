/**
 * Framework-agnostic security contracts for the AWS-hosted runtime.
 *
 * These helpers deliberately accept clocks, identifiers, and persistence state
 * as inputs. Network and database adapters remain responsible for verifying AWS
 * responses and committing revisions with an atomic compare-and-swap.
 */

export type Opaque<T, Name extends string> = T & { readonly __brand: Name };

export type TenantId = Opaque<string, "TenantId">;
export type UserId = Opaque<string, "UserId">;
export type MembershipId = Opaque<string, "MembershipId">;
export type ResourceId = Opaque<string, "ResourceId">;
export type UploadIntentId = Opaque<string, "UploadIntentId">;
export type JobId = Opaque<string, "JobId">;
export type AuditEventId = Opaque<string, "AuditEventId">;
export type Sha256Hex = Opaque<string, "Sha256Hex">;
export type ExactObjectKey = Opaque<string, "ExactObjectKey">;
export type CanonicalHostname = Opaque<string, "CanonicalHostname">;

export type TenantSecurityErrorCode =
  | "INVALID_HOST"
  | "UNTRUSTED_HOST_SOURCE"
  | "TENANT_NOT_FOUND"
  | "TENANT_INACTIVE"
  | "INVALID_PRINCIPAL"
  | "PRINCIPAL_EXPIRED"
  | "MEMBERSHIP_REQUIRED"
  | "ROLE_FORBIDDEN"
  | "OAUTH_SCOPE_REQUIRED"
  | "RESOURCE_NOT_FOUND"
  | "INVALID_IDENTIFIER"
  | "INVALID_OBJECT_KEY"
  | "INVALID_UPLOAD_INTENT"
  | "UPLOAD_INTENT_EXPIRED"
  | "UPLOAD_INTENT_REPLAYED"
  | "UPLOAD_MISMATCH"
  | "RATE_LIMITED"
  | "ILLEGAL_STATE_TRANSITION"
  | "CONCURRENT_MODIFICATION"
  | "INVALID_AUDIT_EVENT"
  | "INVALID_JOB"
  | "RETENTION_VIOLATION"
  | "LEGAL_HOLD_PRECONDITION_DRIFT"
  | "LEGAL_HOLD_ACTIVE";

export class TenantSecurityError extends Error {
  readonly name = "TenantSecurityError";
  readonly code: TenantSecurityErrorCode;
  readonly safeStatus: number;

  constructor(code: TenantSecurityErrorCode, message: string, safeStatus = 400) {
    super(message);
    this.code = code;
    this.safeStatus = safeStatus;
  }
}

const identifierPattern = /^[a-z][a-z0-9]{1,15}_[a-f0-9]{32}$/;
const sha256Pattern = /^[a-f0-9]{64}$/;
const versionPattern = /^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/;

export function asTenantId(value: string): TenantId {
  return asPrefixedId(value, "ten") as TenantId;
}

export function asUserId(value: string): UserId {
  return asPrefixedId(value, "usr") as UserId;
}

export function asMembershipId(value: string): MembershipId {
  return asPrefixedId(value, "mem") as MembershipId;
}

export function asUploadIntentId(value: string): UploadIntentId {
  return asPrefixedId(value, "upl") as UploadIntentId;
}

export function asJobId(value: string): JobId {
  return asPrefixedId(value, "job") as JobId;
}

export function asAuditEventId(value: string): AuditEventId {
  return asPrefixedId(value, "evt") as AuditEventId;
}

export function asResourceId(value: string, allowedPrefixes?: readonly string[]): ResourceId {
  const exact = String(value || "");
  const prefix = exact.split("_", 1)[0];
  if (!identifierPattern.test(exact) || (allowedPrefixes && !allowedPrefixes.includes(prefix))) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Resource identifier is invalid.");
  }
  return exact as ResourceId;
}

function asPrefixedId(value: string, prefix: string): string {
  const exact = String(value || "");
  if (!identifierPattern.test(exact) || !exact.startsWith(`${prefix}_`)) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", `${prefix} identifier is invalid.`);
  }
  return exact;
}

export function asSha256(value: string): Sha256Hex {
  const exact = String(value || "");
  if (!sha256Pattern.test(exact)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "A lowercase SHA-256 digest is required.");
  }
  return exact as Sha256Hex;
}

export function assertVersionId(value: string, label = "Object version"): string {
  const exact = String(value || "");
  if (!versionPattern.test(exact)) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", `${label} is invalid.`);
  }
  return exact;
}

export function assertRevision(actual: number, expected: number): void {
  if (!Number.isSafeInteger(expected) || expected < 0 || actual !== expected) {
    throw new TenantSecurityError(
      "CONCURRENT_MODIFICATION",
      "The stored revision changed. Reload it and retry the operation.",
      409,
    );
  }
}

export function canonicalInstant(value: Date | string, label = "Timestamp"): string {
  const date = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", `${label} is invalid.`);
  }
  return date.toISOString();
}

export function epochMilliseconds(value: Date | string, label = "Timestamp"): number {
  const timestamp = Date.parse(canonicalInstant(value, label));
  if (!Number.isFinite(timestamp)) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", `${label} is invalid.`);
  }
  return timestamp;
}

export function assertBoundedText(value: string, label: string, minimum: number, maximum: number): string {
  const normalized = String(value || "").trim();
  if (normalized.length < minimum || normalized.length > maximum || containsAsciiControlCharacters(normalized, true)) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", `${label} is invalid.`);
  }
  return normalized;
}

export function containsAsciiControlCharacters(value: string, allowFormattingWhitespace = false): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code === 127 || (code < 32 && !(allowFormattingWhitespace && (code === 9 || code === 10 || code === 13)))) return true;
  }
  return false;
}

export function safeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

export async function sha256Hex(value: string | Uint8Array): Promise<Sha256Hex> {
  const bytes = typeof value === "string" ? new TextEncoder().encode(value) : value;
  const exact = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const digest = await crypto.subtle.digest("SHA-256", exact);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("") as Sha256Hex;
}

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

const forbiddenDetailKey = /(authorization|cookie|credential|password|secret|(?:^|[_-])token(?:$|[_-])|session[_-]?token|access[_-]?token|refresh[_-]?token|api[_-]?key|private[_-]?key)/i;
const structuralObjectKeys = new Set(["__proto__", "constructor", "prototype"]);

export function assertSafeJson(value: unknown, label = "Details", depth = 0): JsonValue {
  if (depth > 8) throw new TenantSecurityError("INVALID_AUDIT_EVENT", `${label} is too deeply nested.`);
  if (value === null || typeof value === "string" || typeof value === "boolean") return value as JsonPrimitive;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) {
    if (value.length > 200) throw new TenantSecurityError("INVALID_AUDIT_EVENT", `${label} contains too many entries.`);
    return value.map((entry) => assertSafeJson(entry, label, depth + 1));
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > 100) throw new TenantSecurityError("INVALID_AUDIT_EVENT", `${label} contains too many fields.`);
    const result: Record<string, JsonValue> = {};
    for (const [key, entry] of entries) {
      if (!/^[A-Za-z][A-Za-z0-9_.-]{0,79}$/.test(key) || forbiddenDetailKey.test(key) || structuralObjectKeys.has(key)) {
        throw new TenantSecurityError("INVALID_AUDIT_EVENT", `${label} contains a forbidden field.`);
      }
      result[key] = assertSafeJson(entry, label, depth + 1);
    }
    return result;
  }
  throw new TenantSecurityError("INVALID_AUDIT_EVENT", `${label} is not JSON-safe.`);
}

export function stableJson(value: JsonValue): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
}
