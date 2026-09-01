import {
  asAuditEventId,
  asResourceId,
  asSha256,
  asTenantId,
  assertBoundedText,
  canonicalInstant,
  safeEqual,
  sha256Hex,
  stableJson,
  type JsonValue,
  TenantSecurityError,
} from "../contracts.ts";
import type { TenantAuditEvent } from "../audit.ts";
import { asKmsKeyArn, base64ToBytes, bytesToBase64, hexToBytes } from "./primitives.ts";

export const AUDIT_RECEIPT_DOMAIN = "scopeproof-audit-receipt-v1";
export type KmsSigningAlgorithm = "ECDSA_SHA_256" | "RSASSA_PSS_SHA_256";

export interface KmsSignInput {
  readonly KeyId: string;
  readonly Message: Uint8Array;
  readonly MessageType: "DIGEST";
  readonly SigningAlgorithm: KmsSigningAlgorithm;
}

export interface KmsSignOutput {
  readonly KeyId?: string;
  readonly Signature?: Uint8Array;
  readonly SigningAlgorithm?: string;
}

export interface KmsVerifyInput extends KmsSignInput {
  readonly Signature: Uint8Array;
}

export interface KmsVerifyOutput {
  readonly KeyId?: string;
  readonly SignatureValid?: boolean;
  readonly SigningAlgorithm?: string;
}

/** Facade implemented with KMS SignCommand and VerifyCommand in AWS runtime. */
export interface KmsAsymmetricSigningClient {
  sign(input: KmsSignInput): Promise<KmsSignOutput>;
  verify(input: KmsVerifyInput): Promise<KmsVerifyOutput>;
}

export interface AuditReceiptPayload {
  readonly schemaVersion: 1;
  readonly domain: typeof AUDIT_RECEIPT_DOMAIN;
  readonly tenantId: string;
  readonly sequence: number;
  readonly eventId: string;
  readonly eventHash: string;
  readonly previousHash: string;
  readonly occurredAt: string;
  readonly signedAt: string;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId: string;
  readonly requestId: string;
  readonly outcome: "succeeded" | "denied" | "failed";
}

export interface KmsSignedAuditReceipt {
  readonly schemaVersion: 1;
  readonly payload: AuditReceiptPayload;
  readonly payloadSha256: string;
  readonly keyArn: string;
  readonly signingAlgorithm: KmsSigningAlgorithm;
  readonly signature: string;
}

export async function signTenantAuditReceipt(input: {
  client: KmsAsymmetricSigningClient;
  event: TenantAuditEvent;
  keyArn: string;
  signingAlgorithm: KmsSigningAlgorithm;
  signedAt: Date | string;
}): Promise<KmsSignedAuditReceipt> {
  const keyArn = asKmsKeyArn(input.keyArn);
  const signingAlgorithm = asSigningAlgorithm(input.signingAlgorithm);
  await assertEventHash(input.event);
  const payload = normalizePayload({
    schemaVersion: 1,
    domain: AUDIT_RECEIPT_DOMAIN,
    tenantId: input.event.tenantId,
    sequence: input.event.sequence,
    eventId: input.event.id,
    eventHash: input.event.eventHash,
    previousHash: input.event.previousHash,
    occurredAt: input.event.occurredAt,
    signedAt: input.signedAt,
    action: input.event.action,
    resourceType: input.event.resourceType,
    resourceId: input.event.resourceId,
    requestId: input.event.requestId,
    outcome: input.event.outcome,
  });
  if (Date.parse(payload.signedAt) < Date.parse(payload.occurredAt)) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit receipt cannot predate its event.");
  }
  const payloadSha256 = await auditReceiptDigest(payload);
  const response = await input.client.sign({
    KeyId: keyArn,
    Message: hexToBytes(payloadSha256),
    MessageType: "DIGEST",
    SigningAlgorithm: signingAlgorithm,
  });
  const signature = response.Signature;
  if (
    response.KeyId !== keyArn ||
    response.SigningAlgorithm !== signingAlgorithm ||
    !(signature instanceof Uint8Array) ||
    signature.byteLength < 40 ||
    signature.byteLength > 1_024
  ) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "KMS returned an invalid audit receipt signature.");
  }
  return Object.freeze({
    schemaVersion: 1,
    payload,
    payloadSha256,
    keyArn,
    signingAlgorithm,
    signature: bytesToBase64(signature),
  });
}

export async function verifyTenantAuditReceipt(input: {
  client: KmsAsymmetricSigningClient;
  receipt: KmsSignedAuditReceipt;
  expectedEvent: TenantAuditEvent;
  expectedKeyArn: string;
  expectedTenantId: string;
}): Promise<void> {
  if (input.receipt.schemaVersion !== 1) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit receipt schema is unsupported.");
  }
  const expectedKeyArn = asKmsKeyArn(input.expectedKeyArn);
  const expectedTenantId = asTenantId(input.expectedTenantId);
  const keyArn = asKmsKeyArn(input.receipt.keyArn);
  const signingAlgorithm = asSigningAlgorithm(input.receipt.signingAlgorithm);
  const payload = normalizePayload(input.receipt.payload);
  if (Date.parse(payload.signedAt) < Date.parse(payload.occurredAt)) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit receipt predates its event.");
  }
  await assertEventHash(input.expectedEvent);
  const expectedPayload = normalizePayload({
    schemaVersion: 1,
    domain: AUDIT_RECEIPT_DOMAIN,
    tenantId: input.expectedEvent.tenantId,
    sequence: input.expectedEvent.sequence,
    eventId: input.expectedEvent.id,
    eventHash: input.expectedEvent.eventHash,
    previousHash: input.expectedEvent.previousHash,
    occurredAt: input.expectedEvent.occurredAt,
    signedAt: payload.signedAt,
    action: input.expectedEvent.action,
    resourceType: input.expectedEvent.resourceType,
    resourceId: input.expectedEvent.resourceId,
    requestId: input.expectedEvent.requestId,
    outcome: input.expectedEvent.outcome,
  });
  if (payload.tenantId !== expectedTenantId || keyArn !== expectedKeyArn) {
    throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Audit receipt was not found.", 404);
  }
  if (!safeEqual(stableJson(payload as unknown as JsonValue), stableJson(expectedPayload as unknown as JsonValue))) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit receipt does not match the expected audit event.", 409);
  }
  const digest = await auditReceiptDigest(payload);
  const claimedDigest = asSha256(input.receipt.payloadSha256);
  if (!safeEqual(digest, claimedDigest)) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit receipt payload digest does not match.", 409);
  }
  const signature = base64ToBytes(input.receipt.signature);
  if (signature.byteLength < 40 || signature.byteLength > 1_024) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit receipt signature length is invalid.");
  }
  const response = await input.client.verify({
    KeyId: keyArn,
    Message: hexToBytes(digest),
    MessageType: "DIGEST",
    SigningAlgorithm: signingAlgorithm,
    Signature: signature,
  });
  if (response.SignatureValid !== true || response.KeyId !== keyArn || response.SigningAlgorithm !== signingAlgorithm) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "KMS did not verify the audit receipt signature.", 409);
  }
}

export async function auditReceiptDigest(payload: AuditReceiptPayload): Promise<string> {
  const canonical = stableJson(normalizePayload(payload) as unknown as JsonValue);
  return sha256Hex(`${AUDIT_RECEIPT_DOMAIN}\0${canonical}`);
}

function normalizePayload(input: AuditReceiptPayload | (Omit<AuditReceiptPayload, "signedAt"> & { signedAt: Date | string })): AuditReceiptPayload {
  if (input.schemaVersion !== 1 || input.domain !== AUDIT_RECEIPT_DOMAIN) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit receipt domain or schema is invalid.");
  }
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 1) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit receipt sequence is invalid.");
  }
  const previousHash = input.previousHash === "GENESIS" ? "GENESIS" : asSha256(input.previousHash);
  if ((input.sequence === 1) !== (previousHash === "GENESIS")) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit receipt chain position is invalid.");
  }
  if (!(["succeeded", "denied", "failed"] as const).includes(input.outcome)) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit receipt outcome is invalid.");
  }
  const action = normalizedToken(input.action, "Audit action", 3, 120);
  const resourceType = normalizedToken(input.resourceType, "Audit resource type", 2, 80);
  return Object.freeze({
    schemaVersion: 1,
    domain: AUDIT_RECEIPT_DOMAIN,
    tenantId: asTenantId(input.tenantId),
    sequence: input.sequence,
    eventId: asAuditEventId(input.eventId),
    eventHash: asSha256(input.eventHash),
    previousHash,
    occurredAt: canonicalInstant(input.occurredAt, "Audit event time"),
    signedAt: canonicalInstant(input.signedAt, "Audit receipt time"),
    action,
    resourceType,
    resourceId: asResourceId(input.resourceId),
    requestId: assertBoundedText(input.requestId, "Audit request id", 3, 200),
    outcome: input.outcome,
  });
}

function normalizedToken(value: string, label: string, minimum: number, maximum: number): string {
  const token = assertBoundedText(value, label, minimum, maximum);
  if (!/^[a-z][a-z0-9_.:-]*$/.test(token)) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", `${label} is invalid.`);
  }
  return token;
}

function asSigningAlgorithm(value: string): KmsSigningAlgorithm {
  if (value !== "ECDSA_SHA_256" && value !== "RSASSA_PSS_SHA_256") {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "KMS signing algorithm is not approved.");
  }
  return value;
}

async function assertEventHash(event: TenantAuditEvent): Promise<void> {
  const { eventHash, ...unsigned } = event;
  const canonical = stableJson(unsigned as unknown as JsonValue);
  const calculated = await sha256Hex(canonical);
  if (!safeEqual(calculated, asSha256(eventHash))) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit event hash is invalid.", 409);
  }
}
