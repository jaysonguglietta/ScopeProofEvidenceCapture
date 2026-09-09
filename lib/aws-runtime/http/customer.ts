import { asResourceId, asTenantId, assertBoundedText, assertSafeJson, canonicalInstant, sha256Hex, stableJson, TenantSecurityError } from "../contracts.ts";
import type { AuthorizedApiRequest } from "./api.ts";
import type { VerifiedCognitoAccessToken } from "./jwt.ts";
import type { RdsDataApiExecutor } from "./membership.ts";
import type { CustomerAction, CustomerBody, CustomerReply } from "./customer-contracts.ts";
import { databaseProblem } from "./database-errors.ts";

export interface CustomerRepositoryOptions {
  readonly tenantId: string;
  readonly executor: RdsDataApiExecutor;
  readonly resourceArn: string;
  readonly secretArn: string;
  readonly database: string;
}

function bytes(value: unknown, minimum: number, maximum: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > Math.ceil(maximum * 4 / 3)) throw new TenantSecurityError("INVALID_IDENTIFIER", "Device key or signature encoding is invalid.");
  let decoded: string;
  try { decoded = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4)); } catch { throw new TenantSecurityError("INVALID_IDENTIFIER", "Device key or signature is invalid."); }
  if (decoded.length < minimum || decoded.length > maximum || btoa(decoded).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "") !== value) throw new TenantSecurityError("INVALID_IDENTIFIER", "Device key or signature encoding is not canonical.");
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

/** No physical-device attestation is claimed: this proves key possession. */
export async function verifyDeviceEnrollment(request: AuthorizedApiRequest, input: CustomerBody, now = new Date()): Promise<CustomerBody> {
  const deviceId = asResourceId(String(input.deviceId), ["dev"]);
  const displayName = assertBoundedText(typeof input.displayName === "string" ? input.displayName : "", "Device name", 1, 120);
  const signedAt = canonicalInstant(String(input.signedAt), "Enrollment signing time");
  if (!request.identity.jwtId || Math.abs(now.getTime() - Date.parse(signedAt)) > 5 * 60_000) throw new TenantSecurityError("INVALID_PRINCIPAL", "A fresh token-bound enrollment proof is required.", 401);
  const publicKey = bytes(input.publicKeySpki, 64, 512);
  const signature = bytes(input.signature, 64, 64);
  const publicKeySha256 = await sha256Hex(publicKey);
  const manifest = { schemaVersion: 1, tenantId: request.actor.tenantId, userId: request.actor.userId, deviceId, displayName, publicKeySha256, challenge: request.identity.jwtId, signedAt };
  let verified = false;
  try {
    const key = await crypto.subtle.importKey("spki", publicKey, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    verified = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, new TextEncoder().encode(`scopeproof-device-enrollment-v1\n${stableJson(manifest)}`));
  } catch { /* Fail closed without exposing parsing diagnostics or key bytes. */ }
  if (!verified) throw new TenantSecurityError("INVALID_PRINCIPAL", "Device enrollment possession proof failed.", 403);
  return Object.freeze({ deviceId, displayName, publicKeySha256 });
}

export class RdsDataCustomerRepository {
  readonly #tenantId: string;
  readonly #executor: RdsDataApiExecutor;
  readonly #connection: Readonly<{ resourceArn: string; secretArn: string; database: string }>;
  constructor(options: CustomerRepositoryOptions) {
    this.#tenantId = asTenantId(options.tenantId);
    this.#executor = options.executor;
    const cluster = /^arn:(aws|aws-us-gov|aws-cn):rds:([a-z0-9-]+):(\d{12}):cluster:[A-Za-z0-9-]{1,63}$/.exec(options.resourceArn);
    const secret = /^arn:(aws|aws-us-gov|aws-cn):secretsmanager:([a-z0-9-]+):(\d{12}):secret:[A-Za-z0-9/_+=.@-]{1,512}$/.exec(options.secretArn);
    if (!cluster || !secret || cluster[1] !== secret[1] || cluster[2] !== secret[2] || cluster[3] !== secret[3] || !/^[A-Za-z][A-Za-z0-9_]{0,62}$/.test(options.database)) throw new Error("Customer database connection must be valid and tenant-bound.");
    this.#connection = Object.freeze({ resourceArn: options.resourceArn, secretArn: options.secretArn, database: options.database });
  }

  async invoke(request: AuthorizedApiRequest, action: CustomerAction, body: CustomerBody): Promise<CustomerReply> {
    this.#boundary(request.actor.tenantId);
    const checkedBody = action === "devices.enroll" ? await verifyDeviceEnrollment(request, body) : body;
    const read = action.endsWith(".search") || action === "evidence.status";
    return await this.#execute(request.identity, request.requestId,
      read ? "SELECT scopeproof.customer_read(:subject,CAST(:authenticated_at AS timestamptz),:action,CAST(:body AS jsonb)) AS payload" : "SELECT scopeproof.customer_mutate(:subject,CAST(:authenticated_at AS timestamptz),:action,CAST(:body AS jsonb),:request_id) AS payload",
      { action, body: stableJson(checkedBody) });
  }

  async acceptInvitation(input: Readonly<{ tenantId: string; identity: VerifiedCognitoAccessToken; requestId: string }>): Promise<CustomerReply> {
    this.#boundary(input.tenantId);
    return await this.#execute(input.identity, input.requestId, "SELECT scopeproof.customer_accept_invitation(:subject,CAST(:authenticated_at AS timestamptz),:request_id) AS payload", {});
  }

  /** Only the legal-hold Lambda uses this; never serialize the result to a browser. */
  async legalHoldTarget(request: AuthorizedApiRequest, evidenceId: string, expectedRevision: number): Promise<CustomerReply> {
    this.#boundary(request.actor.tenantId);
    asResourceId(evidenceId, ["evd"]);
    if (!Number.isSafeInteger(expectedRevision) || expectedRevision < 0) throw new TenantSecurityError("INVALID_IDENTIFIER", "Expected evidence revision is invalid.");
    return await this.#execute(request.identity, request.requestId, "SELECT scopeproof.customer_legal_hold_target(:subject,CAST(:authenticated_at AS timestamptz),CAST(:evidence_id AS scopeproof.resource_identifier),CAST(:revision AS integer)) AS payload", { evidence_id: evidenceId, revision: String(expectedRevision) });
  }

  async legalHoldStatus(request: AuthorizedApiRequest, evidenceId: string): Promise<CustomerReply> {
    this.#boundary(request.actor.tenantId);
    asResourceId(evidenceId, ["evd"]);
    return await this.#execute(request.identity, request.requestId, "SELECT scopeproof.customer_legal_hold_status(:subject,CAST(:authenticated_at AS timestamptz),CAST(:evidence_id AS scopeproof.resource_identifier)) AS payload", { evidence_id: evidenceId });
  }

  #boundary(tenantId: string) { if (asTenantId(tenantId) !== this.#tenantId) throw new TenantSecurityError("ROLE_FORBIDDEN", "Tenant does not match the database boundary.", 403); }

  async #execute(identity: VerifiedCognitoAccessToken, requestId: string, sql: string, extra: Readonly<Record<string, string>>): Promise<CustomerReply> {
    if (!identity.signatureVerified || identity.tokenUse !== "access" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(requestId)) throw new TenantSecurityError("INVALID_PRINCIPAL", "Verified request context is required.", 401);
    const subject = assertBoundedText(identity.subject, "Identity subject", 8, 200);
    const authenticatedAt = canonicalInstant(identity.authenticatedAt, "Authentication time");
    const started = await this.#executor.beginTransaction(this.#connection);
    const transactionId = started.transactionId;
    if (!transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transactionId)) throw new Error("Customer database transaction failed.");
    const parameter = (name: string, value: string) => ({ name, value: { stringValue: value } });
    try {
      await this.#executor.executeStatement({ ...this.#connection, transactionId, sql: "SELECT pg_catalog.set_config('scopeproof.tenant_id',:tenant_id,true)", parameters: [parameter("tenant_id", this.#tenantId)] });
      const values = { subject, authenticated_at: authenticatedAt, request_id: requestId, ...extra };
      const parameters = Object.entries(values).filter(([name]) => new RegExp(`:${name}\\b`).test(sql)).map(([name, value]) => parameter(name, value));
      const result = await this.#executor.executeStatement({ ...this.#connection, transactionId, sql, parameters, formatRecordsAs: "JSON" });
      if (!result.formattedRecords || result.formattedRecords.length > 512_000) throw new Error("Customer database response exceeded its bound.");
      const rows: unknown = JSON.parse(result.formattedRecords);
      if (!Array.isArray(rows) || rows.length !== 1 || !rows[0]?.payload || typeof rows[0].payload !== "object" || rows[0].payload.tenantId !== this.#tenantId) throw new Error("Customer database response crossed its tenant boundary.");
      const payload = assertSafeJson(rows[0].payload, "Customer response") as CustomerReply;
      await this.#executor.commitTransaction({ resourceArn: this.#connection.resourceArn, secretArn: this.#connection.secretArn, transactionId });
      return payload;
    } catch (error) {
      try { await this.#executor.rollbackTransaction({ resourceArn: this.#connection.resourceArn, secretArn: this.#connection.secretArn, transactionId }); } catch { /* Preserve original error. */ }
      throw databaseProblem(error);
    }
  }
}
