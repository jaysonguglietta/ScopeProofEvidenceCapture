import { TenantSecurityError, type JsonValue } from "../contracts.ts";
import type { IssuedPresignedUpload } from "../evidence/upload-intent-issuer.ts";
import type { UploadIntentEvidenceProjection } from "../evidence/upload-intent-database.ts";
import type {
  ApprovedExactVersionLegalHold,
  DurableExactVersionLegalHoldRequest,
  ExactVersionLegalHoldApprovalRequest,
  LegalHoldKind,
  RequestedExactVersionLegalHold,
  S3LegalHoldStatus,
} from "../evidence/exact-version-legal-hold.ts";
import {
  handleAuthorizedApiRequest,
  safeProblemResponse,
  type ApiAuthenticationDependencies,
  type ApiGatewayV2Event,
  type AuthorizedApiRequest,
} from "./api.ts";
import { parseStrictJsonObject } from "./jwt.ts";

export interface ApiGatewayRestEvent {
  readonly body?: string | null;
  readonly headers?: Readonly<Record<string, string | undefined>> | null;
  readonly httpMethod?: string;
  readonly isBase64Encoded?: boolean;
  readonly multiValueHeaders?: Readonly<Record<string, readonly string[] | undefined>> | null;
  readonly path?: string;
  readonly requestContext?: Readonly<{
    readonly domainName?: string;
    readonly requestId?: string;
  }>;
}

export interface ApiGatewayRestResult {
  readonly statusCode: number;
  readonly headers: Readonly<Record<string, string>>;
  readonly body: string;
  readonly isBase64Encoded: false;
}

export interface UploadIntentApiPayload {
  readonly idempotencyKey: string;
  readonly controlId: string;
  readonly evidenceId: string;
  readonly expectedSha256: string;
  readonly expectedSize: number;
  readonly contentType: string;
  readonly evidence: Omit<UploadIntentEvidenceProjection, "artifactExpiresAt">;
}

/**
 * Every field below describes the exact evidence version or the requested
 * transition. The requester identity is deliberately absent and is supplied
 * only by the verified Cognito/membership context.
 */
export type LegalHoldRequestApiPayload = Omit<DurableExactVersionLegalHoldRequest, "tenantId">;

/** The approver tenant and identity are both derived from the second request. */
export type LegalHoldApprovalApiPayload = Omit<ExactVersionLegalHoldApprovalRequest, "tenantId">;

export interface TenantApiRequestRuntime {
  readonly authentication: ApiAuthenticationDependencies;
  readonly issueUploadIntent?: (
    request: AuthorizedApiRequest,
    payload: UploadIntentApiPayload,
  ) => Promise<IssuedPresignedUpload>;
  readonly requestLegalHold?: (
    request: AuthorizedApiRequest,
    payload: LegalHoldRequestApiPayload,
  ) => Promise<RequestedExactVersionLegalHold>;
  readonly approveLegalHold?: (
    request: AuthorizedApiRequest,
    payload: LegalHoldApprovalApiPayload,
  ) => Promise<ApprovedExactVersionLegalHold>;
}

export interface TenantApiHandlerOptions {
  readonly apiHostname: string;
  readonly allowedOrigin: string;
  readonly createRequestRuntime: (requestId: string) => TenantApiRequestRuntime;
  readonly onInternalError?: (event: Readonly<{ requestId: string; errorName: string }>) => void;
}

const requestIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const apiHostnamePattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
const uploadBodyKeys = Object.freeze([
  "assessmentId",
  "capturedAt",
  "contentType",
  "controlId",
  "description",
  "deviceId",
  "evidenceId",
  "evidenceType",
  "expectedSha256",
  "expectedSize",
  "idempotencyKey",
  "metadata",
  "source",
  "systemName",
  "title",
] as const);
const legalHoldRequestBodyKeys = Object.freeze([
  "bucket",
  "changedAt",
  "contentType",
  "controlId",
  "evidenceId",
  "expectedHoldRevision",
  "holdId",
  "key",
  "kind",
  "operationId",
  "reason",
  "status",
  "versionId",
] as const);
const legalHoldApprovalBodyKeys = Object.freeze([
  "approvedAt",
  "operationId",
  "requestDigest",
] as const);

function exactObject(value: unknown, keys: readonly string[], label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", `${label} must be a JSON object.`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", `${label} contains missing or unexpected fields.`);
  }
  return value as Record<string, unknown>;
}

function stringField(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function parseJsonBody(
  body: string | null | undefined,
  headers: Readonly<Record<string, string>>,
  keys: readonly string[],
  label: string,
): Record<string, unknown> {
  const contentType = headers["content-type"]?.trim().toLowerCase() ?? "";
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/.test(contentType)) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", `${label} requests require application/json.`, 415);
  }
  if (typeof body !== "string") throw new TenantSecurityError("INVALID_IDENTIFIER", "A JSON request body is required.");
  const encoded = new TextEncoder().encode(body);
  if (encoded.byteLength < 2 || encoded.byteLength > 131_072) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", `${label} request body is invalid or too large.`, encoded.byteLength > 131_072 ? 413 : 400);
  }
  const declaredLength = headers["content-length"];
  if (declaredLength !== undefined && (!/^(?:0|[1-9][0-9]{0,6})$/.test(declaredLength) || Number(declaredLength) !== encoded.byteLength)) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Request content length does not match the body.");
  }
  let parsed: unknown;
  try {
    parsed = parseStrictJsonObject(encoded);
  } catch {
    throw new TenantSecurityError("INVALID_IDENTIFIER", `${label} request body is not unambiguous valid JSON.`);
  }
  return exactObject(parsed, keys, label);
}

function parseUploadBody(body: string | null | undefined, headers: Readonly<Record<string, string>>): UploadIntentApiPayload {
  const contentType = headers["content-type"]?.trim().toLowerCase() ?? "";
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/.test(contentType)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload-intent requests require application/json.", 415);
  }
  if (typeof body !== "string") throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "A JSON request body is required.");
  const encoded = new TextEncoder().encode(body);
  if (encoded.byteLength < 2 || encoded.byteLength > 131_072) throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload-intent request body is invalid or too large.", encoded.byteLength > 131_072 ? 413 : 400);
  const declaredLength = headers["content-length"];
  if (declaredLength !== undefined && (!/^(?:0|[1-9][0-9]{0,6})$/.test(declaredLength) || Number(declaredLength) !== encoded.byteLength)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Request content length does not match the body.");
  }
  let parsed: unknown;
  try {
    parsed = parseStrictJsonObject(encoded);
  } catch {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload-intent request body is not unambiguous valid JSON.");
  }
  const value = exactObject(parsed, uploadBodyKeys, "Upload-intent request");
  if (!Number.isSafeInteger(value.expectedSize)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Expected evidence size must be an integer.");
  }
  return Object.freeze({
    idempotencyKey: stringField(value.idempotencyKey),
    controlId: stringField(value.controlId),
    evidenceId: stringField(value.evidenceId),
    expectedSha256: stringField(value.expectedSha256),
    expectedSize: value.expectedSize as number,
    contentType: stringField(value.contentType),
    evidence: Object.freeze({
      deviceId: stringField(value.deviceId),
      assessmentId: stringField(value.assessmentId),
      title: stringField(value.title),
      description: stringField(value.description),
      evidenceType: stringField(value.evidenceType) as UploadIntentEvidenceProjection["evidenceType"],
      source: stringField(value.source),
      systemName: stringField(value.systemName),
      capturedAt: stringField(value.capturedAt),
      metadata: value.metadata as JsonValue,
    }),
  });
}

function parseLegalHoldRequestBody(body: string | null | undefined, headers: Readonly<Record<string, string>>): LegalHoldRequestApiPayload {
  const value = parseJsonBody(body, headers, legalHoldRequestBodyKeys, "Legal-hold request");
  if (!Number.isSafeInteger(value.expectedHoldRevision)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Expected legal-hold revision must be an integer.");
  }
  const changedAt = new Date(stringField(value.changedAt));
  if (!Number.isFinite(changedAt.getTime())) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold change time is invalid.");
  }
  return Object.freeze({
    operationId: stringField(value.operationId),
    holdId: stringField(value.holdId),
    controlId: stringField(value.controlId),
    evidenceId: stringField(value.evidenceId),
    contentType: stringField(value.contentType),
    bucket: stringField(value.bucket),
    key: stringField(value.key),
    versionId: stringField(value.versionId),
    status: stringField(value.status) as S3LegalHoldStatus,
    changedAt,
    reason: stringField(value.reason),
    kind: stringField(value.kind) as LegalHoldKind,
    expectedHoldRevision: value.expectedHoldRevision as number,
  });
}

function parseLegalHoldApprovalBody(body: string | null | undefined, headers: Readonly<Record<string, string>>): LegalHoldApprovalApiPayload {
  const value = parseJsonBody(body, headers, legalHoldApprovalBodyKeys, "Legal-hold approval");
  const approvedAt = new Date(stringField(value.approvedAt));
  if (!Number.isFinite(approvedAt.getTime())) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold approval time is invalid.");
  }
  return Object.freeze({
    operationId: stringField(value.operationId),
    requestDigest: stringField(value.requestDigest),
    approvedAt,
  });
}

function canonicalHeaders(event: ApiGatewayRestEvent): Readonly<Record<string, string>> {
  const result: Record<string, string> = {};
  const source = event.headers ?? {};
  for (const [rawName, rawValue] of Object.entries(source)) {
    const name = rawName.toLowerCase();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]{1,128}$/.test(name) || typeof rawValue !== "string" || rawValue.length > 32_768 || /\p{Cc}/u.test(rawValue) || Object.hasOwn(result, name)) {
      throw new TenantSecurityError("INVALID_PRINCIPAL", "Request headers are invalid.", 400);
    }
    result[name] = rawValue;
  }
  if (event.multiValueHeaders) {
    const seen = new Set<string>();
    for (const [rawName, values] of Object.entries(event.multiValueHeaders)) {
      const name = rawName.toLowerCase();
      if (seen.has(name) || !Array.isArray(values) || values.length !== 1 || typeof values[0] !== "string" || result[name] !== values[0]) {
        throw new TenantSecurityError("INVALID_PRINCIPAL", "Duplicate request headers are not allowed.", 400);
      }
      seen.add(name);
    }
  }
  return Object.freeze(result);
}

function requestEnvelope(event: ApiGatewayRestEvent, apiHostname: string, allowedOrigin: string): Readonly<{
  v2: ApiGatewayV2Event;
  headers: Readonly<Record<string, string>>;
}> {
  const requestId = String(event.requestContext?.requestId ?? "");
  const domainName = String(event.requestContext?.domainName ?? "").toLowerCase();
  const method = String(event.httpMethod ?? "").toUpperCase();
  const path = String(event.path ?? "");
  if (!requestIdPattern.test(requestId) || domainName !== apiHostname || event.isBase64Encoded === true) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Request context is invalid.", 400);
  }
  const headers = canonicalHeaders(event);
  const origin = headers.origin;
  if (origin !== undefined && origin !== allowedOrigin) {
    throw new TenantSecurityError("INVALID_HOST", "Request origin is not allowed.", 403);
  }
  return Object.freeze({
    headers,
    v2: Object.freeze({
      headers,
      rawPath: path,
      requestContext: Object.freeze({
        requestId,
        domainName,
        http: Object.freeze({ method }),
      }),
    }),
  });
}

function jsonResponse(body: JsonValue, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "x-content-type-options": "nosniff",
    },
  });
}

function routeProblem(status: number, title: string, code: string, requestId: string): Response {
  return new Response(JSON.stringify({ type: "about:blank", title, status, code, requestId }), {
    status,
    headers: {
      "content-type": "application/problem+json",
      "x-content-type-options": "nosniff",
      ...(status === 405 ? { allow: "GET, POST" } : {}),
    },
  });
}

async function restResult(response: Response, requestId: string, allowedOrigin: string): Promise<ApiGatewayRestResult> {
  const body = await response.text();
  if (new TextEncoder().encode(body).byteLength > 1_048_576) {
    throw new Error("Tenant API response exceeded its bounded contract.");
  }
  const headers: Record<string, string> = {};
  response.headers.forEach((value, name) => { headers[name] = value; });
  Object.assign(headers, {
    "access-control-allow-origin": allowedOrigin,
    "cache-control": headers["cache-control"] || "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "vary": "Origin",
    "x-request-id": requestId,
  });
  return Object.freeze({ statusCode: response.status, headers: Object.freeze(headers), body, isBase64Encoded: false });
}

/**
 * REST API/Lambda adapter for the deliberately small production tenant API.
 * AWS clients and temporary credentials are supplied by the concrete entrypoint;
 * this layer owns routing, bounded parsing, authorization, and safe responses.
 */
export function createTenantApiHandler(options: TenantApiHandlerOptions): (event: ApiGatewayRestEvent) => Promise<ApiGatewayRestResult> {
  const apiHostname = String(options.apiHostname || "").toLowerCase();
  if (!apiHostnamePattern.test(apiHostname)) throw new Error("Tenant API hostname is invalid.");
  let origin: URL;
  try { origin = new URL(options.allowedOrigin); } catch { throw new Error("Tenant web origin is invalid."); }
  if (origin.protocol !== "https:" || origin.pathname !== "/" || origin.search || origin.hash || origin.username || origin.password || origin.port) {
    throw new Error("Tenant web origin must be an HTTPS origin.");
  }
  const allowedOrigin = origin.origin;
  return async (event): Promise<ApiGatewayRestResult> => {
    const fallbackRequestId = requestIdPattern.test(String(event.requestContext?.requestId ?? ""))
      ? String(event.requestContext?.requestId)
      : crypto.randomUUID();
    try {
      const envelope = requestEnvelope(event, apiHostname, allowedOrigin);
      const { method } = envelope.v2.requestContext.http;
      const path = envelope.v2.rawPath;
      let response: Response;
      if (path === "/health" && method === "GET") {
        response = jsonResponse({ status: "ok" });
      } else if (path === "/v1/me" && method === "GET") {
        const runtime = options.createRequestRuntime(envelope.v2.requestContext.requestId);
        response = await handleAuthorizedApiRequest(
          envelope.v2,
          "evidence:read",
          runtime.authentication,
          async ({ actor, identity }) => jsonResponse({
            tenantId: actor.tenantId,
            tenantHostname: actor.tenantHostname,
            userId: actor.userId,
            membershipId: actor.membershipId,
            role: actor.role,
            tokenExpiresAt: identity.expiresAt,
          }),
          options.onInternalError,
        );
      } else if (path === "/v1/upload-intents" && method === "POST") {
        const runtime = options.createRequestRuntime(envelope.v2.requestContext.requestId);
        response = await handleAuthorizedApiRequest(
          envelope.v2,
          "evidence:collect",
          runtime.authentication,
          async (request) => {
            const payload = parseUploadBody(event.body, envelope.headers);
            if (!runtime.issueUploadIntent) throw new Error("Upload-intent runtime is not configured for this route.");
            const issued = await runtime.issueUploadIntent(request, payload);
            return jsonResponse({
              uploadIntentId: issued.intent.id,
              evidenceId: issued.intent.resourceId,
              expiresAt: issued.intent.expiresAt,
              nonce: issued.nonce,
              upload: {
                method: issued.upload.method,
                url: issued.upload.url,
                requiredHeaders: issued.upload.requiredHeaders,
              },
            }, 201);
          },
          options.onInternalError,
        );
      } else if (path === "/v1/legal-hold-requests" && method === "POST") {
        const runtime = options.createRequestRuntime(envelope.v2.requestContext.requestId);
        response = await handleAuthorizedApiRequest(
          envelope.v2,
          "retention:manage",
          runtime.authentication,
          async (request) => {
            if (!runtime.requestLegalHold) throw new Error("Legal-hold request runtime is not configured for this route.");
            const result = await runtime.requestLegalHold(request, parseLegalHoldRequestBody(event.body, envelope.headers));
            return jsonResponse({
              operationId: result.operation.operationId,
              requestDigest: result.operation.requestDigest,
              state: result.reservation.state,
              operationRevision: result.reservation.operationRevision,
            }, 202);
          },
          options.onInternalError,
        );
      } else if (path === "/v1/legal-hold-approvals" && method === "POST") {
        const runtime = options.createRequestRuntime(envelope.v2.requestContext.requestId);
        response = await handleAuthorizedApiRequest(
          envelope.v2,
          "retention:manage",
          runtime.authentication,
          async (request) => {
            if (!runtime.approveLegalHold) throw new Error("Legal-hold approval runtime is not configured for this route.");
            const result = await runtime.approveLegalHold(request, parseLegalHoldApprovalBody(event.body, envelope.headers));
            return jsonResponse({
              operationId: result.approval.operationId,
              state: result.state,
              operationRevision: result.operationRevision,
              approvedAt: result.approval.approvedAt,
            }, 202);
          },
          options.onInternalError,
        );
      } else if ([
        "/health",
        "/v1/me",
        "/v1/upload-intents",
        "/v1/legal-hold-requests",
        "/v1/legal-hold-approvals",
      ].includes(path)) {
        response = routeProblem(405, "Method not allowed", "METHOD_NOT_ALLOWED", envelope.v2.requestContext.requestId);
      } else {
        response = routeProblem(404, "Resource not found", "RESOURCE_NOT_FOUND", envelope.v2.requestContext.requestId);
      }
      return await restResult(response, envelope.v2.requestContext.requestId, allowedOrigin);
    } catch (error) {
      if (!(error instanceof TenantSecurityError) || error.safeStatus >= 500) {
        options.onInternalError?.({ requestId: fallbackRequestId, errorName: error instanceof Error ? error.name : "UnknownError" });
      }
      return await restResult(safeProblemResponse(error, fallbackRequestId), fallbackRequestId, allowedOrigin);
    }
  };
}
