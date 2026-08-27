import assert from "node:assert/strict";
import test from "node:test";

import {
  createTenantApiHandler,
  type ApiGatewayRestEvent,
  type LegalHoldApprovalApiPayload,
  type LegalHoldRequestApiPayload,
  type UploadIntentApiPayload,
} from "../lib/aws-runtime/http/lambda-api.ts";
import type { AuthorizedApiRequest } from "../lib/aws-runtime/http/api.ts";
import { TenantDirectory, type TenantRole } from "../lib/aws-runtime/tenancy.ts";
import type { IssuedPresignedUpload } from "../lib/aws-runtime/evidence/upload-intent-issuer.ts";
import type {
  ApprovedExactVersionLegalHold,
  RequestedExactVersionLegalHold,
} from "../lib/aws-runtime/evidence/exact-version-legal-hold.ts";

const TENANT = `ten_${"a".repeat(32)}`;
const USER = `usr_${"b".repeat(32)}`;
const MEMBERSHIP = `mem_${"c".repeat(32)}`;
const EVIDENCE = `evd_${"d".repeat(32)}`;
const INTENT = `upl_${"e".repeat(32)}`;
const DEVICE = `dev_${"1".repeat(32)}`;
const ASSESSMENT = `asm_${"2".repeat(32)}`;
const API_HOST = "api-acme.evidence.example.com";
const WEB_ORIGIN = "https://acme.evidence.example.com";
const CLIENT = "5kexampleclient";

function event(path: string, method = "GET", overrides: Partial<ApiGatewayRestEvent> = {}): ApiGatewayRestEvent {
  const headers = { authorization: "Bearer aaa.bbb.ccc", origin: WEB_ORIGIN, ...(overrides.headers ?? {}) };
  return {
    body: null,
    headers,
    httpMethod: method,
    isBase64Encoded: false,
    path,
    requestContext: { domainName: API_HOST, requestId: "request-12345678" },
    ...overrides,
  };
}

function uploadBody(): Record<string, unknown> {
  return {
    assessmentId: ASSESSMENT,
    capturedAt: "2026-08-27T16:00:00.000Z",
    contentType: "image/png",
    controlId: "PCI-DSS-10.2.1",
    description: "Redacted privileged-access review evidence",
    deviceId: DEVICE,
    evidenceId: EVIDENCE,
    evidenceType: "SCREENSHOT",
    expectedSha256: "f".repeat(64),
    expectedSize: 4096,
    idempotencyKey: "A".repeat(43),
    metadata: { catalogVersion: "pci-dss-v4.0.1" },
    source: "Scopeproof Capture",
    systemName: "Production identity provider",
    title: "Quarterly privileged-access review",
  };
}

function issued(): IssuedPresignedUpload {
  const requiredHeaders = Object.freeze({ "content-type": "image/png", "content-length": "4096" });
  return {
    intent: {
      schemaVersion: 1,
      id: INTENT as IssuedPresignedUpload["intent"]["id"],
      tenantId: TENANT as IssuedPresignedUpload["intent"]["tenantId"],
      requestedBy: USER as IssuedPresignedUpload["intent"]["requestedBy"],
      resourceId: EVIDENCE as IssuedPresignedUpload["intent"]["resourceId"],
      expectedSha256: "f".repeat(64) as IssuedPresignedUpload["intent"]["expectedSha256"],
      expectedSize: 4096,
      contentType: "image/png",
      nonceDigest: "3".repeat(64) as IssuedPresignedUpload["intent"]["nonceDigest"],
      quarantineKey: `tenants/${TENANT}/controls/PCI-DSS-10.2.1/quarantine/${INTENT}.upload` as IssuedPresignedUpload["intent"]["quarantineKey"],
      finalKey: `tenants/${TENANT}/controls/PCI-DSS-10.2.1/evidence/${EVIDENCE}.png` as IssuedPresignedUpload["intent"]["finalKey"],
      issuedAt: "2026-08-27T16:00:00.000Z",
      expiresAt: "2026-08-27T16:05:00.000Z",
      requiredRetentionUntil: "2027-08-27T17:00:00.000Z",
      revision: 0,
      status: "issued",
      controlId: "PCI-DSS-10.2.1",
      quarantineBucket: "scopeproof-quarantine",
      quarantineKmsKeyArn: "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      idempotencyDigest: "4".repeat(64) as IssuedPresignedUpload["intent"]["idempotencyDigest"],
      requestFingerprint: "5".repeat(64) as IssuedPresignedUpload["intent"]["requestFingerprint"],
    },
    nonce: "N".repeat(43),
    upload: {
      method: "PUT",
      url: `https://scopeproof-quarantine.s3.us-east-1.amazonaws.com/${INTENT}?X-Amz-Signature=${"a".repeat(64)}`,
      bucket: "scopeproof-quarantine",
      key: `tenants/${TENANT}/controls/PCI-DSS-10.2.1/quarantine/${INTENT}.upload` as IssuedPresignedUpload["upload"]["key"],
      expiresAt: "2026-08-27T16:05:00.000Z",
      requiredHeaders,
    },
  };
}

function handler(input: {
  role?: TenantRole;
  issue?: (request: AuthorizedApiRequest, payload: UploadIntentApiPayload) => Promise<IssuedPresignedUpload>;
  requestLegalHold?: (request: AuthorizedApiRequest, payload: LegalHoldRequestApiPayload) => Promise<RequestedExactVersionLegalHold>;
  approveLegalHold?: (request: AuthorizedApiRequest, payload: LegalHoldApprovalApiPayload) => Promise<ApprovedExactVersionLegalHold>;
} = {}) {
  let runtimeCreations = 0;
  const directory = new TenantDirectory([
    { id: TENANT as never, slug: "acme", displayName: "Acme Corporation", appClientId: CLIENT, status: "active" },
  ], [
    { tenantId: TENANT as never, hostname: API_HOST as never, status: "active", canonical: true },
  ]);
  const api = createTenantApiHandler({
    apiHostname: API_HOST,
    allowedOrigin: WEB_ORIGIN,
    createRequestRuntime() {
      runtimeCreations += 1;
      return {
        authentication: {
          authority: { mode: "api_gateway_domain" },
          tenants: directory,
          jwt: {
            async verify() {
              return {
                signatureVerified: true,
                issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
                subject: "8f1a75c0-example",
                clientId: CLIENT,
                tokenUse: "access",
                issuedAt: "2026-08-27T15:55:00.000Z",
                authenticatedAt: "2026-08-27T15:55:00.000Z",
                expiresAt: "2026-08-27T16:55:00.000Z",
                scopes: [],
              };
            },
          },
          memberships: {
            async findActiveByIdentity() {
              return {
                tenantId: TENANT as never,
                identitySubject: "8f1a75c0-example",
                membership: {
                  id: MEMBERSHIP as never,
                  tenantId: TENANT as never,
                  userId: USER as never,
                  role: input.role ?? "collector",
                  status: "active",
                },
              };
            },
          },
        },
        issueUploadIntent: input.issue ?? (async () => issued()),
        requestLegalHold: input.requestLegalHold,
        approveLegalHold: input.approveLegalHold,
      };
    },
  });
  return { api, runtimeCreations: () => runtimeCreations };
}

function legalHoldRequestBody(): Record<string, unknown> {
  return {
    bucket: "scopeproof-evidence",
    changedAt: "2026-08-27T16:00:00.000Z",
    contentType: "image/png",
    controlId: "PCI-DSS-10.2.1",
    evidenceId: EVIDENCE,
    expectedHoldRevision: 0,
    holdId: `hld_${"6".repeat(32)}`,
    key: `tenants/${TENANT}/controls/PCI-DSS-10.2.1/evidence/${EVIDENCE}.png`,
    kind: "LEGAL",
    operationId: `lho_${"7".repeat(32)}`,
    reason: "External audit preservation request",
    status: "ON",
    versionId: "exact-version-0001",
  };
}

function postBody(path: string, bodyValue: Record<string, unknown>): ApiGatewayRestEvent {
  const body = JSON.stringify(bodyValue);
  return event(path, "POST", {
    body,
    headers: {
      authorization: "Bearer aaa.bbb.ccc",
      "content-length": String(new TextEncoder().encode(body).byteLength),
      "content-type": "application/json",
      origin: WEB_ORIGIN,
    },
  });
}

test("health is bounded, cache-disabled, and does not create privileged request state", async () => {
  const runtime = handler();
  const response = await runtime.api(event("/health"));
  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), { status: "ok" });
  assert.equal(response.headers["cache-control"], "no-store");
  assert.equal(response.headers["access-control-allow-origin"], WEB_ORIGIN);
  assert.equal(runtime.runtimeCreations(), 0);
});

test("authenticated me derives tenant and membership from verified adapters", async () => {
  const response = await handler().api(event("/v1/me"));
  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), {
    tenantId: TENANT,
    tenantHostname: API_HOST,
    userId: USER,
    membershipId: MEMBERSHIP,
    role: "collector",
    tokenExpiresAt: "2026-08-27T16:55:00.000Z",
  });
  assert.equal(response.body.includes("8f1a75c0-example"), false);
});

test("upload intent accepts exact JSON, uses the actor, and screens server-only digests", async () => {
  let actor = "";
  let payload: UploadIntentApiPayload | undefined;
  const runtime = handler({
    async issue(request, received) {
      actor = request.actor.userId;
      payload = received;
      return issued();
    },
  });
  const body = JSON.stringify(uploadBody());
  const response = await runtime.api(event("/v1/upload-intents", "POST", {
    body,
    headers: {
      authorization: "Bearer aaa.bbb.ccc",
      "content-length": String(new TextEncoder().encode(body).byteLength),
      "content-type": "application/json; charset=utf-8",
      origin: WEB_ORIGIN,
    },
  }));
  assert.equal(response.statusCode, 201);
  assert.equal(actor, USER);
  assert.equal(payload?.evidenceId, EVIDENCE);
  const result = JSON.parse(response.body) as Record<string, unknown>;
  assert.equal(result.uploadIntentId, INTENT);
  assert.equal(response.body.includes("idempotencyDigest"), false);
  assert.equal(response.body.includes("requestFingerprint"), false);
  assert.equal(response.body.includes("nonceDigest"), false);
});

test("auditors cannot issue uploads and the issuer is never called", async () => {
  let called = false;
  const runtime = handler({
    role: "auditor",
    async issue() { called = true; return issued(); },
  });
  const body = JSON.stringify(uploadBody());
  const response = await runtime.api(event("/v1/upload-intents", "POST", {
    body,
    headers: { authorization: "Bearer aaa.bbb.ccc", "content-type": "application/json", origin: WEB_ORIGIN },
  }));
  assert.equal(response.statusCode, 403);
  assert.equal(called, false);
});

test("host, origin, duplicate-header, and media-type confusion fail closed", async () => {
  const runtime = handler();
  const wrongHost = await runtime.api(event("/health", "GET", { requestContext: { domainName: "evil.example.com", requestId: "request-12345678" } }));
  assert.equal(wrongHost.statusCode, 400);
  const wrongOrigin = await runtime.api(event("/health", "GET", { headers: { authorization: "Bearer aaa.bbb.ccc", origin: "https://evil.example.com" } }));
  assert.equal(wrongOrigin.statusCode, 403);
  const duplicated = await runtime.api(event("/v1/me", "GET", {
    multiValueHeaders: { authorization: ["Bearer aaa.bbb.ccc", "Bearer ddd.eee.fff"] },
  }));
  assert.equal(duplicated.statusCode, 400);
  const body = JSON.stringify(uploadBody());
  const wrongType = await runtime.api(event("/v1/upload-intents", "POST", {
    body,
    headers: { authorization: "Bearer aaa.bbb.ccc", "content-type": "text/plain", origin: WEB_ORIGIN },
  }));
  assert.equal(wrongType.statusCode, 415);
});

test("security-sensitive JSON bodies reject duplicate fields at every depth", async () => {
  let uploadCalled = false;
  let legalCalled = false;
  const runtime = handler({
    role: "admin",
    async issue() { uploadCalled = true; return issued(); },
    async requestLegalHold() { legalCalled = true; throw new Error("ambiguous legal-hold JSON reached the service"); },
  });
  const ambiguousUpload = JSON.stringify(uploadBody()).replace(
    '"metadata":{"catalogVersion":"pci-dss-v4.0.1"}',
    '"metadata":{"catalogVersion":"pci-dss-v4.0.1","catalogVersion":"attacker-value"}',
  );
  const upload = await runtime.api(event("/v1/upload-intents", "POST", {
    body: ambiguousUpload,
    headers: {
      authorization: "Bearer aaa.bbb.ccc",
      "content-length": String(new TextEncoder().encode(ambiguousUpload).byteLength),
      "content-type": "application/json",
      origin: WEB_ORIGIN,
    },
  }));
  assert.equal(upload.statusCode, 400);
  assert.equal(uploadCalled, false);

  const legal = JSON.stringify(legalHoldRequestBody()).replace(
    '"status":"ON"',
    '"status":"OFF","status":"ON"',
  );
  const hold = await runtime.api(event("/v1/legal-hold-requests", "POST", {
    body: legal,
    headers: {
      authorization: "Bearer aaa.bbb.ccc",
      "content-length": String(new TextEncoder().encode(legal).byteLength),
      "content-type": "application/json",
      origin: WEB_ORIGIN,
    },
  }));
  assert.equal(hold.statusCode, 400);
  assert.equal(legalCalled, false);
});

test("unknown routes and known-route method confusion return bounded responses", async () => {
  const runtime = handler();
  assert.equal((await runtime.api(event("/v1/unknown"))).statusCode, 404);
  const response = await runtime.api(event("/v1/me", "POST"));
  assert.equal(response.statusCode, 405);
  assert.equal(response.headers.allow, "GET, POST");
});

test("legal-hold request and approval are distinct authenticated admin calls with no client actor fields", async () => {
  let requester = "";
  let approver = "";
  let requestedPayload: LegalHoldRequestApiPayload | undefined;
  let approvedPayload: LegalHoldApprovalApiPayload | undefined;
  const operationId = `lho_${"7".repeat(32)}`;
  const requestDigest = "8".repeat(64);
  const runtime = handler({
    role: "admin",
    async requestLegalHold(request, payload) {
      requester = request.actor.userId;
      requestedPayload = payload;
      return {
        operation: {
          schemaVersion: 2,
          operationId,
          holdId: `hld_${"6".repeat(32)}`,
          tenantId: TENANT,
          controlId: "PCI-DSS-10.2.1",
          evidenceId: EVIDENCE,
          bucket: "scopeproof-evidence",
          key: `tenants/${TENANT}/controls/PCI-DSS-10.2.1/evidence/${EVIDENCE}.png`,
          versionId: "exact-version-0001",
          status: "ON",
          kind: "LEGAL",
          reason: "External audit preservation request",
          requestedBy: USER,
          expectedHoldRevision: 0,
          changedAt: "2026-08-27T16:00:00.000Z",
          canonicalRequest: "{}",
          requestDigest,
        },
        reservation: { state: "REQUESTED", operationRevision: 0 },
      } as RequestedExactVersionLegalHold;
    },
    async approveLegalHold(request, payload) {
      approver = request.actor.userId;
      approvedPayload = payload;
      return {
        state: "APPROVED",
        operationRevision: 1,
        approval: {
          schemaVersion: 1,
          tenantId: TENANT,
          operationId,
          requestDigest,
          approvedBy: USER,
          approvedAt: "2026-08-27T16:05:00.000Z",
          canonicalApproval: "{}",
          approvalDigest: "9".repeat(64),
        },
      } as ApprovedExactVersionLegalHold;
    },
  });

  const requested = await runtime.api(postBody("/v1/legal-hold-requests", legalHoldRequestBody()));
  assert.equal(requested.statusCode, 202);
  assert.equal(requester, USER);
  assert.equal(requestedPayload?.versionId, "exact-version-0001");
  assert.equal("requestedBy" in (requestedPayload as object), false);
  assert.deepEqual(JSON.parse(requested.body), { operationId, requestDigest, state: "REQUESTED", operationRevision: 0 });

  const approved = await runtime.api(postBody("/v1/legal-hold-approvals", {
    approvedAt: "2026-08-27T16:05:00.000Z",
    operationId,
    requestDigest,
  }));
  assert.equal(approved.statusCode, 202);
  assert.equal(approver, USER);
  assert.equal(approvedPayload?.operationId, operationId);
  assert.equal("approvedBy" in (approvedPayload as object), false);
});

test("non-admin legal-hold calls are rejected before parsing or invoking control operations", async () => {
  let called = false;
  const runtime = handler({
    role: "compliance_lead",
    async requestLegalHold() { called = true; throw new Error("must not run"); },
    async approveLegalHold() { called = true; throw new Error("must not run"); },
  });
  assert.equal((await runtime.api(postBody("/v1/legal-hold-requests", legalHoldRequestBody()))).statusCode, 403);
  assert.equal((await runtime.api(postBody("/v1/legal-hold-approvals", {
    approvedAt: "2026-08-27T16:05:00.000Z",
    operationId: `lho_${"7".repeat(32)}`,
    requestDigest: "8".repeat(64),
  }))).statusCode, 403);
  assert.equal(called, false);
});

test("legal-hold routes reject actor injection, unknown fields, and method confusion", async () => {
  const runtime = handler({
    role: "admin",
    async requestLegalHold() { throw new Error("invalid body must not reach control operation"); },
  });
  const injected = { ...legalHoldRequestBody(), requestedBy: `usr_${"f".repeat(32)}` };
  assert.equal((await runtime.api(postBody("/v1/legal-hold-requests", injected))).statusCode, 400);
  assert.equal((await runtime.api(event("/v1/legal-hold-approvals", "GET"))).statusCode, 405);
});
