import assert from "node:assert/strict";
import test from "node:test";

import {
  asMembershipId,
  asTenantId,
  asUserId,
  TenantSecurityError,
  type TenantId,
} from "../lib/aws-runtime/contracts.ts";
import { canonicalHostname, TenantDirectory, type TenantDomainRecord, type TenantMembership, type TenantRecord } from "../lib/aws-runtime/tenancy.ts";
import {
  authorizeApiGatewayRequest,
  authorizeVerifiedTenantIdentity,
  edgeProofCanonicalValue,
  handleAuthorizedApiRequest,
  HmacTrustedEdgeAuthorityVerifier,
  RdsDataMembershipRepository,
  safeProblemResponse,
  type ApiAuthenticationDependencies,
  type ApiGatewayV2Event,
  type CognitoJwtVerifier,
  type EdgeReplayNonceStore,
  type MembershipIdentityRecord,
  type RdsDataApiExecutor,
  type TenantMembershipRepository,
  type VerifiedCognitoAccessToken,
} from "../lib/aws-runtime/http/index.ts";

const TENANT_A = asTenantId(`ten_${"a".repeat(32)}`);
const TENANT_B = asTenantId(`ten_${"b".repeat(32)}`);
const USER_A = asUserId(`usr_${"1".repeat(32)}`);
const MEMBER_A = asMembershipId(`mem_${"2".repeat(32)}`);
const TOKEN = `${"a".repeat(20)}.${"b".repeat(20)}.${"c".repeat(20)}`;
const NOW = new Date("2026-08-27T16:00:00.000Z");
const CLIENT_A = "scopeproof-client-123";
const CLIENT_B = "scopeproof-client-456";

function directory(): TenantDirectory {
  const tenants: TenantRecord[] = [
    { id: TENANT_A, slug: "acme", displayName: "Acme Compliance", appClientId: CLIENT_A, status: "active" },
    { id: TENANT_B, slug: "bravo", displayName: "Bravo Compliance", appClientId: CLIENT_B, status: "active" },
  ];
  const domains: TenantDomainRecord[] = [
    { tenantId: TENANT_A, hostname: canonicalHostname("acme.jsontechology.com"), status: "active", canonical: true },
    { tenantId: TENANT_B, hostname: canonicalHostname("bravo.jsontechology.com"), status: "active", canonical: true },
  ];
  return new TenantDirectory(tenants, domains);
}

function identity(): VerifiedCognitoAccessToken {
  return Object.freeze({
    signatureVerified: true,
    issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Example",
    subject: "248289761001",
    clientId: CLIENT_A,
    tokenUse: "access",
    issuedAt: "2026-08-27T15:59:00.000Z",
    authenticatedAt: "2026-08-27T15:58:00.000Z",
    expiresAt: "2026-08-27T17:00:00.000Z",
    scopes: Object.freeze([
      "scopeproof/evidence.read",
      "scopeproof/evidence.collect",
      "scopeproof/retention.manage",
    ]),
  });
}

function membership(tenantId: TenantId = TENANT_A, role: TenantMembership["role"] = "admin"): MembershipIdentityRecord {
  return {
    tenantId,
    identitySubject: identity().subject,
    membership: { id: MEMBER_A, tenantId, userId: USER_A, role, status: "active" },
  };
}

function event(overrides: Partial<ApiGatewayV2Event> = {}): ApiGatewayV2Event {
  return {
    headers: { authorization: `Bearer ${TOKEN}` },
    requestContext: { requestId: "request-12345678", domainName: "acme.jsontechology.com", http: { method: "GET" } },
    rawPath: "/v1/evidence",
    ...overrides,
  };
}

function dependencies(repository: TenantMembershipRepository, authority: ApiAuthenticationDependencies["authority"] = { mode: "api_gateway_domain" }): ApiAuthenticationDependencies {
  return {
    tenants: directory(),
    jwt: { verify: async (token: string) => {
      assert.equal(token, TOKEN);
      return identity();
    } } as unknown as CognitoJwtVerifier,
    memberships: repository,
    authority,
  };
}

function repository(record: MembershipIdentityRecord | null, observed?: Array<{ tenantId: TenantId; identitySubject: string }>): TenantMembershipRepository {
  return { findActiveByIdentity: async (input) => {
    observed?.push(input);
    return record;
  } };
}

test("API request adapter binds exact gateway domain, verified subject, tenant membership, and role", async () => {
  const observed: Array<{ tenantId: TenantId; identitySubject: string }> = [];
  const request = await authorizeApiGatewayRequest(event(), "evidence:read", dependencies(repository(membership(), observed)));
  assert.equal(request.actor.tenantId, TENANT_A);
  assert.equal(request.actor.userId, USER_A);
  assert.equal(request.actor.role, "admin");
  assert.deepEqual(observed, [{ tenantId: TENANT_A, identitySubject: identity().subject }]);
});

test("API request adapter awaits a production tenant authority resolver", async () => {
  let resolved = false;
  const base = dependencies(repository(membership()));
  const request = await authorizeApiGatewayRequest(event(), "evidence:read", {
    ...base,
    tenants: {
      resolve: async (authority) => {
        await Promise.resolve();
        resolved = true;
        return directory().resolve(authority);
      },
    },
  });
  assert.equal(resolved, true);
  assert.equal(request.actor.tenantId, TENANT_A);
});

test("API request adapter rejects ambiguous authorization headers and unsafe targets", async () => {
  await assert.rejects(authorizeApiGatewayRequest(event({ headers: { Authorization: `Bearer ${TOKEN}`, authorization: `Bearer ${TOKEN}` } }), "evidence:read", dependencies(repository(membership()))), (error: unknown) => error instanceof TenantSecurityError && error.safeStatus === 400);
  await assert.rejects(authorizeApiGatewayRequest(event({ rawPath: "/v1/../tenant" }), "evidence:read", dependencies(repository(membership()))), (error: unknown) => error instanceof TenantSecurityError && error.safeStatus === 400);
  await assert.rejects(authorizeApiGatewayRequest(event({ rawPath: "/v1/%2e%2e/tenant" }), "evidence:read", dependencies(repository(membership()))), (error: unknown) => error instanceof TenantSecurityError && error.safeStatus === 400);
});

test("membership and RBAC deny cross-tenant rows and insufficient roles", async () => {
  await assert.rejects(authorizeVerifiedTenantIdentity({
    resolved: directory().resolve({ source: "direct", host: "acme.jsontechology.com" }),
    identity: identity(),
    memberships: repository(membership(TENANT_B)),
    permission: "evidence:read",
  }), (error: unknown) => error instanceof TenantSecurityError && error.code === "MEMBERSHIP_REQUIRED");
  await assert.rejects(authorizeApiGatewayRequest(event(), "evidence:collect", dependencies(repository(membership(TENANT_A, "auditor")))), (error: unknown) => error instanceof TenantSecurityError && error.code === "ROLE_FORBIDDEN");
});

test("authorization binds a verified Cognito client to the resolved tenant", async () => {
  let membershipLookups = 0;
  await assert.rejects(authorizeVerifiedTenantIdentity({
    resolved: directory().resolve({ source: "direct", host: "bravo.jsontechology.com" }),
    identity: identity(),
    memberships: { findActiveByIdentity: async () => { membershipLookups += 1; return membership(TENANT_B); } },
    permission: "evidence:read",
  }), (error: unknown) => error instanceof TenantSecurityError && error.code === "INVALID_PRINCIPAL" && error.safeStatus === 401);
  assert.equal(membershipLookups, 0);
});

test("authorization requires the exact OAuth scope before membership lookup", async () => {
  let membershipLookups = 0;
  const base = dependencies({
    async findActiveByIdentity() {
      membershipLookups += 1;
      return membership();
    },
  });
  await assert.rejects(authorizeApiGatewayRequest(event(), "audit:read", base), (error: unknown) =>
    error instanceof TenantSecurityError && error.code === "OAUTH_SCOPE_REQUIRED" && error.safeStatus === 403,
  );
  assert.equal(membershipLookups, 0);
});

test("direct authority ignores attacker-controlled Host forwarding headers", async () => {
  const request = await authorizeApiGatewayRequest(event({
    headers: {
      authorization: `Bearer ${TOKEN}`,
      host: "bravo.jsontechology.com",
      "x-forwarded-host": "bravo.jsontechology.com",
      forwarded: "host=bravo.jsontechology.com",
    },
  }), "evidence:read", dependencies(repository(membership())));
  assert.equal(request.actor.tenantId, TENANT_A);

  await assert.rejects(authorizeApiGatewayRequest(event({
    requestContext: { requestId: "request-host-tamper", domainName: "unknown.jsontechology.com", http: { method: "GET" } },
    headers: { authorization: `Bearer ${TOKEN}`, host: "acme.jsontechology.com" },
  }), "evidence:read", dependencies(repository(membership()))), (error: unknown) => error instanceof TenantSecurityError && error.code === "TENANT_NOT_FOUND");
});

test("trusted-edge mode ignores attacker host headers and requires its verifier", async () => {
  const request = await authorizeApiGatewayRequest(event({
    headers: { authorization: `Bearer ${TOKEN}`, "x-forwarded-host": "attacker.invalid", host: "attacker.invalid" },
    requestContext: { requestId: "request-edge-123", domainName: "private-origin.execute-api.us-east-1.amazonaws.com", http: { method: "GET" } },
  }), "evidence:read", dependencies(repository(membership()), { mode: "trusted_edge", verifier: { verify: async () => ({ viewerHost: "acme.jsontechology.com" }) } }));
  assert.equal(request.actor.tenantId, TENANT_A);

  await assert.rejects(authorizeApiGatewayRequest(event(), "evidence:read", dependencies(repository(membership()), {
    mode: "trusted_edge",
    verifier: { verify: async () => { throw new TenantSecurityError("UNTRUSTED_HOST_SOURCE", "Untrusted", 421); } },
  })), (error: unknown) => error instanceof TenantSecurityError && error.code === "UNTRUSTED_HOST_SOURCE");
});

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

test("HMAC edge verifier binds host, request, timestamp, nonce and prevents replay", async () => {
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const consumed = new Set<string>();
  const replayNonces: EdgeReplayNonceStore = { consume: async (nonce) => {
    if (consumed.has(nonce)) return false;
    consumed.add(nonce);
    return true;
  } };
  const baseEvent = event({ headers: {}, requestContext: { requestId: "request-edge-proof", domainName: "private-origin.example.com", http: { method: "GET" } } });
  const timestamp = String(NOW.getTime() / 1_000);
  const nonce = "nonce_1234567890abcdef";
  const canonical = edgeProofCanonicalValue({ viewerHost: "acme.jsontechology.com", requestId: baseEvent.requestContext.requestId, method: "GET", rawPath: baseEvent.rawPath, timestamp, nonce });
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical))));
  const signedEvent = { ...baseEvent, headers: {
    "x-scopeproof-edge-host": "acme.jsontechology.com",
    "x-scopeproof-edge-timestamp": timestamp,
    "x-scopeproof-edge-nonce": nonce,
    "x-scopeproof-edge-signature": `v1=${signature}`,
  } };
  const verifier = new HmacTrustedEdgeAuthorityVerifier({ secret, replayNonces, now: () => NOW });
  assert.equal((await verifier.verify(signedEvent)).viewerHost, "acme.jsontechology.com");
  await assert.rejects(verifier.verify(signedEvent), (error: unknown) => error instanceof TenantSecurityError && error.code === "UNTRUSTED_HOST_SOURCE");
  await assert.rejects(verifier.verify({ ...signedEvent, rawPath: "/v1/other" }), (error: unknown) => error instanceof TenantSecurityError && error.code === "UNTRUSTED_HOST_SOURCE");
});

test("RDS Data API membership adapter supports an explicit direct-table maintenance mode", async () => {
  const statements: Array<Record<string, unknown>> = [];
  let committed = 0;
  const executor: RdsDataApiExecutor = {
    beginTransaction: async () => ({ transactionId: "transaction-123456" }),
    executeStatement: async (input) => {
      statements.push(input as unknown as Record<string, unknown>);
      return input.formatRecordsAs === "JSON" ? { formattedRecords: JSON.stringify([{
        tenant_id: TENANT_A,
        identity_subject: identity().subject,
        membership_id: MEMBER_A,
        principal_id: USER_A,
        role: "reviewer",
      }]) } : {};
    },
    commitTransaction: async () => { committed += 1; return {}; },
    rollbackTransaction: async () => ({}),
  };
  const adapter = new RdsDataMembershipRepository({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:123456789012:cluster:scopeproof-prod",
    secretArn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:scopeproof/runtime-AbCd12",
    database: "scopeproof",
    lookupMode: "direct_tables",
  });
  const found = await adapter.findActiveByIdentity({ tenantId: TENANT_A, identitySubject: identity().subject });
  assert.equal(found?.membership.role, "reviewer");
  assert.equal(committed, 1);
  assert.equal(statements.length, 2);
  assert.match(String(statements[0].sql), /set_config/);
  assert.match(String(statements[1].sql), /CAST\(:tenant_id AS scopeproof\.tenant_identifier\)/);
  assert.doesNotMatch(String(statements[1].sql), new RegExp(identity().subject));
  assert.deepEqual((statements[1].parameters as Array<{ name: string }>).map((parameter) => parameter.name), ["tenant_id", "identity_subject"]);
});

test("RDS membership adapter securely defaults to an execute-only security-definer lookup", async () => {
  const statements: Array<Record<string, unknown>> = [];
  const executor: RdsDataApiExecutor = {
    beginTransaction: async () => ({ transactionId: "transaction-123456" }),
    executeStatement: async (input) => {
      statements.push(input as unknown as Record<string, unknown>);
      return input.formatRecordsAs === "JSON" ? { formattedRecords: JSON.stringify([{
        tenant_id: TENANT_A,
        identity_subject: identity().subject,
        membership_id: MEMBER_A,
        principal_id: USER_A,
        role: "admin",
      }]) } : {};
    },
    commitTransaction: async () => ({}),
    rollbackTransaction: async () => ({}),
  };
  const adapter = new RdsDataMembershipRepository({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:123456789012:cluster:scopeproof-prod",
    secretArn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:scopeproof/legal-api-AbCd12",
    database: "scopeproof",
  });

  assert.equal((await adapter.findActiveByIdentity({ tenantId: TENANT_A, identitySubject: identity().subject }))?.membership.role, "admin");
  assert.match(String(statements[1].sql), /scopeproof\.resolve_active_membership\(:identity_subject\)/);
  assert.doesNotMatch(String(statements[1].sql), /FROM scopeproof\.memberships/);
  assert.deepEqual((statements[1].parameters as Array<{ name: string }>).map((parameter) => parameter.name), ["identity_subject"]);
});

test("RDS Data API membership adapter rolls back malformed or duplicate results", async () => {
  let rollbacks = 0;
  const executor: RdsDataApiExecutor = {
    beginTransaction: async () => ({ transactionId: "transaction-123456" }),
    executeStatement: async (input) => input.formatRecordsAs === "JSON" ? { formattedRecords: "[{},{}]" } : {},
    commitTransaction: async () => ({}),
    rollbackTransaction: async () => { rollbacks += 1; return {}; },
  };
  const adapter = new RdsDataMembershipRepository({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:123456789012:cluster:scopeproof-prod",
    secretArn: "arn:aws:secretsmanager:us-east-1:123456789012:secret:scopeproof/runtime-AbCd12",
    database: "scopeproof",
  });
  await assert.rejects(adapter.findActiveByIdentity({ tenantId: TENANT_A, identitySubject: identity().subject }));
  assert.equal(rollbacks, 1);
});

test("safe problem responses preserve request IDs without disclosing internal errors", async () => {
  const response = safeProblemResponse(new Error("database password super-secret"), "request-problem-1");
  assert.equal(response.status, 500);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-request-id"), "request-problem-1");
  assert.doesNotMatch(await response.text(), /password|super-secret|database/i);

  const limited = safeProblemResponse(
    new TenantSecurityError("RATE_LIMITED", "internal quota details", 429),
    "request-problem-2",
  );
  assert.equal(limited.status, 429);
  assert.equal(limited.headers.get("retry-after"), "60");
  assert.doesNotMatch(await limited.text(), /internal quota details/);

  const handled = await handleAuthorizedApiRequest(event(), "evidence:read", dependencies(repository(membership())), async () => new Response("ok", { status: 200 }));
  assert.equal(handled.status, 200);
  assert.equal(handled.headers.get("x-request-id"), "request-12345678");
});
