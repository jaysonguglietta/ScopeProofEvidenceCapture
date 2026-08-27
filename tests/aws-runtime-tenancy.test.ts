import assert from "node:assert/strict";
import test from "node:test";

import {
  asMembershipId,
  asResourceId,
  asTenantId,
  asUserId,
  assertTenantJoin,
  assertTenantOwned,
  authorizeTenantActor,
  canonicalHostname,
  TenantDirectory,
  TenantSecurityError,
  tenantQueryGuard,
  validatePrincipal,
  type AuthenticatedPrincipal,
  type HostAuthority,
  type TenantActor,
  type TenantDomainRecord,
  type TenantMembership,
  type TenantRecord,
} from "../lib/aws-runtime/index.ts";

const TENANT_A = asTenantId(`ten_${"a".repeat(32)}`);
const TENANT_B = asTenantId(`ten_${"b".repeat(32)}`);
const USER_A = asUserId(`usr_${"1".repeat(32)}`);
const USER_B = asUserId(`usr_${"2".repeat(32)}`);
const MEMBER_A = asMembershipId(`mem_${"3".repeat(32)}`);
const RESOURCE_A = asResourceId(`evd_${"4".repeat(32)}`);
const RESOURCE_B = asResourceId(`evd_${"5".repeat(32)}`);
const NOW = new Date("2026-08-27T16:00:00.000Z");

function hasCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof TenantSecurityError);
    assert.equal(error.code, code);
    return true;
  };
}

function directory(): TenantDirectory {
  const tenants: TenantRecord[] = [
    { id: TENANT_A, slug: "acme", displayName: "Acme Compliance", status: "active" },
    { id: TENANT_B, slug: "bravo", displayName: "Bravo Security", status: "active" },
  ];
  const domains: TenantDomainRecord[] = [
    { tenantId: TENANT_A, hostname: canonicalHostname("acme.jsontechology.com"), status: "active", canonical: true },
    { tenantId: TENANT_B, hostname: canonicalHostname("bravo.jsontechology.com"), status: "active", canonical: true },
  ];
  return new TenantDirectory(tenants, domains);
}

function principal(userId = USER_A): AuthenticatedPrincipal {
  return validatePrincipal({
    signatureVerified: true,
    userId,
    subject: `cognito:${userId}`,
    issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
    audience: "scopeproof-web",
    tokenUse: "access",
    authenticatedAt: "2026-08-27T15:55:00.000Z",
    expiresAt: "2026-08-27T17:00:00.000Z",
  }, {
    issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
    audiences: new Set(["scopeproof-web"]),
    maximumAuthenticationAgeSeconds: 3_600,
  }, NOW);
}

function membership(role: TenantMembership["role"] = "admin"): TenantMembership {
  return { id: MEMBER_A, tenantId: TENANT_A, userId: USER_A, role, status: "active" };
}

function actor(role: TenantMembership["role"] = "admin"): TenantActor {
  return authorizeTenantActor({
    resolved: directory().resolve({ source: "direct", host: "acme.jsontechology.com" }),
    principal: principal(),
    membership: membership(role),
    permission: role === "auditor" ? "audit:read" : "evidence:read",
  });
}

test("tenant resolution accepts only an exact canonical hostname", () => {
  const tenants = directory();
  assert.equal(tenants.resolve({ source: "direct", host: "acme.jsontechology.com" }).tenant.id, TENANT_A);

  for (const host of [
    "ACME.jsontechology.com",
    "acme.jsontechology.com.",
    "acme.jsontechology.com:443",
    " acme.jsontechology.com",
    "acme.jsontechology.com ",
    "acme.jsontechology.com/evil",
    "acme.jsontechology.com@evil.test",
  ]) {
    assert.throws(() => tenants.resolve({ source: "direct", host }), hasCode("INVALID_HOST"));
  }

  assert.throws(
    () => tenants.resolve({ source: "direct", host: "acme.jsontechology.com.evil.test" }),
    hasCode("TENANT_NOT_FOUND"),
  );
  assert.throws(
    () => tenants.resolve({ source: "trusted_edge", viewerHost: "acme.jsontechology.com", edgeProofVerified: false } as unknown as HostAuthority),
    hasCode("UNTRUSTED_HOST_SOURCE"),
  );
});

test("tenant resolution fails closed for inactive domains and tenants", () => {
  const domainDisabled = new TenantDirectory(
    [{ id: TENANT_A, slug: "acme", displayName: "Acme", status: "active" }],
    [{ tenantId: TENANT_A, hostname: canonicalHostname("acme.jsontechology.com"), status: "disabled", canonical: true }],
  );
  assert.throws(() => domainDisabled.resolve({ source: "direct", host: "acme.jsontechology.com" }), hasCode("TENANT_NOT_FOUND"));

  const tenantSuspended = new TenantDirectory(
    [{ id: TENANT_A, slug: "acme", displayName: "Acme", status: "suspended" }],
    [{ tenantId: TENANT_A, hostname: canonicalHostname("acme.jsontechology.com"), status: "active", canonical: true }],
  );
  assert.throws(() => tenantSuspended.resolve({ source: "direct", host: "acme.jsontechology.com" }), hasCode("TENANT_INACTIVE"));
});

test("authentication validates issuer, audience, token use, age, and expiry", () => {
  assert.equal(principal().userId, USER_A);
  const base = {
    ...principal(),
    authenticatedAt: "2026-08-27T15:55:00.000Z",
    expiresAt: "2026-08-27T17:00:00.000Z",
  };
  const policy = {
    issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
    audiences: new Set(["scopeproof-web"]),
    maximumAuthenticationAgeSeconds: 3_600,
  };
  assert.throws(() => validatePrincipal({ ...base, signatureVerified: false } as unknown as AuthenticatedPrincipal, policy, NOW), hasCode("INVALID_PRINCIPAL"));
  assert.throws(() => validatePrincipal({ ...base, issuer: "https://attacker.invalid" }, policy, NOW), hasCode("INVALID_PRINCIPAL"));
  assert.throws(() => validatePrincipal({ ...base, audience: "another-client" }, policy, NOW), hasCode("INVALID_PRINCIPAL"));
  assert.throws(() => validatePrincipal({ ...base, tokenUse: "id" as "access" }, policy, NOW), hasCode("INVALID_PRINCIPAL"));
  assert.throws(() => validatePrincipal({ ...base, expiresAt: "2026-08-27T15:59:59.000Z" }, policy, NOW), hasCode("PRINCIPAL_EXPIRED"));
  assert.throws(() => validatePrincipal(base, { ...policy, maximumAuthenticationAgeSeconds: 0 }, NOW), hasCode("INVALID_PRINCIPAL"));
});

test("membership is bound to both the resolved tenant and authenticated user", () => {
  const resolved = directory().resolve({ source: "direct", host: "acme.jsontechology.com" });
  assert.equal(authorizeTenantActor({ resolved, principal: principal(), membership: membership(), permission: "tenant:manage" }).tenantId, TENANT_A);

  assert.throws(() => authorizeTenantActor({
    resolved,
    principal: principal(),
    membership: { ...membership(), tenantId: TENANT_B },
    permission: "evidence:read",
  }), hasCode("MEMBERSHIP_REQUIRED"));
  assert.throws(() => authorizeTenantActor({
    resolved,
    principal: principal(),
    membership: { ...membership(), userId: USER_B },
    permission: "evidence:read",
  }), hasCode("MEMBERSHIP_REQUIRED"));
  assert.throws(() => authorizeTenantActor({
    resolved,
    principal: principal(),
    membership: { ...membership(), status: "revoked" },
    permission: "evidence:read",
  }), hasCode("MEMBERSHIP_REQUIRED"));
});

test("roles deny unauthorized operations", () => {
  const resolved = directory().resolve({ source: "direct", host: "acme.jsontechology.com" });
  assert.throws(() => authorizeTenantActor({ resolved, principal: principal(), membership: membership("auditor"), permission: "evidence:collect" }), hasCode("ROLE_FORBIDDEN"));
  assert.throws(() => authorizeTenantActor({ resolved, principal: principal(), membership: membership("reviewer"), permission: "jobs:manage" }), hasCode("ROLE_FORBIDDEN"));
  assert.equal(authorizeTenantActor({ resolved, principal: principal(), membership: membership("collector"), permission: "evidence:collect" }).role, "collector");
  assert.throws(() => authorizeTenantActor({ resolved, principal: principal(), membership: membership("collector"), permission: "evidence:approve" }), hasCode("ROLE_FORBIDDEN"));
  assert.equal(authorizeTenantActor({ resolved, principal: principal(), membership: membership("compliance_lead"), permission: "jobs:manage" }).role, "compliance_lead");
});

test("tenant guards make cross-tenant IDOR indistinguishable from a missing resource", () => {
  const tenantActor = actor();
  assert.deepEqual(tenantQueryGuard(tenantActor), { tenantId: TENANT_A });
  assert.equal(assertTenantOwned(tenantActor, { tenantId: TENANT_A, id: RESOURCE_A }).id, RESOURCE_A);
  assert.throws(() => assertTenantOwned(tenantActor, { tenantId: TENANT_B, id: RESOURCE_B }), (error: unknown) => {
    assert.ok(error instanceof TenantSecurityError);
    assert.equal(error.code, "RESOURCE_NOT_FOUND");
    assert.equal(error.safeStatus, 404);
    return true;
  });
  assert.throws(() => assertTenantOwned(tenantActor, null), hasCode("RESOURCE_NOT_FOUND"));
  assert.throws(() => assertTenantJoin({ tenantId: TENANT_A, id: RESOURCE_A }, { tenantId: TENANT_B, id: RESOURCE_B }), hasCode("RESOURCE_NOT_FOUND"));
});

test("security identifiers have one canonical representation", () => {
  assert.throws(() => asTenantId(` ten_${"a".repeat(32)}`), hasCode("INVALID_IDENTIFIER"));
  assert.throws(() => asTenantId(`ten_${"A".repeat(32)}`), hasCode("INVALID_IDENTIFIER"));
  assert.throws(() => asResourceId(`evd_${"f".repeat(31)}../`), hasCode("INVALID_IDENTIFIER"));
});
