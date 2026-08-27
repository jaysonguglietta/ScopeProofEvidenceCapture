import {
  asMembershipId,
  asTenantId,
  asUserId,
  assertBoundedText,
  canonicalInstant,
  containsAsciiControlCharacters,
  type CanonicalHostname,
  type MembershipId,
  type ResourceId,
  type TenantId,
  TenantSecurityError,
  type UserId,
} from "./contracts.ts";

export type TenantStatus = "provisioning" | "active" | "suspended" | "closed";
export type TenantDomainStatus = "pending" | "active" | "disabled";

export interface TenantRecord {
  id: TenantId;
  slug: string;
  displayName: string;
  /** Exact Cognito app client authorized for this tenant. */
  appClientId: string;
  status: TenantStatus;
}

export interface TenantDomainRecord {
  tenantId: TenantId;
  hostname: CanonicalHostname;
  status: TenantDomainStatus;
  canonical: boolean;
}

export type HostAuthority =
  | { source: "direct"; host: string }
  | { source: "trusted_edge"; viewerHost: string; edgeProofVerified: true };

export interface ResolvedTenantAuthority {
  readonly tenant: TenantRecord;
  readonly domain: TenantDomainRecord;
}

/**
 * Resolves the one authoritative tenant associated with a request hostname.
 *
 * In-memory callers can return synchronously while production adapters can
 * perform a strongly consistent registry read. Callers must always await the
 * result and must not infer a tenant from an unverified Host header.
 */
export interface TenantAuthorityResolver {
  resolve(authority: HostAuthority): ResolvedTenantAuthority | Promise<ResolvedTenantAuthority>;
}

const dnsLabelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const cognitoClientIdPattern = /^[A-Za-z0-9_.:+/=_~-]{3,128}$/;

export function assertTenantCognitoClientId(value: string): string {
  const exact = String(value || "");
  if (!cognitoClientIdPattern.test(exact)) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Tenant Cognito client identifier is invalid.", 500);
  }
  return exact;
}

export function canonicalHostname(value: string): CanonicalHostname {
  const raw = String(value || "");
  if (!raw || raw !== raw.trim() || raw.length > 253 || raw !== raw.toLowerCase() || raw.endsWith(".") || raw.includes(":") || raw.includes("/") || raw.includes("@") || raw.includes("%") || /\s/.test(raw) || containsAsciiControlCharacters(raw)) {
    throw new TenantSecurityError("INVALID_HOST", "Request hostname is invalid.", 421);
  }
  const labels = raw.split(".");
  if (labels.length < 2 || labels.some((label) => !dnsLabelPattern.test(label)) || /^\d+(?:\.\d+){3}$/.test(raw)) {
    throw new TenantSecurityError("INVALID_HOST", "Request hostname is invalid.", 421);
  }
  return raw as CanonicalHostname;
}

export function canonicalAuthorityHostname(authority: HostAuthority): CanonicalHostname {
  if (authority.source === "trusted_edge") {
    if (authority.edgeProofVerified !== true) {
      throw new TenantSecurityError("UNTRUSTED_HOST_SOURCE", "Tenant hostname did not come from the trusted edge.", 421);
    }
    return canonicalHostname(authority.viewerHost);
  }
  return canonicalHostname(authority.host);
}

export class TenantDirectory implements TenantAuthorityResolver {
  readonly #tenants: ReadonlyMap<TenantId, TenantRecord>;
  readonly #domains: ReadonlyMap<CanonicalHostname, TenantDomainRecord>;

  constructor(tenants: readonly TenantRecord[], domains: readonly TenantDomainRecord[]) {
    const tenantMap = new Map<TenantId, TenantRecord>();
    for (const tenant of tenants) {
      const id = asTenantId(tenant.id);
      if (tenantMap.has(id)) throw new TenantSecurityError("INVALID_IDENTIFIER", "Tenant directory contains a duplicate tenant.");
      if (!dnsLabelPattern.test(tenant.slug) || tenant.slug.length > 63) throw new TenantSecurityError("INVALID_IDENTIFIER", "Tenant slug is invalid.");
      tenantMap.set(id, Object.freeze({
        ...tenant,
        id,
        appClientId: assertTenantCognitoClientId(tenant.appClientId),
        displayName: assertBoundedText(tenant.displayName, "Tenant name", 1, 160),
      }));
    }
    const domainMap = new Map<CanonicalHostname, TenantDomainRecord>();
    for (const domain of domains) {
      const hostname = canonicalHostname(domain.hostname);
      const tenantId = asTenantId(domain.tenantId);
      if (!tenantMap.has(tenantId)) throw new TenantSecurityError("INVALID_IDENTIFIER", "Tenant domain references an unknown tenant.");
      if (domainMap.has(hostname)) throw new TenantSecurityError("INVALID_HOST", "Tenant hostname is assigned more than once.");
      domainMap.set(hostname, Object.freeze({ ...domain, hostname, tenantId }));
    }
    this.#tenants = tenantMap;
    this.#domains = domainMap;
  }

  resolve(authority: HostAuthority): ResolvedTenantAuthority {
    const hostname = canonicalAuthorityHostname(authority);
    const domain = this.#domains.get(hostname);
    if (!domain || domain.status !== "active") {
      throw new TenantSecurityError("TENANT_NOT_FOUND", "Tenant not found.", 404);
    }
    const tenant = this.#tenants.get(domain.tenantId);
    if (!tenant) throw new TenantSecurityError("TENANT_NOT_FOUND", "Tenant not found.", 404);
    if (tenant.status !== "active") throw new TenantSecurityError("TENANT_INACTIVE", "Tenant is unavailable.", 403);
    return { tenant, domain };
  }
}

export type TenantRole = "admin" | "compliance_lead" | "reviewer" | "auditor" | "collector";
export type TenantPermission =
  | "tenant:manage"
  | "evidence:read"
  | "evidence:collect"
  | "evidence:approve"
  | "evidence:export"
  | "device:manage"
  | "integration:manage"
  | "retention:manage"
  | "audit:read"
  | "jobs:manage";

export interface AuthenticatedPrincipal {
  /** Set only by the adapter after cryptographic JWT signature verification. */
  signatureVerified: true;
  userId: UserId;
  subject: string;
  issuer: string;
  audience: string;
  tokenUse: "access";
  authenticatedAt: string;
  expiresAt: string;
}

export interface PrincipalPolicy {
  issuer: string;
  audiences: ReadonlySet<string>;
  maximumAuthenticationAgeSeconds: number;
}

export interface TenantMembership {
  id: MembershipId;
  tenantId: TenantId;
  userId: UserId;
  role: TenantRole;
  status: "invited" | "active" | "suspended" | "revoked";
}

export interface TenantActor {
  tenantId: TenantId;
  tenantHostname: CanonicalHostname;
  userId: UserId;
  membershipId: MembershipId;
  subject: string;
  role: TenantRole;
}

const rolePermissions: Record<TenantRole, ReadonlySet<TenantPermission>> = {
  auditor: new Set(["evidence:read", "audit:read"]),
  collector: new Set(["evidence:read", "evidence:collect"]),
  reviewer: new Set(["evidence:read", "evidence:approve", "evidence:export", "audit:read"]),
  compliance_lead: new Set(["evidence:read", "evidence:collect", "evidence:export", "device:manage", "integration:manage", "audit:read", "jobs:manage"]),
  admin: new Set(["tenant:manage", "evidence:read", "evidence:collect", "evidence:approve", "evidence:export", "device:manage", "integration:manage", "retention:manage", "audit:read", "jobs:manage"]),
};

export function assertActorPermission(actor: Pick<TenantActor, "role">, permission: TenantPermission): void {
  if (!rolePermissions[actor.role]?.has(permission)) {
    throw new TenantSecurityError("ROLE_FORBIDDEN", "The tenant role does not allow this operation.", 403);
  }
}

export function validatePrincipal(principal: AuthenticatedPrincipal, policy: PrincipalPolicy, now: Date): AuthenticatedPrincipal {
  if (!Number.isSafeInteger(policy.maximumAuthenticationAgeSeconds) || policy.maximumAuthenticationAgeSeconds < 60 || policy.maximumAuthenticationAgeSeconds > 86_400) {
    throw new TenantSecurityError("INVALID_PRINCIPAL", "Authentication policy is invalid.", 500);
  }
  const userId = asUserId(principal.userId);
  const subject = assertBoundedText(principal.subject, "Identity subject", 3, 200);
  const issuer = assertBoundedText(principal.issuer, "Identity issuer", 8, 500);
  const audience = assertBoundedText(principal.audience, "Identity audience", 3, 200);
  if (principal.signatureVerified !== true || principal.tokenUse !== "access" || issuer !== policy.issuer || !policy.audiences.has(audience)) {
    throw new TenantSecurityError("INVALID_PRINCIPAL", "Authentication token is not valid for this application.", 401);
  }
  const authenticatedAt = Date.parse(canonicalInstant(principal.authenticatedAt, "Authentication timestamp"));
  const expiresAt = Date.parse(canonicalInstant(principal.expiresAt, "Token expiry"));
  const current = now.getTime();
  if (expiresAt <= current || authenticatedAt > current + 60_000 || current - authenticatedAt > policy.maximumAuthenticationAgeSeconds * 1_000) {
    throw new TenantSecurityError("PRINCIPAL_EXPIRED", "Authentication has expired.", 401);
  }
  return { ...principal, userId, subject, issuer, audience, authenticatedAt: new Date(authenticatedAt).toISOString(), expiresAt: new Date(expiresAt).toISOString() };
}

export function authorizeTenantActor(input: {
  resolved: ResolvedTenantAuthority;
  principal: AuthenticatedPrincipal;
  membership: TenantMembership | null;
  permission: TenantPermission;
}): TenantActor {
  const { resolved, principal, membership, permission } = input;
  if (!membership || membership.status !== "active") {
    throw new TenantSecurityError("MEMBERSHIP_REQUIRED", "Active tenant membership is required.", 403);
  }
  const membershipTenantId = asTenantId(membership.tenantId);
  const membershipUserId = asUserId(membership.userId);
  if (membershipTenantId !== resolved.tenant.id || membershipUserId !== principal.userId) {
    throw new TenantSecurityError("MEMBERSHIP_REQUIRED", "Active tenant membership is required.", 403);
  }
  const membershipId = asMembershipId(membership.id);
  assertActorPermission(membership, permission);
  return Object.freeze({
    tenantId: resolved.tenant.id,
    tenantHostname: resolved.domain.hostname,
    userId: principal.userId,
    membershipId,
    subject: principal.subject,
    role: membership.role,
  });
}

export interface TenantOwnedRow {
  tenantId: TenantId;
  id: ResourceId | string;
}

export function tenantQueryGuard(actor: Pick<TenantActor, "tenantId">): Readonly<{ tenantId: TenantId }> {
  return Object.freeze({ tenantId: asTenantId(actor.tenantId) });
}

export function assertTenantOwned<T extends TenantOwnedRow>(actor: Pick<TenantActor, "tenantId">, row: T | null | undefined): T {
  if (!row || row.tenantId !== actor.tenantId) {
    // Deliberately indistinguishable from an absent identifier to prevent IDOR enumeration.
    throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Resource not found.", 404);
  }
  return row;
}

export function assertTenantJoin(left: TenantOwnedRow, right: TenantOwnedRow): void {
  if (left.tenantId !== right.tenantId) {
    throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Resource not found.", 404);
  }
}
