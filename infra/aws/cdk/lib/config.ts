export interface TenantDefinition {
  readonly id: string;
  readonly slug: string;
  readonly displayName: string;
  readonly retentionDays?: number;
  readonly retentionMode?: "GOVERNANCE" | "COMPLIANCE";
}

export interface TenantDatabaseIdentifiers {
  readonly databaseName: string;
  readonly ownerUsername: string;
  readonly runtimeUsername: string;
}

export function validateAlertEmail(value: unknown): string | undefined {
  const email = String(value ?? "").trim().toLowerCase();
  if (!email) return undefined;
  if (
    email.length > 254 ||
    !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(email)
  ) {
    throw new Error(`Invalid alertEmail: ${email}`);
  }
  return email;
}

export function validateMonthlyBudgetUsd(value: unknown): number {
  const budget = Number(value ?? 100);
  if (!Number.isFinite(budget) || budget < 10 || budget > 1_000_000) {
    throw new Error("monthlyBudgetUsd must be a number from 10 through 1000000.");
  }
  return Math.round(budget * 100) / 100;
}

const reservedSlugs = new Set([
  "admin",
  "api",
  "app",
  "auth",
  "downloads",
  "status",
  "support",
  "www",
]);

export function validateRootDomain(value: unknown): string {
  const domain = String(value ?? "").trim().toLowerCase().replace(/\.$/, "");
  if (
    domain.length < 4 ||
    domain.length > 64 ||
    !domain.includes(".") ||
    !/^(?=.{1,64}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)
  ) {
    throw new Error(`Invalid rootDomain: ${domain || "<empty>"}`);
  }
  return domain;
}

export function validateBranchName(value: unknown): string {
  const branch = String(value ?? "").trim().toLowerCase();
  if (!/^(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(branch)) {
    throw new Error(`Invalid branchName: ${branch || "<empty>"}. Use a DNS-safe 1-63 character label.`);
  }
  return branch;
}

export function validateTenant(value: unknown): TenantDefinition {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Each tenant context entry must be an object.");
  }
  const candidate = value as Record<string, unknown>;
  const id = String(candidate.id ?? "").trim().toLowerCase();
  const slug = String(candidate.slug ?? "").trim().toLowerCase();
  const displayName = String(candidate.displayName ?? "").trim();
  const retentionDays = Number(candidate.retentionDays ?? 365);
  const retentionMode = String(candidate.retentionMode ?? "GOVERNANCE").toUpperCase();

  if (!/^ten_[a-f0-9]{32}$/.test(id)) {
    throw new Error(`Tenant id ${id || "<empty>"} must match ten_ followed by 32 lowercase hexadecimal characters.`);
  }
  if (!/^(?=.{1,48}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(slug) || reservedSlugs.has(slug)) {
    throw new Error(`Tenant slug ${slug || "<empty>"} is invalid or reserved.`);
  }
  if (displayName.length < 2 || displayName.length > 120) {
    throw new Error(`Tenant ${id} requires a 2-120 character displayName.`);
  }
  if (!Number.isInteger(retentionDays) || retentionDays < 1 || retentionDays > 3_650) {
    throw new Error(`Tenant ${id} retentionDays must be an integer from 1 through 3650.`);
  }
  if (retentionMode !== "GOVERNANCE" && retentionMode !== "COMPLIANCE") {
    throw new Error(`Tenant ${id} retentionMode must be GOVERNANCE or COMPLIANCE.`);
  }

  return {
    id,
    slug,
    displayName,
    retentionDays,
    retentionMode,
  };
}

export function parseTenants(value: unknown): TenantDefinition[] {
  let candidate = value;
  if (typeof value === "string") {
    try {
      candidate = JSON.parse(value);
    } catch {
      throw new Error("The tenants context value must be a JSON array.");
    }
  }
  if (candidate === undefined || candidate === null) return [];
  if (!Array.isArray(candidate)) throw new Error("The tenants context value must be an array.");
  const tenants = candidate.map(validateTenant);
  const ids = new Set<string>();
  const slugs = new Set<string>();
  for (const tenant of tenants) {
    if (ids.has(tenant.id)) throw new Error(`Duplicate tenant id: ${tenant.id}`);
    if (slugs.has(tenant.slug)) throw new Error(`Duplicate tenant slug: ${tenant.slug}`);
    ids.add(tenant.id);
    slugs.add(tenant.slug);
  }
  return tenants;
}

export function tenantDatabaseIdentifiers(tenant: TenantDefinition): TenantDatabaseIdentifiers {
  if (!/^ten_[a-f0-9]{32}$/.test(tenant.id) || !/^(?=.{1,48}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(tenant.slug)) {
    throw new Error("Tenant database identifiers require a validated tenant.");
  }
  const normalizedSlug = tenant.slug.replaceAll("-", "_");
  const roleStem = normalizedSlug.slice(0, 11);
  const tenantSuffix = tenant.id.slice(4);
  const identifiers = {
    databaseName: `scopeproof_${normalizedSlug}`,
    ownerUsername: `scopeproof_${roleStem}_${tenantSuffix}_owner`,
    runtimeUsername: `tenant_${roleStem}_${tenantSuffix}_app_runtime`,
  };
  if (
    identifiers.databaseName.length > 63 ||
    identifiers.ownerUsername.length > 63 ||
    identifiers.runtimeUsername.length > 63
  ) {
    throw new Error("Derived tenant database identifier exceeds PostgreSQL's identifier limit.");
  }
  return Object.freeze(identifiers);
}
