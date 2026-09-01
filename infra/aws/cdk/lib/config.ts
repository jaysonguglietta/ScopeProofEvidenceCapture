export interface TenantDefinition {
  readonly id: string;
  readonly slug: string;
  readonly displayName: string;
  readonly retentionDays?: number;
  readonly retentionMode?: "GOVERNANCE" | "COMPLIANCE";
  /** Independent HTTPS scanner. Promotion fails closed when it is absent. */
  readonly dlpScannerEndpoint?: string;
  readonly dlpScannerSecretArn?: string;
  readonly dlpScannerSecretKmsKeyArn?: string;
  readonly dlpPolicyVersion?: string;
}

export interface TenantDatabaseIdentifiers {
  readonly auditSignerUsername: string;
  readonly controlUsername: string;
  readonly databaseName: string;
  readonly ingestUsername: string;
  readonly legalApiUsername: string;
  readonly ownerUsername: string;
  readonly readUsername: string;
  readonly runtimeUsername: string;
}

export interface TenantLambdaConcurrencyBudget {
  readonly apiAuditSigner: number;
  readonly tenantApi: number;
  readonly evidenceReadApi: number;
  readonly legalHoldApi: number;
  readonly legalHoldWorker: number;
  readonly evidencePromoter: number;
  readonly rejectedEvidenceReconciler: number;
  readonly uploadProjectionRepairer: number;
  readonly tenantProvisioner: number;
}

export const defaultTenantLambdaConcurrencyBudget: TenantLambdaConcurrencyBudget = Object.freeze({
  apiAuditSigner: 1,
  tenantApi: 5,
  evidenceReadApi: 5,
  legalHoldApi: 2,
  legalHoldWorker: 1,
  evidencePromoter: 2,
  rejectedEvidenceReconciler: 1,
  uploadProjectionRepairer: 1,
  tenantProvisioner: 5,
});

/**
 * Fail synthesis when a tenant can reserve an unexpectedly large share of the
 * regional Lambda account quota. The production ceiling is intentionally
 * equal to the reviewed default, so adding a function or increasing capacity
 * requires an explicit security/cost review instead of silently expanding it.
 */
export function validateTenantLambdaConcurrencyBudget(
  value: TenantLambdaConcurrencyBudget,
  environment: "dev" | "stage" | "prod",
): TenantLambdaConcurrencyBudget {
  const entries = Object.entries(value);
  if (entries.length !== Object.keys(defaultTenantLambdaConcurrencyBudget).length ||
      entries.some(([name]) => !(name in defaultTenantLambdaConcurrencyBudget))) {
    throw new Error("Tenant Lambda concurrency budget contains an unknown or missing function.");
  }
  for (const [name, amount] of entries) {
    if (!Number.isSafeInteger(amount) || amount < 1 || amount > 10) {
      throw new Error(`Tenant Lambda concurrency for ${name} must be an integer from 1 through 10.`);
    }
  }
  const total = entries.reduce((sum, [, amount]) => sum + amount, 0);
  const maximum = environment === "prod" ? 23 : 50;
  if (total > maximum) {
    throw new Error(`Tenant Lambda reserved concurrency ${total} exceeds the ${maximum} ${environment} budget.`);
  }
  return Object.freeze({ ...value });
}

export function validateTenantDeploymentSecurity(
  tenant: TenantDefinition,
  environment: "dev" | "stage" | "prod",
): TenantDefinition {
  if (environment === "prod" && tenant.retentionMode !== "COMPLIANCE") {
    throw new Error(`Production tenant ${tenant.id} requires COMPLIANCE evidence retention.`);
  }
  if (environment === "prod" && (!tenant.dlpScannerEndpoint || !tenant.dlpScannerSecretArn || !tenant.dlpScannerSecretKmsKeyArn || !tenant.dlpPolicyVersion)) {
    throw new Error(`Production tenant ${tenant.id} requires an exact server DLP endpoint, KMS-encrypted token secret, and policy version.`);
  }
  return tenant;
}

export function tenantEvidenceControlRoleName(tenant: TenantDefinition): string {
  if (!/^ten_[a-f0-9]{32}$/.test(tenant.id) || !/^(?=.{1,48}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(tenant.slug)) {
    throw new Error("Tenant evidence-control role names require a validated tenant.");
  }
  const directName = `sp-${tenant.slug}-evidence-control`;
  if (directName.length <= 64) return directName;

  // Preserve both a readable slug stem and an immutable tenant-id suffix so
  // long slugs with a shared prefix cannot collapse to the same IAM role name.
  const name = `sp-${tenant.slug.slice(0, 31)}-${tenant.id.slice(4, 16)}-evidence-control`;
  if (name.length > 64) throw new Error("Derived evidence-control IAM role name exceeds AWS's limit.");
  return name;
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
  const dlpScannerEndpoint = optionalHttpsEndpoint(candidate.dlpScannerEndpoint, "DLP scanner endpoint");
  const dlpScannerSecretArn = optionalRegionalArn(candidate.dlpScannerSecretArn, "secretsmanager", "DLP scanner token secret");
  const dlpScannerSecretKmsKeyArn = optionalRegionalArn(candidate.dlpScannerSecretKmsKeyArn, "kms", "DLP scanner token KMS key", "key/");
  const dlpPolicyVersion = optionalPolicyVersion(candidate.dlpPolicyVersion);

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
  const dlpFields = [dlpScannerEndpoint, dlpScannerSecretArn, dlpScannerSecretKmsKeyArn, dlpPolicyVersion].filter(Boolean).length;
  if (dlpFields > 0 && dlpFields < 4) {
    throw new Error(`Tenant ${id} must configure all server DLP fields together.`);
  }

  return {
    id,
    slug,
    displayName,
    retentionDays,
    retentionMode,
    ...(dlpScannerEndpoint ? { dlpScannerEndpoint, dlpScannerSecretArn, dlpScannerSecretKmsKeyArn, dlpPolicyVersion } : {}),
  };
}

function optionalHttpsEndpoint(value: unknown, label: string): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const raw = String(value);
  if (raw !== raw.trim() || raw.length > 500 || /\p{Cc}/u.test(raw)) throw new Error(`${label} is invalid.`);
  let parsed: URL;
  try { parsed = new URL(raw); } catch { throw new Error(`${label} is invalid.`); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash ||
      parsed.port || parsed.pathname === "/" || parsed.hostname === "localhost" ||
      /^(?:127\.|10\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(parsed.hostname)) {
    throw new Error(`${label} must be a public, clean HTTPS URL with an explicit path.`);
  }
  return parsed.toString();
}

function optionalRegionalArn(
  value: unknown,
  service: "kms" | "secretsmanager",
  label: string,
  resourcePrefix = "",
): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const arn = String(value);
  const escapedPrefix = resourcePrefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (arn !== arn.trim() || !new RegExp(`^arn:aws:${service}:[a-z]{2}-[a-z]+-[0-9]:[0-9]{12}:${escapedPrefix}[A-Za-z0-9/_+=.@:-]{1,512}$`).test(arn)) {
    throw new Error(`${label} ARN is invalid.`);
  }
  return arn;
}

function optionalPolicyVersion(value: unknown): string | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const policy = String(value);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(policy)) throw new Error("DLP policy version is invalid.");
  return policy;
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
    auditSignerUsername: `tenant_${normalizedSlug.slice(0, 10)}_${tenantSuffix}_audit_signer`,
    controlUsername: `tenant_${roleStem}_${tenantSuffix}_control`,
    databaseName: `scopeproof_${normalizedSlug}`,
    ingestUsername: `tenant_${roleStem}_${tenantSuffix}_ingest`,
    legalApiUsername: `tenant_${roleStem}_${tenantSuffix}_legal_api`,
    ownerUsername: `scopeproof_${roleStem}_${tenantSuffix}_owner`,
    readUsername: `tenant_${roleStem}_${tenantSuffix}_read`,
    runtimeUsername: `tenant_${roleStem}_${tenantSuffix}_app_runtime`,
  };
  if (
    identifiers.auditSignerUsername.length > 63 ||
    identifiers.controlUsername.length > 63 ||
    identifiers.databaseName.length > 63 ||
    identifiers.ingestUsername.length > 63 ||
    identifiers.legalApiUsername.length > 63 ||
    identifiers.ownerUsername.length > 63 ||
    identifiers.readUsername.length > 63 ||
    identifiers.runtimeUsername.length > 63
  ) {
    throw new Error("Derived tenant database identifier exceeds PostgreSQL's identifier limit.");
  }
  return Object.freeze(identifiers);
}
