import { TenantDefinition } from "./config";

export type DeploymentEnvironment = "dev" | "stage" | "prod";
export type RecoveryMode = "disabled" | "bootstrap" | "enabled";
export type VaultLockMode = "GOVERNANCE" | "COMPLIANCE";

export interface EvidenceRecoveryDestination {
  readonly tenantId: string;
  readonly bucketName: string;
  readonly kmsKeyArn: string;
}

export interface RecoveryConfiguration {
  readonly deploymentEnvironment: DeploymentEnvironment;
  readonly mode: RecoveryMode;
  readonly region?: string;
  readonly vaultLockMode: VaultLockMode;
  readonly vaultLockChangeableDays?: number;
  readonly auroraLocalRetentionDays: number;
  readonly auroraCopyRetentionDays: number;
  readonly s3ReplicationTimeControl: boolean;
  readonly backupVaultName?: string;
  readonly backupVaultArn?: string;
  readonly backupVaultKeyArn?: string;
  readonly evidenceDestinations: ReadonlyMap<string, EvidenceRecoveryDestination>;
}

export interface RecoveryConfigurationOptions {
  readonly account?: string;
  readonly deploymentEnvironment: DeploymentEnvironment;
  readonly primaryRegion: string;
  readonly tenants: readonly TenantDefinition[];
}

export function validateDeploymentEnvironment(value: unknown): DeploymentEnvironment {
  const environment = String(value ?? "dev").trim().toLowerCase();
  if (!new Set(["dev", "stage", "prod"]).has(environment)) {
    throw new Error("deploymentEnvironment must be dev, stage, or prod.");
  }
  return environment as DeploymentEnvironment;
}

export function recoveryEvidenceBucketName(
  account: string,
  region: string,
  tenantId: string,
): string {
  validateAccount(account);
  validateRecoveryRegion(region);
  if (!/^ten_[a-f0-9]{32}$/.test(tenantId)) throw new Error("Invalid tenant id for recovery bucket.");
  return `sp-r-${account}-${bucketRegionSegment(region)}-${tenantId.slice(4)}`;
}

export function primaryEvidenceBucketName(
  account: string,
  region: string,
  tenantId: string,
): string {
  validateAccount(account);
  validateRecoveryRegion(region);
  if (!/^ten_[a-f0-9]{32}$/.test(tenantId)) throw new Error("Invalid tenant id for evidence bucket.");
  return `sp-e-${account}-${bucketRegionSegment(region)}-${tenantId.slice(4)}`;
}

export function recoveryBackupVaultName(environment: DeploymentEnvironment): string {
  return `scopeproof-${environment}-recovery`;
}

export function recoveryBackupRoleName(environment: DeploymentEnvironment): string {
  return `sp-${environment}-aurora-backup`;
}

export function recoveryEvidenceReplicationRoleName(tenant: TenantDefinition): string {
  const suffix = "-evidence-replication";
  const readable = `sp-${tenant.slug}${suffix}`;
  if (readable.length <= 64) return readable;
  return `sp-${tenant.slug.slice(0, 27)}-${tenant.id.slice(4, 16)}${suffix}`;
}

export function recoveryEvidenceBatchRoleName(tenant: TenantDefinition): string {
  const suffix = "-evidence-batch";
  const readable = `sp-${tenant.slug}${suffix}`;
  if (readable.length <= 64) return readable;
  return `sp-${tenant.slug.slice(0, 33)}-${tenant.id.slice(4, 16)}${suffix}`;
}

export function parseRecoveryConfiguration(
  value: unknown,
  options: RecoveryConfigurationOptions,
): RecoveryConfiguration {
  let candidate = value;
  if (typeof value === "string") {
    try {
      candidate = JSON.parse(value);
    } catch {
      throw new Error("The recovery context value must be a JSON object.");
    }
  }
  if (candidate === undefined || candidate === null) candidate = {};
  if (typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new Error("The recovery context value must be an object.");
  }
  const input = candidate as Record<string, unknown>;
  rejectUnknownKeys(input, new Set([
    "mode",
    "region",
    "vaultLockMode",
    "vaultLockChangeableDays",
    "auroraLocalRetentionDays",
    "auroraCopyRetentionDays",
    "s3ReplicationTimeControl",
    "backupVaultKeyArn",
    "evidenceDestinations",
  ]));

  const mode = String(input.mode ?? "disabled").trim().toLowerCase() as RecoveryMode;
  if (!new Set<RecoveryMode>(["disabled", "bootstrap", "enabled"]).has(mode)) {
    throw new Error("recovery.mode must be disabled, bootstrap, or enabled.");
  }
  const vaultLockMode = String(
    input.vaultLockMode ?? (options.deploymentEnvironment === "prod" ? "COMPLIANCE" : "GOVERNANCE"),
  ).trim().toUpperCase() as VaultLockMode;
  if (!new Set<VaultLockMode>(["GOVERNANCE", "COMPLIANCE"]).has(vaultLockMode)) {
    throw new Error("recovery.vaultLockMode must be GOVERNANCE or COMPLIANCE.");
  }
  const auroraLocalRetentionDays = integerInRange(
    input.auroraLocalRetentionDays ?? 35,
    "recovery.auroraLocalRetentionDays",
    7,
    365,
  );
  const auroraCopyRetentionDays = integerInRange(
    input.auroraCopyRetentionDays ?? 365,
    "recovery.auroraCopyRetentionDays",
    35,
    3_650,
  );
  if (auroraCopyRetentionDays < auroraLocalRetentionDays) {
    throw new Error("recovery.auroraCopyRetentionDays cannot be shorter than local retention.");
  }
  const s3ReplicationTimeControl = booleanValue(
    input.s3ReplicationTimeControl,
    options.deploymentEnvironment === "prod",
    "recovery.s3ReplicationTimeControl",
  );
  let vaultLockChangeableDays: number | undefined;
  if (vaultLockMode === "COMPLIANCE") {
    vaultLockChangeableDays = integerInRange(
      input.vaultLockChangeableDays ?? 7,
      "recovery.vaultLockChangeableDays",
      3,
      30,
    );
  } else if (input.vaultLockChangeableDays !== undefined) {
    throw new Error("recovery.vaultLockChangeableDays is valid only with COMPLIANCE Vault Lock.");
  }

  if (mode === "disabled") {
    if (options.deploymentEnvironment === "prod") {
      throw new Error("Production requires recovery.mode=bootstrap or recovery.mode=enabled.");
    }
    return Object.freeze({
      deploymentEnvironment: options.deploymentEnvironment,
      mode,
      vaultLockMode,
      vaultLockChangeableDays,
      auroraLocalRetentionDays,
      auroraCopyRetentionDays,
      s3ReplicationTimeControl,
      evidenceDestinations: new Map(),
    });
  }

  const account = String(options.account ?? "").trim();
  validateAccount(account);
  const region = String(input.region ?? "").trim().toLowerCase();
  validateRecoveryRegion(region);
  if (region === options.primaryRegion) {
    throw new Error("The recovery region must differ from the primary region.");
  }
  if (options.deploymentEnvironment === "prod") {
    if (vaultLockMode !== "COMPLIANCE" || (vaultLockChangeableDays ?? 0) < 7) {
      throw new Error("Production requires COMPLIANCE Vault Lock with a 7-30 day cooling-off period.");
    }
    if (auroraCopyRetentionDays < 365) {
      throw new Error("Production cross-region Aurora copies require at least 365 days of retention.");
    }
    if (!s3ReplicationTimeControl) {
      throw new Error("Production requires S3 Replication Time Control.");
    }
  }

  const vaultName = recoveryBackupVaultName(options.deploymentEnvironment);
  const backupVaultArn = `arn:aws:backup:${region}:${account}:backup-vault:${vaultName}`;
  const evidenceDestinations = parseEvidenceDestinations(
    input.evidenceDestinations,
    account,
    region,
    options.tenants,
    mode,
  );
  let backupVaultKeyArn: string | undefined;
  if (mode === "enabled") {
    backupVaultKeyArn = validateKmsKeyArn(input.backupVaultKeyArn, account, region, "recovery.backupVaultKeyArn");
  } else {
    if (input.backupVaultKeyArn !== undefined || evidenceDestinations.size > 0) {
      throw new Error("Bootstrap mode must not include generated recovery key ARNs or destinations.");
    }
  }

  return Object.freeze({
    deploymentEnvironment: options.deploymentEnvironment,
    mode,
    region,
    vaultLockMode,
    vaultLockChangeableDays,
    auroraLocalRetentionDays,
    auroraCopyRetentionDays,
    s3ReplicationTimeControl,
    backupVaultName: vaultName,
    backupVaultArn,
    backupVaultKeyArn,
    evidenceDestinations,
  });
}

function parseEvidenceDestinations(
  value: unknown,
  account: string,
  region: string,
  tenants: readonly TenantDefinition[],
  mode: RecoveryMode,
): ReadonlyMap<string, EvidenceRecoveryDestination> {
  if (value === undefined && mode === "bootstrap") return new Map();
  if (!Array.isArray(value)) {
    if (mode === "enabled" && tenants.length === 0) return new Map();
    throw new Error("recovery.evidenceDestinations must be an array.");
  }
  const tenantIds = new Set(tenants.map((tenant) => tenant.id));
  const destinations = new Map<string, EvidenceRecoveryDestination>();
  for (const raw of value) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error("Each recovery evidence destination must be an object.");
    }
    const item = raw as Record<string, unknown>;
    rejectUnknownKeys(item, new Set(["tenantId", "bucketName", "kmsKeyArn"]));
    const tenantId = String(item.tenantId ?? "").trim().toLowerCase();
    if (!tenantIds.has(tenantId) || destinations.has(tenantId)) {
      throw new Error(`Recovery destination tenant ${tenantId || "<empty>"} is unknown or duplicated.`);
    }
    const bucketName = String(item.bucketName ?? "").trim().toLowerCase();
    const expectedBucketName = recoveryEvidenceBucketName(account, region, tenantId);
    if (bucketName !== expectedBucketName) {
      throw new Error(`Recovery bucket for ${tenantId} must be ${expectedBucketName}.`);
    }
    destinations.set(tenantId, Object.freeze({
      tenantId,
      bucketName,
      kmsKeyArn: validateKmsKeyArn(item.kmsKeyArn, account, region, `recovery key for ${tenantId}`),
    }));
  }
  if (mode === "enabled" && destinations.size !== tenants.length) {
    throw new Error("Enabled recovery requires exactly one destination for every configured tenant.");
  }
  return destinations;
}

function validateKmsKeyArn(value: unknown, account: string, region: string, label: string): string {
  const arn = String(value ?? "").trim();
  const escapedRegion = escapeRegex(region);
  const escapedAccount = escapeRegex(account);
  const keyId = "(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|mrk-[0-9a-f]{32})";
  if (!new RegExp(`^arn:aws:kms:${escapedRegion}:${escapedAccount}:key/${keyId}$`).test(arn)) {
    throw new Error(`${label} must be a customer-managed KMS key ARN in the recovery account and region.`);
  }
  return arn;
}

function validateAccount(value: string): void {
  if (!/^\d{12}$/.test(value)) throw new Error("Recovery configuration requires an explicit 12-digit AWS account.");
}

function validateRecoveryRegion(value: string): void {
  if (
    !/^[a-z]{2}-[a-z]+-\d$/.test(value) ||
    value.startsWith("cn-") ||
    value.startsWith("us-gov-")
  ) {
    throw new Error("Recovery requires a commercial AWS region in the aws partition.");
  }
}

function bucketRegionSegment(region: string): string {
  return region.replaceAll("-", "");
}

function integerInRange(value: unknown, label: string, minimum: number, maximum: number): number {
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${label} must be an integer from ${minimum} through ${maximum}.`);
  }
  return parsed;
}

function booleanValue(value: unknown, fallback: boolean, label: string): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") throw new Error(`${label} must be a boolean.`);
  return value;
}

function rejectUnknownKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>): void {
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) throw new Error(`Unknown recovery configuration field: ${unknown.sort()[0]}`);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
