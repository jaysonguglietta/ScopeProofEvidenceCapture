const accountPattern = /^\d{12}$/;
const regionPattern = /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/;
const vaultPattern = /^[A-Za-z0-9_.-]{2,50}$/;
const clusterArnPattern = /^arn:(aws|aws-us-gov|aws-cn):rds:([a-z]{2}(?:-gov)?-[a-z]+-\d):(\d{12}):cluster:([A-Za-z][A-Za-z0-9-]{0,62})$/;

function bounded(value, label, pattern) {
  const text = String(value ?? "");
  if (!pattern.test(text)) throw new Error(`Invalid ${label}.`);
  return text;
}

export function parseAuroraFreshnessConfig(env) {
  const accountId = bounded(env.AWS_ACCOUNT_ID_EXPECTED, "AWS account", accountPattern);
  const primaryRegion = bounded(env.AWS_REGION_EXPECTED, "primary region", regionPattern);
  const recoveryRegion = bounded(env.RECOVERY_REGION_EXPECTED, "recovery region", regionPattern);
  const primaryVaultName = bounded(env.PRIMARY_VAULT_NAME, "primary vault name", vaultPattern);
  const recoveryVaultName = bounded(env.RECOVERY_VAULT_NAME, "recovery vault name", vaultPattern);
  const databaseClusterArn = bounded(env.DATABASE_CLUSTER_ARN, "database cluster ARN", clusterArnPattern);
  const environment = bounded(env.DEPLOYMENT_ENVIRONMENT, "deployment environment", /^(dev|stage|prod)$/);
  const cluster = databaseClusterArn.match(clusterArnPattern);
  if (
    primaryRegion === recoveryRegion ||
    primaryVaultName === recoveryVaultName ||
    !cluster ||
    cluster[2] !== primaryRegion ||
    cluster[3] !== accountId
  ) {
    throw new Error("Aurora recovery freshness resources are not safely bound.");
  }
  return Object.freeze({
    accountId,
    databaseClusterArn,
    environment,
    primaryRegion,
    primaryVaultName,
    recoveryRegion,
    recoveryVaultName,
  });
}

export function latestCompletedRecoveryPointAge(recoveryPoints, config, nowIso) {
  if (!Array.isArray(recoveryPoints) || recoveryPoints.length > 1_000) {
    throw new Error("AWS Backup returned an invalid recovery-point set.");
  }
  const now = new Date(nowIso);
  if (!Number.isFinite(now.getTime()) || now.toISOString() !== nowIso) {
    throw new Error("Aurora recovery freshness time is invalid.");
  }
  let latest;
  for (const point of recoveryPoints) {
    if (
      !point || typeof point !== "object" || Array.isArray(point) ||
      point.ResourceArn !== config.databaseClusterArn ||
      point.ResourceType !== "Aurora" ||
      point.Status !== "COMPLETED"
    ) continue;
    const creationDate = point.CreationDate;
    if (!(creationDate instanceof Date) || !Number.isFinite(creationDate.getTime())) {
      throw new Error("AWS Backup returned an invalid recovery-point time.");
    }
    if (creationDate.getTime() > now.getTime() + 5 * 60_000) {
      throw new Error("AWS Backup returned a future recovery point.");
    }
    if (!latest || creationDate > latest) latest = creationDate;
  }
  if (!latest) throw new Error("No completed Aurora recovery point was found.");
  return Object.freeze({
    ageSeconds: Math.max(0, (now.getTime() - latest.getTime()) / 1_000),
    createdAt: latest.toISOString(),
  });
}
