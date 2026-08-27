import { BackupClient, ListRecoveryPointsByBackupVaultCommand } from "@aws-sdk/client-backup";
import { CloudWatchClient, PutMetricDataCommand } from "@aws-sdk/client-cloudwatch";
import {
  latestCompletedRecoveryPointAge,
  parseAuroraFreshnessConfig,
} from "./freshness-contract.mjs";

const config = parseAuroraFreshnessConfig(process.env);
const primaryBackup = new BackupClient({ region: config.primaryRegion });
const recoveryBackup = new BackupClient({ region: config.recoveryRegion });
const cloudwatch = new CloudWatchClient({ region: config.primaryRegion });

export async function handler() {
  const now = new Date();
  const createdAfter = new Date(now.getTime() - 7 * 86_400_000);
  const [primaryPoints, recoveryPoints] = await Promise.all([
    listBounded(primaryBackup, config.primaryVaultName, createdAfter),
    listBounded(recoveryBackup, config.recoveryVaultName, createdAfter),
  ]);
  const primary = latestCompletedRecoveryPointAge(primaryPoints, config, now.toISOString());
  const recovery = latestCompletedRecoveryPointAge(recoveryPoints, config, now.toISOString());
  const timestamp = new Date();
  await cloudwatch.send(new PutMetricDataCommand({
    MetricData: [
      metric("PRIMARY", primary.ageSeconds, timestamp),
      metric("RECOVERY", recovery.ageSeconds, timestamp),
      successMetric("PRIMARY", timestamp),
      successMetric("RECOVERY", timestamp),
    ],
    Namespace: "Scopeproof/Recovery",
  }));
  return Object.freeze({
    primaryCreatedAt: primary.createdAt,
    recoveryCreatedAt: recovery.createdAt,
    status: "CURRENT",
  });
}

async function listBounded(client, vaultName, createdAfter) {
  const points = [];
  let nextToken;
  for (let page = 0; page < 10; page += 1) {
    const response = await client.send(new ListRecoveryPointsByBackupVaultCommand({
      BackupVaultAccountId: config.accountId,
      BackupVaultName: vaultName,
      ByCreatedAfter: createdAfter,
      ByResourceArn: config.databaseClusterArn,
      ByResourceType: "Aurora",
      MaxResults: 100,
      NextToken: nextToken,
    }));
    points.push(...(response.RecoveryPoints ?? []));
    nextToken = response.NextToken;
    if (nextToken === undefined) return points;
    if (typeof nextToken !== "string" || nextToken.length < 1 || nextToken.length > 1_024) {
      throw new Error("AWS Backup returned an invalid pagination token.");
    }
  }
  throw new Error("AWS Backup recovery-point listing exceeded its safety bound.");
}

function dimensions(vaultRole) {
  return [
    { Name: "Environment", Value: config.environment },
    { Name: "VaultRole", Value: vaultRole },
  ];
}

function metric(vaultRole, value, timestamp) {
  return {
    Dimensions: dimensions(vaultRole),
    MetricName: "AuroraRecoveryPointFreshnessSeconds",
    Timestamp: timestamp,
    Unit: "Seconds",
    Value: value,
  };
}

function successMetric(vaultRole, timestamp) {
  return {
    Dimensions: dimensions(vaultRole),
    MetricName: "AuroraRecoveryPointSuccess",
    Timestamp: timestamp,
    Unit: "Count",
    Value: 1,
  };
}
