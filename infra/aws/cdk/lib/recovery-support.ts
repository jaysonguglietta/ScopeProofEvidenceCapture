import {
  ArnFormat,
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
} from "aws-cdk-lib";
import * as path from "node:path";
import * as backup from "aws-cdk-lib/aws-backup";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as events from "aws-cdk-lib/aws-events";
import * as eventTargets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaNodejs from "aws-cdk-lib/aws-lambda-nodejs";
import * as logs from "aws-cdk-lib/aws-logs";
import * as rds from "aws-cdk-lib/aws-rds";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3Notifications from "aws-cdk-lib/aws-s3-notifications";
import * as sns from "aws-cdk-lib/aws-sns";
import { TenantDefinition } from "./config";
import {
  EvidenceRecoveryDestination,
  primaryEvidenceBucketName,
  RecoveryConfiguration,
  recoveryBackupRoleName,
  recoveryEvidenceBatchRoleName,
  recoveryEvidenceReplicationRoleName,
} from "./recovery-config";

export interface AuroraRecoveryProps {
  readonly configuration: RecoveryConfiguration;
  readonly databaseCluster: rds.DatabaseCluster;
  readonly databaseKey: kms.Key;
  readonly operationsTopic: sns.Topic;
}

export function configureAuroraRecovery(scope: Stack, props: AuroraRecoveryProps): void {
  const { configuration } = props;
  if (
    configuration.mode !== "enabled" ||
    !configuration.backupVaultArn ||
    !configuration.backupVaultKeyArn ||
    !configuration.region
  ) {
    throw new Error("Enabled Aurora recovery requires exact destination vault and key ARNs.");
  }

  const localVaultKey = new kms.Key(scope, "PrimaryAuroraBackupKey", {
    alias: `alias/scopeproof/${configuration.deploymentEnvironment}/primary-backup-vault`,
    description: "Primary-region Aurora recovery-point encryption",
    enableKeyRotation: true,
    pendingWindow: Duration.days(30),
    removalPolicy: RemovalPolicy.RETAIN,
  });
  const localVaultName = `scopeproof-${configuration.deploymentEnvironment}-primary`;
  const localVaultArn = scope.formatArn({
    arnFormat: ArnFormat.COLON_RESOURCE_NAME,
    resource: "backup-vault",
    resourceName: localVaultName,
    service: "backup",
  });
  const localVault = new backup.BackupVault(scope, "PrimaryAuroraBackupVault", {
    backupVaultName: localVaultName,
    blockRecoveryPointDeletion: true,
    encryptionKey: localVaultKey,
    lockConfiguration: {
      maxRetention: Duration.days(3_650),
      minRetention: Duration.days(configuration.auroraLocalRetentionDays),
    },
  });
  if (!props.operationsTopic.masterKey) {
    throw new Error("Aurora recovery notifications require a customer-managed SNS KMS key.");
  }
  configureBackupVaultNotifications({
    account: scope.account,
    events: [
      backup.BackupVaultEvents.BACKUP_JOB_FAILED,
      backup.BackupVaultEvents.COPY_JOB_FAILED,
      backup.BackupVaultEvents.RESTORE_JOB_FAILED,
    ],
    key: props.operationsTopic.masterKey,
    topic: props.operationsTopic,
    vault: localVault,
    vaultArn: localVaultArn,
  });
  const destinationVault = backup.BackupVault.fromBackupVaultArn(
    scope,
    "CrossRegionAuroraBackupVault",
    configuration.backupVaultArn,
  );
  const plan = new backup.BackupPlan(scope, "AuroraRecoveryPlan", {
    backupPlanName: `scopeproof-${configuration.deploymentEnvironment}-aurora-recovery`,
    backupPlanRules: [new backup.BackupPlanRule({
      backupVault: localVault,
      completionWindow: Duration.hours(6),
      copyActions: [{
        deleteAfter: Duration.days(configuration.auroraCopyRetentionDays),
        destinationBackupVault: destinationVault,
      }],
      deleteAfter: Duration.days(configuration.auroraLocalRetentionDays),
      recoveryPointTags: {
        Application: "Scopeproof",
        Environment: configuration.deploymentEnvironment,
        RecoveryClass: "AuroraCrossRegion",
      },
      ruleName: "DailyAuroraCrossRegionRecovery",
      scheduleExpression: events.Schedule.cron({ hour: "5", minute: "0" }),
      startWindow: Duration.hours(2),
    })],
  });

  const backupRole = new iam.Role(scope, "AuroraBackupRole", {
    assumedBy: new iam.ServicePrincipal("backup.amazonaws.com"),
    description: "Exact Aurora cluster backup and cross-region copy role",
    path: "/scopeproof/recovery/",
    roleName: recoveryBackupRoleName(configuration.deploymentEnvironment),
  });
  const primaryClusterSnapshotArn = scope.formatArn({
    arnFormat: ArnFormat.COLON_RESOURCE_NAME,
    resource: "cluster-snapshot",
    resourceName: "awsbackup:*",
    service: "rds",
  });
  const recoveryClusterSnapshotArn = scope.formatArn({
    arnFormat: ArnFormat.COLON_RESOURCE_NAME,
    region: configuration.region,
    resource: "cluster-snapshot",
    resourceName: "awsbackup:*",
    service: "rds",
  });
  const clusterSnapshotArns = [primaryClusterSnapshotArn, recoveryClusterSnapshotArn];
  backupRole.addToPolicy(new iam.PolicyStatement({
    actions: [
      "rds:AddTagsToResource",
      "rds:CopyDBClusterSnapshot",
      "rds:CreateDBClusterSnapshot",
      "rds:ListTagsForResource",
    ],
    resources: [props.databaseCluster.clusterArn, ...clusterSnapshotArns],
  }));
  backupRole.addToPolicy(new iam.PolicyStatement({
    actions: ["rds:ModifyDBCluster"],
    resources: [props.databaseCluster.clusterArn],
  }));
  backupRole.addToPolicy(new iam.PolicyStatement({
    actions: [
      "rds:DeleteDBClusterSnapshot",
      "rds:ModifyDBClusterSnapshotAttribute",
    ],
    resources: clusterSnapshotArns,
  }));
  backupRole.addToPolicy(new iam.PolicyStatement({
    actions: [
      "rds:DescribeDBClusterAutomatedBackups",
      "rds:DescribeDBClusters",
      "rds:DescribeDBClusterSnapshots",
      "rds:DescribeDBInstances",
      "rds:DescribeDBSnapshots",
    ],
    resources: ["*"],
  }));
  backupRole.addToPolicy(new iam.PolicyStatement({
    actions: ["backup:CopyIntoBackupVault", "backup:DescribeBackupVault"],
    resources: [localVault.backupVaultArn, configuration.backupVaultArn],
  }));
  backupRole.addToPolicy(new iam.PolicyStatement({
    actions: ["backup:CopyFromBackupVault"],
    // CopyFromBackupVault is authorized against the source recovery point,
    // not the vault that contains it. Keep this source-region and account
    // scoped so the role cannot copy arbitrary recovery points.
    resources: [scope.formatArn({
      arnFormat: ArnFormat.COLON_RESOURCE_NAME,
      region: scope.region,
      resource: "recovery-point",
      resourceName: "*",
      service: "backup",
    })],
  }));
  backupRole.addToPolicy(new iam.PolicyStatement({
    actions: ["backup:TagResource"],
    resources: [scope.formatArn({
      arnFormat: ArnFormat.COLON_RESOURCE_NAME,
      region: "*",
      resource: "recovery-point",
      resourceName: "*",
      service: "backup",
    })],
  }));
  backupRole.addToPolicy(new iam.PolicyStatement({ actions: ["tag:GetResources"], resources: ["*"] }));
  const backupKeys = [
    props.databaseKey.keyArn,
    localVaultKey.keyArn,
    configuration.backupVaultKeyArn,
  ];
  backupRole.addToPolicy(new iam.PolicyStatement({
    actions: ["kms:DescribeKey"],
    resources: backupKeys,
  }));
  backupRole.addToPolicy(new iam.PolicyStatement({
    actions: ["kms:CreateGrant"],
    conditions: { Bool: { "kms:GrantIsForAWSResource": "true" } },
    resources: backupKeys,
  }));
  plan.addSelection("ExactAuroraCluster", {
    backupSelectionName: "scopeproof-exact-aurora-cluster",
    disableDefaultBackupPolicy: true,
    resources: [backup.BackupResource.fromRdsDatabaseCluster(props.databaseCluster)],
    role: backupRole,
  });

  const freshnessLogGroup = new logs.LogGroup(scope, "AuroraRecoveryFreshnessLogs", {
    encryptionKey: localVaultKey,
    removalPolicy: RemovalPolicy.RETAIN,
    retention: logs.RetentionDays.ONE_YEAR,
  });
  const freshnessMonitor = new lambdaNodejs.NodejsFunction(scope, "AuroraRecoveryFreshnessMonitor", {
    architecture: lambda.Architecture.ARM_64,
    bundling: {
      externalModules: [],
      format: lambdaNodejs.OutputFormat.ESM,
      minify: true,
      sourceMap: false,
      target: "node22",
    },
    description: "Fails closed when primary or cross-region Aurora recovery points become stale",
    entry: path.join(__dirname, "..", "runtime", "monitor-aurora-recovery", "index.mjs"),
    environment: {
      AWS_ACCOUNT_ID_EXPECTED: scope.account,
      AWS_REGION_EXPECTED: scope.region,
      DATABASE_CLUSTER_ARN: props.databaseCluster.clusterArn,
      DEPLOYMENT_ENVIRONMENT: configuration.deploymentEnvironment,
      PRIMARY_VAULT_NAME: localVaultName,
      RECOVERY_REGION_EXPECTED: configuration.region,
      RECOVERY_VAULT_NAME: configuration.backupVaultName!,
    },
    handler: "handler",
    logGroup: freshnessLogGroup,
    memorySize: 256,
    reservedConcurrentExecutions: 1,
    runtime: lambda.Runtime.NODEJS_22_X,
    timeout: Duration.minutes(2),
    tracing: lambda.Tracing.ACTIVE,
  });
  freshnessMonitor.addToRolePolicy(new iam.PolicyStatement({
    actions: ["backup:ListRecoveryPointsByBackupVault"],
    resources: [localVault.backupVaultArn, configuration.backupVaultArn],
  }));
  freshnessMonitor.addToRolePolicy(new iam.PolicyStatement({
    actions: ["cloudwatch:PutMetricData"],
    conditions: { StringEquals: { "cloudwatch:namespace": "Scopeproof/Recovery" } },
    resources: ["*"],
  }));
  const freshnessSchedule = new events.Rule(scope, "AuroraRecoveryFreshnessSchedule", {
    description: "Checks exact primary and cross-region Aurora recovery-point age every hour",
    enabled: true,
    schedule: events.Schedule.rate(Duration.hours(1)),
  });
  freshnessSchedule.addTarget(new eventTargets.LambdaFunction(freshnessMonitor, {
    maxEventAge: Duration.hours(2),
    retryAttempts: 2,
  }));
  for (const vaultRole of ["PRIMARY", "RECOVERY"] as const) {
    new cloudwatch.Alarm(scope, `Aurora${vaultRole}RecoveryFreshnessAlarm`, {
      alarmDescription: `${vaultRole.toLowerCase()} Aurora recovery points are stale or not being observed.`,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      datapointsToAlarm: 2,
      evaluationPeriods: 2,
      metric: new cloudwatch.Metric({
        dimensionsMap: {
          Environment: configuration.deploymentEnvironment,
          VaultRole: vaultRole,
        },
        metricName: "AuroraRecoveryPointFreshnessSeconds",
        namespace: "Scopeproof/Recovery",
        period: Duration.hours(1),
        statistic: "Maximum",
      }),
      threshold: Duration.hours(36).toSeconds(),
      treatMissingData: cloudwatch.TreatMissingData.BREACHING,
    }).addAlarmAction(new cloudwatchActions.SnsAction(props.operationsTopic));
  }
  new cloudwatch.Alarm(scope, "AuroraRecoveryFreshnessMonitorErrors", {
    alarmDescription: "Aurora recovery-point freshness monitor failed.",
    comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
    evaluationPeriods: 1,
    metric: freshnessMonitor.metricErrors({ period: Duration.hours(1), statistic: "Sum" }),
    threshold: 1,
    treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
  }).addAlarmAction(new cloudwatchActions.SnsAction(props.operationsTopic));

  new CfnOutput(scope, "AuroraRecoveryPlanArn", { value: plan.backupPlanArn });
  new CfnOutput(scope, "PrimaryAuroraBackupVaultArn", { value: localVault.backupVaultArn });
  new CfnOutput(scope, "CrossRegionAuroraBackupVaultArn", { value: configuration.backupVaultArn });
  new CfnOutput(scope, "AuroraRecoveryFreshnessMonitorArn", { value: freshnessMonitor.functionArn });
}

export interface BackupVaultNotificationProps {
  readonly account: string;
  readonly events: readonly backup.BackupVaultEvents[];
  readonly key: kms.IKey;
  readonly topic: sns.Topic;
  readonly vault: backup.BackupVault;
  readonly vaultArn: string;
}

export function configureBackupVaultNotifications(props: BackupVaultNotificationProps): void {
  const backupPrincipal = new iam.ServicePrincipal("backup.amazonaws.com");
  const conditions = {
    ArnEquals: { "aws:SourceArn": props.vaultArn },
    StringEquals: { "aws:SourceAccount": props.account },
  };
  props.topic.addToResourcePolicy(new iam.PolicyStatement({
    actions: ["sns:Publish"],
    conditions,
    principals: [backupPrincipal],
    resources: [props.topic.topicArn],
  }));
  props.key.addToResourcePolicy(new iam.PolicyStatement({
    actions: ["kms:Decrypt", "kms:GenerateDataKey*"],
    conditions,
    principals: [backupPrincipal],
    resources: ["*"],
  }));
  const cfnVault = props.vault.node.defaultChild as backup.CfnBackupVault;
  cfnVault.notifications = {
    backupVaultEvents: [...props.events],
    snsTopicArn: props.topic.topicArn,
  };
}

export interface EvidenceRecoveryProps {
  readonly auditSigningKey: kms.Key;
  readonly configuration: RecoveryConfiguration;
  readonly controlTableArn: string;
  readonly controlTableName: string;
  readonly destination: EvidenceRecoveryDestination;
  readonly evidenceBucket: s3.Bucket;
  readonly evidenceKey: kms.Key;
  readonly operationsTopic: sns.Topic;
  readonly tenant: TenantDefinition;
}

export function configureEvidenceRecovery(scope: Stack, props: EvidenceRecoveryProps): void {
  const { auditSigningKey, configuration, destination, evidenceBucket, evidenceKey, tenant } = props;
  if (configuration.mode !== "enabled" || !configuration.region) {
    throw new Error("Evidence replication requires enabled cross-region recovery.");
  }
  const sourceBucketName = primaryEvidenceBucketName(scope.account, scope.region, tenant.id);
  const sourceBucketArn = scope.formatArn({
    account: "",
    region: "",
    resource: sourceBucketName,
    service: "s3",
  });
  const destinationBucketArn = `arn:${scope.partition}:s3:::${destination.bucketName}`;
  const evidencePrefix = `tenants/${tenant.id}/controls/`;
  const destinationObjectArn = `${destinationBucketArn}/${evidencePrefix}*`;
  const replicationRole = new iam.Role(scope, "EvidenceReplicationRole", {
    assumedBy: new iam.ServicePrincipal("s3.amazonaws.com"),
    description: `Exact-version cross-region evidence replication for ${tenant.id}`,
    path: "/scopeproof/recovery/",
    roleName: recoveryEvidenceReplicationRoleName(tenant),
  });
  const replicationPolicy = new iam.Policy(scope, "EvidenceReplicationPolicy", {
    statements: [
      new iam.PolicyStatement({
        actions: ["s3:GetReplicationConfiguration", "s3:ListBucket"],
        resources: [sourceBucketArn],
      }),
      new iam.PolicyStatement({
        actions: [
          "s3:GetObjectLegalHold",
          "s3:GetObjectRetention",
          "s3:GetObjectVersionAcl",
          "s3:GetObjectVersionForReplication",
          "s3:GetObjectVersionTagging",
        ],
        resources: [`${sourceBucketArn}/${evidencePrefix}*`],
      }),
      new iam.PolicyStatement({
        // Object Lock replication requires permission to copy the source
        // version's retention and legal-hold metadata as well as its bytes.
        actions: [
          "s3:PutObjectLegalHold",
          "s3:PutObjectRetention",
          "s3:ReplicateObject",
          "s3:ReplicateTags",
        ],
        resources: [destinationObjectArn],
      }),
      new iam.PolicyStatement({
        actions: ["kms:Decrypt"],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:aws:s3:arn": sourceBucketArn,
            "kms:EncryptionContext:scopeproofPurpose": "immutable-evidence",
            "kms:EncryptionContext:scopeproofTenantId": tenant.id,
            "kms:ViaService": `s3.${scope.region}.amazonaws.com`,
          },
        },
        resources: [evidenceKey.keyArn],
      }),
      new iam.PolicyStatement({
        actions: ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:aws:s3:arn": destinationBucketArn,
            "kms:ViaService": `s3.${configuration.region}.amazonaws.com`,
          },
        },
        resources: [destination.kmsKeyArn],
      }),
    ],
  });
  replicationPolicy.attachToRole(replicationRole);

  const backfillReportBucket = new s3.Bucket(scope, "EvidenceRecoveryBackfillReports", {
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    bucketKeyEnabled: true,
    encryption: s3.BucketEncryption.KMS,
    encryptionKey: evidenceKey,
    enforceSSL: true,
    lifecycleRules: [{
      id: "archive-recovery-backfill-reports",
      noncurrentVersionTransitions: [{ storageClass: s3.StorageClass.GLACIER, transitionAfter: Duration.days(30) }],
      transitions: [{ storageClass: s3.StorageClass.GLACIER, transitionAfter: Duration.days(90) }],
    }],
    objectLockDefaultRetention: tenant.retentionMode === "COMPLIANCE"
      ? s3.ObjectLockRetention.compliance(Duration.days(tenant.retentionDays ?? 365))
      : s3.ObjectLockRetention.governance(Duration.days(tenant.retentionDays ?? 365)),
    objectLockEnabled: true,
    objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
    removalPolicy: RemovalPolicy.RETAIN,
    versioned: true,
  });
  backfillReportBucket.policy?.applyRemovalPolicy(RemovalPolicy.RETAIN);
  backfillReportBucket.addToResourcePolicy(new iam.PolicyStatement({
    actions: ["s3:BypassGovernanceRetention", "s3:DeleteObject", "s3:DeleteObjectVersion"],
    effect: iam.Effect.DENY,
    principals: [new iam.AnyPrincipal()],
    resources: [backfillReportBucket.arnForObjects("*")],
  }));
  const batchRole = new iam.Role(scope, "EvidenceRecoveryBatchRole", {
    assumedBy: new iam.ServicePrincipal("batchoperations.s3.amazonaws.com"),
    description: `Initiates exact existing-version evidence replication for ${tenant.id}`,
    path: "/scopeproof/recovery/",
    roleName: recoveryEvidenceBatchRoleName(tenant),
  });
  batchRole.addToPolicy(new iam.PolicyStatement({
    actions: ["s3:InitiateReplication"],
    resources: [`${sourceBucketArn}/${evidencePrefix}*`],
  }));
  batchRole.addToPolicy(new iam.PolicyStatement({
    actions: ["s3:GetReplicationConfiguration", "s3:PutInventoryConfiguration"],
    resources: [sourceBucketArn],
  }));
  backfillReportBucket.grantPut(batchRole);

  const replicationDestination: s3.CfnBucket.ReplicationDestinationProperty = {
    bucket: destinationBucketArn,
    encryptionConfiguration: { replicaKmsKeyId: props.destination.kmsKeyArn },
    metrics: configuration.s3ReplicationTimeControl
      ? { eventThreshold: { minutes: 15 }, status: "Enabled" }
      : undefined,
    replicationTime: configuration.s3ReplicationTimeControl
      ? { status: "Enabled", time: { minutes: 15 } }
      : undefined,
    storageClass: "STANDARD",
  };
  const cfnBucket = evidenceBucket.node.defaultChild as s3.CfnBucket;
  cfnBucket.replicationConfiguration = {
    role: replicationRole.roleArn,
    rules: [{
      deleteMarkerReplication: { status: "Disabled" },
      destination: replicationDestination,
      filter: { prefix: evidencePrefix },
      id: `scopeproof-${tenant.slug}-cross-region-evidence`,
      priority: 1,
      sourceSelectionCriteria: { sseKmsEncryptedObjects: { status: "Enabled" } },
      status: "Enabled",
    }],
  };
  const policyResource = replicationPolicy.node.defaultChild;
  if (policyResource) cfnBucket.node.addDependency(policyResource);

  const reconcilerLogGroup = new logs.LogGroup(scope, "EvidenceRecoveryReconcilerLogs", {
    encryptionKey: evidenceKey,
    removalPolicy: RemovalPolicy.RETAIN,
    retention: logs.RetentionDays.ONE_YEAR,
  });
  const reconciler = new lambdaNodejs.NodejsFunction(scope, "EvidenceRecoveryReconciler", {
    architecture: lambda.Architecture.ARM_64,
    bundling: {
      externalModules: [],
      format: lambdaNodejs.OutputFormat.ESM,
      minify: true,
      sourceMap: false,
      target: "node22",
    },
    description: `Backfills and verifies exact immutable evidence versions for ${tenant.id}`,
    entry: path.join(__dirname, "..", "runtime", "reconcile-recovery", "index.mjs"),
    environment: {
      AWS_ACCOUNT_ID_EXPECTED: scope.account,
      AWS_REGION_EXPECTED: scope.region,
      AUDIT_SIGNING_KEY_ARN: auditSigningKey.keyArn,
      BATCH_ROLE_ARN: batchRole.roleArn,
      CONTROL_TABLE_NAME: props.controlTableName,
      DESTINATION_BUCKET_NAME: destination.bucketName,
      DESTINATION_KMS_KEY_ARN: destination.kmsKeyArn,
      LEDGER_SETTLE_SECONDS: "900",
      MAX_VERSIONS_PER_RUN: "250",
      OPERATIONS_TOPIC_ARN: props.operationsTopic.topicArn,
      RECOVERY_REGION_EXPECTED: configuration.region,
      REPORT_BUCKET_NAME: backfillReportBucket.bucketName,
      SOURCE_BUCKET_NAME: sourceBucketName,
      SOURCE_KMS_KEY_ARN: evidenceKey.keyArn,
      TENANT_ID: tenant.id,
      VERIFICATION_INTERVAL_SECONDS: "86400",
    },
    handler: "handler",
    logGroup: reconcilerLogGroup,
    memorySize: 512,
    reservedConcurrentExecutions: 1,
    runtime: lambda.Runtime.NODEJS_22_X,
    timeout: Duration.minutes(15),
    tracing: lambda.Tracing.ACTIVE,
  });
  reconciler.addToRolePolicy(new iam.PolicyStatement({
    actions: ["s3:CreateJob", "s3:DescribeJob"],
    resources: ["*"],
  }));
  reconciler.addToRolePolicy(new iam.PolicyStatement({
    actions: ["iam:PassRole"],
    conditions: { StringEquals: { "iam:PassedToService": "batchoperations.s3.amazonaws.com" } },
    resources: [batchRole.roleArn],
  }));
  reconciler.addToRolePolicy(new iam.PolicyStatement({
    actions: ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem"],
    conditions: {
      Null: { "dynamodb:LeadingKeys": "false" },
      // Mutable scheduler progress is isolated from the append-only,
      // promoter/worker-authored recovery ledger.
      "ForAllValues:StringEquals": { "dynamodb:LeadingKeys": [`RECOVERY_STATE#TENANT#${tenant.id}`] },
    },
    resources: [props.controlTableArn],
  }));
  reconciler.addToRolePolicy(new iam.PolicyStatement({
    actions: ["dynamodb:GetItem", "dynamodb:Query"],
    conditions: {
      Null: { "dynamodb:LeadingKeys": "false" },
      // Authoritative signed receipts and the ordered change ledger are
      // readable but not writable by the recovery verifier.
      "ForAllValues:StringEquals": { "dynamodb:LeadingKeys": [`RECOVERY#TENANT#${tenant.id}`] },
    },
    resources: [props.controlTableArn],
  }));
  reconciler.addToRolePolicy(new iam.PolicyStatement({
    actions: ["kms:Verify"],
    resources: [auditSigningKey.keyArn],
  }));
  reconciler.addToRolePolicy(new iam.PolicyStatement({
    actions: ["s3:ListBucketVersions"],
    conditions: { StringLike: { "s3:prefix": [`${evidencePrefix}*`] } },
    resources: [sourceBucketArn, destinationBucketArn],
  }));
  reconciler.addToRolePolicy(new iam.PolicyStatement({
    // Exact-version comparison reads Object Lock retention and legal-hold
    // state in addition to object metadata. None of these permissions permits
    // changing or deleting the protected version.
    actions: ["s3:GetObjectLegalHold", "s3:GetObjectRetention", "s3:GetObjectVersion"],
    resources: [`${sourceBucketArn}/${evidencePrefix}*`, destinationObjectArn],
  }));
  reconciler.addToRolePolicy(new iam.PolicyStatement({
    // S3 checksum-mode HEAD requires both permissions for SSE-KMS objects.
    actions: ["kms:Decrypt", "kms:GenerateDataKey"],
    conditions: {
      StringEquals: {
        "kms:EncryptionContext:scopeproofPurpose": "immutable-evidence",
        "kms:EncryptionContext:scopeproofTenantId": tenant.id,
        "kms:ViaService": `s3.${scope.region}.amazonaws.com`,
      },
    },
    resources: [evidenceKey.keyArn],
  }));
  reconciler.addToRolePolicy(new iam.PolicyStatement({
    // Keep destination checksum verification usable without granting a broad
    // KMS context or direct non-S3 key use.
    actions: ["kms:Decrypt", "kms:GenerateDataKey"],
    conditions: {
      StringEquals: {
        "kms:EncryptionContext:aws:s3:arn": destinationBucketArn,
        "kms:ViaService": `s3.${configuration.region}.amazonaws.com`,
      },
    },
    resources: [destination.kmsKeyArn],
  }));
  reconciler.addToRolePolicy(new iam.PolicyStatement({
    actions: ["cloudwatch:PutMetricData"],
    conditions: { StringEquals: { "cloudwatch:namespace": "Scopeproof/Recovery" } },
    resources: ["*"],
  }));
  props.operationsTopic.grantPublish(reconciler);
  const recoverySchedule = new events.Rule(scope, "EvidenceRecoveryReconciliationSchedule", {
    description: `Continues bounded existing-version recovery verification for ${tenant.id}`,
    enabled: true,
    schedule: events.Schedule.rate(Duration.minutes(15)),
  });
  recoverySchedule.addTarget(new eventTargets.LambdaFunction(reconciler, {
    maxEventAge: Duration.hours(2),
    retryAttempts: 2,
  }));
  // Replication failures are S3 Event Notifications, not standard direct S3
  // EventBridge events. Route the exact event to tenant-local compute, which
  // validates it and publishes a redacted alert without creating a shared-
  // stack topic-policy dependency on the tenant bucket.
  evidenceBucket.addEventNotification(
    s3.EventType.REPLICATION_OPERATION_FAILED_REPLICATION,
    new s3Notifications.LambdaDestination(reconciler),
    { prefix: evidencePrefix },
  );
  recoverySchedule.node.addDependency(cfnBucket);
  new cloudwatch.Alarm(scope, "EvidenceRecoveryReconcilerErrors", {
    alarmDescription: `Existing evidence backfill or exact-version verification failed for ${tenant.id}.`,
    comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
    evaluationPeriods: 1,
    metric: reconciler.metricErrors({ period: Duration.minutes(15), statistic: "Sum" }),
    threshold: 1,
    treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
  }).addAlarmAction(new cloudwatchActions.SnsAction(props.operationsTopic));

  new cloudwatch.Alarm(scope, "EvidenceRecoveryVerificationFreshnessAlarm", {
    alarmDescription: `Exact-version evidence verification is stale or missing for ${tenant.id}.`,
    comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
    datapointsToAlarm: 3,
    evaluationPeriods: 3,
    metric: new cloudwatch.Metric({
      dimensionsMap: { TenantId: tenant.id },
      metricName: "EvidenceVerificationFreshnessSeconds",
      namespace: "Scopeproof/Recovery",
      period: Duration.minutes(15),
      statistic: "Maximum",
    }),
    threshold: Duration.hours(36).toSeconds(),
    treatMissingData: cloudwatch.TreatMissingData.BREACHING,
  }).addAlarmAction(new cloudwatchActions.SnsAction(props.operationsTopic));

  new cloudwatch.Alarm(scope, "EvidenceReplicationFailuresAlarm", {
    alarmDescription: `Evidence replication has failed operations for ${tenant.id}.`,
    comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
    evaluationPeriods: 3,
    metric: new cloudwatch.Metric({
      dimensionsMap: {
        DestinationBucket: destination.bucketName,
        RuleId: `scopeproof-${tenant.slug}-cross-region-evidence`,
        SourceBucket: evidenceBucket.bucketName,
      },
      metricName: "OperationsFailedReplication",
      namespace: "AWS/S3",
      period: Duration.minutes(15),
      statistic: "Maximum",
    }),
    threshold: 0,
    treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
  }).addAlarmAction(new cloudwatchActions.SnsAction(props.operationsTopic));

  new CfnOutput(scope, "EvidenceRecoveryBucketName", { value: destination.bucketName });
  new CfnOutput(scope, "EvidenceRecoveryKeyArn", { value: destination.kmsKeyArn });
  new CfnOutput(scope, "EvidenceReplicationRoleArn", { value: replicationRole.roleArn });
  new CfnOutput(scope, "EvidenceRecoveryBackfillRoleArn", { value: batchRole.roleArn });
  new CfnOutput(scope, "EvidenceRecoveryBackfillReportBucket", { value: backfillReportBucket.bucketName });
  new CfnOutput(scope, "EvidenceRecoveryReconcilerFunctionArn", { value: reconciler.functionArn });
  new CfnOutput(scope, "EvidenceReplicationMode", {
    value: configuration.s3ReplicationTimeControl ? "CROSS_REGION_RTC_15_MINUTES" : "CROSS_REGION_ASYNCHRONOUS",
  });
}
