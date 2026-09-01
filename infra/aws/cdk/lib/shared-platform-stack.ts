import {
  ArnFormat,
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  StackProps,
} from "aws-cdk-lib";
import * as path from "node:path";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as amplify from "aws-cdk-lib/aws-amplify";
import * as budgets from "aws-cdk-lib/aws-budgets";
import * as ce from "aws-cdk-lib/aws-ce";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as cloudfrontOrigins from "aws-cdk-lib/aws-cloudfront-origins";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as events from "aws-cdk-lib/aws-events";
import * as eventTargets from "aws-cdk-lib/aws-events-targets";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as lambdaNodejs from "aws-cdk-lib/aws-lambda-nodejs";
import * as logs from "aws-cdk-lib/aws-logs";
import * as rds from "aws-cdk-lib/aws-rds";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as route53Targets from "aws-cdk-lib/aws-route53-targets";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as ses from "aws-cdk-lib/aws-ses";
import * as sns from "aws-cdk-lib/aws-sns";
import * as subscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import { Construct } from "constructs";
import type { MaintenanceLifecycleMode } from "./config";
import { RecoveryConfiguration } from "./recovery-config";
import { configureAuroraRecovery } from "./recovery-support";

export interface SharedPlatformStackProps extends StackProps {
  readonly rootDomain: string;
  readonly branchName: string;
  readonly hostedZoneId?: string;
  readonly createHostedZone?: boolean;
  readonly tenantSlugs: readonly string[];
  readonly alertEmail?: string;
  readonly monthlyBudgetUsd?: number;
  readonly recovery?: RecoveryConfiguration;
  readonly maintenanceLifecycleMode?: MaintenanceLifecycleMode;
}

export class SharedPlatformStack extends Stack {
  public readonly rootDomain: string;
  public readonly branchName: string;
  public readonly hostedZone: route53.IHostedZone;
  public readonly controlTable: dynamodb.TableV2;
  /**
   * Out-of-band, short-lived customer activation approvals. Application and
   * provisioning code receive read-only access; no workload can self-approve.
   */
  public readonly customerActivationTable: dynamodb.TableV2;
  public readonly userPool: cognito.UserPool;
  public readonly oauthScopes: Readonly<{
    evidenceRead: cognito.OAuthScope;
    evidenceCollect: cognito.OAuthScope;
    retentionManage: cognito.OAuthScope;
  }>;
  public readonly databaseCluster: rds.DatabaseCluster;
  public readonly jobsQueue: sqs.Queue;
  public readonly amplifyApp: amplify.CfnApp;
  public readonly amplifyComputeRole: iam.Role;
  public readonly jobWorkerRole: iam.Role;
  public readonly jobsDeadLetterQueue: sqs.Queue;
  public readonly operationsTopic: sns.Topic;
  public readonly releaseBucket: s3.Bucket;
  public readonly releaseDistribution: cloudfront.Distribution;
  public readonly webAcl: wafv2.CfnWebACL;

  public constructor(scope: Construct, id: string, props: SharedPlatformStackProps) {
    super(scope, id, props);
    this.rootDomain = props.rootDomain;
    this.branchName = props.branchName;
    const maintenanceLifecycleMode = props.maintenanceLifecycleMode ?? "backfill";
    if (maintenanceLifecycleMode !== "backfill" && maintenanceLifecycleMode !== "enabled") {
      throw new Error("maintenanceLifecycleMode must be backfill or enabled.");
    }
    const monthlyBudgetUsd = props.monthlyBudgetUsd ?? 100;
    if (!Number.isFinite(monthlyBudgetUsd) || monthlyBudgetUsd < 10 || monthlyBudgetUsd > 1_000_000) {
      throw new Error("monthlyBudgetUsd must be a number from 10 through 1000000.");
    }

    if (props.tenantSlugs.length > 49) {
      throw new Error("Amplify's fixed service quota permits at most 50 subdomain settings, including the root domain.");
    }
    if (this.rootDomain === "jsontechology.com") {
      throw new Error("jsontechology.com is a planning placeholder and cannot be synthesized. Supply an owned domain.");
    }
    if (Boolean(props.hostedZoneId) === Boolean(props.createHostedZone)) {
      throw new Error("Specify exactly one existing hostedZoneId or explicitly authorize createHostedZone.");
    }

    this.hostedZone = props.hostedZoneId
      ? route53.HostedZone.fromHostedZoneAttributes(this, "HostedZone", {
          hostedZoneId: props.hostedZoneId,
          zoneName: this.rootDomain,
        })
      : new route53.PublicHostedZone(this, "HostedZone", {
          zoneName: this.rootDomain,
          comment: "Scopeproof placeholder zone; delegate the domain before deployment.",
        });

    const controlPlaneReplicas: dynamodb.ReplicaTableProps[] = props.recovery?.mode === "enabled"
      ? [{
          deletionProtection: true,
          pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
          region: props.recovery.region!,
        }]
      : [];
    this.controlTable = new dynamodb.TableV2(this, "ControlPlaneTable", {
      billing: dynamodb.Billing.onDemand(),
      deletionProtection: true,
      dynamoStream: dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
      encryption: dynamodb.TableEncryptionV2.dynamoOwnedKey(),
      globalSecondaryIndexes: [{
        // Preserve the deployed legacy index for rollback. DynamoDB cannot
        // mutate an existing GSI key schema in place.
        indexName: "GSI1",
        partitionKey: { name: "GSI1PK", type: dynamodb.AttributeType.STRING },
        projectionType: dynamodb.ProjectionType.ALL,
        sortKey: { name: "GSI1SK", type: dynamodb.AttributeType.STRING },
      }, {
        indexName: "UploadLifecycleByTenantV2",
        nonKeyAttributes: [
          "GSI1PK", "consumedAt", "detectedAt", "expiresAt", "id", "kind", "promotionLeaseExpiresAt", "promotionLeaseId", "reason",
          "reconciliationDetectedAt", "reconciliationDisposition", "reconciliationReason",
          "revision", "schemaVersion", "sourceRevision", "status",
          "tenantId", "ttlEpochSeconds", "validation",
        ],
        // Reuse the immutable base-table partition key so a tenant-scoped role
        // cannot forge another tenant's maintenance partition through a
        // caller-controlled GSI partition attribute.
        partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING },
        projectionType: dynamodb.ProjectionType.INCLUDE,
        sortKey: { name: "GSI1SK", type: dynamodb.AttributeType.STRING },
      }],
      globalTableSettingsReplicationMode: dynamodb.GlobalTableSettingsReplicationMode.ALL,
      partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING },
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      replicas: controlPlaneReplicas,
      sortKey: { name: "SK", type: dynamodb.AttributeType.STRING },
      removalPolicy: RemovalPolicy.RETAIN,
      // Lifecycle records retain canonical ISO timestamps for CAS comparisons;
      // DynamoDB TTL requires a distinct numeric epoch-seconds attribute.
      timeToLiveAttribute: "ttlEpochSeconds",
    });
    this.customerActivationTable = new dynamodb.TableV2(this, "CustomerActivationTable", {
      billing: dynamodb.Billing.onDemand(),
      deletionProtection: true,
      encryption: dynamodb.TableEncryptionV2.dynamoOwnedKey(),
      partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING },
      pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
      removalPolicy: RemovalPolicy.RETAIN,
      sortKey: { name: "SK", type: dynamodb.AttributeType.STRING },
      timeToLiveAttribute: "ttlEpochSeconds",
    });

    this.userPool = new cognito.UserPool(this, "UserPool", {
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      deletionProtection: true,
      featurePlan: cognito.FeaturePlan.ESSENTIALS,
      mfa: cognito.Mfa.REQUIRED,
      mfaSecondFactor: { otp: true, sms: false },
      passwordPolicy: {
        minLength: 14,
        requireDigits: true,
        requireLowercase: true,
        requireSymbols: true,
        requireUppercase: true,
        tempPasswordValidity: Duration.days(3),
      },
      removalPolicy: RemovalPolicy.RETAIN,
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      signInCaseSensitive: false,
    });
    const evidenceReadScope = new cognito.ResourceServerScope({
      scopeName: "evidence.read",
      scopeDescription: "Read tenant evidence metadata and request exact-version downloads",
    });
    const evidenceCollectScope = new cognito.ResourceServerScope({
      scopeName: "evidence.collect",
      scopeDescription: "Create exact, short-lived evidence upload intents",
    });
    const retentionManageScope = new cognito.ResourceServerScope({
      scopeName: "retention.manage",
      scopeDescription: "Request and approve tenant retention and legal-hold operations",
    });
    const scopeproofResourceServer = this.userPool.addResourceServer("ScopeproofResourceServer", {
      identifier: "scopeproof",
      scopes: [evidenceReadScope, evidenceCollectScope, retentionManageScope],
      userPoolResourceServerName: "Scopeproof tenant API",
    });
    this.oauthScopes = Object.freeze({
      evidenceRead: cognito.OAuthScope.resourceServer(scopeproofResourceServer, evidenceReadScope),
      evidenceCollect: cognito.OAuthScope.resourceServer(scopeproofResourceServer, evidenceCollectScope),
      retentionManage: cognito.OAuthScope.resourceServer(scopeproofResourceServer, retentionManageScope),
    });

    const authCertificate = new acm.Certificate(this, "CognitoCertificate", {
      domainName: `auth.${this.rootDomain}`,
      validation: acm.CertificateValidation.fromDns(this.hostedZone),
    });
    const authDomain = this.userPool.addDomain("CognitoDomain", {
      customDomain: {
        certificate: authCertificate,
        domainName: `auth.${this.rootDomain}`,
      },
      managedLoginVersion: cognito.ManagedLoginVersion.NEWER_MANAGED_LOGIN,
    });
    new route53.ARecord(this, "CognitoAlias", {
      zone: this.hostedZone,
      recordName: "auth",
      target: route53.RecordTarget.fromAlias(new route53Targets.UserPoolDomainTarget(authDomain)),
    });

    const vpc = new ec2.Vpc(this, "DatabaseVpc", {
      ipAddresses: ec2.IpAddresses.cidr("10.42.0.0/20"),
      maxAzs: 2,
      natGateways: 0,
      subnetConfiguration: [
        {
          cidrMask: 24,
          name: "database-isolated",
          subnetType: ec2.SubnetType.PRIVATE_ISOLATED,
        },
      ],
    });
    const databaseSecurityGroup = new ec2.SecurityGroup(this, "DatabaseSecurityGroup", {
      vpc,
      allowAllOutbound: false,
      description: "No network clients; Scopeproof reaches Aurora through RDS Data API.",
    });
    const databaseKey = new kms.Key(this, "DatabaseKey", {
      alias: "alias/scopeproof/platform-database",
      description: "Shared Aurora metadata encryption key",
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const engine = rds.DatabaseClusterEngine.auroraPostgres({
      version: rds.AuroraPostgresEngineVersion.of("16.3", "16"),
    });
    const parameterGroup = new rds.ParameterGroup(this, "DatabaseParameterGroup", {
      engine,
      parameters: { "rds.force_ssl": "1" },
    });
    const databaseAdminSecret = new rds.DatabaseSecret(this, "DatabaseAdminSecret", {
      dbname: "scopeproof_admin",
      encryptionKey: databaseKey,
      username: "scopeproof_cluster_admin",
    });
    databaseAdminSecret.applyRemovalPolicy(RemovalPolicy.RETAIN);
    this.databaseCluster = new rds.DatabaseCluster(this, "Database", {
      backup: { retention: Duration.days(7) },
      cloudwatchLogsExports: ["postgresql"],
      copyTagsToSnapshot: true,
      credentials: rds.Credentials.fromSecret(databaseAdminSecret),
      defaultDatabaseName: "scopeproof_admin",
      deletionProtection: true,
      enableDataApi: true,
      engine,
      iamAuthentication: true,
      parameterGroup,
      removalPolicy: RemovalPolicy.RETAIN,
      securityGroups: [databaseSecurityGroup],
      serverlessV2AutoPauseDuration: Duration.minutes(10),
      serverlessV2MaxCapacity: 4,
      serverlessV2MinCapacity: 0,
      storageEncrypted: true,
      storageEncryptionKey: databaseKey,
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PRIVATE_ISOLATED },
      writer: rds.ClusterInstance.serverlessV2("writer", {
        publiclyAccessible: false,
      }),
    });

    this.jobsDeadLetterQueue = new sqs.Queue(this, "JobsDeadLetterQueue", {
      enforceSSL: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: Duration.days(14),
    });
    this.jobsQueue = new sqs.Queue(this, "JobsQueue", {
      deadLetterQueue: { maxReceiveCount: 5, queue: this.jobsDeadLetterQueue },
      enforceSSL: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: Duration.days(4),
      visibilityTimeout: Duration.minutes(16),
    });

    const operationsKey = new kms.Key(this, "OperationsKey", {
      alias: "alias/scopeproof/platform-operations",
      description: "Encryption key for platform alerting and security logs",
      enableKeyRotation: true,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    this.operationsTopic = new sns.Topic(this, "OperationsTopic", {
      displayName: "Scopeproof production operations",
      enforceSSL: true,
      masterKey: operationsKey,
    });
    // An encrypted SNS topic does not implicitly authorize CloudWatch to use
    // its KMS key. Without this grant alarms can enter ALARM while delivery is
    // silently rejected by KMS.
    this.operationsTopic.grantPublish(new iam.ServicePrincipal("cloudwatch.amazonaws.com"));
    if (props.alertEmail) {
      this.operationsTopic.addSubscription(new subscriptions.EmailSubscription(props.alertEmail));
    }
    if (props.recovery?.mode === "enabled") {
      configureAuroraRecovery(this, {
        configuration: props.recovery,
        databaseCluster: this.databaseCluster,
        databaseKey,
        operationsTopic: this.operationsTopic,
      });
    }

    new cloudwatch.Alarm(this, "JobsDeadLetterAlarm", {
      alarmDescription: "At least one shared background job needs operator intervention.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      evaluationPeriods: 1,
      metric: this.jobsDeadLetterQueue.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(1),
        statistic: "Maximum",
      }),
      threshold: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction(new cloudwatchActions.SnsAction(this.operationsTopic));
    new cloudwatch.Alarm(this, "JobsAgeAlarm", {
      alarmDescription: "Shared jobs have waited longer than fifteen minutes.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 2,
      metric: this.jobsQueue.metricApproximateAgeOfOldestMessage({
        period: Duration.minutes(5),
        statistic: "Maximum",
      }),
      threshold: 900,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction(new cloudwatchActions.SnsAction(this.operationsTopic));
    new cloudwatch.Alarm(this, "DatabaseCapacityAlarm", {
      alarmDescription: "Aurora is sustaining more than 75% of its configured maximum ACUs.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 3,
      metric: this.databaseCluster.metricServerlessDatabaseCapacity({
        period: Duration.minutes(5),
        statistic: "Average",
      }),
      threshold: 3,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction(new cloudwatchActions.SnsAction(this.operationsTopic));
    new events.Rule(this, "MaintenanceSchedule", {
      description: "Queues bounded tenant maintenance work every fifteen minutes.",
      // Existing tables start fail-closed while the bounded legacy lifecycle
      // backfill is run and verified. A second reviewed deployment must opt in.
      enabled: maintenanceLifecycleMode === "enabled",
      schedule: events.Schedule.rate(Duration.minutes(15)),
      targets: [
        new eventTargets.SqsQueue(this.jobsQueue, {
          message: events.RuleTargetInput.fromObject({
            schemaVersion: 1,
            type: "scopeproof.maintenance.sweep",
          }),
        }),
      ],
    });

    this.amplifyComputeRole = new iam.Role(this, "AmplifyComputeRole", {
      assumedBy: new iam.ServicePrincipal("amplify.amazonaws.com"),
      description: "Minimal shared SSR role; assumes an authorized tenant role for tenant data.",
    });
    this.amplifyComputeRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:GetItem"],
      conditions: {
        Null: { "dynamodb:LeadingKeys": "false" },
        "ForAllValues:StringLike": {
          "dynamodb:LeadingKeys": ["DOMAIN#*"],
        },
      },
      resources: [this.controlTable.tableArn],
    }));
    this.amplifyComputeRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:PutItem"],
      conditions: {
        Null: { "dynamodb:LeadingKeys": "false" },
        "ForAllValues:StringEquals": {
          "dynamodb:LeadingKeys": ["EDGE_REPLAY#GLOBAL"],
        },
      },
      resources: [this.controlTable.tableArn],
    }));
    this.jobWorkerRole = new iam.Role(this, "JobWorkerRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description: "Bounded shared lifecycle reconciliation worker with no S3, KMS, RDS, secret, or tenant-role access.",
    });
    this.jobsQueue.grantConsumeMessages(this.jobWorkerRole);
    const uploadLifecycleAttributes = [
      "PK", "SK", "GSI1PK", "GSI1SK", "consumedAt", "detectedAt", "expiredAt", "expiresAt", "id", "kind",
      "promotionLeaseExpiresAt", "promotionLeaseId", "reconciledAt",
      "reconciliationActionKey", "reconciliationDetectedAt", "reconciliationDisposition",
      "reconciliationReason", "receiptSha256", "reason", "resolvedAt", "revision", "schemaVersion",
      "sourceIndexSkSha256", "sourcePkSha256", "sourceRevision", "sourceSkSha256", "status",
      "tenantId", "ttlEpochSeconds", "validation",
    ];
    this.jobWorkerRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:Query"],
      conditions: {
        Null: {
          "dynamodb:Attributes": "false",
          "dynamodb:LeadingKeys": "false",
        },
        "ForAllValues:StringEquals": {
          "dynamodb:Attributes": ["PK", "SK", "kind", "schemaVersion", "status", "tenantId"],
          "dynamodb:LeadingKeys": "MAINTENANCE#TENANT_DIRECTORY",
        },
      },
      resources: [this.controlTable.tableArn],
    }));
    this.jobWorkerRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:Query"],
      conditions: {
        Null: { "dynamodb:Attributes": "false" },
        "ForAllValues:StringEquals": { "dynamodb:Attributes": uploadLifecycleAttributes },
      },
      resources: [`${this.controlTable.tableArn}/index/UploadLifecycleByTenantV2`],
    }));
    this.jobWorkerRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:GetItem", "dynamodb:UpdateItem"],
      conditions: {
        Null: { "dynamodb:LeadingKeys": "false" },
        "ForAllValues:StringEquals": { "dynamodb:LeadingKeys": "MAINTENANCE#SHARED" },
        StringEqualsIfExists: { "dynamodb:ReturnValues": ["NONE", "ALL_NEW"] },
      },
      resources: [this.controlTable.tableArn],
    }));
    this.jobWorkerRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:UpdateItem"],
      conditions: {
        Null: {
          "dynamodb:Attributes": "false",
          "dynamodb:LeadingKeys": "false",
        },
        "ForAllValues:StringEquals": { "dynamodb:Attributes": uploadLifecycleAttributes },
        "ForAllValues:StringLike": { "dynamodb:LeadingKeys": "TENANT#ten_*" },
        StringEqualsIfExists: { "dynamodb:ReturnValues": "NONE" },
      },
      resources: [this.controlTable.tableArn],
    }));
    this.jobWorkerRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:PutItem", "dynamodb:UpdateItem"],
      conditions: {
        Null: {
          "dynamodb:Attributes": "false",
          "dynamodb:LeadingKeys": "false",
        },
        "ForAllValues:StringEquals": { "dynamodb:Attributes": uploadLifecycleAttributes },
        "ForAllValues:StringLike": {
          "dynamodb:LeadingKeys": ["TENANT#ten_*", "MAINTENANCE#ACTION_REQUIRED#ten_*"],
        },
        StringEquals: { "dynamodb:EnclosingOperation": "TransactWriteItems" },
        StringEqualsIfExists: { "dynamodb:ReturnValues": "NONE" },
      },
      resources: [this.controlTable.tableArn],
    }));
    this.jobWorkerRole.addToPolicy(new iam.PolicyStatement({
      actions: ["cloudwatch:PutMetricData"],
      conditions: { StringEquals: { "cloudwatch:namespace": "Scopeproof/SharedJobs" } },
      resources: ["*"],
    }));
    const jobWorkerLogGroup = new logs.LogGroup(this, "JobWorkerLogs", {
      encryptionKey: operationsKey,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    this.jobWorkerRole.addToPolicy(new iam.PolicyStatement({
      actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
      resources: [`${jobWorkerLogGroup.logGroupArn}:*`],
    }));
    const jobWorker = new lambdaNodejs.NodejsFunction(this, "SharedJobWorker", {
      architecture: lambda.Architecture.ARM_64,
      bundling: {
        externalModules: [],
        format: lambdaNodejs.OutputFormat.ESM,
        minify: true,
        sourceMap: false,
        target: "node22",
      },
      depsLockFilePath: path.join(__dirname, "..", "pnpm-lock.yaml"),
      description: "Leased, bounded reconciliation for expired and orphaned hosted upload lifecycle records",
      entry: path.join(__dirname, "..", "runtime", "shared-jobs", "index.mjs"),
      environment: {
        CONTROL_TABLE_NAME: this.controlTable.tableName,
        JOBS_QUEUE_ARN: this.jobsQueue.queueArn,
        MAINTENANCE_INDEX_NAME: "UploadLifecycleByTenantV2",
        MAXIMUM_EVALUATED_ITEMS: "250",
        MAXIMUM_TENANTS_PER_SWEEP: "25",
        ORPHAN_GRACE_SECONDS: "900",
        SWEEP_LEASE_SECONDS: "300",
      },
      handler: "handler",
      logGroup: jobWorkerLogGroup,
      memorySize: 256,
      projectRoot: path.join(__dirname, ".."),
      reservedConcurrentExecutions: 1,
      role: this.jobWorkerRole,
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: Duration.minutes(5),
    });
    // This explicit dependency is required for the in-place upgrade path from
    // the deployed legacy GSI1 index. CloudFormation must finish creating and
    // backfilling UploadLifecycleByTenantV2 before it updates the worker to
    // query that index; otherwise scheduled invocations can race the GSI update.
    jobWorker.node.addDependency(this.controlTable);
    jobWorker.addEventSource(new lambdaEventSources.SqsEventSource(this.jobsQueue, {
      batchSize: 1,
      // Disabling only EventBridge is insufficient: retained queue messages
      // could otherwise invoke the V2 worker before the manual backfill ends.
      enabled: maintenanceLifecycleMode === "enabled",
      reportBatchItemFailures: true,
    }));

    // This operator-invoked function is deliberately not attached to an event
    // source. Existing lifecycle rows must be migrated tenant by tenant and
    // verified before the scheduled V2 reconciler is enabled in a separate,
    // reviewed deployment.
    const lifecycleBackfillRole = new iam.Role(this, "UploadLifecycleBackfillRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description: "Manual, bounded tenant lifecycle-index backfill with no data-plane or tenant-role access.",
    });
    const lifecycleBackfillAttributes = [
      "PK", "SK", "GSI1PK", "GSI1SK", "consumedAt", "evidenceProjectionDigest", "expiresAt", "id",
      "idempotencyDigest", "intentId", "kind", "promotionLeaseExpiresAt", "promotionLeaseId",
      "reconciliationActionKey", "reconciliationDetectedAt", "reconciliationDisposition",
      "reconciliationReason", "requestFingerprint", "revision", "schemaVersion", "status", "tenantId",
      "ttlEpochSeconds", "validation",
    ];
    lifecycleBackfillRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:Query", "dynamodb:GetItem"],
      conditions: {
        Null: {
          "dynamodb:Attributes": "false",
          "dynamodb:LeadingKeys": "false",
        },
        "ForAllValues:StringEquals": { "dynamodb:Attributes": lifecycleBackfillAttributes },
        "ForAllValues:StringLike": { "dynamodb:LeadingKeys": "TENANT#ten_*" },
      },
      resources: [this.controlTable.tableArn],
    }));
    lifecycleBackfillRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:UpdateItem"],
      conditions: {
        Null: {
          "dynamodb:Attributes": "false",
          "dynamodb:LeadingKeys": "false",
        },
        "ForAllValues:StringEquals": { "dynamodb:Attributes": lifecycleBackfillAttributes },
        "ForAllValues:StringLike": { "dynamodb:LeadingKeys": "TENANT#ten_*" },
        StringEquals: { "dynamodb:EnclosingOperation": "TransactWriteItems" },
        StringEqualsIfExists: { "dynamodb:ReturnValues": "NONE" },
      },
      resources: [this.controlTable.tableArn],
    }));
    const lifecycleBackfillLogGroup = new logs.LogGroup(this, "UploadLifecycleBackfillLogs", {
      encryptionKey: operationsKey,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    lifecycleBackfillRole.addToPolicy(new iam.PolicyStatement({
      actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
      resources: [`${lifecycleBackfillLogGroup.logGroupArn}:*`],
    }));
    const lifecycleBackfill = new lambdaNodejs.NodejsFunction(this, "UploadLifecycleBackfill", {
      architecture: lambda.Architecture.ARM_64,
      bundling: {
        externalModules: [],
        format: lambdaNodejs.OutputFormat.ESM,
        minify: true,
        sourceMap: false,
        target: "node22",
      },
      depsLockFilePath: path.join(__dirname, "..", "pnpm-lock.yaml"),
      description: "Operator-invoked exact-CAS backfill for legacy hosted upload lifecycle authority",
      entry: path.join(__dirname, "..", "runtime", "shared-jobs", "upload-lifecycle-backfill.mjs"),
      environment: {
        CONTROL_TABLE_NAME: this.controlTable.tableName,
        MAXIMUM_BACKFILL_ITEMS: "100",
      },
      handler: "handler",
      logGroup: lifecycleBackfillLogGroup,
      memorySize: 256,
      projectRoot: path.join(__dirname, ".."),
      reservedConcurrentExecutions: 1,
      role: lifecycleBackfillRole,
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: Duration.minutes(5),
    });
    lifecycleBackfill.node.addDependency(this.controlTable);
    for (const alarm of [
      new cloudwatch.Alarm(this, "UploadLifecycleBackfillErrorAlarm", {
        alarmDescription: "A manual hosted lifecycle backfill invocation failed.",
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: lifecycleBackfill.metricErrors({ period: Duration.minutes(5), statistic: "Sum" }),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, "UploadLifecycleBackfillThrottleAlarm", {
        alarmDescription: "A manual hosted lifecycle backfill invocation was throttled.",
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: lifecycleBackfill.metricThrottles({ period: Duration.minutes(5), statistic: "Sum" }),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    ]) alarm.addAlarmAction(new cloudwatchActions.SnsAction(this.operationsTopic));
    new CfnOutput(this, "UploadLifecycleBackfillFunctionArn", {
      description: "Manual tenant-by-tenant lifecycle backfill; never invoke without the staged migration runbook.",
      value: lifecycleBackfill.functionArn,
    });

    const sharedJobMetric = (metricName: string, statistic: string, period = Duration.minutes(5)) => new cloudwatch.Metric({
      namespace: "Scopeproof/SharedJobs",
      metricName,
      dimensionsMap: { JobType: "PendingOrphanReconciliation" },
      period,
      statistic,
    });
    for (const alarm of [
      new cloudwatch.Alarm(this, "SharedJobReconciliationFailureAlarm", {
        alarmDescription: "At least one hosted upload lifecycle record failed bounded shared reconciliation.",
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: sharedJobMetric("Failures", "Maximum"),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, "SharedJobActionRequiredAlarm", {
        alarmDescription: "At least one durable hosted maintenance action remains unresolved.",
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: sharedJobMetric("OutstandingActionRequired", "Maximum", Duration.hours(1)),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, "SharedJobOldestActionRequiredAlarm", {
        alarmDescription: "The oldest unresolved hosted maintenance action is more than thirty minutes old.",
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: sharedJobMetric("OldestActionRequiredAgeSeconds", "Maximum", Duration.hours(1)),
        threshold: 1_800,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, "SharedJobPendingAgeAlarm", {
        alarmDescription: "A pending hosted upload lifecycle observed by shared maintenance is older than thirty minutes.",
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: sharedJobMetric("MaxPendingAgeSeconds", "Maximum"),
        threshold: 1_800,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, "SharedJobHeartbeatAlarm", {
        alarmDescription: "No successful shared maintenance heartbeat was published for two consecutive windows.",
        comparisonOperator: cloudwatch.ComparisonOperator.LESS_THAN_THRESHOLD,
        evaluationPeriods: 2,
        metric: new cloudwatch.Metric({
          namespace: "Scopeproof/SharedJobs",
          metricName: "Invocations",
          dimensionsMap: { JobType: "PendingOrphanReconciliation" },
          period: Duration.minutes(30),
          statistic: "Sum",
        }),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.BREACHING,
      }),
      new cloudwatch.Alarm(this, "SharedJobWorkerErrorAlarm", {
        alarmDescription: "The shared maintenance Lambda returned an error.",
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: jobWorker.metricErrors({ period: Duration.minutes(5), statistic: "Sum" }),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, "SharedJobWorkerThrottleAlarm", {
        alarmDescription: "The shared maintenance Lambda was throttled.",
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: jobWorker.metricThrottles({ period: Duration.minutes(5), statistic: "Sum" }),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    ]) alarm.addAlarmAction(new cloudwatchActions.SnsAction(this.operationsTopic));

    const amplifyServiceRole = new iam.Role(this, "AmplifyServiceRole", {
      assumedBy: new iam.ServicePrincipal("amplify.amazonaws.com"),
      description: "Least-privilege Amplify deployment and runtime logging role.",
    });
    amplifyServiceRole.addToPolicy(
      new iam.PolicyStatement({
        actions: [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:DescribeLogGroups",
          "logs:PutLogEvents",
        ],
        resources: ["*"],
      }),
    );

    const wafLogGroup = new logs.LogGroup(this, "WebAclLogs", {
      encryptionKey: operationsKey,
      logGroupName: `/aws-waf-logs-scopeproof-${this.stackName.toLowerCase()}`,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    const allowedHosts = [
      this.rootDomain,
      `downloads.${this.rootDomain}`,
      ...props.tenantSlugs.map((slug) => `${slug}.${this.rootDomain}`),
      ...props.tenantSlugs.map((slug) => `api-${slug}.${this.rootDomain}`),
    ];
    this.webAcl = new wafv2.CfnWebACL(this, "WebAcl", {
      defaultAction: { allow: {} },
      description: "Regional host allow-list, bounded requests, rate limiting, and AWS managed protections for Amplify",
      name: "scopeproof-amplify-production",
      rules: [
        {
          action: { block: {} },
          name: "RejectUnknownHost",
          priority: 0,
          statement: {
            notStatement: {
              statement: {
                orStatement: {
                  statements: allowedHosts.map((host) => ({
                    byteMatchStatement: {
                      fieldToMatch: { singleHeader: cloudFormationSingleHeader("host") },
                      positionalConstraint: "EXACTLY",
                      searchString: host,
                      textTransformations: [{ priority: 0, type: "LOWERCASE" }],
                    },
                  })),
                },
              },
            },
          },
          visibilityConfig: wafVisibility("RejectUnknownHost"),
        },
        {
          action: { block: {} },
          name: "RejectOversizedRequestBody",
          priority: 1,
          statement: {
            sizeConstraintStatement: {
              comparisonOperator: "GT",
              fieldToMatch: { body: { oversizeHandling: "MATCH" } },
              size: 65_536,
              textTransformations: [{ priority: 0, type: "NONE" }],
            },
          },
          visibilityConfig: wafVisibility("RejectOversizedRequestBody"),
        },
        managedRule("AWSManagedRulesAmazonIpReputationList", 10),
        managedRule("AWSManagedRulesCommonRuleSet", 20),
        managedRule("AWSManagedRulesKnownBadInputsRuleSet", 30),
        {
          action: { block: {} },
          name: "PerIpRateLimit",
          priority: 40,
          statement: {
            rateBasedStatement: {
              aggregateKeyType: "IP",
              evaluationWindowSec: 300,
              limit: 1_000,
            },
          },
          visibilityConfig: wafVisibility("PerIpRateLimit"),
        },
      ],
      scope: "REGIONAL",
      visibilityConfig: wafVisibility("ScopeproofAmplifyWebAcl"),
    });
    new wafv2.CfnLoggingConfiguration(this, "WebAclLogging", {
      logDestinationConfigs: [wafLogGroup.logGroupArn],
      loggingFilter: cloudFormationLoggingFilter(),
      redactedFields: [
        { singleHeader: cloudFormationSingleHeader("authorization") },
        { singleHeader: cloudFormationSingleHeader("cookie") },
      ],
      resourceArn: this.webAcl.attrArn,
    });

    this.amplifyApp = new amplify.CfnApp(this, "AmplifyApp", {
      buildSpec: [
        "version: 1",
        "frontend:",
        "  phases:",
        "    preBuild:",
        "      commands:",
        "        - npm ci --ignore-scripts --cache .npm --prefer-offline",
        "    build:",
        "      commands:",
        "        - npm run build",
        "  artifacts:",
        "    baseDirectory: .next",
        "    files:",
        "      - '**/*'",
        "  cache:",
        "    paths:",
        "      - .npm/**/*",
        "      - .next/cache/**/*",
      ].join("\n"),
      computeRoleArn: this.amplifyComputeRole.roleArn,
      description: "Scopeproof multi-tenant evidence console",
      iamServiceRole: amplifyServiceRole.roleArn,
      name: "scopeproof",
      platform: "WEB_COMPUTE",
    });
    new wafv2.CfnWebACLAssociation(this, "AmplifyWebAclAssociation", {
      resourceArn: this.formatArn({
        arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
        resource: "apps",
        resourceName: this.amplifyApp.attrAppId,
        service: "amplify",
      }),
      webAclArn: this.webAcl.attrArn,
    });
    const amplifyBranch = new amplify.CfnBranch(this, "AmplifyBranch", {
      appId: this.amplifyApp.attrAppId,
      branchName: this.branchName,
      enableAutoBuild: false,
      enablePullRequestPreview: false,
      environmentVariables: [
        { name: "SCOPEPROOF_ROOT_DOMAIN", value: this.rootDomain },
        { name: "SCOPEPROOF_CONTROL_TABLE", value: this.controlTable.tableName },
      ],
      framework: "Next.js - SSR",
      stage: "PRODUCTION",
    });
    const amplifyDomain = new amplify.CfnDomain(this, "AmplifyDomain", {
      appId: this.amplifyApp.attrAppId,
      domainName: this.rootDomain,
      enableAutoSubDomain: false,
      subDomainSettings: [
        { branchName: this.branchName, prefix: "" },
        ...props.tenantSlugs.map((prefix) => ({ branchName: this.branchName, prefix })),
      ],
    });
    amplifyDomain.addResourceDependency(amplifyBranch);
    authDomain.node.addDependency(amplifyDomain);

    this.releaseBucket = new s3.Bucket(this, "ReleaseBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      lifecycleRules: [
        {
          abortIncompleteMultipartUploadAfter: Duration.days(1),
          id: "retain-current-and-expire-old-release-versions",
          noncurrentVersionExpiration: Duration.days(90),
        },
      ],
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy: RemovalPolicy.RETAIN,
      versioned: true,
    });
    this.releaseBucket.policy?.applyRemovalPolicy(RemovalPolicy.RETAIN);
    const releaseAccessLogs = new s3.Bucket(this, "ReleaseAccessLogs", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      lifecycleRules: [{ expiration: Duration.days(365), id: "expire-release-access-logs" }],
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
      removalPolicy: RemovalPolicy.RETAIN,
    });
    releaseAccessLogs.policy?.applyRemovalPolicy(RemovalPolicy.RETAIN);
    const releaseCertificate = new acm.Certificate(this, "ReleaseCertificate", {
      domainName: `downloads.${this.rootDomain}`,
      validation: acm.CertificateValidation.fromDns(this.hostedZone),
    });
    const securityHeaders = new cloudfront.ResponseHeadersPolicy(this, "ReleaseSecurityHeaders", {
      securityHeadersBehavior: {
        contentSecurityPolicy: {
          contentSecurityPolicy: "default-src 'none'; frame-ancestors 'none'; sandbox",
          override: true,
        },
        contentTypeOptions: { override: true },
        frameOptions: { frameOption: cloudfront.HeadersFrameOption.DENY, override: true },
        referrerPolicy: {
          override: true,
          referrerPolicy: cloudfront.HeadersReferrerPolicy.NO_REFERRER,
        },
        strictTransportSecurity: {
          accessControlMaxAge: Duration.days(365),
          includeSubdomains: true,
          override: true,
          preload: true,
        },
        xssProtection: { override: true, protection: true, modeBlock: true },
      },
    });
    const releaseWafLogGroup = new logs.LogGroup(this, "ReleaseWebAclLogs", {
      encryptionKey: operationsKey,
      logGroupName: `/aws-waf-logs-scopeproof-release-${this.stackName.toLowerCase()}`,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    const releaseWebAcl = new wafv2.CfnWebACL(this, "ReleaseWebAcl", {
      defaultAction: { allow: {} },
      description: "CloudFront protections for public Scopeproof release downloads",
      name: "scopeproof-release-production",
      rules: [
        {
          action: { block: {} },
          name: "RejectUnknownReleaseHost",
          priority: 0,
          statement: {
            notStatement: {
              statement: {
                byteMatchStatement: {
                  fieldToMatch: { singleHeader: cloudFormationSingleHeader("host") },
                  positionalConstraint: "EXACTLY",
                  searchString: `downloads.${this.rootDomain}`,
                  textTransformations: [{ priority: 0, type: "LOWERCASE" }],
                },
              },
            },
          },
          visibilityConfig: wafVisibility("RejectUnknownReleaseHost"),
        },
        managedRule("AWSManagedRulesAmazonIpReputationList", 10),
        managedRule("AWSManagedRulesKnownBadInputsRuleSet", 20),
        {
          action: { block: {} },
          name: "ReleasePerIpRateLimit",
          priority: 30,
          statement: {
            rateBasedStatement: {
              aggregateKeyType: "IP",
              evaluationWindowSec: 300,
              limit: 2_000,
            },
          },
          visibilityConfig: wafVisibility("ReleasePerIpRateLimit"),
        },
      ],
      scope: "CLOUDFRONT",
      visibilityConfig: wafVisibility("ScopeproofReleaseWebAcl"),
    });
    new wafv2.CfnLoggingConfiguration(this, "ReleaseWebAclLogging", {
      logDestinationConfigs: [releaseWafLogGroup.logGroupArn],
      loggingFilter: cloudFormationLoggingFilter(),
      redactedFields: [
        { singleHeader: cloudFormationSingleHeader("authorization") },
        { singleHeader: cloudFormationSingleHeader("cookie") },
      ],
      resourceArn: releaseWebAcl.attrArn,
    });
    this.releaseDistribution = new cloudfront.Distribution(this, "ReleaseDistribution", {
      certificate: releaseCertificate,
      comment: "Private S3 origin for public, checksummed Scopeproof release downloads",
      defaultBehavior: {
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        compress: false,
        origin: cloudfrontOrigins.S3BucketOrigin.withOriginAccessControl(this.releaseBucket),
        responseHeadersPolicy: securityHeaders,
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      domainNames: [`downloads.${this.rootDomain}`],
      enableIpv6: true,
      enableLogging: true,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      logBucket: releaseAccessLogs,
      logFilePrefix: "cloudfront/",
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      webAclId: releaseWebAcl.attrArn,
    });
    new route53.ARecord(this, "ReleaseAlias", {
      recordName: "downloads",
      target: route53.RecordTarget.fromAlias(
        new route53Targets.CloudFrontTarget(this.releaseDistribution),
      ),
      zone: this.hostedZone,
    });

    new ses.EmailIdentity(this, "PlatformEmailIdentity", {
      dkimIdentity: ses.DkimIdentity.easyDkim(ses.EasyDkimSigningKeyLength.RSA_2048_BIT),
      feedbackForwarding: true,
      identity: ses.Identity.publicHostedZone(this.hostedZone),
      mailFromBehaviorOnMxFailure: ses.MailFromBehaviorOnMxFailure.REJECT_MESSAGE,
      mailFromDomain: `mail.${this.rootDomain}`,
    });

    new budgets.CfnBudget(this, "MonthlyBudget", {
      budget: {
        budgetLimit: { amount: monthlyBudgetUsd, unit: "USD" },
        budgetName: "scopeproof-monthly-cost",
        budgetType: "COST",
        timeUnit: "MONTHLY",
      },
      notificationsWithSubscribers: props.alertEmail
        ? [
            {
              notification: {
                comparisonOperator: "GREATER_THAN",
                notificationType: "FORECASTED",
                threshold: 80,
                thresholdType: "PERCENTAGE",
              },
              subscribers: [{ address: props.alertEmail, subscriptionType: "EMAIL" }],
            },
            {
              notification: {
                comparisonOperator: "GREATER_THAN",
                notificationType: "ACTUAL",
                threshold: 100,
                thresholdType: "PERCENTAGE",
              },
              subscribers: [{ address: props.alertEmail, subscriptionType: "EMAIL" }],
            },
          ]
        : undefined,
    });
    const anomalyMonitor = new ce.CfnAnomalyMonitor(this, "ServiceCostAnomalyMonitor", {
      monitorDimension: "SERVICE",
      monitorName: "scopeproof-service-cost-anomalies",
      monitorType: "DIMENSIONAL",
    });
    if (props.alertEmail) {
      new ce.CfnAnomalySubscription(this, "CostAnomalySubscription", {
        frequency: "DAILY",
        monitorArnList: [anomalyMonitor.attrMonitorArn],
        subscribers: [{ address: props.alertEmail, type: "EMAIL" }],
        subscriptionName: "scopeproof-daily-cost-anomalies",
        threshold: Math.max(10, monthlyBudgetUsd * 0.1),
      });
    }

    new CfnOutput(this, "RootDomain", { value: this.rootDomain });
    new CfnOutput(this, "HostedZoneId", { value: this.hostedZone.hostedZoneId });
    new CfnOutput(this, "AmplifyAppId", { value: this.amplifyApp.attrAppId });
    new CfnOutput(this, "AmplifyDefaultDomain", { value: this.amplifyApp.attrDefaultDomain });
    new CfnOutput(this, "CognitoUserPoolId", { value: this.userPool.userPoolId });
    new CfnOutput(this, "CognitoLoginDomain", { value: `https://auth.${this.rootDomain}` });
    new CfnOutput(this, "ControlPlaneTableName", { value: this.controlTable.tableName });
    new CfnOutput(this, "CustomerActivationTableName", {
      description: "Out-of-band CUSTOMER_ENABLED approvals; no application principal has write access",
      value: this.customerActivationTable.tableName,
    });
    new CfnOutput(this, "CustomerActivationTableArn", {
      value: this.customerActivationTable.tableArn,
    });
    new CfnOutput(this, "DatabaseClusterArn", { value: this.databaseCluster.clusterArn });
    new CfnOutput(this, "JobsQueueUrl", { value: this.jobsQueue.queueUrl });
    new CfnOutput(this, "OperationsTopicArn", { value: this.operationsTopic.topicArn });
    new CfnOutput(this, "ReleaseBucketName", { value: this.releaseBucket.bucketName });
    new CfnOutput(this, "ReleaseDownloadOrigin", { value: `https://downloads.${this.rootDomain}` });
  }
}

function wafVisibility(metricName: string): wafv2.CfnWebACL.VisibilityConfigProperty {
  return {
    cloudWatchMetricsEnabled: true,
    metricName,
    sampledRequestsEnabled: true,
  };
}

function cloudFormationSingleHeader(name: string): wafv2.CfnWebACL.SingleHeaderProperty {
  // SingleHeader is nested below a union-typed statement array. Supplying the
  // CloudFormation spelling avoids the L1 renderer leaving a lowercase `name`
  // key in the synthesized template.
  return { Name: name } as unknown as wafv2.CfnWebACL.SingleHeaderProperty;
}

function cloudFormationLoggingFilter(): wafv2.CfnLoggingConfiguration.LoggingFilterProperty {
  // See cloudFormationSingleHeader: this is also nested beneath a union-typed
  // property and therefore must retain CloudFormation's exact key casing.
  return {
    DefaultBehavior: "DROP",
    Filters: [
      {
        Behavior: "KEEP",
        Conditions: [{ ActionCondition: { Action: "BLOCK" } }],
        Requirement: "MEETS_ANY",
      },
    ],
  } as unknown as wafv2.CfnLoggingConfiguration.LoggingFilterProperty;
}

function managedRule(name: string, priority: number): wafv2.CfnWebACL.RuleProperty {
  return {
    name,
    overrideAction: { none: {} },
    priority,
    statement: {
      managedRuleGroupStatement: {
        name,
        vendorName: "AWS",
      },
    },
    visibilityConfig: wafVisibility(name),
  };
}
