import {
  ArnFormat,
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  StackProps,
  Tags,
} from "aws-cdk-lib";
import * as path from "node:path";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as cr from "aws-cdk-lib/custom-resources";
import * as events from "aws-cdk-lib/aws-events";
import * as eventTargets from "aws-cdk-lib/aws-events-targets";
import * as guardduty from "aws-cdk-lib/aws-guardduty";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaEventSources from "aws-cdk-lib/aws-lambda-event-sources";
import * as logs from "aws-cdk-lib/aws-logs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as sfn from "aws-cdk-lib/aws-stepfunctions";
import * as sfnTasks from "aws-cdk-lib/aws-stepfunctions-tasks";
import * as sqs from "aws-cdk-lib/aws-sqs";
import { Construct } from "constructs";
import { tenantDatabaseIdentifiers, TenantDefinition } from "./config";
import { SharedPlatformStack } from "./shared-platform-stack";

export interface TenantStackProps extends StackProps {
  readonly rootDomain: string;
  readonly tenant: TenantDefinition;
  readonly shared: SharedPlatformStack;
}

export class TenantStack extends Stack {
  public readonly evidenceBucket: s3.Bucket;
  public readonly ingestBucket: s3.Bucket;
  public readonly ingestDeadLetterQueue: sqs.Queue;
  public readonly provisioningStateMachine: sfn.StateMachine;

  public constructor(scope: Construct, id: string, props: TenantStackProps) {
    super(scope, id, props);
    const { tenant, shared } = props;
    const hostname = `${tenant.slug}.${props.rootDomain}`;
    const tenantOrigin = `https://${hostname}`;
    const retentionDays = tenant.retentionDays ?? 365;
    const databaseIdentifiers = tenantDatabaseIdentifiers(tenant);
    const databaseIdentifier = databaseIdentifiers.databaseName;
    const databaseUsername = databaseIdentifiers.runtimeUsername;
    const databaseOwner = databaseIdentifiers.ownerUsername;

    Tags.of(this).add("TenantId", tenant.id);
    Tags.of(this).add("TenantSlug", tenant.slug);

    const userPoolClient = new cognito.UserPoolClient(this, "TenantWebClient", {
      accessTokenValidity: Duration.hours(1),
      authFlows: { userSrp: true },
      enableTokenRevocation: true,
      generateSecret: false,
      idTokenValidity: Duration.hours(1),
      oAuth: {
        callbackUrls: [`${tenantOrigin}/auth/callback`],
        flows: { authorizationCodeGrant: true },
        logoutUrls: [`${tenantOrigin}/`],
        scopes: [
          cognito.OAuthScope.OPENID,
          cognito.OAuthScope.EMAIL,
          cognito.OAuthScope.PROFILE,
        ],
      },
      preventUserExistenceErrors: true,
      refreshTokenValidity: Duration.days(7),
      supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.COGNITO],
      userPool: shared.userPool,
      userPoolClientName: `scopeproof-${tenant.slug}-web`,
    });

    const tenantKey = new kms.Key(this, "TenantEvidenceKey", {
      alias: `alias/scopeproof/${tenant.slug}/evidence`,
      description: `Evidence and quarantine object encryption for ${tenant.id}`,
      enableKeyRotation: true,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN,
    });

    this.ingestBucket = new s3.Bucket(this, "IngestBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      bucketKeyEnabled: true,
      cors: [
        {
          allowedHeaders: ["content-type", "x-amz-*"],
          allowedMethods: [s3.HttpMethods.PUT],
          allowedOrigins: [tenantOrigin],
          exposedHeaders: ["ETag", "x-amz-checksum-sha256", "x-amz-request-id"],
          maxAge: 300,
        },
      ],
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: tenantKey,
      enforceSSL: true,
      lifecycleRules: [
        {
          abortIncompleteMultipartUploadAfter: Duration.days(1),
          expiration: Duration.days(1),
          id: "expire-quarantine",
          noncurrentVersionExpiration: Duration.days(1),
        },
      ],
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy: RemovalPolicy.RETAIN,
      versioned: true,
    });
    const retention = tenant.retentionMode === "COMPLIANCE"
      ? s3.ObjectLockRetention.compliance(Duration.days(retentionDays))
      : s3.ObjectLockRetention.governance(Duration.days(retentionDays));
    this.evidenceBucket = new s3.Bucket(this, "EvidenceBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      bucketKeyEnabled: true,
      cors: [
        {
          allowedHeaders: ["*"],
          allowedMethods: [s3.HttpMethods.GET, s3.HttpMethods.HEAD],
          allowedOrigins: [tenantOrigin],
          exposedHeaders: [
            "ETag",
            "x-amz-checksum-sha256",
            "x-amz-version-id",
            "x-amz-request-id",
          ],
          maxAge: 300,
        },
      ],
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: tenantKey,
      enforceSSL: true,
      objectLockDefaultRetention: retention,
      objectLockEnabled: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      removalPolicy: RemovalPolicy.RETAIN,
      versioned: true,
    });
    const ingestBucket = this.ingestBucket;
    const evidenceBucket = this.evidenceBucket;

    const tenantSecretKey = new kms.Key(this, "TenantSecretKey", {
      alias: `alias/scopeproof/${tenant.slug}/secrets`,
      description: `Tenant-scoped credential encryption for ${tenant.id}`,
      enableKeyRotation: true,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const databaseSecret = new secretsmanager.Secret(this, "TenantDatabaseSecret", {
      description: `Database credentials reserved for ${tenant.id}`,
      encryptionKey: tenantSecretKey,
      generateSecretString: {
        excludePunctuation: true,
        generateStringKey: "password",
        passwordLength: 40,
        secretStringTemplate: JSON.stringify({
          database: databaseIdentifier,
          username: databaseUsername,
        }),
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const tenantDataRole = new iam.Role(this, "TenantDataRole", {
      assumedBy: new iam.CompositePrincipal(
        new iam.ArnPrincipal(shared.amplifyComputeRole.roleArn),
        new iam.ArnPrincipal(shared.jobWorkerRole.roleArn),
      ),
      description: `Runtime access boundary for ${tenant.id}`,
      maxSessionDuration: Duration.hours(1),
      path: "/scopeproof/tenants/",
      roleName: `sp-${tenant.slug}-data`,
    });
    const quarantineEncryptionContext = Buffer.from(
      JSON.stringify({
        scopeproofPurpose: "quarantine",
        scopeproofTenantId: tenant.id,
      }),
    ).toString("base64");
    tenantDataRole.addToPolicy(
      new iam.PolicyStatement({
        actions: [
          "rds-data:BatchExecuteStatement",
          "rds-data:BeginTransaction",
          "rds-data:CommitTransaction",
          "rds-data:ExecuteStatement",
          "rds-data:RollbackTransaction",
        ],
        resources: [shared.databaseCluster.clusterArn],
      }),
    );
    databaseSecret.grantRead(tenantDataRole);
    tenantDataRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:scopeproofPurpose": ["immutable-evidence", "quarantine"],
            "kms:EncryptionContext:scopeproofTenantId": tenant.id,
            "kms:ViaService": `s3.${this.region}.amazonaws.com`,
          },
        },
        resources: [tenantKey.keyArn],
      }),
    );
    tenantDataRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["s3:ListBucket", "s3:ListBucketVersions"],
        conditions: {
          StringLike: {
            "s3:prefix": [`tenants/${tenant.id}/quarantine/*`],
          },
        },
        resources: [ingestBucket.bucketArn],
      }),
    );
    tenantDataRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["s3:ListBucket", "s3:ListBucketVersions"],
        conditions: {
          StringLike: {
            "s3:prefix": [`tenants/${tenant.id}/evidence/*`],
          },
        },
        resources: [evidenceBucket.bucketArn],
      }),
    );
    tenantDataRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["s3:GetBucketLocation"],
        resources: [ingestBucket.bucketArn, evidenceBucket.bucketArn],
      }),
    );
    tenantDataRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["s3:PutObject"],
        conditions: {
          StringEquals: {
            "s3:x-amz-server-side-encryption": "aws:kms",
            "s3:x-amz-server-side-encryption-aws-kms-key-id": tenantKey.keyArn,
            "s3:x-amz-server-side-encryption-context": quarantineEncryptionContext,
          },
        },
        resources: [ingestBucket.arnForObjects(`tenants/${tenant.id}/quarantine/*`)],
      }),
    );
    tenantDataRole.addToPolicy(
      new iam.PolicyStatement({
        actions: ["s3:AbortMultipartUpload"],
        resources: [ingestBucket.arnForObjects(`tenants/${tenant.id}/quarantine/*`)],
      }),
    );
    tenantDataRole.addToPolicy(
      new iam.PolicyStatement({
        actions: [
          "s3:GetObject",
          "s3:GetObjectRetention",
          "s3:GetObjectVersion",
        ],
        resources: [evidenceBucket.arnForObjects(`tenants/${tenant.id}/evidence/*`)],
      }),
    );

    const databaseAdminSecret = shared.databaseCluster.secret;
    if (!databaseAdminSecret) {
      throw new Error("The shared database cluster must expose an administrator secret.");
    }
    const provisionerLogGroup = new logs.LogGroup(this, "TenantProvisionerLogs", {
      encryptionKey: tenantKey,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    const provisioner = new lambda.Function(this, "TenantProvisioner", {
      architecture: lambda.Architecture.ARM_64,
      code: lambda.Code.fromAsset(path.join(__dirname, "..", ".."), {
        exclude: [
          "cdk/cdk.out/**",
          "cdk/node_modules/**",
          "cdk/test/**",
          "cdk/*.json",
          "cdk/*.yaml",
          "cdk/*.lock",
          "cdk/README.md",
        ],
      }),
      description: `Idempotently creates and verifies the PostgreSQL boundary for ${tenant.id}`,
      environment: {
        ADMIN_SECRET_ARN: databaseAdminSecret.secretArn,
        AWS_ACCOUNT_ID_EXPECTED: this.account,
        AWS_REGION_EXPECTED: this.region,
        CANONICAL_HOSTNAME: hostname,
        CONTROL_TABLE_NAME: shared.controlTable.tableName,
        DATABASE_CLUSTER_ARN: shared.databaseCluster.clusterArn,
        DATABASE_NAME: databaseIdentifier,
        DATABASE_OWNER: databaseOwner,
        DATABASE_SECRET_ARN: databaseSecret.secretArn,
        DATABASE_USERNAME: databaseUsername,
        DISPLAY_NAME: tenant.displayName,
        DOMAIN_HOSTNAME: hostname,
        EVIDENCE_BUCKET_NAME: evidenceBucket.bucketName,
        EVIDENCE_KEY_ARN: tenantKey.keyArn,
        HOSTED_ZONE_ID: shared.hostedZone.hostedZoneId,
        QUARANTINE_BUCKET_NAME: ingestBucket.bucketName,
        TENANT_CNAME_TARGET: `${shared.branchName}.${shared.amplifyApp.attrDefaultDomain}`,
        RETENTION_DAYS: String(retentionDays),
        RETENTION_MODE: tenant.retentionMode ?? "GOVERNANCE",
        TENANT_SLUG: tenant.slug,
        TENANT_ID: tenant.id,
      },
      handler: "cdk/runtime/provision-tenant/index.handler",
      logGroup: provisionerLogGroup,
      memorySize: 256,
      reservedConcurrentExecutions: 2,
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: Duration.minutes(5),
      tracing: lambda.Tracing.ACTIVE,
    });
    provisioner.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["dynamodb:TransactWriteItems"],
        conditions: {
          "ForAllValues:StringEquals": {
            "dynamodb:LeadingKeys": [`TENANT#${tenant.id}`, `DOMAIN#${hostname}`],
          },
        },
        resources: [shared.controlTable.tableArn],
      }),
    );
    provisioner.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "rds-data:BatchExecuteStatement",
          "rds-data:BeginTransaction",
          "rds-data:CommitTransaction",
          "rds-data:ExecuteStatement",
          "rds-data:RollbackTransaction",
        ],
        resources: [shared.databaseCluster.clusterArn],
      }),
    );
    provisioner.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"],
        resources: [databaseAdminSecret.secretArn],
      }),
    );
    if (!databaseAdminSecret.encryptionKey) {
      throw new Error("The shared database administrator secret must use a customer-managed KMS key.");
    }
    provisioner.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["kms:Decrypt"],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:SecretARN": databaseAdminSecret.secretArn,
            "kms:ViaService": `secretsmanager.${this.region}.amazonaws.com`,
          },
        },
        resources: [databaseAdminSecret.encryptionKey.keyArn],
      }),
    );
    databaseSecret.grantRead(provisioner);
    provisioner.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["route53:ChangeResourceRecordSets"],
        conditions: {
          "ForAllValues:StringEquals": {
            "route53:ChangeResourceRecordSetsActions": ["UPSERT"],
            "route53:ChangeResourceRecordSetsNormalizedRecordNames": [hostname],
            "route53:ChangeResourceRecordSetsRecordTypes": ["CNAME"],
          },
        },
        resources: [
          `arn:${this.partition}:route53:::hostedzone/${shared.hostedZone.hostedZoneId}`,
        ],
      }),
    );
    provisioner.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["route53:GetChange"],
        resources: [`arn:${this.partition}:route53:::change/*`],
      }),
    );

    const leaseRejected = new sfn.Fail(this, "ProvisioningLeaseRejected", {
      cause: "Tenant is active, suspended, or already has a different provisioning execution.",
      error: "Scopeproof.ProvisioningLeaseRejected",
    });
    const provisioningFailed = new sfn.Fail(this, "ProvisioningFailed", {
      cause: "Tenant initialization failed. The registry is marked FAILED and may be retried.",
      error: "Scopeproof.ProvisioningFailed",
    });
    const provisioningSucceeded = new sfn.Succeed(this, "ProvisioningSucceeded");
    const markFailed = new sfnTasks.LambdaInvoke(this, "MarkTenantFailed", {
      lambdaFunction: provisioner,
      payload: sfn.TaskInput.fromObject({
        action: "fail",
        errorName: sfn.JsonPath.stringAt("$.failure.Error"),
        executionId: sfn.JsonPath.executionId,
      }),
      payloadResponseOnly: true,
    });
    markFailed.addCatch(provisioningFailed, { resultPath: sfn.JsonPath.DISCARD });
    markFailed.next(provisioningFailed);
    const acquireLease = tenantProvisioningTask(this, "AcquireProvisioningLease", provisioner, "acquire");
    acquireLease.addCatch(leaseRejected, {
      errors: ["LeaseRejected"],
      resultPath: "$.failure",
    });
    acquireLease.addCatch(provisioningFailed, {
      errors: ["States.ALL"],
      resultPath: "$.failure",
    });
    const initializeDatabase = tenantProvisioningTask(
      this,
      "InitializeTenantDatabase",
      provisioner,
      "initialize",
    );
    const verifyDatabase = tenantProvisioningTask(
      this,
      "VerifyTenantDatabase",
      provisioner,
      "verify",
    );
    const activateTenant = tenantProvisioningTask(this, "ActivateTenant", provisioner, "activate");
    for (const task of [initializeDatabase, verifyDatabase, activateTenant]) {
      task.addCatch(markFailed, { resultPath: "$.failure" });
    }
    acquireLease.next(initializeDatabase).next(verifyDatabase).next(activateTenant).next(provisioningSucceeded);
    const stateMachineLogGroup = new logs.LogGroup(this, "TenantProvisioningWorkflowLogs", {
      encryptionKey: tenantKey,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    this.provisioningStateMachine = new sfn.StateMachine(this, "TenantProvisioningWorkflow", {
      definitionBody: sfn.DefinitionBody.fromChainable(acquireLease),
      logs: {
        destination: stateMachineLogGroup,
        includeExecutionData: false,
        level: sfn.LogLevel.ALL,
      },
      stateMachineType: sfn.StateMachineType.STANDARD,
      timeout: Duration.minutes(15),
      tracingEnabled: true,
    });

    const guardDutyRole = new iam.Role(this, "GuardDutyMalwareProtectionRole", {
      assumedBy: new iam.ServicePrincipal("malware-protection-plan.guardduty.amazonaws.com"),
      description: `Exact-bucket malware scan role for ${tenant.id}`,
    });
    const guardDutyPolicy = new iam.Policy(this, "GuardDutyMalwareProtectionPolicy", {
      statements: [
        new iam.PolicyStatement({
          actions: ["events:PutRule", "events:DeleteRule", "events:PutTargets", "events:RemoveTargets"],
          conditions: {
            StringLike: {
              "events:ManagedBy": "malware-protection-plan.guardduty.amazonaws.com",
            },
          },
          resources: [
            this.formatArn({
              arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
              resource: "rule",
              resourceName: "DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*",
              service: "events",
            }),
          ],
        }),
        new iam.PolicyStatement({
          actions: ["events:DescribeRule", "events:ListTargetsByRule"],
          resources: [
            this.formatArn({
              arnFormat: ArnFormat.SLASH_RESOURCE_NAME,
              resource: "rule",
              resourceName: "DO-NOT-DELETE-AmazonGuardDutyMalwareProtectionS3*",
              service: "events",
            }),
          ],
        }),
        new iam.PolicyStatement({
          actions: [
            "s3:PutObjectTagging",
            "s3:GetObjectTagging",
            "s3:PutObjectVersionTagging",
            "s3:GetObjectVersionTagging",
            "s3:GetObject",
            "s3:GetObjectVersion",
          ],
          resources: [ingestBucket.arnForObjects("*")],
        }),
        new iam.PolicyStatement({
          actions: ["s3:PutBucketNotification", "s3:GetBucketNotification", "s3:ListBucket"],
          resources: [ingestBucket.bucketArn],
        }),
        new iam.PolicyStatement({
          actions: ["s3:PutObject"],
          resources: [ingestBucket.arnForObjects("malware-protection-resource-validation-object")],
        }),
        new iam.PolicyStatement({
          actions: ["kms:Decrypt", "kms:GenerateDataKey"],
          conditions: {
            StringLike: { "kms:ViaService": `s3.${this.region}.amazonaws.com` },
          },
          resources: [tenantKey.keyArn],
        }),
      ],
    });
    guardDutyPolicy.attachToRole(guardDutyRole);
    const malwareProtectionPlan = new guardduty.CfnMalwareProtectionPlan(
      this,
      "IngestMalwareProtectionPlan",
      {
        actions: { tagging: { status: "ENABLED" } },
        protectedResource: { s3Bucket: { bucketName: ingestBucket.bucketName } },
        role: guardDutyRole.roleArn,
        tags: [
          { key: "TenantId", value: tenant.id },
          { key: "Purpose", value: "EvidenceQuarantine" },
        ],
      },
    );
    malwareProtectionPlan.node.addDependency(guardDutyPolicy);

    this.ingestDeadLetterQueue = new sqs.Queue(this, "IngestDeadLetterQueue", {
      enforceSSL: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: Duration.days(14),
    });
    const cleanEvidenceQueue = new sqs.Queue(this, "CleanEvidenceQueue", {
      deadLetterQueue: { maxReceiveCount: 3, queue: this.ingestDeadLetterQueue },
      enforceSSL: true,
      encryption: sqs.QueueEncryption.SQS_MANAGED,
      retentionPeriod: Duration.days(4),
      visibilityTimeout: Duration.minutes(6),
    });
    const cleanScanRule = new events.Rule(this, "CleanMalwareScanResult", {
      description: `Queues only successful NO_THREATS_FOUND scans for ${tenant.id}`,
      enabled: false,
      eventPattern: {
        detail: {
          s3ObjectDetails: { bucketName: [ingestBucket.bucketName] },
          scanResultDetails: { scanResultStatus: ["NO_THREATS_FOUND"] },
          scanStatus: ["COMPLETED"],
        },
        detailType: ["GuardDuty Malware Protection Object Scan Result"],
        source: ["aws.guardduty"],
      },
      targets: [new eventTargets.SqsQueue(cleanEvidenceQueue)],
    });
    cleanScanRule.node.addDependency(malwareProtectionPlan);
    const rejectedScanRule = new events.Rule(this, "RejectedOrFailedMalwareScan", {
      description: `Alerts on unsafe, unsupported, denied, or failed scans for ${tenant.id}`,
      eventPattern: {
        detail: {
          s3ObjectDetails: { bucketName: [ingestBucket.bucketName] },
          scanResultDetails: {
            scanResultStatus: ["THREATS_FOUND", "UNSUPPORTED", "ACCESS_DENIED", "FAILED"],
          },
        },
        detailType: ["GuardDuty Malware Protection Object Scan Result"],
        source: ["aws.guardduty"],
      },
      targets: [new eventTargets.SnsTopic(shared.operationsTopic)],
    });
    rejectedScanRule.node.addDependency(malwareProtectionPlan);

    const promoterLogGroup = new logs.LogGroup(this, "EvidencePromoterLogs", {
      encryptionKey: tenantKey,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    const promoter = new lambda.Function(this, "EvidencePromoter", {
      architecture: lambda.Architecture.ARM_64,
      code: lambda.Code.fromAsset(path.join(__dirname, "..", "runtime", "promote-evidence")),
      description: `Validates and immutably promotes malware-cleared evidence for ${tenant.id}`,
      environment: {
        AWS_ACCOUNT_ID_EXPECTED: this.account,
        AWS_REGION_EXPECTED: this.region,
        CONTROL_TABLE_NAME: shared.controlTable.tableName,
        EVIDENCE_BUCKET_NAME: evidenceBucket.bucketName,
        EVIDENCE_KEY_ARN: tenantKey.keyArn,
        INGEST_BUCKET_NAME: ingestBucket.bucketName,
        MALWARE_PROTECTION_PLAN_ARN: malwareProtectionPlan.attrArn,
        MAX_OBJECT_BYTES: String(25 * 1024 * 1024),
        RETENTION_DAYS: String(retentionDays),
        RETENTION_MODE: tenant.retentionMode ?? "GOVERNANCE",
        TENANT_ID: tenant.id,
      },
      handler: "index.handler",
      logGroup: promoterLogGroup,
      memorySize: 512,
      reservedConcurrentExecutions: 5,
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: Duration.minutes(5),
      tracing: lambda.Tracing.ACTIVE,
    });
    promoter.addEventSource(
      new lambdaEventSources.SqsEventSource(cleanEvidenceQueue, {
        batchSize: 5,
        maxBatchingWindow: Duration.seconds(30),
        reportBatchItemFailures: true,
      }),
    );
    promoter.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["dynamodb:GetItem", "dynamodb:TransactWriteItems"],
        conditions: {
          "ForAllValues:StringEquals": {
            "dynamodb:LeadingKeys": [`TENANT#${tenant.id}`],
          },
        },
        resources: [shared.controlTable.tableArn],
      }),
    );
    promoter.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "s3:DeleteObjectVersion",
          "s3:GetObject",
          "s3:GetObjectTagging",
          "s3:GetObjectVersion",
          "s3:GetObjectVersionTagging",
        ],
        resources: [ingestBucket.arnForObjects(`tenants/${tenant.id}/quarantine/*`)],
      }),
    );
    promoter.addToRolePolicy(
      new iam.PolicyStatement({
        actions: [
          "s3:GetObject",
          "s3:GetObjectRetention",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:PutObjectRetention",
          "s3:PutObjectTagging",
        ],
        resources: [evidenceBucket.arnForObjects(`tenants/${tenant.id}/evidence/*`)],
      }),
    );
    promoter.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:scopeproofPurpose": ["immutable-evidence", "quarantine"],
            "kms:EncryptionContext:scopeproofTenantId": tenant.id,
            "kms:ViaService": `s3.${this.region}.amazonaws.com`,
          },
        },
        resources: [tenantKey.keyArn],
      }),
    );

    new cloudwatch.Alarm(this, "IngestDeadLetterAlarm", {
      alarmDescription: `Evidence promotion requires operator intervention for ${tenant.id}.`,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      evaluationPeriods: 1,
      metric: this.ingestDeadLetterQueue.metricApproximateNumberOfMessagesVisible({
        period: Duration.minutes(1),
        statistic: "Maximum",
      }),
      threshold: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction(new cloudwatchActions.SnsAction(shared.operationsTopic));
    new cr.AwsCustomResource(this, "RegisterTenant", {
      installLatestAwsSdk: false,
      onCreate: tenantRegistryUpdate(
        shared.controlTable.tableName,
        tenant,
        hostname,
        userPoolClient.userPoolClientId,
        tenantDataRole.roleArn,
        ingestBucket.bucketName,
        evidenceBucket.bucketName,
        tenantKey.keyArn,
        databaseIdentifier,
        databaseSecret.secretArn,
        true,
      ),
      onUpdate: tenantRegistryUpdate(
        shared.controlTable.tableName,
        tenant,
        hostname,
        userPoolClient.userPoolClientId,
        tenantDataRole.roleArn,
        ingestBucket.bucketName,
        evidenceBucket.bucketName,
        tenantKey.keyArn,
        databaseIdentifier,
        databaseSecret.secretArn,
        false,
      ),
      policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
        resources: [shared.controlTable.tableArn],
      }),
    });

    new CfnOutput(this, "TenantHostname", { value: hostname });
    new CfnOutput(this, "TenantId", { value: tenant.id });
    new CfnOutput(this, "CognitoAppClientId", { value: userPoolClient.userPoolClientId });
    new CfnOutput(this, "TenantDataRoleArn", { value: tenantDataRole.roleArn });
    new CfnOutput(this, "IngestBucketName", { value: ingestBucket.bucketName });
    new CfnOutput(this, "EvidenceBucketName", { value: evidenceBucket.bucketName });
    new CfnOutput(this, "EvidenceKeyArn", { value: tenantKey.keyArn });
    new CfnOutput(this, "TenantDatabaseName", { value: databaseIdentifier });
    new CfnOutput(this, "TenantDatabaseUsername", { value: databaseUsername });
    new CfnOutput(this, "TenantDatabaseSecretArn", { value: databaseSecret.secretArn });
    new CfnOutput(this, "TenantProvisioningStateMachineArn", {
      value: this.provisioningStateMachine.stateMachineArn,
    });
    new CfnOutput(this, "IngestDeadLetterQueueUrl", {
      value: this.ingestDeadLetterQueue.queueUrl,
    });
    new CfnOutput(this, "MalwareProtectionPlanId", {
      value: malwareProtectionPlan.attrMalwareProtectionPlanId,
    });
    new CfnOutput(this, "HostedPromotionRuleName", { value: cleanScanRule.ruleName });
    new CfnOutput(this, "HostedPromotionActivationState", {
      value: "DISABLED_PENDING_UPLOAD_INTENT_ISSUER",
    });
  }
}

function tenantProvisioningTask(
  scope: Construct,
  id: string,
  provisioner: lambda.IFunction,
  action: "acquire" | "initialize" | "verify" | "activate",
): sfnTasks.LambdaInvoke {
  const task = new sfnTasks.LambdaInvoke(scope, id, {
    lambdaFunction: provisioner,
    payload: sfn.TaskInput.fromObject({
      action,
      executionId: sfn.JsonPath.executionId,
    }),
    payloadResponseOnly: true,
    retryOnServiceExceptions: false,
  });
  task.addRetry({
    backoffRate: 2,
    errors: [
      "Lambda.ClientExecutionTimeoutException",
      "Lambda.ServiceException",
      "Lambda.SdkClientException",
      "Lambda.TooManyRequestsException",
    ],
    interval: Duration.seconds(2),
    maxAttempts: 4,
  });
  return task;
}

function tenantRegistryUpdate(
  tableName: string,
  tenant: TenantDefinition,
  hostname: string,
  appClientId: string,
  roleArn: string,
  ingestBucket: string,
  evidenceBucket: string,
  keyArn: string,
  databaseName: string,
  databaseSecretArn: string,
  initializeStatus: boolean,
): cr.AwsSdkCall {
  return {
    service: "DynamoDB",
    action: "transactWriteItems",
    parameters: {
      TransactItems: [
        {
          Update: {
            TableName: tableName,
            Key: {
              PK: { S: `TENANT#${tenant.id}` },
              SK: { S: "METADATA" },
            },
            ConditionExpression: initializeStatus
              ? "attribute_not_exists(PK) OR (#slug = :slug AND #hostname = :hostname)"
              : "attribute_exists(PK) AND #slug = :slug AND #hostname = :hostname AND attribute_not_exists(provisionExecutionId)",
            UpdateExpression: [
              "SET #kind = :kind",
              "#slug = :slug",
              "#displayName = :displayName",
              "#hostname = :hostname",
              "#status = :provisioning",
              "#appClientId = :appClientId",
              "#roleArn = :roleArn",
              "#ingestBucket = :ingestBucket",
              "#evidenceBucket = :evidenceBucket",
              "#keyArn = :keyArn",
              "#databaseName = :databaseName",
              "#databaseSecretArn = :databaseSecretArn",
              "#retentionDays = :retentionDays",
              "#retentionMode = :retentionMode",
            ].join(", "),
            ExpressionAttributeNames: {
              "#kind": "kind",
              "#slug": "slug",
              "#displayName": "displayName",
              "#hostname": "hostname",
              "#status": "status",
              "#appClientId": "appClientId",
              "#roleArn": "tenantDataRoleArn",
              "#ingestBucket": "ingestBucket",
              "#evidenceBucket": "evidenceBucket",
              "#keyArn": "evidenceKeyArn",
              "#databaseName": "databaseName",
              "#databaseSecretArn": "databaseSecretArn",
              "#retentionDays": "retentionDays",
              "#retentionMode": "retentionMode",
            },
            ExpressionAttributeValues: {
              ":kind": { S: "Tenant" },
              ":slug": { S: tenant.slug },
              ":displayName": { S: tenant.displayName },
              ":hostname": { S: hostname },
              ":provisioning": { S: "PROVISIONING" },
              ":appClientId": { S: appClientId },
              ":roleArn": { S: roleArn },
              ":ingestBucket": { S: ingestBucket },
              ":evidenceBucket": { S: evidenceBucket },
              ":keyArn": { S: keyArn },
              ":databaseName": { S: databaseName },
              ":databaseSecretArn": { S: databaseSecretArn },
              ":retentionDays": { N: String(tenant.retentionDays ?? 365) },
              ":retentionMode": { S: tenant.retentionMode ?? "GOVERNANCE" },
            },
          },
        },
        {
          Update: {
            TableName: tableName,
            Key: {
              PK: { S: `DOMAIN#${hostname}` },
              SK: { S: "METADATA" },
            },
            ConditionExpression: initializeStatus
              ? "attribute_not_exists(PK) OR #tenantId = :tenantId"
              : "attribute_exists(PK) AND #tenantId = :tenantId AND attribute_not_exists(provisionExecutionId)",
            UpdateExpression: [
              "SET #kind = :kind",
              "#tenantId = :tenantId",
              "#hostname = :hostname",
              "#status = :provisioning",
            ].join(", "),
            ExpressionAttributeNames: {
              "#kind": "kind",
              "#tenantId": "tenantId",
              "#hostname": "hostname",
              "#status": "status",
            },
            ExpressionAttributeValues: {
              ":kind": { S: "TenantDomain" },
              ":tenantId": { S: tenant.id },
              ":hostname": { S: hostname },
              ":provisioning": { S: "PROVISIONING" },
            },
          },
        },
      ],
    },
    physicalResourceId: cr.PhysicalResourceId.of(`tenant-registry-${tenant.id}`),
  };
}
