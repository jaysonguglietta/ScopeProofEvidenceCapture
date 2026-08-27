import {
  ArnFormat,
  CfnOutput,
  Duration,
  RemovalPolicy,
  Size,
  Stack,
  StackProps,
  Tags,
} from "aws-cdk-lib";
import * as path from "node:path";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import * as apigateway from "aws-cdk-lib/aws-apigateway";
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
import * as lambdaNodejs from "aws-cdk-lib/aws-lambda-nodejs";
import * as logs from "aws-cdk-lib/aws-logs";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as route53Targets from "aws-cdk-lib/aws-route53-targets";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import * as sfn from "aws-cdk-lib/aws-stepfunctions";
import * as sfnTasks from "aws-cdk-lib/aws-stepfunctions-tasks";
import * as sqs from "aws-cdk-lib/aws-sqs";
import * as wafv2 from "aws-cdk-lib/aws-wafv2";
import { Construct } from "constructs";
import {
  tenantDatabaseIdentifiers,
  tenantEvidenceControlRoleName,
  TenantDefinition,
} from "./config";
import { primaryEvidenceBucketName, RecoveryConfiguration } from "./recovery-config";
import { configureEvidenceRecovery } from "./recovery-support";
import { SharedPlatformStack } from "./shared-platform-stack";

export interface TenantStackProps extends StackProps {
  readonly rootDomain: string;
  readonly tenant: TenantDefinition;
  readonly shared: SharedPlatformStack;
  readonly recovery?: RecoveryConfiguration;
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
    const apiHostname = `api-${tenant.slug}.${props.rootDomain}`;
    const tenantOrigin = `https://${hostname}`;
    const retentionDays = tenant.retentionDays ?? 365;
    const databaseIdentifiers = tenantDatabaseIdentifiers(tenant);
    const databaseIdentifier = databaseIdentifiers.databaseName;
    const databaseUsername = databaseIdentifiers.runtimeUsername;
    const controlDatabaseUsername = databaseIdentifiers.controlUsername;
    const ingestDatabaseUsername = databaseIdentifiers.ingestUsername;
    const legalApiDatabaseUsername = databaseIdentifiers.legalApiUsername;
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
    const auditSigningKey = new kms.Key(this, "TenantAuditSigningKey", {
      alias: `alias/scopeproof/${tenant.slug}/audit-signing`,
      description: `RSA-3072 audit and promotion receipt signing for ${tenant.id}`,
      keySpec: kms.KeySpec.RSA_3072,
      keyUsage: kms.KeyUsage.SIGN_VERIFY,
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
          // GuardDuty scans are asynchronous. Keep the exact version long
          // enough for delayed scan and database reconciliation retries; the
          // object is still private, KMS-bound, and unusable without its intent.
          expiration: Duration.days(7),
          id: "expire-quarantine",
          noncurrentVersionExpiration: Duration.days(7),
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
      bucketName: primaryEvidenceBucketName(this.account, this.region, tenant.id),
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
    const immutableEvidenceObjects = evidenceBucket.arnForObjects(
      `tenants/${tenant.id}/controls/*/evidence/*`,
    );
    evidenceBucket.addToResourcePolicy(new iam.PolicyStatement({
      actions: ["s3:DeleteObject", "s3:DeleteObjectVersion"],
      effect: iam.Effect.DENY,
      principals: [new iam.AnyPrincipal()],
      resources: [immutableEvidenceObjects],
      sid: "DenyImmutableEvidenceDeletion",
    }));
    evidenceBucket.addToResourcePolicy(new iam.PolicyStatement({
      actions: ["s3:PutObject"],
      conditions: { Null: { "s3:if-none-match": "true" } },
      effect: iam.Effect.DENY,
      principals: [new iam.AnyPrincipal()],
      resources: [immutableEvidenceObjects],
      sid: "DenyNonConditionalEvidenceCreation",
    }));
    if (props.recovery?.mode === "enabled") {
      const destination = props.recovery.evidenceDestinations.get(tenant.id);
      if (!destination) throw new Error(`Missing evidence recovery destination for ${tenant.id}.`);
      configureEvidenceRecovery(this, {
        auditSigningKey,
        configuration: props.recovery,
        controlTableArn: shared.controlTable.tableArn,
        controlTableName: shared.controlTable.tableName,
        destination,
        evidenceBucket,
        evidenceKey: tenantKey,
        operationsTopic: shared.operationsTopic,
        tenant,
      });
    }

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
    const ingestDatabaseSecret = new secretsmanager.Secret(this, "TenantIngestDatabaseSecret", {
      description: `Least-privilege reconciliation database credentials for ${tenant.id}`,
      encryptionKey: tenantSecretKey,
      generateSecretString: {
        excludePunctuation: true,
        generateStringKey: "password",
        passwordLength: 40,
        secretStringTemplate: JSON.stringify({
          database: databaseIdentifier,
          username: ingestDatabaseUsername,
        }),
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const controlDatabaseSecret = new secretsmanager.Secret(this, "TenantEvidenceControlDatabaseSecret", {
      description: `Execute-only audit and legal-hold database credentials for ${tenant.id}`,
      encryptionKey: tenantSecretKey,
      generateSecretString: {
        excludePunctuation: true,
        generateStringKey: "password",
        passwordLength: 40,
        secretStringTemplate: JSON.stringify({
          database: databaseIdentifier,
          username: controlDatabaseUsername,
        }),
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const legalApiDatabaseSecret = new secretsmanager.Secret(this, "TenantLegalHoldApiDatabaseSecret", {
      description: `Request-and-approve-only legal-hold API credentials for ${tenant.id}`,
      encryptionKey: tenantSecretKey,
      generateSecretString: {
        excludePunctuation: true,
        generateStringKey: "password",
        passwordLength: 40,
        secretStringTemplate: JSON.stringify({
          database: databaseIdentifier,
          username: legalApiDatabaseUsername,
        }),
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const uploadIdempotencySecret = new secretsmanager.Secret(this, "TenantUploadIdempotencySecret", {
      description: `Server-only HMAC material for retry-safe upload intents in ${tenant.id}`,
      encryptionKey: tenantSecretKey,
      generateSecretString: {
        excludePunctuation: true,
        generateStringKey: "hmacKey",
        passwordLength: 64,
        secretStringTemplate: JSON.stringify({ schemaVersion: 1 }),
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const tenantApiExecutionRole = new iam.Role(this, "TenantApiExecutionRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description: `Unprivileged API entry role that may assume only the ${tenant.id} data boundary`,
      path: "/scopeproof/api/",
      roleName: `sp-${tenant.slug}-api`,
    });
    const tenantLegalHoldApiExecutionRole = new iam.Role(this, "TenantLegalHoldApiExecutionRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description: `Authenticated two-person legal-hold API entry role for ${tenant.id}`,
      path: "/scopeproof/api/",
      roleName: `sp-${tenant.slug}-legal-api`,
    });
    const tenantLegalHoldWorkerExecutionRole = new iam.Role(this, "TenantLegalHoldWorkerExecutionRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description: `Bounded legal-hold reconciliation and stale-request expiry entry role for ${tenant.id}`,
      path: "/scopeproof/workers/",
      roleName: `sp-${tenant.slug}-legal-worker`,
    });
    const tenantLegalHoldWorkflowRole = new iam.Role(this, "TenantLegalHoldWorkflowRole", {
      assumedBy: new iam.ArnPrincipal(tenantLegalHoldApiExecutionRole.roleArn),
      description: `Database-only request and approval boundary for ${tenant.id}`,
      maxSessionDuration: Duration.hours(1),
      path: "/scopeproof/tenants/",
      roleName: `sp-${tenant.slug}-lh-workflow`,
    });
    const tenantDataRole = new iam.Role(this, "TenantDataRole", {
      // Background workers are intentionally excluded. A shared queue worker
      // must use a separately reviewed, operation-specific role instead of
      // inheriting browser/API access to every tenant data plane.
      assumedBy: new iam.ArnPrincipal(tenantApiExecutionRole.roleArn),
      description: `Upload-issuance and active-membership boundary for ${tenant.id}`,
      maxSessionDuration: Duration.hours(1),
      path: "/scopeproof/tenants/",
      roleName: `sp-${tenant.slug}-data`,
    });
    const evidenceControlRole = new iam.Role(this, "TenantEvidenceControlRole", {
      assumedBy: new iam.ArnPrincipal(tenantLegalHoldWorkerExecutionRole.roleArn),
      description: `Dedicated signed-audit and exact-version legal-hold boundary for ${tenant.id}`,
      // IAM role configuration cannot be lower than one hour. Callers must
      // still request the STS minimum (15 minutes) for each control operation.
      maxSessionDuration: Duration.hours(1),
      path: "/scopeproof/tenants/",
      roleName: tenantEvidenceControlRoleName(tenant),
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
          "rds-data:BeginTransaction",
          "rds-data:CommitTransaction",
          "rds-data:ExecuteStatement",
          "rds-data:RollbackTransaction",
        ],
        resources: [shared.databaseCluster.clusterArn, databaseSecret.secretArn],
      }),
    );
    databaseSecret.grantRead(tenantDataRole);
    uploadIdempotencySecret.grantRead(tenantDataRole);
    tenantDataRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:GetItem", "dynamodb:TransactWriteItems"],
      conditions: {
        Null: { "dynamodb:LeadingKeys": "false" },
        "ForAllValues:StringEquals": {
          "dynamodb:LeadingKeys": [`TENANT#${tenant.id}`],
        },
      },
      resources: [shared.controlTable.tableArn],
    }));
    tenantDataRole.addToPolicy(
      new iam.PolicyStatement({
        // A single-part SSE-KMS PutObject needs only data-key generation.
        // The API cannot decrypt either quarantine or immutable evidence.
        actions: ["kms:GenerateDataKey"],
        conditions: {
          StringEquals: {
            "kms:EncryptionContext:scopeproofPurpose": "quarantine",
            "kms:EncryptionContext:scopeproofTenantId": tenant.id,
            "kms:ViaService": `s3.${this.region}.amazonaws.com`,
          },
        },
        resources: [tenantKey.keyArn],
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
        resources: [ingestBucket.arnForObjects(`tenants/${tenant.id}/controls/*/quarantine/*`)],
      }),
    );
    evidenceControlRole.addToPolicy(
      new iam.PolicyStatement({
        actions: [
          "rds-data:BeginTransaction",
          "rds-data:CommitTransaction",
          "rds-data:ExecuteStatement",
          "rds-data:RollbackTransaction",
        ],
        resources: [shared.databaseCluster.clusterArn, controlDatabaseSecret.secretArn],
      }),
    );
    controlDatabaseSecret.grantRead(evidenceControlRole);
    evidenceControlRole.addToPolicy(new iam.PolicyStatement({
      actions: ["kms:GetPublicKey", "kms:Sign", "kms:Verify"],
      resources: [auditSigningKey.keyArn],
    }));
    tenantLegalHoldWorkflowRole.addToPolicy(new iam.PolicyStatement({
      actions: [
        "rds-data:BeginTransaction",
        "rds-data:CommitTransaction",
        "rds-data:ExecuteStatement",
        "rds-data:RollbackTransaction",
      ],
      resources: [shared.databaseCluster.clusterArn, legalApiDatabaseSecret.secretArn],
    }));
    legalApiDatabaseSecret.grantRead(tenantLegalHoldWorkflowRole);
    evidenceControlRole.addToPolicy(new iam.PolicyStatement({
      actions: ["s3:GetObjectLegalHold", "s3:PutObjectLegalHold"],
      resources: [evidenceBucket.arnForObjects(`tenants/${tenant.id}/controls/*/evidence/*`)],
    }));

    tenantApiExecutionRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:GetItem"],
      conditions: {
        Null: { "dynamodb:LeadingKeys": "false" },
        "ForAllValues:StringEquals": {
          "dynamodb:LeadingKeys": [`DOMAIN#${apiHostname}`],
        },
      },
      resources: [shared.controlTable.tableArn],
    }));
    tenantApiExecutionRole.addToPolicy(new iam.PolicyStatement({
      actions: ["sts:AssumeRole"],
      resources: [tenantDataRole.roleArn],
    }));
    tenantLegalHoldApiExecutionRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:GetItem"],
      conditions: {
        Null: { "dynamodb:LeadingKeys": "false" },
        "ForAllValues:StringEquals": {
          "dynamodb:LeadingKeys": [`DOMAIN#${apiHostname}`],
        },
      },
      resources: [shared.controlTable.tableArn],
    }));
    tenantLegalHoldApiExecutionRole.addToPolicy(new iam.PolicyStatement({
      actions: ["sts:AssumeRole"],
      resources: [tenantLegalHoldWorkflowRole.roleArn],
    }));
    tenantLegalHoldWorkerExecutionRole.addToPolicy(new iam.PolicyStatement({
      actions: ["sts:AssumeRole"],
      resources: [evidenceControlRole.roleArn],
    }));
    tenantLegalHoldWorkerExecutionRole.addToPolicy(new iam.PolicyStatement({
      actions: ["dynamodb:GetItem", "dynamodb:TransactWriteItems"],
      conditions: {
        Null: { "dynamodb:LeadingKeys": "false" },
        "ForAllValues:StringEquals": {
          "dynamodb:LeadingKeys": [`RECOVERY#TENANT#${tenant.id}`],
        },
      },
      resources: [shared.controlTable.tableArn],
    }));

    const tenantApiLogGroup = new logs.LogGroup(this, "TenantApiLogs", {
      encryptionKey: tenantKey,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    tenantApiExecutionRole.addToPolicy(new iam.PolicyStatement({
      actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
      resources: [`${tenantApiLogGroup.logGroupArn}:*`],
    }));
    const tenantApi = new lambdaNodejs.NodejsFunction(this, "TenantApiFunction", {
      architecture: lambda.Architecture.ARM_64,
      bundling: {
        externalModules: [],
        minify: true,
        sourceMap: false,
        target: "node22",
      },
      depsLockFilePath: path.join(__dirname, "..", "pnpm-lock.yaml"),
      description: `Authenticated tenant API and upload-intent issuer for ${tenant.id}`,
      entry: path.join(__dirname, "..", "runtime", "tenant-api", "index.ts"),
      environment: {
        API_HOSTNAME: apiHostname,
        COGNITO_APP_CLIENT_ID: userPoolClient.userPoolClientId,
        COGNITO_ISSUER: `https://${shared.userPool.userPoolProviderName}`,
        CONTROL_TABLE_NAME: shared.controlTable.tableName,
        DATABASE_CLUSTER_ARN: shared.databaseCluster.clusterArn,
        DATABASE_NAME: databaseIdentifier,
        DATABASE_SECRET_ARN: databaseSecret.secretArn,
        QUARANTINE_BUCKET_NAME: ingestBucket.bucketName,
        RETENTION_DAYS: String(retentionDays),
        TENANT_DATA_ROLE_ARN: tenantDataRole.roleArn,
        TENANT_ID: tenant.id,
        TENANT_KMS_KEY_ARN: tenantKey.keyArn,
        UPLOAD_IDEMPOTENCY_SECRET_ARN: uploadIdempotencySecret.secretArn,
        WEB_ORIGIN: tenantOrigin,
      },
      handler: "handler",
      logGroup: tenantApiLogGroup,
      memorySize: 512,
      projectRoot: path.join(__dirname, ".."),
      reservedConcurrentExecutions: 5,
      role: tenantApiExecutionRole,
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: Duration.seconds(28),
    });

    const tenantLegalHoldApiLogGroup = new logs.LogGroup(this, "TenantLegalHoldApiLogs", {
      encryptionKey: tenantKey,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    tenantLegalHoldApiExecutionRole.addToPolicy(new iam.PolicyStatement({
      actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
      resources: [`${tenantLegalHoldApiLogGroup.logGroupArn}:*`],
    }));
    const tenantLegalHoldApi = new lambdaNodejs.NodejsFunction(this, "TenantLegalHoldApiFunction", {
      architecture: lambda.Architecture.ARM_64,
      bundling: {
        externalModules: [],
        minify: true,
        sourceMap: false,
        target: "node22",
      },
      depsLockFilePath: path.join(__dirname, "..", "pnpm-lock.yaml"),
      description: `Authenticated two-person legal-hold request and approval API for ${tenant.id}`,
      entry: path.join(__dirname, "..", "runtime", "tenant-legal-hold-api", "index.ts"),
      environment: {
        API_HOSTNAME: apiHostname,
        COGNITO_APP_CLIENT_ID: userPoolClient.userPoolClientId,
        COGNITO_ISSUER: `https://${shared.userPool.userPoolProviderName}`,
        CONTROL_TABLE_NAME: shared.controlTable.tableName,
        DATABASE_CLUSTER_ARN: shared.databaseCluster.clusterArn,
        DATABASE_NAME: databaseIdentifier,
        EVIDENCE_BUCKET_NAME: evidenceBucket.bucketName,
        LEGAL_HOLD_API_ROLE_ARN: tenantLegalHoldWorkflowRole.roleArn,
        LEGAL_HOLD_DATABASE_SECRET_ARN: legalApiDatabaseSecret.secretArn,
        TENANT_ID: tenant.id,
        WEB_ORIGIN: tenantOrigin,
      },
      handler: "handler",
      logGroup: tenantLegalHoldApiLogGroup,
      memorySize: 384,
      projectRoot: path.join(__dirname, ".."),
      reservedConcurrentExecutions: 2,
      role: tenantLegalHoldApiExecutionRole,
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: Duration.seconds(28),
    });

    const legalHoldWorkerLogGroup = new logs.LogGroup(this, "TenantLegalHoldWorkerLogs", {
      encryptionKey: tenantKey,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    tenantLegalHoldWorkerExecutionRole.addToPolicy(new iam.PolicyStatement({
      actions: ["logs:CreateLogStream", "logs:PutLogEvents"],
      resources: [`${legalHoldWorkerLogGroup.logGroupArn}:*`],
    }));
    const legalHoldWorker = new lambdaNodejs.NodejsFunction(this, "TenantLegalHoldWorker", {
      architecture: lambda.Architecture.ARM_64,
      bundling: {
        externalModules: [],
        minify: true,
        sourceMap: false,
        target: "node22",
      },
      depsLockFilePath: path.join(__dirname, "..", "pnpm-lock.yaml"),
      description: `Bounded exact-version legal-hold reconciler and stale-request expiry worker for ${tenant.id}`,
      entry: path.join(__dirname, "..", "runtime", "reconcile-legal-holds", "index.ts"),
      environment: {
        AUDIT_SIGNING_KEY_ARN: auditSigningKey.keyArn,
        CONTROL_TABLE_NAME: shared.controlTable.tableName,
        CONTROL_DATABASE_SECRET_ARN: controlDatabaseSecret.secretArn,
        DATABASE_CLUSTER_ARN: shared.databaseCluster.clusterArn,
        DATABASE_NAME: databaseIdentifier,
        EVIDENCE_BUCKET_NAME: evidenceBucket.bucketName,
        EVIDENCE_CONTROL_ROLE_ARN: evidenceControlRole.roleArn,
        LEGAL_HOLD_MINIMUM_AGE_SECONDS: "60",
        LEGAL_HOLD_SWEEP_LIMIT: "25",
        TENANT_ID: tenant.id,
      },
      handler: "handler",
      logGroup: legalHoldWorkerLogGroup,
      memorySize: 512,
      projectRoot: path.join(__dirname, ".."),
      reservedConcurrentExecutions: 1,
      role: tenantLegalHoldWorkerExecutionRole,
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: Duration.minutes(5),
    });
    new events.Rule(this, "TenantLegalHoldReconciliationSchedule", {
      description: `Expires stale requests and retries only committed APPROVED legal-hold operations for ${tenant.id}`,
      schedule: events.Schedule.rate(Duration.minutes(5)),
      targets: [new eventTargets.LambdaFunction(legalHoldWorker, {
        maxEventAge: Duration.minutes(30),
        retryAttempts: 2,
      })],
    });
    const legalHoldMetric = (metricName: string, statistic: string) => new cloudwatch.Metric({
      namespace: "Scopeproof/LegalHold",
      metricName,
      dimensionsMap: { TenantId: tenant.id },
      period: Duration.minutes(5),
      statistic,
    });
    for (const alarm of [
      new cloudwatch.Alarm(this, "LegalHoldReconciliationFailureAlarm", {
        alarmDescription: `Exact-version legal-hold reconciliation failed for ${tenant.id}.`,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: legalHoldMetric("Failures", "Maximum"),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, "LegalHoldApprovedAgeAlarm", {
        alarmDescription: `An approved legal hold has remained unapplied for at least fifteen minutes in ${tenant.id}.`,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: legalHoldMetric("MaxApprovedAgeSeconds", "Maximum"),
        threshold: 900,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, "LegalHoldRequestedAgeAlarm", {
        alarmDescription: `A legal-hold request has awaited independent approval for at least 24 hours in ${tenant.id}.`,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: legalHoldMetric("MaxRequestedAgeSeconds", "Maximum"),
        threshold: 86_400,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, "LegalHoldExpiredRequestAlarm", {
        alarmDescription: `A legal-hold request expired without independent approval in ${tenant.id}.`,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: legalHoldMetric("Expired", "Sum"),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, "LegalHoldWorkerErrorAlarm", {
        alarmDescription: `The legal-hold worker Lambda failed for ${tenant.id}.`,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: legalHoldWorker.metricErrors({ period: Duration.minutes(5), statistic: "Sum" }),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    ]) {
      alarm.addAlarmAction(new cloudwatchActions.SnsAction(shared.operationsTopic));
    }

    const tenantApiAccessLogs = new logs.LogGroup(this, "TenantApiAccessLogs", {
      encryptionKey: tenantKey,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    const tenantApiCertificate = new acm.Certificate(this, "TenantApiCertificate", {
      domainName: apiHostname,
      validation: acm.CertificateValidation.fromDns(shared.hostedZone),
    });
    const api = new apigateway.RestApi(this, "TenantApi", {
      cloudWatchRole: false,
      defaultCorsPreflightOptions: {
        allowHeaders: ["Authorization", "Content-Type"],
        allowMethods: ["GET", "POST", "OPTIONS"],
        allowOrigins: [tenantOrigin],
        maxAge: Duration.minutes(5),
        statusCode: 204,
      },
      deployOptions: {
        accessLogDestination: new apigateway.LogGroupLogDestination(tenantApiAccessLogs),
        accessLogFormat: apigateway.AccessLogFormat.jsonWithStandardFields({
          caller: false,
          httpMethod: true,
          ip: true,
          protocol: true,
          requestTime: true,
          resourcePath: true,
          responseLength: true,
          status: true,
          user: false,
        }),
        cachingEnabled: false,
        dataTraceEnabled: false,
        loggingLevel: apigateway.MethodLoggingLevel.ERROR,
        metricsEnabled: true,
        stageName: "v1",
        throttlingBurstLimit: 40,
        throttlingRateLimit: 20,
        tracingEnabled: false,
      },
      description: `Fail-closed API boundary for ${tenant.id}`,
      disableExecuteApiEndpoint: true,
      domainName: {
        certificate: tenantApiCertificate,
        domainName: apiHostname,
        endpointType: apigateway.EndpointType.REGIONAL,
        securityPolicy: apigateway.SecurityPolicy.TLS_1_2,
      },
      endpointTypes: [apigateway.EndpointType.REGIONAL],
      minCompressionSize: Size.kibibytes(1),
      restApiName: `scopeproof-${tenant.slug}-api`,
    });
    const integration = new apigateway.LambdaIntegration(tenantApi, {
      allowTestInvoke: false,
      proxy: true,
    });
    const legalHoldIntegration = new apigateway.LambdaIntegration(tenantLegalHoldApi, {
      allowTestInvoke: false,
      proxy: true,
    });
    const health = api.root.addResource("health");
    // Keep unauthenticated liveness entirely inside API Gateway. It must not
    // cold-start a role that can assume the authenticated upload boundary.
    health.addMethod("GET", new apigateway.MockIntegration({
      integrationResponses: [{
        statusCode: "200",
        responseParameters: {
          "method.response.header.Access-Control-Allow-Origin": `'${tenantOrigin}'`,
          "method.response.header.Cache-Control": "'no-store'",
          "method.response.header.Referrer-Policy": "'no-referrer'",
          "method.response.header.Strict-Transport-Security": "'max-age=31536000; includeSubDomains'",
          "method.response.header.X-Content-Type-Options": "'nosniff'",
        },
        responseTemplates: { "application/json": '{"status":"ok"}' },
      }],
      passthroughBehavior: apigateway.PassthroughBehavior.NEVER,
      requestTemplates: { "application/json": '{"statusCode": 200}' },
    }), {
      methodResponses: [{
        statusCode: "200",
        responseModels: { "application/json": apigateway.Model.EMPTY_MODEL },
        responseParameters: {
          "method.response.header.Access-Control-Allow-Origin": true,
          "method.response.header.Cache-Control": true,
          "method.response.header.Referrer-Policy": true,
          "method.response.header.Strict-Transport-Security": true,
          "method.response.header.X-Content-Type-Options": true,
        },
      }],
    });
    const version = api.root.addResource("v1");
    const me = version.addResource("me");
    me.addMethod("GET", integration);
    const uploadIntents = version.addResource("upload-intents");
    const uploadModel = api.addModel("UploadIntentRequestModel", {
      contentType: "application/json",
      modelName: `Scopeproof${tenant.slug.replaceAll("-", "")}UploadIntentRequest`,
      schema: {
        schema: apigateway.JsonSchemaVersion.DRAFT4,
        title: "Scopeproof upload intent request",
        type: apigateway.JsonSchemaType.OBJECT,
        additionalProperties: false,
        required: [
          "assessmentId", "capturedAt", "contentType", "controlId", "description",
          "deviceId", "evidenceId", "evidenceType", "expectedSha256", "expectedSize", "idempotencyKey",
          "metadata", "source", "systemName", "title",
        ],
        properties: {
          assessmentId: { type: apigateway.JsonSchemaType.STRING, pattern: "^asm_[a-f0-9]{32}$" },
          capturedAt: { type: apigateway.JsonSchemaType.STRING, minLength: 20, maxLength: 40 },
          contentType: { type: apigateway.JsonSchemaType.STRING, enum: ["image/png", "application/json", "application/spdx+json", "application/vnd.cyclonedx+json", "text/plain", "text/csv"] },
          controlId: { type: apigateway.JsonSchemaType.STRING, pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" },
          description: { type: apigateway.JsonSchemaType.STRING, maxLength: 8_000 },
          deviceId: { type: apigateway.JsonSchemaType.STRING, pattern: "^dev_[a-f0-9]{32}$" },
          evidenceId: { type: apigateway.JsonSchemaType.STRING, pattern: "^evd_[a-f0-9]{32}$" },
          evidenceType: { type: apigateway.JsonSchemaType.STRING, enum: ["SCREENSHOT", "CODE", "CONFIGURATION", "REPORT", "SBOM", "EXPORT"] },
          expectedSha256: { type: apigateway.JsonSchemaType.STRING, pattern: "^[a-f0-9]{64}$" },
          expectedSize: { type: apigateway.JsonSchemaType.INTEGER, minimum: 1, maximum: 26_214_400 },
          idempotencyKey: { type: apigateway.JsonSchemaType.STRING, pattern: "^[A-Za-z0-9_-]{43}$" },
          metadata: { type: apigateway.JsonSchemaType.OBJECT },
          source: { type: apigateway.JsonSchemaType.STRING, minLength: 1, maxLength: 120 },
          systemName: { type: apigateway.JsonSchemaType.STRING, minLength: 1, maxLength: 160 },
          title: { type: apigateway.JsonSchemaType.STRING, minLength: 1, maxLength: 240 },
        },
      },
    });
    uploadIntents.addMethod("POST", integration, {
      requestModels: { "application/json": uploadModel },
      requestValidator: new apigateway.RequestValidator(this, "UploadIntentRequestValidator", {
        restApi: api,
        validateRequestBody: true,
        validateRequestParameters: false,
      }),
    });
    const legalHoldRequests = version.addResource("legal-hold-requests");
    const legalHoldRequestModel = api.addModel("LegalHoldRequestModel", {
      contentType: "application/json",
      modelName: `Scopeproof${tenant.slug.replaceAll("-", "")}LegalHoldRequest`,
      schema: {
        schema: apigateway.JsonSchemaVersion.DRAFT4,
        title: "Scopeproof exact-version legal-hold request",
        type: apigateway.JsonSchemaType.OBJECT,
        additionalProperties: false,
        required: [
          "bucket", "changedAt", "contentType", "controlId", "evidenceId",
          "expectedHoldRevision", "holdId", "key", "kind", "operationId",
          "reason", "status", "versionId",
        ],
        properties: {
          bucket: { type: apigateway.JsonSchemaType.STRING, pattern: "^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$" },
          changedAt: { type: apigateway.JsonSchemaType.STRING, minLength: 20, maxLength: 40 },
          contentType: { type: apigateway.JsonSchemaType.STRING, enum: ["image/png", "application/json", "application/spdx+json", "application/vnd.cyclonedx+json", "text/plain", "text/csv"] },
          controlId: { type: apigateway.JsonSchemaType.STRING, pattern: "^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$" },
          evidenceId: { type: apigateway.JsonSchemaType.STRING, pattern: "^evd_[a-f0-9]{32}$" },
          expectedHoldRevision: { type: apigateway.JsonSchemaType.INTEGER, minimum: 0 },
          holdId: { type: apigateway.JsonSchemaType.STRING, pattern: "^hld_[a-f0-9]{32}$" },
          key: { type: apigateway.JsonSchemaType.STRING, minLength: 64, maxLength: 1024 },
          kind: { type: apigateway.JsonSchemaType.STRING, enum: ["LEGAL", "AUDIT", "SECURITY_INCIDENT"] },
          operationId: { type: apigateway.JsonSchemaType.STRING, pattern: "^lho_[a-f0-9]{32}$" },
          reason: { type: apigateway.JsonSchemaType.STRING, minLength: 10, maxLength: 2_000 },
          status: { type: apigateway.JsonSchemaType.STRING, enum: ["ON", "OFF"] },
          versionId: { type: apigateway.JsonSchemaType.STRING, minLength: 1, maxLength: 512 },
        },
      },
    });
    legalHoldRequests.addMethod("POST", legalHoldIntegration, {
      requestModels: { "application/json": legalHoldRequestModel },
      requestValidator: new apigateway.RequestValidator(this, "LegalHoldRequestValidator", {
        restApi: api,
        validateRequestBody: true,
        validateRequestParameters: false,
      }),
    });
    const legalHoldApprovals = version.addResource("legal-hold-approvals");
    const legalHoldApprovalModel = api.addModel("LegalHoldApprovalModel", {
      contentType: "application/json",
      modelName: `Scopeproof${tenant.slug.replaceAll("-", "")}LegalHoldApproval`,
      schema: {
        schema: apigateway.JsonSchemaVersion.DRAFT4,
        title: "Scopeproof independent exact-version legal-hold approval",
        type: apigateway.JsonSchemaType.OBJECT,
        additionalProperties: false,
        required: ["approvedAt", "operationId", "requestDigest"],
        properties: {
          approvedAt: { type: apigateway.JsonSchemaType.STRING, minLength: 20, maxLength: 40 },
          operationId: { type: apigateway.JsonSchemaType.STRING, pattern: "^lho_[a-f0-9]{32}$" },
          requestDigest: { type: apigateway.JsonSchemaType.STRING, pattern: "^[a-f0-9]{64}$" },
        },
      },
    });
    legalHoldApprovals.addMethod("POST", legalHoldIntegration, {
      requestModels: { "application/json": legalHoldApprovalModel },
      requestValidator: new apigateway.RequestValidator(this, "LegalHoldApprovalValidator", {
        restApi: api,
        validateRequestBody: true,
        validateRequestParameters: false,
      }),
    });
    for (const [id, type, status] of [
      ["TenantApiDefault4xx", apigateway.ResponseType.DEFAULT_4XX, "400"],
      ["TenantApiDefault5xx", apigateway.ResponseType.DEFAULT_5XX, "500"],
      ["TenantApiThrottled", apigateway.ResponseType.THROTTLED, "429"],
      ["TenantApiWafFiltered", apigateway.ResponseType.WAF_FILTERED, "403"],
    ] as const) {
      new apigateway.GatewayResponse(this, id, {
        restApi: api,
        type,
        statusCode: status,
        responseHeaders: {
          "Access-Control-Allow-Origin": `'${tenantOrigin}'`,
          "Cache-Control": "'no-store'",
          "X-Content-Type-Options": "'nosniff'",
        },
        templates: {
          "application/json": `{"type":"about:blank","title":"Request rejected","status":${status},"code":"GATEWAY_REJECTED","requestId":"$context.requestId"}`,
        },
      });
    }
    new route53.ARecord(this, "TenantApiAlias", {
      recordName: `api-${tenant.slug}`,
      target: route53.RecordTarget.fromAlias(new route53Targets.ApiGateway(api)),
      zone: shared.hostedZone,
    });
    new wafv2.CfnWebACLAssociation(this, "TenantApiWebAclAssociation", {
      resourceArn: api.deploymentStage.stageArn,
      webAclArn: shared.webAcl.attrArn,
    });
    for (const alarm of [
      new cloudwatch.Alarm(this, "TenantApiErrorAlarm", {
        alarmDescription: `Tenant API execution failed for ${tenant.id}.`,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        evaluationPeriods: 1,
        metric: tenantApi.metricErrors({ period: Duration.minutes(5), statistic: "Sum" }),
        threshold: 1,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
      new cloudwatch.Alarm(this, "TenantApiAbuseAlarm", {
        alarmDescription: `Tenant API client errors or quota denials are sustained for ${tenant.id}.`,
        comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
        datapointsToAlarm: 2,
        evaluationPeriods: 2,
        metric: api.deploymentStage.metricClientError({ period: Duration.minutes(5), statistic: "Sum" }),
        threshold: 100,
        treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
      }),
    ]) {
      alarm.addAlarmAction(new cloudwatchActions.SnsAction(shared.operationsTopic));
    }

    const databaseAdminSecret = shared.databaseCluster.secret;
    if (!databaseAdminSecret) {
      throw new Error("The shared database cluster must expose an administrator secret.");
    }
    const provisionerLogGroup = new logs.LogGroup(this, "TenantProvisionerLogs", {
      encryptionKey: tenantKey,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    const provisioner = new lambdaNodejs.NodejsFunction(this, "TenantProvisioner", {
      architecture: lambda.Architecture.ARM_64,
      bundling: {
        commandHooks: {
          beforeBundling() { return []; },
          beforeInstall() { return []; },
          afterBundling(inputDir, outputDir) {
            const databaseOutput = `${outputDir}/database`;
            return [
              `mkdir -p "${databaseOutput}"`,
              ...["001_tenant_schema.sql", "002_runtime_role.sql", "003_ingest_role.sql", "004_evidence_control_role.sql", "005_legal_hold_api_role.sql"].map(
                (name) => `cp -p "${inputDir}/../database/${name}" "${databaseOutput}/${name}"`,
              ),
            ];
          },
        },
        externalModules: [],
        format: lambdaNodejs.OutputFormat.ESM,
        minify: true,
        sourceMap: false,
        target: "node22",
      },
      depsLockFilePath: path.join(__dirname, "..", "pnpm-lock.yaml"),
      description: `Idempotently creates and verifies the PostgreSQL boundary for ${tenant.id}`,
      entry: path.join(__dirname, "..", "runtime", "provision-tenant", "index.mjs"),
      environment: {
        ADMIN_SECRET_ARN: databaseAdminSecret.secretArn,
        API_HOSTNAME: apiHostname,
        AWS_ACCOUNT_ID_EXPECTED: this.account,
        AWS_REGION_EXPECTED: this.region,
        CANONICAL_HOSTNAME: hostname,
        CONTROL_TABLE_NAME: shared.controlTable.tableName,
        DATABASE_CLUSTER_ARN: shared.databaseCluster.clusterArn,
        DATABASE_NAME: databaseIdentifier,
        DATABASE_OWNER: databaseOwner,
        DATABASE_SECRET_ARN: databaseSecret.secretArn,
        DATABASE_USERNAME: databaseUsername,
        CONTROL_DATABASE_SECRET_ARN: controlDatabaseSecret.secretArn,
        CONTROL_DATABASE_USERNAME: controlDatabaseUsername,
        DISPLAY_NAME: tenant.displayName,
        DOMAIN_HOSTNAME: hostname,
        EVIDENCE_BUCKET_NAME: evidenceBucket.bucketName,
        EVIDENCE_KEY_ARN: tenantKey.keyArn,
        AUDIT_SIGNING_KEY_ARN: auditSigningKey.keyArn,
        HOSTED_ZONE_ID: shared.hostedZone.hostedZoneId,
        QUARANTINE_BUCKET_NAME: ingestBucket.bucketName,
        INGEST_DATABASE_SECRET_ARN: ingestDatabaseSecret.secretArn,
        INGEST_DATABASE_USERNAME: ingestDatabaseUsername,
        LEGAL_API_DATABASE_SECRET_ARN: legalApiDatabaseSecret.secretArn,
        LEGAL_API_DATABASE_USERNAME: legalApiDatabaseUsername,
        TENANT_CNAME_TARGET: `${shared.branchName}.${shared.amplifyApp.attrDefaultDomain}`,
        RETENTION_DAYS: String(retentionDays),
        RETENTION_MODE: tenant.retentionMode ?? "GOVERNANCE",
        TENANT_SLUG: tenant.slug,
        TENANT_ID: tenant.id,
      },
      handler: "handler",
      logGroup: provisionerLogGroup,
      memorySize: 256,
      projectRoot: path.join(__dirname, ".."),
      reservedConcurrentExecutions: 2,
      runtime: lambda.Runtime.NODEJS_22_X,
      timeout: Duration.minutes(5),
      tracing: lambda.Tracing.ACTIVE,
    });
    provisioner.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["dynamodb:TransactWriteItems"],
        conditions: {
          Null: { "dynamodb:LeadingKeys": "false" },
          "ForAllValues:StringEquals": {
            "dynamodb:LeadingKeys": [`TENANT#${tenant.id}`, `DOMAIN#${hostname}`, `DOMAIN#${apiHostname}`],
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
        resources: [
          shared.databaseCluster.clusterArn,
          databaseAdminSecret.secretArn,
          databaseSecret.secretArn,
          ingestDatabaseSecret.secretArn,
          controlDatabaseSecret.secretArn,
          legalApiDatabaseSecret.secretArn,
        ],
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
    ingestDatabaseSecret.grantRead(provisioner);
    controlDatabaseSecret.grantRead(provisioner);
    legalApiDatabaseSecret.grantRead(provisioner);
    provisioner.addToRolePolicy(
      new iam.PolicyStatement({
        actions: ["route53:ChangeResourceRecordSets"],
        conditions: {
          Null: {
            "route53:ChangeResourceRecordSetsActions": "false",
            "route53:ChangeResourceRecordSetsNormalizedRecordNames": "false",
            "route53:ChangeResourceRecordSetsRecordTypes": "false",
          },
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
      enabled: true,
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
    const promoter = new lambdaNodejs.NodejsFunction(this, "EvidencePromoter", {
      architecture: lambda.Architecture.ARM_64,
      bundling: {
        externalModules: [],
        format: lambdaNodejs.OutputFormat.ESM,
        minify: true,
        sourceMap: false,
        target: "node22",
      },
      depsLockFilePath: path.join(__dirname, "..", "pnpm-lock.yaml"),
      description: `Validates and immutably promotes malware-cleared evidence for ${tenant.id}`,
      entry: path.join(__dirname, "..", "runtime", "promote-evidence", "index.mjs"),
      environment: {
        AWS_ACCOUNT_ID_EXPECTED: this.account,
        AWS_REGION_EXPECTED: this.region,
        CONTROL_TABLE_NAME: shared.controlTable.tableName,
        EVIDENCE_BUCKET_NAME: evidenceBucket.bucketName,
        EVIDENCE_KEY_ARN: tenantKey.keyArn,
        AUDIT_SIGNING_KEY_ARN: auditSigningKey.keyArn,
        DATABASE_CLUSTER_ARN: shared.databaseCluster.clusterArn,
        DATABASE_NAME: databaseIdentifier,
        INGEST_DATABASE_SECRET_ARN: ingestDatabaseSecret.secretArn,
        INGEST_BUCKET_NAME: ingestBucket.bucketName,
        MALWARE_PROTECTION_PLAN_ARN: malwareProtectionPlan.attrArn,
        MAX_OBJECT_BYTES: String(25 * 1024 * 1024),
        RETENTION_DAYS: String(retentionDays),
        RETENTION_MODE: tenant.retentionMode ?? "GOVERNANCE",
        TENANT_ID: tenant.id,
      },
      handler: "handler",
      logGroup: promoterLogGroup,
      memorySize: 512,
      projectRoot: path.join(__dirname, ".."),
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
        actions: ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:TransactWriteItems"],
        conditions: {
          Null: { "dynamodb:LeadingKeys": "false" },
          "ForAllValues:StringEquals": {
            "dynamodb:LeadingKeys": [
              `TENANT#${tenant.id}`,
              `RECOVERY#TENANT#${tenant.id}`,
            ],
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
        resources: [ingestBucket.arnForObjects(`tenants/${tenant.id}/controls/*/quarantine/*`)],
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
        resources: [evidenceBucket.arnForObjects(`tenants/${tenant.id}/controls/*/evidence/*`)],
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
    promoter.addToRolePolicy(new iam.PolicyStatement({
      actions: [
        "rds-data:BeginTransaction",
        "rds-data:CommitTransaction",
        "rds-data:ExecuteStatement",
        "rds-data:RollbackTransaction",
      ],
      resources: [shared.databaseCluster.clusterArn, ingestDatabaseSecret.secretArn],
    }));
    ingestDatabaseSecret.grantRead(promoter);
    promoter.addToRolePolicy(new iam.PolicyStatement({
      actions: ["kms:Sign", "kms:Verify"],
      resources: [auditSigningKey.keyArn],
    }));

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
        apiHostname,
        userPoolClient.userPoolClientId,
        tenantDataRole.roleArn,
        ingestBucket.bucketName,
        evidenceBucket.bucketName,
        tenantKey.keyArn,
        auditSigningKey.keyArn,
        evidenceControlRole.roleArn,
        databaseIdentifier,
        databaseSecret.secretArn,
        ingestDatabaseSecret.secretArn,
        controlDatabaseSecret.secretArn,
        uploadIdempotencySecret.secretArn,
        true,
      ),
      onUpdate: tenantRegistryUpdate(
        shared.controlTable.tableName,
        tenant,
        hostname,
        apiHostname,
        userPoolClient.userPoolClientId,
        tenantDataRole.roleArn,
        ingestBucket.bucketName,
        evidenceBucket.bucketName,
        tenantKey.keyArn,
        auditSigningKey.keyArn,
        evidenceControlRole.roleArn,
        databaseIdentifier,
        databaseSecret.secretArn,
        ingestDatabaseSecret.secretArn,
        controlDatabaseSecret.secretArn,
        uploadIdempotencySecret.secretArn,
        false,
      ),
      policy: cr.AwsCustomResourcePolicy.fromSdkCalls({
        resources: [shared.controlTable.tableArn],
      }),
    });

    new CfnOutput(this, "TenantHostname", { value: hostname });
    new CfnOutput(this, "TenantApiHostname", { value: apiHostname });
    new CfnOutput(this, "TenantApiOrigin", { value: `https://${apiHostname}` });
    new CfnOutput(this, "TenantId", { value: tenant.id });
    new CfnOutput(this, "CognitoAppClientId", { value: userPoolClient.userPoolClientId });
    new CfnOutput(this, "TenantDataRoleArn", { value: tenantDataRole.roleArn });
    new CfnOutput(this, "IngestBucketName", { value: ingestBucket.bucketName });
    new CfnOutput(this, "EvidenceBucketName", { value: evidenceBucket.bucketName });
    new CfnOutput(this, "EvidenceKeyArn", { value: tenantKey.keyArn });
    new CfnOutput(this, "AuditSigningKeyArn", { value: auditSigningKey.keyArn });
    new CfnOutput(this, "TenantEvidenceControlRoleArn", { value: evidenceControlRole.roleArn });
    new CfnOutput(this, "TenantDatabaseName", { value: databaseIdentifier });
    new CfnOutput(this, "TenantDatabaseUsername", { value: databaseUsername });
    new CfnOutput(this, "TenantDatabaseSecretArn", { value: databaseSecret.secretArn });
    new CfnOutput(this, "TenantIngestDatabaseUsername", { value: ingestDatabaseUsername });
    new CfnOutput(this, "TenantIngestDatabaseSecretArn", { value: ingestDatabaseSecret.secretArn });
    new CfnOutput(this, "TenantEvidenceControlDatabaseUsername", { value: controlDatabaseUsername });
    new CfnOutput(this, "TenantEvidenceControlDatabaseSecretArn", { value: controlDatabaseSecret.secretArn });
    new CfnOutput(this, "TenantLegalHoldWorkflowRoleArn", { value: tenantLegalHoldWorkflowRole.roleArn });
    new CfnOutput(this, "TenantLegalHoldApiDatabaseUsername", { value: legalApiDatabaseUsername });
    new CfnOutput(this, "TenantLegalHoldApiDatabaseSecretArn", { value: legalApiDatabaseSecret.secretArn });
    new CfnOutput(this, "TenantUploadIdempotencySecretArn", { value: uploadIdempotencySecret.secretArn });
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
      value: "ACTIVE_EXACT_INTENT_AND_DATABASE_RECONCILIATION",
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
  apiHostname: string,
  appClientId: string,
  roleArn: string,
  ingestBucket: string,
  evidenceBucket: string,
  keyArn: string,
  auditSigningKeyArn: string,
  evidenceControlRoleArn: string,
  databaseName: string,
  databaseSecretArn: string,
  ingestDatabaseSecretArn: string,
  controlDatabaseSecretArn: string,
  uploadIdempotencySecretArn: string,
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
              "#auditSigningKeyArn = :auditSigningKeyArn",
              "#evidenceControlRoleArn = :evidenceControlRoleArn",
              "#databaseName = :databaseName",
              "#databaseSecretArn = :databaseSecretArn",
              "#ingestDatabaseSecretArn = :ingestDatabaseSecretArn",
              "#controlDatabaseSecretArn = :controlDatabaseSecretArn",
              "#uploadIdempotencySecretArn = :uploadIdempotencySecretArn",
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
              "#auditSigningKeyArn": "auditSigningKeyArn",
              "#evidenceControlRoleArn": "evidenceControlRoleArn",
              "#databaseName": "databaseName",
              "#databaseSecretArn": "databaseSecretArn",
              "#ingestDatabaseSecretArn": "ingestDatabaseSecretArn",
              "#controlDatabaseSecretArn": "controlDatabaseSecretArn",
              "#uploadIdempotencySecretArn": "uploadIdempotencySecretArn",
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
              ":auditSigningKeyArn": { S: auditSigningKeyArn },
              ":evidenceControlRoleArn": { S: evidenceControlRoleArn },
              ":databaseName": { S: databaseName },
              ":databaseSecretArn": { S: databaseSecretArn },
              ":ingestDatabaseSecretArn": { S: ingestDatabaseSecretArn },
              ":controlDatabaseSecretArn": { S: controlDatabaseSecretArn },
              ":uploadIdempotencySecretArn": { S: uploadIdempotencySecretArn },
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
              "#schemaVersion = :schemaVersion",
              "#tenantId = :tenantId",
              "#hostname = :hostname",
              "#slug = :slug",
              "#displayName = :displayName",
              "#appClientId = :appClientId",
              "#canonical = :canonical",
              "#status = :provisioning",
            ].join(", "),
            ExpressionAttributeNames: {
              "#kind": "kind",
              "#schemaVersion": "schemaVersion",
              "#tenantId": "tenantId",
              "#hostname": "hostname",
              "#slug": "slug",
              "#displayName": "displayName",
              "#appClientId": "appClientId",
              "#canonical": "canonical",
              "#status": "status",
            },
            ExpressionAttributeValues: {
              ":kind": { S: "TenantDomain" },
              ":schemaVersion": { N: "1" },
              ":tenantId": { S: tenant.id },
              ":hostname": { S: hostname },
              ":slug": { S: tenant.slug },
              ":displayName": { S: tenant.displayName },
              ":appClientId": { S: appClientId },
              ":canonical": { BOOL: true },
              ":provisioning": { S: "PROVISIONING" },
            },
          },
        },
        {
          Update: {
            TableName: tableName,
            Key: {
              PK: { S: `DOMAIN#${apiHostname}` },
              SK: { S: "METADATA" },
            },
            // The API authority record was introduced after the canonical web
            // record. An update may create it, but can never take over a key
            // already bound to another tenant.
            ConditionExpression: "attribute_not_exists(PK) OR (#tenantId = :tenantId AND attribute_not_exists(provisionExecutionId))",
            UpdateExpression: [
              "SET #kind = :kind",
              "#schemaVersion = :schemaVersion",
              "#tenantId = :tenantId",
              "#hostname = :hostname",
              "#slug = :slug",
              "#displayName = :displayName",
              "#appClientId = :appClientId",
              "#canonical = :canonical",
              "#status = :provisioning",
            ].join(", "),
            ExpressionAttributeNames: {
              "#kind": "kind",
              "#schemaVersion": "schemaVersion",
              "#tenantId": "tenantId",
              "#hostname": "hostname",
              "#slug": "slug",
              "#displayName": "displayName",
              "#appClientId": "appClientId",
              "#canonical": "canonical",
              "#status": "status",
            },
            ExpressionAttributeValues: {
              ":kind": { S: "TenantDomain" },
              ":schemaVersion": { N: "1" },
              ":tenantId": { S: tenant.id },
              ":hostname": { S: apiHostname },
              ":slug": { S: tenant.slug },
              ":displayName": { S: tenant.displayName },
              ":appClientId": { S: appClientId },
              ":canonical": { BOOL: true },
              ":provisioning": { S: "PROVISIONING" },
            },
          },
        },
      ],
    },
    physicalResourceId: cr.PhysicalResourceId.of(`tenant-registry-${tenant.id}`),
  };
}
