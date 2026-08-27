import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  StackProps,
  Tags,
} from "aws-cdk-lib";
import * as backup from "aws-cdk-lib/aws-backup";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as sns from "aws-cdk-lib/aws-sns";
import * as subscriptions from "aws-cdk-lib/aws-sns-subscriptions";
import { Construct } from "constructs";
import { TenantDefinition } from "./config";
import {
  RecoveryConfiguration,
  recoveryBackupRoleName,
  recoveryEvidenceBucketName,
  recoveryEvidenceReplicationRoleName,
} from "./recovery-config";
import { configureBackupVaultNotifications } from "./recovery-support";

export interface RecoveryStackProps extends StackProps {
  readonly alertEmail?: string;
  readonly configuration: RecoveryConfiguration;
  readonly primaryRegion: string;
  readonly tenants: readonly TenantDefinition[];
}

export class RecoveryStack extends Stack {
  public constructor(scope: Construct, id: string, props: RecoveryStackProps) {
    super(scope, id, props);
    const { configuration, tenants } = props;
    if (!configuration.region || this.region !== configuration.region) {
      throw new Error("RecoveryStack must be deployed in the configured recovery region.");
    }
    if (props.primaryRegion === this.region) {
      throw new Error("RecoveryStack must be deployed outside the primary region.");
    }
    if (!/^\d{12}$/.test(this.account)) {
      throw new Error("RecoveryStack requires an explicit AWS account.");
    }
    if (configuration.deploymentEnvironment === "prod" && !props.alertEmail) {
      throw new Error("Production recovery requires a confirmed operations alert email.");
    }

    Tags.of(this).add("Environment", configuration.deploymentEnvironment);
    Tags.of(this).add("DataRole", "DisasterRecovery");

    const alertKey = new kms.Key(this, "RecoveryAlertsKey", {
      alias: `alias/scopeproof/${configuration.deploymentEnvironment}/recovery/alerts`,
      description: "Cross-region backup and restore notification encryption",
      enableKeyRotation: true,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const recoveryTopicName = `scopeproof-${configuration.deploymentEnvironment}-recovery-operations`;
    const recoveryTopic = new sns.Topic(this, "RecoveryOperationsTopic", {
      displayName: `Scopeproof ${configuration.deploymentEnvironment} recovery operations`,
      enforceSSL: true,
      masterKey: alertKey,
      topicName: recoveryTopicName,
    });
    if (props.alertEmail) {
      recoveryTopic.addSubscription(new subscriptions.EmailSubscription(props.alertEmail));
    }

    const backupKey = new kms.Key(this, "RecoveryBackupVaultKey", {
      alias: `alias/scopeproof/${configuration.deploymentEnvironment}/recovery/backup-vault`,
      description: "Cross-region Aurora recovery-point encryption",
      enableKeyRotation: true,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const backupRoleArn = this.formatArn({
      region: "",
      resource: "role",
      resourceName: `scopeproof/recovery/${recoveryBackupRoleName(configuration.deploymentEnvironment)}`,
      service: "iam",
    });
    const vault = new backup.BackupVault(this, "RecoveryBackupVault", {
      backupVaultName: configuration.backupVaultName,
      blockRecoveryPointDeletion: true,
      encryptionKey: backupKey,
      lockConfiguration: {
        changeableFor: configuration.vaultLockChangeableDays === undefined
          ? undefined
          : Duration.days(configuration.vaultLockChangeableDays),
        maxRetention: Duration.days(3_650),
        minRetention: Duration.days(configuration.auroraCopyRetentionDays),
      },
      removalPolicy: RemovalPolicy.RETAIN,
    });
    if (!configuration.backupVaultArn) {
      throw new Error("Recovery vault notifications require the exact recovery vault ARN.");
    }
    configureBackupVaultNotifications({
      account: this.account,
      events: [
        backup.BackupVaultEvents.COPY_JOB_FAILED,
        backup.BackupVaultEvents.RESTORE_JOB_FAILED,
        backup.BackupVaultEvents.COPY_JOB_SUCCESSFUL,
      ],
      key: alertKey,
      topic: recoveryTopic,
      vault,
      vaultArn: configuration.backupVaultArn,
    });

    const accessLogs = new s3.Bucket(this, "RecoveryEvidenceAccessLogs", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      lifecycleRules: [{ expiration: Duration.days(365), id: "expire-recovery-access-logs" }],
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
      removalPolicy: RemovalPolicy.RETAIN,
      versioned: true,
    });

    for (const tenant of tenants) {
      const replicationRoleArn = this.formatArn({
        region: "",
        resource: "role",
        resourceName: `scopeproof/recovery/${recoveryEvidenceReplicationRoleName(tenant)}`,
        service: "iam",
      });
      const evidenceKey = new kms.Key(this, `RecoveryEvidenceKey-${tenant.slug}`, {
        alias: `alias/scopeproof/recovery/${tenant.id}/evidence`,
        description: `Cross-region immutable evidence encryption for ${tenant.id}`,
        enableKeyRotation: true,
        pendingWindow: Duration.days(30),
        removalPolicy: RemovalPolicy.RETAIN,
      });
      const retentionDays = tenant.retentionDays ?? 365;
      const retention = tenant.retentionMode === "COMPLIANCE"
        ? s3.ObjectLockRetention.compliance(Duration.days(retentionDays))
        : s3.ObjectLockRetention.governance(Duration.days(retentionDays));
      const evidenceBucket = new s3.Bucket(this, `RecoveryEvidenceBucket-${tenant.slug}`, {
        blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
        bucketKeyEnabled: true,
        bucketName: recoveryEvidenceBucketName(this.account, this.region, tenant.id),
        encryption: s3.BucketEncryption.KMS,
        encryptionKey: evidenceKey,
        enforceSSL: true,
        lifecycleRules: [{
          abortIncompleteMultipartUploadAfter: Duration.days(1),
          id: "abort-incomplete-recovery-uploads",
        }],
        objectLockDefaultRetention: retention,
        objectLockEnabled: true,
        objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
        removalPolicy: RemovalPolicy.RETAIN,
        serverAccessLogsBucket: accessLogs,
        serverAccessLogsPrefix: `${tenant.id}/evidence/`,
        versioned: true,
      });
      evidenceBucket.addToResourcePolicy(new iam.PolicyStatement({
        actions: [
          "s3:PutObject",
          "s3:PutObjectLegalHold",
          "s3:PutObjectRetention",
          "s3:PutObjectTagging",
          "s3:ReplicateObject",
          "s3:ReplicateTags",
        ],
        conditions: { ArnNotEquals: { "aws:PrincipalArn": replicationRoleArn } },
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        resources: [evidenceBucket.arnForObjects("*")],
      }));
      evidenceBucket.addToResourcePolicy(new iam.PolicyStatement({
        // Delete-marker replication is disabled. Prevent every principal,
        // including administrators and the replication role, from creating a
        // destination-only marker or deleting an exact recovery version under
        // the immutable tenant evidence namespace.
        actions: ["s3:DeleteObject", "s3:DeleteObjectVersion"],
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        resources: [evidenceBucket.arnForObjects(`tenants/${tenant.id}/controls/*`)],
      }));
      evidenceBucket.addToResourcePolicy(new iam.PolicyStatement({
        // Replication supplies its destination KMS key through the replication
        // configuration and may not expose PutObject encryption headers to a
        // bucket-policy condition. Apply header enforcement only to direct PUTs
        // by exempting the exact replication role from this explicit deny.
        actions: ["s3:PutObject"],
        conditions: {
          ArnNotEquals: { "aws:PrincipalArn": replicationRoleArn },
          Null: { "s3:x-amz-server-side-encryption-aws-kms-key-id": "true" },
        },
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        resources: [evidenceBucket.arnForObjects("*")],
      }));
      evidenceBucket.addToResourcePolicy(new iam.PolicyStatement({
        actions: ["s3:PutObject"],
        conditions: {
          ArnNotEquals: { "aws:PrincipalArn": replicationRoleArn },
          StringNotEquals: {
            "s3:x-amz-server-side-encryption-aws-kms-key-id": evidenceKey.keyArn,
          },
        },
        effect: iam.Effect.DENY,
        principals: [new iam.AnyPrincipal()],
        resources: [evidenceBucket.arnForObjects("*")],
      }));

      new CfnOutput(this, `EvidenceReplicaBucket-${tenant.slug}`, {
        description: `Pass this bucket name back in recovery.evidenceDestinations for ${tenant.id}.`,
        value: evidenceBucket.bucketName,
      });
      new CfnOutput(this, `EvidenceReplicaKeyArn-${tenant.slug}`, {
        description: `Pass this key ARN back in recovery.evidenceDestinations for ${tenant.id}.`,
        value: evidenceKey.keyArn,
      });
    }

    new CfnOutput(this, "RecoveryRegion", { value: this.region });
    new CfnOutput(this, "RecoveryBackupVaultArn", { value: vault.backupVaultArn });
    new CfnOutput(this, "RecoveryBackupVaultKeyArn", {
      description: "Pass this exact ARN back as recovery.backupVaultKeyArn.",
      value: backupKey.keyArn,
    });
    new CfnOutput(this, "ExpectedAuroraBackupRoleArn", { value: backupRoleArn });
    new CfnOutput(this, "RecoveryOperationsTopicArn", { value: recoveryTopic.topicArn });
    new CfnOutput(this, "RecoveryVaultLockMode", { value: configuration.vaultLockMode });
  }
}
