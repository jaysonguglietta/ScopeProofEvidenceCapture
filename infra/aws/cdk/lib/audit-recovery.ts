import { CfnOutput, Duration, RemovalPolicy, Stack } from "aws-cdk-lib";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as cr from "aws-cdk-lib/custom-resources";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as sns from "aws-cdk-lib/aws-sns";
import { RecoveryConfiguration, recoveryAuditBucketName, recoveryAuditReplicationRoleName } from "./recovery-config";

export function createAuditRecoveryDestination(scope: Stack, configuration: RecoveryConfiguration, accessLogs: s3.IBucket): void {
  if (configuration.region !== scope.region || configuration.mode === "disabled") throw new Error("Audit recovery destination must be in the configured recovery region.");
  const roleArn = scope.formatArn({ service: "iam", region: "", resource: "role",
    resourceName: `scopeproof/recovery/${recoveryAuditReplicationRoleName(configuration.deploymentEnvironment)}` });
  const key = new kms.Key(scope, "RecoveryAuditKey", {
    alias: `alias/scopeproof/${configuration.deploymentEnvironment}/recovery/audit`,
    description: "Immutable cross-region CloudTrail logs and digest encryption",
    enableKeyRotation: true, pendingWindow: Duration.days(30), removalPolicy: RemovalPolicy.RETAIN,
  });
  const bucket = new s3.Bucket(scope, "RecoveryAuditBucket", {
    bucketName: recoveryAuditBucketName(scope.account, scope.region, configuration.deploymentEnvironment),
    blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL, bucketKeyEnabled: true,
    encryption: s3.BucketEncryption.KMS, encryptionKey: key, enforceSSL: true,
    objectLockEnabled: true, objectLockDefaultRetention: s3.ObjectLockRetention.compliance(Duration.days(365)),
    objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_ENFORCED, removalPolicy: RemovalPolicy.RETAIN,
    serverAccessLogsBucket: accessLogs, serverAccessLogsPrefix: "platform-audit/", versioned: true,
  });
  bucket.addToResourcePolicy(new iam.PolicyStatement({
    actions: ["s3:PutObject", "s3:PutObjectRetention", "s3:PutObjectLegalHold", "s3:PutObjectTagging", "s3:ReplicateObject", "s3:ReplicateTags"],
    conditions: { ArnNotEquals: { "aws:PrincipalArn": roleArn } }, effect: iam.Effect.DENY,
    principals: [new iam.AnyPrincipal()], resources: [bucket.arnForObjects("*")],
  }));
  bucket.addToResourcePolicy(new iam.PolicyStatement({
    actions: ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:BypassGovernanceRetention"],
    effect: iam.Effect.DENY, principals: [new iam.AnyPrincipal()], resources: [bucket.arnForObjects("*")],
  }));
  bucket.policy?.applyRemovalPolicy(RemovalPolicy.RETAIN);
  new CfnOutput(scope, "AuditReplicaBucket", { value: bucket.bucketName, description: "Set recovery.auditDestination.bucketName to this exact value." });
  new CfnOutput(scope, "AuditReplicaKeyArn", { value: key.keyArn, description: "Set recovery.auditDestination.kmsKeyArn to this exact value." });
}

export function configureAuditRecovery(scope: Stack, input: {
  configuration: RecoveryConfiguration; sourceBucket: s3.Bucket; sourceKey: kms.Key; operationsTopic: sns.ITopic;
}): void {
  const { configuration, sourceBucket, sourceKey } = input;
  const destination = configuration.auditDestination;
  if (configuration.mode !== "enabled" || !configuration.region || !destination) throw new Error("Enabled audit recovery requires an exact destination.");
  const prefix = `AWSLogs/${scope.account}/`;
  const destinationArn = `arn:${scope.partition}:s3:::${destination.bucketName}`;
  const role = new iam.Role(scope, "AuditReplicationRole", {
    assumedBy: new iam.ServicePrincipal("s3.amazonaws.com"), path: "/scopeproof/recovery/",
    roleName: recoveryAuditReplicationRoleName(configuration.deploymentEnvironment),
    description: "Copies exact CloudTrail log and digest versions; cannot delete either copy",
  });
  const policy = new iam.Policy(scope, "AuditReplicationPolicy", { statements: [
    new iam.PolicyStatement({ actions: ["s3:GetReplicationConfiguration", "s3:ListBucket"], resources: [sourceBucket.bucketArn] }),
    new iam.PolicyStatement({ actions: ["s3:GetObjectVersionForReplication", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging", "s3:GetObjectRetention", "s3:GetObjectLegalHold"], resources: [sourceBucket.arnForObjects(`${prefix}*`)] }),
    new iam.PolicyStatement({ actions: ["s3:ReplicateObject", "s3:ReplicateTags", "s3:PutObjectRetention", "s3:PutObjectLegalHold"], resources: [`${destinationArn}/${prefix}*`] }),
    new iam.PolicyStatement({ actions: ["kms:Decrypt"], resources: [sourceKey.keyArn], conditions: {
      StringEquals: { "kms:ViaService": `s3.${scope.region}.amazonaws.com` },
      StringLike: { "kms:EncryptionContext:aws:s3:arn": [sourceBucket.bucketArn, sourceBucket.arnForObjects(`${prefix}*`)] },
    } }),
    new iam.PolicyStatement({ actions: ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], resources: [destination.kmsKeyArn], conditions: {
      StringEquals: { "kms:ViaService": `s3.${configuration.region}.amazonaws.com`, "kms:EncryptionContext:aws:s3:arn": destinationArn },
    } }),
  ] });
  policy.attachToRole(role);
  const ruleId = "scopeproof-cross-region-cloudtrail";
  // The retained source bucket has a generated name. Configure replication
  // only after its exact-name policy exists, avoiding bucket <-> policy cycles
  // and avoiding a destructive source-bucket rename/replacement.
  const configure = new cr.AwsCustomResource(scope, "ConfigureAuditReplication", {
    installLatestAwsSdk: false,
    onUpdate: { service: "S3", action: "putBucketReplication", physicalResourceId: cr.PhysicalResourceId.of("scopeproof-audit-replication-v1"),
      parameters: { Bucket: sourceBucket.bucketName, ReplicationConfiguration: { Role: role.roleArn, Rules: [{
        ID: ruleId, Status: "Enabled", Priority: 1, Filter: { Prefix: prefix }, DeleteMarkerReplication: { Status: "Disabled" },
        SourceSelectionCriteria: { SseKmsEncryptedObjects: { Status: "Enabled" } },
        Destination: { Bucket: destinationArn, EncryptionConfiguration: { ReplicaKmsKeyID: destination.kmsKeyArn }, StorageClass: "STANDARD",
          Metrics: { Status: "Enabled", EventThreshold: { Minutes: 15 } },
          ReplicationTime: configuration.s3ReplicationTimeControl ? { Status: "Enabled", Time: { Minutes: 15 } } : undefined,
        },
      }] } },
    },
    policy: cr.AwsCustomResourcePolicy.fromStatements([
      new iam.PolicyStatement({ actions: ["s3:PutReplicationConfiguration"], resources: [sourceBucket.bucketArn] }),
      new iam.PolicyStatement({ actions: ["iam:PassRole"], resources: [role.roleArn], conditions: { StringEquals: { "iam:PassedToService": "s3.amazonaws.com" } } }),
    ]),
  });
  configure.node.addDependency(policy);
  new cloudwatch.Alarm(scope, "AuditReplicationFailureAlarm", {
    alarmDescription: "CloudTrail exact-version replication failed; verify both log and digest copies before recovery acceptance.",
    metric: new cloudwatch.Metric({ namespace: "AWS/S3", metricName: "OperationsFailedReplication",
      dimensionsMap: { SourceBucket: sourceBucket.bucketName, DestinationBucket: destination.bucketName, RuleId: ruleId },
      statistic: "Sum", period: Duration.minutes(15) }),
    evaluationPeriods: 1, threshold: 1, comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
    treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
  }).addAlarmAction(new cloudwatchActions.SnsAction(input.operationsTopic));
  new CfnOutput(scope, "AuditRecoveryDestination", { value: destination.bucketName,
    description: "Live replication only. Backfill and validate existing log/digest versions before declaring recovery ready." });
}
