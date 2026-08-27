import {
  CfnOutput,
  Duration,
  RemovalPolicy,
  Stack,
  StackProps,
} from "aws-cdk-lib";
import * as cloudtrail from "aws-cdk-lib/aws-cloudtrail";
import * as cloudwatch from "aws-cdk-lib/aws-cloudwatch";
import * as cloudwatchActions from "aws-cdk-lib/aws-cloudwatch-actions";
import * as kms from "aws-cdk-lib/aws-kms";
import * as logs from "aws-cdk-lib/aws-logs";
import * as s3 from "aws-cdk-lib/aws-s3";
import { Construct } from "constructs";
import type { SharedPlatformStack } from "./shared-platform-stack";
import type { TenantStack } from "./tenant-stack";

export interface ObservabilityStackProps extends StackProps {
  readonly shared: SharedPlatformStack;
  readonly tenants: readonly TenantStack[];
}

export class ObservabilityStack extends Stack {
  public constructor(scope: Construct, id: string, props: ObservabilityStackProps) {
    super(scope, id, props);
    if (props.tenants.length < 1) {
      throw new Error("The observability stack requires at least one tenant data plane.");
    }

    const auditKey = new kms.Key(this, "AuditKey", {
      alias: "alias/scopeproof/platform-audit",
      description: "Encryption key for immutable platform and tenant API audit records",
      enableKeyRotation: true,
      pendingWindow: Duration.days(30),
      removalPolicy: RemovalPolicy.RETAIN,
    });
    const auditBucket = new s3.Bucket(this, "AuditBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      bucketKeyEnabled: true,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: auditKey,
      enforceSSL: true,
      lifecycleRules: [
        {
          id: "archive-audit-records",
          noncurrentVersionTransitions: [
            { storageClass: s3.StorageClass.GLACIER, transitionAfter: Duration.days(30) },
          ],
          transitions: [
            { storageClass: s3.StorageClass.INFREQUENT_ACCESS, transitionAfter: Duration.days(30) },
            { storageClass: s3.StorageClass.GLACIER, transitionAfter: Duration.days(90) },
          ],
        },
      ],
      objectLockDefaultRetention: s3.ObjectLockRetention.compliance(Duration.days(365)),
      objectLockEnabled: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_PREFERRED,
      removalPolicy: RemovalPolicy.RETAIN,
      versioned: true,
    });
    const trailLogGroup = new logs.LogGroup(this, "TrailLogs", {
      encryptionKey: auditKey,
      removalPolicy: RemovalPolicy.RETAIN,
      retention: logs.RetentionDays.ONE_YEAR,
    });
    const trail = new cloudtrail.Trail(this, "AuditTrail", {
      bucket: auditBucket,
      cloudWatchLogGroup: trailLogGroup,
      cloudWatchLogsRetention: logs.RetentionDays.ONE_YEAR,
      enableFileValidation: true,
      encryptionKey: auditKey,
      includeGlobalServiceEvents: true,
      insightTypes: [cloudtrail.InsightType.API_CALL_RATE, cloudtrail.InsightType.API_ERROR_RATE],
      isMultiRegionTrail: true,
      managementEvents: cloudtrail.ReadWriteType.ALL,
      sendToCloudWatchLogs: true,
      snsTopic: props.shared.operationsTopic,
    });
    trail.addS3EventSelector(
      props.tenants.flatMap((tenant) => [
        { bucket: tenant.ingestBucket },
        { bucket: tenant.evidenceBucket },
      ]),
      {
        includeManagementEvents: true,
        readWriteType: cloudtrail.ReadWriteType.ALL,
      },
    );

    const deniedMetric = new logs.MetricFilter(this, "DeniedApiCallsMetric", {
      filterPattern: logs.FilterPattern.literal(
        '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
      ),
      logGroup: trailLogGroup,
      metricName: "DeniedApiCalls",
      metricNamespace: "Scopeproof/Security",
      metricValue: "1",
    });
    new cloudwatch.Alarm(this, "DeniedApiCallsAlarm", {
      alarmDescription: "Multiple AWS API authorization failures may indicate abuse or broken least privilege.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      evaluationPeriods: 1,
      metric: deniedMetric.metric({ period: Duration.minutes(5), statistic: "Sum" }),
      threshold: 5,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction(new cloudwatchActions.SnsAction(props.shared.operationsTopic));

    const rootUseMetric = new logs.MetricFilter(this, "RootAccountUseMetric", {
      filterPattern: logs.FilterPattern.literal(
        '{ $.userIdentity.type = "Root" && $.eventType != "AwsServiceEvent" }',
      ),
      logGroup: trailLogGroup,
      metricName: "RootAccountUse",
      metricNamespace: "Scopeproof/Security",
      metricValue: "1",
    });
    new cloudwatch.Alarm(this, "RootAccountUseAlarm", {
      alarmDescription: "The AWS account root identity was used.",
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      evaluationPeriods: 1,
      metric: rootUseMetric.metric({ period: Duration.minutes(1), statistic: "Sum" }),
      threshold: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    }).addAlarmAction(new cloudwatchActions.SnsAction(props.shared.operationsTopic));

    new CfnOutput(this, "AuditBucketName", { value: auditBucket.bucketName });
    new CfnOutput(this, "AuditKeyArn", { value: auditKey.keyArn });
    new CfnOutput(this, "AuditTrailArn", { value: trail.trailArn });
  }
}
