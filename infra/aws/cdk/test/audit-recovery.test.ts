import assert from "node:assert/strict";
import test from "node:test";
import { App, Stack } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import * as kms from "aws-cdk-lib/aws-kms";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as sns from "aws-cdk-lib/aws-sns";
import { createAuditRecoveryDestination, configureAuditRecovery } from "../lib/audit-recovery";
import { parseRecoveryConfiguration, recoveryAuditBucketName } from "../lib/recovery-config";

const account = "111111111111";
const input = { mode: "enabled", region: "us-west-2", evidenceDestinations: [],
  backupVaultKeyArn: `arn:aws:kms:us-west-2:${account}:key/11111111-1111-4111-8111-111111111111`,
  auditDestination: { bucketName: recoveryAuditBucketName(account, "us-west-2", "prod"), kmsKeyArn: `arn:aws:kms:us-west-2:${account}:key/22222222-2222-4222-8222-222222222222` },
};
const options = { account, primaryRegion: "us-east-1", deploymentEnvironment: "prod" as const, tenants: [] };

test("enabled recovery requires the exact bootstrapped audit bucket and recovery key", () => {
  assert.throws(() => parseRecoveryConfiguration({ ...input, auditDestination: undefined }, options), /auditDestination/);
  assert.throws(() => parseRecoveryConfiguration({ ...input, auditDestination: { ...input.auditDestination, bucketName: "foreign-bucket" } }, options), /Audit recovery bucket/);
  assert.throws(() => parseRecoveryConfiguration({ ...input, auditDestination: { ...input.auditDestination, kmsKeyArn: input.auditDestination.kmsKeyArn.replace("us-west-2", "us-east-1") } }, options), /recovery account and region/);
  assert.equal(parseRecoveryConfiguration(input, options).auditDestination?.bucketName, input.auditDestination.bucketName);
});

test("audit replication copies logs and digest versions with lock and no delete capability", () => {
  const app = new App();
  const configuration = parseRecoveryConfiguration(input, options);
  const source = new Stack(app, "AuditSource", { env: { account, region: "us-east-1" } });
  const key = new kms.Key(source, "SourceKey");
  const bucket = new s3.Bucket(source, "SourceBucket", { versioned: true, objectLockEnabled: true, encryptionKey: key, bucketKeyEnabled: true });
  configureAuditRecovery(source, { configuration, sourceBucket: bucket, sourceKey: key, operationsTopic: new sns.Topic(source, "Topic") });
  const template = Template.fromStack(source);
  const resources = template.findResources("Custom::AWS");
  const replication = JSON.stringify(resources);
  assert.ok(replication.includes("putBucketReplication"));
  assert.ok(replication.includes("DeleteMarkerReplication"));
  assert.ok(replication.includes(`AWSLogs/${account}/`));
  assert.ok(replication.includes(input.auditDestination.kmsKeyArn));
  assert.ok(replication.includes(input.auditDestination.bucketName));
  const policies = template.findResources("AWS::IAM::Policy");
  const statements = Object.values(policies).flatMap((resource) => resource.Properties.PolicyDocument.Statement) as Array<{ Action: string | string[] }>;
  assert.ok(statements.some((statement) => statement.Action.includes("s3:GetObjectRetention")));
  assert.ok(!statements.some((statement) => JSON.stringify(statement.Action).includes("Delete")));
  const destination = new Stack(new App(), "AuditDestination", { env: { account, region: "us-west-2" } });
  createAuditRecoveryDestination(destination, configuration, new s3.Bucket(destination, "AccessLogs"));
  Template.fromStack(destination).hasResourceProperties("AWS::S3::Bucket", {
    BucketName: input.auditDestination.bucketName, ObjectLockEnabled: true,
    ObjectLockConfiguration: { ObjectLockEnabled: "Enabled", Rule: { DefaultRetention: { Days: 365, Mode: "COMPLIANCE" } } },
    VersioningConfiguration: { Status: "Enabled" },
  });
});
