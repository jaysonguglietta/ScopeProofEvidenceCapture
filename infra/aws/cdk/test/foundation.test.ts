import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import test from "node:test";
import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import {
  parseTenants,
  tenantDatabaseIdentifiers,
  tenantEvidenceControlRoleName,
  validateBranchName,
  validateRootDomain,
  validateTenant,
} from "../lib/config";
import { ObservabilityStack } from "../lib/observability-stack";
import {
  parseRecoveryConfiguration,
  primaryEvidenceBucketName,
  recoveryEvidenceBucketName,
  recoveryEvidenceBatchRoleName,
  recoveryEvidenceReplicationRoleName,
  validateDeploymentEnvironment,
} from "../lib/recovery-config";
import { RecoveryStack } from "../lib/recovery-stack";
import { SharedPlatformStack } from "../lib/shared-platform-stack";
import { TenantStack } from "../lib/tenant-stack";

const env = { account: "111111111111", region: "us-east-1" };
const acmeTenantId = "ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const firstTenantId = "ten_11111111111111111111111111111111";
const secondTenantId = "ten_22222222222222222222222222222222";

function foundation() {
  const app = new App({
    context: {
      "@aws-cdk/aws-route53-targets:userPoolDomainNameMethodWithoutCustomResource": true,
    },
  });
  const shared = new SharedPlatformStack(app, "Shared", {
    branchName: "main",
    env,
    hostedZoneId: "Z1111111111111",
    rootDomain: "evidence.example.com",
    tenantSlugs: ["acme"],
  });
  const tenant = new TenantStack(app, "TenantAcme", {
    env,
    rootDomain: "evidence.example.com",
    shared,
    tenant: {
      displayName: "Acme Corporation",
      id: acmeTenantId,
      retentionDays: 365,
      retentionMode: "GOVERNANCE",
      slug: "acme",
    },
  });
  tenant.addStackDependency(shared);
  const observability = new ObservabilityStack(app, "Observability", {
    env,
    shared,
    tenants: [tenant],
  });
  observability.addStackDependency(shared);
  observability.addStackDependency(tenant);
  return { app, observability, shared, tenant };
}

function assertNoVacuousMultiValueIamConditions(template: Template): void {
  const visit = (value: unknown): void => {
    if (!value || typeof value !== "object") return;
    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }
    const object = value as Record<string, unknown>;
    const multiValue = object["ForAllValues:StringEquals"] ?? object["ForAllValues:StringLike"];
    if (multiValue && typeof multiValue === "object") {
      const keys = multiValue as Record<string, unknown>;
      const nullCondition = object.Null as Record<string, unknown> | undefined;
      for (const key of Object.keys(keys)) {
        if (key === "dynamodb:LeadingKeys" || key.startsWith("route53:ChangeResourceRecordSets")) {
          assert.equal(nullCondition?.[key], "false", `${key} must be present so ForAllValues cannot match an empty request context`);
        }
      }
    }
    Object.values(object).forEach(visit);
  };
  visit(template.toJSON());
}

function recoveryFoundation() {
  const app = new App({
    context: {
      "@aws-cdk/aws-route53-targets:userPoolDomainNameMethodWithoutCustomResource": true,
    },
  });
  const tenantDefinition = validateTenant({
    displayName: "Acme Corporation",
    id: acmeTenantId,
    retentionDays: 365,
    retentionMode: "COMPLIANCE",
    slug: "acme",
  });
  const recovery = parseRecoveryConfiguration({
    auroraCopyRetentionDays: 365,
    auroraLocalRetentionDays: 35,
    backupVaultKeyArn: "arn:aws:kms:us-west-2:111111111111:key/11111111-1111-4111-8111-111111111111",
    evidenceDestinations: [{
      bucketName: recoveryEvidenceBucketName(env.account, "us-west-2", tenantDefinition.id),
      kmsKeyArn: "arn:aws:kms:us-west-2:111111111111:key/22222222-2222-4222-8222-222222222222",
      tenantId: tenantDefinition.id,
    }],
    mode: "enabled",
    region: "us-west-2",
    s3ReplicationTimeControl: true,
    vaultLockChangeableDays: 7,
    vaultLockMode: "COMPLIANCE",
  }, {
    account: env.account,
    deploymentEnvironment: "prod",
    primaryRegion: env.region,
    tenants: [tenantDefinition],
  });
  const recoveryStack = new RecoveryStack(app, "Recovery", {
    alertEmail: "security@example.com",
    configuration: recovery,
    env: { account: env.account, region: "us-west-2" },
    primaryRegion: env.region,
    tenants: [tenantDefinition],
  });
  const shared = new SharedPlatformStack(app, "RecoveryShared", {
    alertEmail: "security@example.com",
    branchName: "main",
    env,
    hostedZoneId: "Z1111111111111",
    recovery,
    rootDomain: "evidence.example.com",
    tenantSlugs: [tenantDefinition.slug],
  });
  shared.addStackDependency(recoveryStack);
  const tenant = new TenantStack(app, "RecoveryTenant", {
    env,
    recovery,
    rootDomain: "evidence.example.com",
    shared,
    tenant: tenantDefinition,
  });
  tenant.addStackDependency(shared);
  tenant.addStackDependency(recoveryStack);
  return { app, recovery, recoveryStack, shared, tenant };
}

test("configuration validation normalizes DNS and rejects ambiguous tenants", () => {
  assert.equal(validateRootDomain("Evidence.Example.COM."), "evidence.example.com");
  assert.equal(validateTenant({ id: firstTenantId, slug: "a", displayName: "A Co" }).slug, "a");
  assert.equal(validateTenant({ id: secondTenantId, slug: "ab", displayName: "AB Co" }).slug, "ab");
  assert.throws(
    () => validateTenant({ id: acmeTenantId, slug: "app", displayName: "Reserved" }),
    /invalid or reserved/,
  );
  assert.throws(
    () => validateTenant({ id: "tenant_acme", slug: "acme", displayName: "Legacy id" }),
    /32 lowercase hexadecimal/,
  );
  assert.throws(
    () => parseTenants([
      { id: firstTenantId, slug: "one", displayName: "One" },
      { id: firstTenantId, slug: "two", displayName: "Two" },
    ]),
    /Duplicate tenant id/,
  );
  assert.throws(
    () => parseTenants([
      { id: firstTenantId, slug: "same", displayName: "One" },
      { id: secondTenantId, slug: "same", displayName: "Two" },
    ]),
    /Duplicate tenant slug/,
  );
  assert.throws(() => validateRootDomain("not-a-domain"), /Invalid rootDomain/);
  assert.throws(() => validateRootDomain(`${"a".repeat(61)}.example.com`), /Invalid rootDomain/);
  assert.equal(validateBranchName("Release-2026"), "release-2026");
  assert.throws(() => validateBranchName("feature/unsafe"), /Invalid branchName/);
  assert.throws(() => validateBranchName("bad.branch"), /Invalid branchName/);

  const sharedPrefix = "customer-long-shared-prefix";
  const firstIdentifiers = tenantDatabaseIdentifiers(validateTenant({
    id: firstTenantId,
    slug: `${sharedPrefix}-one`,
    displayName: "First long-prefix tenant",
  }));
  const secondIdentifiers = tenantDatabaseIdentifiers(validateTenant({
    id: secondTenantId,
    slug: `${sharedPrefix}-two`,
    displayName: "Second long-prefix tenant",
  }));
  assert.notEqual(firstIdentifiers.runtimeUsername, secondIdentifiers.runtimeUsername);
  assert.notEqual(firstIdentifiers.ingestUsername, secondIdentifiers.ingestUsername);
  assert.notEqual(firstIdentifiers.ownerUsername, secondIdentifiers.ownerUsername);
  for (const identifier of Object.values(firstIdentifiers)) assert.ok(identifier.length <= 63);

  const firstLongTenant = validateTenant({
    id: firstTenantId,
    slug: `${"a".repeat(47)}1`,
    displayName: "First long-prefix tenant",
  });
  const secondLongTenant = validateTenant({
    id: secondTenantId,
    slug: `${"a".repeat(47)}2`,
    displayName: "Second long-prefix tenant",
  });
  assert.equal(tenantEvidenceControlRoleName(firstLongTenant).length, 64);
  assert.notEqual(
    tenantEvidenceControlRoleName(firstLongTenant),
    tenantEvidenceControlRoleName(secondLongTenant),
  );
  assert.match(tenantEvidenceControlRoleName(firstLongTenant), /-evidence-control$/);

  const tooManyTenantSlugs = Array.from({ length: 50 }, (_, index) => `tenant-${index}`);
  assert.throws(
    () => new SharedPlatformStack(new App(), "TooManyTenants", {
      branchName: "main",
      env,
      hostedZoneId: "Z1111111111111",
      rootDomain: "evidence.example.com",
      tenantSlugs: tooManyTenantSlugs,
    }),
    /at most 50 subdomain settings/,
  );
});

test("recovery configuration is explicit, cross-region, complete, and production fail-closed", () => {
  assert.equal(validateDeploymentEnvironment("PROD"), "prod");
  assert.equal(
    primaryEvidenceBucketName(env.account, "ap-southeast-2", acmeTenantId).length,
    63,
  );
  assert.equal(
    recoveryEvidenceReplicationRoleName(validateTenant({
      displayName: "Long slug",
      id: acmeTenantId,
      slug: "a".repeat(48),
    })).length,
    64,
  );
  assert.equal(
    recoveryEvidenceBatchRoleName(validateTenant({
      displayName: "Long slug",
      id: acmeTenantId,
      slug: "a".repeat(48),
    })).length,
    64,
  );
  assert.throws(
    () => parseRecoveryConfiguration({ mode: "disabled" }, {
      account: env.account,
      deploymentEnvironment: "prod",
      primaryRegion: env.region,
      tenants: [],
    }),
    /Production requires recovery/,
  );
  assert.throws(
    () => parseRecoveryConfiguration({ mode: "bootstrap", region: env.region }, {
      account: env.account,
      deploymentEnvironment: "prod",
      primaryRegion: env.region,
      tenants: [],
    }),
    /must differ/,
  );
  assert.throws(
    () => parseRecoveryConfiguration({ mode: "bootstrap", region: "cn-north-1" }, {
      account: env.account,
      deploymentEnvironment: "prod",
      primaryRegion: env.region,
      tenants: [],
    }),
    /aws partition/,
  );
  assert.throws(
    () => parseRecoveryConfiguration({
      mode: "enabled",
      region: "us-west-2",
      s3ReplicationTimeControl: false,
      vaultLockChangeableDays: 7,
      vaultLockMode: "COMPLIANCE",
    }, {
      account: env.account,
      deploymentEnvironment: "prod",
      primaryRegion: env.region,
      tenants: [],
    }),
    /Replication Time Control/,
  );
  const bootstrap = parseRecoveryConfiguration({
    mode: "bootstrap",
    region: "us-west-2",
    vaultLockChangeableDays: 7,
    vaultLockMode: "COMPLIANCE",
  }, {
    account: env.account,
    deploymentEnvironment: "prod",
    primaryRegion: env.region,
    tenants: [],
  });
  assert.equal(bootstrap.backupVaultArn, "arn:aws:backup:us-west-2:111111111111:backup-vault:scopeproof-prod-recovery");
});

test("recovery stack creates locked destination vault and immutable tenant evidence replicas", () => {
  const { recoveryStack } = recoveryFoundation();
  const template = Template.fromStack(recoveryStack);
  const synthesized = template.toJSON() as { Resources: Record<string, Record<string, unknown>> };

  template.hasResourceProperties("AWS::Backup::BackupVault", {
    BackupVaultName: "scopeproof-prod-recovery",
    LockConfiguration: {
      ChangeableForDays: 7,
      MaxRetentionDays: 3650,
      MinRetentionDays: 365,
    },
  });
  template.resourceCountIs("AWS::KMS::Key", 3);
  template.resourceCountIs("AWS::S3::Bucket", 2);
  template.hasResourceProperties("AWS::S3::Bucket", {
    BucketName: "sp-r-111111111111-uswest2-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ObjectLockConfiguration: {
      ObjectLockEnabled: "Enabled",
      Rule: { DefaultRetention: { Days: 365, Mode: "COMPLIANCE" } },
    },
    ObjectLockEnabled: true,
    VersioningConfiguration: { Status: "Enabled" },
  });
  const policies = JSON.stringify(
    Object.values(synthesized.Resources).filter((resource) => resource.Type === "AWS::S3::BucketPolicy"),
  );
  assert.match(policies, /ArnNotEquals/);
  assert.match(policies, /sp-acme-evidence-replication/);
  assert.match(policies, /s3:PutObjectRetention/);
  assert.match(policies, /s3:DeleteObject/);
  assert.match(policies, /s3:DeleteObjectVersion/);
  assert.match(policies, /tenants\/ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\/controls\/\*/);
  const recoveryBucketPolicy = Object.values(synthesized.Resources).find((resource) =>
    resource.Type === "AWS::S3::BucketPolicy" &&
    JSON.stringify(resource).includes("sp-acme-evidence-replication") &&
    JSON.stringify(resource).includes("x-amz-server-side-encryption-aws-kms-key-id")
  );
  assert.ok(recoveryBucketPolicy);
  const statements = ((recoveryBucketPolicy.Properties as Record<string, unknown>).PolicyDocument as {
    Statement: Array<Record<string, unknown>>;
  }).Statement;
  const encryptionHeaderDenies = statements.filter((statement) =>
    statement.Effect === "Deny" &&
    JSON.stringify(statement.Action).includes("s3:PutObject") &&
    JSON.stringify(statement.Condition).includes("x-amz-server-side-encryption-aws-kms-key-id")
  );
  assert.equal(encryptionHeaderDenies.length, 2);
  for (const statement of encryptionHeaderDenies) {
    const condition = statement.Condition as Record<string, Record<string, unknown>>;
    assert.match(JSON.stringify(condition.ArnNotEquals?.["aws:PrincipalArn"]), /sp-acme-evidence-replication/);
  }
});

test("enabled recovery adds exact Aurora backup copies and evidence replication without broad managed roles", () => {
  const { app, shared, tenant } = recoveryFoundation();
  const sharedTemplate = Template.fromStack(shared);
  const sharedJson = sharedTemplate.toJSON() as { Resources: Record<string, Record<string, unknown>> };
  sharedTemplate.resourceCountIs("AWS::Backup::BackupPlan", 1);
  sharedTemplate.resourceCountIs("AWS::Backup::BackupSelection", 1);
  sharedTemplate.hasResourceProperties("AWS::Backup::BackupVault", {
    BackupVaultName: "scopeproof-prod-primary",
    LockConfiguration: { MaxRetentionDays: 3650, MinRetentionDays: 35 },
  });
  assert.match(JSON.stringify(sharedJson), /arn:aws:backup:us-west-2:111111111111:backup-vault:scopeproof-prod-recovery/);
  assert.match(JSON.stringify(sharedJson), /sp-prod-aurora-backup/);
  assert.match(JSON.stringify(sharedJson), /cluster-snapshot:awsbackup/);
  assert.match(JSON.stringify(sharedJson), /recovery-point:\*/);
  assert.match(JSON.stringify(sharedJson), /:backup:us-east-1:111111111111:recovery-point:\*/);
  assert.match(JSON.stringify(sharedJson), /backup:CopyFromBackupVault/);
  assert.match(JSON.stringify(sharedJson), /backup:ListRecoveryPointsByBackupVault/);
  assert.match(JSON.stringify(sharedJson), /AuroraRecoveryPointFreshnessSeconds/);
  assert.match(JSON.stringify(sharedJson), /Scopeproof\/Recovery/);
  assert.match(JSON.stringify(sharedJson), /"TreatMissingData":"breaching"/i);
  assert.doesNotMatch(
    JSON.stringify(sharedJson),
    /"Action":"backup:CopyFromBackupVault","Effect":"Allow","Resource":"arn:aws:backup:[^"]+:backup-vault:/,
  );
  assert.doesNotMatch(JSON.stringify(sharedJson), /cluster-snapshot\/awsbackup/);
  assert.doesNotMatch(JSON.stringify(sharedJson), /AWSBackupServiceRolePolicyForBackup/);
  sharedTemplate.hasResourceProperties("AWS::DynamoDB::GlobalTable", {
    BillingMode: "PAY_PER_REQUEST",
    Replicas: Match.arrayWith([
      Match.objectLike({ DeletionProtectionEnabled: true, Region: "us-west-2" }),
      Match.objectLike({ DeletionProtectionEnabled: true, Region: "us-east-1" }),
    ]),
  });

  const tenantTemplate = Template.fromStack(tenant);
  const tenantJson = tenantTemplate.toJSON() as { Resources: Record<string, Record<string, unknown>> };
  const evidence = Object.values(tenantJson.Resources).find(
    (resource) => resource.Type === "AWS::S3::Bucket" &&
      (resource.Properties as Record<string, unknown>).ObjectLockEnabled === true,
  );
  assert.ok(evidence);
  assert.equal(
    (evidence.Properties as Record<string, unknown>).BucketName,
    "sp-e-111111111111-useast1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  );
  const replication = JSON.stringify((evidence.Properties as Record<string, unknown>).ReplicationConfiguration);
  assert.match(replication, /scopeproof-acme-cross-region-evidence/);
  assert.match(replication, /DeleteMarkerReplication.*Disabled/);
  assert.match(replication, /ReplicaKmsKeyID.*22222222-2222-4222-8222-222222222222/);
  assert.match(replication, /ReplicationTime.*Enabled/);
  assert.match(replication, /SseKmsEncryptedObjects.*Enabled/i);
  assert.match(replication, /tenants\/ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\/controls\//);
  assert.match(JSON.stringify(tenantJson), /OperationsFailedReplication/);
  assert.match(JSON.stringify(tenantJson), /sp-acme-evidence-replication/);
  assert.match(JSON.stringify(tenantJson), /s3:PutObjectLegalHold/);
  assert.match(JSON.stringify(tenantJson), /s3:PutObjectRetention/);
  assert.match(JSON.stringify(tenantJson), /s3:InitiateReplication/);
  assert.match(JSON.stringify(tenantJson), /s3:CreateJob/);
  assert.match(JSON.stringify(tenantJson), /s3:DescribeJob/);
  assert.match(JSON.stringify(tenantJson), /s3:GetObjectLegalHold/);
  assert.match(JSON.stringify(tenantJson), /s3:GetObjectRetention/);
  assert.match(JSON.stringify(tenantJson), /kms:GenerateDataKey/);
  assert.match(JSON.stringify(tenantJson), /cloudwatch:PutMetricData/);
  assert.match(JSON.stringify(tenantJson), /EvidenceVerificationFreshnessSeconds/);
  assert.match(JSON.stringify(tenantJson), /VERIFICATION_INTERVAL_SECONDS/);
  assert.match(JSON.stringify(tenantJson), /LEDGER_SETTLE_SECONDS/);
  assert.match(JSON.stringify(tenantJson), /SOURCE_KMS_KEY_ARN/);
  assert.match(JSON.stringify(tenantJson), /RECOVERY#TENANT#ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/);
  assert.match(JSON.stringify(tenantJson), /RECOVERY_STATE#TENANT#ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/);
  assert.match(JSON.stringify(tenantJson), /dynamodb:Query/);
  assert.match(JSON.stringify(tenantJson), /kms:Verify/);
  const recoveryReconcilerPolicy = Object.values(tenantJson.Resources).find((resource) => {
    if (resource.Type !== "AWS::IAM::Policy") return false;
    return JSON.stringify((resource.Properties as Record<string, unknown>).Roles)
      .includes("EvidenceRecoveryReconcilerServiceRole");
  });
  assert.ok(recoveryReconcilerPolicy);
  const recoveryReconcilerPolicyJson = JSON.stringify(recoveryReconcilerPolicy);
  assert.equal(
    [...recoveryReconcilerPolicyJson.matchAll(/"kms:Decrypt","kms:GenerateDataKey"/g)].length,
    2,
  );
  const recoveryTenantDataPolicy = Object.values(tenantJson.Resources).find((resource) => {
    if (resource.Type !== "AWS::IAM::Policy") return false;
    const roles = (resource.Properties as Record<string, unknown>).Roles;
    return Array.isArray(roles) && JSON.stringify(roles).includes("TenantDataRole");
  });
  assert.ok(recoveryTenantDataPolicy);
  assert.doesNotMatch(JSON.stringify(recoveryTenantDataPolicy), /RECOVERY#TENANT#/);
  assert.match(JSON.stringify(tenantJson), /batchoperations\.s3\.amazonaws\.com/);
  assert.match(JSON.stringify(tenantJson), /s3:Replication:OperationFailedReplication/);
  assert.match(JSON.stringify(tenantJson), /EvidenceRecoveryReconciliationSchedule/);
  assert.doesNotMatch(JSON.stringify(tenantJson), /s3:ReplicateDelete/);
  assert.doesNotThrow(() => app.synth());
});

test("shared platform reserves exact tenant mappings but publishes no tenant DNS before verification", () => {
  const { shared } = foundation();
  const template = Template.fromStack(shared);

  template.hasResourceProperties("AWS::Amplify::Domain", {
    DomainName: "evidence.example.com",
    EnableAutoSubDomain: false,
    SubDomainSettings: [
      { BranchName: "main", Prefix: "" },
      { BranchName: "main", Prefix: "acme" },
    ],
  });
  const synthesized = template.toJSON() as { Resources: Record<string, { Type: string; Properties?: unknown }> };
  const domain = Object.values(synthesized.Resources).find((resource) => resource.Type === "AWS::Amplify::Domain");
  const recordSets = Object.values(synthesized.Resources).filter(
    (resource) => resource.Type === "AWS::Route53::RecordSet",
  );
  const recordNames = recordSets.map((record) =>
    (record.Properties as { Name?: unknown } | undefined)?.Name,
  );
  assert.ok(domain);
  assert.doesNotMatch(JSON.stringify(domain), /"Prefix":"\*"/);
  assert.equal(
    recordNames.some((name) => name === "*.evidence.example.com" || name === "*.evidence.example.com."),
    false,
  );
  assert.equal(
    recordNames.some((name) => name === "acme.evidence.example.com" || name === "acme.evidence.example.com."),
    false,
  );

  template.hasResourceProperties("AWS::RDS::DBCluster", {
    EnableHttpEndpoint: true,
    ServerlessV2ScalingConfiguration: {
      MaxCapacity: 4,
      MinCapacity: 0,
      SecondsUntilAutoPause: 600,
    },
    StorageEncrypted: true,
  });
  template.hasResource("AWS::SecretsManager::Secret", {
    DeletionPolicy: "Retain",
    Properties: Match.objectLike({
      GenerateSecretString: Match.objectLike({
        SecretStringTemplate: Match.stringLikeRegexp("scopeproof_cluster_admin"),
      }),
      KmsKeyId: Match.anyValue(),
    }),
    UpdateReplacePolicy: "Retain",
  });
  template.hasResourceProperties("AWS::DynamoDB::GlobalTable", {
    BillingMode: "PAY_PER_REQUEST",
    Replicas: Match.arrayWith([
      Match.objectLike({
        DeletionProtectionEnabled: true,
        PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
        Region: "us-east-1",
      }),
    ]),
  });
  template.hasResourceProperties("AWS::Events::Rule", { State: "DISABLED" });
  assert.doesNotMatch(JSON.stringify(synthesized), /role\/scopeproof\/tenants\/sp-\*-(?:data|evidence-control)/);
  const jobWorkerPolicies = Object.values(synthesized.Resources).filter((resource) =>
    resource.Type === "AWS::IAM::Policy" && JSON.stringify(resource).includes("JobWorkerRole"));
  assert.ok(jobWorkerPolicies.length > 0);
  assert.ok(jobWorkerPolicies.every((resource) => !/sts:AssumeRole/.test(JSON.stringify(resource))));
  assert.ok(jobWorkerPolicies.every((resource) => !/dynamodb:/.test(JSON.stringify(resource))));
  const amplifyPolicies = JSON.stringify(
    Object.values(synthesized.Resources).filter((resource) =>
      resource.Type === "AWS::IAM::Policy" && JSON.stringify(resource).includes("AmplifyComputeRole")),
  );
  assert.match(amplifyPolicies, /dynamodb:GetItem/);
  assert.match(amplifyPolicies, /DOMAIN#\*/);
  assert.match(amplifyPolicies, /dynamodb:PutItem/);
  assert.match(amplifyPolicies, /EDGE_REPLAY#GLOBAL/);
  assert.doesNotMatch(amplifyPolicies, /dynamodb:(?:Scan|Query|BatchGetItem)/);
  assert.doesNotMatch(amplifyPolicies, /sts:AssumeRole|scopeproof\/tenants/);
  assert.equal(
    Object.values(synthesized.Resources).some((resource) => resource.Type === "Custom::AWS"),
    false,
  );
});

test("multi-value IAM scoping keys cannot match vacuously when request context is absent", () => {
  const { shared, tenant } = foundation();
  assertNoVacuousMultiValueIamConditions(Template.fromStack(shared));
  assertNoVacuousMultiValueIamConditions(Template.fromStack(tenant));
  const recovery = recoveryFoundation();
  assertNoVacuousMultiValueIamConditions(Template.fromStack(recovery.recoveryStack));
  assertNoVacuousMultiValueIamConditions(Template.fromStack(recovery.shared));
  assertNoVacuousMultiValueIamConditions(Template.fromStack(recovery.tenant));
});

test("shared edge, release, alerting, email, and cost controls are production bounded", () => {
  const { shared } = foundation();
  const template = Template.fromStack(shared);
  const synthesized = template.toJSON() as { Resources: Record<string, Record<string, unknown>> };

  template.resourceCountIs("AWS::WAFv2::WebACL", 2);
  template.resourceCountIs("AWS::WAFv2::WebACLAssociation", 1);
  template.hasResourceProperties("AWS::WAFv2::WebACL", {
    DefaultAction: { Allow: {} },
    Scope: "REGIONAL",
  });
  template.hasResourceProperties("AWS::WAFv2::WebACL", {
    DefaultAction: { Allow: {} },
    Scope: "CLOUDFRONT",
  });
  const webAcl = Object.values(synthesized.Resources).find(
    (resource) => resource.Type === "AWS::WAFv2::WebACL" &&
      (resource.Properties as Record<string, unknown>).Scope === "REGIONAL",
  );
  assert.ok(webAcl);
  const webAclJson = JSON.stringify(webAcl);
  for (const rule of [
    "RejectUnknownHost",
    "RejectOversizedRequestBody",
    "AWSManagedRulesAmazonIpReputationList",
    "AWSManagedRulesCommonRuleSet",
    "AWSManagedRulesKnownBadInputsRuleSet",
    "PerIpRateLimit",
  ]) {
    assert.match(webAclJson, new RegExp(rule));
  }
  assert.match(webAclJson, /acme\.evidence\.example\.com/);
  assert.doesNotMatch(webAclJson, /"SearchString":"\*\./);

  template.resourceCountIs("AWS::CloudFront::Distribution", 1);
  template.hasResourceProperties("AWS::CloudFront::Distribution", {
    DistributionConfig: {
      Aliases: ["downloads.evidence.example.com"],
      IPV6Enabled: true,
    },
  });
  template.resourceCountIs("AWS::CloudFront::OriginAccessControl", 1);
  template.resourceCountIs("AWS::SES::EmailIdentity", 1);
  template.resourceCountIs("AWS::Budgets::Budget", 1);
  template.resourceCountIs("AWS::CE::AnomalyMonitor", 1);
  template.resourceCountIs("AWS::SNS::Topic", 1);
  template.hasResourceProperties("AWS::Logs::LogGroup", { RetentionInDays: 365 });
  assert.doesNotMatch(JSON.stringify(synthesized), /AKIA[0-9A-Z]{16}/);
});

test("tenant stack is isolated, immutable, and remains provisioning", () => {
  const { tenant } = foundation();
  const template = Template.fromStack(tenant);
  const synthesized = template.toJSON() as { Resources: Record<string, Record<string, unknown>> };
  const buckets = Object.values(synthesized.Resources).filter(
    (resource) => resource.Type === "AWS::S3::Bucket",
  );
  assert.equal(buckets.length, 2);

  for (const bucket of buckets) {
    const properties = bucket.Properties as Record<string, unknown>;
    assert.deepEqual(properties.PublicAccessBlockConfiguration, {
      BlockPublicAcls: true,
      BlockPublicPolicy: true,
      IgnorePublicAcls: true,
      RestrictPublicBuckets: true,
    });
    assert.match(JSON.stringify(properties.BucketEncryption), /"SSEAlgorithm":"aws:kms"/);
    assert.match(JSON.stringify(properties.OwnershipControls), /"ObjectOwnership":"BucketOwnerEnforced"/);
  }

  const evidence = buckets.find(
    (bucket) => (bucket.Properties as Record<string, unknown>).ObjectLockEnabled === true,
  );
  const quarantine = buckets.find(
    (bucket) => (bucket.Properties as Record<string, unknown>).ObjectLockEnabled !== true,
  );
  assert.ok(evidence);
  assert.ok(quarantine);
  assert.equal((evidence.Properties as Record<string, unknown>).VersioningConfiguration instanceof Object, true);
  assert.match(JSON.stringify(evidence), /"Mode":"GOVERNANCE"/);
  assert.match(JSON.stringify(quarantine), /"NoncurrentDays":7/);
  assert.match(JSON.stringify(quarantine), /"ExpirationInDays":7/);

  template.hasResourceProperties("AWS::IAM::Role", {
    Path: "/scopeproof/tenants/",
    RoleName: "sp-acme-data",
  });
  template.hasResourceProperties("AWS::Cognito::UserPoolClient", {
    CallbackURLs: ["https://acme.evidence.example.com/auth/callback"],
    GenerateSecret: false,
    LogoutURLs: ["https://acme.evidence.example.com/"],
    PreventUserExistenceErrors: "ENABLED",
  });
  assert.match(JSON.stringify(synthesized), /PROVISIONING/);
  assert.doesNotMatch(JSON.stringify(synthesized), /#status = if_not_exists\(#status, :provisioning\)/);
  assert.match(JSON.stringify(synthesized), /attribute_not_exists\(provisionExecutionId\)/);
  assert.match(JSON.stringify(synthesized), /DOMAIN#acme\.evidence\.example\.com/);
  assert.doesNotMatch(JSON.stringify(synthesized), /AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}/);

  const evidenceBucketPolicies = JSON.stringify(
    Object.values(synthesized.Resources).filter((resource) => resource.Type === "AWS::S3::BucketPolicy"),
  );
  assert.match(evidenceBucketPolicies, /DenyImmutableEvidenceDeletion/);
  assert.match(evidenceBucketPolicies, /s3:DeleteObject/);
  assert.match(evidenceBucketPolicies, /s3:DeleteObjectVersion/);
  assert.match(evidenceBucketPolicies, /DenyNonConditionalEvidenceCreation/);
  assert.match(evidenceBucketPolicies, /s3:if-none-match/);
  assert.match(evidenceBucketPolicies, /tenants\/ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\/controls\/\*\/evidence\/\*/);

  const tenantPolicy = Object.values(synthesized.Resources).find((resource) => {
    if (resource.Type !== "AWS::IAM::Policy") return false;
    const roles = (resource.Properties as Record<string, unknown>).Roles;
    return Array.isArray(roles) && JSON.stringify(roles).includes("TenantDataRole");
  });
  assert.ok(tenantPolicy);
  const policyJson = JSON.stringify(tenantPolicy);
  assert.doesNotMatch(policyJson, /"Effect":"Allow","Resource":"\*"/);
  assert.doesNotMatch(policyJson, /"Action":"s3:\*"/);
  assert.doesNotMatch(policyJson, /s3:DeleteObject|s3:PutObjectRetention/);
  assert.doesNotMatch(policyJson, /s3:PutObjectLegalHold|kms:Sign/);
  assert.doesNotMatch(policyJson, /s3:GetObject|s3:ListBucket|s3:AbortMultipartUpload/);
  assert.doesNotMatch(policyJson, /rds-data:BatchExecuteStatement|"kms:Encrypt"/);
  assert.match(policyJson, /s3:PutObject/);
  assert.match(policyJson, /kms:GenerateDataKey/);
  assert.match(policyJson, /scopeproofPurpose":"quarantine/);
  assert.match(policyJson, /x-amz-server-side-encryption-context/);
  assert.match(policyJson, /tenants\/ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\/controls\/\*\/quarantine/);
  const evidenceControlPolicy = Object.values(synthesized.Resources).find((resource) => {
    if (resource.Type !== "AWS::IAM::Policy") return false;
    const roles = (resource.Properties as Record<string, unknown>).Roles;
    return Array.isArray(roles) && JSON.stringify(roles).includes("TenantEvidenceControlRole");
  });
  assert.ok(evidenceControlPolicy);
  const evidenceControlJson = JSON.stringify(evidenceControlPolicy);
  assert.match(evidenceControlJson, /s3:PutObjectLegalHold/);
  assert.match(evidenceControlJson, /kms:Sign/);
  assert.doesNotMatch(evidenceControlJson, /"s3:GetObject"|s3:DeleteObject|s3:PutObjectRetention|dynamodb:/);
  const tenantRoles = Object.values(synthesized.Resources).filter((resource) =>
    resource.Type === "AWS::IAM::Role" &&
      ["sp-acme-data", "sp-acme-evidence-control", "sp-acme-lh-workflow"].includes(String((resource.Properties as Record<string, unknown>).RoleName)),
  );
  assert.equal(tenantRoles.length, 3);
  assert.ok(tenantRoles.every((resource) => !/AmplifyComputeRole|amplify\.amazonaws\.com/.test(JSON.stringify((resource.Properties as Record<string, unknown>).AssumeRolePolicyDocument))));
  const dataRole = tenantRoles.find((resource) => (resource.Properties as Record<string, unknown>).RoleName === "sp-acme-data");
  const controlRole = tenantRoles.find((resource) => (resource.Properties as Record<string, unknown>).RoleName === "sp-acme-evidence-control");
  const legalWorkflowRole = tenantRoles.find((resource) => (resource.Properties as Record<string, unknown>).RoleName === "sp-acme-lh-workflow");
  assert.ok(dataRole && controlRole && legalWorkflowRole);
  assert.doesNotMatch(JSON.stringify((dataRole.Properties as Record<string, unknown>).AssumeRolePolicyDocument), /TenantLegalHoldApiExecutionRole/);
  assert.match(JSON.stringify((controlRole.Properties as Record<string, unknown>).AssumeRolePolicyDocument), /TenantLegalHoldWorkerExecutionRole/);
  assert.match(JSON.stringify((legalWorkflowRole.Properties as Record<string, unknown>).AssumeRolePolicyDocument), /TenantLegalHoldApiExecutionRole/);
  const legalWorkflowPolicy = Object.values(synthesized.Resources).find((resource) => {
    if (resource.Type !== "AWS::IAM::Policy") return false;
    const roles = (resource.Properties as Record<string, unknown>).Roles;
    return Array.isArray(roles) && JSON.stringify(roles).includes("TenantLegalHoldWorkflowRole");
  });
  assert.ok(legalWorkflowPolicy);
  assert.match(JSON.stringify(legalWorkflowPolicy), /rds-data:ExecuteStatement/);
  assert.doesNotMatch(JSON.stringify(legalWorkflowPolicy), /s3:|kms:Sign|TenantEvidenceControlDatabaseSecret/);
  const legalWorkerExecutionPolicy = Object.values(synthesized.Resources).find((resource) => {
    if (resource.Type !== "AWS::IAM::Policy") return false;
    const roles = (resource.Properties as Record<string, unknown>).Roles;
    return Array.isArray(roles) && JSON.stringify(roles).includes("TenantLegalHoldWorkerExecutionRole");
  });
  assert.ok(legalWorkerExecutionPolicy);
  const legalWorkerExecutionJson = JSON.stringify(legalWorkerExecutionPolicy);
  assert.match(legalWorkerExecutionJson, /dynamodb:GetItem/);
  assert.match(legalWorkerExecutionJson, /dynamodb:TransactWriteItems/);
  assert.match(legalWorkerExecutionJson, /RECOVERY#TENANT#ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/);
  assert.doesNotMatch(legalWorkerExecutionJson, /s3:PutObjectLegalHold|kms:Sign|rds-data:ExecuteStatement/);
  assert.match(JSON.stringify(synthesized), /legal-hold-requests/);
  assert.match(JSON.stringify(synthesized), /legal-hold-approvals/);
  assert.match(JSON.stringify(synthesized), /sp-acme-legal-api/);
  assert.match(JSON.stringify(synthesized), /sp-acme-legal-worker/);
  assert.match(JSON.stringify(synthesized), /Scopeproof\/LegalHold/);
  assert.match(JSON.stringify(synthesized), /MaxApprovedAgeSeconds/);
  assert.match(JSON.stringify(synthesized), /LegalHoldExpiredRequestAlarm/);
  assert.match(JSON.stringify(synthesized), /LEGAL_HOLD_SWEEP_LIMIT/);
  assert.match(JSON.stringify(synthesized), /CONTROL_TABLE_NAME/);
  assert.match(JSON.stringify(synthesized), /RECOVERY#TENANT#ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/);
  assert.match(JSON.stringify(synthesized), /dynamodb:TransactWriteItems/);
  const allTenantPolicies = JSON.stringify(
    Object.values(synthesized.Resources).filter((resource) => resource.Type === "AWS::IAM::Policy"),
  );
  assert.match(allTenantPolicies, /s3:DeleteObjectVersion/);
  assert.doesNotMatch(allTenantPolicies, /"s3:DeleteObject"/);

  template.resourceCountIs("AWS::GuardDuty::MalwareProtectionPlan", 1);
  template.hasResourceProperties("AWS::GuardDuty::MalwareProtectionPlan", {
    Actions: { Tagging: { Status: "ENABLED" } },
  });
  template.resourceCountIs("AWS::StepFunctions::StateMachine", 1);
  const workflow = Object.values(synthesized.Resources).find(
    (resource) => resource.Type === "AWS::StepFunctions::StateMachine",
  );
  assert.ok(workflow);
  const workflowJson = JSON.stringify(workflow);
  for (const state of [
    "AcquireProvisioningLease",
    "InitializeTenantDatabase",
    "VerifyTenantDatabase",
    "ActivateTenant",
    "MarkTenantFailed",
    "ProvisioningLeaseRejected",
    "ProvisioningFailed",
    "ProvisioningSucceeded",
  ]) {
    assert.match(workflowJson, new RegExp(state));
  }
  template.resourceCountIs("AWS::Lambda::Function", 6);
  assert.equal(
    Object.values(synthesized.Resources).filter(
      (resource) =>
        resource.Type === "AWS::Lambda::Function" &&
        JSON.stringify(resource).includes('"Architectures":["arm64"]'),
    ).length,
    5,
  );
  template.hasResourceProperties("AWS::IAM::Role", {
    Path: "/scopeproof/api/",
    RoleName: "sp-acme-api",
  });
  template.hasResourceProperties("AWS::ApiGateway::RestApi", {
    DisableExecuteApiEndpoint: true,
    EndpointConfiguration: { Types: ["REGIONAL"] },
    MinimumCompressionSize: 1_024,
    Name: "scopeproof-acme-api",
  });
  template.hasResourceProperties("AWS::ApiGateway::DomainName", {
    DomainName: "api-acme.evidence.example.com",
    EndpointConfiguration: { Types: ["REGIONAL"] },
    SecurityPolicy: "TLS_1_2",
  });
  template.hasResourceProperties("AWS::Lambda::Function", {
    Environment: {
      Variables: Match.objectLike({
        API_HOSTNAME: "api-acme.evidence.example.com",
        TENANT_ID: acmeTenantId,
        WEB_ORIGIN: "https://acme.evidence.example.com",
      }),
    },
    MemorySize: 512,
    ReservedConcurrentExecutions: 5,
    Runtime: "nodejs22.x",
    Timeout: 28,
  });
  template.hasResourceProperties("AWS::ApiGateway::Stage", {
    AccessLogSetting: Match.objectLike({ Format: Match.stringLikeRegexp("requestId") }),
    MethodSettings: Match.arrayWith([
      Match.objectLike({
        CachingEnabled: false,
        DataTraceEnabled: false,
        MetricsEnabled: true,
        ThrottlingBurstLimit: 40,
        ThrottlingRateLimit: 20,
      }),
    ]),
    StageName: "v1",
  });
  template.resourceCountIs("AWS::ApiGateway::GatewayResponse", 4);
  template.resourceCountIs("AWS::WAFv2::WebACLAssociation", 1);
  assert.match(JSON.stringify(synthesized), /TenantApiAbuseAlarm/);
  assert.doesNotMatch(JSON.stringify(synthesized), /artifactExpiresAt|requiredRetentionUntil/);
  assert.match(JSON.stringify(synthesized), /DOMAIN#api-acme\.evidence\.example\.com/);
  const apiRolePolicy = Object.values(synthesized.Resources).find((resource) => {
    if (resource.Type !== "AWS::IAM::Policy") return false;
    const roles = (resource.Properties as Record<string, unknown>).Roles;
    return Array.isArray(roles) && JSON.stringify(roles).includes("TenantApiExecutionRole");
  });
  assert.ok(apiRolePolicy);
  const apiRolePolicyJson = JSON.stringify(apiRolePolicy);
  assert.match(apiRolePolicyJson, /dynamodb:GetItem/);
  assert.match(apiRolePolicyJson, /DOMAIN#api-acme\.evidence\.example\.com/);
  assert.match(apiRolePolicyJson, /sts:AssumeRole/);
  assert.doesNotMatch(apiRolePolicyJson, /rds-data:|secretsmanager:GetSecretValue|s3:PutObject|kms:Decrypt/);
  template.resourceCountIs("AWS::SQS::Queue", 2);
  template.hasResourceProperties("AWS::Events::Rule", {
    EventPattern: Match.objectLike({
      detail: Match.objectLike({
        scanResultDetails: Match.objectLike({ scanResultStatus: ["NO_THREATS_FOUND"] }),
      }),
    }),
    State: "ENABLED",
  });
  assert.match(JSON.stringify(synthesized), /NO_THREATS_FOUND/);
  assert.match(JSON.stringify(synthesized), /GuardDuty Malware Protection Object Scan Result/);
  assert.match(JSON.stringify(synthesized), /ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/);
  assert.match(JSON.stringify(synthesized), /route53:ChangeResourceRecordSets/);
  assert.match(JSON.stringify(synthesized), /ChangeResourceRecordSetsNormalizedRecordNames/);
  assert.match(JSON.stringify(synthesized), /acme\.evidence\.example\.com/);
  assert.match(JSON.stringify(synthesized), /ACTIVE_EXACT_INTENT_AND_DATABASE_RECONCILIATION/);
});

test("runtime assets enforce exact provisioning and single-writer promotion contracts", () => {
  const provisioner = readFileSync(
    path.join(__dirname, "..", "runtime", "provision-tenant", "index.mjs"),
    "utf8",
  );
  const promoter = readFileSync(
    path.join(__dirname, "..", "runtime", "promote-evidence", "index.mjs"),
    "utf8",
  );
  const recoveryReconciler = readFileSync(
    path.join(__dirname, "..", "runtime", "reconcile-recovery", "index.mjs"),
    "utf8",
  );
  const recoveryContract = readFileSync(
    path.join(__dirname, "..", "runtime", "reconcile-recovery", "backfill-contract.mjs"),
    "utf8",
  );
  const tenantApi = readFileSync(
    path.join(__dirname, "..", "runtime", "tenant-api", "index.ts"),
    "utf8",
  );
  const legalHoldWorker = readFileSync(
    path.join(__dirname, "..", "runtime", "reconcile-legal-holds", "index.ts"),
    "utf8",
  );

  assert.match(provisioner, /SET LOCAL ROLE/);
  assert.match(provisioner, /REVOKE \$\{ownerRole\} FROM \$\{adminRole\}/);
  assert.match(provisioner, /tenant_security_baseline/);
  assert.match(provisioner, /assert_database_tenant/);
  assert.match(provisioner, /tenant_domains/);
  assert.match(provisioner, /ChangeResourceRecordSetsCommand/);
  assert.match(provisioner, /await verifyDatabase\(\["PROVISIONING", "ACTIVE"\]\)/);
  assert.match(provisioner, /GRANT EXECUTE ON FUNCTION scopeproof\.current_tenant_id\(\)/);
  assert.match(provisioner, /await setDatabaseTenantStatus\("PROVISIONING", \["PROVISIONING", "ACTIVE"\]\)/);
  assert.match(provisioner, /SELECT set_config\('scopeproof\.tenant_id', :tenant_id, true\)/);
  assert.match(provisioner, /SCRAM-SHA-256/);
  assert.match(provisioner, /pbkdf2Sync\(password, salt, iterations, 32, "sha256"\)/);
  assert.match(provisioner, /import \{ transactionToken \} from "\.\/idempotency\.mjs"/);
  assert.match(provisioner, /lastProvisionExecutionId/);
  assert.match(provisioner, /"read_promoted_evidence_receipt"/);
  assert.match(provisioner, /"approve_exact_version_legal_hold"/);
  assert.match(provisioner, /"read_exact_version_legal_hold_operation"/);
  assert.match(provisioner, /p\.proname IN \('current_tenant_id', 'resolve_active_membership', 'create_upload_intent'\)/);
  assert.match(provisioner, /Tenant upload runtime is not an execute-only membership and upload identity/);
  assert.match(provisioner, /const controlRoleAllowedFunctions = Object\.freeze\(\[/);
  for (const functionName of [
    "acknowledge_legal_hold_recovery_publication",
    "current_tenant_id",
    "append_signed_audit_event",
    "read_exact_version_legal_hold_operation",
    "begin_exact_version_legal_hold_application",
    "confirm_exact_version_legal_hold",
    "expire_stale_exact_version_legal_hold_requests",
    "list_pending_exact_version_legal_holds",
    "list_unaudited_applied_legal_holds",
    "list_unaudited_expired_legal_holds",
    "record_exact_version_legal_hold_reconciliation_failure",
    "read_tenant_audit_head",
  ]) assert.match(provisioner, new RegExp(`"${functionName}"`));
  assert.match(provisioner, /fieldNumber\(functions\[0\]\) !== controlRoleAllowedFunctions\.length/);
  assert.match(provisioner, /p\.proname IN \('current_tenant_id', 'resolve_active_membership', 'reserve_exact_version_legal_hold', 'approve_exact_version_legal_hold'\)/);
  assert.match(provisioner, /fieldNumber\(functions\[0\]\) !== 4/);
  assert.match(provisioner, /p\.proname IN \('claim_promotion_fence', 'current_tenant_id', 'read_promoted_evidence_receipt', 'reconcile_promoted_evidence'\)/);
  assert.match(provisioner, /fieldNumber\(functions\[0\]\) !== 4/);
  assert.doesNotMatch(provisioner, /stableToken\(executionId/);
  assert.doesNotMatch(provisioner, /quoteLiteral\(password\)/);

  assert.match(promoter, /scanReconciliationGraceMilliseconds/);
  assert.match(promoter, /head\.LastModified/);
  assert.match(promoter, /receivedAt: \{ S: input\.uploadedAt \}/);
  assert.match(promoter, /\^usr_\[a-f0-9\]\{32\}\$/);
  assert.match(promoter, /\^evd_\[a-f0-9\]\{32\}\$/);
  assert.match(promoter, /promotionFence = :currentFence AND promotionAttemptId = :currentAttemptId[\s\S]*promotionLeaseExpiresAt <= :now/);
  assert.doesNotMatch(promoter, /promotionLeaseId = :eventId OR promotionLeaseExpiresAt/);
  assert.match(promoter, /verifyCompletedPromotion/);
  assert.match(promoter, /VerifyCommand/);
  assert.match(promoter, /readCommittedPromotionReceipt/);
  assert.match(promoter, /read_promoted_evidence_receipt/);
  assert.match(promoter, /verifyCommittedPromotionReceipt/);
  assert.match(recoveryContract, /ObjectReplicationStatuses/);
  assert.match(recoveryReconciler, /ListObjectVersionsCommand/);
  assert.match(recoveryReconciler, /verifyDestinationVersionPage/);
  assert.match(recoveryReconciler, /DESTINATION_DELETE_MARKER_PRESENT/);
  assert.match(recoveryReconciler, /DESTINATION_ORPHAN_VERSION_PRESENT/);
  const sourceVerification = recoveryReconciler.slice(
    recoveryReconciler.indexOf("async function verifySourceVersionPage"),
    recoveryReconciler.indexOf("async function verifyRecoveryChangePage"),
  );
  const changeVerification = recoveryReconciler.slice(
    recoveryReconciler.indexOf("async function verifyRecoveryChangePage"),
    recoveryReconciler.indexOf("async function verifyDestinationVersionPage"),
  );
  const destinationVerification = recoveryReconciler.slice(
    recoveryReconciler.indexOf("async function verifyDestinationVersionPage"),
    recoveryReconciler.indexOf("async function readCurrentLegalHoldExpectation"),
  );
  assert.doesNotMatch(sourceVerification, /verifiedThrough =/);
  assert.doesNotMatch(changeVerification, /verifiedThrough =/);
  assert.match(sourceVerification, /else \{[\s\S]*await verifyExactVersion\(version\.Key, version\.VersionId\);/);
  assert.match(changeVerification, /else \{[\s\S]*await verifyExactVersion\(change\.key, change\.versionId\);/);
  assert.match(destinationVerification, /verifiedThrough = :cutoff/);
  assert.ok(
    destinationVerification.indexOf("DESTINATION_ORPHAN_VERSION_PRESENT") <
      destinationVerification.indexOf("verifiedThrough = :cutoff"),
  );
  assert.match(recoveryReconciler, /Replication:OperationFailedReplication/);
  assert.match(recoveryReconciler, /assertReplicaMatches/);
  assert.match(recoveryReconciler, /ChecksumMode: "ENABLED"/);
  assert.match(recoveryReconciler, /ChecksumType !== "FULL_OBJECT"/);
  assert.match(recoveryReconciler, /verifiedThrough/);
  assert.match(recoveryReconciler, /readPromotionReceipt/);
  assert.match(recoveryReconciler, /readCurrentLegalHoldProjection\(version\.Key, version\.VersionId\)/);
  assert.match(recoveryReconciler, /legalHoldExpectationAtCutoff\(current, state\.cutoffIso\)/);
  assert.match(recoveryReconciler, /ConsistentRead: true/);
  assert.match(tenantApi, /signableHeaders: new Set\(options\.signableHeaders\)/);
  assert.match(legalHoldWorker, /publishLegalHoldRecoveryChange/);
  assert.match(legalHoldWorker, /commitAuditBeforeRecovery/);
  const auditRecoveryFlow = legalHoldWorker.slice(legalHoldWorker.indexOf("await commitAuditBeforeRecovery"));
  assert.ok(
    auditRecoveryFlow.indexOf("commitAudit: () => auditStore.append(event, receipt)") <
      auditRecoveryFlow.indexOf("publishRecovery: async (committedAudit) =>"),
    "APPLIED legal-hold audit must commit before its audit-bound recovery publication",
  );
  assert.ok(
    auditRecoveryFlow.indexOf("await publishLegalHoldRecoveryChange") <
      auditRecoveryFlow.indexOf("await source.acknowledgeRecoveryPublication"),
    "recovery acknowledgement must not clear the outbox before DynamoDB publication",
  );
  assert.match(legalHoldWorker, /evidence\.legal_hold_request_expired/);
  assert.match(legalHoldWorker, /receiptDigest/);
  assert.match(legalHoldWorker, /putRequestId: state\.receipt\.putRequestId/);
  assert.match(legalHoldWorker, /verifyRequestId: state\.receipt\.verifyRequestId/);
  assert.match(legalHoldWorker, /operationRevision: state\.operationRevision/);
  assert.match(tenantApi, /unhoistableHeaders: new Set\(options\.unhoistableHeaders\)/);
});

test("central audit stack captures exact tenant S3 data events immutably", () => {
  const { observability } = foundation();
  const template = Template.fromStack(observability);
  const synthesized = template.toJSON() as { Resources: Record<string, Record<string, unknown>> };

  template.resourceCountIs("AWS::CloudTrail::Trail", 1);
  template.hasResourceProperties("AWS::CloudTrail::Trail", {
    EnableLogFileValidation: true,
    IncludeGlobalServiceEvents: true,
    IsLogging: true,
    IsMultiRegionTrail: true,
  });
  template.hasResourceProperties("AWS::S3::Bucket", {
    ObjectLockEnabled: true,
    VersioningConfiguration: { Status: "Enabled" },
  });
  template.resourceCountIs("AWS::Logs::MetricFilter", 2);
  template.resourceCountIs("AWS::CloudWatch::Alarm", 2);
  const trail = Object.values(synthesized.Resources).find(
    (resource) => resource.Type === "AWS::CloudTrail::Trail",
  );
  assert.ok(trail);
  const trailJson = JSON.stringify(trail);
  assert.match(trailJson, /AWS::S3::Object/);
  assert.match(trailJson, /IngestBucket/);
  assert.match(trailJson, /EvidenceBucket/);
  assert.doesNotMatch(trailJson, /arn:aws:s3:::\*/);
});

test("the complete shared and tenant assembly has no cross-stack cycle", () => {
  const { app } = foundation();
  const assembly = app.synth();
  const stacks = assembly.stacks.map((artifact) => artifact.stackName).sort();
  assert.deepEqual(stacks, ["Observability", "Shared", "TenantAcme"]);
});
