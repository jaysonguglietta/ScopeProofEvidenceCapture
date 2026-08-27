import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as path from "node:path";
import test from "node:test";
import { App } from "aws-cdk-lib";
import { Match, Template } from "aws-cdk-lib/assertions";
import {
  parseTenants,
  tenantDatabaseIdentifiers,
  validateBranchName,
  validateRootDomain,
  validateTenant,
} from "../lib/config";
import { ObservabilityStack } from "../lib/observability-stack";
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
  assert.notEqual(firstIdentifiers.ownerUsername, secondIdentifiers.ownerUsername);
  for (const identifier of Object.values(firstIdentifiers)) assert.ok(identifier.length <= 63);

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
  assert.ok(domain);
  assert.doesNotMatch(JSON.stringify(domain), /"Prefix":"\*"/);
  assert.equal(
    recordSets.some((record) => JSON.stringify(record.Properties).includes("*.evidence.example.com")),
    false,
  );
  assert.equal(
    recordSets.some((record) => JSON.stringify(record.Properties).includes("acme.evidence.example.com")),
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
  template.hasResourceProperties("AWS::DynamoDB::Table", {
    BillingMode: "PAY_PER_REQUEST",
    DeletionProtectionEnabled: true,
    PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
  });
  template.hasResourceProperties("AWS::Events::Rule", { State: "DISABLED" });
  assert.match(JSON.stringify(synthesized), /role\/scopeproof\/tenants\/sp-\*-data/);
  assert.equal(
    Object.values(synthesized.Resources).some((resource) => resource.Type === "Custom::AWS"),
    false,
  );
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
  assert.match(JSON.stringify(quarantine), /"NoncurrentDays":1/);
  assert.match(JSON.stringify(quarantine), /"ExpirationInDays":1/);

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

  const tenantPolicy = Object.values(synthesized.Resources).find((resource) =>
    resource.Type === "AWS::IAM::Policy" && JSON.stringify(resource).includes("TenantDataRole"));
  assert.ok(tenantPolicy);
  const policyJson = JSON.stringify(tenantPolicy);
  assert.doesNotMatch(policyJson, /"Effect":"Allow","Resource":"\*"/);
  assert.doesNotMatch(policyJson, /"Action":"s3:\*"/);
  assert.doesNotMatch(policyJson, /s3:DeleteObject|s3:PutObjectRetention/);
  assert.match(policyJson, /s3:PutObject/);
  assert.match(policyJson, /x-amz-server-side-encryption-context/);
  assert.match(policyJson, /tenants\/ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\/quarantine/);
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
  template.resourceCountIs("AWS::Lambda::Function", 3);
  assert.equal(
    Object.values(synthesized.Resources).filter(
      (resource) =>
        resource.Type === "AWS::Lambda::Function" &&
        JSON.stringify(resource).includes('"Architectures":["arm64"]'),
    ).length,
    2,
  );
  template.resourceCountIs("AWS::SQS::Queue", 2);
  template.hasResourceProperties("AWS::Events::Rule", { State: "DISABLED" });
  assert.match(JSON.stringify(synthesized), /NO_THREATS_FOUND/);
  assert.match(JSON.stringify(synthesized), /GuardDuty Malware Protection Object Scan Result/);
  assert.match(JSON.stringify(synthesized), /ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/);
  assert.match(JSON.stringify(synthesized), /route53:ChangeResourceRecordSets/);
  assert.match(JSON.stringify(synthesized), /ChangeResourceRecordSetsNormalizedRecordNames/);
  assert.match(JSON.stringify(synthesized), /acme\.evidence\.example\.com/);
  assert.match(JSON.stringify(synthesized), /DISABLED_PENDING_UPLOAD_INTENT_ISSUER/);
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
  assert.doesNotMatch(provisioner, /quoteLiteral\(password\)/);

  assert.match(promoter, /intent\.status === "issued" && Date\.parse\(intent\.expiresAt\)/);
  assert.match(promoter, /\^usr_\[a-f0-9\]\{32\}\$/);
  assert.match(promoter, /\^evd_\[a-f0-9\]\{32\}\$/);
  assert.match(promoter, /attribute_not_exists\(promotionLeaseExpiresAt\) OR promotionLeaseExpiresAt < :now/);
  assert.doesNotMatch(promoter, /promotionLeaseId = :eventId OR promotionLeaseExpiresAt/);
  assert.match(promoter, /verifyCompletedPromotion/);
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
