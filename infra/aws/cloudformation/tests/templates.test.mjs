import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const require = createRequire(import.meta.url);
const yaml = require("js-yaml");
const cloudFormationSchema = yaml.DEFAULT_SCHEMA.extend([
  new yaml.Type("!Ref", { kind: "scalar", construct: (value) => ({ Ref: value }) }),
  new yaml.Type("!Sub", { kind: "scalar", construct: (value) => ({ "Fn::Sub": value }) }),
  new yaml.Type("!GetAtt", {
    kind: "scalar",
    construct: (value) => ({ "Fn::GetAtt": String(value).split(".", 2) }),
  }),
  new yaml.Type("!Not", { kind: "sequence", construct: (value) => ({ "Fn::Not": value }) }),
  new yaml.Type("!Equals", { kind: "sequence", construct: (value) => ({ "Fn::Equals": value }) }),
]);

const testDirectory = dirname(fileURLToPath(import.meta.url));
const templateDirectory = resolve(testDirectory, "..");
const expectedTemplates = [
  "cognito-identity-pool-direct-s3.yaml",
  "cognito-presigned-auth.yaml",
  "cross-account-hosted-ingest-role.yaml",
  "identity-center-direct-s3.yaml",
  "native-capture-evidence-bucket.yaml",
  "native-capture-identity-center-s3.yaml",
  "roles-anywhere-direct-s3.yaml",
  "s3-access-grants-instance.yaml",
  "s3-access-grants-read-grant.yaml",
];

const allowedResourceTypes = new Set([
  "AWS::Cognito::IdentityPool",
  "AWS::Cognito::IdentityPoolRoleAttachment",
  "AWS::Cognito::ManagedLoginBranding",
  "AWS::Cognito::UserPool",
  "AWS::Cognito::UserPoolClient",
  "AWS::Cognito::UserPoolDomain",
  "AWS::Cognito::UserPoolResourceServer",
  "AWS::IAM::Role",
  "AWS::RolesAnywhere::Profile",
  "AWS::S3::AccessGrant",
  "AWS::S3::AccessGrantsInstance",
  "AWS::S3::AccessGrantsLocation",
  "AWS::S3::Bucket",
  "AWS::S3::BucketPolicy",
  "AWS::SSO::Assignment",
  "AWS::SSO::PermissionSet",
]);

function loadTemplate(name) {
  const source = readFileSync(join(templateDirectory, name), "utf8");
  const document = yaml.load(source);
  return { document, source };
}

const loaded = Object.fromEntries(
  expectedTemplates.map((name) => [name, loadTemplate(name)]),
);
const legacyObservabilityPath = resolve(templateDirectory, "..", "scopeproof-s3-observability.yaml");
const legacyObservabilitySource = readFileSync(legacyObservabilityPath, "utf8");
const legacyObservability = yaml.load(legacyObservabilitySource, { schema: cloudFormationSchema });

function visit(value, callback, path = [], parentKey = undefined) {
  callback(value, path, parentKey);
  if (Array.isArray(value)) {
    value.forEach((entry, index) => visit(entry, callback, [...path, index], parentKey));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, entry] of Object.entries(value)) {
      visit(entry, callback, [...path, key], key);
    }
  }
}

function unwrapStatements(statements) {
  const result = [];
  for (const statement of statements ?? []) {
    if (statement?.["Fn::If"]) {
      result.push(statement["Fn::If"][1]);
    } else {
      result.push(statement);
    }
  }
  return result.filter((statement) => statement && typeof statement === "object");
}

function inlinePolicyStatements(document) {
  const statements = [];
  for (const resource of Object.values(document.Resources ?? {})) {
    if (resource.Type === "AWS::SSO::PermissionSet") {
      statements.push(...unwrapStatements(resource.Properties.InlinePolicy?.Statement));
    }
    if (resource.Type === "AWS::IAM::Role") {
      for (const policy of resource.Properties.Policies ?? []) {
        statements.push(...unwrapStatements(policy.PolicyDocument?.Statement));
      }
    }
  }
  return statements;
}

function scalarStrings(value) {
  const strings = [];
  visit(value, (entry) => {
    if (typeof entry === "string") strings.push(entry);
  });
  return strings;
}

test("the expected template suite exists and every YAML document parses", () => {
  const actual = readdirSync(templateDirectory)
    .filter((name) => name.endsWith(".yaml"))
    .sort();
  assert.deepEqual(actual, [...expectedTemplates].sort());

  for (const [name, { document }] of Object.entries(loaded)) {
    assert.equal(document.AWSTemplateFormatVersion, "2010-09-09", name);
    assert.ok(document.Description, `${name} must have a description`);
    assert.ok(document.Metadata?.["AWS::CloudFormation::Interface"], `${name} must group parameters`);
    assert.ok(document.Parameters, `${name} must declare parameters`);
    assert.ok(document.Resources, `${name} must declare resources`);
    assert.ok(document.Outputs, `${name} must declare outputs`);
  }
});

test("intrinsic references, conditions, dependencies, and interface parameters resolve locally", () => {
  const pseudoParameters = new Set([
    "AWS::AccountId",
    "AWS::NoValue",
    "AWS::NotificationARNs",
    "AWS::Partition",
    "AWS::Region",
    "AWS::StackId",
    "AWS::StackName",
    "AWS::URLSuffix",
  ]);

  for (const [name, { document }] of Object.entries(loaded)) {
    const parameters = new Set(Object.keys(document.Parameters ?? {}));
    const resources = new Set(Object.keys(document.Resources ?? {}));
    const conditions = new Set(Object.keys(document.Conditions ?? {}));
    const refTargets = new Set([...parameters, ...resources, ...pseudoParameters]);

    for (const group of document.Metadata["AWS::CloudFormation::Interface"].ParameterGroups ?? []) {
      for (const parameter of group.Parameters ?? []) {
        assert.ok(parameters.has(parameter), `${name}: interface references unknown parameter ${parameter}`);
      }
    }

    visit(document, (entry, path, parentKey) => {
      if (parentKey === "Ref" && typeof entry === "string") {
        assert.ok(refTargets.has(entry), `${name}: unknown Ref ${entry} at ${path.join(".")}`);
      }
      if (parentKey === "Condition" && typeof entry === "string") {
        assert.ok(conditions.has(entry), `${name}: unknown condition ${entry} at ${path.join(".")}`);
      }
      if (parentKey === "Fn::If" && Array.isArray(entry)) {
        assert.ok(conditions.has(entry[0]), `${name}: unknown Fn::If condition ${entry[0]}`);
      }
      if (parentKey === "Fn::GetAtt" && Array.isArray(entry)) {
        assert.ok(resources.has(entry[0]), `${name}: unknown Fn::GetAtt resource ${entry[0]}`);
      }
      if (parentKey === "DependsOn") {
        for (const dependency of Array.isArray(entry) ? entry : [entry]) {
          assert.ok(resources.has(dependency), `${name}: unknown dependency ${dependency}`);
        }
      }
      if (parentKey === "Fn::Sub" && typeof entry === "string") {
        for (const [, variable] of entry.matchAll(/\$\{([^}!][^}]*)\}/g)) {
          const target = variable.split(".", 1)[0];
          assert.ok(refTargets.has(target), `${name}: unknown Fn::Sub target ${target}`);
        }
      }
    });
  }
});

test("only reviewed official resource types are present and no long-lived credential resources exist", () => {
  for (const [name, { document, source }] of Object.entries(loaded)) {
    let bucketResources = 0;
    let bucketPolicies = 0;
    for (const resource of Object.values(document.Resources)) {
      assert.ok(allowedResourceTypes.has(resource.Type), `${name}: unexpected ${resource.Type}`);
      assert.notEqual(resource.Type, "AWS::IAM::User");
      assert.notEqual(resource.Type, "AWS::IAM::AccessKey");
      if (resource.Type === "AWS::S3::Bucket") bucketResources += 1;
      if (resource.Type === "AWS::S3::BucketPolicy") bucketPolicies += 1;
    }
    const provisionsNativeBucket = name === "native-capture-evidence-bucket.yaml";
    assert.equal(bucketResources, provisionsNativeBucket ? 1 : 0, `${name}: unexpected bucket count`);
    assert.equal(bucketPolicies, provisionsNativeBucket ? 1 : 0, `${name}: unexpected bucket-policy count`);
    assert.doesNotMatch(source, /\b(AKIA|ASIA)[A-Z0-9]{16}\b/, `${name}: possible access key`);
    assert.doesNotMatch(source, /SecretAccessKey|AccessKeyId/i, `${name}: access-key input is forbidden`);
  }
});

test("all IAM role sessions are bounded and all IAM allows use scoped resources", () => {
  for (const [name, { document }] of Object.entries(loaded)) {
    for (const resource of Object.values(document.Resources)) {
      if (resource.Type === "AWS::IAM::Role") {
        assert.ok(resource.Properties.MaxSessionDuration <= 3600, `${name}: role session exceeds one hour`);
      }
    }

    for (const statement of inlinePolicyStatements(document)) {
      if (statement.Effect !== "Allow") continue;
      for (const resourceString of scalarStrings(statement.Resource)) {
        assert.notEqual(resourceString, "*", `${name}/${statement.Sid}: wildcard allow resource`);
        assert.notEqual(resourceString, "arn:${AWS::Partition}:s3:::*", `${name}/${statement.Sid}: all buckets allowed`);
        assert.notEqual(resourceString, "arn:${AWS::Partition}:s3:::*/*", `${name}/${statement.Sid}: all objects allowed`);
      }
    }
  }
});

test("S3 paths and KMS purposes match the live control-scoped evidence contract", () => {
  const readTemplates = [
    "cognito-identity-pool-direct-s3.yaml",
    "identity-center-direct-s3.yaml",
    "roles-anywhere-direct-s3.yaml",
    "s3-access-grants-read-grant.yaml",
  ];
  for (const name of readTemplates) {
    const { source } = loaded[name];
    assert.match(source, /scopeproofPurpose: immutable-evidence/, `${name}: wrong promoted-evidence KMS purpose`);
    assert.match(source, /tenants\/\$\{TenantId\}\/controls\//, `${name}: missing derived tenant controls root`);
    assert.doesNotMatch(source, /scopeproofPurpose: evidence(?:\s|$)/, `${name}: legacy KMS purpose is unsafe`);
    assert.ok(loaded[name].document.Parameters.EvidenceBucketName, `${name}: evidence bucket must be explicit`);
    assert.equal(loaded[name].document.Parameters.EvidencePrefix, undefined, `${name}: operator-supplied evidence prefix is forbidden`);
  }

  for (const name of [
    "cognito-identity-pool-direct-s3.yaml",
    "identity-center-direct-s3.yaml",
  ]) {
    const { document, source } = loaded[name];
    assert.ok(document.Parameters.IngestBucketName, `${name}: optional ingest bucket must be separate`);
    assert.match(source, /tenants\/\$\{TenantId\}\/controls\/\*\/quarantine\/\*/, `${name}: wrong quarantine key contract`);
    assert.equal(document.Parameters.QuarantinePrefix, undefined, `${name}: operator-supplied quarantine prefix is forbidden`);
    const statements = inlinePolicyStatements(document);
    const putAllow = statements.find(({ Effect, Action }) =>
      Effect === "Allow" && scalarStrings(Action).includes("s3:PutObject"));
    assert.equal(putAllow?.Condition?.StringEquals?.["s3:x-amz-server-side-encryption"], "aws:kms", `${name}: upload encryption algorithm is not bound`);
    assert.ok(putAllow?.Condition?.StringEquals?.["s3:x-amz-server-side-encryption-aws-kms-key-id"], `${name}: upload KMS key is not bound`);
    assert.equal(source.includes("s3:x-amz-server-side-encryption-context"), false, `${name}: unsupported S3 IAM condition key is forbidden`);
    assert.ok(statements.some(({ Sid }) => Sid === "DenyWrongEvidencePurposeEncryptionContext"));
    assert.ok(statements.some(({ Sid }) => Sid === "DenyWrongQuarantinePurposeEncryptionContext"));
  }

  const crossAccount = loaded["cross-account-hosted-ingest-role.yaml"];
  assert.ok(crossAccount.document.Parameters.IngestBucketName);
  assert.equal(crossAccount.document.Parameters.EvidenceBucketName, undefined);
  assert.match(crossAccount.source, /tenants\/\$\{TenantId\}\/controls\/\*\/quarantine\/\*/);
  const crossAccountStatements = inlinePolicyStatements(crossAccount.document);
  const crossAccountPut = crossAccountStatements.find(({ Effect, Action }) =>
    Effect === "Allow" && scalarStrings(Action).includes("s3:PutObject"));
  assert.equal(crossAccountPut?.Condition?.StringEquals?.["s3:x-amz-server-side-encryption"], "aws:kms");
  assert.ok(crossAccountPut?.Condition?.StringEquals?.["s3:x-amz-server-side-encryption-aws-kms-key-id"]);
  assert.equal(crossAccount.source.includes("s3:x-amz-server-side-encryption-context"), false);

  const accessGrant = loaded["s3-access-grants-read-grant.yaml"].document;
  assert.ok(accessGrant.Parameters.ControlId, "Access Grants must scope each grant to one control");
});

test("direct S3 readers deny resource-policy expansion outside their exact evidence prefix", () => {
  const readTemplates = [
    "cognito-identity-pool-direct-s3.yaml",
    "identity-center-direct-s3.yaml",
    "roles-anywhere-direct-s3.yaml",
    "s3-access-grants-read-grant.yaml",
  ];
  for (const name of readTemplates) {
    const statements = inlinePolicyStatements(loaded[name].document);
    const objectBoundary = statements.find(({ Sid }) => Sid === "DenyObjectReadsOutsideExactEvidencePrefix");
    const missingPrefix = statements.find(({ Sid }) => Sid === "DenyListWithoutPrefix");
    const wrongPrefix = statements.find(({ Sid }) => Sid === "DenyListOutsideExactEvidencePrefix");
    assert.ok(objectBoundary, `${name}: missing object-read perimeter deny`);
    assert.deepEqual(objectBoundary.Action, ["s3:GetObject*"]);
    assert.equal(objectBoundary.Resource, undefined);
    assert.equal(scalarStrings(objectBoundary.NotResource).length, 1);
    assert.match(scalarStrings(objectBoundary.NotResource)[0], /\/tenants\/\$\{TenantId\}\/controls\//);

    for (const statement of [missingPrefix, wrongPrefix]) {
      assert.ok(statement, `${name}: missing list perimeter deny`);
      assert.deepEqual(new Set(statement.Action), new Set(["s3:ListBucket", "s3:ListBucketVersions"]));
      assert.deepEqual(scalarStrings(statement.Resource), ["arn:${AWS::Partition}:s3:::*"]);
    }
    assert.equal(missingPrefix.Condition.Null["s3:prefix"], "true");
    const allowedPrefix = scalarStrings(wrongPrefix.Condition.StringNotLike["s3:prefix"]);
    assert.equal(allowedPrefix.length, 1);
    assert.match(allowedPrefix[0], /^tenants\/\$\{TenantId\}\/controls\//);
    if (name === "s3-access-grants-read-grant.yaml") {
      assert.match(allowedPrefix[0], /\$\{ControlId\}/);
      assert.match(scalarStrings(objectBoundary.NotResource)[0], /\$\{ControlId\}/);
    }
  }
});

test("pseudo-parameter interpolation is only used through Fn::Sub", () => {
  for (const [name, { document }] of Object.entries(loaded)) {
    visit(document, (entry, path, parentKey) => {
      if (typeof entry !== "string" || !entry.includes("${AWS::")) return;
      assert.equal(parentKey, "Fn::Sub", `${name}: unsubstituted pseudo parameter at ${path.join(".")}`);
    });
  }
});

test("the Cognito public client is authorization-code-only, secretless, MFA-protected, and retained", () => {
  const { document } = loaded["cognito-presigned-auth.yaml"];
  const pool = document.Resources.UserPool;
  const client = document.Resources.PublicOAuthClient.Properties;

  assert.equal(pool.DeletionPolicy, "Retain");
  assert.equal(pool.Properties.DeletionProtection, "ACTIVE");
  assert.equal(pool.Properties.MfaConfiguration, "ON");
  assert.deepEqual(pool.Properties.EnabledMfas, ["SOFTWARE_TOKEN_MFA"]);
  assert.equal(pool.Properties.AdminCreateUserConfig.AllowAdminCreateUserOnly, true);
  assert.equal(client.GenerateSecret, false);
  assert.deepEqual(client.AllowedOAuthFlows, ["code"]);
  assert.equal(client.AllowedOAuthFlowsUserPoolClient, true);
  assert.equal(client.PreventUserExistenceErrors, "ENABLED");
  assert.equal(client.EnableTokenRevocation, true);
  assert.deepEqual(client.ExplicitAuthFlows, []);
  assert.equal(client.RefreshTokenRotation.Feature, "ENABLED");
  assert.ok(client.RefreshTokenRotation.RetryGracePeriodSeconds <= 30);
  assert.ok(client.AllowedOAuthScopes.includes("scopeproof/evidence.read"));
  assert.ok(client.AllowedOAuthScopes.includes("scopeproof/evidence.collect"));
  assert.equal(client.AllowedOAuthScopes.includes("scopeproof/retention.manage"), false);
  assert.equal(document.Resources.ScopeproofResourceServer.Type, "AWS::Cognito::UserPoolResourceServer");
  assert.ok(document.Resources.UserPoolDomain);
  assert.ok(document.Resources.DefaultManagedLoginBranding);
});

test("IAM Identity Center direct access is read-only and unassigned by default", () => {
  const { document } = loaded["identity-center-direct-s3.yaml"];
  assert.equal(document.Parameters.EnableQuarantineUpload.Default, "false");
  assert.equal(document.Parameters.CreateAccountAssignment.Default, "false");
  assert.equal(document.Resources.EvidencePermissionSet.Properties.SessionDuration, "PT1H");

  const statements = inlinePolicyStatements(document);
  assert.ok(statements.some(({ Sid }) => Sid === "DenyS3OverInsecureTransport"));
  assert.ok(statements.some(({ Sid }) => Sid === "DenyWrongTenantEncryptionContext"));
  assert.ok(statements.some(({ Sid }) => Sid === "DenyEvidenceWrites"));
});

test("native Capture Identity Center access matches the app prefix without bucket administration", () => {
  const { document, source } = loaded["native-capture-identity-center-s3.yaml"];
  const parameters = document.Parameters;
  const daily = document.Resources.NativeCaptureDailyPermissionSet;
  const dailyStatements = unwrapStatements(daily.Properties.InlinePolicy.Statement);

  assert.equal(parameters.EvidencePrefix.Default, undefined);
  assert.equal(parameters.EvidencePrefix.MinLength, 1);
  assert.equal(parameters.CreateDailyAccountAssignment.Default, "false");
  assert.equal(parameters.EnableVersionInventory.Default, "false");
  assert.equal(parameters.EnableValidatedDownloads.Default, "false");
  assert.equal(daily.Properties.SessionDuration, "PT1H");
  assert.ok(parameters.KmsKeyId);
  assert.equal(parameters.KmsKeyArn, undefined);

  const posture = dailyStatements.find(({ Sid }) => Sid === "ReadExactBucketPosture");
  assert.deepEqual(new Set(posture.Action), new Set([
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketVersioning",
    "s3:GetBucketOwnershipControls",
    "s3:GetEncryptionConfiguration",
    "s3:GetBucketObjectLockConfiguration",
    "s3:GetBucketPolicy",
    "s3:GetLifecycleConfiguration",
    "s3:GetReplicationConfiguration",
  ]));
  const prefixList = dailyStatements.find(({ Sid }) => Sid === "VerifyExactNativePrefix");
  assert.deepEqual(prefixList.Condition.StringLike["s3:prefix"], [
    { "Fn::Sub": "${EvidencePrefix}/" },
    { "Fn::Sub": "${EvidencePrefix}/*" },
  ]);
  const put = dailyStatements.find(({ Sid }) => Sid === "WriteExactNativePrefix");
  assert.deepEqual(put.Condition.StringEquals["s3:x-amz-server-side-encryption"], {
    "Fn::If": ["UseSseKms", "aws:kms", "aws:kms:dsse"],
  });
  const derivedKeyArn = {
    "Fn::Sub": "arn:${AWS::Partition}:kms:${AWS::Region}:${BucketOwnerAccountId}:key/${KmsKeyId}",
  };
  assert.deepEqual(put.Condition.StringEquals["s3:x-amz-server-side-encryption-aws-kms-key-id"], derivedKeyArn);
  const describeKey = dailyStatements.find(({ Sid }) => Sid === "DescribeExactNativeKmsKey");
  assert.deepEqual(describeKey.Action, ["kms:DescribeKey"]);
  assert.deepEqual(describeKey.Resource, [derivedKeyArn]);
  const kmsBoundary = dailyStatements.find(({ Sid }) => Sid === "DenyNativeKmsUseOutsideConfiguredKey");
  assert.ok(kmsBoundary.Action.includes("kms:DescribeKey"));
  assert.deepEqual(kmsBoundary.NotResource, [derivedKeyArn]);
  assert.deepEqual(document.Outputs.KmsKeyArn.Value, derivedKeyArn);
  assert.equal(
    scalarStrings(describeKey.Resource).some((value) => value.includes("${BucketOwnerAccountId}")),
    true,
    "DescribeKey must be bound to the configured bucket-owner account",
  );
  assert.ok(dailyStatements.some(({ Sid }) => Sid === "ListExactNativeVersions"));
  assert.ok(dailyStatements.some(({ Sid }) => Sid === "ReadExactNativeVersion"));
  assert.ok(dailyStatements.some(({ Sid }) => Sid === "DenyNativeDestructiveObjectActions"));
  assert.ok(dailyStatements.some(({ Sid }) => Sid === "DenyNativeKmsOutsideRegionalS3"));
  assert.match(source, /arn:\$\{AWS::Partition\}:s3:::\$\{EvidenceBucketName\}\/\$\{EvidencePrefix\}\/\*/);
  assert.match(source, /kms:EncryptionContext:aws:s3:arn/);
  assert.doesNotMatch(source, /scopeproofTenantId|scopeproofPurpose/);
  assert.doesNotMatch(source, /s3:x-amz-server-side-encryption-context/);
  assert.equal(parameters.TenantId, undefined);
  assert.equal(parameters.IngestBucketName, undefined);

  assert.equal(source.includes("StringLikeIfExists"), false);
  assert.equal(document.Resources.DailyAccountAssignment.Condition, "CreateDailyAssignment");
  assert.equal(document.Resources.NativeCaptureSetupPermissionSet, undefined);
  assert.equal(document.Resources.SetupAccountAssignment, undefined);
  const allowedActions = new Set(scalarStrings(
    dailyStatements.filter(({ Effect }) => Effect === "Allow").map(({ Action }) => Action),
  ));
  for (const forbidden of [
    "s3:CreateBucket", "s3:PutBucketPolicy", "s3:PutBucketPublicAccessBlock",
    "s3:PutLifecycleConfiguration", "s3:PutReplicationConfiguration", "iam:PassRole",
  ]) assert.equal(allowedActions.has(forbidden), false, `daily access unexpectedly allows ${forbidden}`);
});

test("native Capture bucket provisioning is fixed, retained, private, encrypted, and immutable", () => {
  const { document, source } = loaded["native-capture-evidence-bucket.yaml"];
  const bucket = document.Resources.NativeEvidenceBucket;
  const bucketPolicy = document.Resources.NativeEvidenceBucketPolicy;
  const policy = bucketPolicy.Properties.PolicyDocument.Statement;

  assert.equal(bucket.Type, "AWS::S3::Bucket");
  assert.equal(bucket.DeletionPolicy, "Retain");
  assert.equal(bucket.UpdateReplacePolicy, "Retain");
  assert.equal(bucketPolicy.DeletionPolicy, "Retain");
  assert.equal(bucketPolicy.UpdateReplacePolicy, "Retain");
  assert.equal(bucket.Properties.ObjectLockEnabled, true);
  assert.equal(bucket.Properties.ObjectLockConfiguration.ObjectLockEnabled, "Enabled");
  assert.equal(bucket.Properties.ObjectLockConfiguration.Rule.DefaultRetention.Mode, "COMPLIANCE");
  assert.equal(document.Parameters.ObjectLockMode, undefined);
  assert.ok(document.Parameters.KmsKeyId);
  assert.equal(document.Parameters.KmsKeyArn, undefined);
  assert.deepEqual(bucket.Properties.VersioningConfiguration, { Status: "Enabled" });
  assert.deepEqual(bucket.Properties.OwnershipControls.Rules, [{ ObjectOwnership: "BucketOwnerEnforced" }]);
  assert.deepEqual(bucket.Properties.PublicAccessBlockConfiguration, {
    BlockPublicAcls: true,
    BlockPublicPolicy: true,
    IgnorePublicAcls: true,
    RestrictPublicBuckets: true,
  });
  const encryption = bucket.Properties.BucketEncryption.ServerSideEncryptionConfiguration[0];
  assert.deepEqual(encryption.BucketKeyEnabled, {
    "Fn::If": ["UseSseKms", true, { Ref: "AWS::NoValue" }],
  });
  const derivedKeyArn = {
    "Fn::Sub": "arn:${AWS::Partition}:kms:${AWS::Region}:${AWS::AccountId}:key/${KmsKeyId}",
  };
  assert.deepEqual(encryption.ServerSideEncryptionByDefault.KMSMasterKeyID, derivedKeyArn);
  assert.deepEqual(encryption.ServerSideEncryptionByDefault.SSEAlgorithm, {
    "Fn::If": ["UseSseKms", "aws:kms", "aws:kms:dsse"],
  });
  assert.equal(bucket.Properties.LifecycleConfiguration, undefined);
  assert.deepEqual(policy.map(({ Sid }) => Sid), [
    "ScopeproofDenyInsecureTransport",
    "ScopeproofDenyBucketDeletion",
    "ScopeproofDenyEvidenceDeletion",
    "ScopeproofDenyWrongEncryption",
    "ScopeproofDenyWrongKMSKey",
  ]);
  assert.deepEqual(policy[2].Action, [
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:BypassGovernanceRetention",
  ]);
  assert.deepEqual(policy[4].Condition.StringNotEquals["s3:x-amz-server-side-encryption-aws-kms-key-id"], derivedKeyArn);
  assert.deepEqual(document.Outputs.KmsKeyArn.Value, derivedKeyArn);
  assert.equal(document.Outputs.ObjectLockMode.Value, "COMPLIANCE");
  assert.ok(bucket.Properties.Tags.some(({ Key, Value }) =>
    Key === "SecurityProfile" && Value === "production-compliance"));
  assert.match(document.Description, /Governance retention is intentionally unsupported/i);
  assert.doesNotMatch(source, /AWS::IAM::|AWS::SSO::|AccessKey|PutBucketPolicy|PutLifecycleConfiguration|PutReplicationConfiguration/);
  assert.doesNotMatch(source, /s3:x-amz-server-side-encryption-context/);
});

test("Cognito identity-pool direct access owns a hardened tenant-only user directory", () => {
  const { document, source } = loaded["cognito-identity-pool-direct-s3.yaml"];
  const pool = document.Resources.AuthenticatedIdentityPool.Properties;
  const tenantUserPool = document.Resources.DedicatedTenantUserPool;
  const tenantClient = document.Resources.DedicatedTenantPublicOAuthClient.Properties;
  const trust = document.Resources.AuthenticatedEvidenceRole.Properties.AssumeRolePolicyDocument.Statement[0];

  assert.equal(pool.AllowUnauthenticatedIdentities, false);
  assert.equal(pool.AllowClassicFlow, false);
  assert.deepEqual(pool.IdentityPoolTags, [
    { Key: "Application", Value: "scopeproof" },
    { Key: "TenantId", Value: { Ref: "TenantId" } },
    { Key: "IsolationMode", Value: "dedicated-user-pool" },
  ]);
  assert.equal(pool.CognitoIdentityProviders[0].ServerSideTokenCheck, true);
  assert.deepEqual(pool.CognitoIdentityProviders[0].ClientId, {
    Ref: "DedicatedTenantPublicOAuthClient",
  });
  assert.deepEqual(pool.CognitoIdentityProviders[0].ProviderName, {
    "Fn::GetAtt": ["DedicatedTenantUserPool", "ProviderName"],
  });
  assert.equal(document.Parameters.UserPoolId, undefined);
  assert.equal(document.Parameters.UserPoolClientId, undefined);
  assert.equal(document.Parameters.DedicatedTenantUserPoolConfirmed, undefined);

  assert.equal(tenantUserPool.DeletionPolicy, "Retain");
  assert.equal(tenantUserPool.UpdateReplacePolicy, "Retain");
  assert.equal(tenantUserPool.Properties.DeletionProtection, "ACTIVE");
  assert.equal(tenantUserPool.Properties.AdminCreateUserConfig.AllowAdminCreateUserOnly, true);
  assert.equal(tenantUserPool.Properties.MfaConfiguration, "ON");
  assert.deepEqual(tenantUserPool.Properties.EnabledMfas, ["SOFTWARE_TOKEN_MFA"]);
  assert.deepEqual(tenantUserPool.Properties.UserPoolTags.TenantId, { Ref: "TenantId" });

  assert.deepEqual(tenantClient.UserPoolId, { Ref: "DedicatedTenantUserPool" });
  assert.equal(tenantClient.GenerateSecret, false);
  assert.equal(tenantClient.AllowedOAuthFlowsUserPoolClient, true);
  assert.deepEqual(tenantClient.AllowedOAuthFlows, ["code"]);
  assert.deepEqual(tenantClient.ExplicitAuthFlows, []);
  assert.equal(tenantClient.PreventUserExistenceErrors, "ENABLED");
  assert.equal(tenantClient.EnableTokenRevocation, true);
  assert.equal(tenantClient.RefreshTokenRotation.Feature, "ENABLED");
  assert.ok(tenantClient.RefreshTokenRotation.RetryGracePeriodSeconds <= 30);
  assert.deepEqual(tenantClient.CallbackURLs, { Ref: "CallbackUrls" });
  assert.deepEqual(tenantClient.LogoutURLs, { Ref: "LogoutUrls" });
  assert.equal(trust.Condition["ForAnyValue:StringLike"]["cognito-identity.amazonaws.com:amr"], "authenticated");
  assert.ok(trust.Condition.StringEquals["cognito-identity.amazonaws.com:aud"]);
  assert.doesNotMatch(source, /^\s*unauthenticated:/m);
});

test("cross-account ingest requires an exact role and external ID and remains write-only", () => {
  const { document } = loaded["cross-account-hosted-ingest-role.yaml"];
  assert.equal(document.Parameters.ExternalId.MinLength, 32);
  assert.match(document.Parameters.SourcePrincipalArn.AllowedPattern, /:role\//);

  const trust = document.Resources.HostedIngestRole.Properties.AssumeRolePolicyDocument.Statement[0];
  assert.ok(trust.Condition.ArnEquals["aws:PrincipalArn"]);
  assert.ok(trust.Condition.StringEquals["sts:ExternalId"]);

  const statements = inlinePolicyStatements(document);
  const allows = statements.filter(({ Effect }) => Effect === "Allow");
  const allowedActions = scalarStrings(allows.map(({ Action }) => Action));
  assert.deepEqual(new Set(allowedActions), new Set(["s3:PutObject", "kms:GenerateDataKey"]));
  assert.ok(statements.some(({ Sid }) => Sid === "DenyAnyObjectPutOutsideExactQuarantinePrefix"));
  assert.ok(statements.some(({ Sid }) => Sid === "DenyS3ReadsListingsAndDestructiveActions"));
  assert.ok(statements.some(({ Sid }) => Sid === "DenyWrongPurposeEncryptionContext"));
});

test("Roles Anywhere is anchor- and certificate-bound with a disabled 15-minute profile", () => {
  const { document } = loaded["roles-anywhere-direct-s3.yaml"];
  const role = document.Resources.RolesAnywhereEvidenceRole.Properties;
  const trust = role.AssumeRolePolicyDocument.Statement[0];
  const profile = document.Resources.EvidenceProfile.Properties;

  assert.ok(trust.Condition.ArnEquals["aws:SourceArn"]);
  assert.ok(trust.Condition.StringEquals["aws:SourceAccount"]);
  assert.ok(trust.Condition.StringEquals["aws:PrincipalTag/x509Subject/CN"]);
  assert.deepEqual(new Set(trust.Action), new Set(["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"]));
  assert.equal(document.Parameters.EnableProfile.Default, "false");
  assert.equal(profile.DurationSeconds, 900);
  assert.equal(profile.AcceptRoleSessionName, false);
  assert.equal(profile.RoleArns.length, 1);
  assert.equal(profile.AttributeMappings[0].CertificateField, "x509Subject");
  assert.equal(profile.AttributeMappings[0].MappingRules[0].Specifier, "CN");
  assert.doesNotThrow(() => JSON.parse(profile.SessionPolicy["Fn::Sub"]));
});

test("S3 Access Grants uses official resources, exact service trust, and READ only", () => {
  const instance = loaded["s3-access-grants-instance.yaml"].document;
  const grant = loaded["s3-access-grants-read-grant.yaml"].document;

  assert.equal(instance.Resources.RegionalAccessGrantsInstance.Type, "AWS::S3::AccessGrantsInstance");
  assert.equal(instance.Resources.RegionalAccessGrantsInstance.DeletionPolicy, "Retain");
  assert.equal(grant.Resources.TenantEvidenceLocation.Type, "AWS::S3::AccessGrantsLocation");
  assert.equal(grant.Resources.TenantEvidenceReadGrant.Type, "AWS::S3::AccessGrant");
  assert.equal(grant.Resources.TenantEvidenceReadGrant.Properties.Permission, "READ");

  const trustDocument = grant.Resources.AccessGrantsLocationRole.Properties.AssumeRolePolicyDocument;
  const baseTrust = trustDocument.Statement[0];
  const setContextIntrinsic = trustDocument.Statement[1]["Fn::If"];
  const setContextTrust = setContextIntrinsic[1];
  assert.equal(baseTrust.Principal.Service, "access-grants.s3.amazonaws.com");
  assert.deepEqual(new Set(baseTrust.Action), new Set(["sts:AssumeRole", "sts:SetSourceIdentity"]));
  assert.equal(baseTrust.Action.includes("sts:SetContext"), false);
  assert.ok(baseTrust.Condition.StringEquals["aws:SourceAccount"]);
  assert.ok(baseTrust.Condition.StringEquals["aws:SourceArn"]);

  assert.equal(setContextIntrinsic[0], "GranteeIsDirectoryGroup");
  assert.deepEqual(setContextIntrinsic[2], { Ref: "AWS::NoValue" });
  assert.equal(setContextTrust.Principal.Service, "access-grants.s3.amazonaws.com");
  assert.deepEqual(setContextTrust.Action, ["sts:SetContext"]);
  assert.deepEqual(
    setContextTrust.Condition.StringEquals,
    baseTrust.Condition.StringEquals,
    "SetContext must retain the exact Access Grants source account and ARN",
  );
  assert.deepEqual(
    setContextTrust.Condition["ForAllValues:ArnEquals"]["sts:RequestContextProviders"],
    [{ "Fn::Sub": "arn:${AWS::Partition}:iam::aws:contextProvider/IdentityCenter" }],
  );
  assert.equal(setContextTrust.Condition.Null["sts:RequestContextProviders"], "false");
  assert.deepEqual(grant.Conditions.GranteeIsDirectoryGroup, {
    "Fn::Equals": [{ Ref: "GranteeMode" }, "DIRECTORY_GROUP"],
  });
  assert.equal(grant.Parameters.DirectoryApplicationArn.Default, "");
  assert.match(
    grant.Parameters.DirectoryApplicationArn.AllowedPattern,
    /:sso::\[0-9\]\{12\}:application\//,
  );
  assert.deepEqual(grant.Rules.RequireDirectoryApplication.RuleCondition, {
    "Fn::Equals": [{ Ref: "GranteeMode" }, "DIRECTORY_GROUP"],
  });
  assert.deepEqual(grant.Rules.RequireDirectoryApplication.Assertions[0].Assert, {
    "Fn::Not": [{ "Fn::Equals": [{ Ref: "DirectoryApplicationArn" }, ""] }],
  });
  assert.deepEqual(grant.Rules.RejectDirectoryApplicationForIamRole.RuleCondition, {
    "Fn::Equals": [{ Ref: "GranteeMode" }, "IAM_ROLE"],
  });
  assert.deepEqual(grant.Rules.RejectDirectoryApplicationForIamRole.Assertions[0].Assert, {
    "Fn::Equals": [{ Ref: "DirectoryApplicationArn" }, ""],
  });
  assert.deepEqual(grant.Resources.TenantEvidenceReadGrant.Properties.ApplicationArn, {
    "Fn::If": [
      "GranteeIsDirectoryGroup",
      { Ref: "DirectoryApplicationArn" },
      { Ref: "AWS::NoValue" },
    ],
  });
  assert.match(grant.Parameters.IamRoleGranteeArn.AllowedPattern, /:role\//);
  assert.doesNotMatch(grant.Parameters.IamRoleGranteeArn.AllowedPattern, /:user\//);
});

test("legacy S3 observability uses retained compliance storage and explicit destructive denies", () => {
  const trailKey = legacyObservability.Resources.TrailLogKey;
  const bucket = legacyObservability.Resources.TrailLogBucket;
  const policy = legacyObservability.Resources.TrailLogBucketPolicy;
  assert.equal(trailKey.Type, "AWS::KMS::Key");
  assert.equal(trailKey.DeletionPolicy, "Retain");
  assert.equal(trailKey.UpdateReplacePolicy, "Retain");
  assert.equal(trailKey.Properties.EnableKeyRotation, true);
  const cloudTrailEncrypt = trailKey.Properties.KeyPolicy.Statement
    .find(({ Sid }) => Sid === "AllowCloudTrailLogEncryption");
  assert.deepEqual(cloudTrailEncrypt.Principal, { Service: "cloudtrail.amazonaws.com" });
  assert.deepEqual(cloudTrailEncrypt.Action, "kms:GenerateDataKey*");
  assert.ok(cloudTrailEncrypt.Condition.StringEquals["aws:SourceArn"]);
  assert.ok(cloudTrailEncrypt.Condition.StringLike["kms:EncryptionContext:aws:cloudtrail:arn"]);
  assert.equal(bucket.DeletionPolicy, "Retain");
  assert.equal(bucket.UpdateReplacePolicy, "Retain");
  assert.equal(bucket.Properties.ObjectLockEnabled, true);
  assert.equal(bucket.Properties.ObjectLockConfiguration.Rule.DefaultRetention.Mode, "COMPLIANCE");
  assert.ok(bucket.Properties.ObjectLockConfiguration.Rule.DefaultRetention.Days >= 365);
  assert.equal(bucket.Properties.VersioningConfiguration.Status, "Enabled");
  const defaultEncryption = bucket.Properties.BucketEncryption.ServerSideEncryptionConfiguration[0];
  assert.equal(defaultEncryption.ServerSideEncryptionByDefault.SSEAlgorithm, "aws:kms");
  assert.deepEqual(defaultEncryption.ServerSideEncryptionByDefault.KMSMasterKeyID, {
    "Fn::GetAtt": ["TrailLogKey", "Arn"],
  });
  assert.equal(defaultEncryption.BucketKeyEnabled, true);
  assert.equal(policy.DeletionPolicy, "Retain");
  assert.equal(policy.UpdateReplacePolicy, "Retain");

  const statements = policy.Properties.PolicyDocument.Statement;
  const objectDeny = statements.find(({ Sid }) => Sid === "DenyAuditLogDestruction");
  const bucketDeny = statements.find(({ Sid }) => Sid === "DenyAuditBucketDestruction");
  assert.equal(objectDeny.Effect, "Deny");
  assert.equal(objectDeny.Principal, "*");
  assert.deepEqual(new Set(objectDeny.Action), new Set([
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:BypassGovernanceRetention",
  ]));
  assert.equal(bucketDeny.Effect, "Deny");
  assert.deepEqual(new Set(bucketDeny.Action), new Set(["s3:DeleteBucket", "s3:DeleteBucketPolicy"]));
  assert.equal(legacyObservability.Resources.EvidenceTrail.Properties.EnableLogFileValidation, true);
  assert.equal(legacyObservability.Resources.EvidenceTrail.Properties.IsMultiRegionTrail, true);
  assert.deepEqual(legacyObservability.Resources.EvidenceTrail.Properties.KMSKeyId, { Ref: "TrailLogKey" });
});

test("legacy security alerts cover both buckets, all accepted KMS identifiers, and exact EventBridge publishers", () => {
  const alertKey = legacyObservability.Resources.SecurityAlertKey;
  assert.equal(alertKey.Type, "AWS::KMS::Key");
  assert.equal(alertKey.DeletionPolicy, "Retain");
  assert.equal(alertKey.UpdateReplacePolicy, "Retain");
  assert.equal(alertKey.Properties.EnableKeyRotation, true);
  const eventBridgeKeyGrant = alertKey.Properties.KeyPolicy.Statement
    .find(({ Sid }) => Sid === "AllowEventBridgeEncryptedPublishing");
  assert.deepEqual(eventBridgeKeyGrant.Principal, { Service: "events.amazonaws.com" });
  assert.deepEqual(new Set(eventBridgeKeyGrant.Action), new Set(["kms:Decrypt", "kms:GenerateDataKey"]));
  assert.deepEqual(legacyObservability.Resources.SecurityAlertTopic.Properties.KmsMasterKeyId, {
    "Fn::GetAtt": ["SecurityAlertKey", "Arn"],
  });

  const s3Pattern = legacyObservability.Resources.S3SecurityChangeRule.Properties.EventPattern;
  assert.deepEqual(s3Pattern.detail.requestParameters.bucketName, [
    { Ref: "EvidenceBucketName" },
    { Ref: "TrailLogBucketName" },
  ]);
  for (const eventName of [
    "DeleteObject", "DeleteObjects", "PutBucketPolicy", "DeleteBucketPolicy",
    "PutBucketVersioning", "PutObjectLockConfiguration", "DeleteBucketEncryption",
  ]) assert.ok(s3Pattern.detail.eventName.includes(eventName), `missing S3 alert event ${eventName}`);

  const kmsPattern = legacyObservability.Resources.KMSSecurityChangeRule.Properties.EventPattern;
  assert.equal(kmsPattern.detail.requestParameters, undefined, "account-wide KMS matching must not be bypassable with an ARN, UUID, or alias");
  for (const eventName of [
    "CreateAlias", "UpdateAlias", "DeleteAlias", "CreateGrant", "RetireGrant", "RevokeGrant",
    "DisableKey", "DisableKeyRotation", "DeleteImportedKeyMaterial", "ScheduleKeyDeletion",
    "PutKeyPolicy", "ReplicateKey", "RotateKeyOnDemand", "UpdatePrimaryRegion",
  ]) assert.ok(kmsPattern.detail.eventName.includes(eventName), `missing KMS alert event ${eventName}`);

  const cloudTrailEvents = legacyObservability.Resources.CloudTrailSecurityChangeRule.Properties.EventPattern.detail.eventName;
  for (const eventName of ["DeleteTrail", "PutEventSelectors", "StopLogging", "UpdateTrail"]) {
    assert.ok(cloudTrailEvents.includes(eventName), `missing CloudTrail alert event ${eventName}`);
  }

  const publish = legacyObservability.Resources.SecurityAlertTopicPolicy.Properties.PolicyDocument.Statement
    .find(({ Sid }) => Sid === "AllowEventBridgePublish");
  assert.deepEqual(publish.Condition.StringEquals["aws:SourceAccount"], { Ref: "AWS::AccountId" });
  assert.deepEqual(new Set(publish.Condition.ArnEquals["aws:SourceArn"].map((value) => value["Fn::GetAtt"][0])), new Set([
    "S3SecurityChangeRule",
    "S3AccountPublicAccessChangeRule",
    "KMSSecurityChangeRule",
    "CloudTrailSecurityChangeRule",
  ]));
});

test("legacy observability intrinsic references resolve within the template", () => {
  const parameters = new Set(Object.keys(legacyObservability.Parameters));
  const resources = new Set(Object.keys(legacyObservability.Resources));
  const conditions = new Set(Object.keys(legacyObservability.Conditions));
  const refs = new Set([...parameters, ...resources, "AWS::AccountId", "AWS::Partition", "AWS::Region"]);
  visit(legacyObservability, (entry, path, parentKey) => {
    if (parentKey === "Ref" && typeof entry === "string") {
      assert.ok(refs.has(entry), `legacy observability: unknown Ref ${entry} at ${path.join(".")}`);
    }
    if (parentKey === "Fn::GetAtt" && Array.isArray(entry)) {
      assert.ok(resources.has(entry[0]), `legacy observability: unknown Fn::GetAtt ${entry[0]}`);
    }
    if (parentKey === "Condition" && typeof entry === "string") {
      assert.ok(conditions.has(entry), `legacy observability: unknown condition ${entry}`);
    }
    if (parentKey === "DependsOn") {
      for (const dependency of Array.isArray(entry) ? entry : [entry]) {
        assert.ok(resources.has(dependency), `legacy observability: unknown dependency ${dependency}`);
      }
    }
    if (parentKey === "Fn::Sub" && typeof entry === "string") {
      for (const [, variable] of entry.matchAll(/\$\{([^}!][^}]*)\}/g)) {
        const target = variable.split(".", 1)[0];
        assert.ok(refs.has(target), `legacy observability: unknown Fn::Sub target ${target}`);
      }
    }
  });
});
