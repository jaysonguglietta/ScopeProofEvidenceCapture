import assert from "node:assert/strict";
import test from "node:test";
import { App, Stack } from "aws-cdk-lib";
import { Template } from "aws-cdk-lib/assertions";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as kms from "aws-cdk-lib/aws-kms";
import * as secrets from "aws-cdk-lib/aws-secretsmanager";
import { DatabaseBootstrapStack } from "../lib/database-bootstrap-stack";
import type { TenantDatabaseBootstrapSource } from "../lib/database-bootstrap-mapping";
import type { SharedPlatformStack } from "../lib/shared-platform-stack";

interface PolicyStatement { Action: string | string[]; Condition: Record<string, Record<string, unknown>> }
interface SynthesizedResource {
  Type: string;
  Properties: { Roles: unknown; PolicyDocument: { Statement: PolicyStatement[] }; Environment?: { Variables?: Record<string, unknown> } };
}

test("known customer/provisioner role paths cannot be nominated as platform bootstrap operators", () => {
  for (const rolePath of ["tenants/sp-acme-data", "provisioning/sp-acme", "api/tenant", "capture/device", "evidence/worker"]) {
    assert.throws(() => new DatabaseBootstrapStack(new App(), "Denied", {
      env: { account: "111111111111", region: "us-east-1" }, shared: {} as SharedPlatformStack, sources: [],
      operatorPrincipalArn: `arn:aws:iam::111111111111:role/scopeproof/${rolePath}`, approverPrincipalArn: "arn:aws:iam::111111111111:role/platform/approver",
    }), /distinct, explicit platform operator/);
  }
});

test("bootstrap template isolates operator approval, immutable mappings and shared-secret authority", () => {
  const app = new App();
  const env = { account: "111111111111", region: "us-east-1" };
  const platform = new Stack(app, "BootstrapFixturePlatform", { env });
  const key = new kms.Key(platform, "SecretsKey");
  const admin = new secrets.Secret(platform, "AdminSecret", { encryptionKey: key });
  const controlTable = new dynamodb.TableV2(platform, "Control", { partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING }, sortKey: { name: "SK", type: dynamodb.AttributeType.STRING } });
  const clusterArn = `arn:aws:rds:${env.region}:${env.account}:cluster:scopeproof-fixture`;
  const shared = { databaseCluster: { clusterArn, secret: admin }, controlTable } as unknown as SharedPlatformStack;
  const sources: TenantDatabaseBootstrapSource[] = ["a", "b"].map((letter) => {
    const roles = ["provisioning", "runtime", "ingest", "control", "legalApi", "read", "apiAudit"].map((kind) => ({ kind,
      username: `tenant_${letter.repeat(32)}_${kind.toLowerCase()}`, secret: new secrets.Secret(platform, `${letter}-${kind}`, { encryptionKey: key }) }));
    return { mapping: { schemaVersion: 1, account: env.account, region: env.region, clusterArn, databaseName: `scopeproof_${letter}`,
      tenantId: `ten_${letter.repeat(32)}`, revision: 1, ownerUsername: `scopeproof_${letter.repeat(32)}_owner`,
      roles: roles.map(({ secret, ...role }) => ({ ...role, secretArn: secret.secretArn })) }, secrets: roles.map((role) => role.secret) };
  });
  const bootstrap = new DatabaseBootstrapStack(app, "BootstrapFixture", { env, shared, sources,
    operatorPrincipalArn: `arn:aws:iam::${env.account}:role/platform/operator`, approverPrincipalArn: `arn:aws:iam::${env.account}:role/platform/approver` });
  const template = Template.fromStack(bootstrap);
  template.resourceCountIs("AWS::StepFunctions::StateMachine", 1);
  template.resourceCountIs("AWS::DynamoDB::Table", 2);
  const resources = template.toJSON().Resources as Record<string, SynthesizedResource>;
  const policies = Object.entries(resources).filter(([, value]) => value.Type === "AWS::IAM::Policy");
  const statementsFor = (roleFragment: string) => policies.filter(([, value]) => JSON.stringify(value.Properties.Roles).includes(roleFragment))
    .flatMap(([, value]) => value.Properties.PolicyDocument.Statement);
  const actions = (statements: PolicyStatement[]) => statements.flatMap((statement) => Array.isArray(statement.Action) ? statement.Action : [statement.Action]);
  assert.ok(actions(statementsFor("BootstrapOperatorRole")).includes("states:StartExecution"));
  assert.ok(!actions(statementsFor("BootstrapOperatorRole")).includes("dynamodb:PutItem"));
  assert.ok(actions(statementsFor("BootstrapApproverRole")).includes("dynamodb:PutItem"));
  assert.ok(!actions(statementsFor("BootstrapApproverRole")).includes("states:StartExecution"));
  for (const fragment of ["BootstrapOperatorRole", "BootstrapApproverRole"]) assert.ok(!actions(statementsFor(fragment)).some((action: string) => action.startsWith("rds-data:") || action.startsWith("secretsmanager:")));
  const workerStatements = statementsFor("CentralDatabaseBootstrapServiceRole");
  assert.ok(actions(workerStatements).includes("rds-data:ExecuteStatement"));
  for (const statement of workerStatements.filter((statement) => actions([statement]).includes("dynamodb:PutItem"))) {
    assert.deepEqual(statement.Condition["ForAllValues:StringEquals"]["dynamodb:LeadingKeys"], sources.map(({ mapping }) => `DATABASE_BOOTSTRAP#${mapping.tenantId}`));
    assert.equal(statement.Condition.Null["dynamodb:LeadingKeys"], "false");
  }
  const mappingPublications = Object.values(resources).filter((resource) => resource.Type === "Custom::AWS");
  assert.equal(mappingPublications.length, 2);
  for (const publication of mappingPublications) assert.match(JSON.stringify(publication), /attribute_not_exists\(PK\) OR mappingJson = :same/);
  const functions = Object.values(resources).filter((resource) => resource.Type === "AWS::Lambda::Function");
  assert.equal(functions.filter((fn) => fn.Properties.Environment?.Variables?.ADMIN_SECRET_ARN).length, 1);
  assert.ok(!Object.values(resources).some((resource) => resource.Type === "AWS::Lambda::Url" || resource.Type === "AWS::ApiGateway::Method"));
});
