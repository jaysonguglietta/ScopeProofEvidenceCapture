import { CfnOutput, Duration, RemovalPolicy, Stack, StackProps } from "aws-cdk-lib";
import * as path from "node:path";
import * as cr from "aws-cdk-lib/custom-resources";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as kms from "aws-cdk-lib/aws-kms";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as lambdaNodejs from "aws-cdk-lib/aws-lambda-nodejs";
import * as logs from "aws-cdk-lib/aws-logs";
import * as sfn from "aws-cdk-lib/aws-stepfunctions";
import * as tasks from "aws-cdk-lib/aws-stepfunctions-tasks";
import { Construct } from "constructs";
import type { SharedPlatformStack } from "./shared-platform-stack";
import type { TenantDatabaseBootstrapSource } from "./database-bootstrap-mapping";

export interface DatabaseBootstrapStackProps extends StackProps {
  readonly shared: SharedPlatformStack;
  readonly sources: readonly TenantDatabaseBootstrapSource[];
  readonly operatorPrincipalArn: string;
  readonly approverPrincipalArn: string;
}

/** A separate platform security stack. Tenant stacks never depend on or invoke its worker. */
export class DatabaseBootstrapStack extends Stack {
  public constructor(scope: Construct, id: string, props: DatabaseBootstrapStackProps) {
    super(scope, id, props);
    const expected = new RegExp(`^arn:aws:iam::${this.account}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`);
    if (!expected.test(props.operatorPrincipalArn) || !expected.test(props.approverPrincipalArn) || props.operatorPrincipalArn === props.approverPrincipalArn ||
        [props.operatorPrincipalArn, props.approverPrincipalArn].some((arn) => /:role\/scopeproof\/(?!platform\/|operators\/)/.test(arn))) throw new Error("Bootstrap requires distinct, explicit platform operator and approver IAM roles.");
    const tenantIds = props.sources.map(({ mapping }) => mapping.tenantId);
    if (!tenantIds.length || new Set(tenantIds).size !== tenantIds.length || tenantIds.some((id) => !/^ten_[a-f0-9]{32}$/.test(id))) throw new Error("Bootstrap requires unique compiled tenant mappings.");
    const identifiers = props.sources.flatMap(({ mapping }) => [mapping.databaseName, mapping.ownerUsername, ...mapping.roles.map((role) => role.username)]);
    if (new Set(identifiers).size !== identifiers.length) throw new Error("Bootstrap database/role mappings collide.");
    const key = new kms.Key(this, "BootstrapControlKey", { enableKeyRotation: true, removalPolicy: RemovalPolicy.RETAIN, pendingWindow: Duration.days(30) });
    const table = (name: string) => new dynamodb.Table(this, name, { partitionKey: { name: "PK", type: dynamodb.AttributeType.STRING }, sortKey: { name: "SK", type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST, encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED, encryptionKey: key,
      deletionProtection: true, pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true }, removalPolicy: RemovalPolicy.RETAIN });
    const mappings = table("ImmutableBootstrapMappings"), approvals = table("BootstrapApprovals");
    for (const { mapping } of props.sources) {
      const mappingJson = this.toJsonString(mapping);
      const publisher = new cr.AwsCustomResource(this, `PublishMapping-${mapping.tenantId}`, {
        installLatestAwsSdk: false,
        onUpdate: { service: "DynamoDB", action: "putItem", physicalResourceId: cr.PhysicalResourceId.of(`${mapping.tenantId}-revision-${mapping.revision}`),
          parameters: { TableName: mappings.tableName, Item: { PK: { S: mapping.tenantId }, SK: { S: `REVISION#${mapping.revision}` }, mappingJson: { S: mappingJson } },
            ConditionExpression: "attribute_not_exists(PK) OR mappingJson = :same", ExpressionAttributeValues: { ":same": { S: mappingJson } } } },
        policy: cr.AwsCustomResourcePolicy.fromStatements([new iam.PolicyStatement({ actions: ["dynamodb:PutItem"], resources: [mappings.tableArn],
          conditions: { Null: { "dynamodb:LeadingKeys": "false" }, "ForAllValues:StringEquals": { "dynamodb:LeadingKeys": [mapping.tenantId] } } })]),
      });
      key.grantEncryptDecrypt(publisher);
    }
    const operator = new iam.Role(this, "BootstrapOperatorRole", { assumedBy: new iam.ArnPrincipal(props.operatorPrincipalArn), path: "/scopeproof/platform/", description: "Can start an approved fixed-mapping database bootstrap; cannot approve one" });
    const approver = new iam.Role(this, "BootstrapApproverRole", { assumedBy: new iam.ArnPrincipal(props.approverPrincipalArn), path: "/scopeproof/platform/", description: "Can approve one short-lived exact bootstrap execution; cannot run it" });
    approver.addToPolicy(scoped("dynamodb:PutItem", approvals.tableArn, tenantIds.map((id) => `BOOTSTRAP#${id}`)));
    approver.addToPolicy(scoped("dynamodb:GetItem", mappings.tableArn, tenantIds));
    operator.addToPolicy(scoped("dynamodb:GetItem", mappings.tableArn, tenantIds));
    key.grantEncryptDecrypt(approver);
    key.grantDecrypt(operator);
    const administrator = props.shared.databaseCluster.secret;
    if (!administrator?.encryptionKey) throw new Error("Central bootstrap requires the retained encrypted platform administrator secret.");
    const logGroup = new logs.LogGroup(this, "BootstrapLogs", { encryptionKey: key, retention: logs.RetentionDays.ONE_YEAR, removalPolicy: RemovalPolicy.RETAIN });
    const name = "scopeproof-database-bootstrap";
    const worker = new lambdaNodejs.NodejsFunction(this, "CentralDatabaseBootstrap", {
      entry: path.join(__dirname, "..", "runtime", "bootstrap-database", "index.mjs"), handler: "handler", runtime: lambda.Runtime.NODEJS_22_X,
      architecture: lambda.Architecture.ARM_64, memorySize: 512, timeout: Duration.minutes(10), reservedConcurrentExecutions: 1,
      logGroup, projectRoot: path.join(__dirname, ".."), bundling: { externalModules: [], format: lambdaNodejs.OutputFormat.ESM, minify: true, sourceMap: false, target: "node22" },
      environment: { ADMIN_SECRET_ARN: administrator.secretArn, DATABASE_CLUSTER_ARN: props.shared.databaseCluster.clusterArn,
        MAPPING_TABLE_NAME: mappings.tableName, APPROVAL_TABLE_NAME: approvals.tableName, CONTROL_TABLE_NAME: props.shared.controlTable.tableName,
        AWS_ACCOUNT_ID_EXPECTED: this.account, AWS_REGION_EXPECTED: this.region, APPROVER_ROLE_ARN: approver.roleArn, STATE_MACHINE_NAME: name },
    });
    // Identity-only grants avoid mutating tenant/shared key policies back toward this
    // dependent stack. Every secret and its decryption context remain exact-bound.
    const bootstrapSecrets = [administrator, ...props.sources.flatMap((source) => source.secrets)];
    for (const secret of bootstrapSecrets) {
      if (!secret.encryptionKey) throw new Error("Every bootstrap secret requires its own declared customer-managed key.");
      worker.addToRolePolicy(new iam.PolicyStatement({ actions: ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"], resources: [secret.secretArn] }));
      worker.addToRolePolicy(new iam.PolicyStatement({ actions: ["kms:Decrypt"], resources: [secret.encryptionKey.keyArn], conditions: {
        StringEquals: { "kms:ViaService": `secretsmanager.${this.region}.amazonaws.com`, "kms:EncryptionContext:SecretARN": secret.secretArn },
      } }));
    }
    key.grantDecrypt(worker);
    worker.addToRolePolicy(new iam.PolicyStatement({ actions: ["rds-data:ExecuteStatement"], resources: [props.shared.databaseCluster.clusterArn, administrator.secretArn] }));
    worker.addToRolePolicy(scoped("dynamodb:GetItem", mappings.tableArn, tenantIds));
    worker.addToRolePolicy(scoped("dynamodb:GetItem", approvals.tableArn, tenantIds.map((id) => `BOOTSTRAP#${id}`)));
    worker.addToRolePolicy(scoped("dynamodb:PutItem", props.shared.controlTable.tableArn, tenantIds.map((id) => `DATABASE_BOOTSTRAP#${id}`)));
    const task = new tasks.LambdaInvoke(this, "PrepareExactTenantDatabaseRoles", { lambdaFunction: worker, payloadResponseOnly: true,
      payload: sfn.TaskInput.fromObject({ tenantId: sfn.JsonPath.stringAt("$.tenantId"), revision: sfn.JsonPath.numberAt("$.revision"), executionId: sfn.JsonPath.executionId }) });
    const workflow = new sfn.StateMachine(this, "ApprovedDatabaseBootstrap", { stateMachineName: name, stateMachineType: sfn.StateMachineType.STANDARD,
      definitionBody: sfn.DefinitionBody.fromChainable(task), timeout: Duration.minutes(12), logs: { destination: logGroup, includeExecutionData: false, level: sfn.LogLevel.ERROR } });
    workflow.grantStartExecution(operator);
    new CfnOutput(this, "BootstrapStateMachineArn", { value: workflow.stateMachineArn });
    new CfnOutput(this, "BootstrapOperatorRoleArn", { value: operator.roleArn });
    new CfnOutput(this, "BootstrapApproverRoleArn", { value: approver.roleArn });
    new CfnOutput(this, "BootstrapMappingTableName", { value: mappings.tableName });
    new CfnOutput(this, "BootstrapApprovalTableName", { value: approvals.tableName });
  }
}

function scoped(action: string, resource: string, keys: readonly string[]): iam.PolicyStatement {
  return new iam.PolicyStatement({ actions: [action], resources: [resource], conditions: { Null: { "dynamodb:LeadingKeys": "false" }, "ForAllValues:StringEquals": { "dynamodb:LeadingKeys": keys } } });
}
