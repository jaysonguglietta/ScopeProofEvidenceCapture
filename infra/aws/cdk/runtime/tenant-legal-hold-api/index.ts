import { DynamoDBClient, GetItemCommand, TransactWriteItemsCommand } from "@aws-sdk/client-dynamodb";
import {
  BeginTransactionCommand,
  CommitTransactionCommand,
  ExecuteStatementCommand,
  RDSDataClient,
  RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";

import {
  AwsSdkV3RdsDataApiExecutor,
  CognitoJwtVerifier,
  DynamoTenantAuthorityResolver,
  RdsDataMembershipRepository,
  createTenantApiHandler,
  type ApiAuthenticationDependencies,
  type ApiGatewayRestEvent,
  type LegalHoldApprovalApiPayload,
  type LegalHoldRequestApiPayload,
  type RdsDataApiCommandConstructors,
  type TenantApiRequestRuntime,
} from "../../../../../lib/aws-runtime/http/index.ts";
import {
  DynamoTenantRouteRateLimiter,
  RdsDataExactVersionLegalHoldOperationStore,
  approveExactVersionLegalHoldChange,
  requestExactVersionLegalHoldChange,
} from "../../../../../lib/aws-runtime/evidence/index.ts";
import type { AuthorizedApiRequest } from "../../../../../lib/aws-runtime/http/api.ts";

const requiredEnvironment = [
  "API_HOSTNAME",
  "COGNITO_APP_CLIENT_IDS",
  "COGNITO_ISSUER",
  "CONTROL_TABLE_NAME",
  "DATABASE_CLUSTER_ARN",
  "DATABASE_NAME",
  "EVIDENCE_BUCKET_NAME",
  "LEGAL_HOLD_API_ROLE_ARN",
  "LEGAL_HOLD_DATABASE_SECRET_ARN",
  "TENANT_ID",
  "WEB_ORIGIN",
] as const;

type RequiredEnvironmentName = typeof requiredEnvironment[number];

function environment(): Readonly<Record<RequiredEnvironmentName, string>> {
  const result = {} as Record<RequiredEnvironmentName, string>;
  for (const name of requiredEnvironment) {
    const value = String(process.env[name] ?? "");
    if (!value || value !== value.trim() || /\p{Cc}/u.test(value)) {
      throw new Error(`Missing or invalid required environment variable ${name}.`);
    }
    result[name] = value;
  }
  if (!/^ten_[a-f0-9]{32}$/.test(result.TENANT_ID)) throw new Error("Legal-hold API tenant identifier is invalid.");
  if (!/^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role\/scopeproof\/tenants\/sp-[a-z0-9-]{1,48}-lh-workflow$/.test(result.LEGAL_HOLD_API_ROLE_ARN)) {
    throw new Error("Legal-hold API workflow role ARN is invalid.");
  }
  return Object.freeze(result);
}

const config = environment();
const cognitoAppClientIds = (() => {
  let parsed: unknown;
  try { parsed = JSON.parse(config.COGNITO_APP_CLIENT_IDS); } catch { throw new Error("Cognito app-client allowlist is invalid."); }
  if (!Array.isArray(parsed) || parsed.length !== 2 || new Set(parsed).size !== parsed.length || parsed.some((value) => typeof value !== "string" || !/^[A-Za-z0-9_.:+/=_~-]{3,128}$/.test(value))) {
    throw new Error("Cognito app-client allowlist is invalid.");
  }
  return Object.freeze([...parsed].sort()) as readonly string[];
})();
const region = process.env.AWS_REGION;
if (!region || !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region)) throw new Error("Lambda AWS region is invalid.");

const baseDynamo = new DynamoDBClient({ region });
type RouteRateLimiterOptions = ConstructorParameters<typeof DynamoTenantRouteRateLimiter>[0];
const sts = new STSClient({ region });
const tenants = new DynamoTenantAuthorityResolver({
  client: baseDynamo,
  commands: { GetItemCommand },
  tableName: config.CONTROL_TABLE_NAME,
});
const routeLimiter = new DynamoTenantRouteRateLimiter({
  client: baseDynamo,
  TransactWriteItemsCommand: compatibleAwsCommand<CommandInput<RouteRateLimiterOptions["TransactWriteItemsCommand"]>>(TransactWriteItemsCommand as never),
  tableName: config.CONTROL_TABLE_NAME,
});
const jwt = new CognitoJwtVerifier({
  issuer: config.COGNITO_ISSUER,
  clientIds: cognitoAppClientIds,
  maximumAuthenticationAgeSeconds: 60 * 60,
  maximumTokenLifetimeSeconds: 60 * 60,
  jwksTimeoutMilliseconds: 3_000,
});

type CommandInput<T> = T extends new(input: infer Input) => unknown ? Input : never;

function compatibleAwsCommand<Input>(constructor: new(input: never) => unknown): new(input: Input) => unknown {
  return constructor as unknown as new(input: Input) => unknown;
}

function assumedCredentialProvider(roleArn: string, purpose: string, requestId: string) {
  let inflight: ReturnType<typeof assume> | undefined;
  const safeRequest = requestId.replace(/[^A-Za-z0-9+=,.@_-]/g, "").slice(0, 32);
  const sessionName = `scopeproof-${purpose}-${safeRequest}`.slice(0, 64);
  async function assume() {
    const response = await sts.send(new AssumeRoleCommand({
      RoleArn: roleArn,
      RoleSessionName: sessionName,
      DurationSeconds: 900,
    }));
    const credentials = response.Credentials;
    const now = Date.now();
    if (!credentials ||
        typeof credentials.AccessKeyId !== "string" || !/^ASIA[A-Z0-9]{16}$/.test(credentials.AccessKeyId) ||
        typeof credentials.SecretAccessKey !== "string" || credentials.SecretAccessKey.length < 32 || credentials.SecretAccessKey.length > 128 ||
        typeof credentials.SessionToken !== "string" || credentials.SessionToken.length < 16 || credentials.SessionToken.length > 8_192 ||
        !(credentials.Expiration instanceof Date) ||
        credentials.Expiration.getTime() < now + 60_000 || credentials.Expiration.getTime() > now + 16 * 60_000) {
      throw new Error("STS returned an invalid legal-hold credential set.");
    }
    return Object.freeze({
      accessKeyId: credentials.AccessKeyId,
      secretAccessKey: credentials.SecretAccessKey,
      sessionToken: credentials.SessionToken,
      expiration: credentials.Expiration,
    });
  }
  return async () => {
    inflight ??= assume();
    return await inflight;
  };
}

function executor(credentials: ReturnType<typeof assumedCredentialProvider>): AwsSdkV3RdsDataApiExecutor {
  const client = new RDSDataClient({ region, credentials });
  return new AwsSdkV3RdsDataApiExecutor(client, {
    BeginTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["BeginTransactionCommand"]>>(BeginTransactionCommand as never),
    ExecuteStatementCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["ExecuteStatementCommand"]>>(ExecuteStatementCommand as never),
    CommitTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["CommitTransactionCommand"]>>(CommitTransactionCommand as never),
    RollbackTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["RollbackTransactionCommand"]>>(RollbackTransactionCommand as never),
  });
}

function createRequestRuntime(requestId: string): TenantApiRequestRuntime {
  const workflowCredentials = assumedCredentialProvider(config.LEGAL_HOLD_API_ROLE_ARN, "legal-workflow", requestId);
  const rds = executor(workflowCredentials);
  const membership = new RdsDataMembershipRepository({
    executor: rds,
    resourceArn: config.DATABASE_CLUSTER_ARN,
    secretArn: config.LEGAL_HOLD_DATABASE_SECRET_ARN,
    database: config.DATABASE_NAME,
    lookupMode: "security_definer_function",
  });
  const authentication: ApiAuthenticationDependencies = Object.freeze({
    authority: Object.freeze({ mode: "api_gateway_domain" as const }),
    jwt,
    memberships: membership,
    tenants,
  });
  const legalHoldStore = new RdsDataExactVersionLegalHoldOperationStore({
    executor: rds,
    resourceArn: config.DATABASE_CLUSTER_ARN,
    secretArn: config.LEGAL_HOLD_DATABASE_SECRET_ARN,
    database: config.DATABASE_NAME,
  });
  return Object.freeze({
    authentication,
    async requestLegalHold(request: AuthorizedApiRequest, payload: LegalHoldRequestApiPayload) {
      assertBoundary(request);
      await consumeLegalQuota(request, "legal_hold.request");
      return await requestExactVersionLegalHoldChange(
        legalHoldStore,
        { ...payload, tenantId: request.actor.tenantId },
        request.actor,
        { evidenceBucket: config.EVIDENCE_BUCKET_NAME },
        { membershipId: request.actor.membershipId, requestId: request.requestId },
      );
    },
    async approveLegalHold(request: AuthorizedApiRequest, payload: LegalHoldApprovalApiPayload) {
      assertBoundary(request);
      await consumeLegalQuota(request, "legal_hold.approve");
      return await approveExactVersionLegalHoldChange(
        legalHoldStore,
        { ...payload, tenantId: request.actor.tenantId },
        request.actor,
        { membershipId: request.actor.membershipId, requestId: request.requestId },
      );
    },
  });
}

async function consumeLegalQuota(
  request: AuthorizedApiRequest,
  route: "legal_hold.request" | "legal_hold.approve",
): Promise<void> {
  await routeLimiter.consume({
    tenantId: request.actor.tenantId,
    requestedBy: request.actor.userId,
    route,
    maximumRequestsPerPrincipalMinute: 10,
    maximumRequestsPerTenantMinute: 50,
    now: new Date(),
  });
}

function assertBoundary(request: AuthorizedApiRequest): void {
  if (request.actor.tenantId !== config.TENANT_ID) {
    throw new Error("Authenticated tenant does not match the legal-hold Lambda boundary.");
  }
}

export const handler = createTenantApiHandler({
  apiHostname: config.API_HOSTNAME,
  allowedOrigin: config.WEB_ORIGIN,
  createRequestRuntime,
  onInternalError: ({ requestId, errorName }) => {
    // Never log request bodies, JWTs, exact version identifiers, or credentials.
    console.error(JSON.stringify({ level: "error", event: "tenant_legal_hold_api_failure", requestId, errorName }));
  },
});

export type TenantLegalHoldApiHandler = (event: ApiGatewayRestEvent) => ReturnType<typeof handler>;
