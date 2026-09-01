import { GetItemCommand, DynamoDBClient, TransactWriteItemsCommand } from "@aws-sdk/client-dynamodb";
import {
  BeginTransactionCommand,
  CommitTransactionCommand,
  ExecuteStatementCommand,
  RDSDataClient,
  RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";
import { GetObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

import {
  AwsSdkV3RdsDataApiExecutor,
  CognitoJwtVerifier,
  DynamoTenantAuthorityResolver,
  RdsDataApiAuditOutbox,
  RdsDataMembershipRepository,
  createTenantApiHandler,
  type ApiAuthenticationDependencies,
  type ApiGatewayRestEvent,
  type AuthorizedApiRequest,
  type EvidenceDownloadIntentApiPayload,
  type EvidenceSearchApiPayload,
  type HostedApiAuditRecord,
  type RdsDataApiCommandConstructors,
  type TenantApiRequestRuntime,
} from "../../../../../lib/aws-runtime/http/index.ts";
import {
  AwsSdkV3ExactGetObjectPresigner,
  DynamoTenantRouteRateLimiter,
  HostedEvidenceAccessService,
  RdsDataEvidenceAccessRepository,
  loadRotatingUploadIdempotencySecrets,
} from "../../../../../lib/aws-runtime/evidence/index.ts";

const requiredEnvironment = [
  "API_HOSTNAME",
  "AWS_ACCOUNT_ID_EXPECTED",
  "COGNITO_APP_CLIENT_IDS",
  "COGNITO_ISSUER",
  "CONTROL_TABLE_NAME",
  "DATABASE_CLUSTER_ARN",
  "DATABASE_NAME",
  "DATABASE_SECRET_ARN",
  "EVIDENCE_CURSOR_SECRET_ARN",
  "EVIDENCE_BUCKET_NAME",
  "TENANT_ID",
  "TENANT_READ_ROLE_ARN",
  "WEB_ORIGIN",
] as const;

type RequiredEnvironmentName = typeof requiredEnvironment[number];

function environment(): Readonly<Record<RequiredEnvironmentName, string>> {
  const result = {} as Record<RequiredEnvironmentName, string>;
  for (const name of requiredEnvironment) {
    const value = String(process.env[name] ?? "");
    if (!value || value !== value.trim() || /\p{Cc}/u.test(value)) throw new Error(`Missing or invalid required environment variable ${name}.`);
    result[name] = value;
  }
  if (!/^ten_[a-f0-9]{32}$/.test(result.TENANT_ID) || !/^\d{12}$/.test(result.AWS_ACCOUNT_ID_EXPECTED)) throw new Error("Tenant read identity is invalid.");
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(result.EVIDENCE_BUCKET_NAME)) throw new Error("Evidence bucket name is invalid.");
  if (!/^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role\/scopeproof\/tenants\/sp-[a-z0-9-]{1,64}-read$/.test(result.TENANT_READ_ROLE_ARN)) {
    throw new Error("Tenant evidence-read role ARN is invalid.");
  }
  return Object.freeze(result);
}

function appClientIds(value: string): readonly string[] {
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new Error("Cognito app-client allowlist is invalid."); }
  if (!Array.isArray(parsed) || parsed.length !== 2 || new Set(parsed).size !== parsed.length || parsed.some((entry) => typeof entry !== "string" || !/^[A-Za-z0-9_.:+/=_~-]{3,128}$/.test(entry))) {
    throw new Error("Cognito app-client allowlist is invalid.");
  }
  return Object.freeze([...parsed].sort()) as readonly string[];
}

const config = environment();
const region = String(process.env.AWS_REGION ?? "");
if (!region || !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region)) throw new Error("Lambda AWS region is invalid.");
const clients = appClientIds(config.COGNITO_APP_CLIENT_IDS);
type RouteRateLimiterOptions = ConstructorParameters<typeof DynamoTenantRouteRateLimiter>[0];
const baseDynamo = new DynamoDBClient({ region });
const sts = new STSClient({ region });
const tenants = new DynamoTenantAuthorityResolver({ client: baseDynamo, commands: { GetItemCommand }, tableName: config.CONTROL_TABLE_NAME });
const routeLimiter = new DynamoTenantRouteRateLimiter({
  client: baseDynamo,
  TransactWriteItemsCommand: compatibleAwsCommand<CommandInput<RouteRateLimiterOptions["TransactWriteItemsCommand"]>>(TransactWriteItemsCommand as never),
  tableName: config.CONTROL_TABLE_NAME,
});
const jwt = new CognitoJwtVerifier({
  issuer: config.COGNITO_ISSUER,
  clientIds: clients,
  maximumAuthenticationAgeSeconds: 60 * 60,
  maximumTokenLifetimeSeconds: 60 * 60,
  jwksTimeoutMilliseconds: 3_000,
});

type CommandInput<T> = T extends new(input: infer Input) => unknown ? Input : never;
function compatibleAwsCommand<Input>(constructor: new(input: never) => unknown): new(input: Input) => unknown {
  return constructor as unknown as new(input: Input) => unknown;
}

function assumedCredentialProvider(requestId: string) {
  let inflight: ReturnType<typeof assume> | undefined;
  const sessionName = `scopeproof-read-${requestId.replace(/[^A-Za-z0-9+=,.@_-]/g, "").slice(0, 42)}`;
  async function assume() {
    const response = await sts.send(new AssumeRoleCommand({
      RoleArn: config.TENANT_READ_ROLE_ARN,
      RoleSessionName: sessionName,
      DurationSeconds: 900,
    }));
    const credentials = response.Credentials;
    const now = Date.now();
    if (!credentials || typeof credentials.AccessKeyId !== "string" || !/^ASIA[A-Z0-9]{16}$/.test(credentials.AccessKeyId) ||
        typeof credentials.SecretAccessKey !== "string" || credentials.SecretAccessKey.length < 32 || credentials.SecretAccessKey.length > 128 ||
        typeof credentials.SessionToken !== "string" || credentials.SessionToken.length < 16 || credentials.SessionToken.length > 4_096 ||
        !(credentials.Expiration instanceof Date) || credentials.Expiration.getTime() < now + 60_000 || credentials.Expiration.getTime() > now + 901_000) {
      throw new Error("Tenant evidence-read role did not return bounded temporary credentials.");
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

function createRequestRuntime(requestId: string): TenantApiRequestRuntime {
  const credentials = assumedCredentialProvider(requestId);
  const rdsClient = new RDSDataClient({ region, credentials });
  const rds = new AwsSdkV3RdsDataApiExecutor(rdsClient, {
    BeginTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["BeginTransactionCommand"]>>(BeginTransactionCommand as never),
    ExecuteStatementCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["ExecuteStatementCommand"]>>(ExecuteStatementCommand as never),
    CommitTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["CommitTransactionCommand"]>>(CommitTransactionCommand as never),
    RollbackTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["RollbackTransactionCommand"]>>(RollbackTransactionCommand as never),
  });
  const memberships = new RdsDataMembershipRepository({
    executor: rds,
    resourceArn: config.DATABASE_CLUSTER_ARN,
    secretArn: config.DATABASE_SECRET_ARN,
    database: config.DATABASE_NAME,
    lookupMode: "security_definer_function",
  });
  const auditOutbox = new RdsDataApiAuditOutbox({
    executor: rds,
    resourceArn: config.DATABASE_CLUSTER_ARN,
    secretArn: config.DATABASE_SECRET_ARN,
    database: config.DATABASE_NAME,
  });
  const authentication: ApiAuthenticationDependencies = Object.freeze({
    authority: Object.freeze({ mode: "api_gateway_domain" as const }),
    jwt,
    memberships,
    tenants,
  });
  let servicePromise: Promise<HostedEvidenceAccessService> | undefined;
  async function accessService(): Promise<HostedEvidenceAccessService> {
    servicePromise ??= (async () => {
      await credentials();
      const secretsClient = new SecretsManagerClient({ region, credentials });
      const cursorSecrets = await loadRotatingUploadIdempotencySecrets({
        async getSecretValue(stage) {
          return await secretsClient.send(new GetSecretValueCommand({ SecretId: config.EVIDENCE_CURSOR_SECRET_ARN, VersionStage: stage }));
        },
      });
      const s3 = new S3Client({ region, credentials });
      const presigner = new AwsSdkV3ExactGetObjectPresigner({
        client: s3,
        GetObjectCommand: compatibleAwsCommand<CommandInput<typeof GetObjectCommand>>(GetObjectCommand as never),
        async getSignedUrl(client, command, options) {
          return await getSignedUrl(client as S3Client, command as GetObjectCommand, {
            expiresIn: options.expiresIn,
            signingDate: options.signingDate,
            signableHeaders: new Set(options.signableHeaders),
            unhoistableHeaders: new Set(options.unhoistableHeaders),
          });
        },
      });
      try {
        return new HostedEvidenceAccessService({
          repository: new RdsDataEvidenceAccessRepository({
            executor: rds,
            resourceArn: config.DATABASE_CLUSTER_ARN,
            secretArn: config.DATABASE_SECRET_ARN,
            database: config.DATABASE_NAME,
          }),
          presigner,
          endpointHostname: `${config.EVIDENCE_BUCKET_NAME}.s3.${region}.${region.startsWith("cn-") ? "amazonaws.com.cn" : "amazonaws.com"}`,
          signingRegion: region,
          expectedBucketOwner: config.AWS_ACCOUNT_ID_EXPECTED,
          cursorSecret: cursorSecrets.current,
          previousCursorSecrets: cursorSecrets.previous,
          downloadTtlSeconds: 60,
          cursorTtlSeconds: 900,
        });
      } finally {
        cursorSecrets.current.fill(0);
        for (const previous of cursorSecrets.previous) previous.fill(0);
      }
    })();
    return await servicePromise;
  }
  return Object.freeze({
    authentication,
    async recordApiAudit(record: HostedApiAuditRecord) {
      if (record.actor.tenantId !== config.TENANT_ID) throw new Error("Authenticated tenant does not match the Lambda boundary.");
      return await auditOutbox.record(record);
    },
    async listEvidence(request: AuthorizedApiRequest, payload: EvidenceSearchApiPayload) {
      if (request.actor.tenantId !== config.TENANT_ID) throw new Error("Authenticated tenant does not match the Lambda boundary.");
      await routeLimiter.consume({
        tenantId: request.actor.tenantId,
        requestedBy: request.actor.userId,
        route: "evidence.search",
        maximumRequestsPerPrincipalMinute: 120,
        maximumRequestsPerTenantMinute: 600,
        now: new Date(),
      });
      return await (await accessService()).list(request.actor, payload);
    },
    async issueEvidenceDownload(request: AuthorizedApiRequest, payload: EvidenceDownloadIntentApiPayload) {
      if (request.actor.tenantId !== config.TENANT_ID) throw new Error("Authenticated tenant does not match the Lambda boundary.");
      await routeLimiter.consume({
        tenantId: request.actor.tenantId,
        requestedBy: request.actor.userId,
        route: "evidence.download",
        maximumRequestsPerPrincipalMinute: 60,
        maximumRequestsPerTenantMinute: 300,
        now: new Date(),
      });
      return await (await accessService()).issueDownload(request.actor, payload);
    },
  });
}

export const handler = createTenantApiHandler({
  apiHostname: config.API_HOSTNAME,
  allowedOrigin: config.WEB_ORIGIN,
  createRequestRuntime,
  onInternalError: ({ requestId, errorName }) => {
    // Never log bearer tokens, cursor values, presigned URLs, keys, headers, or AWS credentials.
    console.error(JSON.stringify({ level: "error", event: "tenant_evidence_read_api_failure", requestId, errorName }));
  },
});

export type TenantEvidenceReadApiHandler = (event: ApiGatewayRestEvent) => ReturnType<typeof handler>;
