import {
  DynamoDBClient,
  GetItemCommand,
  TransactWriteItemsCommand,
} from "@aws-sdk/client-dynamodb";
import {
  BeginTransactionCommand,
  CommitTransactionCommand,
  ExecuteStatementCommand,
  RDSDataClient,
  RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";
import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import { AssumeRoleCommand, STSClient } from "@aws-sdk/client-sts";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

import {
  AwsSdkV3RdsDataApiExecutor,
  CognitoJwtVerifier,
  DynamoTenantAuthorityResolver,
  RdsDataMembershipRepository,
  createTenantApiHandler,
  type ApiAuthenticationDependencies,
  type ApiGatewayRestEvent,
  type RdsDataApiCommandConstructors,
  type TenantApiRequestRuntime,
  type UploadIntentApiPayload,
} from "../../../../../lib/aws-runtime/http/index.ts";
import {
  AwsSdkV3ExactPutObjectPresigner,
  DynamoAndRdsUploadIntentStore,
  DynamoConditionalUploadIntentStore,
  DynamoUploadRequestRateLimiter,
  RdsDataUploadIntentProjection,
  UploadIntentIssuer,
  deriveServerManagedUploadRetention,
  loadRotatingUploadIdempotencySecrets,
} from "../../../../../lib/aws-runtime/evidence/index.ts";
import type { AuthorizedApiRequest } from "../../../../../lib/aws-runtime/http/api.ts";

const requiredEnvironment = [
  "API_HOSTNAME",
  "COGNITO_APP_CLIENT_ID",
  "COGNITO_ISSUER",
  "CONTROL_TABLE_NAME",
  "DATABASE_CLUSTER_ARN",
  "DATABASE_NAME",
  "DATABASE_SECRET_ARN",
  "QUARANTINE_BUCKET_NAME",
  "RETENTION_DAYS",
  "TENANT_DATA_ROLE_ARN",
  "TENANT_ID",
  "TENANT_KMS_KEY_ARN",
  "UPLOAD_IDEMPOTENCY_SECRET_ARN",
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
  if (!/^ten_[a-f0-9]{32}$/.test(result.TENANT_ID)) throw new Error("Tenant API tenant identifier is invalid.");
  if (!/^[1-9][0-9]{0,3}$/.test(result.RETENTION_DAYS) || Number(result.RETENTION_DAYS) > 3_650) {
    throw new Error("Tenant evidence retention period is invalid.");
  }
  if (!/^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role\/scopeproof\/tenants\/sp-[a-z0-9-]{1,64}-data$/.test(result.TENANT_DATA_ROLE_ARN)) {
    throw new Error("Tenant API role ARN is invalid.");
  }
  return Object.freeze(result);
}

const config = environment();
const region = process.env.AWS_REGION;
if (!region || !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region)) throw new Error("Lambda AWS region is invalid.");

const baseDynamo = new DynamoDBClient({ region });
const sts = new STSClient({ region });
const tenants = new DynamoTenantAuthorityResolver({
  client: baseDynamo,
  commands: { GetItemCommand },
  tableName: config.CONTROL_TABLE_NAME,
});
const jwt = new CognitoJwtVerifier({
  issuer: config.COGNITO_ISSUER,
  clientIds: [config.COGNITO_APP_CLIENT_ID],
  maximumAuthenticationAgeSeconds: 60 * 60,
  maximumTokenLifetimeSeconds: 60 * 60,
  jwksTimeoutMilliseconds: 3_000,
});

type CommandInput<T> = T extends new(input: infer Input) => unknown ? Input : never;
type UploadStoreOptions = ConstructorParameters<typeof DynamoConditionalUploadIntentStore>[0];
type UploadRateLimiterOptions = ConstructorParameters<typeof DynamoUploadRequestRateLimiter>[0];

/** AWS SDK inputs are mutable while the reviewed adapters expose readonly inputs. */
function compatibleAwsCommand<Input>(constructor: new(input: never) => unknown): new(input: Input) => unknown {
  return constructor as unknown as new(input: Input) => unknown;
}

function assumedCredentialProvider(requestId: string) {
  let inflight: ReturnType<typeof assume> | undefined;
  const sessionName = `scopeproof-api-${requestId.replace(/[^A-Za-z0-9+=,.@_-]/g, "").slice(0, 44)}`;
  async function assume() {
    const response = await sts.send(new AssumeRoleCommand({
      RoleArn: config.TENANT_DATA_ROLE_ARN,
      RoleSessionName: sessionName,
      DurationSeconds: 900,
    }));
    const credentials = response.Credentials;
    const now = Date.now();
    if (
      !credentials ||
      typeof credentials.AccessKeyId !== "string" || !/^ASIA[A-Z0-9]{16}$/.test(credentials.AccessKeyId) ||
      typeof credentials.SecretAccessKey !== "string" || credentials.SecretAccessKey.length < 32 || credentials.SecretAccessKey.length > 128 ||
      typeof credentials.SessionToken !== "string" || credentials.SessionToken.length < 16 || credentials.SessionToken.length > 8_192 ||
      !(credentials.Expiration instanceof Date) ||
      credentials.Expiration.getTime() < now + 60_000 || credentials.Expiration.getTime() > now + 16 * 60_000
    ) {
      throw new Error("STS returned an invalid tenant credential set.");
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
  const membership = new RdsDataMembershipRepository({
    executor: rds,
    resourceArn: config.DATABASE_CLUSTER_ARN,
    secretArn: config.DATABASE_SECRET_ARN,
    database: config.DATABASE_NAME,
    lookupMode: "security_definer_function",
  });
  const authentication: ApiAuthenticationDependencies = Object.freeze({
    authority: Object.freeze({ mode: "api_gateway_domain" as const }),
    jwt,
    memberships: membership,
    tenants,
  });
  return Object.freeze({
    authentication,
    async issueUploadIntent(request: AuthorizedApiRequest, payload: UploadIntentApiPayload) {
      if (request.actor.tenantId !== config.TENANT_ID) throw new Error("Authenticated tenant does not match the Lambda boundary.");
      const requestNow = new Date();
      const retention = deriveServerManagedUploadRetention({
        capturedAt: payload.evidence.capturedAt,
        retentionDays: Number(config.RETENTION_DAYS),
        now: requestNow,
      });
      await credentials();
      const dynamoClient = new DynamoDBClient({ region, credentials });
      const requestRateLimiter = new DynamoUploadRequestRateLimiter({
        client: dynamoClient,
        TransactWriteItemsCommand: compatibleAwsCommand<CommandInput<UploadRateLimiterOptions["TransactWriteItemsCommand"]>>(TransactWriteItemsCommand as never),
        tableName: config.CONTROL_TABLE_NAME,
      });
      await requestRateLimiter.consume({
        tenantId: request.actor.tenantId,
        requestedBy: request.actor.userId,
        now: requestNow,
      });
      const dynamo = new DynamoConditionalUploadIntentStore({
        client: dynamoClient,
        TransactWriteItemsCommand: compatibleAwsCommand<CommandInput<UploadStoreOptions["TransactWriteItemsCommand"]>>(TransactWriteItemsCommand as never),
        GetItemCommand: compatibleAwsCommand<CommandInput<UploadStoreOptions["GetItemCommand"]>>(GetItemCommand as never),
        tableName: config.CONTROL_TABLE_NAME,
      });
      const database = new RdsDataUploadIntentProjection({
        executor: rds,
        resourceArn: config.DATABASE_CLUSTER_ARN,
        secretArn: config.DATABASE_SECRET_ARN,
        database: config.DATABASE_NAME,
      });
      const store = new DynamoAndRdsUploadIntentStore({
        dynamo,
        database,
        evidence: Object.freeze({
          ...payload.evidence,
          capturedAt: retention.capturedAt,
          artifactExpiresAt: retention.artifactExpiresAt,
        }),
      });
      const s3 = new S3Client({ region, credentials });
      const presigner = new AwsSdkV3ExactPutObjectPresigner({
        client: s3,
        PutObjectCommand,
        async getSignedUrl(client, command, options) {
          return await getSignedUrl(client as S3Client, command as PutObjectCommand, {
            expiresIn: options.expiresIn,
            signingDate: options.signingDate,
            signableHeaders: new Set(options.signableHeaders),
            unhoistableHeaders: new Set(options.unhoistableHeaders),
          });
        },
      });
      const secretsClient = new SecretsManagerClient({ region, credentials });
      const idempotencySecrets = await loadRotatingUploadIdempotencySecrets({
        async getSecretValue(stage) {
          return await secretsClient.send(new GetSecretValueCommand({
            SecretId: config.UPLOAD_IDEMPOTENCY_SECRET_ARN,
            VersionStage: stage,
          }));
        },
      });
      let issuer: UploadIntentIssuer;
      try {
        issuer = new UploadIntentIssuer({
          store,
          presigner,
          idempotencySecret: idempotencySecrets.current,
          previousIdempotencySecrets: idempotencySecrets.previous,
          clock: () => new Date(),
          configuration: {
            quarantineBucket: config.QUARANTINE_BUCKET_NAME,
            quarantineKmsKeyArn: config.TENANT_KMS_KEY_ARN,
          },
        });
      } finally {
        idempotencySecrets.current.fill(0);
        for (const previous of idempotencySecrets.previous) previous.fill(0);
      }
      return await issuer.issue({
        idempotencyKey: payload.idempotencyKey,
        tenantId: request.actor.tenantId,
        requestedBy: request.actor.userId,
        controlId: payload.controlId,
        evidenceId: payload.evidenceId,
        expectedSha256: payload.expectedSha256,
        expectedSize: payload.expectedSize,
        contentType: payload.contentType,
        requiredRetentionUntil: retention.requiredRetentionUntil,
      });
    },
  });
}

export const handler = createTenantApiHandler({
  apiHostname: config.API_HOSTNAME,
  allowedOrigin: config.WEB_ORIGIN,
  createRequestRuntime,
  onInternalError: ({ requestId, errorName }) => {
    // Never log request bodies, JWTs, presigned URLs, credentials, or secrets.
    console.error(JSON.stringify({ level: "error", event: "tenant_api_failure", requestId, errorName }));
  },
});

export type TenantApiHandler = (event: ApiGatewayRestEvent) => ReturnType<typeof handler>;
