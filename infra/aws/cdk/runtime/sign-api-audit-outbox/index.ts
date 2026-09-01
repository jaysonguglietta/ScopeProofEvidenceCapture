import { KMSClient, SignCommand, VerifyCommand } from "@aws-sdk/client-kms";
import {
  BeginTransactionCommand,
  CommitTransactionCommand,
  ExecuteStatementCommand,
  RDSDataClient,
  RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";

import { createTenantAuditEvent } from "../../../../../lib/aws-runtime/audit.ts";
import { asMembershipId, asSha256, asUserId } from "../../../../../lib/aws-runtime/contracts.ts";
import {
  AwsSdkV3KmsAsymmetricSigningClient,
  signTenantAuditReceipt,
  type KmsCommandConstructors,
} from "../../../../../lib/aws-runtime/evidence/index.ts";
import {
  ApiAuditOutboxPoisonedClaimError,
  apiAuditEventDetails,
  AwsSdkV3RdsDataApiExecutor,
  RdsDataApiAuditOutboxSignerStore,
  type RdsDataApiCommandConstructors,
} from "../../../../../lib/aws-runtime/http/index.ts";

const requiredEnvironment = [
  "API_AUDIT_BATCH_LIMIT",
  "API_AUDIT_DATABASE_SECRET_ARN",
  "API_AUDIT_LEASE_SECONDS",
  "AUDIT_SIGNING_KEY_ARN",
  "DATABASE_CLUSTER_ARN",
  "DATABASE_NAME",
  "TENANT_ID",
] as const;

type RequiredEnvironmentName = typeof requiredEnvironment[number];

function environment(): Readonly<Record<RequiredEnvironmentName, string>> {
  const result = {} as Record<RequiredEnvironmentName, string>;
  for (const name of requiredEnvironment) {
    const value = String(process.env[name] ?? "");
    if (!value || value !== value.trim() || /\p{Cc}/u.test(value)) throw new Error(`Missing or invalid required environment variable ${name}.`);
    result[name] = value;
  }
  if (!/^ten_[a-f0-9]{32}$/.test(result.TENANT_ID)) throw new Error("API audit signer tenant identifier is invalid.");
  if (!/^arn:(?:aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:\d{12}:key\/[0-9a-f-]{36}$/.test(result.AUDIT_SIGNING_KEY_ARN)) {
    throw new Error("API audit signer KMS key ARN is invalid.");
  }
  const limit = Number(result.API_AUDIT_BATCH_LIMIT);
  const leaseSeconds = Number(result.API_AUDIT_LEASE_SECONDS);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 25 ||
      !Number.isSafeInteger(leaseSeconds) || leaseSeconds < 30 || leaseSeconds > 300) {
    throw new Error("API audit signer bounds are invalid.");
  }
  return Object.freeze(result);
}

const config = environment();
const region = String(process.env.AWS_REGION ?? "");
if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(region)) throw new Error("API audit signer AWS region is invalid.");

type CommandInput<T> = T extends new(input: infer Input) => unknown ? Input : never;

function compatibleAwsCommand<Input>(constructor: new(input: never) => unknown): new(input: Input) => unknown {
  return constructor as unknown as new(input: Input) => unknown;
}

function emitMetrics(input: Readonly<{
  claimed: number;
  signed: number;
  retryScheduled: number;
  deadLetterTransitions: number;
  failures: number;
  backlogCount: number;
  deadLetteredCount: number;
  oldestUnsignedAgeSeconds: number;
}>): void {
  console.log(JSON.stringify({
    _aws: {
      Timestamp: Date.now(),
      CloudWatchMetrics: [{
        Namespace: "Scopeproof/ApiAudit",
        Dimensions: [["TenantId"]],
        Metrics: [
          { Name: "Claimed", Unit: "Count" },
          { Name: "Signed", Unit: "Count" },
          { Name: "RetryScheduled", Unit: "Count" },
          { Name: "DeadLetterTransitions", Unit: "Count" },
          { Name: "Failures", Unit: "Count" },
          { Name: "BacklogCount", Unit: "Count" },
          { Name: "DeadLetteredCount", Unit: "Count" },
          { Name: "OldestUnsignedAgeSeconds", Unit: "Seconds" },
        ],
      }],
    },
    TenantId: config.TENANT_ID,
    Claimed: input.claimed,
    Signed: input.signed,
    RetryScheduled: input.retryScheduled,
    DeadLetterTransitions: input.deadLetterTransitions,
    Failures: input.failures,
    BacklogCount: input.backlogCount,
    DeadLetteredCount: input.deadLetteredCount,
    OldestUnsignedAgeSeconds: input.oldestUnsignedAgeSeconds,
  }));
}

export async function handler(
  _event: unknown,
  context: Readonly<{ awsRequestId?: string; getRemainingTimeInMillis?: () => number }> = {},
): Promise<Readonly<Record<string, number>>> {
  const requestId = typeof context.awsRequestId === "string" && /^[A-Za-z0-9-]{8,128}$/.test(context.awsRequestId)
    ? context.awsRequestId
    : crypto.randomUUID();
  const rds = new RDSDataClient({ region });
  const executor = new AwsSdkV3RdsDataApiExecutor(rds, {
    BeginTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["BeginTransactionCommand"]>>(BeginTransactionCommand as never),
    ExecuteStatementCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["ExecuteStatementCommand"]>>(ExecuteStatementCommand as never),
    CommitTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["CommitTransactionCommand"]>>(CommitTransactionCommand as never),
    RollbackTransactionCommand: compatibleAwsCommand<CommandInput<RdsDataApiCommandConstructors["RollbackTransactionCommand"]>>(RollbackTransactionCommand as never),
  });
  const kms = new AwsSdkV3KmsAsymmetricSigningClient(new KMSClient({ region }), {
    SignCommand: compatibleAwsCommand<CommandInput<KmsCommandConstructors["SignCommand"]>>(SignCommand as never),
    VerifyCommand: compatibleAwsCommand<CommandInput<KmsCommandConstructors["VerifyCommand"]>>(VerifyCommand as never),
  });
  const store = new RdsDataApiAuditOutboxSignerStore({
    executor,
    resourceArn: config.DATABASE_CLUSTER_ARN,
    secretArn: config.API_AUDIT_DATABASE_SECRET_ARN,
    database: config.DATABASE_NAME,
    kms,
    signingKeyArn: config.AUDIT_SIGNING_KEY_ARN,
  });

  let claimed = 0;
  let signed = 0;
  let retryScheduled = 0;
  let deadLetterTransitions = 0;
  let failures = 0;
  for (let index = 0; index < Number(config.API_AUDIT_BATCH_LIMIT); index += 1) {
    if (context.getRemainingTimeInMillis && context.getRemainingTimeInMillis() < 20_000) break;
    const leaseToken = `${crypto.randomUUID().replaceAll("-", "")}_${index}`;
    let claim: Awaited<ReturnType<typeof store.claim>>;
    try {
      claim = await store.claim({
        tenantId: config.TENANT_ID,
        leaseToken,
        claimedAt: new Date(),
        leaseSeconds: Number(config.API_AUDIT_LEASE_SECONDS),
      });
    } catch (error) {
      if (!(error instanceof ApiAuditOutboxPoisonedClaimError)) throw error;
      claimed += 1;
      failures += 1;
      let failureState;
      try {
        failureState = await store.recordFailure({
          claim: error.lease,
          errorCode: "CLAIM_PARSE_FAILED",
          failedAt: new Date(),
        });
      } catch (recordError) {
        console.error(JSON.stringify({
          level: "error",
          event: "api_audit_failure_record_failed",
          requestId,
          outboxId: error.lease.outboxId,
          stage: "CLAIM_PARSE",
          errorName: error.name,
          recordErrorName: recordError instanceof Error ? recordError.name : "UnknownError",
        }));
        throw new Error("API audit signer could not durably record an invalid leased outbox row.");
      }
      if (failureState.state === "already_completed") {
        signed += 1;
        failures -= 1;
      } else if (failureState.state === "retry_scheduled") {
        retryScheduled += 1;
      } else if (failureState.state === "dead_lettered") {
        deadLetterTransitions += 1;
      }
      console.error(JSON.stringify({
        level: "error",
        event: "api_audit_claim_parse_failed",
        requestId,
        outboxId: error.lease.outboxId,
        failureState: failureState.state,
        attemptCount: failureState.attemptCount,
      }));
      continue;
    }
    if (!claim) break;
    claimed += 1;
    let stage = "READ_HEAD";
    try {
      const head = await store.readAuditHead(config.TENANT_ID);
      stage = "CREATE_EVENT";
      const event = await createTenantAuditEvent({
        tenantId: config.TENANT_ID,
        sequence: head.sequence + 1,
        id: claim.eventId,
        occurredAt: claim.occurredAt,
        actor: {
          type: "user",
          userId: asUserId(claim.actorUserId),
          membershipId: asMembershipId(claim.membershipId),
        },
        action: claim.action,
        resourceType: claim.resourceType,
        resourceId: claim.resourceId,
        requestId: claim.requestId,
        outcome: claim.outcome,
        details: apiAuditEventDetails(claim),
        previousHash: head.eventHash === "GENESIS" ? "GENESIS" : asSha256(head.eventHash),
      });
      stage = "KMS_SIGN";
      const now = new Date();
      const signedAt = now.getTime() < Date.parse(claim.occurredAt) ? claim.occurredAt : now.toISOString();
      const receipt = await signTenantAuditReceipt({
        client: kms,
        event,
        keyArn: config.AUDIT_SIGNING_KEY_ARN,
        signingAlgorithm: "RSASSA_PSS_SHA_256",
        signedAt,
      });
      stage = "DATABASE_APPEND";
      await store.append(claim, event, receipt);
      signed += 1;
    } catch (error) {
      failures += 1;
      const errorCode = `${stage}_FAILED`;
      let failureState;
      try {
        failureState = await store.recordFailure({ claim, errorCode, failedAt: new Date() });
      } catch (recordError) {
        console.error(JSON.stringify({
          level: "error",
          event: "api_audit_failure_record_failed",
          requestId,
          outboxId: claim.outboxId,
          stage,
          errorName: error instanceof Error ? error.name : "UnknownError",
          recordErrorName: recordError instanceof Error ? recordError.name : "UnknownError",
        }));
        throw new Error("API audit signer could not durably record a failed outbox attempt.");
      }
      if (failureState.state === "already_completed") {
        signed += 1;
        failures -= 1;
      } else if (failureState.state === "retry_scheduled") {
        retryScheduled += 1;
      } else if (failureState.state === "dead_lettered") {
        deadLetterTransitions += 1;
      }
      console.error(JSON.stringify({
        level: "error",
        event: "api_audit_signing_failed",
        requestId,
        outboxId: claim.outboxId,
        stage,
        errorName: error instanceof Error ? error.name : "UnknownError",
        failureState: failureState.state,
        attemptCount: failureState.attemptCount,
      }));
    }
  }

  const health = await store.health({ tenantId: config.TENANT_ID, observedAt: new Date() });
  emitMetrics({ claimed, signed, retryScheduled, deadLetterTransitions, failures, ...health });
  return Object.freeze({ claimed, signed, retryScheduled, deadLetterTransitions, failures, ...health });
}
