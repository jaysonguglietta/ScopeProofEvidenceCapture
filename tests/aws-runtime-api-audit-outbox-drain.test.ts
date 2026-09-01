import assert from "node:assert/strict";
import test from "node:test";

import { createTenantAuditEvent } from "../lib/aws-runtime/audit.ts";
import { asMembershipId, asSha256, asUserId } from "../lib/aws-runtime/contracts.ts";
import {
  signTenantAuditReceipt,
  type KmsAsymmetricSigningClient,
  type KmsSignInput,
  type KmsSignOutput,
  type KmsVerifyInput,
  type KmsVerifyOutput,
} from "../lib/aws-runtime/evidence/index.ts";
import {
  ApiAuditOutboxPoisonedClaimError,
  apiAuditEventDetails,
  RdsDataApiAuditOutboxSignerStore,
} from "../lib/aws-runtime/http/audit-outbox-drain.ts";
import type { RdsDataApiExecutor } from "../lib/aws-runtime/http/membership.ts";

const TENANT = `ten_${"a".repeat(32)}`;
const USER = `usr_${"b".repeat(32)}`;
const MEMBERSHIP = `mem_${"c".repeat(32)}`;
const EVIDENCE = `evd_${"d".repeat(32)}`;
const DIGEST = "e".repeat(64);
const EVENT = `evt_${DIGEST.slice(0, 32)}`;
const OUTBOX = `aob_${DIGEST.slice(0, 32)}`;
const KMS_ARN = "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

class RecordingKms implements KmsAsymmetricSigningClient {
  readonly signInputs: KmsSignInput[] = [];
  readonly verifyInputs: KmsVerifyInput[] = [];

  async sign(input: KmsSignInput): Promise<KmsSignOutput> {
    this.signInputs.push(input);
    return { KeyId: input.KeyId, SigningAlgorithm: input.SigningAlgorithm, Signature: new Uint8Array(384).fill(9) };
  }

  async verify(input: KmsVerifyInput): Promise<KmsVerifyOutput> {
    this.verifyInputs.push(input);
    return {
      KeyId: input.KeyId,
      SigningAlgorithm: input.SigningAlgorithm,
      SignatureValid: input.Signature.byteLength === 384 && input.Signature.every((byte) => byte === 9),
    };
  }
}

function parameters(input: Readonly<{ parameters: readonly { name: string; value: { stringValue: string } }[] }>): Record<string, string> {
  return Object.fromEntries(input.parameters.map((entry) => [entry.name, entry.value.stringValue]));
}

function executor(
  calls: Array<{ sql: string; parameters: Record<string, string> }>,
  options: Readonly<{
    claimDetails?: Readonly<Record<string, unknown>>;
    onCommit?: () => void;
  }> = {},
): RdsDataApiExecutor {
  let transaction = 0;
  return {
    async beginTransaction() { transaction += 1; return { transactionId: `transaction-${String(transaction).padStart(8, "0")}` }; },
    async executeStatement(input) {
      const bound = parameters(input);
      calls.push({ sql: input.sql, parameters: bound });
      if (input.sql.includes("claim_next_api_audit_event")) {
        return { formattedRecords: JSON.stringify([{
          outbox_id: OUTBOX,
          event_id: EVENT,
          occurred_at: "2026-08-28T16:00:00.000Z",
          actor_user_id: USER,
          membership_id: MEMBERSHIP,
          request_id: "request-12345678",
          action: "evidence.download_intent_issued",
          resource_type: "evidence",
          resource_id: EVIDENCE,
          outcome: "succeeded",
          details: options.claimDetails ?? { checksumSha256: "1".repeat(64), revision: 4 },
          event_digest: DIGEST,
          attempt_count: 0,
          lease_expires_at: "2026-08-28T16:02:00.000Z",
        }]) };
      }
      if (input.sql.includes("read_tenant_audit_head")) {
        return { formattedRecords: JSON.stringify([{ current_sequence: 0, current_event_hash: "GENESIS" }]) };
      }
      if (input.sql.includes("append_signed_api_audit_event")) {
        return { formattedRecords: JSON.stringify([{
          committed_sequence: Number(bound.sequence),
          committed_event_hash: bound.event_hash,
          was_created: true,
          committed_canonical_receipt: bound.canonical_receipt,
          committed_receipt_payload_sha256: bound.receipt_payload_sha256,
          committed_signature: bound.signature,
          committed_signed_at: bound.signed_at,
        }]) };
      }
      if (input.sql.includes("record_api_audit_outbox_failure")) {
        return { formattedRecords: JSON.stringify([{
          failure_state: "retry_scheduled",
          committed_attempt_count: 1,
          committed_next_attempt_at: "2026-08-28T16:00:31.000Z",
          committed_dead_lettered_at: null,
        }]) };
      }
      if (input.sql.includes("read_api_audit_outbox_health")) {
        return { formattedRecords: JSON.stringify([{
          backlog_count: 2,
          dead_lettered_count: 1,
          oldest_unsigned_age_seconds: 301,
        }]) };
      }
      return {};
    },
    async commitTransaction() { options.onCommit?.(); },
    async rollbackTransaction() {},
  };
}

test("API audit signer drains one exact lease into a verified KMS-signed chain event", async () => {
  const calls: Array<{ sql: string; parameters: Record<string, string> }> = [];
  const kms = new RecordingKms();
  const store = new RdsDataApiAuditOutboxSignerStore({
    executor: executor(calls),
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:audit-signer-AbCd",
    database: "scopeproof_acme",
    kms,
    signingKeyArn: KMS_ARN,
  });
  const claim = await store.claim({
    tenantId: TENANT,
    leaseToken: "lease_1234567890abcdef",
    claimedAt: "2026-08-28T16:00:00.000Z",
    leaseSeconds: 120,
  });
  assert.ok(claim);
  const head = await store.readAuditHead(TENANT);
  const event = await createTenantAuditEvent({
    tenantId: TENANT,
    sequence: head.sequence + 1,
    id: claim.eventId,
    occurredAt: claim.occurredAt,
    actor: { type: "user", userId: asUserId(claim.actorUserId), membershipId: asMembershipId(claim.membershipId) },
    action: claim.action,
    resourceType: claim.resourceType,
    resourceId: claim.resourceId,
    requestId: claim.requestId,
    outcome: claim.outcome,
    details: apiAuditEventDetails(claim),
    previousHash: head.eventHash === "GENESIS" ? "GENESIS" : asSha256(head.eventHash),
  });
  const receipt = await signTenantAuditReceipt({
    client: kms,
    event,
    keyArn: KMS_ARN,
    signingAlgorithm: "RSASSA_PSS_SHA_256",
    signedAt: "2026-08-28T16:00:01.000Z",
  });
  const committed = await store.append(claim, event, receipt);
  assert.equal(committed.outcome, "applied");
  assert.equal(kms.signInputs.length, 1);
  assert.equal(kms.verifyInputs.length, 2);

  const append = calls.find((call) => call.sql.includes("append_signed_api_audit_event"));
  assert.ok(append);
  assert.equal(append.parameters.outbox_id, OUTBOX);
  assert.equal(append.parameters.lease_token, "lease_1234567890abcdef");
  assert.equal(append.parameters.event_id, EVENT);
  assert.equal(JSON.parse(append.parameters.actor).userId, USER);
  assert.deepEqual(JSON.parse(append.parameters.details), {
    checksumSha256: "1".repeat(64),
    revision: 4,
    scopeproofMembershipId: MEMBERSHIP,
    scopeproofOutboxDigest: DIGEST,
    scopeproofOutboxId: OUTBOX,
  });
  assert.match(append.sql, /scopeproof\.append_signed_api_audit_event/);
  assert.doesNotMatch(append.sql, /scopeproof\.append_signed_audit_event\(/);

  const failure = await store.recordFailure({ claim, errorCode: "KMS_SIGN_FAILED", failedAt: "2026-08-28T16:00:01.000Z" });
  assert.deepEqual(failure, {
    state: "retry_scheduled",
    attemptCount: 1,
    nextAttemptAt: "2026-08-28T16:00:31.000Z",
  });
  assert.deepEqual(await store.health({ tenantId: TENANT, observedAt: "2026-08-28T16:05:01.000Z" }), {
    backlogCount: 2,
    deadLetteredCount: 1,
    oldestUnsignedAgeSeconds: 301,
  });
});

test("API audit signer rejects a changed event before database append", async () => {
  const calls: Array<{ sql: string; parameters: Record<string, string> }> = [];
  const kms = new RecordingKms();
  const store = new RdsDataApiAuditOutboxSignerStore({
    executor: executor(calls),
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:audit-signer-AbCd",
    database: "scopeproof_acme",
    kms,
    signingKeyArn: KMS_ARN,
  });
  const claim = await store.claim({ tenantId: TENANT, leaseToken: "lease_1234567890abcdef", claimedAt: "2026-08-28T16:00:00.000Z", leaseSeconds: 120 });
  assert.ok(claim);
  const event = await createTenantAuditEvent({
    tenantId: TENANT,
    sequence: 1,
    id: claim.eventId,
    occurredAt: claim.occurredAt,
    actor: { type: "user", userId: asUserId(claim.actorUserId), membershipId: asMembershipId(claim.membershipId) },
    action: claim.action,
    resourceType: claim.resourceType,
    resourceId: claim.resourceId,
    requestId: claim.requestId,
    outcome: claim.outcome,
    details: apiAuditEventDetails(claim),
    previousHash: "GENESIS",
  });
  const receipt = await signTenantAuditReceipt({ client: kms, event, keyArn: KMS_ARN, signingAlgorithm: "RSASSA_PSS_SHA_256", signedAt: "2026-08-28T16:00:01.000Z" });
  await assert.rejects(store.append(claim, { ...event, requestId: "attacker-request" }, receipt), /does not match its leased outbox row/);
  assert.equal(calls.filter((call) => call.sql.includes("append_signed_api_audit_event")).length, 0);
});

test("API audit signer commits a minimal lease so a poisoned row can be durably retried", async () => {
  const calls: Array<{ sql: string; parameters: Record<string, string> }> = [];
  let commits = 0;
  const store = new RdsDataApiAuditOutboxSignerStore({
    executor: executor(calls, {
      claimDetails: { scopeproofOutboxId: OUTBOX },
      onCommit: () => { commits += 1; },
    }),
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:audit-signer-AbCd",
    database: "scopeproof_acme",
    kms: new RecordingKms(),
    signingKeyArn: KMS_ARN,
  });

  let poisoned: ApiAuditOutboxPoisonedClaimError | undefined;
  try {
    await store.claim({
      tenantId: TENANT,
      leaseToken: "lease_1234567890abcdef",
      claimedAt: "2026-08-28T16:00:00.000Z",
      leaseSeconds: 120,
    });
  } catch (error) {
    if (error instanceof ApiAuditOutboxPoisonedClaimError) poisoned = error;
    else throw error;
  }
  assert.ok(poisoned);
  assert.equal(commits, 1, "the lease must survive validation failure");
  assert.deepEqual(poisoned.lease, {
    tenantId: TENANT,
    outboxId: OUTBOX,
    leaseToken: "lease_1234567890abcdef",
  });
  const failure = await store.recordFailure({
    claim: poisoned.lease,
    errorCode: "CLAIM_PARSE_FAILED",
    failedAt: "2026-08-28T16:00:01.000Z",
  });
  assert.equal(failure.state, "retry_scheduled");
  assert.equal(
    calls.filter((call) => call.sql.includes("record_api_audit_outbox_failure")).length,
    1,
  );
});
