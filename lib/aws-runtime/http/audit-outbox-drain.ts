import {
  asAuditEventId,
  asMembershipId,
  asResourceId,
  asSha256,
  asTenantId,
  asUserId,
  assertSafeJson,
  canonicalInstant,
  stableJson,
  TenantSecurityError,
  type JsonValue,
} from "../contracts.ts";
import type { TenantAuditEvent } from "../audit.ts";
import { asKmsKeyArn } from "../evidence/primitives.ts";
import type { CommittedSignedAuditReceipt } from "../evidence/aws.ts";
import {
  verifyTenantAuditReceipt,
  type KmsAsymmetricSigningClient,
  type KmsSignedAuditReceipt,
} from "../evidence/signed-audit-receipt.ts";
import type { HostedApiAuditAction, HostedApiAuditResourceType } from "./audit-outbox.ts";
import type { RdsDataApiExecutor } from "./membership.ts";

export interface ClaimedApiAuditOutboxEvent {
  readonly tenantId: string;
  readonly outboxId: string;
  readonly eventId: string;
  readonly occurredAt: string;
  readonly actorUserId: string;
  readonly membershipId: string;
  readonly requestId: string;
  readonly action: HostedApiAuditAction;
  readonly resourceType: HostedApiAuditResourceType;
  readonly resourceId: string;
  readonly outcome: "succeeded";
  readonly details: Readonly<Record<string, JsonValue>>;
  readonly eventDigest: string;
  readonly attemptCount: number;
  readonly leaseToken: string;
  readonly leaseExpiresAt: string;
}

export interface ApiAuditOutboxLease {
  readonly tenantId: string;
  readonly outboxId: string;
  readonly leaseToken: string;
}

export class ApiAuditOutboxPoisonedClaimError extends Error {
  readonly lease: ApiAuditOutboxLease;

  constructor(lease: ApiAuditOutboxLease) {
    super("Leased API audit outbox row is invalid.");
    this.name = "ApiAuditOutboxPoisonedClaimError";
    this.lease = Object.freeze({ ...lease });
  }
}

export interface ApiAuditOutboxHealth {
  readonly backlogCount: number;
  readonly deadLetteredCount: number;
  readonly oldestUnsignedAgeSeconds: number;
}

export interface ApiAuditOutboxFailureState {
  readonly state: "retry_scheduled" | "dead_lettered" | "already_completed" | "already_dead_lettered";
  readonly attemptCount: number;
  readonly nextAttemptAt: string;
  readonly deadLetteredAt?: string;
}

const setTenantSql = "SELECT pg_catalog.set_config('scopeproof.tenant_id', :tenant_id, true)";
const claimSql = [
  "SELECT outbox_id::text, event_id::text, occurred_at, actor_user_id::text, membership_id::text,",
  "       request_id, action, resource_type, resource_id, outcome, details, event_digest,",
  "       attempt_count, lease_expires_at",
  "FROM scopeproof.claim_next_api_audit_event(:lease_token, CAST(:claimed_at AS timestamptz), CAST(:lease_seconds AS integer))",
].join("\n");
const readHeadSql = "SELECT current_sequence, current_event_hash FROM scopeproof.read_tenant_audit_head()";
const appendSql = [
  "SELECT committed_sequence, committed_event_hash, was_created, committed_canonical_receipt,",
  "       committed_receipt_payload_sha256, committed_signature, committed_signed_at",
  "FROM scopeproof.append_signed_api_audit_event(",
  "  CAST(:outbox_id AS scopeproof.resource_identifier), :lease_token, CAST(:sequence AS bigint),",
  "  CAST(:event_id AS scopeproof.resource_identifier), CAST(:occurred_at AS timestamptz), CAST(:actor AS jsonb),",
  "  :action, :resource_type, CAST(:resource_id AS scopeproof.resource_identifier), :request_id, :outcome,",
  "  CAST(:details AS jsonb), :previous_hash, :event_hash, :canonical_event, CAST(:receipt_payload AS jsonb),",
  "  :canonical_receipt, :receipt_payload_sha256, :signing_key_arn, :signing_algorithm, :signature,",
  "  CAST(:signed_at AS timestamptz)",
  ")",
].join("\n");
const failureSql = [
  "SELECT failure_state, committed_attempt_count, committed_next_attempt_at, committed_dead_lettered_at",
  "FROM scopeproof.record_api_audit_outbox_failure(",
  "  CAST(:outbox_id AS scopeproof.resource_identifier), :lease_token, :error_code, CAST(:failed_at AS timestamptz)",
  ")",
].join("\n");
const healthSql = [
  "SELECT backlog_count, dead_lettered_count, oldest_unsigned_age_seconds",
  "FROM scopeproof.read_api_audit_outbox_health(CAST(:observed_at AS timestamptz))",
].join("\n");

export class RdsDataApiAuditOutboxSignerStore {
  readonly #executor: RdsDataApiExecutor;
  readonly #connection: Readonly<{ resourceArn: string; secretArn: string; database: string }>;
  readonly #kms: KmsAsymmetricSigningClient;
  readonly #signingKeyArn: string;

  constructor(options: Readonly<{
    executor: RdsDataApiExecutor;
    resourceArn: string;
    secretArn: string;
    database: string;
    kms: KmsAsymmetricSigningClient;
    signingKeyArn: string;
  }>) {
    if (!options.executor) throw new Error("RDS API-audit signer executor is required.");
    const resource = /^arn:(aws|aws-us-gov|aws-cn):rds:([a-z0-9-]+):(\d{12}):cluster:[A-Za-z0-9-]{1,63}$/.exec(options.resourceArn);
    const secret = /^arn:(aws|aws-us-gov|aws-cn):secretsmanager:([a-z0-9-]+):(\d{12}):secret:[A-Za-z0-9/_+=.@-]{1,512}$/.exec(options.secretArn);
    if (!resource || !secret || resource[1] !== secret[1] || resource[2] !== secret[2] || resource[3] !== secret[3]) {
      throw new Error("RDS API-audit signer cluster and secret must be valid and co-located.");
    }
    if (!/^[A-Za-z][A-Za-z0-9_]{0,62}$/.test(options.database)) throw new Error("API-audit signer database name is invalid.");
    if (!options.kms) throw new Error("API-audit signer KMS client is required.");
    this.#executor = options.executor;
    this.#connection = Object.freeze({ resourceArn: options.resourceArn, secretArn: options.secretArn, database: options.database });
    this.#kms = options.kms;
    this.#signingKeyArn = asKmsKeyArn(options.signingKeyArn);
  }

  async claim(input: Readonly<{
    tenantId: string;
    leaseToken: string;
    claimedAt: Date | string;
    leaseSeconds: number;
  }>): Promise<ClaimedApiAuditOutboxEvent | null> {
    const tenantId = asTenantId(input.tenantId);
    const leaseToken = exactLeaseToken(input.leaseToken);
    const claimedAt = canonicalInstant(input.claimedAt, "API audit claim time");
    if (!Number.isSafeInteger(input.leaseSeconds) || input.leaseSeconds < 30 || input.leaseSeconds > 300) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "API audit lease duration is invalid.");
    }
    // Commit the database lease before parsing attacker-influenced JSON. If the
    // row violates the runtime contract, the caller receives a minimal trusted
    // lease and can durably advance its bounded retry/dead-letter state instead
    // of rolling the lease back and blocking every later row forever.
    const formattedRecords = await this.#transaction(tenantId, async (transactionId) => {
      const response = await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql: claimSql,
        parameters: [
          parameter("lease_token", leaseToken),
          parameter("claimed_at", claimedAt),
          parameter("lease_seconds", String(input.leaseSeconds)),
        ],
        formatRecordsAs: "JSON",
      });
      return response.formattedRecords;
    });
    try {
      return parseClaim(formattedRecords, tenantId, leaseToken);
    } catch (error) {
      const lease = parsePoisonLease(formattedRecords, tenantId, leaseToken);
      if (lease) throw new ApiAuditOutboxPoisonedClaimError(lease);
      throw error;
    }
  }

  async readAuditHead(tenantIdInput: string): Promise<Readonly<{ sequence: number; eventHash: string | "GENESIS" }>> {
    const tenantId = asTenantId(tenantIdInput);
    return await this.#transaction(tenantId, async (transactionId) => {
      const response = await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql: readHeadSql,
        parameters: [],
        formatRecordsAs: "JSON",
      });
      return parseHead(response.formattedRecords);
    });
  }

  async append(
    claim: ClaimedApiAuditOutboxEvent,
    event: TenantAuditEvent,
    receipt: KmsSignedAuditReceipt,
  ): Promise<CommittedSignedAuditReceipt> {
    assertEventMatchesClaim(claim, event);
    if (receipt.keyArn !== this.#signingKeyArn || receipt.signingAlgorithm !== "RSASSA_PSS_SHA_256") {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "API audit receipt uses an unapproved signing key or algorithm.", 409);
    }
    await verifyTenantAuditReceipt({
      client: this.#kms,
      receipt,
      expectedEvent: event,
      expectedKeyArn: this.#signingKeyArn,
      expectedTenantId: claim.tenantId,
    });
    const unsigned = Object.fromEntries(Object.entries(event).filter(([key]) => key !== "eventHash"));
    const canonicalEvent = stableJson(unsigned as unknown as JsonValue);
    const canonicalReceipt = stableJson(receipt.payload as unknown as JsonValue);
    const stored = await this.#transaction(claim.tenantId, async (transactionId) => {
      const response = await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql: appendSql,
        parameters: [
          parameter("outbox_id", claim.outboxId),
          parameter("lease_token", claim.leaseToken),
          parameter("sequence", String(event.sequence)),
          parameter("event_id", event.id),
          parameter("occurred_at", event.occurredAt),
          parameter("actor", stableJson(event.actor as unknown as JsonValue)),
          parameter("action", event.action),
          parameter("resource_type", event.resourceType),
          parameter("resource_id", event.resourceId),
          parameter("request_id", event.requestId),
          parameter("outcome", event.outcome),
          parameter("details", stableJson(event.details)),
          parameter("previous_hash", event.previousHash),
          parameter("event_hash", event.eventHash),
          parameter("canonical_event", canonicalEvent),
          parameter("receipt_payload", canonicalReceipt),
          parameter("canonical_receipt", canonicalReceipt),
          parameter("receipt_payload_sha256", receipt.payloadSha256),
          parameter("signing_key_arn", receipt.keyArn),
          parameter("signing_algorithm", receipt.signingAlgorithm),
          parameter("signature", receipt.signature),
          parameter("signed_at", receipt.payload.signedAt),
        ],
        formatRecordsAs: "JSON",
      });
      return parseAppend(response.formattedRecords, event, receipt);
    });
    await verifyTenantAuditReceipt({
      client: this.#kms,
      receipt: stored.receipt,
      expectedEvent: event,
      expectedKeyArn: this.#signingKeyArn,
      expectedTenantId: claim.tenantId,
    });
    return stored;
  }

  async recordFailure(input: Readonly<{
    claim: ApiAuditOutboxLease;
    errorCode: string;
    failedAt: Date | string;
  }>): Promise<ApiAuditOutboxFailureState> {
    const tenantId = asTenantId(input.claim.tenantId);
    const outboxId = asResourceId(input.claim.outboxId, ["aob"]);
    const leaseToken = exactLeaseToken(input.claim.leaseToken);
    const errorCode = String(input.errorCode ?? "");
    if (!/^[A-Z][A-Z0-9_]{2,63}$/.test(errorCode)) throw new TenantSecurityError("INVALID_AUDIT_EVENT", "API audit failure code is invalid.");
    const failedAt = canonicalInstant(input.failedAt, "API audit failure time");
    return await this.#transaction(tenantId, async (transactionId) => {
      const response = await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql: failureSql,
        parameters: [
          parameter("outbox_id", outboxId),
          parameter("lease_token", leaseToken),
          parameter("error_code", errorCode),
          parameter("failed_at", failedAt),
        ],
        formatRecordsAs: "JSON",
      });
      return parseFailure(response.formattedRecords);
    });
  }

  async health(input: Readonly<{ tenantId: string; observedAt: Date | string }>): Promise<ApiAuditOutboxHealth> {
    const tenantId = asTenantId(input.tenantId);
    const observedAt = canonicalInstant(input.observedAt, "API audit health time");
    return await this.#transaction(tenantId, async (transactionId) => {
      const response = await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql: healthSql,
        parameters: [parameter("observed_at", observedAt)],
        formatRecordsAs: "JSON",
      });
      return parseHealth(response.formattedRecords);
    });
  }

  async #transaction<T>(tenantIdInput: string, operation: (transactionId: string) => Promise<T>): Promise<T> {
    const tenantId = asTenantId(tenantIdInput);
    const started = await this.#executor.beginTransaction(this.#connection);
    const transactionId = started.transactionId;
    if (!transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transactionId)) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "API audit signer transaction could not be established.", 500);
    }
    try {
      await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql: setTenantSql,
        parameters: [parameter("tenant_id", tenantId)],
      });
      const result = await operation(transactionId);
      await this.#executor.commitTransaction({
        resourceArn: this.#connection.resourceArn,
        secretArn: this.#connection.secretArn,
        transactionId,
      });
      return result;
    } catch (error) {
      try {
        await this.#executor.rollbackTransaction({
          resourceArn: this.#connection.resourceArn,
          secretArn: this.#connection.secretArn,
          transactionId,
        });
      } catch {
        // Preserve the authoritative operation failure.
      }
      throw error;
    }
  }
}

function parsePoisonLease(
  value: string | undefined,
  tenantId: string,
  leaseToken: string,
): ApiAuditOutboxLease | null {
  let parsed: unknown;
  if (!value || value.length > 32_768) return null;
  try { parsed = JSON.parse(value); } catch { return null; }
  if (!Array.isArray(parsed) || parsed.length !== 1) return null;
  const row = parsed[0];
  if (!row || typeof row !== "object" || Array.isArray(row)) return null;
  try {
    return Object.freeze({
      tenantId: asTenantId(tenantId),
      outboxId: asResourceId(exactString((row as Record<string, unknown>).outbox_id), ["aob"]),
      leaseToken: exactLeaseToken(leaseToken),
    });
  } catch {
    return null;
  }
}

export function apiAuditEventDetails(claim: ClaimedApiAuditOutboxEvent): Readonly<Record<string, JsonValue>> {
  const safe = assertSafeJson(claim.details, "API audit outbox details");
  if (!safe || typeof safe !== "object" || Array.isArray(safe)) throw malformed("API audit outbox details are invalid.");
  return Object.freeze({
    ...(safe as Record<string, JsonValue>),
    scopeproofMembershipId: asMembershipId(claim.membershipId),
    scopeproofOutboxDigest: asSha256(claim.eventDigest),
    scopeproofOutboxId: asResourceId(claim.outboxId, ["aob"]),
  });
}

function assertEventMatchesClaim(claim: ClaimedApiAuditOutboxEvent, event: TenantAuditEvent): void {
  const expectedActor = stableJson({
    type: "user",
    userId: asUserId(claim.actorUserId),
    membershipId: asMembershipId(claim.membershipId),
  } as unknown as JsonValue);
  if (event.tenantId !== asTenantId(claim.tenantId) ||
      event.id !== asAuditEventId(claim.eventId) ||
      event.occurredAt !== canonicalInstant(claim.occurredAt, "API audit occurrence time") ||
      stableJson(event.actor as unknown as JsonValue) !== expectedActor ||
      event.action !== claim.action || event.resourceType !== claim.resourceType ||
      event.resourceId !== asResourceId(claim.resourceId) || event.requestId !== claim.requestId ||
      event.outcome !== claim.outcome ||
      stableJson(event.details) !== stableJson(apiAuditEventDetails(claim))) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Signed API audit event does not match its leased outbox row.", 409);
  }
}

function parseClaim(value: string | undefined, tenantId: string, leaseToken: string): ClaimedApiAuditOutboxEvent | null {
  const rows = exactRows(value, 1, 32_768);
  if (rows.length === 0) return null;
  const row = exactObject(rows[0]);
  exactKeys(row, [
    "action", "actor_user_id", "attempt_count", "details", "event_digest", "event_id",
    "lease_expires_at", "membership_id", "occurred_at", "outbox_id", "outcome",
    "request_id", "resource_id", "resource_type",
  ]);
  const eventDigest = asSha256(exactString(row.event_digest));
  const outboxId = asResourceId(exactString(row.outbox_id), ["aob"]);
  const eventId = asAuditEventId(exactString(row.event_id));
  if (outboxId !== `aob_${eventDigest.slice(0, 32)}` || eventId !== `evt_${eventDigest.slice(0, 32)}`) throw malformed();
  const action = exactAction(row.action);
  const resourceType = exactResourceType(row.resource_type);
  const resourceId = asResourceId(exactString(row.resource_id));
  assertActionResource(action, resourceType, resourceId, tenantId);
  const details = assertSafeJson(row.details, "API audit outbox details");
  if (!details || typeof details !== "object" || Array.isArray(details)) throw malformed();
  for (const reserved of ["scopeproofMembershipId", "scopeproofOutboxDigest", "scopeproofOutboxId"]) {
    if (Object.hasOwn(details, reserved)) throw malformed();
  }
  const attemptCount = exactNonnegativeInteger(row.attempt_count, 8);
  const requestId = exactBounded(row.request_id, 8, 128);
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(requestId)) throw malformed();
  return Object.freeze({
    tenantId: asTenantId(tenantId),
    outboxId,
    eventId,
    occurredAt: canonicalInstant(exactString(row.occurred_at), "API audit occurrence time"),
    actorUserId: asUserId(exactString(row.actor_user_id)),
    membershipId: asMembershipId(exactString(row.membership_id)),
    requestId,
    action,
    resourceType,
    resourceId,
    outcome: exactString(row.outcome) === "succeeded" ? "succeeded" : (() => { throw malformed(); })(),
    details: Object.freeze(details as Record<string, JsonValue>),
    eventDigest,
    attemptCount,
    leaseToken,
    leaseExpiresAt: canonicalInstant(exactString(row.lease_expires_at), "API audit lease expiry"),
  });
}

function parseHead(value: string | undefined): Readonly<{ sequence: number; eventHash: string | "GENESIS" }> {
  const rows = exactRows(value, 1, 2_048);
  if (rows.length !== 1) throw malformed();
  const row = exactObject(rows[0]);
  exactKeys(row, ["current_event_hash", "current_sequence"]);
  const sequence = exactNonnegativeInteger(row.current_sequence, Number.MAX_SAFE_INTEGER);
  const eventHash = exactString(row.current_event_hash);
  if ((sequence === 0) !== (eventHash === "GENESIS") || (eventHash !== "GENESIS" && !/^[a-f0-9]{64}$/.test(eventHash))) throw malformed();
  return Object.freeze({ sequence, eventHash: eventHash as string | "GENESIS" });
}

function parseAppend(value: string | undefined, event: TenantAuditEvent, submitted: KmsSignedAuditReceipt): CommittedSignedAuditReceipt {
  const rows = exactRows(value, 1, 65_536);
  if (rows.length !== 1) throw malformed();
  const row = exactObject(rows[0]);
  exactKeys(row, [
    "committed_canonical_receipt", "committed_event_hash", "committed_receipt_payload_sha256",
    "committed_sequence", "committed_signature", "committed_signed_at", "was_created",
  ]);
  if (row.committed_sequence !== event.sequence || row.committed_event_hash !== event.eventHash || typeof row.was_created !== "boolean") throw malformed();
  const canonicalReceipt = exactString(row.committed_canonical_receipt);
  let payload: unknown;
  try { payload = JSON.parse(canonicalReceipt); } catch { throw malformed(); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw malformed();
  const signedAt = canonicalInstant(exactString(row.committed_signed_at), "Stored API audit signing time");
  if (!("signedAt" in payload) || payload.signedAt !== signedAt) throw malformed();
  const receipt: KmsSignedAuditReceipt = Object.freeze({
    schemaVersion: 1,
    payload: payload as KmsSignedAuditReceipt["payload"],
    payloadSha256: asSha256(exactString(row.committed_receipt_payload_sha256)),
    keyArn: submitted.keyArn,
    signingAlgorithm: submitted.signingAlgorithm,
    signature: exactBounded(row.committed_signature, 512, 512),
  });
  return Object.freeze({
    outcome: row.was_created ? "applied" : "already_applied",
    sequence: event.sequence,
    eventHash: event.eventHash,
    receipt,
  });
}

function parseFailure(value: string | undefined): ApiAuditOutboxFailureState {
  const rows = exactRows(value, 1, 4_096);
  if (rows.length !== 1) throw malformed();
  const row = exactObject(rows[0]);
  exactKeys(row, ["committed_attempt_count", "committed_dead_lettered_at", "committed_next_attempt_at", "failure_state"]);
  const state = exactString(row.failure_state);
  if (!["retry_scheduled", "dead_lettered", "already_completed", "already_dead_lettered"].includes(state)) throw malformed();
  const deadLetteredAt = row.committed_dead_lettered_at === null
    ? undefined
    : canonicalInstant(exactString(row.committed_dead_lettered_at), "API audit dead-letter time");
  if ((state === "dead_lettered" || state === "already_dead_lettered") !== (deadLetteredAt !== undefined)) throw malformed();
  return Object.freeze({
    state: state as ApiAuditOutboxFailureState["state"],
    attemptCount: exactNonnegativeInteger(row.committed_attempt_count, 8),
    nextAttemptAt: canonicalInstant(exactString(row.committed_next_attempt_at), "API audit retry time"),
    ...(deadLetteredAt ? { deadLetteredAt } : {}),
  });
}

function parseHealth(value: string | undefined): ApiAuditOutboxHealth {
  const rows = exactRows(value, 1, 2_048);
  if (rows.length !== 1) throw malformed();
  const row = exactObject(rows[0]);
  exactKeys(row, ["backlog_count", "dead_lettered_count", "oldest_unsigned_age_seconds"]);
  const backlogCount = exactNonnegativeInteger(row.backlog_count, 1_000_000_000);
  const deadLetteredCount = exactNonnegativeInteger(row.dead_lettered_count, backlogCount);
  return Object.freeze({
    backlogCount,
    deadLetteredCount,
    oldestUnsignedAgeSeconds: exactNonnegativeInteger(row.oldest_unsigned_age_seconds, 10 * 365 * 24 * 60 * 60),
  });
}

function exactRows(value: string | undefined, maximumRows: number, maximumBytes: number): unknown[] {
  if (!value || value.length > maximumBytes) throw malformed();
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw malformed(); }
  if (!Array.isArray(parsed) || parsed.length > maximumRows) throw malformed();
  return parsed;
}

function exactObject(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw malformed();
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw malformed();
}

function exactString(value: unknown): string {
  if (typeof value !== "string") throw malformed();
  return value;
}

function exactBounded(value: unknown, minimum: number, maximum: number): string {
  const exact = exactString(value);
  if (exact.length < minimum || exact.length > maximum || exact !== exact.trim() || /\p{Cc}/u.test(exact)) throw malformed();
  return exact;
}

function exactNonnegativeInteger(value: unknown, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > maximum) throw malformed();
  return value as number;
}

function exactLeaseToken(value: string): string {
  const exact = String(value ?? "");
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(exact)) throw new TenantSecurityError("INVALID_AUDIT_EVENT", "API audit lease token is invalid.");
  return exact;
}

function exactAction(value: unknown): HostedApiAuditAction {
  const action = exactString(value);
  if (!["evidence.upload_intent_issued", "evidence.search_performed", "evidence.download_intent_issued", "evidence.legal_hold_requested", "evidence.legal_hold_approved"].includes(action)) throw malformed();
  return action as HostedApiAuditAction;
}

function exactResourceType(value: unknown): HostedApiAuditResourceType {
  const resourceType = exactString(value);
  if (!["evidence", "evidence_collection", "legal_hold_operation"].includes(resourceType)) throw malformed();
  return resourceType as HostedApiAuditResourceType;
}

function assertActionResource(action: HostedApiAuditAction, type: HostedApiAuditResourceType, id: string, tenantId: string): void {
  if (action === "evidence.search_performed") {
    if (type !== "evidence_collection" || id !== tenantId) throw malformed();
  } else if (action === "evidence.upload_intent_issued" || action === "evidence.download_intent_issued") {
    if (type !== "evidence" || !/^evd_[a-f0-9]{32}$/.test(id)) throw malformed();
  } else if (type !== "legal_hold_operation" || !/^lho_[a-f0-9]{32}$/.test(id)) {
    throw malformed();
  }
}

function parameter(name: string, value: string) {
  return Object.freeze({ name, value: Object.freeze({ stringValue: value }) });
}

function malformed(message = "API audit signer database response is invalid."): TenantSecurityError {
  return new TenantSecurityError("INVALID_AUDIT_EVENT", message, 500);
}
