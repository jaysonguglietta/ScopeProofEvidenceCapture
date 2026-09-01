import {
  asMembershipId,
  asResourceId,
  asTenantId,
  asUserId,
  assertSafeJson,
  containsAsciiControlCharacters,
  stableJson,
  TenantSecurityError,
  type JsonValue,
} from "../contracts.ts";
import type { TenantActor } from "../tenancy.ts";
import type { RdsDataApiExecutor } from "./membership.ts";

export type HostedApiAuditAction =
  | "evidence.upload_intent_issued"
  | "evidence.search_performed"
  | "evidence.download_intent_issued"
  | "evidence.legal_hold_requested"
  | "evidence.legal_hold_approved";

export type HostedApiAuditResourceType = "evidence" | "evidence_collection" | "legal_hold_operation";

export interface HostedApiAuditRecord {
  readonly action: HostedApiAuditAction;
  readonly actor: TenantActor;
  readonly requestId: string;
  readonly resourceType: HostedApiAuditResourceType;
  readonly resourceId: string;
  readonly idempotencyKey: string;
  readonly details: unknown;
}

export interface RecordedHostedApiAudit {
  readonly outboxId: string;
  readonly wasCreated: boolean;
  readonly eventDigest: string;
}

const setTenantSql = "SELECT pg_catalog.set_config('scopeproof.tenant_id', :tenant_id, true)";
const recordAuditSql = [
  "SELECT outbox_id::text, was_created, committed_event_digest",
  "FROM scopeproof.record_api_audit_event(",
  "  CAST(:actor_user_id AS scopeproof.resource_identifier),",
  "  CAST(:membership_id AS scopeproof.resource_identifier),",
  "  :request_id, :action, :resource_type, :resource_id, :idempotency_key, CAST(:details AS jsonb)",
  ")",
].join("\n");

export class RdsDataApiAuditOutbox {
  readonly #executor: RdsDataApiExecutor;
  readonly #connection: Readonly<{ resourceArn: string; secretArn: string; database: string }>;

  constructor(options: Readonly<{
    executor: RdsDataApiExecutor;
    resourceArn: string;
    secretArn: string;
    database: string;
  }>) {
    if (!options.executor) throw new Error("RDS audit-outbox executor is required.");
    this.#executor = options.executor;
    const resource = /^arn:(aws|aws-us-gov|aws-cn):rds:([a-z0-9-]+):(\d{12}):cluster:[A-Za-z0-9-]{1,63}$/.exec(options.resourceArn);
    const secret = /^arn:(aws|aws-us-gov|aws-cn):secretsmanager:([a-z0-9-]+):(\d{12}):secret:[A-Za-z0-9/_+=.@-]{1,512}$/.exec(options.secretArn);
    if (!resource || !secret || resource[1] !== secret[1] || resource[2] !== secret[2] || resource[3] !== secret[3]) {
      throw new Error("RDS audit-outbox cluster and secret must be valid and co-located.");
    }
    if (!/^[A-Za-z][A-Za-z0-9_]{0,62}$/.test(options.database)) throw new Error("Audit-outbox database name is invalid.");
    this.#connection = Object.freeze({
      resourceArn: options.resourceArn,
      secretArn: options.secretArn,
      database: options.database,
    });
  }

  async record(input: HostedApiAuditRecord): Promise<RecordedHostedApiAudit> {
    const normalized = normalizeRecord(input);
    const started = await this.#executor.beginTransaction(this.#connection);
    const transactionId = started.transactionId;
    if (!transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transactionId)) {
      throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit transaction could not be established.", 500);
    }
    try {
      await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql: setTenantSql,
        parameters: [parameter("tenant_id", normalized.tenantId)],
      });
      const result = await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql: recordAuditSql,
        parameters: [
          parameter("actor_user_id", normalized.actorUserId),
          parameter("membership_id", normalized.membershipId),
          parameter("request_id", normalized.requestId),
          parameter("action", normalized.action),
          parameter("resource_type", normalized.resourceType),
          parameter("resource_id", normalized.resourceId),
          parameter("idempotency_key", normalized.idempotencyKey),
          parameter("details", normalized.details),
        ],
        formatRecordsAs: "JSON",
      });
      const recorded = parseResult(result.formattedRecords);
      await this.#executor.commitTransaction({
        resourceArn: this.#connection.resourceArn,
        secretArn: this.#connection.secretArn,
        transactionId,
      });
      return recorded;
    } catch (error) {
      try {
        await this.#executor.rollbackTransaction({
          resourceArn: this.#connection.resourceArn,
          secretArn: this.#connection.secretArn,
          transactionId,
        });
      } catch {
        // Preserve the authoritative failure; rollback failures are monitored.
      }
      throw error;
    }
  }
}

function normalizeRecord(input: HostedApiAuditRecord): Readonly<{
  tenantId: string;
  actorUserId: string;
  membershipId: string;
  requestId: string;
  action: HostedApiAuditAction;
  resourceType: HostedApiAuditResourceType;
  resourceId: string;
  idempotencyKey: string;
  details: string;
}> {
  const tenantId = asTenantId(input.actor.tenantId);
  const actorUserId = asUserId(input.actor.userId);
  const membershipId = asMembershipId(input.actor.membershipId);
  const requestId = exactBounded(input.requestId, "Audit request id", 8, 128, /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/);
  const idempotencyKey = exactBounded(input.idempotencyKey, "Audit idempotency key", 16, 200);
  let resourceId: string;
  if (input.action === "evidence.search_performed") {
    if (input.resourceType !== "evidence_collection" || input.resourceId !== tenantId) throw invalidResource();
    resourceId = tenantId;
  } else if (input.action === "evidence.upload_intent_issued" || input.action === "evidence.download_intent_issued") {
    if (input.resourceType !== "evidence") throw invalidResource();
    resourceId = asResourceId(input.resourceId, ["evd"]);
  } else if (input.action === "evidence.legal_hold_requested" || input.action === "evidence.legal_hold_approved") {
    if (input.resourceType !== "legal_hold_operation") throw invalidResource();
    resourceId = asResourceId(input.resourceId, ["lho"]);
  } else {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Hosted API audit action is invalid.");
  }
  const safeDetails = assertSafeJson(input.details, "Hosted API audit details");
  if (!safeDetails || typeof safeDetails !== "object" || Array.isArray(safeDetails)) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Hosted API audit details must be an object.");
  }
  const details = stableJson(safeDetails as JsonValue);
  if (new TextEncoder().encode(details).byteLength > 16_384) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Hosted API audit details are too large.");
  }
  return Object.freeze({
    tenantId,
    actorUserId,
    membershipId,
    requestId,
    action: input.action,
    resourceType: input.resourceType,
    resourceId,
    idempotencyKey,
    details,
  });
}

function exactBounded(value: string, label: string, minimum: number, maximum: number, pattern?: RegExp): string {
  const exact = String(value ?? "");
  if (exact.length < minimum || exact.length > maximum || exact !== exact.trim() || containsAsciiControlCharacters(exact) || (pattern && !pattern.test(exact))) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", `${label} is invalid.`);
  }
  return exact;
}

function invalidResource(): TenantSecurityError {
  return new TenantSecurityError("INVALID_AUDIT_EVENT", "Hosted API audit resource binding is invalid.");
}

function parseResult(value: string | undefined): RecordedHostedApiAudit {
  if (!value || value.length > 2_048) throw malformedResult();
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw malformedResult(); }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !parsed[0] || typeof parsed[0] !== "object" || Array.isArray(parsed[0])) throw malformedResult();
  const row = parsed[0] as Record<string, unknown>;
  const keys = Object.keys(row).sort();
  if (keys.join(",") !== "committed_event_digest,outbox_id,was_created" ||
      typeof row.was_created !== "boolean" ||
      typeof row.outbox_id !== "string" ||
      typeof row.committed_event_digest !== "string" ||
      !/^aob_[a-f0-9]{32}$/.test(row.outbox_id) ||
      !/^[a-f0-9]{64}$/.test(row.committed_event_digest)) throw malformedResult();
  return Object.freeze({
    outboxId: row.outbox_id,
    wasCreated: row.was_created,
    eventDigest: row.committed_event_digest,
  });
}

function malformedResult(): TenantSecurityError {
  return new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit outbox response is invalid.", 500);
}

function parameter(name: string, value: string) {
  return Object.freeze({ name, value: Object.freeze({ stringValue: value }) });
}
