import {
  asAuditEventId,
  asMembershipId,
  asResourceId,
  asSha256,
  asTenantId,
  asUserId,
  assertBoundedText,
  assertSafeJson,
  canonicalInstant,
  sha256Hex,
  stableJson,
  type AuditEventId,
  type JsonValue,
  type MembershipId,
  type ResourceId,
  type Sha256Hex,
  type TenantId,
  TenantSecurityError,
  type UserId,
} from "./contracts.ts";

export type AuditActor =
  | { type: "user"; userId: UserId; membershipId: MembershipId }
  | { type: "device"; deviceId: ResourceId; userId: UserId }
  | { type: "system"; service: string };

export interface TenantAuditEvent {
  readonly schemaVersion: 1;
  readonly tenantId: TenantId;
  readonly sequence: number;
  readonly id: AuditEventId;
  readonly occurredAt: string;
  readonly actor: AuditActor;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId: ResourceId;
  readonly requestId: string;
  readonly outcome: "succeeded" | "denied" | "failed";
  readonly details: JsonValue;
  readonly previousHash: Sha256Hex | "GENESIS";
  readonly eventHash: Sha256Hex;
}

export async function createTenantAuditEvent(input: Omit<TenantAuditEvent, "schemaVersion" | "eventHash" | "tenantId" | "id" | "resourceId" | "occurredAt" | "details"> & {
  tenantId: string;
  id: string;
  resourceId: string;
  occurredAt: Date | string;
  details: unknown;
}): Promise<TenantAuditEvent> {
  const tenantId = asTenantId(input.tenantId);
  const id = asAuditEventId(input.id);
  const resourceId = asResourceId(input.resourceId);
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 1) throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit sequence is invalid.");
  const previousHash: Sha256Hex | "GENESIS" = input.previousHash === "GENESIS" ? "GENESIS" : asSha256(input.previousHash);
  if ((input.sequence === 1) !== (previousHash === "GENESIS")) throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit genesis and sequence do not agree.");
  const action = assertBoundedText(input.action, "Audit action", 3, 120);
  const resourceType = assertBoundedText(input.resourceType, "Audit resource type", 2, 80);
  const requestId = assertBoundedText(input.requestId, "Audit request id", 3, 200);
  if (!/^[a-z][a-z0-9_.:-]*$/.test(action) || !/^[a-z][a-z0-9_.:-]*$/.test(resourceType)) throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit action or resource type is invalid.");
  if (!['succeeded', 'denied', 'failed'].includes(input.outcome)) throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit outcome is invalid.");
  const details = assertSafeJson(input.details);
  const occurredAt = canonicalInstant(input.occurredAt, "Audit timestamp");
  const unsigned = {
    schemaVersion: 1 as const,
    tenantId,
    sequence: input.sequence,
    id,
    occurredAt,
    actor: normalizeActor(input.actor),
    action,
    resourceType,
    resourceId,
    requestId,
    outcome: input.outcome,
    details,
    previousHash,
  };
  const canonical = stableJson(unsigned as unknown as JsonValue);
  if (canonical.length > 32_000) throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit event is too large.");
  return Object.freeze({ ...unsigned, eventHash: await sha256Hex(canonical) });
}

function normalizeActor(actor: AuditActor): AuditActor {
  if (actor.type === "system") return Object.freeze({ type: "system", service: assertBoundedText(actor.service, "Audit service", 2, 100) });
  if (actor.type === "device") return Object.freeze({ type: "device", deviceId: asResourceId(actor.deviceId, ["dev"]), userId: asUserId(actor.userId) });
  if (actor.type === "user") return Object.freeze({ type: "user", userId: asUserId(actor.userId), membershipId: asMembershipId(actor.membershipId) });
  throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit actor is invalid.");
}

export function assertAuditContinuation(previous: TenantAuditEvent, next: TenantAuditEvent): void {
  if (previous.tenantId !== next.tenantId || next.sequence !== previous.sequence + 1 || next.previousHash !== previous.eventHash) {
    throw new TenantSecurityError("INVALID_AUDIT_EVENT", "Audit event does not continue the tenant chain.", 409);
  }
}
