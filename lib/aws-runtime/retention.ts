import {
  asResourceId,
  asTenantId,
  asUserId,
  assertBoundedText,
  assertRevision,
  assertVersionId,
  canonicalInstant,
  type ExactObjectKey,
  type ResourceId,
  type TenantId,
  TenantSecurityError,
  type UserId,
} from "./contracts.ts";
import { exactObjectKey } from "./upload.ts";

export type ObjectLockMode = "GOVERNANCE" | "COMPLIANCE";
export type RetentionStatus = "retained" | "deletion_eligible" | "deletion_pending" | "deleted";

export interface LegalHold {
  readonly id: string;
  readonly placedAt: string;
  readonly placedBy: UserId;
  readonly reason: string;
}

export interface EvidenceRetention {
  readonly schemaVersion: 1;
  readonly tenantId: TenantId;
  readonly resourceId: ResourceId;
  readonly objectKey: ExactObjectKey;
  readonly versionId: string;
  readonly lockMode: ObjectLockMode;
  readonly retainUntil: string;
  readonly legalHold: LegalHold | null;
  readonly status: RetentionStatus;
  readonly revision: number;
  readonly deletionRequestedAt?: string;
  readonly deletedAt?: string;
  readonly deleteRequestId?: string;
}

export function createEvidenceRetention(input: {
  tenantId: string;
  resourceId: string;
  objectKey: string;
  versionId: string;
  lockMode: ObjectLockMode;
  retainUntil: Date;
  now: Date;
}): EvidenceRetention {
  const tenantId = asTenantId(input.tenantId);
  const resourceId = asResourceId(input.resourceId);
  const objectKey = exactObjectKey(input.objectKey);
  const prefix = `tenants/${tenantId}/evidence/`;
  if (!objectKey.startsWith(prefix) || objectKey.slice(prefix.length).includes("/") || !objectKey.slice(prefix.length).startsWith(`${resourceId}.`)) throw new TenantSecurityError("RETENTION_VIOLATION", "Retained object key is outside the exact tenant evidence namespace.");
  if (!['GOVERNANCE', 'COMPLIANCE'].includes(input.lockMode) || input.retainUntil.getTime() <= input.now.getTime()) throw new TenantSecurityError("RETENTION_VIOLATION", "A future Object Lock retention date is required.");
  return Object.freeze({ schemaVersion: 1, tenantId, resourceId, objectKey, versionId: assertVersionId(input.versionId), lockMode: input.lockMode, retainUntil: canonicalInstant(input.retainUntil), legalHold: null, status: "retained", revision: 0 });
}

export function extendRetention(record: EvidenceRetention, input: { expectedRevision: number; retainUntil: Date }): EvidenceRetention {
  assertRevision(record.revision, input.expectedRevision);
  if (record.status === "deleted" || input.retainUntil.getTime() <= Date.parse(record.retainUntil)) throw new TenantSecurityError("RETENTION_VIOLATION", "Retention can only be extended.", 409);
  return Object.freeze({ ...record, retainUntil: canonicalInstant(input.retainUntil), revision: record.revision + 1, status: "retained", deletionRequestedAt: undefined, deleteRequestId: undefined });
}

export function placeLegalHold(record: EvidenceRetention, input: { expectedRevision: number; holdId: string; actor: UserId; reason: string; now: Date }): EvidenceRetention {
  assertRevision(record.revision, input.expectedRevision);
  if (record.status === "deleted" || record.legalHold) throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "A legal hold cannot be placed in the current state.", 409);
  const id = retentionToken(input.holdId, "Legal hold id");
  return Object.freeze({ ...record, legalHold: { id, placedAt: canonicalInstant(input.now), placedBy: asUserId(input.actor), reason: assertBoundedText(input.reason, "Legal hold reason", 20, 1_000) }, status: "retained", revision: record.revision + 1, deletionRequestedAt: undefined, deleteRequestId: undefined });
}

export function releaseLegalHold(record: EvidenceRetention, input: { expectedRevision: number; holdId: string; actor: UserId; reason: string }): EvidenceRetention {
  assertRevision(record.revision, input.expectedRevision);
  if (!record.legalHold || record.legalHold.id !== input.holdId) throw new TenantSecurityError("LEGAL_HOLD_ACTIVE", "Matching legal hold authorization is required.", 409);
  const actor = asUserId(input.actor);
  if (actor === record.legalHold.placedBy) throw new TenantSecurityError("LEGAL_HOLD_ACTIVE", "A different authorized user must release the legal hold.", 409);
  assertBoundedText(input.reason, "Legal hold release reason", 20, 1_000);
  return Object.freeze({ ...record, legalHold: null, revision: record.revision + 1 });
}

export function evaluateDeletionEligibility(record: EvidenceRetention, input: { expectedRevision: number; now: Date }): EvidenceRetention {
  assertRevision(record.revision, input.expectedRevision);
  if (record.status === "deleted" || record.status === "deletion_pending") throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "Deletion eligibility cannot be evaluated in the current state.", 409);
  if (record.legalHold) throw new TenantSecurityError("LEGAL_HOLD_ACTIVE", "Evidence is protected by a legal hold.", 409);
  if (input.now.getTime() < Date.parse(record.retainUntil)) throw new TenantSecurityError("RETENTION_VIOLATION", "Evidence retention has not elapsed.", 409);
  return Object.freeze({ ...record, status: "deletion_eligible", revision: record.revision + 1 });
}

export function requestExactVersionDeletion(record: EvidenceRetention, input: { expectedRevision: number; now: Date; objectKey: string; versionId: string; requestId: string }): EvidenceRetention {
  assertRevision(record.revision, input.expectedRevision);
  if (record.status !== "deletion_eligible" || record.legalHold) throw new TenantSecurityError(record.legalHold ? "LEGAL_HOLD_ACTIVE" : "ILLEGAL_STATE_TRANSITION", "Evidence is not eligible for deletion.", 409);
  if (input.now.getTime() < Date.parse(record.retainUntil)) throw new TenantSecurityError("RETENTION_VIOLATION", "Evidence retention has not elapsed.", 409);
  if (exactObjectKey(input.objectKey) !== record.objectKey || assertVersionId(input.versionId) !== record.versionId) throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Evidence version not found.", 404);
  return Object.freeze({ ...record, status: "deletion_pending", revision: record.revision + 1, deletionRequestedAt: canonicalInstant(input.now), deleteRequestId: retentionToken(input.requestId, "Delete request id") });
}

export function confirmExactVersionDeleted(record: EvidenceRetention, input: { expectedRevision: number; now: Date; objectKey: string; versionId: string; requestId: string; exactVersionAbsent: boolean }): EvidenceRetention {
  assertRevision(record.revision, input.expectedRevision);
  if (record.status !== "deletion_pending" || record.legalHold) throw new TenantSecurityError(record.legalHold ? "LEGAL_HOLD_ACTIVE" : "ILLEGAL_STATE_TRANSITION", "Deletion is not pending.", 409);
  if (exactObjectKey(input.objectKey) !== record.objectKey || assertVersionId(input.versionId) !== record.versionId || input.requestId !== record.deleteRequestId || input.exactVersionAbsent !== true) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Exact object-version deletion was not verified.", 409);
  }
  if (!record.deletionRequestedAt || input.now.getTime() < Date.parse(record.deletionRequestedAt)) throw new TenantSecurityError("RETENTION_VIOLATION", "Deletion confirmation timestamp is invalid.", 409);
  return Object.freeze({ ...record, status: "deleted", revision: record.revision + 1, deletedAt: canonicalInstant(input.now) });
}

function retentionToken(value: string, label: string): string {
  const token = assertBoundedText(value, label, 3, 160);
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(token)) throw new TenantSecurityError("RETENTION_VIOLATION", `${label} is invalid.`);
  return token;
}
