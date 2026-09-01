import {
  asJobId,
  asResourceId,
  asTenantId,
  asUserId,
  assertBoundedText,
  assertRevision,
  canonicalInstant,
  type JobId,
  type ResourceId,
  type TenantId,
  TenantSecurityError,
  type UserId,
} from "./contracts.ts";
import { assertActorPermission, type TenantActor } from "./tenancy.ts";

export type TenantJobStatus = "queued" | "leased" | "retry_scheduled" | "succeeded" | "dead_lettered" | "cancelled";
export type TenantJobKind = "collection.run" | "sbom.generate" | "export.build" | "evidence.validate" | "retention.evaluate" | "audit.checkpoint";

const tenantJobKinds = new Set<TenantJobKind>([
  "collection.run", "sbom.generate", "export.build", "evidence.validate", "retention.evaluate", "audit.checkpoint",
]);

export interface TenantJob {
  readonly schemaVersion: 1;
  readonly id: JobId;
  readonly tenantId: TenantId;
  readonly kind: TenantJobKind;
  readonly idempotencyKey: string;
  readonly resourceId: ResourceId;
  readonly requestedBy: UserId | "system";
  readonly status: TenantJobStatus;
  readonly attempt: number;
  readonly maxAttempts: number;
  readonly availableAt: string;
  readonly createdAt: string;
  readonly revision: number;
  readonly leaseId?: string;
  readonly leasedBy?: string;
  readonly leasedAt?: string;
  readonly leaseExpiresAt?: string;
  readonly completedAt?: string;
  readonly errorCode?: string;
  readonly deadLetteredAt?: string;
}

export interface TenantJobEnvelope {
  readonly schemaVersion: 1;
  readonly tenantId: TenantId;
  readonly jobId: JobId;
  readonly kind: TenantJobKind;
  readonly idempotencyKey: string;
  readonly resourceId: ResourceId;
}

export function queueTenantJob(input: {
  id: string;
  tenantId: string;
  kind: TenantJobKind;
  idempotencyKey: string;
  resourceId: ResourceId;
  requestedBy: UserId | "system";
  now: Date;
  maxAttempts?: number;
}): TenantJob {
  const maxAttempts = input.maxAttempts ?? 3;
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10) throw new TenantSecurityError("INVALID_JOB", "Job retry policy is invalid.");
  const now = canonicalInstant(input.now);
  const requestedBy = input.requestedBy === "system" ? "system" : asUserId(input.requestedBy);
  return Object.freeze({
    schemaVersion: 1,
    id: asJobId(input.id),
    tenantId: asTenantId(input.tenantId),
    kind: jobKind(input.kind),
    idempotencyKey: jobToken(input.idempotencyKey, "Idempotency key"),
    resourceId: asResourceId(input.resourceId),
    requestedBy,
    status: "queued",
    attempt: 0,
    maxAttempts,
    availableAt: now,
    createdAt: now,
    revision: 0,
  });
}

export function jobEnvelope(job: TenantJob): TenantJobEnvelope {
  return Object.freeze({ schemaVersion: 1, tenantId: job.tenantId, jobId: job.id, kind: job.kind, idempotencyKey: job.idempotencyKey, resourceId: job.resourceId });
}

export function assertJobEnvelope(job: TenantJob, envelope: TenantJobEnvelope): void {
  if (job.tenantId !== envelope.tenantId || job.id !== envelope.jobId || job.kind !== envelope.kind || job.idempotencyKey !== envelope.idempotencyKey || job.resourceId !== envelope.resourceId) {
    throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Job not found.", 404);
  }
}

export function leaseTenantJob(job: TenantJob, input: { expectedRevision: number; workerId: string; leaseId: string; now: Date; leaseDurationMs: number }): TenantJob {
  assertRevision(job.revision, input.expectedRevision);
  const current = input.now.getTime();
  const expiredLease = job.status === "leased" && Boolean(job.leaseExpiresAt) && Date.parse(job.leaseExpiresAt!) <= current;
  const available = ['queued', 'retry_scheduled'].includes(job.status) && Date.parse(job.availableAt) <= current;
  if (!available && !expiredLease) throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "Job is not available for lease.", 409);
  if (!Number.isSafeInteger(input.leaseDurationMs) || input.leaseDurationMs < 1_000 || input.leaseDurationMs > 15 * 60_000) throw new TenantSecurityError("INVALID_JOB", "Job lease duration is invalid.");
  const attempt = job.attempt + 1;
  if (attempt > job.maxAttempts) return deadLetter(job, input.expectedRevision, input.now, "ATTEMPTS_EXHAUSTED");
  const workerId = jobToken(input.workerId, "Worker id");
  return Object.freeze({
    ...job,
    status: "leased",
    attempt,
    revision: job.revision + 1,
    leaseId: jobToken(input.leaseId, "Lease id"),
    leasedBy: workerId,
    leasedAt: canonicalInstant(input.now),
    leaseExpiresAt: new Date(current + input.leaseDurationMs).toISOString(),
    errorCode: undefined,
    deadLetteredAt: undefined,
    completedAt: undefined,
    availableAt: canonicalInstant(input.now),
  });
}

export function completeTenantJob(job: TenantJob, input: { expectedRevision: number; leaseId: string; workerId: string; now: Date }): TenantJob {
  assertActiveLease(job, input.expectedRevision, input.leaseId, input.workerId, input.now);
  return Object.freeze({ ...job, status: "succeeded", revision: job.revision + 1, completedAt: canonicalInstant(input.now), leaseId: undefined, leasedBy: undefined, leasedAt: undefined, leaseExpiresAt: undefined, errorCode: undefined });
}

export function failTenantJob(job: TenantJob, input: { expectedRevision: number; leaseId: string; workerId: string; now: Date; retryable: boolean; errorCode: string }): TenantJob {
  assertActiveLease(job, input.expectedRevision, input.leaseId, input.workerId, input.now);
  const errorCode = jobToken(input.errorCode, "Job error code").toUpperCase();
  if (!input.retryable || job.attempt >= job.maxAttempts) return deadLetter(job, input.expectedRevision, input.now, errorCode, input.leaseId);
  const delay = Math.min(60 * 60_000, 2 ** job.attempt * 60_000);
  return Object.freeze({ ...job, status: "retry_scheduled", revision: job.revision + 1, availableAt: new Date(input.now.getTime() + delay).toISOString(), leaseId: undefined, leasedBy: undefined, leasedAt: undefined, leaseExpiresAt: undefined, errorCode });
}

export function cancelTenantJob(job: TenantJob, input: { expectedRevision: number; actor: TenantActor; now: Date }): TenantJob {
  assertRevision(job.revision, input.expectedRevision);
  assertJobActor(job, input.actor);
  if (!['queued', 'retry_scheduled'].includes(job.status)) throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "Only an unleased pending job can be cancelled.", 409);
  return Object.freeze({ ...job, status: "cancelled", revision: job.revision + 1, completedAt: canonicalInstant(input.now), leaseId: undefined, leasedBy: undefined, leasedAt: undefined, leaseExpiresAt: undefined });
}

export function redriveDeadLetter(job: TenantJob, input: { expectedRevision: number; actor: TenantActor; now: Date; maxAttempts?: number }): TenantJob {
  assertRevision(job.revision, input.expectedRevision);
  assertJobActor(job, input.actor);
  if (job.status !== "dead_lettered") throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "Only a dead-lettered job can be redriven.", 409);
  const maxAttempts = input.maxAttempts ?? job.maxAttempts;
  if (!Number.isSafeInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10) throw new TenantSecurityError("INVALID_JOB", "Job retry policy is invalid.");
  return Object.freeze({ ...job, status: "queued", attempt: 0, maxAttempts, availableAt: canonicalInstant(input.now), revision: job.revision + 1, leaseId: undefined, leasedBy: undefined, leasedAt: undefined, leaseExpiresAt: undefined, completedAt: undefined, deadLetteredAt: undefined, errorCode: undefined });
}

function assertJobActor(job: TenantJob, actor: TenantActor): void {
  if (job.tenantId !== actor.tenantId) throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Job not found.", 404);
  assertActorPermission(actor, "jobs:manage");
}

function deadLetter(job: TenantJob, expectedRevision: number, now: Date, errorCode: string, leaseId?: string): TenantJob {
  assertRevision(job.revision, expectedRevision);
  if (leaseId && job.leaseId !== leaseId) throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "Job lease does not match.", 409);
  return Object.freeze({ ...job, status: "dead_lettered", revision: job.revision + 1, deadLetteredAt: canonicalInstant(now), completedAt: canonicalInstant(now), leaseId: undefined, leasedBy: undefined, leasedAt: undefined, leaseExpiresAt: undefined, errorCode });
}

function assertActiveLease(job: TenantJob, expectedRevision: number, leaseId: string, workerId: string, now: Date): void {
  assertRevision(job.revision, expectedRevision);
  if (job.status !== "leased" || job.leaseId !== jobToken(leaseId, "Lease id") || job.leasedBy !== jobToken(workerId, "Worker id") || !job.leasedAt || !job.leaseExpiresAt || now.getTime() < Date.parse(job.leasedAt) || Date.parse(job.leaseExpiresAt) <= now.getTime()) {
    throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "Active job lease is required.", 409);
  }
}

function jobToken(value: string, label: string): string {
  const token = assertBoundedText(value, label, 2, 100);
  if (!/^[A-Za-z][A-Za-z0-9_.:-]*$/.test(token)) throw new TenantSecurityError("INVALID_JOB", `${label} is invalid.`);
  return token;
}

function jobKind(value: string): TenantJobKind {
  if (!tenantJobKinds.has(value as TenantJobKind)) throw new TenantSecurityError("INVALID_JOB", "Job kind is invalid.");
  return value as TenantJobKind;
}
