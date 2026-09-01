import {
  asResourceId,
  asTenantId,
  assertBoundedText,
  canonicalInstant,
  sha256Hex,
  stableJson,
  type JsonValue,
  TenantSecurityError,
} from "../contracts.ts";
import { assertActorPermission, type TenantActor } from "../tenancy.ts";
import {
  asBucketName,
  asControlId,
  asEvidenceMimeType,
  assertExactObjectVersion,
  buildControlledEvidenceObjectKey,
  exactStringRecordEqual,
} from "./primitives.ts";

export type S3LegalHoldStatus = "ON" | "OFF";
export type LegalHoldKind = "LEGAL" | "AUDIT" | "SECURITY_INCIDENT";
export type LegalHoldOperationState = "REQUESTED" | "APPROVED" | "APPLYING" | "APPLIED" | "EXPIRED";
export const EXACT_VERSION_LEGAL_HOLD_APPROVAL_WINDOW_SECONDS = 86_400;

export interface PutObjectLegalHoldInput {
  readonly Bucket: string;
  readonly Key: string;
  readonly VersionId: string;
  readonly LegalHold: { readonly Status: S3LegalHoldStatus };
}

export interface GetObjectLegalHoldInput {
  readonly Bucket: string;
  readonly Key: string;
  readonly VersionId: string;
}

export interface S3LegalHoldOutput {
  readonly LegalHold?: { readonly Status?: string };
  readonly requestId?: string;
}

/** Deliberately excludes delete and governance-retention bypass capabilities. */
export interface ExactVersionLegalHoldClient {
  putObjectLegalHold(input: PutObjectLegalHoldInput): Promise<S3LegalHoldOutput>;
  getObjectLegalHold(input: GetObjectLegalHoldInput): Promise<S3LegalHoldOutput>;
}

export interface ExactVersionLegalHoldRequest {
  readonly tenantId: string;
  readonly controlId: string;
  readonly evidenceId: string;
  readonly contentType: string;
  readonly bucket: string;
  readonly key: string;
  readonly versionId: string;
  readonly status: S3LegalHoldStatus;
  readonly changedAt: Date;
}

/**
 * Client-controlled legal-hold facts. Actor identifiers are intentionally not
 * accepted here: requestExactVersionLegalHoldChange derives requestedBy from a
 * separately authenticated and authorized TenantActor.
 */
export interface DurableExactVersionLegalHoldRequest extends ExactVersionLegalHoldRequest {
  readonly operationId: string;
  readonly holdId: string;
  readonly reason: string;
  readonly kind?: LegalHoldKind;
  /** Zero for a new ON hold; the current hold revision for OFF. */
  readonly expectedHoldRevision: number;
}

export interface ExactVersionLegalHoldApprovalRequest {
  readonly tenantId: string;
  readonly operationId: string;
  readonly requestDigest: string;
  readonly approvedAt: Date;
}

export interface ExactVersionLegalHoldPolicy {
  readonly evidenceBucket: string;
}

export interface ExactVersionLegalHoldReceipt {
  readonly schemaVersion: 1;
  readonly operationId?: string;
  readonly holdId?: string;
  readonly tenantId: string;
  readonly controlId: string;
  readonly evidenceId: string;
  readonly bucket: string;
  readonly key: string;
  readonly versionId: string;
  readonly status: S3LegalHoldStatus;
  readonly changedAt: string;
  readonly applicationAttemptId?: string;
  readonly priorStatus?: S3LegalHoldStatus;
  readonly putRequestId: string;
  readonly verifyRequestId: string;
}

export interface ExactVersionLegalHoldApplicationAttempt {
  readonly schemaVersion: 1;
  readonly attemptId: string;
  readonly priorStatus: S3LegalHoldStatus;
  readonly observedRequestId: string;
  readonly startedAt: string;
}

/** Immutable request record. Approval facts are deliberately absent. */
export interface ExactVersionLegalHoldOperation {
  readonly schemaVersion: 2;
  readonly operationId: string;
  readonly holdId: string;
  readonly tenantId: string;
  readonly controlId: string;
  readonly evidenceId: string;
  readonly bucket: string;
  readonly key: string;
  readonly versionId: string;
  readonly status: S3LegalHoldStatus;
  readonly kind: LegalHoldKind;
  readonly reason: string;
  readonly requestedBy: string;
  readonly expectedHoldRevision: number;
  readonly changedAt: string;
  readonly canonicalRequest: string;
  readonly requestDigest: string;
}

/** Immutable approval record bound to one exact request digest. */
export interface ExactVersionLegalHoldApproval {
  readonly schemaVersion: 1;
  readonly tenantId: string;
  readonly operationId: string;
  readonly requestDigest: string;
  readonly approvedBy: string;
  readonly approvedAt: string;
  readonly canonicalApproval: string;
  readonly approvalDigest: string;
}

export type ReservedExactVersionLegalHold = Readonly<{
  state: "REQUESTED";
  operationRevision: 0;
}> | Readonly<{
  state: "EXPIRED";
  operationRevision: 1;
}> | Readonly<{
  state: "APPROVED";
  operationRevision: 1;
  approval: ExactVersionLegalHoldApproval;
}> | Readonly<{
  state: "APPLYING";
  operationRevision: 2;
  approval: ExactVersionLegalHoldApproval;
  applicationAttempt: ExactVersionLegalHoldApplicationAttempt;
}> | Readonly<{
  state: "APPLIED";
  operationRevision: 3;
  approval: ExactVersionLegalHoldApproval;
  receipt: ExactVersionLegalHoldReceipt;
}>;

export type ApprovedExactVersionLegalHold = Readonly<{
  state: "APPROVED";
  operationRevision: 1;
  approval: ExactVersionLegalHoldApproval;
}> | Readonly<{
  state: "APPLYING";
  operationRevision: 2;
  approval: ExactVersionLegalHoldApproval;
}> | Readonly<{
  state: "APPLIED";
  operationRevision: 3;
  approval: ExactVersionLegalHoldApproval;
}>;

export interface AppliedExactVersionLegalHold {
  readonly outcome: "applied" | "already_applied";
  readonly operationRevision: number;
  readonly holdRevision: number;
  readonly receipt: ExactVersionLegalHoldReceipt;
}

/**
 * Authenticated API facts that the RDS boundary commits with the legal-hold
 * transition. Keeping these facts separate from the client payload prevents a
 * caller from nominating an audit identity or request identifier.
 */
export interface ExactVersionLegalHoldApiAuditContext {
  readonly membershipId: string;
  readonly requestId: string;
}

/**
 * Every method is a separate committed transaction. request() authenticates the
 * requester, approve() independently authenticates a different approver, and
 * read() prevents a reconciliation worker from creating or approving work.
 */
export interface ExactVersionLegalHoldOperationStore {
  request(
    operation: ExactVersionLegalHoldOperation,
    apiAudit?: ExactVersionLegalHoldApiAuditContext,
  ): Promise<ReservedExactVersionLegalHold>;
  approve(
    approval: ExactVersionLegalHoldApproval,
    apiAudit?: ExactVersionLegalHoldApiAuditContext,
  ): Promise<ApprovedExactVersionLegalHold>;
  read(operation: ExactVersionLegalHoldOperation): Promise<ReservedExactVersionLegalHold>;
  beginApply(
    operation: ExactVersionLegalHoldOperation,
    approval: ExactVersionLegalHoldApproval,
    expectedOperationRevision: 1,
    applicationAttempt: ExactVersionLegalHoldApplicationAttempt,
  ): Promise<Extract<ReservedExactVersionLegalHold, { state: "APPLYING" }>>;
  apply(
    operation: ExactVersionLegalHoldOperation,
    approval: ExactVersionLegalHoldApproval,
    expectedOperationRevision: 2,
    receipt: ExactVersionLegalHoldReceipt,
  ): Promise<AppliedExactVersionLegalHold>;
}

export interface RequestedExactVersionLegalHold {
  readonly operation: ExactVersionLegalHoldOperation;
  readonly reservation: ReservedExactVersionLegalHold;
}

/** Low-level exact-VersionId S3 primitive. Prefer the durable reconciler. */
export async function setExactVersionLegalHold(
  client: ExactVersionLegalHoldClient,
  request: ExactVersionLegalHoldRequest,
  policy: ExactVersionLegalHoldPolicy,
): Promise<ExactVersionLegalHoldReceipt> {
  const target = normalizeTarget(request, policy);
  return await setNormalizedExactVersionLegalHold(client, target);
}

/**
 * Phase one. The requester is taken only from an already authenticated tenant
 * actor. No approver identifier is accepted and no S3 call can occur here.
 */
export async function requestExactVersionLegalHoldChange(
  store: ExactVersionLegalHoldOperationStore,
  request: DurableExactVersionLegalHoldRequest,
  requester: Pick<TenantActor, "tenantId" | "userId" | "role">,
  policy: ExactVersionLegalHoldPolicy,
  apiAudit?: ExactVersionLegalHoldApiAuditContext,
): Promise<RequestedExactVersionLegalHold> {
  const operation = await prepareExactVersionLegalHoldOperation(request, requester, policy);
  const reservation = await store.request(operation, apiAudit);
  assertReservationState(reservation, operation);
  return Object.freeze({ operation, reservation });
}

/**
 * Phase two. Call this only from a distinct authenticated HTTP request. The
 * approver identity is derived from its TenantActor and is bound to the exact
 * request digest before the database performs its independent membership check.
 */
export async function approveExactVersionLegalHoldChange(
  store: ExactVersionLegalHoldOperationStore,
  request: ExactVersionLegalHoldApprovalRequest,
  approver: Pick<TenantActor, "tenantId" | "userId" | "role">,
  apiAudit?: ExactVersionLegalHoldApiAuditContext,
): Promise<ApprovedExactVersionLegalHold> {
  const approval = await prepareExactVersionLegalHoldApproval(request, approver);
  const approved = await store.approve(approval, apiAudit);
  assertApprovalMatchesRequest(approved.approval, approval.operationId, approval.requestDigest);
  if (approved.approval.canonicalApproval !== approval.canonicalApproval ||
      approved.approval.approvalDigest !== approval.approvalDigest ||
      approved.operationRevision < 1) {
    throw new TenantSecurityError("CONCURRENT_MODIFICATION", "Legal-hold approval conflicts with the committed approval.", 409);
  }
  return Object.freeze(approved);
}

/**
 * Worker-only application phase. It can read only an existing request; it
 * cannot create a request or nominate an approver. S3 is called only after the
 * store proves an independently committed APPROVED state.
 */
export async function reconcileExactVersionLegalHold(
  client: ExactVersionLegalHoldClient,
  store: ExactVersionLegalHoldOperationStore,
  operation: ExactVersionLegalHoldOperation,
  policy: ExactVersionLegalHoldPolicy,
): Promise<AppliedExactVersionLegalHold> {
  await assertPreparedOperation(operation, policy);
  const reservation = await store.read(operation);
  assertReservationState(reservation, operation);
  if (reservation.state === "REQUESTED") {
    throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "A second active administrator must approve this legal-hold request.", 409);
  }
  if (reservation.state === "EXPIRED") {
    throw new TenantSecurityError("ILLEGAL_STATE_TRANSITION", "The legal-hold request expired before independent approval.", 409);
  }
  await assertPreparedApproval(reservation.approval, operation);
  if (reservation.state === "APPLIED") {
    assertReceiptMatchesOperation(reservation.receipt, operation);
    const verification = await client.getObjectLegalHold({
      Bucket: operation.bucket,
      Key: operation.key,
      VersionId: operation.versionId,
    });
    requireProviderRequestId(verification.requestId, "S3 legal-hold drift check");
    if (verification.LegalHold?.Status !== operation.status) {
      throw new TenantSecurityError(
        "RETENTION_VIOLATION",
        "Stored legal-hold state no longer matches the exact S3 object version.",
        409,
      );
    }
    return Object.freeze({
      outcome: "already_applied",
      operationRevision: reservation.operationRevision,
      holdRevision: operation.status === "ON" ? 0 : operation.expectedHoldRevision + 1,
      receipt: reservation.receipt,
    });
  }

  let applying = reservation.state === "APPLYING" ? reservation : undefined;
  if (!applying) {
    const observed = await client.getObjectLegalHold({
      Bucket: operation.bucket,
      Key: operation.key,
      VersionId: operation.versionId,
    });
    const observedRequestId = requireProviderRequestId(observed.requestId, "S3 legal-hold precondition check");
    const priorStatus = observed.LegalHold?.Status;
    const expectedPriorStatus: S3LegalHoldStatus = operation.status === "ON" ? "OFF" : "ON";
    if (priorStatus !== expectedPriorStatus) {
      throw new TenantSecurityError(
        "LEGAL_HOLD_PRECONDITION_DRIFT",
        "The exact S3 version changed outside the approved legal-hold workflow.",
        409,
      );
    }
    const startedAt = new Date().toISOString();
    const attemptId = await sha256Hex(
      `scopeproof-legal-hold-apply-attempt-v1\u001f${operation.operationId}\u001f${operation.requestDigest}\u001f${reservation.approval.approvalDigest}\u001f${priorStatus}\u001f${operation.status}`,
    );
    applying = await store.beginApply(operation, reservation.approval, 1, Object.freeze({
      schemaVersion: 1,
      attemptId,
      priorStatus,
      observedRequestId,
      startedAt,
    }));
  }

  const current = await client.getObjectLegalHold({
    Bucket: operation.bucket,
    Key: operation.key,
    VersionId: operation.versionId,
  });
  requireProviderRequestId(current.requestId, "S3 legal-hold applying-state check");
  let putRequestId: string | undefined;
  if (current.LegalHold?.Status === applying.applicationAttempt.priorStatus) {
    try {
      const put = await client.putObjectLegalHold({
        Bucket: operation.bucket,
        Key: operation.key,
        VersionId: operation.versionId,
        LegalHold: { Status: operation.status },
      });
      putRequestId = requireProviderRequestId(put.requestId, "S3 legal-hold write");
    } catch (error) {
      // A lost provider response is resolved below by an exact-VersionId read.
      const recovered = await client.getObjectLegalHold({ Bucket: operation.bucket, Key: operation.key, VersionId: operation.versionId });
      requireProviderRequestId(recovered.requestId, "S3 legal-hold ambiguous-write verification");
      if (recovered.LegalHold?.Status !== operation.status) throw error;
      // Repeat the idempotent exact-version Put while APPLYING is durable so
      // the final receipt always contains a provider write request identity.
      const retryPut = await client.putObjectLegalHold({ Bucket: operation.bucket, Key: operation.key, VersionId: operation.versionId, LegalHold: { Status: operation.status } });
      putRequestId = requireProviderRequestId(retryPut.requestId, "S3 legal-hold ambiguous-write retry");
    }
  } else if (current.LegalHold?.Status === operation.status) {
    const retryPut = await client.putObjectLegalHold({ Bucket: operation.bucket, Key: operation.key, VersionId: operation.versionId, LegalHold: { Status: operation.status } });
    putRequestId = requireProviderRequestId(retryPut.requestId, "S3 legal-hold applying-state retry");
  } else {
    throw new TenantSecurityError("LEGAL_HOLD_PRECONDITION_DRIFT", "The exact S3 version no longer matches the durable application precondition.", 409);
  }
  const verification = await client.getObjectLegalHold({ Bucket: operation.bucket, Key: operation.key, VersionId: operation.versionId });
  const verifyRequestId = requireProviderRequestId(verification.requestId, "S3 legal-hold verification");
  if (verification.LegalHold?.Status !== operation.status) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "S3 did not confirm legal hold state on the exact object version.", 409);
  }
  const s3Receipt: ExactVersionLegalHoldReceipt = Object.freeze({
    schemaVersion: 1,
    tenantId: operation.tenantId, controlId: operation.controlId, evidenceId: operation.evidenceId,
    bucket: operation.bucket, key: operation.key, versionId: operation.versionId, status: operation.status,
    changedAt: operation.changedAt, applicationAttemptId: applying.applicationAttempt.attemptId,
    priorStatus: applying.applicationAttempt.priorStatus, putRequestId: putRequestId!, verifyRequestId,
  });
  const receipt: ExactVersionLegalHoldReceipt = Object.freeze({
    ...s3Receipt,
    operationId: operation.operationId,
    holdId: operation.holdId,
  });
  assertReceiptMatchesOperation(receipt, operation);
  let applied: AppliedExactVersionLegalHold;
  try {
    applied = await store.apply(operation, applying.approval, 2, receipt);
  } catch (error) {
    // A Data API/COMMIT response can be lost after the database made APPLIED
    // durable. Read back the exact digest-bound operation before reporting a
    // failure or scheduling retry; never repeat S3 solely because the response
    // to the commit was ambiguous.
    let recovered: ReservedExactVersionLegalHold;
    try {
      recovered = await store.read(operation);
    } catch {
      throw error;
    }
    assertReservationState(recovered, operation);
    if (recovered.state !== "APPLIED") throw error;
    return Object.freeze({
      outcome: "already_applied",
      operationRevision: recovered.operationRevision,
      holdRevision: operation.status === "ON" ? 0 : operation.expectedHoldRevision + 1,
      receipt: recovered.receipt,
    });
  }
  assertReceiptMatchesOperation(applied.receipt, operation);
  if (!Number.isSafeInteger(applied.operationRevision) || applied.operationRevision < 3 ||
      !Number.isSafeInteger(applied.holdRevision) || applied.holdRevision < 0) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold reconciliation result is invalid.", 500);
  }
  return Object.freeze(applied);
}

export async function prepareExactVersionLegalHoldOperation(
  request: DurableExactVersionLegalHoldRequest,
  requester: Pick<TenantActor, "tenantId" | "userId" | "role">,
  policy: ExactVersionLegalHoldPolicy,
): Promise<ExactVersionLegalHoldOperation> {
  const target = normalizeTarget(request, policy);
  const requestedBy = assertAuthenticatedLegalHoldActor(requester, target.tenantId);
  const operationId = asResourceId(request.operationId, ["lho"]);
  const holdId = asResourceId(request.holdId, ["hld"]);
  const kind = request.kind ?? "LEGAL";
  if (kind !== "LEGAL" && kind !== "AUDIT" && kind !== "SECURITY_INCIDENT") {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Retention hold kind is invalid.");
  }
  const reason = assertBoundedText(request.reason, "Retention hold reason", 10, 2_000);
  if (!Number.isSafeInteger(request.expectedHoldRevision) || request.expectedHoldRevision < 0 ||
      (target.status === "ON" && request.expectedHoldRevision !== 0)) {
    throw new TenantSecurityError("CONCURRENT_MODIFICATION", "Retention hold revision is invalid.", 409);
  }
  const facts = Object.freeze({
    schemaVersion: 2 as const,
    operationId,
    holdId,
    tenantId: target.tenantId,
    controlId: target.controlId,
    evidenceId: target.evidenceId,
    bucket: target.bucket,
    key: target.key,
    versionId: target.versionId,
    status: target.status,
    kind,
    reason,
    requestedBy,
    expectedHoldRevision: request.expectedHoldRevision,
    changedAt: target.changedAt,
  });
  const canonicalRequest = stableJson(facts as unknown as JsonValue);
  const requestDigest = await sha256Hex(`scopeproof-legal-hold-request-v2\n${canonicalRequest}`);
  return Object.freeze({ ...facts, canonicalRequest, requestDigest });
}

export async function prepareExactVersionLegalHoldApproval(
  request: ExactVersionLegalHoldApprovalRequest,
  approver: Pick<TenantActor, "tenantId" | "userId" | "role">,
): Promise<ExactVersionLegalHoldApproval> {
  const tenantId = asTenantId(request.tenantId);
  const approvedBy = assertAuthenticatedLegalHoldActor(approver, tenantId);
  const operationId = asResourceId(request.operationId, ["lho"]);
  const requestDigest = requireSha256(request.requestDigest, "Legal-hold request digest");
  const approvedAt = canonicalInstant(request.approvedAt, "Legal-hold approval time");
  const facts = Object.freeze({
    schemaVersion: 1 as const,
    tenantId,
    operationId,
    requestDigest,
    approvedBy,
    approvedAt,
  });
  const canonicalApproval = stableJson(facts as unknown as JsonValue);
  const approvalDigest = await sha256Hex(`scopeproof-legal-hold-approval-v1\n${canonicalApproval}`);
  return Object.freeze({ ...facts, canonicalApproval, approvalDigest });
}

export async function assertPreparedOperation(
  operation: ExactVersionLegalHoldOperation,
  policy: ExactVersionLegalHoldPolicy,
): Promise<void> {
  const tenantId = asTenantId(operation.tenantId);
  const operationId = asResourceId(operation.operationId, ["lho"]);
  const holdId = asResourceId(operation.holdId, ["hld"]);
  const evidenceId = asResourceId(operation.evidenceId, ["evd"]);
  const requestedBy = asResourceId(operation.requestedBy, ["usr"]);
  const controlId = asControlId(operation.controlId);
  const bucket = asBucketName(operation.bucket);
  if (bucket !== asBucketName(policy.evidenceBucket)) {
    throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Evidence version was not found.", 404);
  }
  const expectedPrefix = `tenants/${tenantId}/controls/${controlId}/evidence/${evidenceId}.`;
  if (!operation.key.startsWith(expectedPrefix) ||
      !/\.(?:png|json|spdx\.json|cdx\.json|txt|csv)$/.test(operation.key)) {
    throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Evidence version was not found.", 404);
  }
  const versionId = assertExactObjectVersion(operation.versionId);
  if (operation.status !== "ON" && operation.status !== "OFF") {
    throw new TenantSecurityError("RETENTION_VIOLATION", "S3 legal hold status is invalid.");
  }
  if (operation.kind !== "LEGAL" && operation.kind !== "AUDIT" && operation.kind !== "SECURITY_INCIDENT") {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Retention hold kind is invalid.");
  }
  const reason = assertBoundedText(operation.reason, "Retention hold reason", 10, 2_000);
  if (!Number.isSafeInteger(operation.expectedHoldRevision) || operation.expectedHoldRevision < 0 ||
      (operation.status === "ON" && operation.expectedHoldRevision !== 0)) {
    throw new TenantSecurityError("CONCURRENT_MODIFICATION", "Retention hold revision is invalid.", 409);
  }
  const changedAt = canonicalInstant(operation.changedAt, "Legal hold change time");
  const expectedFacts = Object.freeze({
    schemaVersion: 2 as const,
    operationId,
    holdId,
    tenantId,
    controlId,
    evidenceId,
    bucket,
    key: operation.key,
    versionId,
    status: operation.status,
    kind: operation.kind,
    reason,
    requestedBy,
    expectedHoldRevision: operation.expectedHoldRevision,
    changedAt,
  });
  const canonicalRequest = stableJson(expectedFacts as unknown as JsonValue);
  const requestDigest = await sha256Hex(`scopeproof-legal-hold-request-v2\n${canonicalRequest}`);
  if (operation.schemaVersion !== 2 || operation.canonicalRequest !== canonicalRequest || operation.requestDigest !== requestDigest) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold request integrity check failed.", 409);
  }
}

export function assertApprovalMatchesRequest(
  approval: ExactVersionLegalHoldApproval,
  operationId: string,
  requestDigest: string,
): void {
  if (approval.schemaVersion !== 1 || approval.operationId !== operationId || approval.requestDigest !== requestDigest ||
      !/^[0-9a-f]{64}$/.test(approval.approvalDigest) || !/^[0-9a-f]{64}$/.test(approval.requestDigest)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold approval conflicts with the requested operation.", 409);
  }
  asTenantId(approval.tenantId);
  asResourceId(approval.approvedBy, ["usr"]);
  canonicalInstant(approval.approvedAt, "Legal-hold approval time");
}

export async function assertPreparedApproval(
  approval: ExactVersionLegalHoldApproval,
  operation: ExactVersionLegalHoldOperation,
): Promise<void> {
  assertApprovalMatchesRequest(approval, operation.operationId, operation.requestDigest);
  const tenantId = asTenantId(approval.tenantId);
  const approvedBy = asResourceId(approval.approvedBy, ["usr"]);
  const approvedAt = canonicalInstant(approval.approvedAt, "Legal-hold approval time");
  if (tenantId !== operation.tenantId || approvedBy === operation.requestedBy) {
    throw new TenantSecurityError("ROLE_FORBIDDEN", "A distinct administrator must approve this exact legal-hold request.", 403);
  }
  const expectedFacts = Object.freeze({
    schemaVersion: 1 as const,
    tenantId,
    operationId: operation.operationId,
    requestDigest: operation.requestDigest,
    approvedBy,
    approvedAt,
  });
  const canonicalApproval = stableJson(expectedFacts as unknown as JsonValue);
  const approvalDigest = await sha256Hex(`scopeproof-legal-hold-approval-v1\n${canonicalApproval}`);
  if (approval.canonicalApproval !== canonicalApproval || approval.approvalDigest !== approvalDigest) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold approval integrity check failed.", 409);
  }
}

export function assertReceiptMatchesOperation(
  receipt: ExactVersionLegalHoldReceipt,
  operation: ExactVersionLegalHoldOperation,
): void {
  if (receipt.schemaVersion !== 1 || receipt.operationId !== operation.operationId || receipt.holdId !== operation.holdId ||
      !exactStringRecordEqual(
        {
          tenantId: receipt.tenantId,
          controlId: receipt.controlId,
          evidenceId: receipt.evidenceId,
          bucket: receipt.bucket,
          key: receipt.key,
          versionId: receipt.versionId,
          status: receipt.status,
          changedAt: receipt.changedAt,
        },
        {
          tenantId: operation.tenantId,
          controlId: operation.controlId,
          evidenceId: operation.evidenceId,
          bucket: operation.bucket,
          key: operation.key,
          versionId: operation.versionId,
          status: operation.status,
          changedAt: operation.changedAt,
        },
      )) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold receipt conflicts with the requested operation.", 409);
  }
  requireProviderRequestId(receipt.putRequestId, "Stored S3 legal-hold write");
  requireProviderRequestId(receipt.verifyRequestId, "Stored S3 legal-hold verification");
}

export interface PendingExactVersionLegalHoldSweepItem {
  readonly operation: ExactVersionLegalHoldOperation;
  readonly state: "REQUESTED" | "APPROVED" | "APPLYING";
  readonly stateChangedAt: string;
}

export interface PendingExactVersionLegalHoldSource {
  /** Atomically expires at most limit REQUESTED records whose 24-hour approval window elapsed. */
  expireStaleRequests(input: Readonly<{
    tenantId: string;
    now: string;
    limit: number;
  }>): Promise<readonly ExpiredExactVersionLegalHoldSweepItem[]>;
  /** Must return at most limit records and never scan outside the supplied tenant. */
  listPending(input: Readonly<{
    tenantId: string;
    stateChangedBefore: string;
    limit: number;
  }>): Promise<readonly PendingExactVersionLegalHoldSweepItem[]>;
  /** Records a bounded worker retry without changing immutable request/approval facts. */
  recordReconciliationFailure(input: Readonly<{
    tenantId: string;
    operationId: string;
    requestDigest: string;
    errorCode: string;
    failedAt: string;
  }>): Promise<LegalHoldReconciliationRetry>;
}

export interface ExpiredExactVersionLegalHoldSweepItem {
  readonly operation: ExactVersionLegalHoldOperation;
  readonly expiredAt: string;
}

export interface LegalHoldReconciliationRetry {
  readonly attemptCount: number;
  readonly nextAttemptAt: string;
}

export interface PendingLegalHoldAgeObservation {
  readonly tenantId: string;
  readonly operationId: string;
  readonly state: "REQUESTED" | "APPROVED" | "APPLYING" | "EXPIRED";
  readonly ageSeconds: number;
}

export interface ExactVersionLegalHoldSweepResult {
  readonly observed: number;
  readonly expired: number;
  readonly attempted: number;
  readonly applied: number;
  readonly alreadyApplied: number;
  readonly failedOperationIds: readonly string[];
}

/**
 * Bounded reconciliation/age-alarm hook for stale durable work. REQUESTED rows
 * are observed but never auto-approved; only already-APPROVED rows reach S3.
 */
export async function sweepPendingExactVersionLegalHolds(input: Readonly<{
  tenantId: string;
  client: ExactVersionLegalHoldClient;
  store: ExactVersionLegalHoldOperationStore;
  source: PendingExactVersionLegalHoldSource;
  policy: ExactVersionLegalHoldPolicy;
  minimumAgeSeconds: number;
  limit?: number;
  now?: Date;
  observeAge?: (observation: PendingLegalHoldAgeObservation) => void | Promise<void>;
}>): Promise<ExactVersionLegalHoldSweepResult> {
  const tenantId = asTenantId(input.tenantId);
  const limit = input.limit ?? 25;
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100 ||
      !Number.isSafeInteger(input.minimumAgeSeconds) || input.minimumAgeSeconds < 60 || input.minimumAgeSeconds > 2_592_000) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold sweep bounds are invalid.", 500);
  }
  const now = input.now ?? new Date();
  const nowMillis = Date.parse(canonicalInstant(now, "Legal-hold sweep time"));
  const stateChangedBefore = new Date(nowMillis - input.minimumAgeSeconds * 1_000).toISOString();
  const expiredItems = await input.source.expireStaleRequests({
    tenantId,
    now: new Date(nowMillis).toISOString(),
    limit,
  });
  if (!Array.isArray(expiredItems) || expiredItems.length > limit) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold expiry source exceeded its bounded result contract.", 500);
  }
  const seen = new Set<string>();
  for (const item of expiredItems) {
    await assertPreparedOperation(item.operation, input.policy);
    if (item.operation.tenantId !== tenantId || seen.has(item.operation.operationId)) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold expiry source returned invalid work.", 500);
    }
    seen.add(item.operation.operationId);
    const changedMillis = Date.parse(item.operation.changedAt);
    const expiredMillis = Date.parse(canonicalInstant(item.expiredAt, "Legal-hold expiry time"));
    if (expiredMillis < changedMillis + EXACT_VERSION_LEGAL_HOLD_APPROVAL_WINDOW_SECONDS * 1_000 ||
        expiredMillis > nowMillis + 5 * 60_000) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold expiry source returned an invalid terminal transition.", 500);
    }
    await input.observeAge?.({
      tenantId,
      operationId: item.operation.operationId,
      state: "EXPIRED",
      ageSeconds: Math.floor((expiredMillis - changedMillis) / 1_000),
    });
  }
  const items = await input.source.listPending({ tenantId, stateChangedBefore, limit });
  if (!Array.isArray(items) || items.length > limit) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold sweep source exceeded its bounded result contract.", 500);
  }
  let attempted = 0;
  let applied = 0;
  let alreadyApplied = 0;
  const failedOperationIds: string[] = [];
  for (const item of items) {
    await assertPreparedOperation(item.operation, input.policy);
    if (item.operation.tenantId !== tenantId || (item.state !== "REQUESTED" && item.state !== "APPROVED" && item.state !== "APPLYING") ||
        seen.has(item.operation.operationId)) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold sweep source returned invalid work.", 500);
    }
    seen.add(item.operation.operationId);
    const changedMillis = Date.parse(canonicalInstant(item.stateChangedAt, "Legal-hold state change time"));
    const ageSeconds = Math.floor((nowMillis - changedMillis) / 1_000);
    if (changedMillis > Date.parse(stateChangedBefore) || ageSeconds < input.minimumAgeSeconds) {
      throw new TenantSecurityError("RETENTION_VIOLATION", "Legal-hold sweep source returned work newer than the requested cutoff.", 500);
    }
    await input.observeAge?.({ tenantId, operationId: item.operation.operationId, state: item.state, ageSeconds });
    if (item.state === "REQUESTED") continue;
    attempted += 1;
    try {
      const result = await reconcileExactVersionLegalHold(input.client, input.store, item.operation, input.policy);
      if (result.outcome === "applied") applied += 1;
      else alreadyApplied += 1;
    } catch (error) {
      await input.source.recordReconciliationFailure({
        tenantId,
        operationId: item.operation.operationId,
        requestDigest: item.operation.requestDigest,
        errorCode: reconciliationFailureCode(error),
        failedAt: new Date().toISOString(),
      });
      failedOperationIds.push(item.operation.operationId);
    }
  }
  return Object.freeze({
    observed: expiredItems.length + items.length,
    expired: expiredItems.length,
    attempted,
    applied,
    alreadyApplied,
    failedOperationIds: Object.freeze(failedOperationIds),
  });
}

function reconciliationFailureCode(error: unknown): string {
  if (error instanceof TenantSecurityError && /^[A-Z][A-Z0-9_]{2,63}$/.test(error.code)) {
    return error.code;
  }
  return "RECONCILIATION_FAILED";
}

function assertAuthenticatedLegalHoldActor(
  actor: Pick<TenantActor, "tenantId" | "userId" | "role">,
  expectedTenantId: string,
): string {
  const tenantId = asTenantId(actor.tenantId);
  if (tenantId !== expectedTenantId) {
    throw new TenantSecurityError("ROLE_FORBIDDEN", "The authenticated actor does not belong to this tenant.", 403);
  }
  assertActorPermission(actor, "retention:manage");
  return asResourceId(actor.userId, ["usr"]);
}

function assertReservationState(
  reservation: ReservedExactVersionLegalHold,
  operation: ExactVersionLegalHoldOperation,
): void {
  if ((reservation.state === "REQUESTED" && reservation.operationRevision !== 0) ||
      (reservation.state === "EXPIRED" && reservation.operationRevision !== 1) ||
      (reservation.state === "APPROVED" && reservation.operationRevision !== 1) ||
      (reservation.state === "APPLYING" && reservation.operationRevision !== 2) ||
      (reservation.state === "APPLIED" && reservation.operationRevision !== 3)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Stored legal-hold operation revision is invalid.", 500);
  }
  if (reservation.state === "APPROVED" || reservation.state === "APPLYING" || reservation.state === "APPLIED") {
    assertApprovalMatchesRequest(reservation.approval, operation.operationId, operation.requestDigest);
  }
  if (reservation.state === "APPLIED") assertReceiptMatchesOperation(reservation.receipt, operation);
}

async function setNormalizedExactVersionLegalHold(
  client: ExactVersionLegalHoldClient,
  target: Readonly<{
    tenantId: string;
    controlId: string;
    evidenceId: string;
    bucket: string;
    key: string;
    versionId: string;
    status: S3LegalHoldStatus;
    changedAt: string;
  }>,
): Promise<ExactVersionLegalHoldReceipt> {
  const putResponse = await client.putObjectLegalHold(Object.freeze({
    Bucket: target.bucket,
    Key: target.key,
    VersionId: target.versionId,
    LegalHold: Object.freeze({ Status: target.status }),
  }));
  const putRequestId = requireProviderRequestId(putResponse.requestId, "S3 legal-hold write");
  const verification = await client.getObjectLegalHold(Object.freeze({
    Bucket: target.bucket,
    Key: target.key,
    VersionId: target.versionId,
  }));
  const verifyRequestId = requireProviderRequestId(verification.requestId, "S3 legal-hold verification");
  if (verification.LegalHold?.Status !== target.status) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "S3 did not confirm legal hold state on the exact object version.", 409);
  }
  return Object.freeze({
    schemaVersion: 1,
    tenantId: target.tenantId,
    controlId: target.controlId,
    evidenceId: target.evidenceId,
    bucket: target.bucket,
    key: target.key,
    versionId: target.versionId,
    status: target.status,
    changedAt: target.changedAt,
    putRequestId,
    verifyRequestId,
  });
}

function normalizeTarget(request: ExactVersionLegalHoldRequest, policy: ExactVersionLegalHoldPolicy): {
  tenantId: string;
  controlId: string;
  evidenceId: string;
  bucket: string;
  key: string;
  versionId: string;
  status: S3LegalHoldStatus;
  changedAt: string;
} {
  const tenantId = asTenantId(request.tenantId);
  const controlId = asControlId(request.controlId);
  const evidenceId = asResourceId(request.evidenceId, ["evd"]);
  const contentType = asEvidenceMimeType(request.contentType);
  const key = buildControlledEvidenceObjectKey({ tenantId, controlId, evidenceId, contentType }).evidenceKey;
  if (request.key !== key) {
    throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Evidence version was not found.", 404);
  }
  if (request.status !== "ON" && request.status !== "OFF") {
    throw new TenantSecurityError("RETENTION_VIOLATION", "S3 legal hold status is invalid.");
  }
  const bucket = asBucketName(request.bucket);
  if (bucket !== asBucketName(policy.evidenceBucket)) {
    throw new TenantSecurityError("RESOURCE_NOT_FOUND", "Evidence version was not found.", 404);
  }
  return Object.freeze({
    tenantId,
    controlId,
    evidenceId,
    bucket,
    key,
    versionId: assertExactObjectVersion(request.versionId),
    status: request.status,
    changedAt: canonicalInstant(request.changedAt, "Legal hold change time"),
  });
}

function requireSha256(value: string, label: string): string {
  const digest = String(value || "");
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", `${label} is invalid.`);
  }
  return digest;
}

export function requireProviderRequestId(value: string | undefined | null, label: string): string {
  const requestId = String(value ?? "");
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]{2,199}$/.test(requestId)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", `${label} request identifier is invalid.`, 502);
  }
  return requestId;
}
