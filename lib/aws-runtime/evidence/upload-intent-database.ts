import {
  asResourceId,
  asTenantId,
  asUploadIntentId,
  asUserId,
  assertBoundedText,
  assertSafeJson,
  canonicalInstant,
  sha256Hex,
  stableJson,
  type JsonValue,
  TenantSecurityError,
} from "../contracts.ts";
import type { RdsDataApiExecutor } from "../http/membership.ts";
import type {
  ConditionalUploadIntentStore,
  ControlledUploadIntent,
  RecoveredUploadIntentReservation,
  UploadIntentReservation,
  UploadIntentRecoveryProjection,
} from "./upload-intent-issuer.ts";
import { asControlId, asEvidenceMimeType } from "./primitives.ts";

export type EvidenceArtifactType = "SCREENSHOT" | "CODE" | "CONFIGURATION" | "REPORT" | "SBOM" | "EXPORT";

export interface UploadIntentEvidenceProjection {
  readonly deviceId: string;
  readonly assessmentId: string;
  readonly title: string;
  readonly description: string;
  readonly evidenceType: EvidenceArtifactType;
  readonly source: string;
  readonly systemName: string;
  readonly capturedAt: Date | string;
  readonly artifactExpiresAt: Date | string;
  readonly metadata: unknown;
}

export interface RdsUploadIntentProjectionOptions {
  readonly executor: RdsDataApiExecutor;
  readonly resourceArn: string;
  readonly secretArn: string;
  readonly database: string;
}

export interface UploadIntentProjectionResult {
  readonly outcome: "created" | "already_created";
  readonly uploadIntentId: string;
  readonly evidenceId: string;
}

const setTenantSql = "SELECT pg_catalog.set_config('scopeproof.tenant_id', :tenant_id, true)";
const createIntentSql = [
  "SELECT upload_intent_id::text, evidence_id::text, was_created",
  "FROM scopeproof.create_upload_intent(",
  "  CAST(:id AS scopeproof.resource_identifier), :nonce_digest,",
  "  CAST(:requested_by AS scopeproof.resource_identifier), CAST(:device_id AS scopeproof.resource_identifier),",
  "  CAST(:assessment_id AS scopeproof.resource_identifier), CAST(:evidence_id AS scopeproof.resource_identifier),",
  "  :object_key, :final_object_key, :content_type, CAST(:content_length AS bigint), :checksum_sha256,",
  "  CAST(:expires_at AS timestamptz), CAST(:required_retention_until AS timestamptz), :control_id,",
  "  :title, :description, :evidence_type, :source, :system_name,",
  "  CAST(:captured_at AS timestamptz), CAST(:artifact_expires_at AS timestamptz), CAST(:metadata AS jsonb)",
  ")",
].join("\n");

/**
 * Idempotently projects an exact Dynamo upload reservation into the tenant
 * database. The SECURITY DEFINER procedure enforces membership, device,
 * assessment, object-path, and row-level tenant invariants in one transaction.
 */
export class RdsDataUploadIntentProjection {
  readonly #executor: RdsDataApiExecutor;
  readonly #connection: Readonly<{ resourceArn: string; secretArn: string; database: string }>;

  constructor(options: RdsUploadIntentProjectionOptions) {
    this.#executor = options.executor;
    this.#connection = validateRdsConnection(options.resourceArn, options.secretArn, options.database);
  }

  async project(intent: ControlledUploadIntent, evidence: UploadIntentEvidenceProjection): Promise<UploadIntentProjectionResult> {
    const normalized = normalizeProjection(intent, evidence);
    const started = await this.#executor.beginTransaction(this.#connection);
    const transactionId = started.transactionId;
    if (!transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transactionId)) {
      throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload database transaction could not be established.", 500);
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
        sql: createIntentSql,
        parameters: projectionParameters(normalized),
        formatRecordsAs: "JSON",
      });
      const committed = parseProjectionResult(result.formattedRecords, normalized.id, normalized.evidenceId);
      await this.#executor.commitTransaction({
        resourceArn: this.#connection.resourceArn,
        secretArn: this.#connection.secretArn,
        transactionId,
      });
      return committed;
    } catch (error) {
      try {
        await this.#executor.rollbackTransaction({
          resourceArn: this.#connection.resourceArn,
          secretArn: this.#connection.secretArn,
          transactionId,
        });
      } catch {
        // Preserve the authoritative projection error. Operations monitoring
        // must alert on rollback failures separately.
      }
      throw error;
    }
  }
}

/**
 * Cross-service fail-closed reservation. Dynamo is the durable recovery
 * authority and stores a bounded, secret-screened projection snapshot. Every
 * exact first request or retry re-runs the idempotent database procedure before
 * a presigned capability can be returned. This closes the ambiguous RDS COMMIT
 * response window without pretending Dynamo and Aurora share a transaction.
 */
export class DynamoAndRdsUploadIntentStore implements ConditionalUploadIntentStore {
  readonly #dynamo: ConditionalUploadIntentStore;
  readonly #database: RdsDataUploadIntentProjection;
  readonly #evidence: UploadIntentEvidenceProjection;

  constructor(input: {
    readonly dynamo: ConditionalUploadIntentStore;
    readonly database: RdsDataUploadIntentProjection;
    readonly evidence: UploadIntentEvidenceProjection;
  }) {
    this.#dynamo = input.dynamo;
    this.#database = input.database;
    this.#evidence = snapshotEvidenceProjection(input.evidence);
  }

  async recoverExact(intent: ControlledUploadIntent): Promise<RecoveredUploadIntentReservation | undefined> {
    const recoveryProjection = await buildRecoveryProjection(intent, this.#evidence);
    const reservation = await this.#dynamo.recoverExact(intent, recoveryProjection);
    if (!reservation) return undefined;
    // Recovery is intentionally allowed to repair only the exact RDS
    // projection proven by Dynamo. It never creates a new Dynamo reservation.
    await this.#database.project(reservation.intent, this.#evidence);
    return reservation;
  }

  async reserve(intent: ControlledUploadIntent): Promise<UploadIntentReservation> {
    const recoveryProjection = await buildRecoveryProjection(intent, this.#evidence);
    const reservation = await this.#dynamo.reserve(intent, recoveryProjection);
    // Deliberately run this for both `created` and `existing`. If an Aurora
    // COMMIT succeeded but its response was lost, the exact retry repairs the
    // observable boundary via the SQL procedure's equality-checked idempotency.
    await this.#database.project(reservation.intent, this.#evidence);
    return reservation;
  }
}

function snapshotEvidenceProjection(value: UploadIntentEvidenceProjection): UploadIntentEvidenceProjection {
  const metadata = assertSafeJson(value.metadata, "Evidence metadata");
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Evidence metadata must be a JSON object.");
  }
  // JSON round-tripping a stable, already-screened value severs all caller
  // references. A caller cannot mutate the RDS facts while Dynamo is awaiting.
  const immutableMetadata = JSON.parse(stableJson(metadata)) as Readonly<Record<string, JsonValue>>;
  return Object.freeze({
    deviceId: String(value.deviceId),
    assessmentId: String(value.assessmentId),
    title: String(value.title),
    description: String(value.description),
    evidenceType: value.evidenceType,
    source: String(value.source),
    systemName: String(value.systemName),
    capturedAt: canonicalInstant(value.capturedAt, "Evidence capture time"),
    artifactExpiresAt: canonicalInstant(value.artifactExpiresAt, "Evidence expiry"),
    metadata: immutableMetadata,
  });
}

async function buildRecoveryProjection(
  intent: ControlledUploadIntent,
  evidence: UploadIntentEvidenceProjection,
): Promise<UploadIntentRecoveryProjection> {
  const normalized = normalizeProjection(intent, evidence);
  const canonicalEvidenceProjection = stableJson({
    schemaVersion: 1,
    deviceId: normalized.deviceId,
    assessmentId: normalized.assessmentId,
    title: normalized.title,
    description: normalized.description,
    evidenceType: normalized.evidenceType,
    source: normalized.source,
    systemName: normalized.systemName,
    capturedAt: normalized.capturedAt,
    artifactExpiresAt: normalized.artifactExpiresAt,
    metadata: normalized.metadata,
  });
  if (canonicalEvidenceProjection.length > 131_072) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Evidence recovery projection is too large for the control plane.", 413);
  }
  return Object.freeze({
    canonicalEvidenceProjection,
    evidenceProjectionDigest: await sha256Hex(`scopeproof-upload-evidence-projection-v1\n${canonicalEvidenceProjection}`),
  });
}

interface NormalizedProjection {
  readonly tenantId: string;
  readonly id: string;
  readonly nonceDigest: string;
  readonly requestedBy: string;
  readonly deviceId: string;
  readonly assessmentId: string;
  readonly evidenceId: string;
  readonly objectKey: string;
  readonly finalObjectKey: string;
  readonly contentType: string;
  readonly contentLength: number;
  readonly checksumSha256: string;
  readonly expiresAt: string;
  readonly requiredRetentionUntil: string;
  readonly controlId: string;
  readonly title: string;
  readonly description: string;
  readonly evidenceType: EvidenceArtifactType;
  readonly source: string;
  readonly systemName: string;
  readonly capturedAt: string;
  readonly artifactExpiresAt: string;
  readonly metadata: Readonly<Record<string, JsonValue>>;
}

function normalizeProjection(intent: ControlledUploadIntent, evidence: UploadIntentEvidenceProjection): NormalizedProjection {
  const tenantId = asTenantId(intent.tenantId);
  const id = asUploadIntentId(intent.id);
  const requestedBy = asUserId(intent.requestedBy);
  const deviceId = asResourceId(evidence.deviceId, ["dev"]);
  const assessmentId = asResourceId(evidence.assessmentId, ["asm"]);
  const evidenceId = asResourceId(intent.resourceId, ["evd"]);
  const controlId = asControlId(intent.controlId);
  const contentType = asEvidenceMimeType(intent.contentType);
  const capturedAt = canonicalInstant(evidence.capturedAt, "Evidence capture time");
  const artifactExpiresAt = canonicalInstant(evidence.artifactExpiresAt, "Evidence expiry");
  const requiredRetentionUntil = canonicalInstant(intent.requiredRetentionUntil, "Required retention time");
  if (Date.parse(artifactExpiresAt) < Date.parse(capturedAt) || Date.parse(artifactExpiresAt) > Date.parse(requiredRetentionUntil)) {
    throw new TenantSecurityError("RETENTION_VIOLATION", "Evidence expiry must cover capture and remain within the required retention boundary.", 409);
  }
  if (!(["SCREENSHOT", "CODE", "CONFIGURATION", "REPORT", "SBOM", "EXPORT"] as const).includes(evidence.evidenceType)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Evidence artifact type is invalid.");
  }
  if (!Number.isSafeInteger(intent.expectedSize) || intent.expectedSize < 1 || intent.expectedSize > 26_214_400) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Evidence size exceeds the database contract.", 413);
  }
  const safeMetadata = assertSafeJson(evidence.metadata, "Evidence metadata");
  if (!safeMetadata || typeof safeMetadata !== "object" || Array.isArray(safeMetadata)) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Evidence metadata must be a JSON object.");
  }
  return Object.freeze({
    tenantId,
    id,
    nonceDigest: String(intent.nonceDigest),
    requestedBy,
    deviceId,
    assessmentId,
    evidenceId,
    objectKey: String(intent.quarantineKey),
    finalObjectKey: String(intent.finalKey),
    contentType,
    contentLength: intent.expectedSize,
    checksumSha256: String(intent.expectedSha256),
    expiresAt: canonicalInstant(intent.expiresAt, "Upload expiry"),
    requiredRetentionUntil,
    controlId,
    title: assertBoundedText(evidence.title, "Evidence title", 1, 240),
    description: assertBoundedText(evidence.description || "", "Evidence description", 0, 8_000),
    evidenceType: evidence.evidenceType,
    source: assertBoundedText(evidence.source, "Evidence source", 1, 120),
    systemName: assertBoundedText(evidence.systemName, "Evidence system name", 1, 160),
    capturedAt,
    artifactExpiresAt,
    metadata: Object.freeze(safeMetadata as Record<string, JsonValue>),
  });
}

function projectionParameters(value: NormalizedProjection): readonly ReturnType<typeof parameter>[] {
  return [
    parameter("id", value.id),
    parameter("nonce_digest", value.nonceDigest),
    parameter("requested_by", value.requestedBy),
    parameter("device_id", value.deviceId),
    parameter("assessment_id", value.assessmentId),
    parameter("evidence_id", value.evidenceId),
    parameter("object_key", value.objectKey),
    parameter("final_object_key", value.finalObjectKey),
    parameter("content_type", value.contentType),
    parameter("content_length", String(value.contentLength)),
    parameter("checksum_sha256", value.checksumSha256),
    parameter("expires_at", value.expiresAt),
    parameter("required_retention_until", value.requiredRetentionUntil),
    parameter("control_id", value.controlId),
    parameter("title", value.title),
    parameter("description", value.description),
    parameter("evidence_type", value.evidenceType),
    parameter("source", value.source),
    parameter("system_name", value.systemName),
    parameter("captured_at", value.capturedAt),
    parameter("artifact_expires_at", value.artifactExpiresAt),
    parameter("metadata", stableJson(value.metadata)),
  ];
}

function parseProjectionResult(value: string | undefined, expectedIntent: string, expectedEvidence: string): UploadIntentProjectionResult {
  if (!value || value.length > 16_384) throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload database response is invalid.", 500);
  let rows: unknown;
  try { rows = JSON.parse(value); } catch { throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload database response is invalid.", 500); }
  if (!Array.isArray(rows) || rows.length !== 1 || !rows[0] || typeof rows[0] !== "object" || Array.isArray(rows[0])) {
    throw new TenantSecurityError("INVALID_UPLOAD_INTENT", "Upload database response is invalid.", 500);
  }
  const row = rows[0] as Record<string, unknown>;
  if (row.upload_intent_id !== expectedIntent || row.evidence_id !== expectedEvidence || typeof row.was_created !== "boolean") {
    throw new TenantSecurityError("UPLOAD_MISMATCH", "Upload database returned conflicting state.", 409);
  }
  return Object.freeze({
    outcome: row.was_created ? "created" : "already_created",
    uploadIntentId: expectedIntent,
    evidenceId: expectedEvidence,
  });
}

function parameter(name: string, value: string): { name: string; value: { stringValue: string } } {
  return { name, value: { stringValue: value } };
}

function validateRdsConnection(resourceArnValue: string, secretArnValue: string, databaseValue: string): Readonly<{ resourceArn: string; secretArn: string; database: string }> {
  const resourceArn = String(resourceArnValue || "");
  const secretArn = String(secretArnValue || "");
  const database = String(databaseValue || "");
  const resource = /^arn:(aws|aws-us-gov|aws-cn):rds:([a-z0-9-]+):(\d{12}):cluster:[A-Za-z0-9-]{1,63}$/.exec(resourceArn);
  const secret = /^arn:(aws|aws-us-gov|aws-cn):secretsmanager:([a-z0-9-]+):(\d{12}):secret:[A-Za-z0-9/_+=.@-]{1,512}$/.exec(secretArn);
  if (!resource || !secret || resource[1] !== secret[1] || resource[2] !== secret[2] || resource[3] !== secret[3]) {
    throw new Error("RDS cluster and secret must use valid ARNs in the same partition, region, and account.");
  }
  if (!/^[A-Za-z][A-Za-z0-9_]{0,62}$/.test(database)) throw new Error("Database name is invalid.");
  return Object.freeze({ resourceArn, secretArn, database });
}
