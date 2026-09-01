import {
  asResourceId,
  asTenantId,
  asUserId,
  canonicalInstant,
  TenantSecurityError,
  type TenantId,
  type UserId,
} from "../contracts.ts";
import type { DataApiStringParameter, RdsDataApiExecutor } from "../http/membership.ts";
import {
  normalizeEvidenceRecord,
  normalizeEvidenceCursor,
  type EvidenceAccessRepository,
  type EvidenceArtifactAccessRecord,
  type EvidencePageCursor,
} from "./evidence-access.ts";

export interface RdsDataEvidenceAccessRepositoryOptions {
  readonly executor: RdsDataApiExecutor;
  readonly resourceArn: string;
  readonly secretArn: string;
  readonly database: string;
}

const setTenantSql = "SELECT pg_catalog.set_config('scopeproof.tenant_id', :tenant_id, true)";
const listEvidenceSql = [
  "SELECT tenant_id::text AS tenant_id, evidence_id::text AS evidence_id, control_id, title, description,",
  "       evidence_type, source, system_name, status, revision, content_type, byte_size, checksum_sha256,",
  "       evidence_bucket, object_key, object_version_id, captured_at, retain_until, created_at",
  "FROM scopeproof.list_accessible_evidence(",
  "  CAST(:requested_by AS scopeproof.resource_identifier),",
  "  CAST(NULLIF(:cursor_captured_at, '') AS timestamptz),",
  "  CAST(NULLIF(:cursor_evidence_id, '') AS scopeproof.resource_identifier),",
  "  CAST(:result_limit AS integer)",
  ")",
].join("\n");
const readEvidenceSql = [
  "SELECT tenant_id::text AS tenant_id, evidence_id::text AS evidence_id, control_id, title, description,",
  "       evidence_type, source, system_name, status, revision, content_type, byte_size, checksum_sha256,",
  "       evidence_bucket, object_key, object_version_id, captured_at, retain_until, created_at",
  "FROM scopeproof.read_accessible_evidence(",
  "  CAST(:requested_by AS scopeproof.resource_identifier),",
  "  CAST(:evidence_id AS scopeproof.resource_identifier)",
  ")",
].join("\n");

type EvidenceJsonRow = Readonly<Record<string, unknown>>;

export class RdsDataEvidenceAccessRepository implements EvidenceAccessRepository {
  readonly #executor: RdsDataApiExecutor;
  readonly #connection: Readonly<{ resourceArn: string; secretArn: string; database: string }>;

  constructor(options: RdsDataEvidenceAccessRepositoryOptions) {
    if (!options.executor) throw new Error("RDS evidence executor is required.");
    this.#executor = options.executor;
    this.#connection = validateRdsConnection(options.resourceArn, options.secretArn, options.database);
  }

  async list(input: Readonly<{ tenantId: TenantId; requestedBy: UserId; limit: number; cursor?: EvidencePageCursor }>): Promise<readonly EvidenceArtifactAccessRecord[]> {
    const tenantId = asTenantId(input.tenantId);
    const requestedBy = asUserId(input.requestedBy);
    if (!Number.isSafeInteger(input.limit) || input.limit < 2 || input.limit > 101) {
      throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence repository page size is invalid.");
    }
    let cursor: EvidencePageCursor | undefined;
    if (input.cursor) {
      cursor = normalizeEvidenceCursor(input.cursor);
    }
    const rows = await this.#execute(tenantId, listEvidenceSql, [
      parameter("requested_by", requestedBy),
      parameter("cursor_captured_at", cursor?.capturedAt ?? ""),
      parameter("cursor_evidence_id", cursor?.evidenceId ?? ""),
      parameter("result_limit", String(input.limit)),
    ], 101);
    return Object.freeze(rows.map(rowToEvidence));
  }

  async readExact(input: Readonly<{ tenantId: TenantId; requestedBy: UserId; evidenceId: string; expectedRevision: number }>): Promise<EvidenceArtifactAccessRecord | null> {
    const tenantId = asTenantId(input.tenantId);
    const requestedBy = asUserId(input.requestedBy);
    const evidenceId = String(asResourceId(input.evidenceId, ["evd"]));
    if (!Number.isSafeInteger(input.expectedRevision) || input.expectedRevision < 0) {
      throw new TenantSecurityError("INVALID_IDENTIFIER", "Expected evidence revision is invalid.");
    }
    const rows = await this.#execute(tenantId, readEvidenceSql, [
      parameter("requested_by", requestedBy),
      parameter("evidence_id", evidenceId),
    ], 1);
    if (rows.length > 1) throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence lookup returned ambiguous state.", 500);
    return rows.length === 0 ? null : rowToEvidence(rows[0]);
  }

  async #execute(tenantId: TenantId, sql: string, parameters: readonly DataApiStringParameter[], maximumRows: number): Promise<readonly EvidenceJsonRow[]> {
    const transaction = await this.#executor.beginTransaction(this.#connection);
    if (!transaction.transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transaction.transactionId)) {
      throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence transaction could not be established.", 500);
    }
    const transactionId = transaction.transactionId;
    try {
      await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql: setTenantSql,
        parameters: [parameter("tenant_id", tenantId)],
      });
      const response = await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql,
        parameters,
        formatRecordsAs: "JSON",
      });
      const rows = parseRows(response.formattedRecords, maximumRows);
      await this.#executor.commitTransaction({
        resourceArn: this.#connection.resourceArn,
        secretArn: this.#connection.secretArn,
        transactionId,
      });
      return rows;
    } catch (error) {
      try {
        await this.#executor.rollbackTransaction({
          resourceArn: this.#connection.resourceArn,
          secretArn: this.#connection.secretArn,
          transactionId,
        });
      } catch {
        // Preserve the original failure. Monitoring alerts on rollback errors.
      }
      throw error;
    }
  }
}

function parseRows(value: string | undefined, maximumRows: number): readonly EvidenceJsonRow[] {
  if (!value || value.length > 1_048_576) throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence lookup response is invalid.", 500);
  let parsed: unknown;
  try { parsed = JSON.parse(value); } catch { throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence lookup response is invalid.", 500); }
  if (!Array.isArray(parsed) || parsed.length > maximumRows || parsed.some((row) => !row || typeof row !== "object" || Array.isArray(row))) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence lookup response is invalid.", 500);
  }
  return parsed as EvidenceJsonRow[];
}

function rowToEvidence(row: EvidenceJsonRow): EvidenceArtifactAccessRecord {
  if (Object.keys(row).sort().join(",") !== [
    "byte_size", "captured_at", "checksum_sha256", "content_type", "control_id", "created_at", "description",
    "evidence_bucket", "evidence_id", "evidence_type", "object_key", "object_version_id", "retain_until", "revision",
    "source", "status", "system_name", "tenant_id", "title",
  ].sort().join(",")) {
    throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence lookup response is invalid.", 500);
  }
  const revision = exactInteger(row.revision);
  const byteSize = exactInteger(row.byte_size);
  return normalizeEvidenceRecord({
    tenantId: String(row.tenant_id) as TenantId,
    evidenceId: String(row.evidence_id),
    controlId: String(row.control_id),
    title: String(row.title),
    description: String(row.description),
    evidenceType: String(row.evidence_type) as EvidenceArtifactAccessRecord["evidenceType"],
    source: String(row.source),
    systemName: String(row.system_name),
    status: String(row.status) as EvidenceArtifactAccessRecord["status"],
    revision,
    contentType: String(row.content_type),
    byteSize,
    checksumSha256: String(row.checksum_sha256) as EvidenceArtifactAccessRecord["checksumSha256"],
    evidenceBucket: String(row.evidence_bucket),
    objectKey: String(row.object_key),
    objectVersionId: String(row.object_version_id),
    capturedAt: canonicalInstant(String(row.captured_at), "Evidence capture time"),
    retainUntil: canonicalInstant(String(row.retain_until), "Evidence retention time"),
    createdAt: canonicalInstant(String(row.created_at), "Evidence creation time"),
  });
}

function exactInteger(value: unknown): number {
  if (typeof value === "number" && Number.isSafeInteger(value)) return value;
  if (typeof value === "string" && /^(?:0|[1-9][0-9]{0,15})$/.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed)) return parsed;
  }
  throw new TenantSecurityError("INVALID_IDENTIFIER", "Evidence numeric metadata is invalid.", 500);
}

function parameter(name: string, value: string): DataApiStringParameter {
  return Object.freeze({ name, value: Object.freeze({ stringValue: value }) });
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
