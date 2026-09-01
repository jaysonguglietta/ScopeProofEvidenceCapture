import type { AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { decryptEvidence, encryptEvidence, randomId, sha256, stableJson } from "./crypto";
import { getEnv } from "./env";
import { getAssessment } from "./assessments";
import { evidenceSafetyReceiptSha256 } from "./image-safety";
import { NATIVE_ORPHAN_GRACE_MS } from "./native-provenance-contract";
import { redactJson, redactText, type RedactionFinding } from "./redaction";
import { decodePageCursor, pageLimit, pageMeta, type PageMeta } from "./pagination";

export type ArtifactType = "screenshot" | "code" | "configuration" | "report";
export interface EvidenceInput {
  controlId: string;
  framework?: string;
  catalogVersion?: string;
  title: string;
  description: string;
  type: ArtifactType;
  source: string;
  system: string;
  environment?: string;
  assessmentPeriod?: string;
  evidenceOwner?: string;
  tags?: string[];
  expectedEvidence?: string;
  mappedControls?: Array<{ framework: string; controlID: string; relationship: string }>;
  jiraIssueKey?: string;
  jiraIssueURL?: string;
  manualRedactions?: number;
  contentType: string;
  bytes: Uint8Array;
  collectorId?: string;
  jobId?: string;
  sessionId?: string;
  deviceId?: string;
  capturedAt?: string;
  validityDays?: number;
  createdBy: AuthenticatedUser;
  preflightFindings?: RedactionFinding[];
  manifestSha256?: string;
  chainPreviousHash?: string;
  chainEventHash?: string;
  timestampAuthority?: string;
  timestampToken?: string;
  safetyScanSha256?: string;
  safetyScanPolicy?: string;
  safetyScanCompletedAt?: string;
  serverSafetyScan?: { digest: string; policy: string; completedAt: string; scannerOrigin: string; receiptSha256: string };
  assessmentId: string;
  coverageStatus?: "complete" | "partial" | "not_applicable";
  coverage?: Record<string, unknown>;
}

function isTextual(contentType: string): boolean {
  return contentType.startsWith("text/") || /json|xml|yaml|javascript|typescript|x-sh|hcl/i.test(contentType);
}

export type StoreEvidenceResult = {
  id: string;
  deduplicated: boolean;
  occurrenceId: string;
  occurrenceRecorded: boolean;
  redactionCount: number;
  sha256: string;
};

async function occurrenceIdFor(artifactId: string, input: EvidenceInput): Promise<string> {
  const replayKey = input.jobId
    ? { kind: "job", value: input.jobId }
    : input.deviceId && input.manifestSha256
      ? { kind: "native_manifest", value: `${input.deviceId}:${input.manifestSha256}` }
      : input.sessionId
        ? { kind: "session", value: input.sessionId }
        : null;
  if (!replayKey) return randomId("occ");
  // Replay identity must not depend on a timestamp reconstructed by a retry.
  // The artifact plus authoritative job/manifest/session identity is stable.
  const digest = await sha256(stableJson({ artifactId, replayKey }));
  return `occ_${digest.slice(0, 32)}`;
}

function occurrenceInsert(input: EvidenceInput, occurrenceId: string, artifactId: string, capturedAt: string, receivedAt: string, expiresAt: string): D1PreparedStatement {
  const coverageStatus = input.coverageStatus || (input.collectorId ? "complete" : "not_applicable");
  const coverageJson = stableJson(input.coverage || {});
  const provenance = stableJson({
    assessmentId: input.assessmentId || null,
    chainEventHash: input.chainEventHash || null,
    collectorId: input.collectorId || null,
    controlId: input.controlId,
    manifestSha256: input.manifestSha256 || null,
    safetyScanSha256: input.safetyScanSha256 || null,
    serverSafetyScan: input.serverSafetyScan ? {
      sha256: input.serverSafetyScan.digest,
      policy: input.serverSafetyScan.policy,
      completedAt: input.serverSafetyScan.completedAt,
      scannerOrigin: input.serverSafetyScan.scannerOrigin,
      receiptSha256: input.serverSafetyScan.receiptSha256,
    } : null,
    source: input.source,
    coverageStatus,
    coverage: input.coverage || {},
  });
  return getEnv().DB.prepare(`INSERT OR IGNORE INTO evidence_occurrences
    (id, artifact_id, job_id, session_id, device_id, captured_at, received_at, created_by, expires_at, status, coverage_status, coverage_json, provenance_json)
    SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, 'needs_review', ?, ?, ?
    WHERE EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND status NOT IN ('expired', 'purged') AND expires_at > ?)`).bind(
    occurrenceId, artifactId, input.jobId || null, input.sessionId || null, input.deviceId || null,
    capturedAt, receivedAt, input.createdBy.id, expiresAt, coverageStatus, coverageJson, provenance, artifactId, receivedAt,
  );
}

export async function storeEvidence(input: EvidenceInput): Promise<StoreEvidenceResult> {
  const env = getEnv();
  if (!/^asm_[a-f0-9]{32}$/u.test(input.assessmentId)) throw new Response(JSON.stringify({ error: "Evidence requires an explicit assessment." }), { status: 400, headers: { "content-type": "application/json" } });
  const assessment = await getAssessment(input.assessmentId);
  if (!assessment || assessment.status === "closed") throw new Response(JSON.stringify({ error: "Evidence must target an open assessment." }), { status: 409, headers: { "content-type": "application/json" } });
  const systems = assessment.systems as string[];
  const controls = assessment.controls as string[];
  if (assessment.scope_mode !== "explicit" || !assessment.catalog_id || !systems.length || !controls.length) throw new Response(JSON.stringify({ error: "Evidence cannot target an assessment without an explicit, non-empty, versioned scope." }), { status: 409, headers: { "content-type": "application/json" } });
  if (String(assessment.framework) !== (input.framework || "PCI DSS 4.0.1") || !systems.includes(input.system) || !controls.includes(input.controlId)) {
    throw new Response(JSON.stringify({ error: "Evidence falls outside the selected assessment scope." }), { status: 422, headers: { "content-type": "application/json" } });
  }
  const id = randomId("ev");
  let bytes = input.bytes;
  const findings = [...(input.preflightFindings || [])];
  if (isTextual(input.contentType)) {
    let decoded: string;
    try { decoded = new TextDecoder("utf-8", { fatal: true }).decode(input.bytes); }
    catch { throw new Response(JSON.stringify({ error: "Text evidence must be valid UTF-8." }), { status: 422, headers: { "content-type": "application/json" } }); }
    if (/json/i.test(input.contentType)) {
      try {
        const result = redactJson(JSON.parse(decoded));
        bytes = new TextEncoder().encode(JSON.stringify(result.value, null, 2));
        findings.push(...result.findings);
      } catch {
        throw new Response(JSON.stringify({ error: "JSON evidence is invalid or exceeds the redaction complexity limit." }), { status: 422, headers: { "content-type": "application/json" } });
      }
    } else {
      const result = redactText(decoded);
      bytes = new TextEncoder().encode(result.value);
      findings.push(...result.findings);
    }
  }
  const redactionCount = findings.reduce((sum, finding) => sum + finding.count, 0);
  const digest = await sha256(bytes);
  if (input.safetyScanSha256 && input.safetyScanSha256 !== digest) throw new Response(JSON.stringify({ error: "Safety scan digest does not match the evidence artifact." }), { status: 422, headers: { "content-type": "application/json" } });
  if (input.type === "screenshot" && (!input.safetyScanSha256 || !input.safetyScanPolicy || !input.safetyScanCompletedAt)) throw new Response(JSON.stringify({ error: "Screenshot evidence requires a digest-bound exact-pixel safety scan." }), { status: 422, headers: { "content-type": "application/json" } });
  if (input.type === "screenshot") {
    const serverScan = input.serverSafetyScan;
    let scannerOrigin = "";
    try { scannerOrigin = serverScan ? new URL(serverScan.scannerOrigin).origin : ""; } catch { scannerOrigin = ""; }
    const receiptMatches = serverScan && /^[a-f0-9]{64}$/.test(serverScan.receiptSha256)
      ? await evidenceSafetyReceiptSha256(serverScan) === serverScan.receiptSha256
      : false;
    if (!serverScan || serverScan.digest !== digest || !/^[A-Za-z0-9._-]{1,100}$/.test(serverScan.policy)
      || !Number.isFinite(Date.parse(serverScan.completedAt)) || scannerOrigin !== serverScan.scannerOrigin || !scannerOrigin.startsWith("https://")
      || !receiptMatches) {
      throw new Response(JSON.stringify({ error: "Screenshot evidence requires an independent digest-bound server safety receipt." }), { status: 422, headers: { "content-type": "application/json" } });
    }
  }
  const receivedAt = new Date();
  const capturedAt = input.capturedAt || receivedAt.toISOString();
  const capturedMillis = Date.parse(capturedAt);
  if (!Number.isFinite(capturedMillis)) throw new Response(JSON.stringify({ error: "Evidence capture time is invalid." }), { status: 422, headers: { "content-type": "application/json" } });
  if (capturedMillis > receivedAt.getTime() + 5 * 60_000) throw new Response(JSON.stringify({ error: "Evidence capture time is too far in the future." }), { status: 422, headers: { "content-type": "application/json" } });
  const receivedAtISO = receivedAt.toISOString();
  const expiresAt = new Date(receivedAt.getTime() + (input.validityDays || 90) * 86_400_000).toISOString();
  const nativeQueueDueAt = input.deviceId
    ? new Date(receivedAt.getTime() + NATIVE_ORPHAN_GRACE_MS).toISOString()
    : null;
  if (input.deviceId && (!/^dev_[a-f0-9]{32}$/u.test(input.deviceId) || input.type !== "screenshot" ||
      input.contentType !== "image/png" || !input.source.startsWith(`Scopeproof Capture / ${input.deviceId} / EV-`) ||
      !/^[a-f0-9]{64}$/u.test(input.manifestSha256 || "") ||
      !/^(GENESIS|[a-f0-9]{64})$/u.test(input.chainPreviousHash || "") ||
      !/^[a-f0-9]{64}$/u.test(input.chainEventHash || ""))) {
    throw new Response(JSON.stringify({ error: "Native evidence reconciliation authority is invalid." }), { status: 422, headers: { "content-type": "application/json" } });
  }
  // SQLite's `=` never matches NULL. `IS ?` preserves scoped equality while also
  // making unscoped evidence participate in the same deduplication contract.
  const dedupeBindings = [digest, input.source, input.controlId, input.framework || "PCI DSS 4.0.1", input.system, input.environment || null, input.assessmentPeriod || null, input.assessmentId || null] as const;
  const existing = await env.DB.prepare("SELECT id FROM evidence_artifacts WHERE sha256 = ? AND source = ? AND control_id = ? AND framework = ? AND system = ? AND environment IS ? AND assessment_period IS ? AND assessment_id IS ? AND status NOT IN ('expired', 'purged') AND expires_at > ?")
    .bind(...dedupeBindings, receivedAtISO).first<{ id: string }>();
  if (existing) {
    const occurrenceId = await occurrenceIdFor(existing.id, input);
    // A native/device retry can arrive after the artifact and occurrence were
    // committed but before its separate device-chain lease was finalized. An
    // exact replay must not mutate freshness or try to append the same audit
    // event again; returning the committed identity lets the route finish the
    // pending chain transaction safely.
    const exactOccurrenceReplay = await env.DB.prepare(`SELECT 1
      FROM evidence_occurrences AS occurrence
      WHERE occurrence.id = ? AND occurrence.artifact_id = ?
        AND occurrence.created_by = ? AND occurrence.captured_at = ?
        AND occurrence.job_id IS ? AND occurrence.session_id IS ? AND occurrence.device_id IS ?
        AND EXISTS (
          SELECT 1 FROM audit_events AS audit
          WHERE audit.action = 'evidence.occurrence_recorded'
            AND audit.resource_type = 'evidence_occurrence'
            AND audit.resource_id = occurrence.id
        )`)
      .bind(occurrenceId, existing.id, input.createdBy.id, capturedAt,
        input.jobId || null, input.sessionId || null, input.deviceId || null)
      .first();
    if (exactOccurrenceReplay) {
      return { id: existing.id, deduplicated: true, occurrenceId, occurrenceRecorded: false, redactionCount, sha256: digest };
    }
    const [occurrence] = await executeAuditedBatch(input.createdBy, "evidence.occurrence_recorded", "evidence_occurrence", occurrenceId, {
      artifactId: existing.id,
      capturedAt,
      collectorId: input.collectorId || null,
      jobId: input.jobId || null,
      source: input.source,
      validThrough: expiresAt,
    }, [
      occurrenceInsert(input, occurrenceId, existing.id, capturedAt, receivedAtISO, expiresAt),
      env.DB.prepare(`UPDATE evidence_artifacts SET expires_at = ?, status = 'needs_review', approved_by = NULL, approved_at = NULL,
        coverage_status = ?, coverage_json = ?, created_by = ?, collector_id = ?, job_id = ?,
        server_safety_scan_sha256 = COALESCE(?, server_safety_scan_sha256), server_safety_scan_policy = COALESCE(?, server_safety_scan_policy),
        server_safety_scan_completed_at = COALESCE(?, server_safety_scan_completed_at), server_safety_scanner_origin = COALESCE(?, server_safety_scanner_origin),
        server_safety_receipt_sha256 = COALESCE(?, server_safety_receipt_sha256)
        WHERE id = ? AND status NOT IN ('expired', 'purged') AND EXISTS (SELECT 1 FROM evidence_occurrences WHERE id = ? AND received_at = ?)`)
        .bind(expiresAt, input.coverageStatus || (input.collectorId ? "complete" : "not_applicable"), stableJson(input.coverage || {}), input.createdBy.id, input.collectorId || null, input.jobId || null,
          input.serverSafetyScan?.digest || null, input.serverSafetyScan?.policy || null, input.serverSafetyScan?.completedAt || null,
          input.serverSafetyScan?.scannerOrigin || null, input.serverSafetyScan?.receiptSha256 || null, existing.id, occurrenceId, receivedAtISO),
    ], {
      sql: "EXISTS (SELECT 1 FROM evidence_occurrences WHERE id = ?) AND NOT EXISTS (SELECT 1 FROM audit_events WHERE action = 'evidence.occurrence_recorded' AND resource_type = 'evidence_occurrence' AND resource_id = ?)",
      bindings: [occurrenceId, occurrenceId],
    });
    const occurrenceRecorded = Boolean(occurrence.meta.changes);
    if (!occurrenceRecorded) {
      const replay = await env.DB.prepare("SELECT 1 FROM evidence_occurrences WHERE id = ? AND artifact_id = ?").bind(occurrenceId, existing.id).first();
      if (!replay) throw new Response(JSON.stringify({ error: "Evidence freshness changed concurrently. Retry the collection once." }), { status: 409, headers: { "content-type": "application/json" } });
    }
    return { id: existing.id, deduplicated: true, occurrenceId, occurrenceRecorded, redactionCount, sha256: digest };
  }
  const staleDuplicate = await env.DB.prepare("SELECT id FROM evidence_artifacts WHERE sha256 = ? AND source = ? AND control_id = ? AND framework = ? AND system = ? AND environment IS ? AND assessment_period IS ? AND assessment_id IS ? AND status NOT IN ('expired', 'purged') AND expires_at <= ? ORDER BY expires_at DESC LIMIT 1")
    .bind(...dedupeBindings, receivedAtISO).first<{ id: string }>();
  const occurrenceId = await occurrenceIdFor(id, input);
  const associatedData = stableJson({ id, controlId: input.controlId, source: input.source, capturedAt });
  const encrypted = await encryptEvidence(bytes, associatedData);
  const r2Key = `evidence/${capturedAt.slice(0, 7)}/${id}.enc`;
  await env.EVIDENCE_BUCKET.put(r2Key, encrypted.ciphertext, { customMetadata: { evidenceId: id, sha256: digest, encryptionVersion: "2", encryptionKeyId: encrypted.keyId }, httpMetadata: { contentType: "application/octet-stream" } });
  try {
    const insert = env.DB.prepare(`INSERT INTO evidence_artifacts
      (id, control_id, framework, catalog_version, title, description, type, source, system, environment, assessment_period, evidence_owner, tags_json, expected_evidence, mapped_controls_json, jira_issue_key, jira_issue_url, manual_redactions, collector_id, job_id, session_id, device_id, r2_key, content_type, byte_size, sha256, encryption_iv, encryption_version, encryption_key_id, captured_at, expires_at, redaction_count, redaction_summary_json, manifest_sha256, chain_previous_hash, chain_event_hash, timestamp_authority, timestamp_token, safety_scan_sha256, safety_scan_policy, safety_scan_completed_at, server_safety_scan_sha256, server_safety_scan_policy, server_safety_scan_completed_at, server_safety_scanner_origin, server_safety_receipt_sha256, created_by, assessment_id, coverage_status, coverage_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      id, input.controlId, input.framework || "PCI DSS 4.0.1", input.catalogVersion || null, input.title, input.description, input.type, input.source, input.system,
      input.environment || null, input.assessmentPeriod || null, input.evidenceOwner || null, stableJson(input.tags || []), input.expectedEvidence || null,
      stableJson(input.mappedControls || []), input.jiraIssueKey || null, input.jiraIssueURL || null, Math.max(0, Math.min(input.manualRedactions || 0, 10_000)), input.collectorId || null, input.jobId || null,
      input.sessionId || null, input.deviceId || null, r2Key, input.contentType, bytes.byteLength, digest, encrypted.iv, 2, encrypted.keyId, capturedAt, expiresAt, redactionCount, stableJson(findings),
      input.manifestSha256 || null, input.chainPreviousHash || null, input.chainEventHash || null, input.timestampAuthority || null, input.timestampToken || null,
      input.safetyScanSha256 || null, input.safetyScanPolicy || null, input.safetyScanCompletedAt || null,
      input.serverSafetyScan?.digest || null, input.serverSafetyScan?.policy || null, input.serverSafetyScan?.completedAt || null,
      input.serverSafetyScan?.scannerOrigin || null, input.serverSafetyScan?.receiptSha256 || null, input.createdBy.id, input.assessmentId || null,
      input.coverageStatus || (input.collectorId ? "complete" : "not_applicable"), stableJson(input.coverage || {}),
    );
    await executeAuditedBatch(input.createdBy, "evidence.created", "evidence", id, { controlId: input.controlId, source: input.source, jiraIssueKey: input.jiraIssueKey || null, sha256: digest, occurrenceId, redactionCount, byteSize: bytes.byteLength, replacesExpiredArtifactId: staleDuplicate?.id || null }, [
      ...(staleDuplicate ? [env.DB.prepare("UPDATE evidence_artifacts SET status = 'expired' WHERE id = ? AND status NOT IN ('expired', 'purged') AND expires_at <= ?").bind(staleDuplicate.id, receivedAtISO)] : []),
      insert,
      ...(nativeQueueDueAt ? [env.DB.prepare(`INSERT INTO native_provenance_reconciliation_queue
        (artifact_id, due_at, created_at) VALUES (?, ?, ?)`).bind(id, nativeQueueDueAt, receivedAtISO)] : []),
      occurrenceInsert(input, occurrenceId, id, capturedAt, receivedAtISO, expiresAt),
    ]);
  } catch (error) {
    await env.EVIDENCE_BUCKET.delete(r2Key);
    throw error;
  }
  return { id, deduplicated: false, occurrenceId, occurrenceRecorded: true, redactionCount, sha256: digest };
}

export type EvidenceListInput = {
  assessmentId?: string;
  cursor?: string;
  limit?: string;
  status?: string;
  type?: string;
  query?: string;
};

export type EvidenceSummary = {
  total: number;
  approved: number;
  needsReview: number;
  rejected: number;
  returned: number;
  superseded: number;
  expired: number;
  openFindings: number;
  controls: Array<{ controlId: string; total: number; approved: number; needsReview: number; partialCoverage: number }>;
};

async function evidenceRowsForPage(sql: string, bindings: unknown[]): Promise<Array<Record<string, unknown>>> {
  const rows = (await getEnv().DB.prepare(sql).bind(...bindings).all<Record<string, unknown>>()).results;
  return Promise.all(rows.map(async (row) => {
    let serverSafetyStatus: "verified" | "pending" | "not_applicable" = "not_applicable";
    if (row.type === "screenshot") {
      const receiptFields = {
        digest: String(row.server_safety_scan_sha256 || ""), policy: String(row.server_safety_scan_policy || ""),
        completedAt: String(row.server_safety_scan_completed_at || ""), scannerOrigin: String(row.server_safety_scanner_origin || ""),
      };
      const receiptDigest = String(row.server_safety_receipt_sha256 || "");
      serverSafetyStatus = receiptFields.digest === row.sha256 && /^[a-f0-9]{64}$/u.test(receiptDigest)
        && await evidenceSafetyReceiptSha256(receiptFields) === receiptDigest ? "verified" : "pending";
    }
    return {
      ...row,
      server_safety_status: serverSafetyStatus,
      redaction_summary: JSON.parse(String(row.redaction_summary_json || "[]")),
      tags: JSON.parse(String(row.tags_json || "[]")),
      mapped_controls: JSON.parse(String(row.mapped_controls_json || "[]")),
      coverage: JSON.parse(String(row.coverage_json || "{}")),
      redaction_summary_json: undefined,
      tags_json: undefined,
      mapped_controls_json: undefined,
      coverage_json: undefined,
    };
  }));
}

export async function listEvidence(input: EvidenceListInput = {}): Promise<{ evidence: Array<Record<string, unknown>>; page: PageMeta; summary: EvidenceSummary }> {
  const limit = pageLimit(input.limit, 50, 100);
  const cursor = decodePageCursor(input.cursor, /^ev_[a-f0-9]{32}$/u);
  const assessmentId = String(input.assessmentId || "");
  if (assessmentId && !/^asm_[a-f0-9]{32}$/u.test(assessmentId)) throw new Response(JSON.stringify({ error: "Assessment identifier is invalid." }), { status: 400, headers: { "content-type": "application/json" } });
  const statuses = new Set(["needs_review", "approved", "expiring", "rejected", "returned", "superseded", "expired"]);
  if (input.status && !statuses.has(input.status)) throw new Response(JSON.stringify({ error: "Evidence status filter is invalid." }), { status: 400, headers: { "content-type": "application/json" } });
  const types = new Set(["screenshot", "code", "configuration", "report"]);
  if (input.type && !types.has(input.type)) throw new Response(JSON.stringify({ error: "Evidence type filter is invalid." }), { status: 400, headers: { "content-type": "application/json" } });
  const query = String(input.query || "").trim();
  if (query.length > 200) throw new Response(JSON.stringify({ error: "Evidence search is limited to 200 characters." }), { status: 400, headers: { "content-type": "application/json" } });
  const now = new Date().toISOString();
  const baseConditions: string[] = [];
  const baseBindings: unknown[] = [];
  if (assessmentId) { baseConditions.push("e.assessment_id = ?"); baseBindings.push(assessmentId); }
  const conditions = [...baseConditions];
  const bindings = [...baseBindings];
  if (input.status === "expired") {
    conditions.push("(e.status = 'expired' OR (e.status != 'purged' AND e.expires_at <= ?))");
    bindings.push(now);
  } else if (input.status) {
    conditions.push("e.status = ? AND e.expires_at > ?");
    bindings.push(input.status, now);
  }
  if (input.type) { conditions.push("e.type = ?"); bindings.push(input.type); }
  if (query) {
    const escaped = `%${query.replace(/[\\%_]/gu, (character) => `\\${character}`)}%`;
    conditions.push("(e.title LIKE ? ESCAPE '\\' OR e.control_id LIKE ? ESCAPE '\\' OR e.source LIKE ? ESCAPE '\\' OR e.system LIKE ? ESCAPE '\\' OR e.jira_issue_key LIKE ? ESCAPE '\\')");
    bindings.push(escaped, escaped, escaped, escaped, escaped);
  }
  if (cursor) { conditions.push("(e.captured_at < ? OR (e.captured_at = ? AND e.id < ?))"); bindings.push(cursor.sortValue, cursor.sortValue, cursor.id); }
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const countConditions = conditions.filter((condition) => !condition.startsWith("(e.captured_at <"));
  const countBindings = cursor ? bindings.slice(0, -3) : bindings;
  const countWhere = countConditions.length ? `WHERE ${countConditions.join(" AND ")}` : "";
  const totalRow = await getEnv().DB.prepare(`SELECT COUNT(*) AS total FROM evidence_artifacts e ${countWhere}`).bind(...countBindings).first<{ total: number }>();
  const rows = await evidenceRowsForPage(`SELECT e.id, e.control_id, e.framework, e.catalog_version, e.title, e.description, e.type, e.source, e.system, e.environment, e.assessment_period, e.evidence_owner, e.tags_json, e.expected_evidence, e.mapped_controls_json, e.jira_issue_key, e.jira_issue_url, e.manual_redactions, e.collector_id, e.job_id, e.session_id, e.device_id, e.content_type, e.byte_size, e.sha256, e.captured_at, e.expires_at,
      CASE WHEN e.status != 'purged' AND e.expires_at <= ? THEN 'expired' ELSE e.status END AS status,
      e.redaction_count, e.redaction_summary_json, e.manifest_sha256, e.chain_previous_hash, e.chain_event_hash, e.timestamp_authority, e.safety_scan_sha256, e.safety_scan_policy, e.safety_scan_completed_at,
      e.server_safety_scan_sha256, e.server_safety_scan_policy, e.server_safety_scan_completed_at, e.server_safety_scanner_origin, e.server_safety_receipt_sha256,
      e.created_by, e.created_at, e.approved_by, e.approved_at, e.assessment_id, e.coverage_status, e.coverage_json,
      CASE WHEN e.device_id IS NULL THEN 'not_applicable' WHEN EXISTS (
        SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
        WHERE n.artifact_id = e.id AND n.device_id = e.device_id AND n.image_sha256 = e.sha256 AND n.manifest_sha256 = e.manifest_sha256
          AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash
          AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence
      ) THEN 'verified' ELSE 'pending' END AS native_provenance_status,
      (SELECT expires_at FROM retention_holds WHERE evidence_id = e.id AND expires_at > ?) AS retention_hold_expires_at,
      (SELECT id FROM retention_hold_release_requests WHERE evidence_id = e.id AND status = 'pending' AND expires_at > ? LIMIT 1) AS retention_release_request_id,
      (SELECT requested_by FROM retention_hold_release_requests WHERE evidence_id = e.id AND status = 'pending' AND expires_at > ? LIMIT 1) AS retention_release_requested_by,
      (SELECT COUNT(*) FROM evidence_occurrences WHERE artifact_id = e.id) AS occurrence_count,
      (SELECT MAX(received_at) FROM evidence_occurrences WHERE artifact_id = e.id) AS last_observed_at
    FROM evidence_artifacts e ${where} ORDER BY e.captured_at DESC, e.id DESC LIMIT ?`, [now, now, now, now, ...bindings, limit + 1]);
  const paged = pageMeta(rows, limit, Number(totalRow?.total || 0), "captured_at", "id");
  const baseWhere = baseConditions.length ? `WHERE ${baseConditions.join(" AND ")}` : "";
  const aggregate = await getEnv().DB.prepare(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN status = 'approved' AND expires_at > ? THEN 1 ELSE 0 END) AS approved,
      SUM(CASE WHEN status = 'needs_review' AND expires_at > ? THEN 1 ELSE 0 END) AS needs_review,
      SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected,
      SUM(CASE WHEN status = 'returned' THEN 1 ELSE 0 END) AS returned,
      SUM(CASE WHEN status = 'superseded' THEN 1 ELSE 0 END) AS superseded,
      SUM(CASE WHEN status = 'expired' OR expires_at <= ? THEN 1 ELSE 0 END) AS expired
    FROM evidence_artifacts e ${baseWhere}`).bind(now, now, now, ...baseBindings).first<Record<string, number>>();
  const controlRows = (await getEnv().DB.prepare(`SELECT e.control_id,
      COUNT(*) AS total,
      SUM(CASE WHEN e.status = 'approved' AND e.expires_at > ? THEN 1 ELSE 0 END) AS approved,
      SUM(CASE WHEN e.status = 'needs_review' AND e.expires_at > ? THEN 1 ELSE 0 END) AS needs_review,
      SUM(CASE WHEN e.coverage_status = 'partial' AND e.expires_at > ? THEN 1 ELSE 0 END) AS partial_coverage
    FROM evidence_artifacts e ${baseWhere} GROUP BY e.control_id ORDER BY e.control_id`).bind(now, now, now, ...baseBindings).all<Record<string, unknown>>()).results;
  const findingRow = assessmentId ? await getEnv().DB.prepare("SELECT COUNT(*) AS total FROM findings WHERE assessment_id = ? AND status IN ('open','in_progress')").bind(assessmentId).first<{ total: number }>() : { total: 0 };
  return {
    evidence: paged.items,
    page: paged.page,
    summary: {
      total: Number(aggregate?.total || 0), approved: Number(aggregate?.approved || 0), needsReview: Number(aggregate?.needs_review || 0),
      rejected: Number(aggregate?.rejected || 0), returned: Number(aggregate?.returned || 0), superseded: Number(aggregate?.superseded || 0), expired: Number(aggregate?.expired || 0),
      openFindings: Number(findingRow?.total || 0),
      controls: controlRows.map((row) => ({ controlId: String(row.control_id), total: Number(row.total || 0), approved: Number(row.approved || 0), needsReview: Number(row.needs_review || 0), partialCoverage: Number(row.partial_coverage || 0) })),
    },
  };
}

export async function readEvidenceBytes(id: string, actor?: AuthenticatedUser): Promise<{ bytes: Uint8Array; row: Record<string, unknown> } | null> {
  const env = getEnv();
  const row = await env.DB.prepare("SELECT * FROM evidence_artifacts WHERE id = ?").bind(id).first<Record<string, unknown>>();
  if (!row) return null;
  if (row.type === "screenshot") {
    const receiptFields = {
      digest: String(row.server_safety_scan_sha256 || ""), policy: String(row.server_safety_scan_policy || ""),
      completedAt: String(row.server_safety_scan_completed_at || ""), scannerOrigin: String(row.server_safety_scanner_origin || ""),
    };
    const receiptMatches = /^[a-f0-9]{64}$/.test(String(row.server_safety_receipt_sha256 || ""))
      && await evidenceSafetyReceiptSha256(receiptFields) === row.server_safety_receipt_sha256;
    if (receiptFields.digest !== row.sha256 || !receiptFields.policy || !receiptFields.completedAt || !receiptFields.scannerOrigin || !receiptMatches) {
      throw new Response(JSON.stringify({ error: "Independent server-side screenshot safety verification is pending or invalid. Recollect browser evidence or retry the original device upload before this screenshot can be reviewed or disclosed." }), { status: 409, headers: { "content-type": "application/json" } });
    }
  }
  if (row.device_id) {
    const finalized = await env.DB.prepare(`SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
      WHERE n.artifact_id = ? AND n.device_id = ? AND n.image_sha256 = ? AND n.manifest_sha256 = ?
        AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = ? AND n.provenance_key_id IS NOT NULL
        AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence`)
      .bind(row.id, row.device_id, row.sha256, row.manifest_sha256, row.chain_event_hash).first();
    if (!finalized) throw new Response(JSON.stringify({ error: "Native provenance finalization is pending. Retry the original device upload before this evidence can be reviewed or disclosed." }), { status: 409, headers: { "content-type": "application/json" } });
    if (actor && String(row.status) !== "approved" && !["reviewer", "compliance_lead", "admin"].includes(actor.role)) {
      throw new Response(JSON.stringify({ error: "Unapproved native evidence is restricted to authorized internal reviewers." }), { status: 403, headers: { "content-type": "application/json" } });
    }
  }
  if (String(row.status) === "purged") throw new Response(JSON.stringify({ error: "This evidence has been purged and is no longer available." }), { status: 410, headers: { "content-type": "application/json" } });
  if (new Date(String(row.expires_at)).getTime() <= Date.now()) {
    const retained = await env.DB.prepare(`SELECT 1 FROM retention_holds WHERE evidence_id = ? AND expires_at > ?
      UNION ALL SELECT 1 FROM assessments WHERE id = ? AND status IN ('draft', 'active') LIMIT 1`)
      .bind(id, new Date().toISOString(), row.assessment_id || null).first();
    if (!retained) throw new Response(JSON.stringify({ error: "This evidence has expired and is no longer available." }), { status: 410, headers: { "content-type": "application/json" } });
  }
  const object = await env.EVIDENCE_BUCKET.get(String(row.r2_key));
  if (!object) throw new Error("Encrypted evidence object is missing.");
  const associatedData = stableJson({ id: row.id, controlId: row.control_id, source: row.source, capturedAt: row.captured_at });
  const keyId = String(row.encryption_key_id || object.customMetadata?.encryptionKeyId || "legacy-v1");
  const bytes = await decryptEvidence(new Uint8Array(await object.arrayBuffer()), String(row.encryption_iv), associatedData, keyId);
  if (await sha256(bytes) !== row.sha256) throw new Error("Evidence integrity verification failed.");
  return { bytes, row };
}

export async function approveEvidence(id: string, actor: AuthenticatedUser, review: { expectedSha256: string; rationale: string }): Promise<boolean> {
  const expectedSha256 = review.expectedSha256.trim().toLowerCase();
  const rationale = review.rationale.trim();
  if (!/^[a-f0-9]{64}$/.test(expectedSha256) || rationale.length < 20 || rationale.length > 1_000) throw new Response(JSON.stringify({ error: "Approval requires the full artifact digest and a 20–1,000 character review rationale." }), { status: 400, headers: { "content-type": "application/json" } });
  const artifact = await getEnv().DB.prepare(`SELECT e.id, e.sha256, e.type, e.status, e.device_id,
      e.server_safety_scan_sha256, e.server_safety_scan_policy, e.server_safety_scan_completed_at, e.server_safety_scanner_origin, e.server_safety_receipt_sha256,
      o.id AS occurrence_id, o.created_by, o.status AS occurrence_status, o.expires_at, o.coverage_status,
      CASE WHEN e.type != 'screenshot' OR (
        e.server_safety_scan_sha256 = e.sha256 AND e.server_safety_scan_policy IS NOT NULL AND e.server_safety_scan_completed_at IS NOT NULL
        AND e.server_safety_scanner_origin IS NOT NULL AND e.server_safety_receipt_sha256 IS NOT NULL
      ) THEN 1 ELSE 0 END AS server_safety_verified,
      CASE WHEN e.device_id IS NULL OR EXISTS (
        SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
        WHERE n.artifact_id = e.id AND n.device_id = e.device_id AND n.image_sha256 = e.sha256 AND n.manifest_sha256 = e.manifest_sha256
          AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash
          AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence
      ) THEN 1 ELSE 0 END AS native_finalized
    FROM evidence_artifacts e JOIN evidence_occurrences o ON o.artifact_id = e.id
    WHERE e.id = ? AND o.id = (SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = e.id ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1)`)
    .bind(id).first<{ id: string; sha256: string; type: string; status: string; device_id: string | null; server_safety_scan_sha256: string | null; server_safety_scan_policy: string | null; server_safety_scan_completed_at: string | null; server_safety_scanner_origin: string | null; server_safety_receipt_sha256: string | null; occurrence_id: string; created_by: string; occurrence_status: string; expires_at: string; coverage_status: string; server_safety_verified: number; native_finalized: number }>();
  if (!artifact) throw new Response(JSON.stringify({ error: "Evidence not found" }), { status: 404, headers: { "content-type": "application/json" } });
  if (new Date(artifact.expires_at).getTime() <= Date.now() || artifact.status === "purged") throw new Response(JSON.stringify({ error: "Expired evidence cannot be approved." }), { status: 410, headers: { "content-type": "application/json" } });
  if (artifact.created_by === actor.id) throw new Response(JSON.stringify({ error: "Collectors and uploaders cannot approve their own evidence." }), { status: 403, headers: { "content-type": "application/json" } });
  if (artifact.type === "screenshot") {
    const receiptFields = { digest: artifact.server_safety_scan_sha256 || "", policy: artifact.server_safety_scan_policy || "", completedAt: artifact.server_safety_scan_completed_at || "", scannerOrigin: artifact.server_safety_scanner_origin || "" };
    const receiptMatches = /^[a-f0-9]{64}$/.test(artifact.server_safety_receipt_sha256 || "")
      && await evidenceSafetyReceiptSha256(receiptFields) === artifact.server_safety_receipt_sha256;
    if (artifact.server_safety_verified !== 1 || !receiptMatches) throw new Response(JSON.stringify({ error: "Independent server-side screenshot safety verification is pending or invalid. Recollect browser evidence or retry the original device upload before approval." }), { status: 409, headers: { "content-type": "application/json" } });
  }
  if (artifact.device_id && artifact.native_finalized !== 1) throw new Response(JSON.stringify({ error: "Native provenance finalization is pending. Retry the original device upload before approval." }), { status: 409, headers: { "content-type": "application/json" } });
  if (artifact.sha256 !== expectedSha256) throw new Response(JSON.stringify({ error: "The reviewed artifact digest changed. Reload and inspect the evidence again." }), { status: 409, headers: { "content-type": "application/json" } });
  if (artifact.coverage_status === "partial") throw new Response(JSON.stringify({ error: "Partial collector evidence cannot be approved as complete. Resolve the coverage gap and recollect it." }), { status: 409, headers: { "content-type": "application/json" } });
  const approvedAt = new Date().toISOString();
  const reviewEventId = randomId("rev");
  const [result] = await executeAuditedBatch(actor, "evidence.approved", "evidence", id, { artifactSha256: expectedSha256, occurrenceId: artifact.occurrence_id, rationale, reviewEventId }, [
    getEnv().DB.prepare(`UPDATE evidence_occurrences SET status = 'approved', approved_by = ?, approved_at = ?, last_review_event_id = ?
      WHERE id = ? AND artifact_id = ? AND created_by != ? AND status = 'needs_review' AND expires_at > ?
        AND id = (SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = ? ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM evidence_artifacts e WHERE e.id = ? AND e.sha256 = ?
          AND (e.type != 'screenshot' OR (
            e.server_safety_scan_sha256 = e.sha256 AND e.server_safety_scan_policy IS NOT NULL AND e.server_safety_scan_completed_at IS NOT NULL
            AND e.server_safety_scanner_origin IS NOT NULL AND e.server_safety_receipt_sha256 IS NOT NULL
          ))
          AND (e.device_id IS NULL OR EXISTS (
          SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
          WHERE n.artifact_id = e.id AND n.device_id = e.device_id AND n.image_sha256 = e.sha256 AND n.manifest_sha256 = e.manifest_sha256
            AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash
            AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence
        )))`)
      .bind(actor.id, approvedAt, reviewEventId, artifact.occurrence_id, id, actor.id, approvedAt, id, id, expectedSha256),
    getEnv().DB.prepare(`INSERT INTO evidence_review_events
      (id, evidence_id, occurrence_id, action, previous_status, resulting_status, rationale, expected_sha256, actor_id, created_at)
      SELECT ?, ?, ?, 'approved', ?, 'approved', ?, ?, ?, ?
      WHERE EXISTS (SELECT 1 FROM evidence_occurrences WHERE id = ? AND status = 'approved' AND approved_by = ? AND approved_at = ? AND last_review_event_id = ?)`)
      .bind(reviewEventId, id, artifact.occurrence_id, artifact.occurrence_status, rationale, expectedSha256, actor.id, approvedAt, artifact.occurrence_id, actor.id, approvedAt, reviewEventId),
  ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND approved_by = ? AND approved_at = ?) AND EXISTS (SELECT 1 FROM evidence_review_events WHERE id = ? AND actor_id = ?)", bindings: [id, actor.id, approvedAt, reviewEventId, actor.id] });
  if (!result.meta.changes) return false;
  return true;
}

export type EvidenceReviewAction = "reject" | "return" | "reopen" | "supersede";

const reviewTransitions: Record<EvidenceReviewAction, { from: string[]; to: string }> = {
  reject: { from: ["needs_review"], to: "rejected" },
  return: { from: ["needs_review"], to: "returned" },
  reopen: { from: ["rejected", "returned"], to: "needs_review" },
  supersede: { from: ["approved"], to: "superseded" },
};

export async function transitionEvidenceReview(id: string, actor: AuthenticatedUser, review: { action: EvidenceReviewAction; expectedSha256: string; rationale: string; replacementEvidenceId?: string }): Promise<{ changed: boolean; status: string; reviewEventId: string }> {
  const expectedSha256 = review.expectedSha256.trim().toLowerCase();
  const rationale = review.rationale.trim();
  if (!/^[a-f0-9]{64}$/u.test(expectedSha256) || rationale.length < 20 || rationale.length > 1_000) throw new Response(JSON.stringify({ error: "Review requires the full artifact digest and a 20–1,000 character rationale." }), { status: 400, headers: { "content-type": "application/json" } });
  const transition = reviewTransitions[review.action];
  if (!transition) throw new Response(JSON.stringify({ error: "Review action is invalid." }), { status: 400, headers: { "content-type": "application/json" } });
  const artifact = await getEnv().DB.prepare(`SELECT e.id, e.sha256, e.status, e.assessment_id, e.control_id,
      o.id AS occurrence_id, o.created_by, o.status AS occurrence_status, o.expires_at
    FROM evidence_artifacts e JOIN evidence_occurrences o ON o.artifact_id = e.id
    WHERE e.id = ? AND o.id = (SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = e.id ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1)`)
    .bind(id).first<{ id: string; sha256: string; status: string; assessment_id: string | null; control_id: string; occurrence_id: string; created_by: string; occurrence_status: string; expires_at: string }>();
  if (!artifact) throw new Response(JSON.stringify({ error: "Evidence not found." }), { status: 404, headers: { "content-type": "application/json" } });
  if (artifact.sha256 !== expectedSha256) throw new Response(JSON.stringify({ error: "The reviewed artifact digest changed. Reload and inspect it again." }), { status: 409, headers: { "content-type": "application/json" } });
  if (new Date(artifact.expires_at).getTime() <= Date.now()) throw new Response(JSON.stringify({ error: "Expired evidence cannot change review state." }), { status: 410, headers: { "content-type": "application/json" } });
  if (artifact.created_by === actor.id) throw new Response(JSON.stringify({ error: "Collectors and uploaders cannot review their own evidence." }), { status: 403, headers: { "content-type": "application/json" } });
  if (!transition.from.includes(artifact.occurrence_status)) throw new Response(JSON.stringify({ error: `Evidence cannot transition from ${artifact.occurrence_status} using ${review.action}.` }), { status: 409, headers: { "content-type": "application/json" } });
  let replacementId: string | null = null;
  if (review.action === "supersede") {
    replacementId = String(review.replacementEvidenceId || "");
    if (!/^ev_[a-f0-9]{32}$/u.test(replacementId) || replacementId === id) throw new Response(JSON.stringify({ error: "Superseding approved evidence requires a different approved replacement evidence identifier." }), { status: 400, headers: { "content-type": "application/json" } });
    const replacement = await getEnv().DB.prepare("SELECT 1 FROM evidence_artifacts WHERE id = ? AND assessment_id IS ? AND control_id = ? AND status = 'approved' AND expires_at > ?")
      .bind(replacementId, artifact.assessment_id, artifact.control_id, new Date().toISOString()).first();
    if (!replacement) throw new Response(JSON.stringify({ error: "The replacement must be approved, current, and mapped to the same assessment and control." }), { status: 422, headers: { "content-type": "application/json" } });
  }
  const reviewEventId = randomId("rev");
  const reviewedAt = new Date().toISOString();
  const actionName = review.action === "return" ? "returned" : review.action === "reopen" ? "reopened" : review.action === "supersede" ? "superseded" : "rejected";
  const approvedBy = transition.to === "approved" ? actor.id : null;
  const approvedAt = transition.to === "approved" ? reviewedAt : null;
  const [result] = await executeAuditedBatch(actor, `evidence.${actionName}`, "evidence", id, { artifactSha256: expectedSha256, occurrenceId: artifact.occurrence_id, rationale, reviewEventId, replacementEvidenceId: replacementId }, [
    getEnv().DB.prepare(`UPDATE evidence_occurrences SET status = ?, approved_by = ?, approved_at = ?, last_review_event_id = ?
      WHERE id = ? AND artifact_id = ? AND status = ? AND created_by != ? AND expires_at > ?
        AND id = (SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = ? ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1)`)
      .bind(transition.to, approvedBy, approvedAt, reviewEventId, artifact.occurrence_id, id, artifact.occurrence_status, actor.id, reviewedAt, id),
    getEnv().DB.prepare(`INSERT INTO evidence_review_events
      (id, evidence_id, occurrence_id, action, previous_status, resulting_status, rationale, expected_sha256, replacement_evidence_id, actor_id, created_at)
      SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (SELECT 1 FROM evidence_occurrences WHERE id = ? AND status = ? AND last_review_event_id = ?)`)
      .bind(reviewEventId, id, artifact.occurrence_id, actionName, artifact.occurrence_status, transition.to, rationale, expectedSha256, replacementId, actor.id, reviewedAt, artifact.occurrence_id, transition.to, reviewEventId),
  ], { sql: "EXISTS (SELECT 1 FROM evidence_review_events WHERE id = ? AND evidence_id = ? AND resulting_status = ?)", bindings: [reviewEventId, id, transition.to] });
  return { changed: Boolean(result.meta.changes), status: transition.to, reviewEventId };
}

export async function listEvidenceReviewEvents(id: string): Promise<Array<Record<string, unknown>>> {
  if (!/^ev_[a-f0-9]{32}$/u.test(id)) return [];
  return (await getEnv().DB.prepare(`SELECT r.id, r.evidence_id, r.occurrence_id, r.action, r.previous_status, r.resulting_status, r.rationale,
      r.expected_sha256, r.replacement_evidence_id, r.actor_id, u.email AS actor_email, r.created_at
    FROM evidence_review_events r LEFT JOIN users u ON u.id = r.actor_id
    WHERE r.evidence_id = ? ORDER BY r.created_at DESC, r.id DESC LIMIT 250`).bind(id).all<Record<string, unknown>>()).results;
}
