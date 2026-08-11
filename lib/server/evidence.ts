import type { AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { decryptEvidence, encryptEvidence, randomId, sha256, stableJson } from "./crypto";
import { getEnv } from "./env";
import { redactText, type RedactionFinding } from "./redaction";

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
}

function isTextual(contentType: string): boolean {
  return contentType.startsWith("text/") || /json|xml|yaml|javascript|typescript|x-sh|hcl/i.test(contentType);
}

export async function storeEvidence(input: EvidenceInput): Promise<{ id: string; deduplicated: boolean; redactionCount: number }> {
  const env = getEnv();
  const id = randomId("ev");
  let bytes = input.bytes;
  const findings = [...(input.preflightFindings || [])];
  if (isTextual(input.contentType)) {
    const result = redactText(new TextDecoder().decode(input.bytes));
    bytes = new TextEncoder().encode(result.value);
    findings.push(...result.findings);
  }
  const redactionCount = findings.reduce((sum, finding) => sum + finding.count, 0);
  const digest = await sha256(bytes);
  if (input.safetyScanSha256 && input.safetyScanSha256 !== digest) throw new Response(JSON.stringify({ error: "Safety scan digest does not match the evidence artifact." }), { status: 422, headers: { "content-type": "application/json" } });
  if (input.type === "screenshot" && (!input.safetyScanSha256 || !input.safetyScanPolicy || !input.safetyScanCompletedAt)) throw new Response(JSON.stringify({ error: "Screenshot evidence requires a digest-bound exact-pixel safety scan." }), { status: 422, headers: { "content-type": "application/json" } });
  const existing = await env.DB.prepare("SELECT id FROM evidence_artifacts WHERE sha256 = ? AND source = ? AND control_id = ?").bind(digest, input.source, input.controlId).first<{ id: string }>();
  if (existing) return { id: existing.id, deduplicated: true, redactionCount };
  const capturedAt = input.capturedAt || new Date().toISOString();
  const expiresAt = new Date(new Date(capturedAt).getTime() + (input.validityDays || 90) * 86_400_000).toISOString();
  const associatedData = stableJson({ id, controlId: input.controlId, source: input.source, capturedAt });
  const encrypted = await encryptEvidence(bytes, associatedData);
  const r2Key = `evidence/${capturedAt.slice(0, 7)}/${id}.enc`;
  await env.EVIDENCE_BUCKET.put(r2Key, encrypted.ciphertext, { customMetadata: { evidenceId: id, sha256: digest, encryptionVersion: "1" }, httpMetadata: { contentType: "application/octet-stream" } });
  try {
    const insert = env.DB.prepare(`INSERT INTO evidence_artifacts
      (id, control_id, framework, catalog_version, title, description, type, source, system, environment, assessment_period, evidence_owner, tags_json, expected_evidence, mapped_controls_json, jira_issue_key, jira_issue_url, manual_redactions, collector_id, job_id, session_id, device_id, r2_key, content_type, byte_size, sha256, encryption_iv, captured_at, expires_at, redaction_count, redaction_summary_json, manifest_sha256, chain_previous_hash, chain_event_hash, timestamp_authority, timestamp_token, safety_scan_sha256, safety_scan_policy, safety_scan_completed_at, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      id, input.controlId, input.framework || "PCI DSS 4.0.1", input.catalogVersion || null, input.title, input.description, input.type, input.source, input.system,
      input.environment || null, input.assessmentPeriod || null, input.evidenceOwner || null, stableJson(input.tags || []), input.expectedEvidence || null,
      stableJson(input.mappedControls || []), input.jiraIssueKey || null, input.jiraIssueURL || null, Math.max(0, Math.min(input.manualRedactions || 0, 10_000)), input.collectorId || null, input.jobId || null,
      input.sessionId || null, input.deviceId || null, r2Key, input.contentType, bytes.byteLength, digest, encrypted.iv, capturedAt, expiresAt, redactionCount, stableJson(findings),
      input.manifestSha256 || null, input.chainPreviousHash || null, input.chainEventHash || null, input.timestampAuthority || null, input.timestampToken || null,
      input.safetyScanSha256 || null, input.safetyScanPolicy || null, input.safetyScanCompletedAt || null, input.createdBy.id,
    );
    await executeAuditedBatch(input.createdBy, "evidence.created", "evidence", id, { controlId: input.controlId, source: input.source, jiraIssueKey: input.jiraIssueKey || null, sha256: digest, redactionCount, byteSize: bytes.byteLength }, [insert]);
  } catch (error) {
    await env.EVIDENCE_BUCKET.delete(r2Key);
    throw error;
  }
  return { id, deduplicated: false, redactionCount };
}

export async function listEvidence(limit = 100): Promise<Array<Record<string, unknown>>> {
  const rows = (await getEnv().DB.prepare(`SELECT id, control_id, framework, catalog_version, title, description, type, source, system, environment, assessment_period, evidence_owner, tags_json, expected_evidence, mapped_controls_json, jira_issue_key, jira_issue_url, manual_redactions, collector_id, job_id, session_id, device_id, content_type, byte_size, sha256, captured_at, expires_at, status, redaction_count, redaction_summary_json, manifest_sha256, chain_previous_hash, chain_event_hash, timestamp_authority, safety_scan_sha256, safety_scan_policy, safety_scan_completed_at, created_by, created_at, approved_by, approved_at
    FROM evidence_artifacts ORDER BY captured_at DESC LIMIT ?`).bind(Math.min(Math.max(limit, 1), 250)).all<Record<string, unknown>>()).results;
  return rows.map((row: Record<string, unknown>) => ({ ...row, redaction_summary: JSON.parse(String(row.redaction_summary_json || "[]")), tags: JSON.parse(String(row.tags_json || "[]")), mapped_controls: JSON.parse(String(row.mapped_controls_json || "[]")), redaction_summary_json: undefined, tags_json: undefined, mapped_controls_json: undefined }));
}

export async function readEvidenceBytes(id: string): Promise<{ bytes: Uint8Array; row: Record<string, unknown> } | null> {
  const env = getEnv();
  const row = await env.DB.prepare("SELECT * FROM evidence_artifacts WHERE id = ?").bind(id).first<Record<string, unknown>>();
  if (!row) return null;
  const object = await env.EVIDENCE_BUCKET.get(String(row.r2_key));
  if (!object) throw new Error("Encrypted evidence object is missing.");
  const associatedData = stableJson({ id: row.id, controlId: row.control_id, source: row.source, capturedAt: row.captured_at });
  const bytes = await decryptEvidence(new Uint8Array(await object.arrayBuffer()), String(row.encryption_iv), associatedData);
  if (await sha256(bytes) !== row.sha256) throw new Error("Evidence integrity verification failed.");
  return { bytes, row };
}

export async function approveEvidence(id: string, actor: AuthenticatedUser, review: { expectedSha256: string; rationale: string }): Promise<boolean> {
  const expectedSha256 = review.expectedSha256.trim().toLowerCase();
  const rationale = review.rationale.trim();
  if (!/^[a-f0-9]{64}$/.test(expectedSha256) || rationale.length < 20 || rationale.length > 1_000) throw new Response(JSON.stringify({ error: "Approval requires the full artifact digest and a 20–1,000 character review rationale." }), { status: 400, headers: { "content-type": "application/json" } });
  const artifact = await getEnv().DB.prepare("SELECT id, sha256, created_by, status FROM evidence_artifacts WHERE id = ?").bind(id).first<{ id: string; sha256: string; created_by: string; status: string }>();
  if (!artifact) throw new Response(JSON.stringify({ error: "Evidence not found" }), { status: 404, headers: { "content-type": "application/json" } });
  if (artifact.created_by === actor.id) throw new Response(JSON.stringify({ error: "Collectors and uploaders cannot approve their own evidence." }), { status: 403, headers: { "content-type": "application/json" } });
  if (artifact.sha256 !== expectedSha256) throw new Response(JSON.stringify({ error: "The reviewed artifact digest changed. Reload and inspect the evidence again." }), { status: 409, headers: { "content-type": "application/json" } });
  const approvedAt = new Date().toISOString();
  const [result] = await executeAuditedBatch(actor, "evidence.approved", "evidence", id, { artifactSha256: expectedSha256, rationale }, [
    getEnv().DB.prepare("UPDATE evidence_artifacts SET status = 'approved', approved_by = ?, approved_at = ? WHERE id = ? AND sha256 = ? AND created_by != ? AND status IN ('needs_review', 'expiring')").bind(actor.id, approvedAt, id, expectedSha256, actor.id),
  ], { sql: "EXISTS (SELECT 1 FROM evidence_artifacts WHERE id = ? AND approved_by = ? AND approved_at = ?)", bindings: [id, actor.id, approvedAt] });
  if (!result.meta.changes) return false;
  return true;
}
