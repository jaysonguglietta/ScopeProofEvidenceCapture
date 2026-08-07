import type { AuthenticatedUser } from "./auth";
import { appendAuditEvent } from "./audit";
import { decryptEvidence, encryptEvidence, randomId, sha256, stableJson } from "./crypto";
import { getEnv } from "./env";
import { redactText, type RedactionFinding } from "./redaction";

export type ArtifactType = "screenshot" | "code" | "configuration" | "report";
export interface EvidenceInput {
  controlId: string;
  title: string;
  description: string;
  type: ArtifactType;
  source: string;
  system: string;
  contentType: string;
  bytes: Uint8Array;
  collectorId?: string;
  jobId?: string;
  capturedAt?: string;
  validityDays?: number;
  createdBy: AuthenticatedUser;
  preflightFindings?: RedactionFinding[];
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
  const existing = await env.DB.prepare("SELECT id FROM evidence_artifacts WHERE sha256 = ? AND source = ? AND control_id = ?").bind(digest, input.source, input.controlId).first<{ id: string }>();
  if (existing) return { id: existing.id, deduplicated: true, redactionCount };
  const capturedAt = input.capturedAt || new Date().toISOString();
  const expiresAt = new Date(new Date(capturedAt).getTime() + (input.validityDays || 90) * 86_400_000).toISOString();
  const associatedData = stableJson({ id, controlId: input.controlId, source: input.source, capturedAt });
  const encrypted = await encryptEvidence(bytes, associatedData);
  const r2Key = `evidence/${capturedAt.slice(0, 7)}/${id}.enc`;
  await env.EVIDENCE_BUCKET.put(r2Key, encrypted.ciphertext, { customMetadata: { evidenceId: id, sha256: digest, encryptionVersion: "1" }, httpMetadata: { contentType: "application/octet-stream" } });
  try {
    await env.DB.prepare(`INSERT INTO evidence_artifacts
      (id, control_id, title, description, type, source, system, collector_id, job_id, r2_key, content_type, byte_size, sha256, encryption_iv, captured_at, expires_at, redaction_count, redaction_summary_json, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(
      id, input.controlId, input.title, input.description, input.type, input.source, input.system, input.collectorId || null, input.jobId || null,
      r2Key, input.contentType, bytes.byteLength, digest, encrypted.iv, capturedAt, expiresAt, redactionCount, stableJson(findings), input.createdBy.id,
    ).run();
  } catch (error) {
    await env.EVIDENCE_BUCKET.delete(r2Key);
    throw error;
  }
  await appendAuditEvent(input.createdBy, "evidence.created", "evidence", id, { controlId: input.controlId, source: input.source, sha256: digest, redactionCount, byteSize: bytes.byteLength });
  return { id, deduplicated: false, redactionCount };
}

export async function listEvidence(limit = 100): Promise<Array<Record<string, unknown>>> {
  const rows = (await getEnv().DB.prepare(`SELECT id, control_id, title, description, type, source, system, collector_id, job_id, content_type, byte_size, sha256, captured_at, expires_at, status, redaction_count, redaction_summary_json, created_by, created_at, approved_by, approved_at
    FROM evidence_artifacts ORDER BY captured_at DESC LIMIT ?`).bind(Math.min(Math.max(limit, 1), 250)).all<Record<string, unknown>>()).results;
  return rows.map((row: Record<string, unknown>) => ({ ...row, redaction_summary: JSON.parse(String(row.redaction_summary_json || "[]")), redaction_summary_json: undefined }));
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

export async function approveEvidence(id: string, actor: AuthenticatedUser): Promise<boolean> {
  const result = await getEnv().DB.prepare("UPDATE evidence_artifacts SET status = 'approved', approved_by = ?, approved_at = ? WHERE id = ? AND status != 'approved'").bind(actor.id, new Date().toISOString(), id).run();
  if (!result.meta.changes) return false;
  await appendAuditEvent(actor, "evidence.approved", "evidence", id);
  return true;
}
