import { getEnv } from "./env";
import { PACKAGE_ELIGIBLE_EVIDENCE_SQL } from "./package-eligibility";
import { decodePageCursor, pageLimit, pageMeta } from "./pagination";

export type FindingEvidenceSnapshot = { evidenceId: string; occurrenceId: string; sha256: string; title: string; controlId: string; system: string; approvedAt: string; linkedAt: string };
function failure(message: string, status = 422): Response { return Response.json({ error: message }, { status }); }
const evidenceIdPattern = /^ev_[a-f0-9]{32}$/u;
const latestOccurrence = `JOIN evidence_occurrences o ON o.id = (SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = e.id ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1)`;
const reviewedEvidence = `${PACKAGE_ELIGIBLE_EVIDENCE_SQL} AND e.status NOT IN ('expired','purged') AND o.approved_by IS NOT NULL AND o.approved_by != o.created_by AND o.approved_at IS NOT NULL`;
const fields = "e.id AS evidenceId, o.id AS occurrenceId, e.sha256, e.title, e.control_id AS controlId, e.system, o.approved_at AS approvedAt, e.created_at";

export function parseFindingEvidence(value: unknown): FindingEvidenceSnapshot[] {
  try {
    const parsed: unknown = typeof value === "string" ? JSON.parse(value) : value;
    if (!Array.isArray(parsed) || parsed.length > 10 || parsed.some((item) => !item || typeof item !== "object" || !evidenceIdPattern.test(item.evidenceId) || typeof item.occurrenceId !== "string" || !/^[a-f0-9]{64}$/u.test(item.sha256))) return [];
    return parsed as FindingEvidenceSnapshot[];
  } catch { return []; }
}

export function findingEvidenceIds(value: unknown): string[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 10 || value.some((id) => typeof id !== "string" || !evidenceIdPattern.test(id)) || new Set(value).size !== value.length) throw failure("Resolution requires 1–10 distinct evidence identifiers.");
  return [...value].sort();
}

export async function resolveFindingEvidence(assessmentId: string, controlId: unknown, value: unknown, at: string): Promise<FindingEvidenceSnapshot[]> {
  const ids = findingEvidenceIds(value);
  const rows = (await getEnv().DB.prepare(`SELECT ${fields} FROM evidence_artifacts e ${latestOccurrence}
    WHERE e.assessment_id = ? AND (? IS NULL OR e.control_id = ?) AND e.id IN (${ids.map(() => "?").join(",")}) AND ${reviewedEvidence} ORDER BY e.id`)
    .bind(assessmentId, controlId || null, controlId || null, ...ids, at).all<Record<string, unknown>>()).results;
  if (rows.length !== ids.length) throw failure("Choose current, independently approved, complete evidence from this assessment and finding control. Expired, partial, unsafe, or unverified evidence cannot resolve a finding.");
  return rows.map((row) => ({ evidenceId: String(row.evidenceId), occurrenceId: String(row.occurrenceId), sha256: String(row.sha256), title: String(row.title), controlId: String(row.controlId), system: String(row.system), approvedAt: String(row.approvedAt), linkedAt: at }));
}

/** Recheck the SAME occurrence, digest, scope and approval in the audited write. */
export function findingEvidenceFence(assessmentId: string, controlId: unknown, evidence: FindingEvidenceSnapshot[], at: string): { sql: string; bindings: unknown[] } {
  return { sql: evidence.map(() => `EXISTS (SELECT 1 FROM evidence_artifacts e ${latestOccurrence} WHERE e.assessment_id = ? AND (? IS NULL OR e.control_id = ?) AND e.id = ? AND o.id = ? AND e.sha256 = ? AND ${reviewedEvidence})`).join(" AND ") || "1 = 1",
    bindings: evidence.flatMap((item) => [assessmentId, controlId || null, controlId || null, item.evidenceId, item.occurrenceId, item.sha256, at]) };
}

export async function listFindingResolutionEvidence(id: string, input: { q?: string; cursor?: string; limit?: string }) {
  if (!/^fnd_[a-f0-9]{32}$/u.test(id)) throw failure("Finding identifier is invalid.", 400);
  const finding = await getEnv().DB.prepare("SELECT assessment_id, control_id FROM findings WHERE id = ?").bind(id).first<{ assessment_id: string; control_id: string | null }>();
  if (!finding) throw failure("Finding not found.", 404);
  const q = String(input.q || "").trim(); if (q.length > 120) throw failure("Search is limited to 120 characters.", 400);
  const limit = pageLimit(input.limit, 25, 100), cursor = decodePageCursor(input.cursor, evidenceIdPattern);
  const conditions = ["e.assessment_id = ?", "(? IS NULL OR e.control_id = ?)", reviewedEvidence];
  const bindings: unknown[] = [finding.assessment_id, finding.control_id, finding.control_id, new Date().toISOString()];
  if (q) { conditions.push("(e.title LIKE ? ESCAPE '\\' OR e.id = ?)"); bindings.push(`%${q.replace(/[\\%_]/gu, "\\$&")}%`, q); }
  const count = await getEnv().DB.prepare(`SELECT COUNT(*) AS total FROM evidence_artifacts e ${latestOccurrence} WHERE ${conditions.join(" AND ")}`).bind(...bindings).first<{ total: number }>();
  if (cursor) { conditions.push("(e.created_at < ? OR (e.created_at = ? AND e.id < ?))"); bindings.push(cursor.sortValue, cursor.sortValue, cursor.id); }
  const rows = (await getEnv().DB.prepare(`SELECT ${fields} FROM evidence_artifacts e ${latestOccurrence} WHERE ${conditions.join(" AND ")} ORDER BY e.created_at DESC,e.id DESC LIMIT ?`).bind(...bindings, limit + 1).all<Record<string, unknown>>()).results;
  const page = pageMeta(rows, limit, Number(count?.total || 0), "created_at", "evidenceId");
  return { evidence: page.items, page: page.page };
}
