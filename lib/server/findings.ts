import { assertPermission, type AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { randomId, stableJson } from "./crypto";
import { getAssessment } from "./assessments";
import { getEnv } from "./env";
import { decodePageCursor, pageLimit, pageMeta, type PageMeta } from "./pagination";
import { nextWorkflowTimestamp, normalizeFindingDueAt, workflowBody } from "./workflow-validation";
import { findingEvidenceFence, parseFindingEvidence, resolveFindingEvidence } from "./finding-resolution";

type FindingStatus = "open" | "in_progress" | "accepted" | "resolved" | "closed";
type FindingSeverity = "critical" | "high" | "medium" | "low";
const reassignmentNeededSql = "f.status IN ('open','in_progress') AND f.owner_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM users eligible_owner WHERE eligible_owner.id = f.owner_id AND eligible_owner.status = 'active' AND eligible_owner.role IN ('admin','compliance_lead','reviewer'))";
function findingResponse(row: Record<string, unknown>): Record<string, unknown> {
  const clean = { ...row }; delete clean.resolution_evidence_json;
  return { ...clean, resolutionEvidence: parseFindingEvidence(row.resolution_evidence_json), reassignment_needed: Boolean(row.reassignment_needed) };
}

const findingTransitions: Record<FindingStatus, ReadonlySet<FindingStatus>> = {
  open: new Set(["open", "in_progress", "accepted", "resolved"]),
  in_progress: new Set(["open", "in_progress", "accepted", "resolved"]),
  accepted: new Set(["accepted", "in_progress", "closed"]),
  resolved: new Set(["resolved", "in_progress", "closed"]),
  closed: new Set(["closed"]),
};

function failure(message: string, status = 400): Response {
  return new Response(JSON.stringify({ error: message }), { status, headers: { "content-type": "application/json" } });
}

export async function listFindings(input: { assessmentId: string; cursor?: string; limit?: string; status?: string; ownerId?: string; severity?: string; due?: string; q?: string }): Promise<{ findings: Array<Record<string, unknown>>; page: PageMeta; summary: Record<string, number> }> {
  if (!/^asm_[a-f0-9]{32}$/u.test(input.assessmentId)) throw failure("A valid assessment is required.");
  const limit = pageLimit(input.limit, 50, 100);
  const cursor = decodePageCursor(input.cursor, /^fnd_[a-f0-9]{32}$/u);
  const statuses = new Set<FindingStatus>(["open", "in_progress", "accepted", "resolved", "closed"]);
  if (input.status && !statuses.has(input.status as FindingStatus)) throw failure("Finding status filter is invalid.");
  const conditions = ["f.assessment_id = ?"];
  const bindings: unknown[] = [input.assessmentId];
  if (input.status) { conditions.push("f.status = ?"); bindings.push(input.status); }
  if (input.severity) {
    if (!["critical", "high", "medium", "low"].includes(input.severity)) throw failure("Finding severity filter is invalid.");
    conditions.push("f.severity = ?"); bindings.push(input.severity);
  }
  if (input.ownerId === "unassigned") conditions.push("f.owner_id IS NULL");
  else if (input.ownerId === "reassignment_needed") conditions.push(reassignmentNeededSql);
  else if (input.ownerId) {
    if (!/^[A-Za-z0-9_.:-]{3,200}$/u.test(input.ownerId)) throw failure("Finding owner filter is invalid.");
    conditions.push("f.owner_id = ?"); bindings.push(input.ownerId);
  }
  if (input.due === "overdue") { conditions.push("f.due_at < ? AND f.status IN ('open','in_progress')"); bindings.push(new Date().toISOString()); }
  else if (input.due === "undated") conditions.push("f.due_at IS NULL");
  else if (input.due) throw failure("Finding due-date filter is invalid.");
  if (input.q) {
    const query = input.q.trim();
    if (query.length > 120) throw failure("Finding search is limited to 120 characters.");
    conditions.push("(f.title LIKE ? ESCAPE '\\' OR f.description LIKE ? ESCAPE '\\')");
    const pattern = `%${query.replace(/[\\%_]/gu, "\\$&")}%`; bindings.push(pattern, pattern);
  }
  if (cursor) { conditions.push("(f.created_at < ? OR (f.created_at = ? AND f.id < ?))"); bindings.push(cursor.sortValue, cursor.sortValue, cursor.id); }
  const countBindings = cursor ? bindings.slice(0, -3) : bindings;
  const countConditions = cursor ? conditions.slice(0, -1) : conditions;
  const total = await getEnv().DB.prepare(`SELECT COUNT(*) AS total FROM findings f WHERE ${countConditions.join(" AND ")}`).bind(...countBindings).first<{ total: number }>();
  const rows = (await getEnv().DB.prepare(`SELECT f.*, owner.email AS owner_email, owner.status AS owner_status, owner.role AS owner_role, (${reassignmentNeededSql}) AS reassignment_needed, creator.email AS created_by_email
    FROM findings f LEFT JOIN users owner ON owner.id = f.owner_id LEFT JOIN users creator ON creator.id = f.created_by
    WHERE ${conditions.join(" AND ")} ORDER BY f.created_at DESC, f.id DESC LIMIT ?`).bind(...bindings, limit + 1).all<Record<string, unknown>>()).results;
  const aggregate = await getEnv().DB.prepare(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open,
      SUM(CASE WHEN status = 'in_progress' THEN 1 ELSE 0 END) AS in_progress,
      SUM(CASE WHEN status = 'accepted' THEN 1 ELSE 0 END) AS accepted,
      SUM(CASE WHEN status = 'resolved' THEN 1 ELSE 0 END) AS resolved,
      SUM(CASE WHEN severity = 'critical' AND status IN ('open','in_progress') THEN 1 ELSE 0 END) AS critical,
      SUM(CASE WHEN severity = 'high' AND status IN ('open','in_progress') THEN 1 ELSE 0 END) AS high
    FROM findings WHERE assessment_id = ?`).bind(input.assessmentId).first<Record<string, number>>();
  const paged = pageMeta(rows, limit, Number(total?.total || 0), "created_at", "id");
  return { findings: paged.items.map(findingResponse), page: paged.page, summary: Object.fromEntries(Object.entries(aggregate || {}).map(([key, value]) => [key, Number(value || 0)])) };
}

export async function createFinding(actor: AuthenticatedUser, input: Record<string, unknown>): Promise<Record<string, unknown>> {
  assertPermission(actor, "manage_findings");
  workflowBody(input, ["assessmentId", "controlId", "description", "dueAt", "evidenceId", "jobId", "ownerId", "severity", "title"]);
  const assessmentId = String(input.assessmentId || "");
  const assessment = await getAssessment(assessmentId);
  if (!assessment || assessment.status === "closed") throw failure("Findings require an open assessment.", 409);
  const title = String(input.title || "").trim();
  const description = String(input.description || "").trim();
  const severity = String(input.severity || "medium") as FindingSeverity;
  const controlId = String(input.controlId || "").trim() || null;
  const evidenceId = String(input.evidenceId || "").trim() || null;
  const jobId = String(input.jobId || "").trim() || null;
  const ownerId = String(input.ownerId || "").trim() || null;
  const dueAt = input.dueAt === undefined ? null : normalizeFindingDueAt(input.dueAt);
  if (title.length < 5 || title.length > 180 || description.length < 20 || description.length > 4_000 || !["critical", "high", "medium", "low"].includes(severity)) throw failure("Finding title, 20–4,000 character description, and severity are required.");
  if (controlId && !(assessment.controls as string[]).includes(controlId)) throw failure("Finding control is outside the assessment scope.", 422);
  if (evidenceId && !/^ev_[a-f0-9]{32}$/u.test(evidenceId)) throw failure("Evidence identifier is invalid.");
  if (jobId && !/^job_[a-f0-9]{32}$/u.test(jobId)) throw failure("Collection job identifier is invalid.");
  if (ownerId && !(await getEnv().DB.prepare("SELECT 1 FROM users WHERE id = ? AND status = 'active' AND role IN ('admin','compliance_lead','reviewer')").bind(ownerId).first())) throw failure("Finding owner must be an active user permitted to manage findings.", 422);
  if (evidenceId && !(await getEnv().DB.prepare("SELECT 1 FROM evidence_artifacts WHERE id = ? AND assessment_id = ?").bind(evidenceId, assessmentId).first())) throw failure("Evidence is not part of this assessment.", 422);
  if (jobId && !(await getEnv().DB.prepare("SELECT 1 FROM collection_jobs WHERE id = ? AND assessment_id = ?").bind(jobId, assessmentId).first())) throw failure("Collection job is not part of this assessment.", 422);
  const id = randomId("fnd");
  const eventId = randomId("fne");
  const now = new Date().toISOString();
  await executeAuditedBatch(actor, "finding.created", "finding", id, { assessmentId, controlId, evidenceId, jobId, severity, ownerId, dueAt }, [
    getEnv().DB.prepare("INSERT INTO findings (id, assessment_id, control_id, evidence_id, job_id, title, description, severity, owner_id, due_at, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(id, assessmentId, controlId, evidenceId, jobId, title, description, severity, ownerId, dueAt, actor.id, now, now),
    getEnv().DB.prepare("INSERT INTO finding_events (id, finding_id, action, actor_id, details_json, created_at) SELECT ?, ?, 'created', ?, ?, ? WHERE EXISTS (SELECT 1 FROM findings WHERE id = ?)")
      .bind(eventId, id, actor.id, stableJson({ severity, ownerId, dueAt }), now, id),
  ]);
  return (await getEnv().DB.prepare("SELECT * FROM findings WHERE id = ?").bind(id).first<Record<string, unknown>>())!;
}

export async function updateFinding(actor: AuthenticatedUser, id: string, input: Record<string, unknown>): Promise<Record<string, unknown>> {
  assertPermission(actor, "manage_findings");
  workflowBody(input, ["ownerId", "dueAt", "resolution", "resolutionEvidenceIds", "status", "expectedUpdatedAt"]);
  if (!/^fnd_[a-f0-9]{32}$/u.test(id)) throw failure("Finding identifier is invalid.");
  const current = await getEnv().DB.prepare("SELECT * FROM findings WHERE id = ?").bind(id).first<Record<string, unknown>>();
  if (!current) throw failure("Finding not found.", 404);
  if (input.expectedUpdatedAt !== undefined && input.expectedUpdatedAt !== current.updated_at) throw failure("Finding changed since it was opened. Reload before saving.", 409);
  const assessment = await getAssessment(String(current.assessment_id));
  if (!assessment || assessment.status === "closed" || current.status === "closed") throw failure("Closed findings and assessments are immutable.", 409);
  const status = String(input.status || current.status) as FindingStatus;
  const ownerId = input.ownerId === undefined ? current.owner_id : String(input.ownerId || "").trim() || null;
  const resolution = input.resolution === undefined ? current.resolution : String(input.resolution || "").trim() || null;
  const dueAt = input.dueAt === undefined ? current.due_at : normalizeFindingDueAt(input.dueAt);
  if (resolution && String(resolution).length > 4_000) throw failure("Disposition is limited to 4,000 characters.");
  if (!["open", "in_progress", "accepted", "resolved", "closed"].includes(status)) throw failure("Finding status is invalid.");
  const currentStatus = String(current.status) as FindingStatus;
  if (!findingTransitions[currentStatus]?.has(status)) throw failure(`Finding cannot transition from ${currentStatus} to ${status}.`, 409);
  if (["accepted", "closed"].includes(status) && (status !== currentStatus || input.resolution !== undefined)) {
    assertPermission(actor, "dispose_findings");
  }
  if (["accepted", "resolved", "closed"].includes(status) && (!resolution || String(resolution).length < 20 || String(resolution).length > 4_000)) throw failure("Accepted, resolved, or closed findings require a 20–4,000 character disposition.");
  if (ownerId && ownerId !== current.owner_id && !(await getEnv().DB.prepare("SELECT 1 FROM users WHERE id = ? AND status = 'active' AND role IN ('admin','compliance_lead','reviewer')").bind(ownerId).first())) throw failure("Finding owner must be an active user permitted to manage findings.", 422);
  const now = nextWorkflowTimestamp(current.updated_at);
  const previousEvidence = parseFindingEvidence(current.resolution_evidence_json);
  const needsEvidence = status === "resolved" || (status === "closed" && currentStatus === "resolved");
  if (input.resolutionEvidenceIds !== undefined && !needsEvidence) throw failure("Evidence links belong to remediation resolution, not risk acceptance or reopening.");
  const revalidateEvidence = needsEvidence && (status !== currentStatus || input.resolutionEvidenceIds !== undefined || resolution !== current.resolution);
  const resolutionEvidence = revalidateEvidence ? await resolveFindingEvidence(String(current.assessment_id), current.control_id, input.resolutionEvidenceIds ?? previousEvidence.map((item) => item.evidenceId), now) : needsEvidence ? previousEvidence : [];
  if (status === currentStatus && ownerId === current.owner_id && dueAt === current.due_at && resolution === current.resolution && input.resolutionEvidenceIds === undefined) return findingResponse(current);
  const proofFence = findingEvidenceFence(String(current.assessment_id), current.control_id, revalidateEvidence ? resolutionEvidence : [], now);
  const eventId = randomId("fne");
  const enteringTerminalState = status !== currentStatus && ["resolved", "closed"].includes(status);
  const resolvedBy = enteringTerminalState ? actor.id : (["resolved", "closed"].includes(status) ? current.resolved_by : null);
  const resolvedAt = enteringTerminalState ? now : (["resolved", "closed"].includes(status) ? current.resolved_at : null);
  const details = { previousStatus: current.status, status, previousOwnerId: current.owner_id, ownerId, previousDueAt: current.due_at, dueAt, previousResolution: current.resolution, resolution, previousResolutionEvidence: previousEvidence, resolutionEvidence };
  const [result] = await executeAuditedBatch(actor, `finding.${status === currentStatus ? "updated" : status}`, "finding", id, details, [
    getEnv().DB.prepare(`UPDATE findings SET status = ?, owner_id = ?, due_at = ?, resolution = ?, resolution_evidence_json = ?, resolved_by = ?, resolved_at = ?, updated_at = ? WHERE id = ? AND status = ? AND updated_at = ? AND EXISTS (SELECT 1 FROM assessments WHERE id = findings.assessment_id AND status != 'closed') AND ${proofFence.sql}`)
      .bind(status, ownerId, dueAt, resolution, stableJson(resolutionEvidence), resolvedBy, resolvedAt, now, id, current.status, current.updated_at, ...proofFence.bindings),
    getEnv().DB.prepare("INSERT INTO finding_events (id, finding_id, action, actor_id, details_json, created_at) SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM findings WHERE id = ? AND status = ? AND updated_at = ?)")
      .bind(eventId, id, status === currentStatus ? "updated" : status, actor.id, stableJson(details), now, id, status, now),
  ], { sql: "EXISTS (SELECT 1 FROM finding_events WHERE id = ?)", bindings: [eventId] });
  if (!result.meta.changes) throw failure("Finding changed concurrently. Reload before updating it.", 409);
  return findingResponse((await getEnv().DB.prepare("SELECT * FROM findings WHERE id = ?").bind(id).first<Record<string, unknown>>())!);
}

export async function getFindingHistory(id: string, input: { cursor?: string; limit?: string } = {}) {
  if (!/^fnd_[a-f0-9]{32}$/u.test(id)) throw failure("Finding identifier is invalid.");
  const finding = await getEnv().DB.prepare(`SELECT f.*, owner.email AS owner_email, owner.status AS owner_status, owner.role AS owner_role, (${reassignmentNeededSql}) AS reassignment_needed FROM findings f LEFT JOIN users owner ON owner.id = f.owner_id WHERE f.id = ?`).bind(id).first<Record<string, unknown>>();
  if (!finding) throw failure("Finding not found.", 404);
  const limit = pageLimit(input.limit, 25, 100);
  const cursor = decodePageCursor(input.cursor, /^fne_[a-f0-9]{32}$/u);
  const conditions = ["e.finding_id = ?"];
  const bindings: unknown[] = [id];
  if (cursor) { conditions.push("(e.created_at < ? OR (e.created_at = ? AND e.id < ?))"); bindings.push(cursor.sortValue, cursor.sortValue, cursor.id); }
  const total = await getEnv().DB.prepare("SELECT COUNT(*) AS total FROM finding_events WHERE finding_id = ?").bind(id).first<{ total: number }>();
  const rows = (await getEnv().DB.prepare(`SELECT e.*, actor.email AS actor_email FROM finding_events e LEFT JOIN users actor ON actor.id = e.actor_id WHERE ${conditions.join(" AND ")} ORDER BY e.created_at DESC, e.id DESC LIMIT ?`).bind(...bindings, limit + 1).all<Record<string, unknown>>()).results;
  const paged = pageMeta(rows, limit, Number(total?.total || 0), "created_at", "id");
  return { finding: findingResponse(finding), events: paged.items.map((row) => { const clean = { ...row }; delete clean.details_json; return { ...clean, details: JSON.parse(String(row.details_json || "{}")) }; }), page: paged.page };
}

export async function listFindingAssignees(actor: AuthenticatedUser, query = "") {
  assertPermission(actor, "manage_findings");
  if (query.length > 120) throw failure("Assignee search is limited to 120 characters.");
  const pattern = `%${query.trim().replace(/[\\%_]/gu, "\\$&")}%`;
  const rows = (await getEnv().DB.prepare("SELECT id, display_name, email FROM users WHERE status = 'active' AND role IN ('admin','compliance_lead','reviewer') AND (email LIKE ? ESCAPE '\\' OR display_name LIKE ? ESCAPE '\\') ORDER BY email, id LIMIT 101").bind(pattern, pattern).all<Record<string, unknown>>()).results;
  return { assignees: rows.slice(0, 100), hasMore: rows.length > 100 };
}
