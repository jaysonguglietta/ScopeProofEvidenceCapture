import { assertPermission, type AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { randomId, stableJson } from "./crypto";
import { getAssessment } from "./assessments";
import { getEnv } from "./env";
import { decodePageCursor, pageLimit, pageMeta, type PageMeta } from "./pagination";

type FindingStatus = "open" | "in_progress" | "accepted" | "resolved" | "closed";
type FindingSeverity = "critical" | "high" | "medium" | "low";

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

export async function listFindings(input: { assessmentId: string; cursor?: string; limit?: string; status?: string }): Promise<{ findings: Array<Record<string, unknown>>; page: PageMeta; summary: Record<string, number> }> {
  if (!/^asm_[a-f0-9]{32}$/u.test(input.assessmentId)) throw failure("A valid assessment is required.");
  const limit = pageLimit(input.limit, 50, 100);
  const cursor = decodePageCursor(input.cursor, /^fnd_[a-f0-9]{32}$/u);
  const statuses = new Set<FindingStatus>(["open", "in_progress", "accepted", "resolved", "closed"]);
  if (input.status && !statuses.has(input.status as FindingStatus)) throw failure("Finding status filter is invalid.");
  const conditions = ["f.assessment_id = ?"];
  const bindings: unknown[] = [input.assessmentId];
  if (input.status) { conditions.push("f.status = ?"); bindings.push(input.status); }
  if (cursor) { conditions.push("(f.created_at < ? OR (f.created_at = ? AND f.id < ?))"); bindings.push(cursor.sortValue, cursor.sortValue, cursor.id); }
  const countBindings = cursor ? bindings.slice(0, -3) : bindings;
  const countConditions = cursor ? conditions.slice(0, -1) : conditions;
  const total = await getEnv().DB.prepare(`SELECT COUNT(*) AS total FROM findings f WHERE ${countConditions.join(" AND ")}`).bind(...countBindings).first<{ total: number }>();
  const rows = (await getEnv().DB.prepare(`SELECT f.*, owner.email AS owner_email, creator.email AS created_by_email
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
  return { findings: paged.items, page: paged.page, summary: Object.fromEntries(Object.entries(aggregate || {}).map(([key, value]) => [key, Number(value || 0)])) };
}

export async function createFinding(actor: AuthenticatedUser, input: Record<string, unknown>): Promise<Record<string, unknown>> {
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
  let dueAt: string | null = null;
  if (input.dueAt) {
    const dueDate = new Date(String(input.dueAt));
    if (!Number.isFinite(dueDate.getTime()) || dueDate.getTime() > Date.now() + 10 * 365 * 24 * 60 * 60_000) throw failure("Finding due date is invalid or unreasonably distant.");
    dueAt = dueDate.toISOString();
  }
  if (title.length < 5 || title.length > 180 || description.length < 20 || description.length > 4_000 || !["critical", "high", "medium", "low"].includes(severity)) throw failure("Finding title, 20–4,000 character description, and severity are required.");
  if (controlId && !(assessment.controls as string[]).includes(controlId)) throw failure("Finding control is outside the assessment scope.", 422);
  if (evidenceId && !/^ev_[a-f0-9]{32}$/u.test(evidenceId)) throw failure("Evidence identifier is invalid.");
  if (jobId && !/^job_[a-f0-9]{32}$/u.test(jobId)) throw failure("Collection job identifier is invalid.");
  if (ownerId && !(await getEnv().DB.prepare("SELECT 1 FROM users WHERE id = ? AND status = 'active'").bind(ownerId).first())) throw failure("Finding owner is not an active user.", 422);
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
  if (!/^fnd_[a-f0-9]{32}$/u.test(id)) throw failure("Finding identifier is invalid.");
  const current = await getEnv().DB.prepare("SELECT * FROM findings WHERE id = ?").bind(id).first<Record<string, unknown>>();
  if (!current) throw failure("Finding not found.", 404);
  const status = String(input.status || current.status) as FindingStatus;
  const ownerId = input.ownerId === undefined ? current.owner_id : String(input.ownerId || "").trim() || null;
  const resolution = input.resolution === undefined ? current.resolution : String(input.resolution || "").trim() || null;
  if (!["open", "in_progress", "accepted", "resolved", "closed"].includes(status)) throw failure("Finding status is invalid.");
  const currentStatus = String(current.status) as FindingStatus;
  if (!findingTransitions[currentStatus]?.has(status)) throw failure(`Finding cannot transition from ${currentStatus} to ${status}.`, 409);
  if (["accepted", "closed"].includes(status) && (status !== currentStatus || input.resolution !== undefined)) {
    assertPermission(actor, "dispose_findings");
  }
  if (["accepted", "resolved", "closed"].includes(status) && (!resolution || String(resolution).length < 20 || String(resolution).length > 4_000)) throw failure("Accepted, resolved, or closed findings require a 20–4,000 character disposition.");
  if (ownerId && !(await getEnv().DB.prepare("SELECT 1 FROM users WHERE id = ? AND status = 'active'").bind(ownerId).first())) throw failure("Finding owner is not active.", 422);
  const now = new Date().toISOString();
  const eventId = randomId("fne");
  const enteringTerminalState = status !== currentStatus && ["resolved", "closed"].includes(status);
  const resolvedBy = enteringTerminalState ? actor.id : (["resolved", "closed"].includes(status) ? current.resolved_by : null);
  const resolvedAt = enteringTerminalState ? now : (["resolved", "closed"].includes(status) ? current.resolved_at : null);
  const [result] = await executeAuditedBatch(actor, `finding.${status}`, "finding", id, { previousStatus: current.status, status, ownerId, resolution }, [
    getEnv().DB.prepare("UPDATE findings SET status = ?, owner_id = ?, resolution = ?, resolved_by = ?, resolved_at = ?, updated_at = ? WHERE id = ? AND status = ? AND updated_at = ?")
      .bind(status, ownerId, resolution, resolvedBy, resolvedAt, now, id, current.status, current.updated_at),
    getEnv().DB.prepare("INSERT INTO finding_events (id, finding_id, action, actor_id, details_json, created_at) SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM findings WHERE id = ? AND status = ? AND updated_at = ?)")
      .bind(eventId, id, status, actor.id, stableJson({ previousStatus: current.status, ownerId, resolution }), now, id, status, now),
  ], { sql: "EXISTS (SELECT 1 FROM finding_events WHERE id = ?)", bindings: [eventId] });
  if (!result.meta.changes) throw failure("Finding changed concurrently. Reload before updating it.", 409);
  return (await getEnv().DB.prepare("SELECT * FROM findings WHERE id = ?").bind(id).first<Record<string, unknown>>())!;
}
