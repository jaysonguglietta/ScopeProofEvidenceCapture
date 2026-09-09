import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { collectorConfiguration, type CollectorProvider } from "../../../lib/server/collectors";
import { getEnv } from "../../../lib/server/env";
import { ensureDefaultCollectors } from "../../../lib/server/jobs";
import { executeAuditedBatch } from "../../../lib/server/audit";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";
import { nextCollectorRun, nextWorkflowTimestamp, normalizeCollectorSchedule, workflowBody } from "../../../lib/server/workflow-validation";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "collector:list", 120, 60);
    await ensureDefaultCollectors(user);
    const rows = (await getEnv().DB.prepare("SELECT id, provider, display_name, enabled, schedule_cron, scheduled_assessment_id, status, last_run_at, last_error, updated_at FROM collectors ORDER BY provider").all<Record<string, unknown>>()).results;
    return Response.json({ collectors: rows.map((row: Record<string, unknown>) => ({ ...row, nextRunAt: row.enabled && row.scheduled_assessment_id ? nextCollectorRun(row.schedule_cron) : null, configuration: collectorConfiguration(String(row.provider) as CollectorProvider) })), schedulePolicy: "UTC; at most hourly; only the explicitly selected active assessment; no fallback when scope closes. Minutes 0, 15, 30 and 45 align with the deployed 15-minute scheduler tick." }, { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}

export async function PATCH(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "manage_collectors");
    await enforceRateLimit(request, user.id, "collector:update", 30, 3_600);
    requireBoundedContentLength(request, 16 * 1024);
    const body = workflowBody(await request.json(), ["id", "enabled", "scheduleCron", "scheduledAssessmentId", "expectedUpdatedAt"]);
    if (typeof body.id !== "string" || !/^collector_(aws|github|okta|cloudflare|browser)$/u.test(body.id)) return Response.json({ error: "A supported collector id is required." }, { status: 400 });
    if (body.enabled !== undefined && typeof body.enabled !== "boolean") return Response.json({ error: "Collector enabled must be a boolean." }, { status: 400 });
    if (body.enabled === undefined && body.scheduleCron === undefined && body.scheduledAssessmentId === undefined) return Response.json({ error: "Choose an enabled state, schedule or assessment to update." }, { status: 400 });
    const current = await getEnv().DB.prepare("SELECT id, provider, enabled, schedule_cron, scheduled_assessment_id, updated_at FROM collectors WHERE id = ?").bind(body.id).first<Record<string, unknown>>();
    if (!current) return Response.json({ error: "Collector not found." }, { status: 404 });
    if (body.expectedUpdatedAt !== undefined && body.expectedUpdatedAt !== current.updated_at) return Response.json({ error: "Collector changed since it was opened. Reload before saving." }, { status: 409 });
    const enabled = body.enabled === undefined ? Number(current.enabled) : Number(body.enabled);
    const schedule = body.scheduleCron === undefined ? current.schedule_cron : normalizeCollectorSchedule(body.scheduleCron);
    if (enabled && schedule) normalizeCollectorSchedule(schedule);
    const assessmentId = body.scheduledAssessmentId === undefined ? current.scheduled_assessment_id : body.scheduledAssessmentId;
    if (assessmentId !== null && (typeof assessmentId !== "string" || !/^asm_[a-f0-9]{32}$/u.test(assessmentId))) return Response.json({ error: "Choose an explicit scheduled assessment or clear it." }, { status: 400 });
    if (enabled && schedule && (!assessmentId || !(await getEnv().DB.prepare("SELECT 1 FROM assessments WHERE id = ? AND status = 'active' AND scope_mode = 'explicit' AND catalog_id IS NOT NULL AND json_array_length(systems_json) > 0 AND json_array_length(controls_json) > 0").bind(assessmentId).first()))) return Response.json({ error: "Scheduled collection requires an explicitly selected active assessment with non-empty catalog controls and systems. No other assessment is selected automatically." }, { status: 409 });
    const updatedAt = nextWorkflowTimestamp(current.updated_at);
    const [result] = await executeAuditedBatch(user, "collector.updated", "collector", body.id, { enabled, scheduleCron: schedule, scheduledAssessmentId: assessmentId, previousScheduledAssessmentId: current.scheduled_assessment_id, previousEnabled: current.enabled, previousScheduleCron: current.schedule_cron }, [
      getEnv().DB.prepare("UPDATE collectors SET enabled = ?, schedule_cron = ?, scheduled_assessment_id = ?, updated_at = ? WHERE id = ? AND updated_at = ? AND (? = 0 OR ? IS NULL OR EXISTS (SELECT 1 FROM assessments WHERE id = ? AND status = 'active' AND scope_mode = 'explicit' AND catalog_id IS NOT NULL AND json_array_length(systems_json) > 0 AND json_array_length(controls_json) > 0))").bind(enabled, schedule, assessmentId, updatedAt, body.id, current.updated_at, enabled, schedule, assessmentId),
    ], { sql: "EXISTS (SELECT 1 FROM collectors WHERE id = ? AND updated_at = ?)", bindings: [body.id, updatedAt] });
    if (!result.meta.changes) return Response.json({ error: "Collector changed concurrently. Reload before saving." }, { status: 409 });
    return Response.json({ updated: true, actor: user.id, collector: { ...current, enabled, schedule_cron: schedule, scheduled_assessment_id: assessmentId, updated_at: updatedAt } });
  } catch (error) { return jsonError(error); }
}
