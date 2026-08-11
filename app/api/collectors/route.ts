import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { collectorConfiguration, type CollectorProvider } from "../../../lib/server/collectors";
import { getEnv } from "../../../lib/server/env";
import { ensureDefaultCollectors } from "../../../lib/server/jobs";
import { executeAuditedBatch } from "../../../lib/server/audit";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await ensureDefaultCollectors(user);
    const rows = (await getEnv().DB.prepare("SELECT id, provider, display_name, enabled, schedule_cron, status, last_run_at, last_error FROM collectors ORDER BY provider").all<Record<string, unknown>>()).results;
    return Response.json({ collectors: rows.map((row: Record<string, unknown>) => ({ ...row, configuration: collectorConfiguration(String(row.provider) as CollectorProvider) })) });
  } catch (error) { return jsonError(error); }
}

export async function PATCH(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "manage_collectors");
    const body = await request.json() as { id?: string; enabled?: boolean; scheduleCron?: string };
    if (!body.id || (body.scheduleCron && !/^(\*|\d{1,2}) (\*|\d{1,2}) \* \* (\*|[0-6])$/.test(body.scheduleCron))) return Response.json({ error: "Collector id and a supported five-field UTC cron are required." }, { status: 400 });
    const updatedAt = new Date().toISOString();
    const [result] = await executeAuditedBatch(user, "collector.updated", "collector", body.id, { enabled: body.enabled ?? null, scheduleCron: body.scheduleCron ?? null }, [
      getEnv().DB.prepare("UPDATE collectors SET enabled = COALESCE(?, enabled), schedule_cron = COALESCE(?, schedule_cron), updated_at = ? WHERE id = ?").bind(typeof body.enabled === "boolean" ? Number(body.enabled) : null, body.scheduleCron || null, updatedAt, body.id),
    ], { sql: "EXISTS (SELECT 1 FROM collectors WHERE id = ? AND updated_at = ?)", bindings: [body.id, updatedAt] });
    if (!result.meta.changes) return Response.json({ error: "Collector not found" }, { status: 404 });
    return Response.json({ updated: true, actor: user.id });
  } catch (error) { return jsonError(error); }
}
