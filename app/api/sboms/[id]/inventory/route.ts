import { jsonError, requireApiUser } from "../../../../../lib/server/auth";
import { enforceRateLimit } from "../../../../../lib/server/rate-limit";
import { sbomDetail } from "../../../../../lib/server/sbom-detail";
import { appendAuditEvent } from "../../../../../lib/server/audit";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const actor = await requireApiUser(request);
    await enforceRateLimit(request, actor.id, "sbom:detail", 60, 60);
    const query = new URL(request.url).searchParams;
    const body = await sbomDetail((await context.params).id, query.get("baseline") || undefined, actor);
    await appendAuditEvent(actor, "sbom.inventory_inspected", "sbom_job", body.job.id, { baselineId: body.baseline?.id || null, componentCount: body.components.length });
    return Response.json(body, { headers: { "cache-control": "private, no-store", ...(query.get("download") === "true" ? { "content-disposition": 'attachment; filename="scopeproof-inventory-detail.json"' } : {}) } });
  } catch (error) { return jsonError(error); }
}
