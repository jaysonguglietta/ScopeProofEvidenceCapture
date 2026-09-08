import { jsonError, requireApiPermission } from "../../../../../lib/server/auth";
import { listFindingResolutionEvidence } from "../../../../../lib/server/finding-resolution";
import { enforceRateLimit } from "../../../../../lib/server/rate-limit";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const actor = await requireApiPermission(request, "manage_findings");
    await enforceRateLimit(request, actor.id, "findings:resolution-evidence", 120, 60);
    const query = new URL(request.url).searchParams;
    return Response.json(await listFindingResolutionEvidence((await context.params).id, { q: query.get("q") || undefined, cursor: query.get("cursor") || undefined, limit: query.get("limit") || undefined }), { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}
