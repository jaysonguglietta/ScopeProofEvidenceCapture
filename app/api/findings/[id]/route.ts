import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../../lib/server/auth";
import { getFindingHistory, updateFinding } from "../../../../lib/server/findings";
import { enforceRateLimit, requireBoundedContentLength } from "../../../../lib/server/rate-limit";
import { workflowBody } from "../../../../lib/server/workflow-validation";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const actor = await requireApiUser(request);
    await enforceRateLimit(request, actor.id, "findings:history", 120, 60);
    const query = new URL(request.url).searchParams;
    return Response.json(await getFindingHistory((await context.params).id, { cursor: query.get("cursor") || undefined, limit: query.get("limit") || undefined }), { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}

export async function PATCH(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_findings");
    await enforceRateLimit(request, actor.id, "findings:update", 120, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const { id } = await context.params;
    const body = workflowBody(await request.json(), ["ownerId", "dueAt", "resolution", "resolutionEvidenceIds", "status", "expectedUpdatedAt"]);
    return Response.json({ finding: await updateFinding(actor, id, body) });
  } catch (error) { return jsonError(error); }
}
