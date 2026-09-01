import { jsonError, requireApiPermission, requireSameOrigin } from "../../../../lib/server/auth";
import { updateFinding } from "../../../../lib/server/findings";
import { enforceRateLimit, requireBoundedContentLength } from "../../../../lib/server/rate-limit";

export async function PATCH(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_findings");
    await enforceRateLimit(request, actor.id, "findings:update", 120, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const { id } = await context.params;
    const body = await request.json() as Record<string, unknown>;
    const allowed = new Set(["ownerId", "resolution", "status"]);
    if (Object.keys(body).some((key) => !allowed.has(key))) return Response.json({ error: "Finding update contains unsupported fields." }, { status: 400 });
    return Response.json({ finding: await updateFinding(actor, id, body) });
  } catch (error) { return jsonError(error); }
}
