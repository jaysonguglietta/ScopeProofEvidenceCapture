import { jsonError, requireApiPermission } from "../../../../lib/server/auth";
import { listFindingAssignees } from "../../../../lib/server/findings";
import { enforceRateLimit } from "../../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try {
    const actor = await requireApiPermission(request, "manage_findings");
    await enforceRateLimit(request, actor.id, "findings:assignees", 120, 60);
    return Response.json(await listFindingAssignees(actor, new URL(request.url).searchParams.get("q") || ""), { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}
