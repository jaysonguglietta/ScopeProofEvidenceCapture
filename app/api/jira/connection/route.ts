import { jsonError, requireApiPermission, requireSameOrigin } from "../../../../lib/server/auth";
import { disconnectJira, getJiraConnectionSummary, testJiraConnection } from "../../../../lib/server/jira";
import { enforceRateLimit } from "../../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try {
    const actor = await requireApiPermission(request, "manage_jira");
    await enforceRateLimit(request, actor.id, "jira:status", 120, 60);
    return Response.json({ connection: await getJiraConnectionSummary(actor.id) });
  } catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_jira");
    await enforceRateLimit(request, actor.id, "jira:test", 20, 3_600);
    return Response.json({ connection: await testJiraConnection(actor) });
  } catch (error) { return jsonError(error); }
}

export async function DELETE(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_jira");
    await enforceRateLimit(request, actor.id, "jira:disconnect", 10, 3_600);
    return Response.json({ disconnected: await disconnectJira(actor) });
  } catch (error) { return jsonError(error); }
}
