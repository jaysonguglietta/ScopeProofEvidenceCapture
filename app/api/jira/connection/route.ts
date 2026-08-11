import { jsonError, requireApiPermission, requireSameOrigin } from "../../../../lib/server/auth";
import { disconnectJira, getJiraConnectionSummary, testJiraConnection } from "../../../../lib/server/jira";

export async function GET(request: Request) {
  try {
    const actor = await requireApiPermission(request, "manage_jira");
    return Response.json({ connection: await getJiraConnectionSummary(actor.id) });
  } catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_jira");
    return Response.json({ connection: await testJiraConnection(actor) });
  } catch (error) { return jsonError(error); }
}

export async function DELETE(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_jira");
    return Response.json({ disconnected: await disconnectJira(actor) });
  } catch (error) { return jsonError(error); }
}
