import { jsonError, requireApiPermission, requireSameOrigin } from "../../../../../lib/server/auth";
import { startJiraOAuth } from "../../../../../lib/server/jira";

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_jira");
    const body = await request.json() as { siteUrl?: string; allowedProjects?: unknown };
    const authorizeUrl = await startJiraOAuth(actor, String(body.siteUrl || ""), body.allowedProjects);
    return Response.json({ authorizeUrl });
  } catch (error) { return jsonError(error); }
}
