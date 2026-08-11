import { jsonError, requireApiPermission, requireSameOrigin } from "../../../../../lib/server/auth";
import { startJiraOAuth } from "../../../../../lib/server/jira";
import { enforceRateLimit, requireBoundedContentLength } from "../../../../../lib/server/rate-limit";

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_jira");
    await enforceRateLimit(request, actor.id, "jira:oauth", 10, 3_600);
    requireBoundedContentLength(request, 16 * 1024);
    const body = await request.json() as { siteUrl?: string; allowedProjects?: unknown };
    const authorizeUrl = await startJiraOAuth(actor, String(body.siteUrl || ""), body.allowedProjects);
    return Response.json({ authorizeUrl });
  } catch (error) { return jsonError(error); }
}
