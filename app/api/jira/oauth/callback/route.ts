import { requireApiPermission } from "../../../../../lib/server/auth";
import { completeJiraOAuth } from "../../../../../lib/server/jira";

function destination(request: Request, status: "connected" | "error", reason?: string): URL {
  const url = new URL("/", request.url);
  url.searchParams.set("jira", status);
  if (reason) url.searchParams.set("reason", reason);
  return url;
}

export async function GET(request: Request) {
  const url = new URL(request.url);
  if (url.searchParams.get("error")) return Response.redirect(destination(request, "error", "consent_denied"), 303);
  const state = url.searchParams.get("state") || "";
  const code = url.searchParams.get("code") || "";
  try {
    const actor = await requireApiPermission(request, "manage_jira");
    await completeJiraOAuth(actor, state, code);
    return Response.redirect(destination(request, "connected"), 303);
  } catch (error) {
    if (error instanceof Response && [401, 403].includes(error.status)) return error;
    const requestId = crypto.randomUUID();
    console.error("jira_oauth_callback_error", { requestId, error: error instanceof Error ? error.message : String(error) });
    return Response.redirect(destination(request, "error", `callback_${requestId}`), 303);
  }
}
