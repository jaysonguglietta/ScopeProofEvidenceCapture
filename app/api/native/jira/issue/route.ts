import { jsonError } from "../../../../../lib/server/auth";
import { requireCaptureDevice } from "../../../../../lib/server/devices";
import { assertJiraOperator, getJiraIssueForUser } from "../../../../../lib/server/jira";
import { enforceRateLimit, requireBoundedContentLength } from "../../../../../lib/server/rate-limit";

export async function POST(request: Request) {
  try {
    const { actor } = await requireCaptureDevice(request);
    assertJiraOperator(actor);
    await enforceRateLimit(request, actor.id, "native-jira-issue", 120, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const body = await request.json() as { issueKey?: string };
    return Response.json({ issue: await getJiraIssueForUser(actor.id, String(body.issueKey || "")) });
  } catch (error) { return jsonError(error); }
}
