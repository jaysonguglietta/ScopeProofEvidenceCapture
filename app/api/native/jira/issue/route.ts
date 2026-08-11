import { jsonError } from "../../../../../lib/server/auth";
import { requireCaptureDevice } from "../../../../../lib/server/devices";
import { assertJiraOperator, getJiraIssueForUser } from "../../../../../lib/server/jira";

export async function POST(request: Request) {
  try {
    const { actor } = await requireCaptureDevice(request);
    assertJiraOperator(actor);
    const body = await request.json() as { issueKey?: string };
    return Response.json({ issue: await getJiraIssueForUser(actor.id, String(body.issueKey || "")) });
  } catch (error) { return jsonError(error); }
}
