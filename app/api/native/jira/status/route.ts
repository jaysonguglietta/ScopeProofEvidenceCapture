import { jsonError } from "../../../../../lib/server/auth";
import { requireCaptureDevice } from "../../../../../lib/server/devices";
import { assertJiraOperator, getJiraConnectionSummary } from "../../../../../lib/server/jira";
import { enforceRateLimit } from "../../../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try {
    const { actor } = await requireCaptureDevice(request);
    assertJiraOperator(actor);
    await enforceRateLimit(request, actor.id, "native-jira-status", 120, 3_600);
    return Response.json({ connection: await getJiraConnectionSummary(actor.id) });
  } catch (error) { return jsonError(error); }
}
