import { jsonError } from "../../../../../lib/server/auth";
import { requireCaptureDevice } from "../../../../../lib/server/devices";
import { assertJiraOperator, getJiraConnectionSummary } from "../../../../../lib/server/jira";

export async function GET(request: Request) {
  try {
    const { actor } = await requireCaptureDevice(request);
    assertJiraOperator(actor);
    return Response.json({ connection: await getJiraConnectionSummary(actor.id) });
  } catch (error) { return jsonError(error); }
}
