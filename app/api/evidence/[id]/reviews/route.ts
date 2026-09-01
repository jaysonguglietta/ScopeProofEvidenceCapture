import { jsonError, requireApiUser } from "../../../../../lib/server/auth";
import { listEvidenceReviewEvents } from "../../../../../lib/server/evidence";
import { enforceRateLimit } from "../../../../../lib/server/rate-limit";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const actor = await requireApiUser(request);
    await enforceRateLimit(request, actor.id, "evidence:review-history", 120, 60);
    const { id } = await context.params;
    return Response.json({ reviews: await listEvidenceReviewEvents(id) }, { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}
