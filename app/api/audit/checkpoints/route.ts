import { jsonError, requireApiUser } from "../../../../lib/server/auth";
import { getLatestAuditCheckpoint } from "../../../../lib/server/checkpoints";
import { enforceRateLimit } from "../../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try {
    const actor = await requireApiUser(request, "auditor");
    await enforceRateLimit(request, actor.id, "audit:checkpoint", 30, 60);
    const checkpoint = await getLatestAuditCheckpoint();
    return Response.json({ checkpoint }, { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}
