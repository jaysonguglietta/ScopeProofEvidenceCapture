import { jsonError, requireApiUser } from "../../../../lib/server/auth";
import { productionReadiness } from "../../../../lib/server/readiness";
import { enforceRateLimit } from "../../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try {
    const actor = await requireApiUser(request, "admin");
    await enforceRateLimit(request, actor.id, "admin:readiness", 30, 60);
    const result = await productionReadiness();
    return Response.json(result, { status: result.ready ? 200 : 503, headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}
