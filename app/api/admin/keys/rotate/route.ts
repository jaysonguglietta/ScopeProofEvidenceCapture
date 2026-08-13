import { jsonError, requireApiPermission, requireSameOrigin } from "../../../../../lib/server/auth";
import { rotateStoredKeys } from "../../../../../lib/server/key-operations";
import { enforceRateLimit, requireBoundedContentLength } from "../../../../../lib/server/rate-limit";

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_users");
    await enforceRateLimit(request, actor.id, "keys:rotate", 10, 3_600);
    requireBoundedContentLength(request, 2_048);
    const body = await request.json().catch(() => ({})) as { limit?: number };
    return Response.json(await rotateStoredKeys(actor, Number(body.limit || 10)));
  } catch (error) { return jsonError(error); }
}
