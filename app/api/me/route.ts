import { jsonError, requireApiUser } from "../../../lib/server/auth";
import { enforceRateLimit } from "../../../lib/server/rate-limit";
import { ensureDefaultCollectors } from "../../../lib/server/jobs";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "session:read", 120, 60);
    await ensureDefaultCollectors(user);
    return Response.json({ user });
  } catch (error) { return jsonError(error); }
}
