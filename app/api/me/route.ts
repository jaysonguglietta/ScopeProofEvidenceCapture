import { jsonError, requireApiUser } from "../../../lib/server/auth";
import { ensureDefaultCollectors } from "../../../lib/server/jobs";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await ensureDefaultCollectors(user);
    return Response.json({ user });
  } catch (error) { return jsonError(error); }
}
