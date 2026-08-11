import { jsonError } from "../../../../../lib/server/auth";
import { requireCaptureDevice } from "../../../../../lib/server/devices";
import { getEnv } from "../../../../../lib/server/env";
import { enforceRateLimit } from "../../../../../lib/server/rate-limit";
import { configuredMacRelease } from "../../../../../lib/server/releases";

export async function GET(request: Request) {
  try {
    const { device } = await requireCaptureDevice(request);
    await enforceRateLimit(request, device.id, "native-release-check", 30, 3_600);
    const env = getEnv();
    return Response.json(configuredMacRelease(env));
  } catch (error) { return jsonError(error); }
}
