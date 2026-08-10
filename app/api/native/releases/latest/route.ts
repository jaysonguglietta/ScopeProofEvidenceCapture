import { jsonError } from "../../../../../lib/server/auth";
import { requireCaptureDevice } from "../../../../../lib/server/devices";
import { getEnv } from "../../../../../lib/server/env";

export async function GET(request: Request) {
  try {
    await requireCaptureDevice(request);
    const env = getEnv();
    return Response.json({
      version: env.MACOS_LATEST_VERSION || "1.1.0",
      downloadUrl: env.MACOS_RELEASE_URL || null,
      sha256: env.MACOS_RELEASE_SHA256 || null,
      notes: env.MACOS_RELEASE_NOTES || "Capture safety, device upload, guided sessions, and Help improvements.",
    });
  } catch (error) { return jsonError(error); }
}
