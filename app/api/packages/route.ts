import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { getEnv } from "../../../lib/server/env";
import { buildAssessorPackage } from "../../../lib/server/packages";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "package:list", 120, 60);
    const packages = (await getEnv().DB.prepare("SELECT id, status, sha256, signature, evidence_count, byte_size, error_message, created_at, completed_at, expires_at FROM export_packages WHERE requested_by = ? ORDER BY created_at DESC LIMIT 25").bind(user.id).all<Record<string, unknown>>()).results;
    return Response.json({ packages });
  } catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "export_packages");
    await enforceRateLimit(request, user.id, "package:create", 10, 3_600);
    if (request.headers.get("content-length")) requireBoundedContentLength(request, 4 * 1024);
    return Response.json({ package: await buildAssessorPackage(user) }, { status: 201 });
  } catch (error) { return jsonError(error); }
}
