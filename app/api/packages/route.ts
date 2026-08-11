import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { getEnv } from "../../../lib/server/env";
import { buildAssessorPackage } from "../../../lib/server/packages";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    const packages = (await getEnv().DB.prepare("SELECT id, status, sha256, signature, evidence_count, byte_size, error_message, created_at, completed_at, expires_at FROM export_packages WHERE requested_by = ? ORDER BY created_at DESC LIMIT 25").bind(user.id).all<Record<string, unknown>>()).results;
    return Response.json({ packages });
  } catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "export_packages");
    return Response.json({ package: await buildAssessorPackage(user) }, { status: 201 });
  } catch (error) { return jsonError(error); }
}
