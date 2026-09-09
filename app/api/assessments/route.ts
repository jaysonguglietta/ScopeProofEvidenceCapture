import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { createAssessment, getAssessment, listAssessments, listControlCatalogs, updateAssessment } from "../../../lib/server/assessments";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "assessment:list", 120, 60);
    const query = new URL(request.url).searchParams;
    if (query.has("id")) {
      const assessment = await getAssessment(query.get("id") || "");
      return Response.json(assessment ? { assessment } : { error: "Assessment not found." }, { status: assessment ? 200 : 404, headers: { "cache-control": "private, no-store" } });
    }
    const result = await listAssessments({ cursor: query.get("cursor") || undefined, limit: query.get("limit") || undefined, status: query.get("status") || undefined });
    return Response.json({ ...result, catalogs: await listControlCatalogs() }, { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}

export async function PATCH(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "manage_collectors");
    await enforceRateLimit(request, user.id, "assessment:update", 30, 3_600);
    requireBoundedContentLength(request, 32 * 1024);
    return Response.json({ assessment: await updateAssessment(user, await request.json() as Record<string, unknown>) });
  } catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "manage_collectors");
    await enforceRateLimit(request, user.id, "assessment:create", 20, 3_600);
    requireBoundedContentLength(request, 32 * 1024);
    return Response.json({ assessment: await createAssessment(user, await request.json() as Record<string, unknown>) }, { status: 201 });
  } catch (error) { return jsonError(error); }
}
