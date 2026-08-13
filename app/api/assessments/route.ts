import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { createAssessment, listAssessments, updateAssessment } from "../../../lib/server/assessments";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "assessment:list", 120, 60);
    return Response.json({ assessments: await listAssessments() });
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
