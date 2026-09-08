import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { listEvidenceRequirements, reviseEvidenceRequirement } from "../../../lib/server/evidence-requirements";
import { getEnv } from "../../../lib/server/env";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try {
    const actor = await requireApiUser(request);
    await enforceRateLimit(request, actor.id, "requirements:read", 60, 60);
    const assessmentId = new URL(request.url).searchParams.get("assessmentId") || "";
    const result = await listEvidenceRequirements(assessmentId);
    const canEdit = ["compliance_lead", "admin"].includes(actor.role);
    const owners = canEdit ? (await getEnv().DB.prepare("SELECT id, email FROM users WHERE status = 'active' ORDER BY email LIMIT 1000").all()).results : [];
    return Response.json({ ...result, owners, canEdit }, { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_collectors");
    await enforceRateLimit(request, actor.id, "requirements:revise", 60, 3600);
    requireBoundedContentLength(request, 4096);
    return Response.json(await reviseEvidenceRequirement(actor, await request.json() as Record<string, unknown>), { status: 201 });
  } catch (error) { return jsonError(error); }
}
