import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { createFinding, listFindings } from "../../../lib/server/findings";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try {
    const actor = await requireApiUser(request);
    await enforceRateLimit(request, actor.id, "findings:list", 120, 60);
    const query = new URL(request.url).searchParams;
    return Response.json(await listFindings({ assessmentId: query.get("assessmentId") || "", cursor: query.get("cursor") || undefined, limit: query.get("limit") || undefined, status: query.get("status") || undefined }), { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_findings");
    await enforceRateLimit(request, actor.id, "findings:create", 60, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const body = await request.json() as Record<string, unknown>;
    const allowed = new Set(["assessmentId", "controlId", "description", "dueAt", "evidenceId", "jobId", "ownerId", "severity", "title"]);
    if (Object.keys(body).some((key) => !allowed.has(key))) return Response.json({ error: "Finding request contains unsupported fields." }, { status: 400 });
    return Response.json({ finding: await createFinding(actor, body) }, { status: 201 });
  } catch (error) { return jsonError(error); }
}
