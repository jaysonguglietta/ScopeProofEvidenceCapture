import { jsonError, requireApiUser, requireSameOrigin } from "../../../../lib/server/auth";
import { approveEvidence, readEvidenceBytes } from "../../../../lib/server/evidence";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    await requireApiUser(request);
    const { id } = await context.params;
    const artifact = await readEvidenceBytes(id);
    if (!artifact) return Response.json({ error: "Evidence not found" }, { status: 404 });
    return new Response(artifact.bytes.buffer.slice(artifact.bytes.byteOffset, artifact.bytes.byteOffset + artifact.bytes.byteLength) as ArrayBuffer, { headers: { "content-type": String(artifact.row.content_type), "content-disposition": `attachment; filename="${id}"`, "x-content-type-options": "nosniff", "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}

export async function PATCH(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    requireSameOrigin(request);
    const user = await requireApiUser(request, "reviewer");
    const { id } = await context.params;
    const body = await request.json() as { action?: string };
    if (body.action !== "approve") return Response.json({ error: "Unsupported evidence action" }, { status: 400 });
    const changed = await approveEvidence(id, user);
    return Response.json({ approved: changed });
  } catch (error) { return jsonError(error); }
}
