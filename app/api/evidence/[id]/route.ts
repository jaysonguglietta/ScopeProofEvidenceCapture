import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../../lib/server/auth";
import { approveEvidence, readEvidenceBytes } from "../../../../lib/server/evidence";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    await requireApiUser(request);
    const { id } = await context.params;
    const artifact = await readEvidenceBytes(id);
    if (!artifact) return Response.json({ error: "Evidence not found" }, { status: 404 });
    const inline = new URL(request.url).searchParams.get("view") === "inline";
    return new Response(artifact.bytes.buffer.slice(artifact.bytes.byteOffset, artifact.bytes.byteOffset + artifact.bytes.byteLength) as ArrayBuffer, { headers: {
      "content-type": String(artifact.row.content_type),
      "content-disposition": `${inline ? "inline" : "attachment"}; filename="${id}"`,
      "content-security-policy": "default-src 'none'; sandbox",
      "x-content-type-options": "nosniff",
      "x-scopeproof-sha256": String(artifact.row.sha256),
      "cache-control": "private, no-store",
    } });
  } catch (error) { return jsonError(error); }
}

export async function PATCH(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "approve_evidence");
    const { id } = await context.params;
    const body = await request.json() as { action?: string; expectedSha256?: string; rationale?: string; confirmedActualArtifact?: boolean };
    if (body.action !== "approve" || body.confirmedActualArtifact !== true) return Response.json({ error: "Approval requires explicit confirmation that the actual artifact was reviewed." }, { status: 400 });
    const changed = await approveEvidence(id, user, { expectedSha256: String(body.expectedSha256 || ""), rationale: String(body.rationale || "") });
    return Response.json({ approved: changed });
  } catch (error) { return jsonError(error); }
}
