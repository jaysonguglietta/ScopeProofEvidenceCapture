import { jsonError, requireApiUser } from "../../../../lib/server/auth";
import { appendAuditEvent } from "../../../../lib/server/audit";
import { readAssessorPackage } from "../../../../lib/server/packages";
import { enforceRateLimit } from "../../../../lib/server/rate-limit";

export async function GET(request: Request, context: { params: Promise<{ id: string }> }) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "package:download", 30, 3_600);
    const { id } = await context.params;
    const result = await readAssessorPackage(id, user);
    if (!result) return Response.json({ error: "Package not found" }, { status: 404 });
    await appendAuditEvent(user, "package.downloaded", "export_package", id, { sha256: result.sha256 });
    return new Response(result.bytes.buffer.slice(result.bytes.byteOffset, result.bytes.byteOffset + result.bytes.byteLength) as ArrayBuffer, { headers: { "content-type": "application/zip", "content-disposition": `attachment; filename="scopeproof-${id}.zip"`, "x-content-type-options": "nosniff", "cache-control": "private, no-store", "x-scopeproof-sha256": result.sha256 } });
  } catch (error) { return jsonError(error); }
}
