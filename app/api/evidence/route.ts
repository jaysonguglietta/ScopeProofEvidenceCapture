import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { listEvidence, storeEvidence, type ArtifactType } from "../../../lib/server/evidence";

export async function GET(request: Request) {
  try { await requireApiUser(request); return Response.json({ evidence: await listEvidence() }); }
  catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "collect_evidence");
    const form = await request.formData();
    const title = String(form.get("title") || "").trim().slice(0, 180);
    const controlId = String(form.get("control") || "").trim().slice(0, 32);
    const system = String(form.get("system") || "").trim().slice(0, 180);
    const description = String(form.get("description") || "").trim().slice(0, 2000);
    const type = String(form.get("type") || "code").toLowerCase() as ArtifactType;
    if (!title || !controlId || !system || !["screenshot", "code", "configuration", "report"].includes(type)) return Response.json({ error: "Title, control, system, and a valid evidence type are required." }, { status: 400 });
    const attachment = form.get("attachment");
    let contentType = "text/plain";
    let bytes = new TextEncoder().encode(String(form.get("code") || description));
    if (attachment instanceof File && attachment.size) {
      if (attachment.size > 10 * 1024 * 1024) return Response.json({ error: "Evidence files are limited to 10 MB." }, { status: 413 });
      if (!/^(text\/|application\/(json|xml|yaml|x-yaml))/.test(attachment.type)) return Response.json({ error: "Manual binary evidence is blocked because it cannot be reliably scanned. Use the browser collector for screenshots." }, { status: 415 });
      contentType = attachment.type || "text/plain";
      bytes = new Uint8Array(await attachment.arrayBuffer());
    }
    const result = await storeEvidence({ controlId, title, description, type, source: "Manual submission", system, contentType, bytes, createdBy: user });
    return Response.json(result, { status: result.deduplicated ? 200 : 201 });
  } catch (error) { return jsonError(error); }
}
