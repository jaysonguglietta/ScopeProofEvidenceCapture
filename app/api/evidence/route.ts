import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { listEvidence, storeEvidence, type ArtifactType } from "../../../lib/server/evidence";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";
import { SAFE_MANUAL_EVIDENCE_TYPES } from "../../../lib/server/evidence-response";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "evidence:list", 120, 60);
    const query = new URL(request.url).searchParams;
    return Response.json(await listEvidence({
      assessmentId: query.get("assessmentId") || undefined,
      cursor: query.get("cursor") || undefined,
      limit: query.get("limit") || undefined,
      status: query.get("status") || undefined,
      type: query.get("type") || undefined,
      query: query.get("q") || undefined,
    }), { headers: { "cache-control": "private, no-store" } });
  }
  catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "collect_evidence");
    await enforceRateLimit(request, user.id, "evidence:create", 20, 3_600);
    requireBoundedContentLength(request, 11 * 1024 * 1024);
    const form = await request.formData();
    const title = String(form.get("title") || "").trim().slice(0, 180);
    const controlId = String(form.get("control") || "").trim().slice(0, 32);
    const system = String(form.get("system") || "").trim().slice(0, 180);
    const description = String(form.get("description") || "").trim().slice(0, 2000);
    const type = String(form.get("type") || "code").toLowerCase() as ArtifactType;
    const assessmentId = String(form.get("assessmentId") || "").trim();
    if (!title || !controlId || !system || !["code", "configuration", "report"].includes(type)) return Response.json({ error: "Title, control, system, and a scannable text evidence type are required. Screenshots must use a digest-bound capture workflow." }, { status: 400 });
    const attachment = form.get("attachment");
    let contentType = "text/plain";
    let bytes = new TextEncoder().encode(String(form.get("code") || description));
    if (attachment instanceof File && attachment.size) {
      if (attachment.size > 10 * 1024 * 1024) return Response.json({ error: "Evidence files are limited to 10 MB." }, { status: 413 });
      const requestedType = attachment.type.trim().toLowerCase();
      if (!SAFE_MANUAL_EVIDENCE_TYPES.has(requestedType)) return Response.json({ error: "Only plain text, CSV, Markdown, JSON, XML, or YAML evidence can be manually uploaded. Active browser content and binary files are blocked." }, { status: 415 });
      contentType = requestedType;
      bytes = new Uint8Array(await attachment.arrayBuffer());
    }
    if (!/^asm_[a-f0-9]{32}$/.test(assessmentId)) return Response.json({ error: "Select an open assessment for this evidence." }, { status: 400 });
    const result = await storeEvidence({ controlId, title, description, type, source: "Manual submission", system, contentType, bytes, createdBy: user, assessmentId, framework: String(form.get("framework") || "PCI DSS 4.0.1").slice(0, 100), assessmentPeriod: String(form.get("assessmentPeriod") || "").slice(0, 100) });
    return Response.json(result, { status: result.deduplicated ? 200 : 201 });
  } catch (error) { return jsonError(error); }
}
