import { jsonError, requireApiPermission } from "../../../../lib/server/auth";
import { getEnv } from "../../../../lib/server/env";
import { enforceRateLimit } from "../../../../lib/server/rate-limit";
import { collectorScopeCompatibility } from "../../../../lib/collector-scope";
export async function GET(request: Request) {
  try {
    const user = await requireApiPermission(request, "manage_collectors");
    await enforceRateLimit(request, user.id, "collector:scope-preview", 30, 60);
    const id = new URL(request.url).searchParams.get("assessmentId") || "";
    if (!/^asm_[a-f0-9]{32}$/u.test(id)) return Response.json({ error: "Choose a saved assessment." }, { status: 400 });
    const env = getEnv();
    const assessment = await env.DB.prepare("SELECT id,updated_at,controls_json,systems_json FROM assessments WHERE id=?").bind(id).first<{ id: string; updated_at: string; controls_json: string; systems_json: string }>();
    if (!assessment) return Response.json({ error: "Assessment unavailable." }, { status: 404 });
    const previews = collectorScopeCompatibility({ awsRegion: env.AWS_REGION, githubOrganization: env.GITHUB_ORG, oktaOrigin: env.OKTA_BASE_URL, cloudflareZoneIds: env.CLOUDFLARE_ZONE_IDS, browserUrls: env.BROWSER_CAPTURE_URLS }, JSON.parse(assessment.controls_json), JSON.parse(assessment.systems_json));
    return Response.json({ assessmentId: id, assessmentUpdatedAt: assessment.updated_at, previews, checkedAt: new Date().toISOString() }, { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}
