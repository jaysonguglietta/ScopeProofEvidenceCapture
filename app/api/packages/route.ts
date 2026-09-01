import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { getEnv } from "../../../lib/server/env";
import { buildAssessorPackage, preflightAssessorPackage } from "../../../lib/server/packages";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";
import { decodePageCursor, pageLimit, pageMeta } from "../../../lib/server/pagination";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "package:list", 120, 60);
    const query = new URL(request.url).searchParams;
    const assessmentId = query.get("assessmentId") || "";
    if (assessmentId && !/^asm_[a-f0-9]{32}$/u.test(assessmentId)) return Response.json({ error: "Assessment identifier is invalid." }, { status: 400 });
    const limit = pageLimit(query.get("limit"), 25, 100);
    const cursor = decodePageCursor(query.get("cursor"), /^pkg_[a-f0-9]{32}$/u);
    const conditions = ["(requested_by = ? OR ? = 'admin')"];
    const bindings: unknown[] = [user.id, user.role];
    if (assessmentId) { conditions.push("assessment_id = ?"); bindings.push(assessmentId); }
    if (cursor) { conditions.push("(created_at < ? OR (created_at = ? AND id < ?))"); bindings.push(cursor.sortValue, cursor.sortValue, cursor.id); }
    const countBindings = cursor ? bindings.slice(0, -3) : bindings;
    const countConditions = cursor ? conditions.slice(0, -1) : conditions;
    const total = await getEnv().DB.prepare(`SELECT COUNT(*) AS total FROM export_packages WHERE ${countConditions.join(" AND ")}`).bind(...countBindings).first<{ total: number }>();
    const packages = (await getEnv().DB.prepare(`SELECT id, assessment_id, selection_json, status, sha256, signature, evidence_count, excluded_count, byte_size, error_message, created_at, completed_at, expires_at FROM export_packages WHERE ${conditions.join(" AND ")} ORDER BY created_at DESC, id DESC LIMIT ?`).bind(...bindings, limit + 1).all<Record<string, unknown>>()).results;
    const paged = pageMeta(packages, limit, Number(total?.total || 0), "created_at", "id");
    return Response.json({ packages: paged.items, page: paged.page, preflight: assessmentId ? await preflightAssessorPackage(assessmentId) : null }, { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "export_packages");
    await enforceRateLimit(request, user.id, "package:create", 10, 3_600);
    requireBoundedContentLength(request, 4 * 1024);
    const body = await request.json() as { assessmentId?: string };
    const assessmentId = String(body.assessmentId || "");
    const preflight = await preflightAssessorPackage(assessmentId);
    if (!preflight.ready) return Response.json({ error: "Package preflight failed.", preflight }, { status: 409 });
    return Response.json({ package: await buildAssessorPackage(user, assessmentId), preflight }, { status: 201 });
  } catch (error) { return jsonError(error); }
}
