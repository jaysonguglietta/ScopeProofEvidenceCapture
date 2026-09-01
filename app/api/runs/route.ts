import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { getEnv } from "../../../lib/server/env";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";
import { ensureDefaultCollectors, queueCollection } from "../../../lib/server/jobs";
import { decodePageCursor, pageLimit, pageMeta } from "../../../lib/server/pagination";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "collection:list", 120, 60);
    await ensureDefaultCollectors(user);
    const query = new URL(request.url).searchParams;
    const assessmentId = query.get("assessmentId") || "";
    if (assessmentId && !/^asm_[a-f0-9]{32}$/u.test(assessmentId)) return Response.json({ error: "Assessment identifier is invalid." }, { status: 400 });
    const limit = pageLimit(query.get("limit"), 50, 100);
    const cursor = decodePageCursor(query.get("cursor"), /^job_[a-f0-9]{32}$/u);
    const conditions: string[] = [];
    const bindings: unknown[] = [];
    if (assessmentId) { conditions.push("j.assessment_id = ?"); bindings.push(assessmentId); }
    if (cursor) { conditions.push("(j.created_at < ? OR (j.created_at = ? AND j.id < ?))"); bindings.push(cursor.sortValue, cursor.sortValue, cursor.id); }
    const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
    const baseWhere = assessmentId ? "WHERE j.assessment_id = ?" : "";
    const baseBindings = assessmentId ? [assessmentId] : [];
    const total = await getEnv().DB.prepare(`SELECT COUNT(*) AS total FROM collection_jobs j ${baseWhere}`).bind(...baseBindings).first<{ total: number }>();
    const rows = (await getEnv().DB.prepare(`SELECT j.*, c.display_name, c.provider FROM collection_jobs j JOIN collectors c ON c.id = j.collector_id ${where} ORDER BY j.created_at DESC, j.id DESC LIMIT ?`).bind(...bindings, limit + 1).all<Record<string, unknown>>()).results;
    const summary = await getEnv().DB.prepare(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN j.status IN ('queued','running','retrying') THEN 1 ELSE 0 END) AS active,
      SUM(CASE WHEN j.status = 'completed' THEN 1 ELSE 0 END) AS completed,
      SUM(CASE WHEN j.status = 'partial' THEN 1 ELSE 0 END) AS partial,
      SUM(CASE WHEN j.status = 'failed' THEN 1 ELSE 0 END) AS failed
      FROM collection_jobs j ${baseWhere}`).bind(...baseBindings).first<Record<string, number>>();
    const paged = pageMeta(rows, limit, Number(total?.total || 0), "created_at", "id");
    return Response.json({ runs: paged.items, page: paged.page, summary }, { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "manage_collectors");
    await enforceRateLimit(request, user.id, "collection:queue", 20, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    await ensureDefaultCollectors(user);
    const body = await request.json() as { collectorIds?: string[]; assessmentId?: string };
    const ids = [...new Set(body.collectorIds || [])].filter((id) => /^collector_(aws|github|okta|cloudflare|browser)$/.test(id)).slice(0, 5);
    if (!ids.length) return Response.json({ error: "Select at least one valid collector." }, { status: 400 });
    const assessmentId = String(body.assessmentId || "");
    if (!/^asm_[a-f0-9]{32}$/.test(assessmentId)) return Response.json({ error: "Select an active assessment before collecting evidence." }, { status: 400 });
    const results: Array<{ jobId: string; collectorId: string; status: "queued" }> = [];
    for (const collectorId of ids) {
      const jobId = await queueCollection(collectorId, user, "manual", assessmentId);
      results.push({ jobId, collectorId, status: "queued" });
    }
    return Response.json({ results }, { status: 202, headers: { location: `/api/runs?assessmentId=${encodeURIComponent(assessmentId)}` } });
  } catch (error) { return jsonError(error); }
}
