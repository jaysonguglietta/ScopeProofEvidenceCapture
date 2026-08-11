import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { getEnv } from "../../../lib/server/env";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";
import { ensureDefaultCollectors, processJob, queueCollection } from "../../../lib/server/jobs";

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "collection:list", 120, 60);
    await ensureDefaultCollectors(user);
    const runs = (await getEnv().DB.prepare(`SELECT j.*, c.display_name, c.provider FROM collection_jobs j JOIN collectors c ON c.id = j.collector_id ORDER BY j.created_at DESC LIMIT 100`).all<Record<string, unknown>>()).results;
    return Response.json({ runs });
  } catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "manage_collectors");
    await enforceRateLimit(request, user.id, "collection:queue", 20, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    await ensureDefaultCollectors(user);
    const body = await request.json() as { collectorIds?: string[] };
    const ids = [...new Set(body.collectorIds || [])].filter((id) => /^collector_(aws|github|okta|cloudflare|browser)$/.test(id)).slice(0, 5);
    if (!ids.length) return Response.json({ error: "Select at least one valid collector." }, { status: 400 });
    const results = [];
    for (const collectorId of ids) {
      const jobId = await queueCollection(collectorId, user);
      results.push({ jobId, collectorId, ...(await processJob(jobId, user)) });
    }
    return Response.json({ results }, { status: results.some((result) => result.status === "failed") ? 207 : 200 });
  } catch (error) { return jsonError(error); }
}
