import { jsonError, requireApiPermission } from "../../../../lib/server/auth";
import { enforceRateLimit } from "../../../../lib/server/rate-limit";
import { preflightAssessorPackage } from "../../../../lib/server/packages";
import { loadPackagePlan } from "../../../../lib/server/package-plan";

export async function GET(request: Request) {
  try {
    const actor = await requireApiPermission(request, "export_packages");
    await enforceRateLimit(request, actor.id, "package:plan", 30, 3600);
    const id = new URL(request.url).searchParams.get("assessmentId") || "";
    const preflight = await preflightAssessorPackage(id);
    const blockers = preflight.blockers.filter((row) => !["PACKAGE_LIMIT", "PACKAGE_BYTES_LIMIT"].includes(row.code));
    if (blockers.length) return Response.json({ error: "Resolve evidence integrity and review blockers before partitioning.", blockers }, { status: 409 });
    return Response.json({ plan: await loadPackagePlan(id) }, { headers: { "cache-control": "private, no-store" } });
  } catch (error) { return jsonError(error); }
}
