import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";
import { getEnv } from "../../../lib/server/env";
import { listSbomJobs, listSbomRepositories, processSbom, queueSbom, SbomError, type SbomFormat } from "../../../lib/server/sbom";

function sbomError(error: unknown): Response {
  return error instanceof SbomError ? Response.json({ error: error.message, code: error.code }, { status: error.status }) : jsonError(error);
}

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "sbom:list", 120, 60);
    const assessmentId = new URL(request.url).searchParams.get("assessmentId") || undefined;
    if (assessmentId && !/^asm_[a-f0-9]{32}$/.test(assessmentId)) return Response.json({ error: "Assessment identifier is invalid." }, { status: 400 });
    const configured = Boolean(getEnv().GITHUB_TOKEN && getEnv().GITHUB_ORG);
    const [jobs, repositories] = await Promise.all([listSbomJobs(assessmentId), configured ? listSbomRepositories() : Promise.resolve([])]);
    return Response.json({ jobs, repositories, configured });
  } catch (error) { return sbomError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "generate_sbom");
    await enforceRateLimit(request, user.id, "sbom:generate", 10, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const body = await request.json() as { assessmentId?: string; repository?: string; ref?: string; format?: SbomFormat };
    const jobId = await queueSbom({ assessmentId: String(body.assessmentId || ""), repository: String(body.repository || ""), ref: String(body.ref || ""), format: String(body.format || "cyclonedx_json") as SbomFormat }, user);
    const job = await processSbom(jobId, user);
    return Response.json({ job }, { status: job.status === "completed" ? 201 : job.status === "retrying" ? 202 : 422 });
  } catch (error) { return sbomError(error); }
}
