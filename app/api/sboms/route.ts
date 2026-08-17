import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";
import { getEnv } from "../../../lib/server/env";
import { listSbomJobs, listSbomRepositories, parseGitHubRepositoryUrl, processSbom, queueSbom, SbomError, validateOneTimeGitHubToken, type SbomFormat } from "../../../lib/server/sbom";

const noStoreHeaders = { "cache-control": "no-store, max-age=0", pragma: "no-cache" };

function sbomError(error: unknown): Response {
  if (error instanceof SbomError) return Response.json({ error: error.message, code: error.code }, { status: error.status, headers: noStoreHeaders });
  const response = jsonError(error);
  response.headers.set("cache-control", noStoreHeaders["cache-control"]);
  response.headers.set("pragma", noStoreHeaders.pragma);
  return response;
}

export async function GET(request: Request) {
  try {
    const user = await requireApiUser(request);
    await enforceRateLimit(request, user.id, "sbom:list", 120, 60);
    const assessmentId = new URL(request.url).searchParams.get("assessmentId") || undefined;
    if (assessmentId && !/^asm_[a-f0-9]{32}$/.test(assessmentId)) return Response.json({ error: "Assessment identifier is invalid." }, { status: 400 });
    const managedPresent = Boolean(getEnv().GITHUB_TOKEN && getEnv().GITHUB_ORG);
    const jobs = await listSbomJobs(assessmentId);
    let repositories: Awaited<ReturnType<typeof listSbomRepositories>> = [];
    let managedError: string | null = null;
    if (managedPresent) {
      try { repositories = await listSbomRepositories(); }
      catch (error) { managedError = error instanceof SbomError ? error.message : "Managed GitHub repository access is unavailable."; }
    }
    return Response.json({ jobs, repositories, configured: managedPresent && !managedError, managedError }, { headers: noStoreHeaders });
  } catch (error) { return sbomError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const user = await requireApiPermission(request, "generate_sbom");
    await enforceRateLimit(request, user.id, "sbom:generate", 10, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const body = await request.json() as { assessmentId?: string; sourceMode?: "managed" | "one_time"; repository?: string; repositoryUrl?: string; githubToken?: string; ref?: string; format?: SbomFormat };
    const common = { assessmentId: String(body.assessmentId || ""), ref: String(body.ref || ""), format: String(body.format || "cyclonedx_json") as SbomFormat };
    if (body.sourceMode === "one_time") {
      const target = parseGitHubRepositoryUrl(String(body.repositoryUrl || ""));
      const token = validateOneTimeGitHubToken(String(body.githubToken || ""));
      const jobId = await queueSbom({ ...common, ...target, credentialMode: "one_time" }, user);
      const job = await processSbom(jobId, user, { mode: "one_time", owner: target.owner, token });
      return Response.json({ job }, { status: job.status === "completed" ? 201 : 422, headers: noStoreHeaders });
    }
    const jobId = await queueSbom({ ...common, repository: String(body.repository || ""), credentialMode: "managed" }, user);
    const job = await processSbom(jobId, user);
    return Response.json({ job }, { status: job.status === "completed" ? 201 : job.status === "retrying" ? 202 : 422, headers: noStoreHeaders });
  } catch (error) { return sbomError(error); }
}
