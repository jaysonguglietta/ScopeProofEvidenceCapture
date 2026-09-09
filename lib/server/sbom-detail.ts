import { getEnv } from "./env";
import { comparison, type SbomComponent } from "./sbom-inventory";
import type { AuthenticatedUser } from "./auth";

export async function sbomDetail(id: string, baselineId: string | undefined, actor: AuthenticatedUser) {
  if (!/^sbom_[a-f0-9]{32}$/u.test(id) || baselineId && !/^sbom_[a-f0-9]{32}$/u.test(baselineId)) throw new Response(JSON.stringify({ error: "A valid inventory identifier is required." }), { status: 400 });
  const load = (jobId: string) => getEnv().DB.prepare(`SELECT j.id, j.assessment_id, j.repository_full_name, j.status, j.resolved_commit_sha, j.generator_name, j.generator_version, j.components_json, j.comparison_json
    FROM sbom_jobs j JOIN evidence_artifacts e ON e.id = j.evidence_id
    JOIN evidence_occurrences o ON o.id = (SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = e.id ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1)
    WHERE j.id = ? AND e.status != 'purged' AND o.expires_at > ? AND (? != 'auditor' OR o.status = 'approved')`).bind(jobId, new Date().toISOString(), actor.role).first<Record<string, unknown>>();
  const row = await load(id);
  if (!row || row.status !== "completed") throw new Response(JSON.stringify({ error: "Completed inventory not found." }), { status: 404 });
  const previous = baselineId ? await load(baselineId) : null;
  if (baselineId && (!previous || previous.status !== "completed" || previous.assessment_id !== row.assessment_id || previous.repository_full_name !== row.repository_full_name)) throw new Response(JSON.stringify({ error: "Select a completed baseline from the same repository and assessment." }), { status: 422 });
  const decode = (value: unknown): SbomComponent[] => {
    const components = JSON.parse(String(value || "[]")) as SbomComponent[];
    if (!Array.isArray(components) || components.length > 5000 || components.some((item) => !item || typeof item.purl !== "string" || typeof item.name !== "string" || typeof item.version !== "string")) throw new Error("Stored inventory cannot be safely inspected.");
    return components;
  };
  const components = decode(row.components_json);
  const baseline = previous ? decode(previous.components_json) : [];
  const currentSet = new Set(components.map((item) => item.purl));
  const previousSet = new Set(baseline.map((item) => item.purl));
  const delta = comparison(components, previous ? baseline : null, baselineId, 5000);
  const describe = (job: Record<string, unknown>) => ({ id: String(job.id), commit: String(job.resolved_commit_sha), generator: `${job.generator_name}@${job.generator_version}` });
  return { job: describe(row), repository: String(row.repository_full_name), assessmentId: String(row.assessment_id),
    coverage: (JSON.parse(String(row.comparison_json || "{}")) as Record<string, unknown>).inventoryCoverage || null,
    components, baseline: previous ? describe(previous) : null,
    comparison: { ...delta, addedComponents: previous ? components.filter((item) => !previousSet.has(item.purl)) : [], removedComponents: baseline.filter((item) => !currentSet.has(item.purl)), detailScope: "full_component_identities_and_version_sets" } };
}
