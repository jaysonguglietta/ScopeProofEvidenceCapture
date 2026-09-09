import { getEnv } from "./env";
import { sha256, stableJson } from "./crypto";
import { PACKAGE_ELIGIBLE_EVIDENCE_SQL } from "./package-eligibility";
import { exclusionReason, partitionEvidence, type PackageSnapshotRow } from "./package-partitions";

export async function loadPackagePlan(assessmentId: string) {
  if (!/^asm_[a-f0-9]{32}$/u.test(assessmentId)) throw new Response(JSON.stringify({ error: "A valid assessment is required." }), { status: 400 });
  const assessment = await getEnv().DB.prepare("SELECT id, status, updated_at, systems_json, controls_json, period_start, period_end FROM assessments WHERE id = ?").bind(assessmentId).first<Record<string, unknown>>();
  if (!assessment || assessment.status === "draft") throw new Response(JSON.stringify({ error: "Choose an active or closed assessment." }), { status: 409 });
  const now = new Date().toISOString();
  const raw = (await getEnv().DB.prepare(`SELECT e.id, e.sha256, e.byte_size, o.id AS occurrence_id, o.status, o.coverage_status, o.expires_at,
    CASE WHEN ${PACKAGE_ELIGIBLE_EVIDENCE_SQL} THEN 1 ELSE 0 END AS eligible
    FROM evidence_artifacts e JOIN evidence_occurrences o ON o.id = (
      SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = e.id ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1
    ) WHERE e.assessment_id = ? ORDER BY e.id LIMIT 1001`).bind(now, assessmentId).all<Record<string, unknown>>()).results;
  const snapshot: PackageSnapshotRow[] = raw.map((row) => ({ id: String(row.id), occurrenceId: String(row.occurrence_id), sha256: String(row.sha256), bytes: Number(row.byte_size), status: String(row.status), coverage: String(row.coverage_status), expiresAt: String(row.expires_at), eligible: Boolean(row.eligible) }));
  const parts = partitionEvidence(snapshot);
  const body = { schemaVersion: 1, assessment, snapshot, parts, exclusions: snapshot.filter((row) => !row.eligible).map((row) => ({ evidenceId: row.id, reason: exclusionReason(row) })) };
  return { ...body, digest: await sha256(stableJson(body)), total: snapshot.length, eligible: snapshot.filter((row) => row.eligible).length };
}

export type PackagePlan = Awaited<ReturnType<typeof loadPackagePlan>>;
export type PartitionRequest = { digest: string; index: number };

export { PACKAGE_PLAN_SNAPSHOT_FENCE_SQL } from "./package-partitions";
