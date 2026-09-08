import { PACKAGE_ELIGIBLE_EVIDENCE_SQL, PACKAGE_ELIGIBILITY_PUBLISH_FENCE_SQL, PACKAGE_PARTITION_PUBLISH_FENCE_SQL, packageEligibilityPublishFenceBindings } from "./package-eligibility.ts";
import { PACKAGE_PLAN_SNAPSHOT_FENCE_SQL } from "./package-partitions.ts";
import type { ExpectedPackagePublication } from "./package-publication-reconciliation.ts";

/** One JSON binding for the entire selected set; never one SQL clause per artifact. */
const SELECTED_OCCURRENCES_FENCE_SQL = `NOT EXISTS (
  SELECT 1 FROM json_each(?) selected WHERE NOT EXISTS (
    SELECT 1 FROM evidence_artifacts e JOIN evidence_occurrences o ON o.artifact_id = e.id
    WHERE e.id = json_extract(selected.value, '$.artifactId') AND e.assessment_id = export_packages.assessment_id
      AND o.id = json_extract(selected.value, '$.occurrenceId')
      AND o.id = (SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = e.id ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1)
      AND ${PACKAGE_ELIGIBLE_EVIDENCE_SQL}
  )
)`;

/** The actual publication statement, shared with SQLite semantic/size-limit tests. */
export function packagePublicationQuery(input: {
  id: string; assessmentId: string; assessmentStatus: string; assessmentUpdatedAt: string;
  publication: ExpectedPackagePublication;
  occurrences: Array<{ artifactId: string; occurrenceId: string }>;
  totalCount: number; eligibleCount: number; snapshotJson?: string;
}): { sql: string; bindings: Array<string | number> } {
  const { id, assessmentId, assessmentStatus, assessmentUpdatedAt, publication, occurrences, totalCount, eligibleCount, snapshotJson } = input;
  if (!occurrences.length || occurrences.length > 100 || occurrences.length !== publication.evidenceCount
    || new Set(occurrences.map((item) => item.artifactId)).size !== occurrences.length
    || new Set(occurrences.map((item) => item.occurrenceId)).size !== occurrences.length) throw new Error("Package publication requires 1–100 distinct selected artifact occurrences matching its evidence count.");
  const partitioned = snapshotJson !== undefined;
  return {
    sql: `UPDATE export_packages SET status = 'ready', r2_key = ?, sha256 = ?, signature = ?, evidence_count = ?, excluded_count = ?, encryption_key_id = ?, byte_size = ?, completed_at = ?, expires_at = ?, error_message = NULL
      WHERE id = ? AND status = 'building'
        AND EXISTS (SELECT 1 FROM assessments WHERE id = ? AND status = ? AND updated_at = ?)
        AND ${SELECTED_OCCURRENCES_FENCE_SQL}
        AND ${partitioned ? PACKAGE_PARTITION_PUBLISH_FENCE_SQL : PACKAGE_ELIGIBILITY_PUBLISH_FENCE_SQL}
        ${partitioned ? `AND ${PACKAGE_PLAN_SNAPSHOT_FENCE_SQL}` : ""}`,
    bindings: [publication.r2Key, publication.sha256, publication.signature, publication.evidenceCount, publication.excludedCount,
      publication.encryptionKeyId, publication.byteSize, publication.completedAt, publication.expiresAt, id,
      assessmentId, assessmentStatus, assessmentUpdatedAt, JSON.stringify(occurrences), publication.completedAt,
      ...packageEligibilityPublishFenceBindings(assessmentId, publication.completedAt, totalCount, eligibleCount) as Array<string | number>,
      ...(partitioned ? [snapshotJson, assessmentId, publication.completedAt] : [])],
  };
}
