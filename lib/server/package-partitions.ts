import { PACKAGE_MAXIMUM_EVIDENCE_BYTES, PACKAGE_ELIGIBLE_EVIDENCE_SQL } from "./package-eligibility.ts";

export type PackageSnapshotRow = {
  id: string; occurrenceId: string; sha256: string; bytes: number;
  status: string; coverage: string; expiresAt: string; eligible: boolean;
};
export type PackagePart = { index: number; evidenceIds: string[]; bytes: number };

/** Every eligible artifact appears exactly once; never split or truncate bytes. */
export function partitionEvidence(snapshot: PackageSnapshotRow[]): PackagePart[] {
  if (!snapshot.length || snapshot.length > 1000) throw new Error("Partition planning supports 1–1,000 assessment records. No records were truncated.");
  if (new Set(snapshot.map((row) => row.id)).size !== snapshot.length) throw new Error("Duplicate evidence identity in package snapshot.");
  const parts: PackagePart[] = [];
  for (const row of [...snapshot].sort((a, b) => a.id.localeCompare(b.id, "en"))) {
    if (!row.eligible) continue;
    if (!Number.isSafeInteger(row.bytes) || row.bytes < 0 || row.bytes > PACKAGE_MAXIMUM_EVIDENCE_BYTES) throw new Error(`Evidence ${row.id} cannot fit safely in a package part. No bytes were omitted.`);
    let part = parts.at(-1);
    if (!part || part.evidenceIds.length === 100 || part.bytes + row.bytes > PACKAGE_MAXIMUM_EVIDENCE_BYTES) {
      part = { index: parts.length + 1, evidenceIds: [], bytes: 0 }; parts.push(part);
    }
    part.evidenceIds.push(row.id); part.bytes += row.bytes;
  }
  if (!parts.length) throw new Error("No eligible evidence is available for partitioning.");
  return parts;
}

export function exclusionReason(row: PackageSnapshotRow): string {
  if (row.eligible) return "included";
  if (row.status !== "approved") return `review_status:${row.status}`;
  if (row.coverage === "partial") return "partial_coverage";
  return "not_current_or_scope_or_integrity_ineligible";
}

/** Commit-time snapshot fence, including records assigned to other parts. */
export const PACKAGE_PLAN_SNAPSHOT_FENCE_SQL = `NOT EXISTS (
  SELECT 1 FROM json_each(?) planned WHERE NOT EXISTS (
    SELECT 1 FROM evidence_artifacts e JOIN evidence_occurrences o ON o.id = json_extract(planned.value, '$.occurrenceId')
    WHERE e.id = json_extract(planned.value, '$.id') AND e.assessment_id = ? AND o.artifact_id = e.id
      AND e.sha256 = json_extract(planned.value, '$.sha256') AND e.byte_size = json_extract(planned.value, '$.bytes')
      AND o.status = json_extract(planned.value, '$.status') AND o.coverage_status = json_extract(planned.value, '$.coverage')
      AND o.expires_at = json_extract(planned.value, '$.expiresAt')
      AND (CASE WHEN ${PACKAGE_ELIGIBLE_EVIDENCE_SQL} THEN 1 ELSE 0 END) = json_extract(planned.value, '$.eligible')
      AND o.id = (SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = e.id ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1)
  )
)`;
