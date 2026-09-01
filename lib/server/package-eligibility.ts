/**
 * One authoritative eligibility query is shared by package preflight and the
 * package builder. Keeping this policy in one place prevents the UI gate from
 * disagreeing with the transaction that creates an assessor package.
 */
export const PACKAGE_ELIGIBILITY_COUNTS_SQL = `SELECT COUNT(*) AS total,
  SUM(CASE WHEN o.status = 'approved' AND o.expires_at > ? AND o.coverage_status != 'partial'
    AND (e.type != 'screenshot' OR (
      e.server_safety_scan_sha256 = e.sha256 AND e.server_safety_scan_policy IS NOT NULL AND e.server_safety_scan_completed_at IS NOT NULL
      AND e.server_safety_scanner_origin IS NOT NULL AND e.server_safety_receipt_sha256 IS NOT NULL
    ))
    AND (e.device_id IS NULL OR EXISTS (
      SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
      WHERE n.artifact_id = e.id AND n.device_id = e.device_id AND n.image_sha256 = e.sha256 AND n.manifest_sha256 = e.manifest_sha256
        AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash
        AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence
    )) THEN 1 ELSE 0 END) AS eligible,
  SUM(CASE WHEN e.type = 'screenshot' AND o.status = 'approved' AND o.expires_at > ? AND o.coverage_status != 'partial'
    AND NOT (
      e.server_safety_scan_sha256 = e.sha256 AND e.server_safety_scan_policy IS NOT NULL AND e.server_safety_scan_completed_at IS NOT NULL
      AND e.server_safety_scanner_origin IS NOT NULL AND e.server_safety_receipt_sha256 IS NOT NULL
    ) THEN 1 ELSE 0 END) AS pending_safety,
  SUM(CASE WHEN e.device_id IS NOT NULL AND o.status = 'approved' AND o.expires_at > ? AND o.coverage_status != 'partial'
    AND NOT EXISTS (
      SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
      WHERE n.artifact_id = e.id AND n.device_id = e.device_id AND n.image_sha256 = e.sha256 AND n.manifest_sha256 = e.manifest_sha256
        AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash
        AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence
    ) THEN 1 ELSE 0 END) AS pending_native,
  SUM(CASE WHEN o.coverage_status = 'partial' AND o.status = 'needs_review' AND o.expires_at > ?
    AND NOT EXISTS (SELECT 1 FROM evidence_artifacts newer
      JOIN evidence_occurrences newer_o ON newer_o.id = (
        SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = newer.id
        ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1
      )
      WHERE newer.assessment_id = e.assessment_id AND newer.control_id = e.control_id
      AND newer.framework = e.framework AND newer.source = e.source AND newer.system = e.system
      AND newer.environment IS e.environment AND newer.assessment_period IS e.assessment_period
      AND newer.collector_id IS e.collector_id AND newer_o.coverage_status != 'partial' AND newer_o.captured_at > o.captured_at
      AND newer_o.status = 'approved' AND newer_o.expires_at > ?
      AND (newer.type != 'screenshot' OR (
        newer.server_safety_scan_sha256 = newer.sha256 AND newer.server_safety_scan_policy IS NOT NULL
        AND newer.server_safety_scan_completed_at IS NOT NULL AND newer.server_safety_scanner_origin IS NOT NULL
        AND newer.server_safety_receipt_sha256 IS NOT NULL
      ))
      AND (newer.device_id IS NULL OR EXISTS (
        SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
        WHERE n.artifact_id = newer.id AND n.device_id = newer.device_id AND n.image_sha256 = newer.sha256
          AND n.manifest_sha256 = newer.manifest_sha256 AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0
          AND n.chain_event_hash = newer.chain_event_hash AND n.provenance_key_id IS NOT NULL
          AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence
      ))) THEN 1 ELSE 0 END) AS partial
  FROM evidence_artifacts e
  JOIN evidence_occurrences o ON o.id = (
    SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = e.id
    ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1
  )
  WHERE e.assessment_id = ?`;

/**
 * Re-evaluate the complete assessment immediately before publishing an R2
 * package. This closes the count/selection race: a new partial, unscanned, or
 * provenance-incomplete artifact cannot arrive between package construction
 * and the audited ready-state transition.
 */
export const PACKAGE_ELIGIBILITY_PUBLISH_FENCE_SQL = `EXISTS (
  SELECT 1 FROM (${PACKAGE_ELIGIBILITY_COUNTS_SQL}) package_eligibility
  WHERE COALESCE(package_eligibility.total, 0) = ?
    AND COALESCE(package_eligibility.eligible, 0) = ?
    AND COALESCE(package_eligibility.pending_safety, 0) = 0
    AND COALESCE(package_eligibility.pending_native, 0) = 0
    AND COALESCE(package_eligibility.partial, 0) = 0
)`;

export function packageEligibilityBindings(assessmentId: string, at: string): [string, string, string, string, string, string] {
  return [at, at, at, at, at, assessmentId];
}

export function packageEligibilityPublishFenceBindings(assessmentId: string, at: string, total: number, eligible: number): unknown[] {
  return [...packageEligibilityBindings(assessmentId, at), total, eligible];
}

export type PackageEligibilityCounts = { total: number; eligible: number; pending_safety: number; pending_native: number; partial: number };
