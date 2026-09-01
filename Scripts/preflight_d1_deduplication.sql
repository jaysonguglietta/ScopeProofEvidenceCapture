-- Run against the deployed D1 database before applying migration 0018.
-- Any returned row represents active historical artifacts that collide under
-- the hardened evidence identity. Resolve them with the documented evidence
-- reconciliation procedure before migration; do not delete evidence objects.
SELECT
  sha256,
  source,
  control_id,
  framework,
  system,
  COALESCE(assessment_id, '<NULL>') AS assessment_id,
  COALESCE(environment, '<NULL>') AS environment,
  COALESCE(assessment_period, '<NULL>') AS assessment_period,
  COUNT(*) AS active_artifact_count,
  GROUP_CONCAT(id) AS artifact_ids
FROM evidence_artifacts
WHERE status NOT IN ('expired', 'purged')
GROUP BY sha256, source, control_id, framework, system, assessment_id, environment, assessment_period
HAVING COUNT(*) > 1
ORDER BY active_artifact_count DESC, control_id, system;
