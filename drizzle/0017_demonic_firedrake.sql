DROP INDEX `idx_evidence_occurrences_job_artifact`;--> statement-breakpoint
DROP INDEX `idx_evidence_occurrences_artifact_received`;--> statement-breakpoint
DROP INDEX `idx_evidence_occurrences_device_captured`;--> statement-breakpoint
CREATE TABLE `__new_evidence_occurrences` (
	`id` text PRIMARY KEY NOT NULL,
	`artifact_id` text NOT NULL,
	`job_id` text,
	`session_id` text,
	`device_id` text,
	`captured_at` text NOT NULL,
	`received_at` text NOT NULL,
	`created_by` text NOT NULL,
	`expires_at` text NOT NULL,
	`status` text DEFAULT 'needs_review' NOT NULL,
	`coverage_status` text DEFAULT 'not_applicable' NOT NULL,
	`coverage_json` text DEFAULT '{}' NOT NULL,
	`approved_by` text,
	`approved_at` text,
	`provenance_json` text DEFAULT '{}' NOT NULL
);--> statement-breakpoint
INSERT INTO `__new_evidence_occurrences` (`id`, `artifact_id`, `job_id`, `session_id`, `device_id`, `captured_at`, `received_at`, `created_by`, `expires_at`, `status`, `coverage_status`, `coverage_json`, `approved_by`, `approved_at`, `provenance_json`)
WITH ranked_occurrences AS (
  SELECT o.*, ROW_NUMBER() OVER (PARTITION BY o.`artifact_id` ORDER BY o.`received_at` DESC, o.`id` DESC) AS `latest_rank`
  FROM `evidence_occurrences` o
)
SELECT o.`id`, o.`artifact_id`, o.`job_id`, o.`session_id`, o.`device_id`, o.`captured_at`, o.`received_at`, o.`created_by`, e.`expires_at`,
  CASE WHEN o.`latest_rank` = 1
    THEN CASE e.`status` WHEN 'approved' THEN 'approved' WHEN 'rejected' THEN 'rejected' WHEN 'expired' THEN 'expired' WHEN 'purged' THEN 'expired' ELSE 'needs_review' END
    ELSE 'needs_review' END,
  e.`coverage_status`, e.`coverage_json`,
  CASE WHEN o.`latest_rank` = 1 THEN e.`approved_by` ELSE NULL END,
  CASE WHEN o.`latest_rank` = 1 THEN e.`approved_at` ELSE NULL END,
  o.`provenance_json`
FROM ranked_occurrences o JOIN `evidence_artifacts` e ON e.`id` = o.`artifact_id`;--> statement-breakpoint
DROP TABLE `evidence_occurrences`;--> statement-breakpoint
ALTER TABLE `__new_evidence_occurrences` RENAME TO `evidence_occurrences`;--> statement-breakpoint
CREATE UNIQUE INDEX `idx_evidence_occurrences_job_artifact` ON `evidence_occurrences` (`job_id`,`artifact_id`);--> statement-breakpoint
CREATE INDEX `idx_evidence_occurrences_artifact_received` ON `evidence_occurrences` (`artifact_id`,`received_at`);--> statement-breakpoint
CREATE INDEX `idx_evidence_occurrences_device_captured` ON `evidence_occurrences` (`device_id`,`captured_at`);--> statement-breakpoint
INSERT INTO `evidence_occurrences` (`id`, `artifact_id`, `job_id`, `session_id`, `device_id`, `captured_at`, `received_at`, `created_by`, `expires_at`, `status`, `coverage_status`, `coverage_json`, `approved_by`, `approved_at`, `provenance_json`)
SELECT 'occ_migration_0017_' || e.`id`, e.`id`, e.`job_id`, e.`session_id`, e.`device_id`, e.`captured_at`, e.`created_at`, e.`created_by`, e.`expires_at`,
  CASE e.`status` WHEN 'approved' THEN 'approved' WHEN 'rejected' THEN 'rejected' WHEN 'expired' THEN 'expired' WHEN 'purged' THEN 'expired' ELSE 'needs_review' END,
  e.`coverage_status`, e.`coverage_json`, e.`approved_by`, e.`approved_at`, '{"migration":"0017"}'
FROM `evidence_artifacts` e WHERE NOT EXISTS (SELECT 1 FROM `evidence_occurrences` o WHERE o.`artifact_id` = e.`id`);--> statement-breakpoint
CREATE TRIGGER `evidence_occurrences_latest_insert`
AFTER INSERT ON `evidence_occurrences`
WHEN NEW.`id` = (SELECT latest.`id` FROM `evidence_occurrences` latest WHERE latest.`artifact_id` = NEW.`artifact_id` ORDER BY latest.`received_at` DESC, latest.`id` DESC LIMIT 1)
BEGIN
  UPDATE `evidence_artifacts` SET
    `expires_at` = NEW.`expires_at`, `status` = NEW.`status`, `coverage_status` = NEW.`coverage_status`,
    `coverage_json` = NEW.`coverage_json`, `created_by` = NEW.`created_by`, `job_id` = NEW.`job_id`,
    `session_id` = NEW.`session_id`, `device_id` = NEW.`device_id`, `approved_by` = NEW.`approved_by`,
    `approved_at` = NEW.`approved_at`
  WHERE `id` = NEW.`artifact_id` AND `status` != 'purged';
END;--> statement-breakpoint
CREATE TRIGGER `evidence_occurrences_latest_review`
AFTER UPDATE OF `status`, `approved_by`, `approved_at` ON `evidence_occurrences`
WHEN NEW.`id` = (SELECT latest.`id` FROM `evidence_occurrences` latest WHERE latest.`artifact_id` = NEW.`artifact_id` ORDER BY latest.`received_at` DESC, latest.`id` DESC LIMIT 1)
BEGIN
  UPDATE `evidence_artifacts` SET `status` = NEW.`status`, `approved_by` = NEW.`approved_by`, `approved_at` = NEW.`approved_at`
  WHERE `id` = NEW.`artifact_id` AND `status` != 'purged';
END;
