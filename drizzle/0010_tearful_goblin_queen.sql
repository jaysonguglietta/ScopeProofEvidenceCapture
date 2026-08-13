CREATE TABLE `assessments` (
	`id` text PRIMARY KEY NOT NULL,
	`name` text NOT NULL,
	`framework` text NOT NULL,
	`period_start` text NOT NULL,
	`period_end` text NOT NULL,
	`systems_json` text DEFAULT '[]' NOT NULL,
	`controls_json` text DEFAULT '[]' NOT NULL,
	`owner_id` text NOT NULL,
	`status` text DEFAULT 'draft' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_assessments_status_period` ON `assessments` (`status`,`period_end`);--> statement-breakpoint
CREATE INDEX `idx_assessments_owner` ON `assessments` (`owner_id`);--> statement-breakpoint
ALTER TABLE `collection_jobs` ADD `assessment_id` text;--> statement-breakpoint
ALTER TABLE `collection_jobs` ADD `coverage_status` text DEFAULT 'unknown' NOT NULL;--> statement-breakpoint
ALTER TABLE `collection_jobs` ADD `coverage_json` text DEFAULT '{}' NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `assessment_id` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `coverage_status` text DEFAULT 'not_applicable' NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `coverage_json` text DEFAULT '{}' NOT NULL;--> statement-breakpoint
CREATE INDEX `idx_evidence_assessment_status` ON `evidence_artifacts` (`assessment_id`,`status`);--> statement-breakpoint
ALTER TABLE `export_packages` ADD `assessment_id` text;--> statement-breakpoint
ALTER TABLE `export_packages` ADD `selection_json` text DEFAULT '{}' NOT NULL;--> statement-breakpoint
ALTER TABLE `export_packages` ADD `excluded_count` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
CREATE INDEX `idx_exports_assessment_created` ON `export_packages` (`assessment_id`,`created_at`);