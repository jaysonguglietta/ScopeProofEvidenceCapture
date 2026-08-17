CREATE TABLE `sbom_jobs` (
	`id` text PRIMARY KEY NOT NULL,
	`requested_by` text NOT NULL,
	`assessment_id` text NOT NULL,
	`repository_owner` text NOT NULL,
	`repository_name` text NOT NULL,
	`repository_full_name` text NOT NULL,
	`requested_ref` text NOT NULL,
	`resolved_commit_sha` text,
	`format` text NOT NULL,
	`status` text DEFAULT 'queued' NOT NULL,
	`attempt` integer DEFAULT 0 NOT NULL,
	`max_attempts` integer DEFAULT 3 NOT NULL,
	`next_attempt_at` text,
	`lease_id` text,
	`lease_expires_at` text,
	`evidence_id` text,
	`previous_job_id` text,
	`component_count` integer DEFAULT 0 NOT NULL,
	`direct_dependency_count` integer DEFAULT 0 NOT NULL,
	`manifest_count` integer DEFAULT 0 NOT NULL,
	`source_archive_sha256` text,
	`artifact_sha256` text,
	`generator_name` text DEFAULT 'scopeproof-static-sbom' NOT NULL,
	`generator_version` text DEFAULT '1.0.0' NOT NULL,
	`manifests_json` text DEFAULT '[]' NOT NULL,
	`components_json` text DEFAULT '[]' NOT NULL,
	`comparison_json` text DEFAULT '{}' NOT NULL,
	`error_code` text,
	`error_message` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`started_at` text,
	`completed_at` text
);
--> statement-breakpoint
CREATE INDEX `idx_sbom_jobs_assessment_created` ON `sbom_jobs` (`assessment_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_sbom_jobs_status_next_attempt` ON `sbom_jobs` (`status`,`next_attempt_at`);--> statement-breakpoint
CREATE INDEX `idx_sbom_jobs_repo_completed` ON `sbom_jobs` (`repository_full_name`,`completed_at`);--> statement-breakpoint
CREATE INDEX `idx_sbom_jobs_evidence` ON `sbom_jobs` (`evidence_id`);