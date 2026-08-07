CREATE TABLE `audit_events` (
	`sequence` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`id` text NOT NULL,
	`occurred_at` text NOT NULL,
	`actor_id` text NOT NULL,
	`actor_email` text NOT NULL,
	`action` text NOT NULL,
	`resource_type` text NOT NULL,
	`resource_id` text NOT NULL,
	`details_json` text DEFAULT '{}' NOT NULL,
	`previous_hash` text NOT NULL,
	`event_hash` text NOT NULL,
	`signature` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_audit_id` ON `audit_events` (`id`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_audit_event_hash` ON `audit_events` (`event_hash`);--> statement-breakpoint
CREATE INDEX `idx_audit_resource` ON `audit_events` (`resource_type`,`resource_id`);--> statement-breakpoint
CREATE INDEX `idx_audit_occurred` ON `audit_events` (`occurred_at`);--> statement-breakpoint
CREATE TABLE `collection_jobs` (
	`id` text PRIMARY KEY NOT NULL,
	`collector_id` text NOT NULL,
	`requested_by` text NOT NULL,
	`trigger_type` text NOT NULL,
	`status` text DEFAULT 'queued' NOT NULL,
	`attempt` integer DEFAULT 0 NOT NULL,
	`max_attempts` integer DEFAULT 3 NOT NULL,
	`artifact_count` integer DEFAULT 0 NOT NULL,
	`next_attempt_at` text,
	`error_code` text,
	`error_message` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`started_at` text,
	`completed_at` text
);
--> statement-breakpoint
CREATE INDEX `idx_jobs_status_next_attempt` ON `collection_jobs` (`status`,`next_attempt_at`);--> statement-breakpoint
CREATE INDEX `idx_jobs_collector_created` ON `collection_jobs` (`collector_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `collectors` (
	`id` text PRIMARY KEY NOT NULL,
	`provider` text NOT NULL,
	`display_name` text NOT NULL,
	`enabled` integer DEFAULT true NOT NULL,
	`config_json` text DEFAULT '{}' NOT NULL,
	`schedule_cron` text,
	`status` text DEFAULT 'not_configured' NOT NULL,
	`last_run_at` text,
	`last_error` text,
	`created_by` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_collectors_provider` ON `collectors` (`provider`);--> statement-breakpoint
CREATE INDEX `idx_collectors_enabled` ON `collectors` (`enabled`);--> statement-breakpoint
CREATE TABLE `evidence_artifacts` (
	`id` text PRIMARY KEY NOT NULL,
	`control_id` text NOT NULL,
	`title` text NOT NULL,
	`description` text DEFAULT '' NOT NULL,
	`type` text NOT NULL,
	`source` text NOT NULL,
	`system` text NOT NULL,
	`collector_id` text,
	`job_id` text,
	`r2_key` text NOT NULL,
	`content_type` text NOT NULL,
	`byte_size` integer NOT NULL,
	`sha256` text NOT NULL,
	`encryption_iv` text NOT NULL,
	`encryption_version` integer DEFAULT 1 NOT NULL,
	`captured_at` text NOT NULL,
	`expires_at` text NOT NULL,
	`status` text DEFAULT 'needs_review' NOT NULL,
	`redaction_count` integer DEFAULT 0 NOT NULL,
	`redaction_summary_json` text DEFAULT '[]' NOT NULL,
	`created_by` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`approved_by` text,
	`approved_at` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_evidence_sha_source_control` ON `evidence_artifacts` (`sha256`,`source`,`control_id`);--> statement-breakpoint
CREATE INDEX `idx_evidence_status_created` ON `evidence_artifacts` (`status`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_evidence_control_captured` ON `evidence_artifacts` (`control_id`,`captured_at`);--> statement-breakpoint
CREATE INDEX `idx_evidence_job` ON `evidence_artifacts` (`job_id`);--> statement-breakpoint
CREATE TABLE `export_packages` (
	`id` text PRIMARY KEY NOT NULL,
	`requested_by` text NOT NULL,
	`status` text DEFAULT 'building' NOT NULL,
	`r2_key` text,
	`sha256` text,
	`signature` text,
	`evidence_count` integer DEFAULT 0 NOT NULL,
	`byte_size` integer DEFAULT 0 NOT NULL,
	`error_message` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`completed_at` text,
	`expires_at` text
);
--> statement-breakpoint
CREATE INDEX `idx_exports_requested_created` ON `export_packages` (`requested_by`,`created_at`);--> statement-breakpoint
CREATE TABLE `users` (
	`id` text PRIMARY KEY NOT NULL,
	`email` text NOT NULL,
	`display_name` text NOT NULL,
	`role` text DEFAULT 'auditor' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`last_seen_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_users_email` ON `users` (`email`);
--> statement-breakpoint
CREATE TRIGGER `audit_events_no_update`
BEFORE UPDATE ON `audit_events`
BEGIN
  SELECT RAISE(ABORT, 'audit_events are immutable');
END;
--> statement-breakpoint
CREATE TRIGGER `audit_events_no_delete`
BEFORE DELETE ON `audit_events`
BEGIN
  SELECT RAISE(ABORT, 'audit_events are immutable');
END;
--> statement-breakpoint
CREATE TRIGGER `audit_events_chain_guard`
BEFORE INSERT ON `audit_events`
WHEN NEW.previous_hash != COALESCE((SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1), 'GENESIS')
BEGIN
  SELECT RAISE(ABORT, 'audit chain head changed');
END;
--> statement-breakpoint
PRAGMA optimize;
