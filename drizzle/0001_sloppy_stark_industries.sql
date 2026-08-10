CREATE TABLE `capture_devices` (
	`id` text PRIMARY KEY NOT NULL,
	`display_name` text NOT NULL,
	`platform` text DEFAULT 'macOS' NOT NULL,
	`token_hash` text NOT NULL,
	`owner_id` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`app_version` text,
	`last_seen_at` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`revoked_at` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_capture_devices_token_hash` ON `capture_devices` (`token_hash`);--> statement-breakpoint
CREATE INDEX `idx_capture_devices_owner_status` ON `capture_devices` (`owner_id`,`status`);--> statement-breakpoint
CREATE TABLE `capture_sessions` (
	`id` text PRIMARY KEY NOT NULL,
	`display_name` text NOT NULL,
	`control_id` text NOT NULL,
	`system_name` text NOT NULL,
	`environment` text NOT NULL,
	`assessment_period` text NOT NULL,
	`created_by` text NOT NULL,
	`status` text DEFAULT 'open' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`completed_at` text
);
--> statement-breakpoint
CREATE INDEX `idx_capture_sessions_control_created` ON `capture_sessions` (`control_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_capture_sessions_creator_status` ON `capture_sessions` (`created_by`,`status`);--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `session_id` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `device_id` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `manifest_sha256` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `chain_previous_hash` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `chain_event_hash` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `timestamp_authority` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `timestamp_token` text;--> statement-breakpoint
CREATE INDEX `idx_evidence_device_captured` ON `evidence_artifacts` (`device_id`,`captured_at`);--> statement-breakpoint
CREATE INDEX `idx_evidence_session` ON `evidence_artifacts` (`session_id`);