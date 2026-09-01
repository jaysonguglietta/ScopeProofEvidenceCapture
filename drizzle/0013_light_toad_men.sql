CREATE TABLE `evidence_occurrences` (
	`id` text PRIMARY KEY NOT NULL,
	`artifact_id` text NOT NULL,
	`job_id` text,
	`session_id` text,
	`device_id` text,
	`captured_at` text NOT NULL,
	`received_at` text NOT NULL,
	`created_by` text NOT NULL,
	`provenance_json` text DEFAULT '{}' NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_evidence_occurrences_job_artifact` ON `evidence_occurrences` (`job_id`,`artifact_id`);--> statement-breakpoint
CREATE INDEX `idx_evidence_occurrences_artifact_received` ON `evidence_occurrences` (`artifact_id`,`received_at`);--> statement-breakpoint
CREATE INDEX `idx_evidence_occurrences_device_captured` ON `evidence_occurrences` (`device_id`,`captured_at`);--> statement-breakpoint
CREATE TABLE `user_invitations` (
	`id` text PRIMARY KEY NOT NULL,
	`email` text NOT NULL,
	`role` text DEFAULT 'auditor' NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`invited_by` text NOT NULL,
	`expires_at` text NOT NULL,
	`accepted_user_id` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`accepted_at` text,
	`revoked_at` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_user_invitations_email_pending` ON `user_invitations` (`email`,`status`);--> statement-breakpoint
CREATE INDEX `idx_user_invitations_status_expiry` ON `user_invitations` (`status`,`expires_at`);--> statement-breakpoint
DROP INDEX `idx_capture_devices_token_hash`;--> statement-breakpoint
DROP INDEX `idx_capture_devices_owner_status`;--> statement-breakpoint
CREATE TABLE `__new_capture_devices` (
	`id` text PRIMARY KEY NOT NULL,
	`display_name` text NOT NULL,
	`platform` text DEFAULT 'macOS' NOT NULL,
	`token_hash` text NOT NULL,
	`owner_id` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`app_version` text,
	`last_seen_at` text,
	`token_issued_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`token_expires_at` text DEFAULT (datetime('now', '+30 days')) NOT NULL,
	`token_last_rotated_at` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`revoked_at` text
);--> statement-breakpoint
INSERT INTO `__new_capture_devices` (`id`,`display_name`,`platform`,`token_hash`,`owner_id`,`status`,`app_version`,`last_seen_at`,`token_issued_at`,`token_expires_at`,`token_last_rotated_at`,`created_at`,`revoked_at`)
SELECT `id`,`display_name`,`platform`,`token_hash`,`owner_id`,`status`,`app_version`,`last_seen_at`,
	COALESCE(`last_seen_at`, `created_at`, CURRENT_TIMESTAMP),
	datetime(COALESCE(`last_seen_at`, `created_at`, CURRENT_TIMESTAMP), '+30 days'),
	NULL,`created_at`,`revoked_at`
FROM `capture_devices`;--> statement-breakpoint
DROP TABLE `capture_devices`;--> statement-breakpoint
ALTER TABLE `__new_capture_devices` RENAME TO `capture_devices`;--> statement-breakpoint
CREATE UNIQUE INDEX `idx_capture_devices_token_hash` ON `capture_devices` (`token_hash`);--> statement-breakpoint
CREATE INDEX `idx_capture_devices_owner_status` ON `capture_devices` (`owner_id`,`status`);--> statement-breakpoint
ALTER TABLE `users` ADD `status` text DEFAULT 'active' NOT NULL;--> statement-breakpoint
ALTER TABLE `users` ADD `invited_by` text;--> statement-breakpoint
CREATE TRIGGER `users_preserve_last_active_admin`
BEFORE UPDATE OF `role`, `status` ON `users`
WHEN OLD.`role` = 'admin' AND OLD.`status` = 'active'
  AND (NEW.`role` != 'admin' OR NEW.`status` != 'active')
  AND (SELECT COUNT(*) FROM `users` WHERE `role` = 'admin' AND `status` = 'active') <= 1
BEGIN
  SELECT RAISE(ABORT, 'cannot remove final active admin');
END;
