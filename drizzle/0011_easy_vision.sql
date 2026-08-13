CREATE TABLE `audit_checkpoints` (
	`id` text PRIMARY KEY NOT NULL,
	`sequence` integer NOT NULL,
	`event_hash` text NOT NULL,
	`event_count` integer NOT NULL,
	`hmac_key_id` text NOT NULL,
	`checkpoint_sha256` text NOT NULL,
	`signature` text NOT NULL,
	`public_key_fingerprint` text NOT NULL,
	`r2_key` text NOT NULL,
	`external_status` text NOT NULL,
	`external_receipt` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_audit_checkpoints_sequence` ON `audit_checkpoints` (`sequence`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_audit_checkpoints_sha` ON `audit_checkpoints` (`checkpoint_sha256`);--> statement-breakpoint
ALTER TABLE `audit_events` ADD `hmac_key_id` text DEFAULT 'legacy-v1' NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `encryption_key_id` text DEFAULT 'legacy-v1' NOT NULL;--> statement-breakpoint
ALTER TABLE `export_packages` ADD `encryption_key_id` text DEFAULT 'legacy-v1' NOT NULL;--> statement-breakpoint
ALTER TABLE `jira_connections` ADD `token_key_id` text DEFAULT 'legacy-v1' NOT NULL;--> statement-breakpoint
ALTER TABLE `jira_upload_receipts` ADD `hmac_key_id` text DEFAULT 'legacy-v1' NOT NULL;