CREATE TABLE `rate_limit_buckets` (
	`key_hash` text PRIMARY KEY NOT NULL,
	`window_start` integer NOT NULL,
	`request_count` integer DEFAULT 0 NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_rate_limit_expiry` ON `rate_limit_buckets` (`expires_at`);--> statement-breakpoint
CREATE TABLE `retention_holds` (
	`evidence_id` text PRIMARY KEY NOT NULL,
	`owner_id` text NOT NULL,
	`reason` text NOT NULL,
	`expires_at` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_retention_holds_expiry` ON `retention_holds` (`expires_at`);--> statement-breakpoint
ALTER TABLE `collection_jobs` ADD `lease_id` text;--> statement-breakpoint
ALTER TABLE `collection_jobs` ADD `lease_expires_at` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `purged_at` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `purge_attempts` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `purge_error` text;