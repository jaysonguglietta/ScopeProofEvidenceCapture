CREATE TABLE `jira_upload_operations` (
	`id` text PRIMARY KEY NOT NULL,
	`connection_id` text NOT NULL,
	`user_id` text NOT NULL,
	`device_id` text NOT NULL,
	`evidence_id` text NOT NULL,
	`issue_key` text NOT NULL,
	`request_sha256` text NOT NULL,
	`status` text DEFAULT 'reserved' NOT NULL,
	`lease_id` text,
	`lease_expires_at` text,
	`attempt` integer DEFAULT 0 NOT NULL,
	`receipt_id` text,
	`last_error` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_jira_upload_operations_target` ON `jira_upload_operations` (`connection_id`,`evidence_id`,`issue_key`);--> statement-breakpoint
CREATE INDEX `idx_jira_upload_operations_status_lease` ON `jira_upload_operations` (`status`,`lease_expires_at`);--> statement-breakpoint
ALTER TABLE `jira_connections` ADD `token_version` integer DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE `jira_connections` ADD `refresh_lease_id` text;--> statement-breakpoint
ALTER TABLE `jira_connections` ADD `refresh_lease_expires_at` text;