CREATE TABLE `jira_connections` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`cloud_id` text NOT NULL,
	`site_url` text NOT NULL,
	`site_name` text NOT NULL,
	`allowed_projects_json` text DEFAULT '[]' NOT NULL,
	`access_token_ciphertext` text NOT NULL,
	`access_token_iv` text NOT NULL,
	`refresh_token_ciphertext` text NOT NULL,
	`refresh_token_iv` text NOT NULL,
	`access_token_expires_at` text NOT NULL,
	`scopes` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`last_tested_at` text,
	`last_error` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_jira_connections_user` ON `jira_connections` (`user_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_jira_connections_user_cloud` ON `jira_connections` (`user_id`,`cloud_id`);--> statement-breakpoint
CREATE TABLE `jira_oauth_states` (
	`state_hash` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`requested_site_url` text NOT NULL,
	`allowed_projects_json` text NOT NULL,
	`expires_at` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_jira_oauth_states_user_expires` ON `jira_oauth_states` (`user_id`,`expires_at`);--> statement-breakpoint
CREATE TABLE `jira_upload_receipts` (
	`id` text PRIMARY KEY NOT NULL,
	`connection_id` text NOT NULL,
	`user_id` text NOT NULL,
	`device_id` text NOT NULL,
	`evidence_id` text NOT NULL,
	`issue_key` text NOT NULL,
	`site_url` text NOT NULL,
	`uploaded_at` text NOT NULL,
	`attachments_json` text NOT NULL,
	`receipt_sha256` text NOT NULL,
	`signature` text NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_jira_upload_receipts_target` ON `jira_upload_receipts` (`connection_id`,`evidence_id`,`issue_key`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_jira_upload_receipts_sha` ON `jira_upload_receipts` (`receipt_sha256`);--> statement-breakpoint
CREATE INDEX `idx_jira_upload_receipts_user_created` ON `jira_upload_receipts` (`user_id`,`uploaded_at`);--> statement-breakpoint
CREATE TRIGGER `jira_upload_receipts_no_update`
BEFORE UPDATE ON `jira_upload_receipts`
BEGIN
  SELECT RAISE(ABORT, 'jira upload receipts are immutable');
END;--> statement-breakpoint
CREATE TRIGGER `jira_upload_receipts_no_delete`
BEFORE DELETE ON `jira_upload_receipts`
BEGIN
  SELECT RAISE(ABORT, 'jira upload receipts are immutable');
END;
