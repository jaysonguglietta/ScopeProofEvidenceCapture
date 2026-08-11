CREATE TABLE `native_evidence_manifests` (
	`id` text PRIMARY KEY NOT NULL,
	`device_id` text NOT NULL,
	`local_evidence_id` text NOT NULL,
	`artifact_id` text NOT NULL,
	`manifest_sha256` text NOT NULL,
	`image_sha256` text NOT NULL,
	`jira_issue_key` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_native_manifest_device_local` ON `native_evidence_manifests` (`device_id`,`local_evidence_id`);--> statement-breakpoint
CREATE INDEX `idx_native_manifest_artifact` ON `native_evidence_manifests` (`artifact_id`);