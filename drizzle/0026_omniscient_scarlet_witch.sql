CREATE TABLE `key_rotation_attempts` (
	`resource_type` text NOT NULL,
	`resource_id` text NOT NULL,
	`attempt_count` integer NOT NULL,
	`status` text NOT NULL,
	`next_attempt_at` text,
	`last_error_code` text NOT NULL,
	`first_failed_at` text NOT NULL,
	`last_attempt_at` text NOT NULL,
	`last_attempt_id` text NOT NULL,
	`resolved_at` text,
	PRIMARY KEY(`resource_type`, `resource_id`),
	CONSTRAINT "key_rotation_attempt_count_bounded" CHECK("key_rotation_attempts"."attempt_count" BETWEEN 1 AND 1000000),
	CONSTRAINT "key_rotation_resource_type_allowlist" CHECK("key_rotation_attempts"."resource_type" IN ('evidence', 'package', 'jira_connection')),
	CONSTRAINT "key_rotation_error_code_allowlist" CHECK("key_rotation_attempts"."last_error_code" IN ('CRYPTOGRAPHIC_FAILURE', 'MISSING_METADATA', 'MISSING_OBJECT', 'RETAINED_KEY_UNAVAILABLE', 'STORAGE_OR_DATABASE_FAILURE')),
	CONSTRAINT "key_rotation_attempt_state_shape" CHECK(
    ("key_rotation_attempts"."status" IN ('retrying', 'action_required') AND "key_rotation_attempts"."next_attempt_at" IS NOT NULL AND "key_rotation_attempts"."resolved_at" IS NULL)
    OR ("key_rotation_attempts"."status" = 'resolved' AND "key_rotation_attempts"."next_attempt_at" IS NULL AND "key_rotation_attempts"."resolved_at" IS NOT NULL)
  )
);
--> statement-breakpoint
CREATE INDEX `idx_key_rotation_attempts_status_next` ON `key_rotation_attempts` (`status`,`next_attempt_at`);
