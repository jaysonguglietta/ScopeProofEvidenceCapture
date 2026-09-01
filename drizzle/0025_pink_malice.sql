CREATE TABLE `audit_checkpoint_delivery_attempts` (
	`id` text PRIMARY KEY NOT NULL,
	`checkpoint_id` text NOT NULL,
	`checkpoint_sha256` text NOT NULL,
	`sequence` integer NOT NULL,
	`endpoint_origin` text NOT NULL,
	`attempted_at` text NOT NULL,
	`status` text NOT NULL,
	`external_receipt` text,
	`external_receipt_sha256` text,
	`external_receipt_signature` text,
	`external_receipt_r2_key` text,
	`failure_code` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "checkpoint_delivery_attempt_shape" CHECK(
    ("audit_checkpoint_delivery_attempts"."status" = 'delivered'
      AND "audit_checkpoint_delivery_attempts"."external_receipt" IS NOT NULL
      AND "audit_checkpoint_delivery_attempts"."external_receipt_sha256" IS NOT NULL
      AND "audit_checkpoint_delivery_attempts"."external_receipt_signature" IS NOT NULL
      AND "audit_checkpoint_delivery_attempts"."external_receipt_r2_key" IS NOT NULL
      AND "audit_checkpoint_delivery_attempts"."failure_code" IS NULL)
    OR
    ("audit_checkpoint_delivery_attempts"."status" = 'failed'
      AND "audit_checkpoint_delivery_attempts"."external_receipt" IS NULL
      AND "audit_checkpoint_delivery_attempts"."external_receipt_sha256" IS NULL
      AND "audit_checkpoint_delivery_attempts"."external_receipt_signature" IS NULL
      AND "audit_checkpoint_delivery_attempts"."external_receipt_r2_key" IS NULL
      AND "audit_checkpoint_delivery_attempts"."failure_code" IS NOT NULL)
  )
);
--> statement-breakpoint
CREATE INDEX `idx_checkpoint_delivery_attempts_checkpoint_created` ON `audit_checkpoint_delivery_attempts` (`checkpoint_id`,`created_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_checkpoint_delivery_attempts_delivered` ON `audit_checkpoint_delivery_attempts` (`checkpoint_id`) WHERE "audit_checkpoint_delivery_attempts"."status" = 'delivered';--> statement-breakpoint
CREATE UNIQUE INDEX `idx_checkpoint_delivery_attempts_r2_key` ON `audit_checkpoint_delivery_attempts` (`external_receipt_r2_key`) WHERE "audit_checkpoint_delivery_attempts"."external_receipt_r2_key" IS NOT NULL;--> statement-breakpoint
CREATE TRIGGER `audit_checkpoint_delivery_attempts_no_update`
BEFORE UPDATE ON `audit_checkpoint_delivery_attempts`
BEGIN
	SELECT RAISE(ABORT, 'audit checkpoint delivery attempts are immutable');
END;--> statement-breakpoint
CREATE TRIGGER `audit_checkpoint_delivery_attempts_no_delete`
BEFORE DELETE ON `audit_checkpoint_delivery_attempts`
BEGIN
	SELECT RAISE(ABORT, 'audit checkpoint delivery attempts are immutable');
END;
