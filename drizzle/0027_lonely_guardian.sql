CREATE TABLE `audit_checkpoint_delivery_retry_state` (
	`checkpoint_id` text PRIMARY KEY NOT NULL,
	`checkpoint_sha256` text NOT NULL,
	`status` text NOT NULL,
	`attempt_count` integer DEFAULT 0 NOT NULL,
	`next_attempt_at` text,
	`lease_id` text,
	`lease_expires_at` text,
	`endpoint_origin` text,
	`last_attempt_id` text,
	`last_attempt_at` text,
	`last_failure_code` text,
	`delivered_attempt_id` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "checkpoint_delivery_retry_attempt_count_bounded" CHECK("audit_checkpoint_delivery_retry_state"."attempt_count" BETWEEN 0 AND 10),
	CONSTRAINT "checkpoint_delivery_retry_failure_code_allowlist" CHECK("audit_checkpoint_delivery_retry_state"."last_failure_code" IS NULL OR "audit_checkpoint_delivery_retry_state"."last_failure_code" IN (
    'AUDIT_HEAD_CHANGED', 'CHECKPOINT_CORE_INVALID', 'DELIVERY_REQUEST_FAILED', 'ENDPOINT_HTTP_ERROR',
    'EXTERNAL_RECEIPT_INVALID', 'RECEIPT_BINDING_FAILED', 'RECEIPT_STORAGE_FAILED',
    'DELIVERY_COMMIT_PRECONDITION_FAILED', 'DELIVERY_CLAIM_EXPIRED'
  )),
	CONSTRAINT "checkpoint_delivery_retry_state_shape" CHECK(
    ("audit_checkpoint_delivery_retry_state"."status" = 'retrying'
      AND "audit_checkpoint_delivery_retry_state"."attempt_count" BETWEEN 0 AND 9
      AND "audit_checkpoint_delivery_retry_state"."next_attempt_at" IS NOT NULL
      AND "audit_checkpoint_delivery_retry_state"."lease_id" IS NULL AND "audit_checkpoint_delivery_retry_state"."lease_expires_at" IS NULL AND "audit_checkpoint_delivery_retry_state"."endpoint_origin" IS NULL
      AND "audit_checkpoint_delivery_retry_state"."delivered_attempt_id" IS NULL
      AND (("audit_checkpoint_delivery_retry_state"."attempt_count" = 0 AND "audit_checkpoint_delivery_retry_state"."last_attempt_id" IS NULL AND "audit_checkpoint_delivery_retry_state"."last_attempt_at" IS NULL AND "audit_checkpoint_delivery_retry_state"."last_failure_code" IS NULL)
        OR ("audit_checkpoint_delivery_retry_state"."attempt_count" > 0 AND "audit_checkpoint_delivery_retry_state"."last_attempt_id" IS NOT NULL AND "audit_checkpoint_delivery_retry_state"."last_attempt_at" IS NOT NULL AND "audit_checkpoint_delivery_retry_state"."last_failure_code" IS NOT NULL)))
    OR ("audit_checkpoint_delivery_retry_state"."status" = 'claimed'
      AND "audit_checkpoint_delivery_retry_state"."attempt_count" BETWEEN 1 AND 10
      AND "audit_checkpoint_delivery_retry_state"."next_attempt_at" IS NOT NULL
      AND "audit_checkpoint_delivery_retry_state"."lease_id" IS NOT NULL AND "audit_checkpoint_delivery_retry_state"."lease_expires_at" IS NOT NULL AND "audit_checkpoint_delivery_retry_state"."endpoint_origin" IS NOT NULL
      AND "audit_checkpoint_delivery_retry_state"."last_attempt_id" IS NOT NULL AND "audit_checkpoint_delivery_retry_state"."last_attempt_at" IS NOT NULL
      AND "audit_checkpoint_delivery_retry_state"."delivered_attempt_id" IS NULL)
    OR ("audit_checkpoint_delivery_retry_state"."status" = 'action_required'
      AND "audit_checkpoint_delivery_retry_state"."attempt_count" = 10
      AND "audit_checkpoint_delivery_retry_state"."next_attempt_at" IS NULL
      AND "audit_checkpoint_delivery_retry_state"."lease_id" IS NULL AND "audit_checkpoint_delivery_retry_state"."lease_expires_at" IS NULL AND "audit_checkpoint_delivery_retry_state"."endpoint_origin" IS NULL
      AND "audit_checkpoint_delivery_retry_state"."last_attempt_id" IS NOT NULL AND "audit_checkpoint_delivery_retry_state"."last_attempt_at" IS NOT NULL AND "audit_checkpoint_delivery_retry_state"."last_failure_code" IS NOT NULL
      AND "audit_checkpoint_delivery_retry_state"."delivered_attempt_id" IS NULL)
    OR ("audit_checkpoint_delivery_retry_state"."status" = 'delivered'
      AND "audit_checkpoint_delivery_retry_state"."next_attempt_at" IS NULL
      AND "audit_checkpoint_delivery_retry_state"."lease_id" IS NULL AND "audit_checkpoint_delivery_retry_state"."lease_expires_at" IS NULL AND "audit_checkpoint_delivery_retry_state"."endpoint_origin" IS NULL
      AND "audit_checkpoint_delivery_retry_state"."last_failure_code" IS NULL
      AND (("audit_checkpoint_delivery_retry_state"."delivered_attempt_id" IS NULL AND "audit_checkpoint_delivery_retry_state"."last_attempt_id" IS NULL AND "audit_checkpoint_delivery_retry_state"."last_attempt_at" IS NULL)
        OR ("audit_checkpoint_delivery_retry_state"."delivered_attempt_id" IS NOT NULL AND "audit_checkpoint_delivery_retry_state"."delivered_attempt_id" = "audit_checkpoint_delivery_retry_state"."last_attempt_id" AND "audit_checkpoint_delivery_retry_state"."last_attempt_at" IS NOT NULL)))
  )
);
--> statement-breakpoint
CREATE INDEX `idx_checkpoint_delivery_retry_status_next` ON `audit_checkpoint_delivery_retry_state` (`status`,`next_attempt_at`);--> statement-breakpoint
CREATE INDEX `idx_checkpoint_delivery_retry_claim_expiry` ON `audit_checkpoint_delivery_retry_state` (`status`,`lease_expires_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_checkpoint_delivery_retry_delivered_attempt` ON `audit_checkpoint_delivery_retry_state` (`delivered_attempt_id`) WHERE "audit_checkpoint_delivery_retry_state"."delivered_attempt_id" IS NOT NULL;--> statement-breakpoint
WITH checkpoint_delivery_history AS (
	SELECT c.id AS checkpoint_id,
		c.checkpoint_sha256,
		c.created_at,
		c.external_status,
		(SELECT COUNT(*) FROM audit_checkpoint_delivery_attempts failed
			WHERE failed.checkpoint_id = c.id AND failed.status = 'failed') AS failure_count,
		(SELECT failed.id FROM audit_checkpoint_delivery_attempts failed
			WHERE failed.checkpoint_id = c.id AND failed.status = 'failed'
			ORDER BY failed.created_at DESC, failed.id DESC LIMIT 1) AS failed_attempt_id,
		(SELECT failed.attempted_at FROM audit_checkpoint_delivery_attempts failed
			WHERE failed.checkpoint_id = c.id AND failed.status = 'failed'
			ORDER BY failed.created_at DESC, failed.id DESC LIMIT 1) AS failed_attempt_at,
		(SELECT failed.failure_code FROM audit_checkpoint_delivery_attempts failed
			WHERE failed.checkpoint_id = c.id AND failed.status = 'failed'
			ORDER BY failed.created_at DESC, failed.id DESC LIMIT 1) AS failed_code,
		(SELECT delivered.id FROM audit_checkpoint_delivery_attempts delivered
			WHERE delivered.checkpoint_id = c.id AND delivered.status = 'delivered' LIMIT 1) AS delivered_attempt_id,
		(SELECT delivered.attempted_at FROM audit_checkpoint_delivery_attempts delivered
			WHERE delivered.checkpoint_id = c.id AND delivered.status = 'delivered' LIMIT 1) AS delivered_attempt_at
	FROM audit_checkpoints c
)
INSERT INTO audit_checkpoint_delivery_retry_state
	(checkpoint_id, checkpoint_sha256, status, attempt_count, next_attempt_at,
	 last_attempt_id, last_attempt_at, last_failure_code, delivered_attempt_id, created_at, updated_at)
SELECT checkpoint_id,
	checkpoint_sha256,
	CASE
		WHEN external_status = 'delivered' OR delivered_attempt_id IS NOT NULL THEN 'delivered'
		WHEN failure_count >= 10 THEN 'action_required'
		ELSE 'retrying'
	END,
	MIN(10, failure_count + CASE WHEN delivered_attempt_id IS NULL THEN 0 ELSE 1 END),
	CASE
		WHEN external_status = 'delivered' OR delivered_attempt_id IS NOT NULL OR failure_count >= 10 THEN NULL
		WHEN failure_count = 0 THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
		ELSE strftime('%Y-%m-%dT%H:%M:%fZ', failed_attempt_at,
			CASE failure_count
				WHEN 1 THEN '+60 seconds'
				WHEN 2 THEN '+120 seconds'
				WHEN 3 THEN '+240 seconds'
				WHEN 4 THEN '+480 seconds'
				WHEN 5 THEN '+960 seconds'
				WHEN 6 THEN '+1920 seconds'
				WHEN 7 THEN '+3840 seconds'
				WHEN 8 THEN '+7680 seconds'
				ELSE '+15360 seconds'
			END)
	END,
	CASE WHEN external_status = 'delivered' OR delivered_attempt_id IS NOT NULL THEN delivered_attempt_id ELSE failed_attempt_id END,
	CASE WHEN external_status = 'delivered' OR delivered_attempt_id IS NOT NULL THEN delivered_attempt_at ELSE failed_attempt_at END,
	CASE WHEN external_status = 'delivered' OR delivered_attempt_id IS NOT NULL THEN NULL ELSE failed_code END,
	delivered_attempt_id,
	created_at,
	strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
FROM checkpoint_delivery_history;--> statement-breakpoint
CREATE TRIGGER `audit_checkpoint_delivery_retry_state_checkpoint_binding`
BEFORE INSERT ON `audit_checkpoint_delivery_retry_state`
WHEN NOT EXISTS (
	SELECT 1 FROM audit_checkpoints c
	WHERE c.id = NEW.checkpoint_id AND c.checkpoint_sha256 = NEW.checkpoint_sha256
)
BEGIN
	SELECT RAISE(ABORT, 'checkpoint retry state does not match an immutable checkpoint');
END;--> statement-breakpoint
CREATE TRIGGER `audit_checkpoint_delivery_retry_state_identity_immutable`
BEFORE UPDATE ON `audit_checkpoint_delivery_retry_state`
WHEN NEW.checkpoint_id <> OLD.checkpoint_id
	OR NEW.checkpoint_sha256 <> OLD.checkpoint_sha256
	OR NEW.created_at <> OLD.created_at
BEGIN
	SELECT RAISE(ABORT, 'checkpoint retry identity is immutable');
END;--> statement-breakpoint
CREATE TRIGGER `audit_checkpoint_delivery_retry_state_delivered_terminal`
BEFORE UPDATE ON `audit_checkpoint_delivery_retry_state`
WHEN OLD.status = 'delivered'
BEGIN
	SELECT RAISE(ABORT, 'delivered checkpoint retry state is terminal');
END;--> statement-breakpoint
CREATE TRIGGER `audit_checkpoint_delivery_retry_state_no_delete`
BEFORE DELETE ON `audit_checkpoint_delivery_retry_state`
BEGIN
	SELECT RAISE(ABORT, 'checkpoint retry state cannot be deleted');
END;--> statement-breakpoint
CREATE TRIGGER `audit_checkpoint_delivery_attempts_require_active_claim`
BEFORE INSERT ON `audit_checkpoint_delivery_attempts`
WHEN NOT EXISTS (
	SELECT 1
	FROM audit_checkpoint_delivery_retry_state retry
	JOIN audit_checkpoints checkpoint ON checkpoint.id = retry.checkpoint_id
	WHERE retry.checkpoint_id = NEW.checkpoint_id
		AND retry.checkpoint_sha256 = NEW.checkpoint_sha256
		AND retry.status = 'claimed'
		AND retry.lease_id IS NOT NULL
		AND retry.last_attempt_id = NEW.id
		AND retry.last_attempt_at = NEW.attempted_at
		AND retry.endpoint_origin = NEW.endpoint_origin
		AND checkpoint.checkpoint_sha256 = NEW.checkpoint_sha256
		AND checkpoint.sequence = NEW.sequence
)
BEGIN
	SELECT RAISE(ABORT, 'checkpoint delivery completion does not own the active claim');
END;--> statement-breakpoint
CREATE TRIGGER `audit_checkpoint_delivery_attempts_complete_claim`
AFTER INSERT ON `audit_checkpoint_delivery_attempts`
BEGIN
	UPDATE audit_checkpoint_delivery_retry_state
	SET status = CASE
			WHEN NEW.status = 'delivered' THEN 'delivered'
			WHEN attempt_count >= 10 THEN 'action_required'
			ELSE 'retrying'
		END,
		next_attempt_at = CASE
			WHEN NEW.status = 'failed' AND attempt_count < 10 THEN next_attempt_at
			ELSE NULL
		END,
		lease_id = NULL,
		lease_expires_at = NULL,
		endpoint_origin = NULL,
		last_failure_code = CASE WHEN NEW.status = 'failed' THEN NEW.failure_code ELSE NULL END,
		delivered_attempt_id = CASE WHEN NEW.status = 'delivered' THEN NEW.id ELSE NULL END,
		updated_at = NEW.created_at
	WHERE checkpoint_id = NEW.checkpoint_id
		AND checkpoint_sha256 = NEW.checkpoint_sha256
		AND status = 'claimed'
		AND last_attempt_id = NEW.id
		AND last_attempt_at = NEW.attempted_at;
END;
