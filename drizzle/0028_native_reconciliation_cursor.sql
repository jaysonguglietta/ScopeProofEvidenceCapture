CREATE TABLE `native_provenance_reconciliation_queue` (
	`artifact_id` text PRIMARY KEY NOT NULL,
	`due_at` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "native_reconciliation_queue_due_valid" CHECK(unixepoch("native_provenance_reconciliation_queue"."due_at") IS NOT NULL)
);
--> statement-breakpoint
CREATE INDEX `idx_native_reconciliation_queue_due` ON `native_provenance_reconciliation_queue` (unixepoch("due_at"),`artifact_id`);--> statement-breakpoint
CREATE TABLE `native_provenance_reconciliation_state` (
	`id` text PRIMARY KEY NOT NULL,
	`revision` integer DEFAULT 0 NOT NULL,
	`pending_cursor_expires_epoch` integer,
	`pending_cursor_device_id` text,
	`orphan_cursor_due_epoch` integer,
	`orphan_cursor_artifact_id` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	CONSTRAINT "native_reconciliation_singleton_identity" CHECK("native_provenance_reconciliation_state"."id" = 'native_provenance'),
	CONSTRAINT "native_reconciliation_revision_nonnegative" CHECK("native_provenance_reconciliation_state"."revision" >= 0),
	CONSTRAINT "native_reconciliation_pending_cursor_shape" CHECK(
    ("native_provenance_reconciliation_state"."pending_cursor_expires_epoch" IS NULL AND "native_provenance_reconciliation_state"."pending_cursor_device_id" IS NULL)
    OR ("native_provenance_reconciliation_state"."pending_cursor_expires_epoch" IS NOT NULL AND "native_provenance_reconciliation_state"."pending_cursor_device_id" IS NOT NULL)
  ),
	CONSTRAINT "native_reconciliation_orphan_cursor_shape" CHECK(
    ("native_provenance_reconciliation_state"."orphan_cursor_due_epoch" IS NULL AND "native_provenance_reconciliation_state"."orphan_cursor_artifact_id" IS NULL)
    OR ("native_provenance_reconciliation_state"."orphan_cursor_due_epoch" IS NOT NULL AND "native_provenance_reconciliation_state"."orphan_cursor_artifact_id" IS NOT NULL)
  )
);
--> statement-breakpoint
CREATE INDEX `idx_capture_devices_pending_reconciliation_cursor` ON `capture_devices` (unixepoch("chain_pending_expires_at"),`id`) WHERE "capture_devices"."chain_pending_lease_id" IS NOT NULL AND "capture_devices"."chain_pending_expires_at" IS NOT NULL;--> statement-breakpoint
INSERT INTO `native_provenance_reconciliation_queue` (`artifact_id`, `due_at`)
SELECT e.id,
  CASE
    WHEN unixepoch(e.created_at) IS NULL THEN strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
    ELSE strftime('%Y-%m-%dT%H:%M:%fZ', e.created_at, '+10 minutes')
  END
FROM evidence_artifacts e
WHERE e.device_id IS NOT NULL AND e.type = 'screenshot' AND e.content_type = 'image/png'
  AND e.status IN ('needs_review', 'approved', 'expiring')
  AND e.source LIKE 'Scopeproof Capture / %'
  AND NOT EXISTS (SELECT 1 FROM native_evidence_manifests n WHERE n.artifact_id = e.id);--> statement-breakpoint
INSERT INTO `native_provenance_reconciliation_state`
  (`id`, `revision`, `pending_cursor_expires_epoch`, `pending_cursor_device_id`,
   `orphan_cursor_due_epoch`, `orphan_cursor_artifact_id`)
VALUES ('native_provenance', 0, NULL, NULL, NULL, NULL);--> statement-breakpoint
CREATE TRIGGER `native_provenance_reconciliation_state_identity_immutable`
BEFORE UPDATE ON `native_provenance_reconciliation_state`
WHEN NEW.id <> OLD.id OR NEW.created_at <> OLD.created_at
BEGIN
  SELECT RAISE(ABORT, 'native reconciliation cursor identity is immutable');
END;--> statement-breakpoint
CREATE TRIGGER `native_provenance_reconciliation_state_revision_cas`
BEFORE UPDATE ON `native_provenance_reconciliation_state`
WHEN NEW.revision <> OLD.revision + 1
BEGIN
  SELECT RAISE(ABORT, 'native reconciliation cursor revision must advance exactly once');
END;--> statement-breakpoint
CREATE TRIGGER `native_provenance_reconciliation_state_no_delete`
BEFORE DELETE ON `native_provenance_reconciliation_state`
BEGIN
  SELECT RAISE(ABORT, 'native reconciliation cursor state cannot be deleted');
END;
