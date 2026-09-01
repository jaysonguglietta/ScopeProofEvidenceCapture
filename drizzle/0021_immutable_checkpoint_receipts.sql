ALTER TABLE `audit_checkpoints` ADD `external_receipt_sha256` text;--> statement-breakpoint
ALTER TABLE `audit_checkpoints` ADD `external_receipt_signature` text;--> statement-breakpoint
ALTER TABLE `audit_checkpoints` ADD `external_receipt_r2_key` text;--> statement-breakpoint
CREATE TRIGGER `audit_checkpoints_no_update`
BEFORE UPDATE ON `audit_checkpoints`
BEGIN
  SELECT RAISE(ABORT, 'audit_checkpoints are immutable');
END;--> statement-breakpoint
CREATE TRIGGER `audit_checkpoints_no_delete`
BEFORE DELETE ON `audit_checkpoints`
BEGIN
  SELECT RAISE(ABORT, 'audit_checkpoints are immutable');
END;
