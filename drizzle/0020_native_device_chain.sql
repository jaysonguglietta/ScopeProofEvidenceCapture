ALTER TABLE `capture_devices` ADD `provenance_key_id` text;--> statement-breakpoint
ALTER TABLE `capture_devices` ADD `provenance_public_key` text;--> statement-breakpoint
ALTER TABLE `capture_devices` ADD `chain_sequence` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `capture_devices` ADD `chain_event_hash` text DEFAULT 'GENESIS' NOT NULL;--> statement-breakpoint
ALTER TABLE `capture_devices` ADD `chain_pending_lease_id` text;--> statement-breakpoint
ALTER TABLE `capture_devices` ADD `chain_pending_sequence` integer;--> statement-breakpoint
ALTER TABLE `capture_devices` ADD `chain_pending_previous_hash` text;--> statement-breakpoint
ALTER TABLE `capture_devices` ADD `chain_pending_event_hash` text;--> statement-breakpoint
ALTER TABLE `capture_devices` ADD `chain_pending_evidence_id` text;--> statement-breakpoint
ALTER TABLE `capture_devices` ADD `chain_pending_expires_at` text;--> statement-breakpoint
CREATE UNIQUE INDEX `idx_capture_devices_provenance_key` ON `capture_devices` (`provenance_key_id`);