ALTER TABLE `native_evidence_manifests` ADD `chain_sequence` integer;--> statement-breakpoint
ALTER TABLE `native_evidence_manifests` ADD `chain_event_hash` text;--> statement-breakpoint
ALTER TABLE `native_evidence_manifests` ADD `provenance_key_id` text;--> statement-breakpoint
CREATE UNIQUE INDEX `idx_native_manifest_device_sequence` ON `native_evidence_manifests` (`device_id`,`chain_sequence`);--> statement-breakpoint
CREATE TRIGGER `native_evidence_manifests_no_update`
BEFORE UPDATE ON `native_evidence_manifests`
BEGIN
  SELECT RAISE(ABORT, 'native evidence manifests are immutable');
END;--> statement-breakpoint
CREATE TRIGGER `native_evidence_manifests_no_delete`
BEFORE DELETE ON `native_evidence_manifests`
BEGIN
  SELECT RAISE(ABORT, 'native evidence manifests are immutable');
END;
