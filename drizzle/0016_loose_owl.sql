ALTER TABLE `evidence_artifacts` ADD `rotation_lease_id` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `rotation_lease_expires_at` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `rotation_pending_r2_key` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `rotation_previous_r2_key` text;--> statement-breakpoint
ALTER TABLE `export_packages` ADD `rotation_lease_id` text;--> statement-breakpoint
ALTER TABLE `export_packages` ADD `rotation_lease_expires_at` text;--> statement-breakpoint
ALTER TABLE `export_packages` ADD `rotation_pending_r2_key` text;--> statement-breakpoint
ALTER TABLE `export_packages` ADD `rotation_previous_r2_key` text;