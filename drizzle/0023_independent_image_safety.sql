ALTER TABLE `evidence_artifacts` ADD `server_safety_scan_sha256` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `server_safety_scan_policy` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `server_safety_scan_completed_at` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `server_safety_scanner_origin` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `server_safety_receipt_sha256` text;