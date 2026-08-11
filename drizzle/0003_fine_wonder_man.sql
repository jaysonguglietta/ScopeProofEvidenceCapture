ALTER TABLE `evidence_artifacts` ADD `framework` text DEFAULT 'PCI DSS 4.0.1' NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `catalog_version` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `environment` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `assessment_period` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `evidence_owner` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `tags_json` text DEFAULT '[]' NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `expected_evidence` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `mapped_controls_json` text DEFAULT '[]' NOT NULL;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `manual_redactions` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
CREATE INDEX `idx_evidence_framework_control` ON `evidence_artifacts` (`framework`,`control_id`);