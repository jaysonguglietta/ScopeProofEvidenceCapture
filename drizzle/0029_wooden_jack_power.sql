CREATE TABLE `evidence_requirements` (
	`id` text PRIMARY KEY NOT NULL,
	`assessment_id` text NOT NULL,
	`control_id` text NOT NULL,
	`system` text NOT NULL,
	`revision` integer NOT NULL,
	`minimum_artifacts` integer NOT NULL,
	`owner_id` text,
	`reason` text NOT NULL,
	`created_by` text NOT NULL,
	`created_at` text NOT NULL,
	CONSTRAINT "evidence_requirements_revision_positive" CHECK("evidence_requirements"."revision" > 0),
	CONSTRAINT "evidence_requirements_minimum_bounded" CHECK("evidence_requirements"."minimum_artifacts" BETWEEN 1 AND 25)
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_evidence_requirements_revision` ON `evidence_requirements` (`assessment_id`,`control_id`,`system`,`revision`);