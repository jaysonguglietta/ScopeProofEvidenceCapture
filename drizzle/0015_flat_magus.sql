DROP INDEX `idx_evidence_sha_source_control_assessment`;--> statement-breakpoint
CREATE INDEX `idx_evidence_dedupe_unscoped` ON `evidence_artifacts` (`sha256`,`source`,`control_id`) WHERE "evidence_artifacts"."assessment_id" IS NULL AND "evidence_artifacts"."status" NOT IN ('expired', 'purged');--> statement-breakpoint
CREATE INDEX `idx_evidence_sha_source_control_assessment` ON `evidence_artifacts` (`sha256`,`source`,`control_id`,`assessment_id`) WHERE "evidence_artifacts"."status" NOT IN ('expired', 'purged');
