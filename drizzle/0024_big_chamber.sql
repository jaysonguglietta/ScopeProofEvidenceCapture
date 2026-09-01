CREATE TABLE `control_catalogs` (
	`id` text PRIMARY KEY NOT NULL,
	`framework` text NOT NULL,
	`version` text NOT NULL,
	`title` text NOT NULL,
	`controls_json` text NOT NULL,
	`digest_sha256` text NOT NULL,
	`status` text DEFAULT 'active' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_control_catalog_framework_version` ON `control_catalogs` (`framework`,`version`);--> statement-breakpoint
CREATE UNIQUE INDEX `idx_control_catalog_digest` ON `control_catalogs` (`digest_sha256`);--> statement-breakpoint
ALTER TABLE `evidence_occurrences` ADD `last_review_event_id` text;--> statement-breakpoint
INSERT INTO `control_catalogs` (`id`,`framework`,`version`,`title`,`controls_json`,`digest_sha256`,`status`)
VALUES (
  'pci-dss-4.0.1-scopeproof-operations-v1',
  'PCI DSS',
  '4.0.1',
  'PCI DSS 4.0.1 · Scopeproof operations catalog',
  '[{"defaultEvidence":"Current network security control inventory and reviewed configuration.","id":"1.2.5","requirement":"Requirement 1","title":"Maintain an inventory of network security controls"},{"defaultEvidence":"Approved configuration standard and implementation evidence for each scoped component.","id":"2.2.1","requirement":"Requirement 2","title":"Configuration standards cover all system components"},{"defaultEvidence":"Key inventory, location, custodian, and access-control evidence.","id":"3.5.1.1","requirement":"Requirement 3","title":"Cryptographic keys are stored in the fewest locations"},{"defaultEvidence":"Transport configuration proving approved protocol and cipher enforcement.","id":"4.2.1","requirement":"Requirement 4","title":"Strong cryptography protects PAN during transmission"},{"defaultEvidence":"Versioned software inventory or SBOM bound to an immutable source revision.","id":"6.3.2","requirement":"Requirement 6","title":"Software inventory identifies custom and third-party components"},{"defaultEvidence":"Dated access review with population, reviewer, exceptions, and disposition.","id":"7.2.5","requirement":"Requirement 7","title":"Application and system accounts are reviewed periodically"},{"defaultEvidence":"Authentication policy and enforcement configuration for scoped identities.","id":"8.3.6","requirement":"Requirement 8","title":"Authentication factors are protected from misuse"},{"defaultEvidence":"Review schedule, alert configuration, and completed review record.","id":"10.4.1","requirement":"Requirement 10","title":"Audit logs are reviewed at least once daily"},{"defaultEvidence":"Authenticated scan results, scope, date, and remediation disposition.","id":"11.3.1","requirement":"Requirement 11","title":"Internal vulnerability scans occur every three months"},{"defaultEvidence":"Approved targeted risk analysis with scope, assumptions, frequency, and owner.","id":"12.3.1","requirement":"Requirement 12","title":"Targeted risk analyses document required elements"}]',
  'dd51b71a3ccbc0ddbcdb12a519ee8c1d5b9f6728323b3b621cbc165aa5c50abd',
  'active'
);--> statement-breakpoint
CREATE TABLE `evidence_review_events` (
	`id` text PRIMARY KEY NOT NULL,
	`evidence_id` text NOT NULL,
	`occurrence_id` text NOT NULL,
	`action` text NOT NULL,
	`previous_status` text NOT NULL,
	`resulting_status` text NOT NULL,
	`rationale` text NOT NULL,
	`expected_sha256` text NOT NULL,
	`replacement_evidence_id` text,
	`actor_id` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_review_events_evidence_created` ON `evidence_review_events` (`evidence_id`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_review_events_actor_created` ON `evidence_review_events` (`actor_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `finding_events` (
	`id` text PRIMARY KEY NOT NULL,
	`finding_id` text NOT NULL,
	`action` text NOT NULL,
	`actor_id` text NOT NULL,
	`details_json` text DEFAULT '{}' NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
CREATE INDEX `idx_finding_events_finding_created` ON `finding_events` (`finding_id`,`created_at`);--> statement-breakpoint
CREATE TABLE `findings` (
	`id` text PRIMARY KEY NOT NULL,
	`assessment_id` text NOT NULL,
	`control_id` text,
	`evidence_id` text,
	`job_id` text,
	`title` text NOT NULL,
	`description` text NOT NULL,
	`severity` text NOT NULL,
	`status` text DEFAULT 'open' NOT NULL,
	`owner_id` text,
	`due_at` text,
	`resolution` text,
	`created_by` text NOT NULL,
	`resolved_by` text,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`updated_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL,
	`resolved_at` text
);
--> statement-breakpoint
CREATE INDEX `idx_findings_assessment_status_created` ON `findings` (`assessment_id`,`status`,`created_at`);--> statement-breakpoint
CREATE INDEX `idx_findings_owner_status` ON `findings` (`owner_id`,`status`);--> statement-breakpoint
CREATE INDEX `idx_findings_evidence` ON `findings` (`evidence_id`);--> statement-breakpoint
CREATE TABLE `retention_hold_release_requests` (
	`id` text PRIMARY KEY NOT NULL,
	`evidence_id` text NOT NULL,
	`requested_by` text NOT NULL,
	`reason` text NOT NULL,
	`request_digest` text NOT NULL,
	`hold_owner_id` text NOT NULL,
	`hold_reason` text NOT NULL,
	`hold_expires_at` text NOT NULL,
	`status` text DEFAULT 'pending' NOT NULL,
	`requested_at` text NOT NULL,
	`expires_at` text NOT NULL,
	`approved_by` text,
	`approved_at` text,
	`released_at` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `idx_hold_release_pending_evidence` ON `retention_hold_release_requests` (`evidence_id`) WHERE "retention_hold_release_requests"."status" = 'pending';--> statement-breakpoint
CREATE UNIQUE INDEX `idx_hold_release_digest` ON `retention_hold_release_requests` (`request_digest`);--> statement-breakpoint
CREATE INDEX `idx_hold_release_status_expiry` ON `retention_hold_release_requests` (`status`,`expires_at`);--> statement-breakpoint
ALTER TABLE `assessments` ADD `catalog_id` text;--> statement-breakpoint
ALTER TABLE `assessments` ADD `scope_mode` text DEFAULT 'explicit' NOT NULL;--> statement-breakpoint
UPDATE `assessments`
SET `catalog_id` = 'pci-dss-4.0.1-scopeproof-operations-v1'
WHERE `framework` = 'PCI DSS 4.0.1'
  AND json_valid(`controls_json`)
  AND NOT EXISTS (
    SELECT 1 FROM json_each(`assessments`.`controls_json`) scoped
    WHERE scoped.value NOT IN ('1.2.5','2.2.1','3.5.1.1','4.2.1','6.3.2','7.2.5','8.3.6','10.4.1','11.3.1','12.3.1')
  );
