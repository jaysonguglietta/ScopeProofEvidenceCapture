ALTER TABLE `evidence_artifacts` ADD `jira_issue_key` text;--> statement-breakpoint
ALTER TABLE `evidence_artifacts` ADD `jira_issue_url` text;--> statement-breakpoint
CREATE INDEX `idx_evidence_jira_issue` ON `evidence_artifacts` (`jira_issue_key`);