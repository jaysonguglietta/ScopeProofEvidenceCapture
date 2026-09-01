CREATE TABLE `audit_batch_guards` (
	`id` text PRIMARY KEY NOT NULL,
	`baseline_changes` integer NOT NULL,
	`mutation_changes` integer DEFAULT 0 NOT NULL,
	`valid` integer DEFAULT 1 NOT NULL,
	CONSTRAINT "audit_batch_guards_valid" CHECK("audit_batch_guards"."valid" = 1)
);
