CREATE TABLE `security_invariants` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL,
	`created_at` text DEFAULT CURRENT_TIMESTAMP NOT NULL
);
--> statement-breakpoint
INSERT OR IGNORE INTO `security_invariants` (`key`, `value`)
SELECT 'admin_bootstrap', `id` FROM `users` WHERE `role` = 'admin' ORDER BY `created_at` LIMIT 1;
--> statement-breakpoint
CREATE TRIGGER `security_invariants_no_update`
BEFORE UPDATE ON `security_invariants`
BEGIN
  SELECT RAISE(ABORT, 'security invariants are immutable');
END;
--> statement-breakpoint
CREATE TRIGGER `security_invariants_no_delete`
BEFORE DELETE ON `security_invariants`
BEGIN
  SELECT RAISE(ABORT, 'security invariants are immutable');
END;
--> statement-breakpoint
CREATE TRIGGER `users_preserve_last_admin`
BEFORE UPDATE OF `role` ON `users`
WHEN OLD.`role` = 'admin' AND NEW.`role` != 'admin' AND (SELECT COUNT(*) FROM `users` WHERE `role` = 'admin') <= 1
BEGIN
  SELECT RAISE(ABORT, 'the final administrator cannot be demoted');
END;
--> statement-breakpoint
CREATE TRIGGER `users_preserve_last_admin_delete`
BEFORE DELETE ON `users`
WHEN OLD.`role` = 'admin' AND (SELECT COUNT(*) FROM `users` WHERE `role` = 'admin') <= 1
BEGIN
  SELECT RAISE(ABORT, 'the final administrator cannot be deleted');
END;
