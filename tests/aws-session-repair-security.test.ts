import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { repairDue, repairFailure } from "../infra/aws/cdk/runtime/repair-upload-projections/retry-policy.ts";

const migration = readFileSync(new URL("../infra/aws/database/010_session_and_repair_security.sql", import.meta.url), "utf8");

test("provisioning schema inspection is separate from the execute-only runtime identity", () => {
  const provisioner = readFileSync(new URL("../infra/aws/cdk/runtime/provision-tenant/index.mjs", import.meta.url), "utf8");
  const verifier = provisioner.slice(provisioner.indexOf("async function verifyDatabase("), provisioner.indexOf("function executeAdmin("));
  const runtimeTransaction = verifier.slice(verifier.indexOf("const runtimeIdentityResults"), verifier.indexOf("const inspectionResults"));
  assert.match(runtimeTransaction, /runTransaction\(config.databaseSecretArn/);
  assert.match(runtimeTransaction, /pg_catalog\.pg_roles/);
  assert.doesNotMatch(runtimeTransaction, /FROM scopeproof\./);
  assert.match(verifier, /const inspectionResults = await runTransaction\(config.provisioningDatabaseSecretArn/);
  assert.match(verifier, /\.\.\.runtimeIdentityResults, \.\.\.inspectionResults\.slice\(1\)/);
  const grant = readFileSync(new URL("../infra/aws/database/002_runtime_role.sql", import.meta.url), "utf8");
  assert.match(grant, /REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof/);
  assert.doesNotMatch(grant, /GRANT SELECT|GRANT ALL|GRANT UPDATE|GRANT INSERT/);
});

test("forward security migration rejects NULL and binds delayed repair to immutable reservation time", () => {
  assert.match(migration, /actor_role IS NULL OR actor_role NOT IN/);
  const fresh = migration.slice(migration.indexOf("CREATE OR REPLACE FUNCTION scopeproof.create_upload_intent("), migration.indexOf("CREATE FUNCTION scopeproof.repair_upload_intent("));
  assert.ok(fresh.indexOf("IF intent_exists THEN") < fresh.indexOf("device proof is outside the fresh issuance window"));
  const repair = migration.slice(migration.indexOf("CREATE FUNCTION scopeproof.repair_upload_intent("));
  assert.match(repair, /p_reserved_at < clock_timestamp\(\) - interval '14 days'/);
  assert.match(repair, /signedAt'\)::timestamptz < p_reserved_at/);
  assert.match(migration, /p_authenticated_at > principal.sessions_revoked_through/);
  assert.match(migration, /session-revoke:/);
});

test("repair backoff is bounded, and exhausted rows require explicit operator action", () => {
  const now = new Date("2026-09-08T12:00:00.000Z");
  const first = repairFailure(0, now);
  assert.equal(first.status, "RETRY");
  assert.equal(repairDue(first, now), false);
  assert.equal(repairDue(first, new Date(first.retryAt)), true);
  const last = repairFailure(7, now);
  assert.equal(last.status, "ACTION_REQUIRED");
  assert.equal(last.attemptCount, 8);
  assert.equal(repairDue(last, new Date(now.getTime() + 86_400_000)), false);
  assert.throws(() => repairFailure(-1, now));
  assert.throws(() => repairDue({ retryAt: "not-a-time" }, now));
});

const pgUrl = process.env.SCOPEPROOF_TEST_PG_URL;
test("real PostgreSQL migration, NULL authorization, revocation and six-minute repair", {
  skip: !pgUrl ? "Set SCOPEPROOF_TEST_PG_URL to an empty local scopeproof_test_* database; no PostgreSQL engine is assumed." : false,
}, () => {
  const url = new URL(pgUrl!);
  assert.ok(["postgres:", "postgresql:"].includes(url.protocol));
  assert.ok(["localhost", "127.0.0.1", "[::1]"].includes(url.hostname), "Only a local disposable database is permitted.");
  assert.match(url.pathname, /^\/scopeproof_test_[a-z0-9_]+$/);
  const stripTransaction = (sql: string) => sql.replace(/^BEGIN;$/m, "").replace(/^COMMIT;$/m, "");
  const sql = [
    "DO $$ BEGIN IF current_database() !~ '^scopeproof_test_' OR to_regnamespace('scopeproof') IS NOT NULL THEN RAISE EXCEPTION 'requires empty disposable test database'; END IF; END $$;",
    ...["001_tenant_schema.sql", "006_evidence_access_api.sql", "009_runtime_hardening.sql", "010_session_and_repair_security.sql"].map((file) =>
      readFileSync(new URL("../infra/aws/database/" + file, import.meta.url), "utf8")),
    "BEGIN; CREATE ROLE tenant_scopeproof_test_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; GRANT tenant_scopeproof_test_runtime TO CURRENT_USER;",
    stripTransaction(readFileSync(new URL("../infra/aws/database/002_runtime_role.sql", import.meta.url), "utf8")).replaceAll("__SCOPEPROOF_RUNTIME_ROLE__", "tenant_scopeproof_test_runtime"),
    stripTransaction(readFileSync(new URL("./fixtures/aws-session-repair-semantic.sql", import.meta.url), "utf8")),
    "DROP OWNED BY tenant_scopeproof_test_runtime; DROP ROLE tenant_scopeproof_test_runtime; COMMIT;",
  ].join("\n");
  const result = spawnSync("psql", ["--no-psqlrc", "--set=ON_ERROR_STOP=1", "--dbname", pgUrl!], {
    input: sql, encoding: "utf8", timeout: 60_000, maxBuffer: 2_000_000,
  });
  assert.equal(result.error, undefined, "psql must be installed for an opted-in semantic run.");
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /scopeproof semantic checks passed/);
});
