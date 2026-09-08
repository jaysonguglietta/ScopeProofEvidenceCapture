import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { PGlite } from "@electric-sql/pglite";
import { canonical, mappingDigest, validateMapping, validateApproval, roleKinds, scramVerifier } from "../infra/aws/cdk/runtime/bootstrap-database/contract.mjs";
import { executableHistoricalBaseline, historicalBaselineSha256 } from "../infra/aws/database/bootstrap-baseline.mjs";

const tenant = `ten_${"a".repeat(32)}`;
const mapping = { schemaVersion: 1, tenantId: tenant, revision: 1, account: "111111111111", region: "us-east-1",
  clusterArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof-test", databaseName: "scopeproof_test",
  ownerUsername: `scopeproof_${"a".repeat(32)}_owner`, roles: roleKinds.map((kind: string) => ({ kind, username: `tenant_${"a".repeat(32)}_${kind.toLowerCase()}`,
    secretArn: `arn:aws:secretsmanager:us-east-1:111111111111:secret:scopeproof/test/${kind}-AbCdEf` })) };

test("bootstrap mapping and approval bind exact tenant, role, account, revision, execution and expiry", () => {
  assert.equal(mappingDigest(mapping), mappingDigest(JSON.parse(canonical(mapping))));
  assert.throws(() => validateMapping({ ...mapping, unexpected: true }));
  assert.throws(() => validateMapping({ ...mapping, roles: [mapping.roles[0], ...mapping.roles.slice(1).map((role) => ({ ...role, username: mapping.roles[0].username }))] }));
  assert.throws(() => validateMapping({ ...mapping, ownerUsername: `scopeproof_${"b".repeat(32)}_owner` }));
  const executionId = "arn:aws:states:us-east-1:111111111111:execution:scopeproof-database-bootstrap:approved-run";
  const now = Date.parse("2026-09-08T12:00:00.000Z");
  const item = { PK: { S: `BOOTSTRAP#${tenant}` }, SK: { S: executionId }, kind: { S: "DatabaseBootstrapApproval" }, decision: { S: "APPROVED" },
    mappingDigest: { S: mappingDigest(mapping) }, executionId: { S: executionId }, approvedAt: { S: "2026-09-08T11:59:00.000Z" },
    expiresAt: { S: "2026-09-08T12:10:00.000Z" }, approvedBy: { S: "arn:aws:iam::111111111111:role/platform-approver" } };
  assert.equal(validateApproval(item, { mapping, executionId, now }), true);
  for (const changed of [{ ...item, mappingDigest: { S: "b".repeat(64) } }, { ...item, expiresAt: { S: "2026-09-08T12:20:00.000Z" } }, { ...item, executionId: { S: executionId + "different" } }]) assert.throws(() => validateApproval(changed, { mapping, executionId, now }));
  assert.throws(() => validateApproval(item, { mapping, executionId, now: now + 900_000 }));
  const verifier = scramVerifier("A".repeat(40));
  assert.match(verifier, /^SCRAM-SHA-256\$4096:/);
  assert.ok(!verifier.includes("A".repeat(40)));
});

test("historical bootstrap transform is source-shared and exact-byte guarded", () => {
  const sql = readFileSync(new URL("../infra/aws/database/001_tenant_schema.sql", import.meta.url), "utf8");
  assert.equal(historicalBaselineSha256, "be0798f20decabb911f0187c8ee499b5277b313500658d4bce99a935724785df");
  assert.match(executableHistoricalBaseline(sql), /BEGIN;\nSET LOCAL check_function_bodies = off;/);
  assert.throws(() => executableHistoricalBaseline(sql + "\n"));
  const provisioner = readFileSync(new URL("../infra/aws/cdk/runtime/provision-tenant/index.mjs", import.meta.url), "utf8");
  assert.match(provisioner, /executableHistoricalBaseline\(tenantSchemaSql\)/);
  assert.doesNotMatch(provisioner, /ADMIN_SECRET_ARN|CREATE ROLE|ALTER ROLE|CREATE DATABASE|scopeproof_admin/);
  assert.match(provisioner, /SET LOCAL ROLE/);
  const tenantStack = readFileSync(new URL("../infra/aws/cdk/lib/tenant-stack.ts", import.meta.url), "utf8");
  assert.doesNotMatch(tenantStack, /databaseAdminSecret|ADMIN_SECRET_ARN|shared\.databaseCluster\.secret/);
  for (const filename of ["002_runtime_role.sql", "003_ingest_role.sql", "004_evidence_control_role.sql", "005_legal_hold_api_role.sql", "007_evidence_read_role.sql", "008_api_audit_signer_role.sql"]) assert.doesNotMatch(readFileSync(new URL(`../infra/aws/database/${filename}`, import.meta.url), "utf8"), /ALTER ROLE|CREATE ROLE/);
});

test("real PostgreSQL role semantics: tenant provisioning cannot delegate, create roles, or read another tenant's objects", async () => {
  const pg = new PGlite();
  try {
    await pg.exec(`CREATE ROLE tenant_a_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
      CREATE ROLE tenant_b_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
      CREATE ROLE tenant_a_provisioner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
      CREATE ROLE tenant_a_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS;
      GRANT tenant_a_owner TO tenant_a_provisioner WITH ADMIN FALSE, INHERIT FALSE, SET TRUE;
      CREATE SCHEMA tenant_a AUTHORIZATION tenant_a_owner;
      CREATE SCHEMA tenant_b AUTHORIZATION tenant_b_owner;
      SET ROLE tenant_b_owner; CREATE TABLE tenant_b.secrets(value text); INSERT INTO tenant_b.secrets VALUES ('synthetic-only'); RESET ROLE;
      SET SESSION AUTHORIZATION tenant_a_provisioner;`);
    await assert.rejects(pg.exec("CREATE ROLE forbidden_role"));
    await assert.rejects(pg.exec("GRANT tenant_a_owner TO tenant_a_runtime"));
    await assert.rejects(pg.exec("SET ROLE tenant_b_owner"));
    await assert.rejects(pg.query("SELECT * FROM tenant_b.secrets"));
    await assert.rejects(pg.exec("CREATE TABLE tenant_a.before_set_role(value text)"));
    await pg.exec("SET ROLE tenant_a_owner; CREATE TABLE tenant_a.allowed(value text); INSERT INTO tenant_a.allowed VALUES ('owned');");
    assert.deepEqual((await pg.query("SELECT value FROM tenant_a.allowed")).rows, [{ value: "owned" }]);
    await assert.rejects(pg.query("SELECT * FROM tenant_b.secrets"));
    await pg.exec("RESET SESSION AUTHORIZATION; SET SESSION AUTHORIZATION tenant_a_runtime;");
    await assert.rejects(pg.query("SELECT * FROM tenant_a.allowed"));
  } finally { await pg.close(); }
  // PGlite is one database. These are actual role/ACL checks, not proof of
  // Aurora multi-database CONNECT isolation or AWS IAM integration.
});
