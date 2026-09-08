import { DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { RDSDataClient, ExecuteStatementCommand } from "@aws-sdk/client-rds-data";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { canonical, mappingDigest, validateMapping, validateApproval, quoteIdentifier as qi, literal as ql, scramVerifier } from "./contract.mjs";

const names = ["ADMIN_SECRET_ARN", "DATABASE_CLUSTER_ARN", "MAPPING_TABLE_NAME", "APPROVAL_TABLE_NAME", "CONTROL_TABLE_NAME", "AWS_ACCOUNT_ID_EXPECTED", "AWS_REGION_EXPECTED", "APPROVER_ROLE_ARN", "STATE_MACHINE_NAME"];
const env = Object.freeze(Object.fromEntries(names.map((name) => { const value = process.env[name]; if (!value || value !== value.trim()) throw new Error(`Missing ${name}.`); return [name, value]; })));
const clients = { dynamo: new DynamoDBClient({}), rds: new RDSDataClient({}), secrets: new SecretsManagerClient({}) };

// This Lambda has no URL, API integration, schedule, or tenant invocation grant.
// Its only application invoker is the operator-only Standard state machine.
export async function handler(event) {
  try { return await bootstrap(event, clients); }
  catch { throw new Error("Approved database bootstrap failed; inspect the bounded execution and role checks."); }
}

export async function bootstrap(event, clients) {
  if (!event || JSON.stringify(Object.keys(event).sort()) !== JSON.stringify(["executionId", "revision", "tenantId"]) ||
      !/^ten_[a-f0-9]{32}$/.test(event.tenantId) || !Number.isSafeInteger(event.revision) || event.revision < 1 ||
      !new RegExp(`^arn:aws:states:${env.AWS_REGION_EXPECTED}:${env.AWS_ACCOUNT_ID_EXPECTED}:execution:${env.STATE_MACHINE_NAME}:[A-Za-z0-9_-]{1,80}$`).test(event.executionId)) throw new Error("Invalid operator bootstrap request.");
  const record = (await clients.dynamo.send(new GetItemCommand({ TableName: env.MAPPING_TABLE_NAME, ConsistentRead: true,
    Key: { PK: { S: event.tenantId }, SK: { S: `REVISION#${event.revision}` } } }))).Item;
  if (!record?.mappingJson?.S || record.mappingJson.S.length > 12_000) throw new Error("Compiled mapping is missing.");
  const mapping = validateMapping(JSON.parse(record.mappingJson.S));
  if (mapping.tenantId !== event.tenantId || mapping.revision !== event.revision || mapping.clusterArn !== env.DATABASE_CLUSTER_ARN ||
      mapping.account !== env.AWS_ACCOUNT_ID_EXPECTED || mapping.region !== env.AWS_REGION_EXPECTED ||
      mapping.roles.some((role) => role.secretArn === env.ADMIN_SECRET_ARN)) throw new Error("Mapping differs from the platform boundary.");
  const approval = (await clients.dynamo.send(new GetItemCommand({ TableName: env.APPROVAL_TABLE_NAME, ConsistentRead: true,
    Key: { PK: { S: `BOOTSTRAP#${event.tenantId}` }, SK: { S: event.executionId } } }))).Item;
  validateApproval(approval, { mapping, executionId: event.executionId, now: Date.now() });
  if (approval.approvedBy.S !== env.APPROVER_ROLE_ARN) throw new Error("Approval is not from the configured independent approval role.");

  const provisioner = mapping.roles[0];
  const execute = async (database, sql, parameters) => clients.rds.send(new ExecuteStatementCommand({
    database, sql, parameters, resourceArn: mapping.clusterArn, secretArn: env.ADMIN_SECRET_ARN,
  }));
  const adminSecret = JSON.parse((await clients.secrets.send(new GetSecretValueCommand({ SecretId: env.ADMIN_SECRET_ARN }))).SecretString ?? "{}");
  const adminUsername = String(adminSecret.username ?? "");
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(adminUsername) || [mapping.ownerUsername, ...mapping.roles.map((role) => role.username)].includes(adminUsername)) throw new Error("Invalid bootstrap administrator identity.");
  const admin = `"${adminUsername}"`, owner = qi(mapping.ownerUsername), database = qi(mapping.databaseName);
  // Unknown databases are not altered. Dedicated platform infrastructure must
  // be reviewed before a bootstrap can close PUBLIC access to catalog DBs.
  const databases = await execute("scopeproof_admin", "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate");
  if ((databases.records ?? []).some((row) => !/^(postgres|scopeproof_admin|scopeproof_[a-z0-9_]{1,48})$/.test(row[0]?.stringValue ?? ""))) throw new Error("Unexpected shared-cluster database; require operator review.");
  const existing = await execute("scopeproof_admin", `SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = ${ql(mapping.databaseName)}`);
  if (existing.records?.length && existing.records[0]?.[0]?.stringValue !== mapping.ownerUsername) throw new Error("Tenant database owner collision.");
  const managed = [mapping.ownerUsername, ...mapping.roles.map((role) => role.username)];
  const managedList = managed.map(ql).join(",");
  const roleState = await execute("scopeproof_admin", `SELECT rolname, rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls AS privileged, rolcanlogin FROM pg_roles WHERE rolname IN (${managedList})`);
  if ((roleState.records ?? []).some((row) => row[1]?.booleanValue !== false || (row[0]?.stringValue === mapping.ownerUsername && row[2]?.booleanValue !== false))) throw new Error("Managed role collision or privileged legacy role.");
  // Remove only the legacy exact temporary administrator edge. Any other
  // unexpected role membership is a blocker, never silently cleaned up.
  if ((roleState.records ?? []).some((row) => row[0]?.stringValue === mapping.ownerUsername)) await execute("scopeproof_admin", `REVOKE ${owner} FROM ${admin}`);
  const memberships = await execute("scopeproof_admin", `SELECT parent.rolname, member.rolname, edge.admin_option, edge.inherit_option, edge.set_option FROM pg_auth_members edge JOIN pg_roles parent ON parent.oid=edge.roleid JOIN pg_roles member ON member.oid=edge.member WHERE parent.rolname IN (${managedList}) OR member.rolname IN (${managedList})`);
  if ((memberships.records ?? []).some((row) => row[0]?.stringValue !== mapping.ownerUsername || row[1]?.stringValue !== provisioner.username || row[2]?.booleanValue !== false || row[3]?.booleanValue !== false || row[4]?.booleanValue !== true)) throw new Error("Unexpected managed-role membership.");

  const passwords = new Set();
  const credentials = [];
  for (const role of mapping.roles) {
    const response = await clients.secrets.send(new GetSecretValueCommand({ SecretId: role.secretArn }));
    const secret = JSON.parse(response.SecretString ?? "{}");
    if (secret.database !== mapping.databaseName || secret.username !== role.username || !/^[A-Za-z0-9]{32,128}$/.test(secret.password ?? "") || passwords.has(secret.password)) throw new Error("Mapped credential is invalid or reused.");
    passwords.add(secret.password); credentials.push({ ...role, verifier: scramVerifier(secret.password) });
  }
  await execute("scopeproof_admin", `DO $b$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=${ql(mapping.ownerUsername)}) THEN CREATE ROLE ${owner} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $b$`);
  for (const role of credentials) {
    const name = qi(role.username);
    await execute("scopeproof_admin", `DO $b$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=${ql(role.username)}) THEN CREATE ROLE ${name} LOGIN PASSWORD ${ql(role.verifier)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; ELSE ALTER ROLE ${name} LOGIN PASSWORD ${ql(role.verifier)} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $b$`);
    for (const [setting, value] of [["search_path", "pg_catalog, scopeproof"], ["row_security", "on"], ["statement_timeout", role.kind === "provisioning" ? "120s" : "15s"], ["lock_timeout", role.kind === "provisioning" ? "15s" : "3s"], ["idle_in_transaction_session_timeout", role.kind === "provisioning" ? "180s" : "15s"]]) {
      await execute("scopeproof_admin", `ALTER ROLE ${name} SET ${setting} = ${setting === "search_path" ? value : ql(value)}`);
    }
  }
  await execute("scopeproof_admin", `GRANT ${owner} TO ${admin}`);
  try {
    if (!existing.records?.length) await execute("scopeproof_admin", `CREATE DATABASE ${database} OWNER ${owner}`);
    for (const name of [mapping.databaseName, "scopeproof_admin", "postgres", "template1"]) {
      await execute("scopeproof_admin", `REVOKE CONNECT ON DATABASE ${qi(name)} FROM PUBLIC`);
    }
    for (const role of mapping.roles) await execute("scopeproof_admin", `GRANT CONNECT ON DATABASE ${database} TO ${qi(role.username)}`);
    await execute("scopeproof_admin", `GRANT ${owner} TO ${qi(provisioner.username)} WITH ADMIN FALSE, INHERIT FALSE, SET TRUE`);
  } finally {
    await execute("scopeproof_admin", `REVOKE ${owner} FROM ${admin}`);
  }
  // Fail if any managed login can connect to another customer/catalog DB. Do
  // not broaden a per-tenant worker merely to make this check pass.
  const foreign = await execute("scopeproof_admin", `SELECT count(*)::bigint FROM pg_database d CROSS JOIN unnest(ARRAY[${mapping.roles.map((role) => ql(role.username)).join(",")}]::text[]) AS r(name) WHERE d.datallowconn AND d.datname <> ${ql(mapping.databaseName)} AND has_database_privilege(r.name,d.oid,'CONNECT')`);
  if (Number(foreign.records?.[0]?.[0]?.longValue ?? -1) !== 0) throw new Error("Managed tenant login can connect outside its database.");
  const digest = mappingDigest(mapping);
  const item = { PK: { S: `DATABASE_BOOTSTRAP#${mapping.tenantId}` }, SK: { S: `REVISION#${mapping.revision}` },
    kind: { S: "TenantDatabaseRoleSetup" }, schemaVersion: { N: "1" }, tenantId: { S: mapping.tenantId },
    mappingDigest: { S: digest }, mappingJson: { S: canonical(mapping) }, status: { S: "PREPARED" } };
  await clients.dynamo.send(new PutItemCommand({ TableName: env.CONTROL_TABLE_NAME, Item: item,
    ConditionExpression: "attribute_not_exists(PK) OR (mappingDigest = :digest AND mappingJson = :mapping AND #status = :prepared)",
    ExpressionAttributeNames: { "#status": "status" }, ExpressionAttributeValues: { ":digest": { S: digest }, ":mapping": item.mappingJson, ":prepared": { S: "PREPARED" } } }));
  return { tenantId: mapping.tenantId, revision: mapping.revision, mappingDigest: digest, status: "PREPARED" };
}
