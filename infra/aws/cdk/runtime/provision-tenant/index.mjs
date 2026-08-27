import {
  DynamoDBClient,
  TransactWriteItemsCommand,
} from "@aws-sdk/client-dynamodb";
import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  BeginTransactionCommand,
  CommitTransactionCommand,
  ExecuteStatementCommand,
  RDSDataClient,
  RollbackTransactionCommand,
} from "@aws-sdk/client-rds-data";
import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import {
  ChangeResourceRecordSetsCommand,
  GetChangeCommand,
  Route53Client,
} from "@aws-sdk/client-route-53";
import { transactionToken } from "./idempotency.mjs";

const required = [
  "ADMIN_SECRET_ARN",
  "API_HOSTNAME",
  "AUDIT_SIGNING_KEY_ARN",
  "AWS_ACCOUNT_ID_EXPECTED",
  "AWS_REGION_EXPECTED",
  "CANONICAL_HOSTNAME",
  "CONTROL_TABLE_NAME",
  "CONTROL_DATABASE_SECRET_ARN",
  "CONTROL_DATABASE_USERNAME",
  "DATABASE_CLUSTER_ARN",
  "DATABASE_NAME",
  "DATABASE_OWNER",
  "DATABASE_SECRET_ARN",
  "DATABASE_USERNAME",
  "DISPLAY_NAME",
  "DOMAIN_HOSTNAME",
  "EVIDENCE_BUCKET_NAME",
  "EVIDENCE_KEY_ARN",
  "HOSTED_ZONE_ID",
  "INGEST_DATABASE_SECRET_ARN",
  "INGEST_DATABASE_USERNAME",
  "LEGAL_API_DATABASE_SECRET_ARN",
  "LEGAL_API_DATABASE_USERNAME",
  "QUARANTINE_BUCKET_NAME",
  "RETENTION_DAYS",
  "RETENTION_MODE",
  "TENANT_SLUG",
  "TENANT_ID",
  "TENANT_CNAME_TARGET",
];
for (const name of required) {
  if (!process.env[name]) throw new Error(`Missing required environment variable ${name}.`);
}

const config = Object.freeze({
  adminSecretArn: process.env.ADMIN_SECRET_ARN,
  apiHostname: process.env.API_HOSTNAME,
  auditSigningKeyArn: process.env.AUDIT_SIGNING_KEY_ARN,
  awsAccountId: process.env.AWS_ACCOUNT_ID_EXPECTED,
  awsRegion: process.env.AWS_REGION_EXPECTED,
  canonicalHostname: process.env.CANONICAL_HOSTNAME,
  clusterArn: process.env.DATABASE_CLUSTER_ARN,
  controlTable: process.env.CONTROL_TABLE_NAME,
  controlDatabaseSecretArn: process.env.CONTROL_DATABASE_SECRET_ARN,
  controlDatabaseUsername: process.env.CONTROL_DATABASE_USERNAME,
  databaseName: process.env.DATABASE_NAME,
  databaseOwner: process.env.DATABASE_OWNER,
  databaseSecretArn: process.env.DATABASE_SECRET_ARN,
  databaseUsername: process.env.DATABASE_USERNAME,
  displayName: process.env.DISPLAY_NAME,
  evidenceBucket: process.env.EVIDENCE_BUCKET_NAME,
  evidenceKeyArn: process.env.EVIDENCE_KEY_ARN,
  hostname: process.env.DOMAIN_HOSTNAME,
  hostedZoneId: process.env.HOSTED_ZONE_ID,
  ingestDatabaseSecretArn: process.env.INGEST_DATABASE_SECRET_ARN,
  ingestDatabaseUsername: process.env.INGEST_DATABASE_USERNAME,
  legalApiDatabaseSecretArn: process.env.LEGAL_API_DATABASE_SECRET_ARN,
  legalApiDatabaseUsername: process.env.LEGAL_API_DATABASE_USERNAME,
  quarantineBucket: process.env.QUARANTINE_BUCKET_NAME,
  retentionDays: Number(process.env.RETENTION_DAYS),
  retentionMode: process.env.RETENTION_MODE,
  tenantId: process.env.TENANT_ID,
  tenantCnameTarget: process.env.TENANT_CNAME_TARGET,
  tenantSlug: process.env.TENANT_SLUG,
});

if (!/^scopeproof_[a-z0-9_]{1,48}$/.test(config.databaseName)) {
  throw new Error("Unsafe tenant database identifier.");
}
if (!/^tenant_[a-z0-9_]{3,56}_runtime$/.test(config.databaseUsername)) {
  throw new Error("Unsafe tenant database role identifier.");
}
if (!/^tenant_[a-z0-9_]{3,56}_ingest$/.test(config.ingestDatabaseUsername)) {
  throw new Error("Unsafe tenant ingest database role identifier.");
}
if (!/^tenant_[a-z0-9_]{3,56}_control$/.test(config.controlDatabaseUsername)) {
  throw new Error("Unsafe tenant evidence-control database role identifier.");
}
if (!/^tenant_[a-z0-9_]{3,56}_legal_api$/.test(config.legalApiDatabaseUsername)) {
  throw new Error("Unsafe tenant legal-hold API database role identifier.");
}
if (!/^scopeproof_[a-z0-9_]{1,46}_owner$/.test(config.databaseOwner)) {
  throw new Error("Unsafe tenant database owner identifier.");
}
if (!/^ten_[a-f0-9]{32}$/.test(config.tenantId)) {
  throw new Error("Unsafe tenant identifier.");
}
if (!/^[a-z0-9-]{1,48}(?:\.[a-z0-9-]{1,63})+$/.test(config.hostname)) {
  throw new Error("Unsafe tenant hostname.");
}
if (
  !/^[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$/.test(config.apiHostname) ||
  config.apiHostname === config.hostname
) {
  throw new Error("Unsafe tenant API hostname.");
}
if (
  !/^Z[A-Z0-9]{8,31}$/.test(config.hostedZoneId) ||
  !/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(
    config.tenantCnameTarget,
  ) ||
  config.tenantCnameTarget === config.hostname
) {
  throw new Error("Unsafe tenant DNS activation metadata.");
}
if (
  config.hostname !== config.canonicalHostname ||
  !/^\d{12}$/.test(config.awsAccountId) ||
  !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(config.awsRegion) ||
  !/^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(config.tenantSlug) ||
  config.displayName.length < 2 ||
  config.displayName.length > 120 ||
  containsControlCharacters(config.displayName) ||
  !Number.isInteger(config.retentionDays) ||
  config.retentionDays < 1 ||
  config.retentionDays > 3650 ||
  !new Set(["GOVERNANCE", "COMPLIANCE"]).has(config.retentionMode)
) {
  throw new Error("Unsafe tenant provisioning metadata.");
}
const bucketPattern = /^(?=.{3,63}$)[a-z0-9][a-z0-9.-]*[a-z0-9]$/;
const escapedRegion = config.awsRegion.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const escapedAccount = config.awsAccountId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
if (
  !bucketPattern.test(config.quarantineBucket) ||
  !bucketPattern.test(config.evidenceBucket) ||
  config.quarantineBucket === config.evidenceBucket ||
  !new RegExp(
    `^arn:(aws|aws-us-gov|aws-cn):kms:${escapedRegion}:${escapedAccount}:key/[0-9a-f-]{36}$`,
  ).test(config.evidenceKeyArn) ||
  !new RegExp(
    `^arn:(aws|aws-us-gov|aws-cn):kms:${escapedRegion}:${escapedAccount}:key/[0-9a-f-]{36}$`,
  ).test(config.auditSigningKeyArn) ||
  config.auditSigningKeyArn === config.evidenceKeyArn
) {
  throw new Error("Unsafe tenant storage metadata.");
}

const tenantSchemaSql = readFileSync("/var/task/database/001_tenant_schema.sql", "utf8");
const runtimeRoleSql = readFileSync("/var/task/database/002_runtime_role.sql", "utf8");
const ingestRoleSql = readFileSync("/var/task/database/003_ingest_role.sql", "utf8");
const controlRoleSql = readFileSync("/var/task/database/004_evidence_control_role.sql", "utf8");
const legalApiRoleSql = readFileSync("/var/task/database/005_legal_hold_api_role.sql", "utf8");
const tenantSchemaSha256 = createHash("sha256").update(tenantSchemaSql).digest("hex");
const tenantSchemaMarker = `scopeproof:001:sha256:${tenantSchemaSha256}`;
const isolatedTables = Object.freeze([
  "assessments",
  "audit_events",
  "audit_heads",
  "device_enrollments",
  "evidence_artifacts",
  "export_receipts",
  "ingest_receipts",
  "integrations",
  "jobs",
  "memberships",
  "principals",
  "retention_holds",
  "legal_hold_operations",
  "support_access_grants",
  "tenant_domains",
  "upload_intents",
]);
const baselineTables = Object.freeze([
  ...isolatedTables,
  "schema_migrations",
  "tenant_identity",
].sort());
const baselineFunctions = Object.freeze([
  "advance_audit_head",
  "acknowledge_legal_hold_recovery_publication",
  "append_signed_audit_event",
  "approve_exact_version_legal_hold",
  "assert_actor_permission",
  "assert_database_tenant",
  "claim_promotion_fence",
  "confirm_exact_version_legal_hold",
  "begin_exact_version_legal_hold_application",
  "create_upload_intent",
  "current_tenant_id",
  "expire_stale_exact_version_legal_hold_requests",
  "list_pending_exact_version_legal_holds",
  "list_unaudited_applied_legal_holds",
  "list_unaudited_expired_legal_holds",
  "protect_immutable_security_fields",
  "record_exact_version_legal_hold_reconciliation_failure",
  "read_tenant_audit_head",
  "read_exact_version_legal_hold_operation",
  "read_promoted_evidence_receipt",
  "resolve_active_membership",
  "reconcile_promoted_evidence",
  "reserve_exact_version_legal_hold",
]);
const controlRoleAllowedFunctions = Object.freeze([
  "acknowledge_legal_hold_recovery_publication",
  "current_tenant_id",
  "append_signed_audit_event",
  "read_exact_version_legal_hold_operation",
  "begin_exact_version_legal_hold_application",
  "confirm_exact_version_legal_hold",
  "expire_stale_exact_version_legal_hold_requests",
  "list_pending_exact_version_legal_holds",
  "list_unaudited_applied_legal_holds",
  "list_unaudited_expired_legal_holds",
  "record_exact_version_legal_hold_reconciliation_failure",
  "read_tenant_audit_head",
]);
if (!runtimeRoleSql.includes("__SCOPEPROOF_RUNTIME_ROLE__")) {
  throw new Error("Runtime grant migration token is missing.");
}
if (!ingestRoleSql.includes("__SCOPEPROOF_INGEST_ROLE__")) {
  throw new Error("Ingest grant migration token is missing.");
}
if (!controlRoleSql.includes("__SCOPEPROOF_CONTROL_ROLE__")) {
  throw new Error("Evidence-control grant migration token is missing.");
}
if (!legalApiRoleSql.includes("__SCOPEPROOF_LEGAL_API_ROLE__")) {
  throw new Error("Legal-hold API grant migration token is missing.");
}

const dynamo = new DynamoDBClient({});
const rds = new RDSDataClient({});
const secrets = new SecretsManagerClient({});
const route53 = new Route53Client({});

export async function handler(event) {
  const action = String(event?.action ?? "");
  const executionId = validateExecutionId(event?.executionId);
  try {
    switch (action) {
      case "acquire":
        await setProvisioning(executionId);
        return { action, status: "PROVISIONING", tenantId: config.tenantId };
      case "initialize":
        await initializeDatabase();
        return { action, status: "INITIALIZED", tenantId: config.tenantId };
      case "verify":
        await verifyDatabase();
        return { action, status: "VERIFIED", tenantId: config.tenantId };
      case "activate":
        await activateTenant(executionId);
        return { action, status: "ACTIVE", tenantId: config.tenantId };
      case "fail":
        await restoreDatabaseProvisioningStatus();
        await setTerminalStatus(executionId, "FAILED", sanitizeErrorName(event?.errorName));
        return { action, status: "FAILED", tenantId: config.tenantId };
      default:
        throw namedError("InvalidAction", "Unsupported provisioning action.");
    }
  } catch (error) {
    if (error?.name === "LeaseRejected" || error?.name === "InvalidAction") throw error;
    const safe = new Error(`Tenant provisioning action ${action || "unknown"} failed.`);
    safe.name = "TenantProvisioningError";
    throw safe;
  }
}

async function activateTenant(executionId) {
  // Activation is deliberately self-verifying: a caller cannot skip the
  // preceding Step Functions verification task and publish a tenant hostname.
  await verifyDatabase(["PROVISIONING", "ACTIVE"]);
  await publishTenantDns();
  await setDatabaseTenantStatus("ACTIVE", ["PROVISIONING", "ACTIVE"]);
  try {
    await setTerminalStatus(executionId, "ACTIVE");
  } catch (error) {
    await restoreDatabaseProvisioningStatus();
    throw error;
  }
}

async function publishTenantDns() {
  const response = await route53.send(
    new ChangeResourceRecordSetsCommand({
      ChangeBatch: {
        Changes: [
          {
            Action: "UPSERT",
            ResourceRecordSet: {
              Name: config.hostname,
              ResourceRecords: [{ Value: config.tenantCnameTarget }],
              TTL: 300,
              Type: "CNAME",
            },
          },
        ],
        Comment: `Scopeproof verified tenant ${config.tenantId}`,
      },
      HostedZoneId: config.hostedZoneId,
    }),
  );
  const changeId = response.ChangeInfo?.Id;
  if (!changeId || !/^\/change\/C[A-Z0-9]{8,32}$/.test(changeId)) {
    throw new Error("Route 53 did not return a valid tenant DNS change identifier.");
  }
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    const change = await route53.send(new GetChangeCommand({ Id: changeId }));
    if (change.ChangeInfo?.Status === "INSYNC") return;
    await new Promise((resolve) => setTimeout(resolve, 5_000));
  }
  throw new Error("Tenant DNS change was not INSYNC before the activation deadline.");
}

async function restoreDatabaseProvisioningStatus() {
  try {
    await setDatabaseTenantStatus("PROVISIONING", ["PROVISIONING", "ACTIVE"]);
  } catch {
    // The Step Functions terminal failure remains authoritative. Operators can
    // safely re-run verification after correcting a database connectivity issue.
  }
}

async function setDatabaseTenantStatus(status, allowedStatuses) {
  const allowed = allowedStatuses.map(quoteLiteral).join(", ");
  const responses = await runTransaction(config.adminSecretArn, [
    {
      sql: "SELECT set_config('scopeproof.tenant_id', :tenant_id, true)",
      parameters: [stringParameter("tenant_id", config.tenantId)],
    },
    {
      sql: `UPDATE scopeproof.tenant_identity SET status = :status, updated_at = clock_timestamp() WHERE tenant_id = :tenant_id AND status IN (${allowed})`,
      parameters: [
        stringParameter("status", status),
        stringParameter("tenant_id", config.tenantId),
      ],
    },
  ]);
  const response = responses[1];
  if (response.numberOfRecordsUpdated !== 1) {
    throw new Error("Tenant database activation status did not match the expected state.");
  }
}

function validateExecutionId(value) {
  const executionId = String(value ?? "");
  if (
    executionId.length < 20 ||
    executionId.length > 512 ||
    !/^arn:[a-z0-9-]+:states:[a-z0-9-]+:\d{12}:execution:[A-Za-z0-9-_]+:[A-Za-z0-9-_]+$/.test(
      executionId,
    )
  ) {
    throw namedError("InvalidAction", "Invalid Step Functions execution identifier.");
  }
  return executionId;
}

async function setProvisioning(executionId) {
  const now = new Date().toISOString();
  const clientRequestToken = transactionToken({
    action: "acquire",
    apiHostname: config.apiHostname,
    executionId,
    hostname: config.hostname,
    now,
    tenantId: config.tenantId,
  });
  try {
    await dynamo.send(
      new TransactWriteItemsCommand({
        ClientRequestToken: clientRequestToken,
        TransactItems: registryKeys().map((key, index) => ({
          Update: {
            ConditionExpression:
              "(#status IN (:provisioning, :failed)) AND (attribute_not_exists(#executionId) OR #executionId = :executionId)" +
              (index > 0 ? " AND #tenantId = :tenantId" : ""),
            ExpressionAttributeNames: {
              "#executionId": "provisionExecutionId",
              "#lastExecutionId": "lastProvisionExecutionId",
              "#lastError": "lastProvisionError",
              "#status": "status",
              ...(index > 0 ? { "#tenantId": "tenantId" } : {}),
            },
            ExpressionAttributeValues: {
              ":executionId": { S: executionId },
              ":failed": { S: "FAILED" },
              ":now": { S: now },
              ":provisioning": { S: "PROVISIONING" },
              ...(index > 0 ? { ":tenantId": { S: config.tenantId } } : {}),
            },
            Key: key,
            TableName: config.controlTable,
            UpdateExpression:
              "SET #status = :provisioning, #executionId = :executionId, provisionStartedAt = :now REMOVE #lastError, #lastExecutionId",
          },
        })),
      }),
    );
  } catch (error) {
    if (error?.name === "TransactionCanceledException" || error?.name === "ConditionalCheckFailedException") {
      throw namedError("LeaseRejected", "Tenant provisioning lease was rejected.");
    }
    throw error;
  }
}

async function setTerminalStatus(executionId, status, errorName) {
  const now = new Date().toISOString();
  const clientRequestToken = transactionToken({
    action: "terminal",
    apiHostname: config.apiHostname,
    errorName: errorName ?? null,
    executionId,
    hostname: config.hostname,
    now,
    schemaSha256: status === "ACTIVE" ? tenantSchemaSha256 : null,
    status,
    tenantId: config.tenantId,
  });
  await dynamo.send(
    new TransactWriteItemsCommand({
      ClientRequestToken: clientRequestToken,
      TransactItems: registryKeys().map((key, index) => ({
        Update: {
          ConditionExpression:
            "((#status = :provisioning AND #executionId = :executionId) OR " +
            "(#status = :status AND #lastExecutionId = :executionId))" +
            (index > 0 ? " AND #tenantId = :tenantId" : ""),
          ExpressionAttributeNames: {
              "#executionId": "provisionExecutionId",
              "#lastExecutionId": "lastProvisionExecutionId",
            "#lastError": "lastProvisionError",
            "#status": "status",
            ...(index > 0 ? { "#tenantId": "tenantId" } : {}),
          },
          ExpressionAttributeValues: {
            ":executionId": { S: executionId },
            ":now": { S: now },
            ":provisioning": { S: "PROVISIONING" },
            ":status": { S: status },
            ...(errorName ? { ":lastError": { S: errorName } } : {}),
            ...(status === "ACTIVE"
              ? {
                  ":schemaSha256": { S: tenantSchemaSha256 },
                  ":schemaVersion": { N: "1" },
                }
              : {}),
            ...(index > 0 ? { ":tenantId": { S: config.tenantId } } : {}),
          },
          Key: key,
          TableName: config.controlTable,
          UpdateExpression:
            status === "FAILED"
              ? "SET #status = :status, #lastExecutionId = :executionId, #lastError = :lastError, provisionCompletedAt = :now REMOVE #executionId"
              : "SET #status = :status, #lastExecutionId = :executionId, databaseSchemaVersion = :schemaVersion, databaseMigrationSha256 = :schemaSha256, provisionCompletedAt = :now REMOVE #executionId, #lastError",
        },
      })),
    }),
  );
}

async function initializeDatabase() {
  const [runtimeResponse, ingestResponse, controlResponse, legalApiResponse, adminResponse] = await Promise.all([
    secrets.send(new GetSecretValueCommand({ SecretId: config.databaseSecretArn })),
    secrets.send(new GetSecretValueCommand({ SecretId: config.ingestDatabaseSecretArn })),
    secrets.send(new GetSecretValueCommand({ SecretId: config.controlDatabaseSecretArn })),
    secrets.send(new GetSecretValueCommand({ SecretId: config.legalApiDatabaseSecretArn })),
    secrets.send(new GetSecretValueCommand({ SecretId: config.adminSecretArn })),
  ]);
  const secret = JSON.parse(runtimeResponse.SecretString ?? "{}");
  const ingestSecret = JSON.parse(ingestResponse.SecretString ?? "{}");
  const controlSecret = JSON.parse(controlResponse.SecretString ?? "{}");
  const legalApiSecret = JSON.parse(legalApiResponse.SecretString ?? "{}");
  const adminSecret = JSON.parse(adminResponse.SecretString ?? "{}");
  const adminUsername = String(adminSecret.username ?? "");
  const password = String(secret.password ?? "");
  const ingestPassword = String(ingestSecret.password ?? "");
  const controlPassword = String(controlSecret.password ?? "");
  const legalApiPassword = String(legalApiSecret.password ?? "");
  if (
    secret.username !== config.databaseUsername ||
    ingestSecret.username !== config.ingestDatabaseUsername ||
    controlSecret.username !== config.controlDatabaseUsername ||
    legalApiSecret.username !== config.legalApiDatabaseUsername ||
    !/^[A-Za-z0-9]{32,128}$/.test(password) ||
    !/^[A-Za-z0-9]{32,128}$/.test(ingestPassword) ||
    !/^[A-Za-z0-9]{32,128}$/.test(controlPassword) ||
    !/^[A-Za-z0-9]{32,128}$/.test(legalApiPassword) ||
    !/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(adminUsername) ||
    new Set([
      config.databaseUsername,
      config.ingestDatabaseUsername,
      config.controlDatabaseUsername,
      config.legalApiDatabaseUsername,
      config.databaseOwner,
    ]).has(adminUsername) ||
    new Set([
      config.databaseUsername,
      config.ingestDatabaseUsername,
      config.controlDatabaseUsername,
      config.legalApiDatabaseUsername,
    ]).size !== 4
  ) {
    throw new Error("Database credentials did not meet the provisioning contract.");
  }

  const runtimeRole = quoteIdentifier(config.databaseUsername);
  const ingestRole = quoteIdentifier(config.ingestDatabaseUsername);
  const controlRole = quoteIdentifier(config.controlDatabaseUsername);
  const legalApiRole = quoteIdentifier(config.legalApiDatabaseUsername);
  const ownerRole = quoteIdentifier(config.databaseOwner);
  const adminRole = quoteIdentifier(adminUsername);
  const database = quoteIdentifier(config.databaseName);
  // Failed PostgreSQL utility statements can be copied to server logs. Supply
  // PostgreSQL's native SCRAM verifier so the reusable plaintext secret never
  // appears in CREATE/ALTER ROLE SQL or CloudWatch database logs.
  const passwordVerifier = quoteLiteral(scramSha256Verifier(password));
  const ingestPasswordVerifier = quoteLiteral(scramSha256Verifier(ingestPassword));
  const controlPasswordVerifier = quoteLiteral(scramSha256Verifier(controlPassword));
  const legalApiPasswordVerifier = quoteLiteral(scramSha256Verifier(legalApiPassword));
  await executeAdmin(
    "scopeproof_admin",
    `DO $scopeproof$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${quoteLiteral(config.databaseOwner)}) THEN CREATE ROLE ${ownerRole} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; ELSE ALTER ROLE ${ownerRole} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $scopeproof$;`,
  );
  await executeAdmin(
    "scopeproof_admin",
    `DO $scopeproof$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${quoteLiteral(config.databaseUsername)}) THEN CREATE ROLE ${runtimeRole} LOGIN PASSWORD ${passwordVerifier} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; ELSE ALTER ROLE ${runtimeRole} LOGIN PASSWORD ${passwordVerifier} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $scopeproof$;`,
  );
  await executeAdmin(
    "scopeproof_admin",
    `DO $scopeproof$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${quoteLiteral(config.ingestDatabaseUsername)}) THEN CREATE ROLE ${ingestRole} LOGIN PASSWORD ${ingestPasswordVerifier} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; ELSE ALTER ROLE ${ingestRole} LOGIN PASSWORD ${ingestPasswordVerifier} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $scopeproof$;`,
  );
  await executeAdmin(
    "scopeproof_admin",
    `DO $scopeproof$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${quoteLiteral(config.controlDatabaseUsername)}) THEN CREATE ROLE ${controlRole} LOGIN PASSWORD ${controlPasswordVerifier} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; ELSE ALTER ROLE ${controlRole} LOGIN PASSWORD ${controlPasswordVerifier} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $scopeproof$;`,
  );
  await executeAdmin(
    "scopeproof_admin",
    `DO $scopeproof$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${quoteLiteral(config.legalApiDatabaseUsername)}) THEN CREATE ROLE ${legalApiRole} LOGIN PASSWORD ${legalApiPasswordVerifier} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; ELSE ALTER ROLE ${legalApiRole} LOGIN PASSWORD ${legalApiPasswordVerifier} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; END IF; END $scopeproof$;`,
  );

  // The cluster administrator receives temporary SET ROLE membership only for
  // the migration transaction. Objects are therefore owned by the dedicated
  // NOLOGIN owner, and the membership is revoked on every exit path.
  await executeAdmin("scopeproof_admin", `GRANT ${ownerRole} TO ${adminRole}`);
  try {
    const databaseExists = await executeAdmin(
      "scopeproof_admin",
      `SELECT 1 FROM pg_database WHERE datname = ${quoteLiteral(config.databaseName)}`,
    );
    if (!databaseExists.records?.length) {
      try {
        await executeAdmin("scopeproof_admin", `CREATE DATABASE ${database} OWNER ${ownerRole}`);
      } catch {
        const concurrentCreate = await executeAdmin(
          "scopeproof_admin",
          `SELECT 1 FROM pg_database WHERE datname = ${quoteLiteral(config.databaseName)}`,
        );
        if (!concurrentCreate.records?.length) throw new Error("Tenant database creation failed.");
      }
    }
    await executeAdmin("scopeproof_admin", `ALTER DATABASE ${database} OWNER TO ${ownerRole}`);
    await executeAdmin("scopeproof_admin", "REVOKE CONNECT ON DATABASE scopeproof_admin FROM PUBLIC");
    await executeAdmin("scopeproof_admin", `REVOKE CONNECT ON DATABASE ${database} FROM PUBLIC`);
    await executeAdmin("scopeproof_admin", `GRANT CONNECT ON DATABASE ${database} TO ${runtimeRole}`);
    await executeAdmin("scopeproof_admin", `GRANT CONNECT ON DATABASE ${database} TO ${ingestRole}`);
    await executeAdmin("scopeproof_admin", `GRANT CONNECT ON DATABASE ${database} TO ${controlRole}`);
    await executeAdmin("scopeproof_admin", `GRANT CONNECT ON DATABASE ${database} TO ${legalApiRole}`);

    const migrationState = await executeAdmin(
      config.databaseName,
      "SELECT to_regclass('scopeproof.schema_migrations')::text, to_regnamespace('scopeproof')::text",
    );
    const migrationsTable = fieldString(migrationState.records?.[0]?.[0]);
    const scopeproofSchema = fieldString(migrationState.records?.[0]?.[1]);
    if (!migrationsTable) {
      if (scopeproofSchema) {
        throw new Error("A partial unversioned scopeproof schema exists; automatic recovery is unsafe.");
      }
      await applyMigration(
        tenantSchemaSql,
        config.adminSecretArn,
        config.databaseOwner,
        tenantSchemaMarker,
      );
    } else {
      // 001 is an immutable pre-deployment baseline, not an in-place upgrade
      // script. Refuse to seed or re-grant an older/modified schema. Once a
      // tenant has been deployed, every DDL change must ship as a separately
      // versioned forward migration with its own reviewed compatibility path.
      const baseline = await executeAdmin(
        config.databaseName,
        "SELECT count(*)::bigint, min(version), max(version), min(name), max(name), obj_description('scopeproof.schema_migrations'::regclass, 'pg_class') FROM scopeproof.schema_migrations",
      );
      const row = baseline.records?.[0] ?? [];
      if (
        fieldNumber(row[0]) !== 1 ||
        fieldNumber(row[1]) !== 1 ||
        fieldNumber(row[2]) !== 1 ||
        fieldString(row[3]) !== "tenant_security_baseline" ||
        fieldString(row[4]) !== "tenant_security_baseline" ||
        fieldString(row[5]) !== tenantSchemaMarker
      ) {
        throw new Error("Tenant schema is not the exact packaged baseline; a reviewed forward migration is required.");
      }
    }

    await runTransaction(config.adminSecretArn, [
      {
        sql: "SELECT set_config('scopeproof.tenant_id', :tenant_id, true)",
        parameters: [stringParameter("tenant_id", config.tenantId)],
      },
      {
        sql: [
          "INSERT INTO scopeproof.tenant_identity",
          "(tenant_id, slug, display_name, status, canonical_hostname, retention_days, retention_mode, aws_account_id, aws_region, quarantine_bucket, evidence_bucket, evidence_kms_key_arn, audit_signing_key_arn)",
          "VALUES (:tenant_id, :slug, :display_name, 'PROVISIONING', :hostname, :retention_days, :retention_mode, :account_id, :region, :quarantine_bucket, :evidence_bucket, :key_arn, :signing_key_arn)",
          "ON CONFLICT (tenant_id) DO NOTHING",
        ].join(" "),
        parameters: tenantIdentityParameters(),
      },
      {
        sql: [
          "INSERT INTO scopeproof.tenant_domains (tenant_id, hostname, status, is_canonical, verified_at)",
          "VALUES (:tenant_id, :hostname, 'VERIFIED', true, clock_timestamp())",
          "ON CONFLICT (tenant_id, hostname) DO NOTHING",
        ].join(" "),
        parameters: [
          stringParameter("tenant_id", config.tenantId),
          stringParameter("hostname", config.canonicalHostname),
        ],
      },
    ]);

    const renderedRuntimeGrant = runtimeRoleSql.replaceAll(
      "__SCOPEPROOF_RUNTIME_ROLE__",
      config.databaseUsername,
    );
    if (renderedRuntimeGrant.includes("__SCOPEPROOF_RUNTIME_ROLE__")) {
      throw new Error("Runtime role migration rendering failed.");
    }
    await applyMigration(renderedRuntimeGrant, config.adminSecretArn);
    const renderedIngestGrant = ingestRoleSql.replaceAll(
      "__SCOPEPROOF_INGEST_ROLE__",
      config.ingestDatabaseUsername,
    );
    if (renderedIngestGrant.includes("__SCOPEPROOF_INGEST_ROLE__")) {
      throw new Error("Ingest role migration rendering failed.");
    }
    await applyMigration(renderedIngestGrant, config.adminSecretArn);
    const renderedControlGrant = controlRoleSql.replaceAll(
      "__SCOPEPROOF_CONTROL_ROLE__",
      config.controlDatabaseUsername,
    );
    if (renderedControlGrant.includes("__SCOPEPROOF_CONTROL_ROLE__")) {
      throw new Error("Evidence-control role migration rendering failed.");
    }
    await applyMigration(renderedControlGrant, config.adminSecretArn);
    const renderedLegalApiGrant = legalApiRoleSql.replaceAll(
      "__SCOPEPROOF_LEGAL_API_ROLE__",
      config.legalApiDatabaseUsername,
    );
    if (renderedLegalApiGrant.includes("__SCOPEPROOF_LEGAL_API_ROLE__")) {
      throw new Error("Legal-hold API role migration rendering failed.");
    }
    await applyMigration(renderedLegalApiGrant, config.adminSecretArn);
    // Keep only the narrow control-plane access needed to verify and change the
    // activation status after owner membership is revoked.
    await executeAdmin("scopeproof_admin", `GRANT CONNECT ON DATABASE ${database} TO ${adminRole}`);
    await executeAdmin(config.databaseName, `GRANT USAGE ON SCHEMA scopeproof TO ${adminRole}`);
    await executeAdmin(
      config.databaseName,
      `GRANT SELECT ON scopeproof.tenant_identity TO ${adminRole}`,
    );
    await executeAdmin(
      config.databaseName,
      `GRANT UPDATE (status, updated_at) ON scopeproof.tenant_identity TO ${adminRole}`,
    );
    await executeAdmin(
      config.databaseName,
      `GRANT EXECUTE ON FUNCTION scopeproof.current_tenant_id() TO ${adminRole}`,
    );
  } finally {
    await executeAdmin("scopeproof_admin", `REVOKE ${ownerRole} FROM ${adminRole}`);
  }
  // A reviewed tenant-stack update returns registry state to PROVISIONING.
  // Mirror that fail-closed state in the database before verification so an
  // unchanged security boundary can be reactivated and changed metadata fails
  // the exact identity comparison instead of remaining live.
  await setDatabaseTenantStatus("PROVISIONING", ["PROVISIONING", "ACTIVE"]);
}

async function verifyDatabase(allowedIdentityStatuses = ["PROVISIONING"]) {
  const adminResponse = await secrets.send(
    new GetSecretValueCommand({ SecretId: config.adminSecretArn }),
  );
  const adminUsername = String(JSON.parse(adminResponse.SecretString ?? "{}").username ?? "");
  if (!/^[A-Za-z_][A-Za-z0-9_]{0,62}$/.test(adminUsername)) {
    throw new Error("The database administrator identity is invalid.");
  }
  const isolatedTableList = isolatedTables.map(quoteLiteral).join(", ");
  const baselineTableList = baselineTables.map(quoteLiteral).join(", ");
  const baselineFunctionList = baselineFunctions.map(quoteLiteral).join(", ");
  const results = await runTransaction(config.databaseSecretArn, [
    {
      sql: "SELECT set_config('scopeproof.tenant_id', :tenant_id, true)",
      parameters: [stringParameter("tenant_id", config.tenantId)],
    },
    {
      sql: "SELECT current_user, current_database(), has_schema_privilege(current_user, 'scopeproof', 'USAGE'), has_schema_privilege(current_user, 'scopeproof', 'CREATE')",
    },
    {
      sql: "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user",
    },
    {
      sql: "SELECT count(*)::bigint, min(version), max(version), min(name), max(name), obj_description('scopeproof.schema_migrations'::regclass, 'pg_class') FROM scopeproof.schema_migrations",
    },
    {
      sql: [
        "SELECT count(*)::bigint,",
        `count(*) FILTER (WHERE c.relname IN (${baselineTableList}))::bigint,`,
        `count(*) FILTER (WHERE c.relname IN (${baselineTableList}) AND pg_get_userbyid(c.relowner) = ${quoteLiteral(config.databaseOwner)})::bigint`,
        "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace",
        "WHERE n.nspname = 'scopeproof' AND c.relkind = 'r'",
      ].join(" "),
    },
    {
      sql: [
        "SELECT count(c.oid)::bigint,",
        "count(c.oid) FILTER (WHERE c.relrowsecurity AND c.relforcerowsecurity)::bigint,",
        "count(c.oid) FILTER (WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid AND p.polname = 'tenant_isolation' AND pg_get_expr(p.polqual, p.polrelid) LIKE '%current_tenant_id()%' AND pg_get_expr(p.polwithcheck, p.polrelid) LIKE '%current_tenant_id()%'))::bigint,",
        "count(c.oid) FILTER (WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_constraint k WHERE k.conrelid = c.oid AND k.contype = 'f' AND k.confrelid = 'scopeproof.tenant_identity'::regclass AND k.conname = left(c.relname || '_tenant_identity_fk', 63)))::bigint,",
        "count(c.oid) FILTER (WHERE EXISTS (SELECT 1 FROM pg_catalog.pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal AND t.tgname = 'enforce_database_tenant' AND t.tgfoid = 'scopeproof.assert_database_tenant()'::regprocedure))::bigint,",
        "(SELECT count(*)::bigint FROM pg_catalog.pg_policy all_policies JOIN pg_catalog.pg_class all_classes ON all_classes.oid = all_policies.polrelid JOIN pg_catalog.pg_namespace all_namespaces ON all_namespaces.oid = all_classes.relnamespace WHERE all_namespaces.nspname = 'scopeproof')",
        `FROM unnest(ARRAY[${isolatedTableList}]::text[]) AS expected(name)`,
        "LEFT JOIN pg_catalog.pg_namespace n ON n.nspname = 'scopeproof'",
        "LEFT JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname = expected.name AND c.relkind = 'r'",
      ].join(" "),
    },
    {
      sql: [
        "SELECT count(*) FILTER (WHERE (",
        "(t.tgname = 'protect_immutable_fields' AND c.relname IN ('jobs', 'upload_intents', 'evidence_artifacts', 'retention_holds', 'legal_hold_operations', 'support_access_grants') AND p.proname = 'protect_immutable_security_fields')",
        "OR (t.tgname = 'append_audit_chain' AND c.relname = 'audit_events' AND p.proname = 'advance_audit_head')))::bigint, count(*)::bigint",
        "FROM pg_catalog.pg_trigger t",
        "JOIN pg_catalog.pg_class c ON c.oid = t.tgrelid",
        "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace",
        "JOIN pg_catalog.pg_proc p ON p.oid = t.tgfoid",
        "WHERE n.nspname = 'scopeproof' AND NOT t.tgisinternal",
      ].join(" "),
    },
    {
      sql: [
        "SELECT count(*)::bigint,",
        `count(*) FILTER (WHERE p.proname IN (${baselineFunctionList}))::bigint,`,
        `count(*) FILTER (WHERE p.proname IN (${baselineFunctionList}) AND pg_get_userbyid(p.proowner) = ${quoteLiteral(config.databaseOwner)})::bigint`,
        "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace",
        "WHERE n.nspname = 'scopeproof'",
      ].join(" "),
    },
    {
      sql: [
        "SELECT count(*)::bigint,",
        `count(*) FILTER (WHERE t.typname IN ('tenant_identifier', 'resource_identifier') AND pg_get_userbyid(t.typowner) = ${quoteLiteral(config.databaseOwner)})::bigint`,
        "FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace",
        "WHERE n.nspname = 'scopeproof' AND t.typtype = 'd'",
      ].join(" "),
    },
    {
      sql: "SELECT pg_get_userbyid(d.datdba), pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_database d CROSS JOIN pg_catalog.pg_namespace n WHERE d.datname = current_database() AND n.nspname = 'scopeproof'",
    },
    {
      sql: [
        "SELECT (SELECT count(*)::bigint FROM scopeproof.tenant_identity), tenant_id, slug, display_name, status, canonical_hostname, retention_days, retention_mode, aws_account_id, aws_region, quarantine_bucket, evidence_bucket, evidence_kms_key_arn, audit_signing_key_arn",
        "FROM scopeproof.tenant_identity WHERE singleton",
      ].join(" "),
    },
    {
      sql: [
        "SELECT (SELECT count(*)::bigint FROM scopeproof.tenant_domains), tenant_id, hostname, status, is_canonical, (verified_at IS NOT NULL)",
        "FROM scopeproof.tenant_domains WHERE tenant_id = :tenant_id AND hostname = :hostname",
      ].join(" "),
      parameters: [
        stringParameter("tenant_id", config.tenantId),
        stringParameter("hostname", config.canonicalHostname),
      ],
    },
  ]);

  const session = results[1].records?.[0] ?? [];
  const role = results[2].records?.[0] ?? [];
  const migration = results[3].records?.[0] ?? [];
  const tableOwners = results[4].records?.[0] ?? [];
  const rls = results[5].records?.[0] ?? [];
  const securityTriggers = results[6].records?.[0] ?? [];
  const functionOwners = results[7].records?.[0] ?? [];
  const domainOwners = results[8].records?.[0] ?? [];
  const owners = results[9].records?.[0] ?? [];
  const identity = results[10].records?.[0] ?? [];
  const domain = results[11].records?.[0] ?? [];
  const actualIdentity = identity.slice(1).map((field) => fieldString(field) ?? fieldNumber(field));
  const identityMatches = allowedIdentityStatuses.some((status) =>
    JSON.stringify(actualIdentity) === JSON.stringify([
      config.tenantId,
      config.tenantSlug,
      config.displayName,
      status,
      config.canonicalHostname,
      config.retentionDays,
      config.retentionMode,
      config.awsAccountId,
      config.awsRegion,
      config.quarantineBucket,
      config.evidenceBucket,
      config.evidenceKeyArn,
      config.auditSigningKeyArn,
    ]),
  );
  if (
    fieldString(session[0]) !== config.databaseUsername ||
    fieldString(session[1]) !== config.databaseName ||
    session[2]?.booleanValue !== true ||
    session[3]?.booleanValue !== false ||
    role.length !== 6 ||
    role[0]?.booleanValue !== true ||
    role.slice(1).some((field) => field?.booleanValue !== false) ||
    fieldNumber(migration[0]) !== 1 ||
    fieldNumber(migration[1]) !== 1 ||
    fieldNumber(migration[2]) !== 1 ||
    fieldString(migration[3]) !== "tenant_security_baseline" ||
    fieldString(migration[4]) !== "tenant_security_baseline" ||
    fieldString(migration[5]) !== tenantSchemaMarker ||
    tableOwners.length !== 3 ||
    tableOwners.some((field) => fieldNumber(field) !== baselineTables.length) ||
    rls.length !== 6 ||
    rls.some((field) => fieldNumber(field) !== isolatedTables.length) ||
    fieldNumber(securityTriggers[0]) !== 7 ||
    fieldNumber(securityTriggers[1]) !== 23 ||
    functionOwners.length !== 3 ||
    functionOwners.some((field) => fieldNumber(field) !== baselineFunctions.length) ||
    fieldNumber(domainOwners[0]) !== 2 ||
    fieldNumber(domainOwners[1]) !== 2 ||
    fieldString(owners[0]) !== config.databaseOwner ||
    fieldString(owners[1]) !== config.databaseOwner ||
    fieldNumber(identity[0]) !== 1 ||
    !identityMatches ||
    fieldNumber(domain[0]) !== 1 ||
    fieldString(domain[1]) !== config.tenantId ||
    fieldString(domain[2]) !== config.canonicalHostname ||
    fieldString(domain[3]) !== "VERIFIED" ||
    domain[4]?.booleanValue !== true ||
    domain[5]?.booleanValue !== true
  ) {
    throw new Error("Tenant database ownership, schema, identity, or RLS verification failed.");
  }
  await verifyOwnerRole(adminUsername);
  await verifyRuntimeControlIsolation();
  await verifyIngestRole();
  await verifyControlRole();
  await verifyLegalApiRole();
  await verifyWrongTenantDenied();
}

function executeAdmin(database, sql, parameters = undefined) {
  return rds.send(
    new ExecuteStatementCommand({
      database,
      includeResultMetadata: false,
      parameters,
      resourceArn: config.clusterArn,
      secretArn: config.adminSecretArn,
      sql,
    }),
  );
}

async function verifyOwnerRole(adminUsername) {
  const response = await executeAdmin(
    "scopeproof_admin",
    "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, pg_has_role(:admin, :owner, 'MEMBER') FROM pg_catalog.pg_roles WHERE rolname = :owner",
    [stringParameter("admin", adminUsername), stringParameter("owner", config.databaseOwner)],
  );
  const row = response.records?.[0] ?? [];
  if (row.length !== 7 || row.some((field) => field?.booleanValue !== false)) {
    throw new Error("Tenant database owner must remain NOLOGIN, unprivileged, and ungranted.");
  }
}

async function verifyIngestRole() {
  const isolatedTableList = isolatedTables.map(quoteLiteral).join(", ");
  const results = await runTransaction(config.ingestDatabaseSecretArn, [
    {
      sql: "SELECT set_config('scopeproof.tenant_id', :tenant_id, true)",
      parameters: [stringParameter("tenant_id", config.tenantId)],
    },
    {
      sql: "SELECT current_user, current_database(), has_schema_privilege(current_user, 'scopeproof', 'USAGE'), has_schema_privilege(current_user, 'scopeproof', 'CREATE')",
    },
    {
      sql: "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user",
    },
    {
      sql: [
        "SELECT count(*) FILTER (WHERE has_function_privilege(current_user, p.oid, 'EXECUTE'))::bigint,",
        "count(*) FILTER (WHERE p.proname IN ('claim_promotion_fence', 'current_tenant_id', 'read_promoted_evidence_receipt', 'reconcile_promoted_evidence') AND has_function_privilege(current_user, p.oid, 'EXECUTE'))::bigint",
        "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace",
        "WHERE n.nspname = 'scopeproof'",
      ].join(" "),
    },
    {
      sql: [
        "SELECT count(*) FILTER (WHERE",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'SELECT') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'INSERT') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'UPDATE') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'DELETE'))::bigint",
        `FROM unnest(ARRAY[${isolatedTableList}]::text[]) AS expected(name)`,
      ].join(" "),
    },
  ]);
  const session = results[1].records?.[0] ?? [];
  const role = results[2].records?.[0] ?? [];
  const functions = results[3].records?.[0] ?? [];
  const tables = results[4].records?.[0] ?? [];
  if (
    fieldString(session[0]) !== config.ingestDatabaseUsername ||
    fieldString(session[1]) !== config.databaseName ||
    session[2]?.booleanValue !== true ||
    session[3]?.booleanValue !== false ||
    role.length !== 6 ||
    role[0]?.booleanValue !== true ||
    role.slice(1).some((field) => field?.booleanValue !== false) ||
    fieldNumber(functions[0]) !== 4 ||
    fieldNumber(functions[1]) !== 4 ||
    fieldNumber(tables[0]) !== 0
  ) {
    throw new Error("Tenant ingest role is not an execute-only reconciliation identity.");
  }
}

async function verifyRuntimeControlIsolation() {
  const isolatedTableList = isolatedTables.map(quoteLiteral).join(", ");
  const results = await runTransaction(config.databaseSecretArn, [
    {
      sql: "SELECT set_config('scopeproof.tenant_id', :tenant_id, true)",
      parameters: [stringParameter("tenant_id", config.tenantId)],
    },
    {
      sql: [
        "SELECT count(*) FILTER (WHERE has_function_privilege(current_user, p.oid, 'EXECUTE'))::bigint,",
        "count(*) FILTER (WHERE p.proname IN ('current_tenant_id', 'resolve_active_membership', 'create_upload_intent') AND has_function_privilege(current_user, p.oid, 'EXECUTE'))::bigint",
        "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace",
        "WHERE n.nspname = 'scopeproof'",
      ].join(" "),
    },
    {
      sql: [
        "SELECT count(*) FILTER (WHERE",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'SELECT') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'INSERT') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'UPDATE') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'DELETE'))::bigint",
        `FROM unnest(ARRAY[${isolatedTableList}]::text[]) AS expected(name)`,
      ].join(" "),
    },
  ]);
  const functions = results[1].records?.[0] ?? [];
  const operations = results[2].records?.[0] ?? [];
  if (
    fieldNumber(functions[0]) !== 3 ||
    fieldNumber(functions[1]) !== 3 ||
    fieldNumber(operations[0]) !== 0
  ) {
    throw new Error("Tenant upload runtime is not an execute-only membership and upload identity.");
  }
}

async function verifyControlRole() {
  const isolatedTableList = isolatedTables.map(quoteLiteral).join(", ");
  const allowedFunctionList = controlRoleAllowedFunctions.map(quoteLiteral).join(", ");
  const results = await runTransaction(config.controlDatabaseSecretArn, [
    {
      sql: "SELECT set_config('scopeproof.tenant_id', :tenant_id, true)",
      parameters: [stringParameter("tenant_id", config.tenantId)],
    },
    {
      sql: "SELECT current_user, current_database(), has_schema_privilege(current_user, 'scopeproof', 'USAGE'), has_schema_privilege(current_user, 'scopeproof', 'CREATE')",
    },
    {
      sql: "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user",
    },
    {
      sql: [
        "SELECT count(*) FILTER (WHERE has_function_privilege(current_user, p.oid, 'EXECUTE'))::bigint,",
        `count(*) FILTER (WHERE p.proname IN (${allowedFunctionList}) AND has_function_privilege(current_user, p.oid, 'EXECUTE'))::bigint`,
        "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace",
        "WHERE n.nspname = 'scopeproof'",
      ].join(" "),
    },
    {
      sql: [
        "SELECT count(*) FILTER (WHERE",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'SELECT') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'INSERT') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'UPDATE') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'DELETE'))::bigint",
        `FROM unnest(ARRAY[${isolatedTableList}]::text[]) AS expected(name)`,
      ].join(" "),
    },
  ]);
  const session = results[1].records?.[0] ?? [];
  const role = results[2].records?.[0] ?? [];
  const functions = results[3].records?.[0] ?? [];
  const tables = results[4].records?.[0] ?? [];
  if (
    fieldString(session[0]) !== config.controlDatabaseUsername ||
    fieldString(session[1]) !== config.databaseName ||
    session[2]?.booleanValue !== true ||
    session[3]?.booleanValue !== false ||
    role.length !== 6 ||
    role[0]?.booleanValue !== true ||
    role.slice(1).some((field) => field?.booleanValue !== false) ||
    fieldNumber(functions[0]) !== controlRoleAllowedFunctions.length ||
    fieldNumber(functions[1]) !== controlRoleAllowedFunctions.length ||
    fieldNumber(tables[0]) !== 0
  ) {
    throw new Error("Tenant evidence-control role is not an execute-only control identity.");
  }
}

async function verifyLegalApiRole() {
  const isolatedTableList = isolatedTables.map(quoteLiteral).join(", ");
  const results = await runTransaction(config.legalApiDatabaseSecretArn, [
    {
      sql: "SELECT set_config('scopeproof.tenant_id', :tenant_id, true)",
      parameters: [stringParameter("tenant_id", config.tenantId)],
    },
    {
      sql: "SELECT current_user, current_database(), has_schema_privilege(current_user, 'scopeproof', 'USAGE'), has_schema_privilege(current_user, 'scopeproof', 'CREATE')",
    },
    {
      sql: "SELECT rolcanlogin, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls FROM pg_catalog.pg_roles WHERE rolname = current_user",
    },
    {
      sql: [
        "SELECT count(*) FILTER (WHERE has_function_privilege(current_user, p.oid, 'EXECUTE'))::bigint,",
        "count(*) FILTER (WHERE p.proname IN ('current_tenant_id', 'resolve_active_membership', 'reserve_exact_version_legal_hold', 'approve_exact_version_legal_hold') AND has_function_privilege(current_user, p.oid, 'EXECUTE'))::bigint",
        "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace",
        "WHERE n.nspname = 'scopeproof'",
      ].join(" "),
    },
    {
      sql: [
        "SELECT count(*) FILTER (WHERE",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'SELECT') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'INSERT') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'UPDATE') OR",
        "has_table_privilege(current_user, format('scopeproof.%I', expected.name), 'DELETE'))::bigint",
        `FROM unnest(ARRAY[${isolatedTableList}]::text[]) AS expected(name)`,
      ].join(" "),
    },
  ]);
  const session = results[1].records?.[0] ?? [];
  const role = results[2].records?.[0] ?? [];
  const functions = results[3].records?.[0] ?? [];
  const tables = results[4].records?.[0] ?? [];
  if (
    fieldString(session[0]) !== config.legalApiDatabaseUsername ||
    fieldString(session[1]) !== config.databaseName ||
    session[2]?.booleanValue !== true ||
    session[3]?.booleanValue !== false ||
    role.length !== 6 ||
    role[0]?.booleanValue !== true ||
    role.slice(1).some((field) => field?.booleanValue !== false) ||
    fieldNumber(functions[0]) !== 4 ||
    fieldNumber(functions[1]) !== 4 ||
    fieldNumber(tables[0]) !== 0
  ) {
    throw new Error("Tenant legal-hold API role is not an execute-only request and approval identity.");
  }
}

async function verifyWrongTenantDenied() {
  const wrongTenantId = config.tenantId === "ten_00000000000000000000000000000000"
    ? "ten_ffffffffffffffffffffffffffffffff"
    : "ten_00000000000000000000000000000000";
  const transaction = await beginTransaction(config.databaseSecretArn);
  let denied = false;
  try {
    await executeTransaction(transaction, {
      sql: "SELECT set_config('scopeproof.tenant_id', :tenant_id, true)",
      parameters: [stringParameter("tenant_id", wrongTenantId)],
    }, config.databaseSecretArn);
    await executeTransaction(transaction, {
      sql: "INSERT INTO scopeproof.principals (tenant_id, id, cognito_sub, email, display_name) VALUES (:tenant_id, 'usr_00000000000000000000000000000000', 'rls_verification_subject', 'rls-verification@invalid.example', 'RLS verification')",
      parameters: [stringParameter("tenant_id", config.tenantId)],
    }, config.databaseSecretArn);
  } catch (error) {
    const message = String(error?.message ?? "");
    denied = /tenant boundary violation/i.test(message) ||
      (/42501/.test(message) && /row.level security/i.test(message));
  } finally {
    await rollbackTransaction(transaction, config.databaseSecretArn);
  }
  if (!denied) throw new Error("Wrong-tenant write was not denied by the RLS boundary.");
}

async function applyMigration(sql, secretArn, runAsRole = undefined, migrationMarker = undefined) {
  const statements = splitSqlStatements(sql).filter(
    (statement) => !/^(BEGIN|COMMIT)\s*$/i.test(withoutSqlComments(statement)),
  );
  if (!statements.length) throw new Error("Migration contained no executable SQL.");
  const commands = statements.map((statement) => ({ sql: statement }));
  if (runAsRole) commands.unshift({ sql: `SET LOCAL ROLE ${quoteIdentifier(runAsRole)}` });
  if (migrationMarker) {
    commands.push({
      sql: `COMMENT ON TABLE scopeproof.schema_migrations IS ${quoteLiteral(migrationMarker)}`,
    });
  }
  await runTransaction(secretArn, commands);
}

async function runTransaction(secretArn, statements) {
  const transaction = await beginTransaction(secretArn);
  const results = [];
  try {
    for (const statement of statements) {
      results.push(await executeTransaction(transaction, statement, secretArn));
    }
    await rds.send(
      new CommitTransactionCommand({
        resourceArn: config.clusterArn,
        secretArn,
        transactionId: transaction,
      }),
    );
    return results;
  } catch (error) {
    await rollbackTransaction(transaction, secretArn);
    throw error;
  }
}

async function beginTransaction(secretArn) {
  const response = await rds.send(
    new BeginTransactionCommand({
      database: config.databaseName,
      resourceArn: config.clusterArn,
      secretArn,
    }),
  );
  if (!response.transactionId) throw new Error("RDS Data API did not return a transaction identifier.");
  return response.transactionId;
}

function executeTransaction(transactionId, statement, secretArn) {
  return rds.send(
    new ExecuteStatementCommand({
      database: config.databaseName,
      includeResultMetadata: false,
      parameters: statement.parameters,
      resourceArn: config.clusterArn,
      secretArn,
      sql: statement.sql,
      transactionId,
    }),
  );
}

async function rollbackTransaction(transactionId, secretArn) {
  try {
    await rds.send(
      new RollbackTransactionCommand({
        resourceArn: config.clusterArn,
        secretArn,
        transactionId,
      }),
    );
  } catch {
    // The service can already have expired/rolled back the transaction. Never
    // mask the original provisioning or verification failure.
  }
}

function tenantIdentityParameters() {
  return [
    stringParameter("tenant_id", config.tenantId),
    stringParameter("slug", config.tenantSlug),
    stringParameter("display_name", config.displayName),
    stringParameter("hostname", config.canonicalHostname),
    { name: "retention_days", value: { longValue: config.retentionDays } },
    stringParameter("retention_mode", config.retentionMode),
    stringParameter("account_id", config.awsAccountId),
    stringParameter("region", config.awsRegion),
    stringParameter("quarantine_bucket", config.quarantineBucket),
    stringParameter("evidence_bucket", config.evidenceBucket),
    stringParameter("key_arn", config.evidenceKeyArn),
    stringParameter("signing_key_arn", config.auditSigningKeyArn),
  ];
}

function stringParameter(name, value) {
  return { name, value: { stringValue: value } };
}

function fieldString(field) {
  if (!field || field.isNull) return undefined;
  return field.stringValue;
}

function fieldNumber(field) {
  if (!field || field.isNull) return undefined;
  return field.longValue ?? (field.stringValue === undefined ? undefined : Number(field.stringValue));
}

function splitSqlStatements(sql) {
  const statements = [];
  let current = "";
  let index = 0;
  let quote = null;
  let dollarTag = null;
  let blockCommentDepth = 0;
  let lineComment = false;
  while (index < sql.length) {
    const character = sql[index];
    const next = sql[index + 1];
    if (lineComment) {
      current += character;
      if (character === "\n") lineComment = false;
      index += 1;
      continue;
    }
    if (blockCommentDepth > 0) {
      current += character;
      if (character === "/" && next === "*") {
        current += next;
        blockCommentDepth += 1;
        index += 2;
      } else if (character === "*" && next === "/") {
        current += next;
        blockCommentDepth -= 1;
        index += 2;
      } else {
        index += 1;
      }
      continue;
    }
    if (dollarTag) {
      if (sql.startsWith(dollarTag, index)) {
        current += dollarTag;
        index += dollarTag.length;
        dollarTag = null;
      } else {
        current += character;
        index += 1;
      }
      continue;
    }
    if (quote) {
      current += character;
      if (character === quote) {
        if (next === quote) {
          current += next;
          index += 2;
          continue;
        }
        quote = null;
      }
      index += 1;
      continue;
    }
    if (character === "-" && next === "-") {
      current += character + next;
      lineComment = true;
      index += 2;
      continue;
    }
    if (character === "/" && next === "*") {
      current += character + next;
      blockCommentDepth = 1;
      index += 2;
      continue;
    }
    if (character === "'" || character === '"') {
      quote = character;
      current += character;
      index += 1;
      continue;
    }
    if (character === "$") {
      const match = sql.slice(index).match(/^\$[A-Za-z_][A-Za-z0-9_]*\$|^\$\$/);
      if (match) {
        dollarTag = match[0];
        current += dollarTag;
        index += dollarTag.length;
        continue;
      }
    }
    if (character === ";") {
      if (current.trim()) statements.push(current.trim());
      current = "";
      index += 1;
      continue;
    }
    current += character;
    index += 1;
  }
  if (quote || dollarTag || blockCommentDepth > 0) {
    throw new Error("Migration contains an unterminated quoted or comment section.");
  }
  if (current.trim()) statements.push(current.trim());
  return statements;
}

function withoutSqlComments(statement) {
  return statement
    .replace(/--[^\n]*(?:\n|$)/g, " ")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .trim();
}

function registryKeys() {
  return [
    { PK: { S: `TENANT#${config.tenantId}` }, SK: { S: "METADATA" } },
    { PK: { S: `DOMAIN#${config.hostname}` }, SK: { S: "METADATA" } },
    { PK: { S: `DOMAIN#${config.apiHostname}` }, SK: { S: "METADATA" } },
  ];
}

function quoteIdentifier(value) {
  return `"${value.replaceAll('"', '""')}"`;
}

function quoteLiteral(value) {
  return `'${value.replaceAll("'", "''")}'`;
}

function scramSha256Verifier(password) {
  const iterations = 4096;
  const salt = randomBytes(16);
  const saltedPassword = pbkdf2Sync(password, salt, iterations, 32, "sha256");
  const clientKey = createHmac("sha256", saltedPassword).update("Client Key", "utf8").digest();
  const storedKey = createHash("sha256").update(clientKey).digest("base64");
  const serverKey = createHmac("sha256", saltedPassword).update("Server Key", "utf8").digest("base64");
  return `SCRAM-SHA-256$${iterations}:${salt.toString("base64")}$${storedKey}:${serverKey}`;
}

function sanitizeErrorName(value) {
  const name = String(value ?? "TenantProvisioningError").replace(/[^A-Za-z0-9_.:-]/g, "");
  return name.slice(0, 120) || "TenantProvisioningError";
}

function namedError(name, message) {
  const error = new Error(message);
  error.name = name;
  return error;
}

function containsControlCharacters(value) {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 32 || code === 127) return true;
  }
  return false;
}
