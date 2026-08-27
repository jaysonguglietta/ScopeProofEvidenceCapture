#!/usr/bin/env node

import { chmod, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const migrationDirectory = new URL("../infra/aws/database/", import.meta.url);
const tenantPattern = /^ten_[a-f0-9]{32}$/;
const slugPattern = /^(?=.{1,48}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
const rolePattern = /^tenant_[a-z0-9_]{3,56}_runtime$/;
const ingestRolePattern = /^tenant_[a-z0-9_]{3,56}_ingest$/;
const controlRolePattern = /^tenant_[a-z0-9_]{3,56}_control$/;
const legalApiRolePattern = /^tenant_[a-z0-9_]{3,56}_legal_api$/;
const hostnamePattern = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const bucketPattern = /^(?=.{3,63}$)(?!\d+\.\d+\.\d+\.\d+$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])$/;
const regionPattern = /^[a-z]{2}(?:-gov)?-[a-z]+-\d$/;

function sqlLiteral(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function isValidBucketName(value) {
  return bucketPattern.test(value) && !value.includes("..") && !value.includes(".-") && !value.includes("-.") &&
    !value.startsWith("xn--") && !value.startsWith("sthree-") && !value.startsWith("amzn_s3_demo_") &&
    !["-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"].some((suffix) => value.endsWith(suffix));
}

export function validateTenantSqlOptions(candidate) {
  const value = {
    tenantId: String(candidate.tenantId || "").trim().toLowerCase(),
    slug: String(candidate.slug || "").trim().toLowerCase(),
    displayName: String(candidate.displayName || "").trim(),
    hostname: String(candidate.hostname || "").trim().toLowerCase().replace(/\.$/, ""),
    retentionDays: Number(candidate.retentionDays),
    retentionMode: String(candidate.retentionMode || "").trim().toUpperCase(),
    runtimeRole: String(candidate.runtimeRole || "").trim().toLowerCase(),
    ingestRole: String(candidate.ingestRole || "").trim().toLowerCase(),
    controlRole: String(candidate.controlRole || "").trim().toLowerCase(),
    legalApiRole: String(candidate.legalApiRole || "").trim().toLowerCase(),
    awsAccountId: String(candidate.awsAccountId || "").trim(),
    awsRegion: String(candidate.awsRegion || "").trim().toLowerCase(),
    quarantineBucket: String(candidate.quarantineBucket || "").trim().toLowerCase(),
    evidenceBucket: String(candidate.evidenceBucket || "").trim().toLowerCase(),
    kmsKeyArn: String(candidate.kmsKeyArn || "").trim(),
    signingKeyArn: String(candidate.signingKeyArn || "").trim(),
  };
  if (!tenantPattern.test(value.tenantId)) throw new Error("--tenant-id must match ten_ followed by 32 lowercase hexadecimal characters.");
  if (!slugPattern.test(value.slug)) throw new Error("--slug must be a 1-48 character DNS label.");
  if (value.displayName.length < 2 || value.displayName.length > 120) throw new Error("--display-name must contain 2-120 characters.");
  if (!hostnamePattern.test(value.hostname) || !value.hostname.startsWith(`${value.slug}.`)) throw new Error("--hostname must be an exact lowercase hostname beginning with the tenant slug.");
  if (!Number.isInteger(value.retentionDays) || value.retentionDays < 1 || value.retentionDays > 3650) throw new Error("--retention-days must be an integer from 1 through 3650.");
  if (!["GOVERNANCE", "COMPLIANCE"].includes(value.retentionMode)) throw new Error("--retention-mode must be GOVERNANCE or COMPLIANCE.");
  if (!rolePattern.test(value.runtimeRole)) throw new Error("--runtime-role must match tenant_[a-z0-9_]{3,56}_runtime.");
  if (!ingestRolePattern.test(value.ingestRole) || value.ingestRole === value.runtimeRole) throw new Error("--ingest-role must be a distinct role matching tenant_[a-z0-9_]{3,56}_ingest.");
  if (
    !controlRolePattern.test(value.controlRole) ||
    value.controlRole === value.runtimeRole ||
    value.controlRole === value.ingestRole
  ) throw new Error("--control-role must be a distinct role matching tenant_[a-z0-9_]{3,56}_control.");
  if (
    !legalApiRolePattern.test(value.legalApiRole) ||
    value.legalApiRole === value.runtimeRole ||
    value.legalApiRole === value.ingestRole ||
    value.legalApiRole === value.controlRole
  ) throw new Error("--legal-api-role must be a distinct role matching tenant_[a-z0-9_]{3,56}_legal_api.");
  if (!/^\d{12}$/.test(value.awsAccountId)) throw new Error("--aws-account-id must contain exactly 12 digits.");
  if (!regionPattern.test(value.awsRegion)) throw new Error("--aws-region is invalid.");
  if (!isValidBucketName(value.quarantineBucket) || !isValidBucketName(value.evidenceBucket) || value.quarantineBucket === value.evidenceBucket) throw new Error("Quarantine and evidence bucket names must be distinct valid S3 bucket names.");
  const escapedRegion = value.awsRegion.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const escapedAccount = value.awsAccountId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const kmsArnPattern = new RegExp(`^arn:(?:aws|aws-us-gov|aws-cn):kms:${escapedRegion}:${escapedAccount}:key/[0-9a-f-]{36}$`);
  if (!kmsArnPattern.test(value.kmsKeyArn)) throw new Error("--kms-key-arn must be a customer-managed key ARN in the configured account and region.");
  if (!kmsArnPattern.test(value.signingKeyArn) || value.signingKeyArn === value.kmsKeyArn) throw new Error("--signing-key-arn must be a distinct asymmetric customer-managed key ARN in the configured account and region.");
  return Object.freeze(value);
}

export async function renderTenantSql(candidate) {
  const options = validateTenantSqlOptions(candidate);
  const [schema, grants, ingestGrants, controlGrants, legalApiGrants] = await Promise.all([
    readFile(new URL("001_tenant_schema.sql", migrationDirectory), "utf8"),
    readFile(new URL("002_runtime_role.sql", migrationDirectory), "utf8"),
    readFile(new URL("003_ingest_role.sql", migrationDirectory), "utf8"),
    readFile(new URL("004_evidence_control_role.sql", migrationDirectory), "utf8"),
    readFile(new URL("005_legal_hold_api_role.sql", migrationDirectory), "utf8"),
  ]);
  const seed = [
    "-- Seed the immutable database identity before granting runtime access.",
    "BEGIN;",
    `SELECT pg_catalog.set_config('scopeproof.tenant_id', ${sqlLiteral(options.tenantId)}, true);`,
    "INSERT INTO scopeproof.tenant_identity",
    "  (tenant_id, slug, display_name, status, canonical_hostname, retention_days, retention_mode, aws_account_id, aws_region, quarantine_bucket, evidence_bucket, evidence_kms_key_arn, audit_signing_key_arn)",
    `VALUES (${sqlLiteral(options.tenantId)}, ${sqlLiteral(options.slug)}, ${sqlLiteral(options.displayName)}, 'PROVISIONING', ${sqlLiteral(options.hostname)}, ${options.retentionDays}, ${sqlLiteral(options.retentionMode)}, ${sqlLiteral(options.awsAccountId)}, ${sqlLiteral(options.awsRegion)}, ${sqlLiteral(options.quarantineBucket)}, ${sqlLiteral(options.evidenceBucket)}, ${sqlLiteral(options.kmsKeyArn)}, ${sqlLiteral(options.signingKeyArn)});`,
    "INSERT INTO scopeproof.tenant_domains (tenant_id, hostname, status, is_canonical)",
    `VALUES (${sqlLiteral(options.tenantId)}, ${sqlLiteral(options.hostname)}, 'PENDING', true);`,
    "COMMIT;",
  ].join("\n");
  const renderedGrants = grants.replaceAll("__SCOPEPROOF_RUNTIME_ROLE__", options.runtimeRole);
  if (renderedGrants.includes("__SCOPEPROOF_RUNTIME_ROLE__")) throw new Error("Runtime role substitution did not complete.");
  const renderedIngestGrants = ingestGrants.replaceAll("__SCOPEPROOF_INGEST_ROLE__", options.ingestRole);
  if (renderedIngestGrants.includes("__SCOPEPROOF_INGEST_ROLE__")) throw new Error("Ingest role substitution did not complete.");
  const renderedControlGrants = controlGrants.replaceAll("__SCOPEPROOF_CONTROL_ROLE__", options.controlRole);
  if (renderedControlGrants.includes("__SCOPEPROOF_CONTROL_ROLE__")) throw new Error("Evidence-control role substitution did not complete.");
  const renderedLegalApiGrants = legalApiGrants.replaceAll("__SCOPEPROOF_LEGAL_API_ROLE__", options.legalApiRole);
  if (renderedLegalApiGrants.includes("__SCOPEPROOF_LEGAL_API_ROLE__")) throw new Error("Legal-hold API role substitution did not complete.");
  return `${schema.trim()}\n\n${seed}\n\n${renderedGrants.trim()}\n\n${renderedIngestGrants.trim()}\n\n${renderedControlGrants.trim()}\n\n${renderedLegalApiGrants.trim()}\n`;
}

function parseArguments(argv) {
  const aliases = new Map([
    ["tenant-id", "tenantId"], ["slug", "slug"], ["display-name", "displayName"],
    ["hostname", "hostname"], ["retention-days", "retentionDays"],
    ["retention-mode", "retentionMode"], ["runtime-role", "runtimeRole"],
    ["ingest-role", "ingestRole"], ["output", "output"],
    ["control-role", "controlRole"],
    ["legal-api-role", "legalApiRole"],
    ["aws-account-id", "awsAccountId"], ["aws-region", "awsRegion"],
    ["quarantine-bucket", "quarantineBucket"], ["evidence-bucket", "evidenceBucket"],
    ["kms-key-arn", "kmsKeyArn"],
    ["signing-key-arn", "signingKeyArn"],
  ]);
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument.startsWith("--") || !aliases.has(argument.slice(2))) throw new Error(`Unknown argument: ${argument}`);
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${argument}`);
    result[aliases.get(argument.slice(2))] = value;
    index += 1;
  }
  return result;
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const sql = await renderTenantSql(options);
  if (options.output) {
    await writeFile(options.output, sql, { encoding: "utf8", flag: "wx", mode: 0o600 });
    await chmod(options.output, 0o600);
    process.stdout.write(`Wrote tenant SQL bundle to ${options.output}\n`);
    return;
  }
  process.stdout.write(sql);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((error) => {
    process.stderr.write(`Unable to render tenant SQL: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
