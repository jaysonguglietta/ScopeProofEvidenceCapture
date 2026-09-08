import { createHash } from "node:crypto";
import { canonical } from "../bootstrap-database/contract.mjs";
export { canonical };
export const hash = (value) => createHash("sha256").update(value).digest("hex");
export function exactOperatorIdentity(identity, account, roleArn) {
  const roleName = roleArn.split("/").at(-1);
  const prefix = `arn:aws:sts::${account}:assumed-role/${roleName}/`;
  return identity.Account === account && typeof identity.Arn === "string"
    && identity.Arn.startsWith(prefix) && /^[A-Za-z0-9+=,.@_-]{1,64}$/.test(identity.Arn.slice(prefix.length));
}
const arn = (service, region, account, value) => new RegExp(`^arn:aws:${service}:${region}:${account}:${value}$`);
const fail = () => { throw new Error("Recovery contract is not exact, cross-region and isolated."); };
export function keys(value, expected) {
  if (!value || typeof value !== "object" || Array.isArray(value) || canonical(Object.keys(value).sort()) !== canonical([...expected].sort())) fail();
}
export function validateConfig(c) {
  keys(c, ["schemaVersion", "account", "primaryRegion", "recoveryRegion", "sourceClusterArn", "recoveryVaultName", "recoveryPointArn", "backupKeyArn", "restoreRoleArn", "operatorRoleArn", "approvalKeyArn", "inventorySigningKeyArn", "targetClusterIdentifier", "targetInstanceClass", "targetSubnetGroup", "targetSecurityGroupIds", "targetVpcId", "tenantIds", "buckets", "maxRecoveryAgeSeconds"]);
  if (c.schemaVersion !== 1 || !/^\d{12}$/.test(c.account) || c.primaryRegion !== "us-east-1" || !/^us-(east|west)-[1-2]$/.test(c.recoveryRegion) || c.primaryRegion === c.recoveryRegion ||
      !arn("rds", c.primaryRegion, c.account, "cluster:[a-zA-Z0-9-]{1,63}").test(c.sourceClusterArn) ||
      !arn("rds", c.recoveryRegion, c.account, "cluster-snapshot:[a-zA-Z0-9:-]{1,255}").test(c.recoveryPointArn) ||
      !/^scopeproof-[a-z0-9-]{1,60}-recovery$/.test(c.recoveryVaultName) || !/^scopeproof-restore-[a-z0-9-]{1,40}$/.test(c.targetClusterIdentifier) ||
      !["db.t4g.medium", "db.r6g.large", "db.r7g.large"].includes(c.targetInstanceClass) || !/^[a-z][a-z0-9-]{1,62}$/.test(c.targetSubnetGroup) || !/^vpc-[a-f0-9]{8,17}$/.test(c.targetVpcId) ||
      !Number.isSafeInteger(c.maxRecoveryAgeSeconds) || c.maxRecoveryAgeSeconds < 1 || c.maxRecoveryAgeSeconds > 604800 ||
      !Array.isArray(c.targetSecurityGroupIds) || !c.targetSecurityGroupIds.length || c.targetSecurityGroupIds.length > 5 || c.targetSecurityGroupIds.some((v) => !/^sg-[a-f0-9]{8,17}$/.test(v)) ||
      !Array.isArray(c.tenantIds) || !c.tenantIds.length || c.tenantIds.some((v) => !/^ten_[a-f0-9]{32}$/.test(v)) || new Set(c.tenantIds).size !== c.tenantIds.length) fail();
  for (const key of [c.backupKeyArn, c.approvalKeyArn, c.inventorySigningKeyArn]) if (!arn("kms", c.recoveryRegion, c.account, "key/[a-zA-Z0-9-]{1,80}").test(key)) fail();
  if (c.approvalKeyArn === c.inventorySigningKeyArn) fail();
  for (const role of [c.restoreRoleArn, c.operatorRoleArn]) if (!new RegExp(`^arn:aws:iam::${c.account}:role/scopeproof/recovery/[A-Za-z0-9+=,.@_-]{1,64}$`).test(role)) fail();
  if (!Array.isArray(c.buckets) || !c.buckets.length || c.buckets.length > 1000) fail();
  for (const b of c.buckets) {
    keys(b, ["name", "kmsKeyArn", "prefix"]);
    if (!/^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$/.test(b.name) || !arn("kms", c.recoveryRegion, c.account, "key/[a-zA-Z0-9-]{1,80}").test(b.kmsKeyArn) ||
        !(b.prefix === `AWSLogs/${c.account}/` || c.tenantIds.some((id) => b.prefix === `tenants/${id}/`))) fail();
  }
  if (new Set(c.buckets.map((b) => b.name)).size !== c.buckets.length || !c.buckets.some((b) => b.prefix.startsWith("AWSLogs/")) || c.tenantIds.some((id) => !c.buckets.some((b) => b.prefix === `tenants/${id}/`))) fail();
  return c;
}
export function createPlan(configInput, manifest, now = Date.now()) {
  const config = validateConfig(configInput);
  keys(manifest, ["schemaVersion", "sourceClusterArn", "recoveryPointArn", "inventoryAt", "tenantIds", "artifacts", "completenessReceiptSha256", "cloudTrailValidationReceiptSha256"]);
  if (manifest.schemaVersion !== 1 || manifest.sourceClusterArn !== config.sourceClusterArn || manifest.recoveryPointArn !== config.recoveryPointArn ||
      canonical([...manifest.tenantIds].sort()) !== canonical([...config.tenantIds].sort()) ||
      !/^[a-f0-9]{64}$/.test(manifest.completenessReceiptSha256) || !/^[a-f0-9]{64}$/.test(manifest.cloudTrailValidationReceiptSha256) ||
      !Number.isFinite(Date.parse(manifest.inventoryAt)) || Date.parse(manifest.inventoryAt) > now || now - Date.parse(manifest.inventoryAt) > 3600000 ||
      !Array.isArray(manifest.artifacts) || !manifest.artifacts.length || manifest.artifacts.length > 10000) fail();
  const unique = new Set();
  for (const a of manifest.artifacts) {
    keys(a, ["kind", "bucket", "key", "versionId", "sha256", "bytes", "retainUntil", "legalHold"]);
    const b = config.buckets.find((b) => b.name === a.bucket);
    const identity = canonical([a.bucket, a.key, a.versionId]);
    if (!b || typeof a.key !== "string" || a.key.length > 1024 || !a.key.startsWith(b.prefix) || [...a.key].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127) || !/^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/.test(a.versionId) || a.versionId === "null" ||
        !/^[a-f0-9]{64}$/.test(a.sha256) || !Number.isSafeInteger(a.bytes) || a.bytes < 1 || a.bytes > 67108864 || !["ON", "OFF"].includes(a.legalHold) ||
        !["EVIDENCE", "CLOUDTRAIL_LOG", "CLOUDTRAIL_DIGEST", "COMPLETENESS_RECEIPT", "CLOUDTRAIL_VALIDATION_RECEIPT"].includes(a.kind) ||
        !Number.isFinite(Date.parse(a.retainUntil)) || Date.parse(a.retainUntil) <= now || unique.has(identity)) fail();
    if (a.kind === "EVIDENCE" ? !b.prefix.startsWith("tenants/") : !b.prefix.startsWith("AWSLogs/")) fail();
    unique.add(identity);
  }
  for (const kind of ["CLOUDTRAIL_LOG", "CLOUDTRAIL_DIGEST", "COMPLETENESS_RECEIPT", "CLOUDTRAIL_VALIDATION_RECEIPT"]) if (!manifest.artifacts.some((a) => a.kind === kind)) fail();
  if (!manifest.artifacts.some((a) => a.kind === "COMPLETENESS_RECEIPT" && a.sha256 === manifest.completenessReceiptSha256) || !manifest.artifacts.some((a) => a.kind === "CLOUDTRAIL_VALIDATION_RECEIPT" && a.sha256 === manifest.cloudTrailValidationReceiptSha256)) fail();
  const core = { schemaVersion: 1, action: "ISOLATED_RESTORE_ONLY", config, manifest };
  return { ...core, planDigest: hash(`scopeproof-recovery-plan-v1\n${canonical(core)}`), dnsMutation: false };
}
export function approvalMessage(plan, approval, phase, now = Date.now()) {
  keys(approval, ["schemaVersion", "decision", "phase", "planDigest", "operatorRoleArn", "approvedAt", "expiresAt", "signature"]);
  const start = Date.parse(approval.approvedAt), end = Date.parse(approval.expiresAt);
  if (approval.schemaVersion !== 1 || approval.decision !== "APPROVED" || approval.phase !== phase || approval.planDigest !== plan.planDigest || approval.operatorRoleArn !== plan.config.operatorRoleArn ||
      !["START_CLUSTER", "ATTACH_WRITER"].includes(phase) || !Number.isFinite(start) || !Number.isFinite(end) || !Number.isFinite(now) || start > now || end <= now || end > start + 900000 || !/^[A-Za-z0-9+/]{40,2048}={0,2}$/.test(approval.signature)) fail();
  const body = Object.fromEntries(Object.entries(approval).filter(([key]) => key !== "signature"));
  return Buffer.from(`scopeproof-recovery-approval-v1\n${canonical(body)}`);
}
export function restoreRequest(plan) {
  const c = plan.config;
  return { RecoveryPointArn: c.recoveryPointArn, IamRoleArn: c.restoreRoleArn, ResourceType: "Aurora", IdempotencyToken: plan.planDigest,
    CopySourceTagsToRestoredResource: false, Metadata: { DBClusterIdentifier: c.targetClusterIdentifier, Engine: "aurora-postgresql", EngineMode: "provisioned", Port: "5432",
      DBSubnetGroupName: c.targetSubnetGroup, VpcSecurityGroupIds: JSON.stringify(c.targetSecurityGroupIds), KmsKeyId: c.backupKeyArn,
      EnableIAMDatabaseAuthentication: "true", EnableCloudwatchLogsExports: '["postgresql"]' } };
}
