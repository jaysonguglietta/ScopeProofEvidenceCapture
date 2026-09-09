import { canonical, hash, keys } from "../restore-operator/contract.mjs";
export { canonical };
const fail = () => { throw new Error("Cutover requires an exact accepted recovery mapping and independent current approval."); };
const hostname = /^(?=.{4,254}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.$/;
const gates = ["databaseReconciled", "sessionsReconciled", "evidenceReconciled", "auditChainVerified", "customerAcceptance", "primaryWritesFenced"];
function timeWindow(value, now) {
  const from = Date.parse(value.acceptedAt ?? value.approvedAt), until = Date.parse(value.expiresAt);
  if (!Number.isFinite(from) || !Number.isFinite(until) || !Number.isFinite(now) || from > now || until <= now || until > from + 900000) fail();
}
function record(value, name) {
  if (value.Type === "CNAME") {
    keys(value, ["Name", "Type", "TTL", "ResourceRecords"]);
    if (!Number.isSafeInteger(value.TTL) || value.TTL < 30 || value.TTL > 3600 || !Array.isArray(value.ResourceRecords) || value.ResourceRecords.length !== 1) fail();
    keys(value.ResourceRecords[0], ["Value"]);
    if (!hostname.test(value.ResourceRecords[0].Value)) fail();
  } else if (value.Type === "A") {
    keys(value, ["Name", "Type", "AliasTarget"]); keys(value.AliasTarget, ["DNSName", "HostedZoneId", "EvaluateTargetHealth"]);
    if (!hostname.test(value.AliasTarget.DNSName) || !/^Z[A-Z0-9]{5,31}$/.test(value.AliasTarget.HostedZoneId) || value.AliasTarget.EvaluateTargetHealth !== false) fail();
  } else fail();
  if (value.Name !== name || !hostname.test(name)) fail();
}
export function createCutoverPlan(config, restoreReceipt, acceptance, now = Date.now()) {
  keys(config, ["schemaVersion", "account", "recoveryRegion", "hostedZoneId", "zoneName", "operatorRoleArn", "acceptanceKeyArn", "approvalKeyArn", "mappings"]);
  if (config.schemaVersion !== 1 || !/^\d{12}$/.test(config.account) || !/^us-(east|west)-[1-2]$/.test(config.recoveryRegion) || config.recoveryRegion === "us-east-1" ||
      !/^Z[A-Z0-9]{5,31}$/.test(config.hostedZoneId) || !hostname.test(config.zoneName) ||
      !new RegExp(`^arn:aws:iam::${config.account}:role/scopeproof/recovery/[A-Za-z0-9+=,.@_-]{1,64}$`).test(config.operatorRoleArn) ||
      !Array.isArray(config.mappings) || !config.mappings.length || config.mappings.length > 40) fail();
  const keyArn = new RegExp(`^arn:aws:kms:${config.recoveryRegion}:${config.account}:key/[a-zA-Z0-9-]{1,80}$`);
  if (!keyArn.test(config.acceptanceKeyArn) || !keyArn.test(config.approvalKeyArn) || config.acceptanceKeyArn === config.approvalKeyArn) fail();
  const names = new Set(), tenants = new Set();
  for (const mapping of config.mappings) {
    keys(mapping, ["tenantId", "name", "before", "after"]);
    if (!/^ten_[a-f0-9]{32}$/.test(mapping.tenantId) || !hostname.test(mapping.name) || !mapping.name.endsWith(`.${config.zoneName}`) ||
        mapping.name === `auth.${config.zoneName}` || names.has(mapping.name)) fail();
    record(mapping.before, mapping.name); record(mapping.after, mapping.name);
    if (canonical(mapping.before) === canonical(mapping.after)) fail();
    names.add(mapping.name); tenants.add(mapping.tenantId);
  }
  const mappingDigest = hash(`scopeproof-cutover-mapping-v1\n${canonical(config)}`);
  keys(restoreReceipt, ["schemaVersion", "status", "planDigest", "restoreJobId", "targetClusterArn", "verifiedAt", "verifiedArtifactCount", "dnsMutation", "cutoverAuthorized", "remainingGates", "receiptSha256"]);
  const receiptBody = Object.fromEntries(Object.entries(restoreReceipt).filter(([key]) => key !== "receiptSha256"));
  if (restoreReceipt.schemaVersion !== 1 || restoreReceipt.status !== "ISOLATED_INFRASTRUCTURE_RESTORED" || restoreReceipt.dnsMutation !== false || restoreReceipt.cutoverAuthorized !== false ||
      !/^[a-f0-9]{64}$/.test(restoreReceipt.planDigest) || restoreReceipt.receiptSha256 !== hash(`scopeproof-isolated-restore-receipt-v1\n${canonical(receiptBody)}`) ||
      !new RegExp(`^arn:aws:rds:${config.recoveryRegion}:${config.account}:cluster:scopeproof-restore-[a-z0-9-]{1,40}$`).test(restoreReceipt.targetClusterArn)) fail();
  keys(acceptance, ["schemaVersion", "decision", "mappingDigest", "restorePlanDigest", "restoreReceiptSha256", "targetClusterArn", "tenantIds", "primaryWriteFenceReceiptSha256", "gates", "acceptedAt", "expiresAt"]);
  keys(acceptance.gates, gates); timeWindow(acceptance, now);
  if (acceptance.schemaVersion !== 1 || acceptance.decision !== "APPLICATION_ACCEPTED" || acceptance.mappingDigest !== mappingDigest || acceptance.restorePlanDigest !== restoreReceipt.planDigest ||
      acceptance.restoreReceiptSha256 !== restoreReceipt.receiptSha256 || acceptance.targetClusterArn !== restoreReceipt.targetClusterArn || !/^[a-f0-9]{64}$/.test(acceptance.primaryWriteFenceReceiptSha256) ||
      Date.parse(acceptance.acceptedAt) < Date.parse(restoreReceipt.verifiedAt) || !Number.isFinite(Date.parse(restoreReceipt.verifiedAt)) ||
      canonical([...acceptance.tenantIds].sort()) !== canonical([...tenants].sort()) || gates.some((gate) => acceptance.gates[gate] !== true)) fail();
  const body = { schemaVersion: 1, action: "EXPLICIT_DNS_CUTOVER", config, restoreReceipt, acceptance, mappingDigest };
  return { ...body, planDigest: hash(`scopeproof-cutover-plan-v1\n${canonical(body)}`) };
}
export function cutoverApprovalMessage(plan, approval, now = Date.now()) {
  keys(approval, ["schemaVersion", "decision", "planDigest", "operatorRoleArn", "approvedAt", "expiresAt", "signature"]); timeWindow(approval, now);
  if (approval.schemaVersion !== 1 || approval.decision !== "AUTHORIZE_DNS_CUTOVER" || approval.planDigest !== plan.planDigest || approval.operatorRoleArn !== plan.config.operatorRoleArn ||
      Date.parse(approval.approvedAt) < Date.parse(plan.acceptance.acceptedAt) || !/^[A-Za-z0-9+/]{40,2048}={0,2}$/.test(approval.signature)) fail();
  return Buffer.from(`scopeproof-cutover-approval-v1\n${canonical(Object.fromEntries(Object.entries(approval).filter(([key]) => key !== "signature")))}`);
}
export function cutoverRequest(plan) {
  return { HostedZoneId: plan.config.hostedZoneId, ChangeBatch: { Comment: `Scopeproof accepted cutover ${plan.planDigest}`,
    Changes: plan.config.mappings.flatMap((m) => [{ Action: "DELETE", ResourceRecordSet: m.before }, { Action: "CREATE", ResourceRecordSet: m.after }]) } };
}
