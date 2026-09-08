import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { hash, canonical } from "../runtime/restore-operator/contract.mjs";
import { createCutoverPlan } from "../runtime/cutover-operator/contract.mjs";
import { verifyCutover, executeCutover, cutoverReceipt } from "../runtime/cutover-operator/workflow.mjs";
const now = Date.parse("2026-09-08T12:00:00Z"), tenant = `ten_${"a".repeat(32)}`, account = "111111111111";
function fixture() {
  const cname = (value) => ({ Name: "acme.evidence.example.com.", Type: "CNAME", TTL: 60, ResourceRecords: [{ Value: value }] });
  const config = { schemaVersion: 1, account, recoveryRegion: "us-west-2", hostedZoneId: "Z123456789", zoneName: "evidence.example.com.", operatorRoleArn: `arn:aws:iam::${account}:role/scopeproof/recovery/cutover`,
    acceptanceKeyArn: `arn:aws:kms:us-west-2:${account}:key/acceptance`, approvalKeyArn: `arn:aws:kms:us-west-2:${account}:key/approval`,
    mappings: [{ tenantId: tenant, name: "acme.evidence.example.com.", before: cname("primary.amplifyapp.com."), after: cname("recovery.amplifyapp.com.") }] };
  const body = { schemaVersion: 1, status: "ISOLATED_INFRASTRUCTURE_RESTORED", planDigest: "a".repeat(64), restoreJobId: "job-fixture", targetClusterArn: `arn:aws:rds:us-west-2:${account}:cluster:scopeproof-restore-fixture`, verifiedAt: new Date(now - 120000).toISOString(), verifiedArtifactCount: 10,
    dnsMutation: false, cutoverAuthorized: false, remainingGates: ["Database schema/tenant/session reconciliation", "Evidence and audit application reconciliation", "Independent application acceptance", "Separately authorized cutover"] };
  const restored = { ...body, receiptSha256: hash(`scopeproof-isolated-restore-receipt-v1\n${canonical(body)}`) };
  const acceptance = { schemaVersion: 1, decision: "APPLICATION_ACCEPTED", mappingDigest: hash(`scopeproof-cutover-mapping-v1\n${canonical(config)}`), restorePlanDigest: restored.planDigest, restoreReceiptSha256: restored.receiptSha256,
    targetClusterArn: restored.targetClusterArn, tenantIds: [tenant], primaryWriteFenceReceiptSha256: "b".repeat(64), gates: { databaseReconciled: true, sessionsReconciled: true, evidenceReconciled: true, auditChainVerified: true, customerAcceptance: true, primaryWritesFenced: true },
    acceptedAt: new Date(now - 60000).toISOString(), expiresAt: new Date(now + 600000).toISOString() };
  const plan = createCutoverPlan(config, restored, acceptance, now);
  const approval = { schemaVersion: 1, decision: "AUTHORIZE_DNS_CUTOVER", planDigest: plan.planDigest, operatorRoleArn: config.operatorRoleArn,
    approvedAt: new Date(now - 30000).toISOString(), expiresAt: new Date(now + 600000).toISOString(), signature: "A".repeat(88) };
  const writes = [], signatureKeys = [], records = new Map([[config.mappings[0].name, config.mappings[0].before]]);
  const aws = {
    identity: async () => ({ Account: account, Arn: `arn:aws:sts::${account}:assumed-role/cutover/approved-run` }),
    verifySignature: async (key) => { signatureKeys.push(key); return true; },
    zone: async () => ({ Id: "/hostedzone/Z123456789", Name: config.zoneName, Config: { PrivateZone: false } }),
    record: async (zone, expected) => records.get(expected.Name),
    change: async (request) => { writes.push(request); for (const change of request.ChangeBatch.Changes) if (change.Action === "CREATE") records.set(change.ResourceRecordSet.Name, change.ResourceRecordSet); return { Id: "/change/C123456", Status: "PENDING" }; },
    changeStatus: async () => ({ Id: "/change/C123456", Status: "INSYNC", Comment: `Scopeproof accepted cutover ${plan.planDigest}` }),
  };
  return { config, restored, acceptance, plan, approval, aws, writes, signatureKeys, records, signature: "A".repeat(88) };
}
test("offline cutover plan requires all application/fence gates and exact restored tenant mapping", () => {
  const f = fixture();
  for (const acceptance of [{ ...f.acceptance, gates: { ...f.acceptance.gates, primaryWritesFenced: false } }, { ...f.acceptance, tenantIds: [`ten_${"b".repeat(32)}`] }, { ...f.acceptance, expiresAt: "invalid" }, { ...f.acceptance, mappingDigest: "c".repeat(64) }]) assert.throws(() => createCutoverPlan(f.config, f.restored, acceptance, now));
  assert.throws(() => createCutoverPlan({ ...f.config, mappings: [{ ...f.config.mappings[0], name: "auth.evidence.example.com." }] }, f.restored, f.acceptance, now));
  assert.throws(() => createCutoverPlan(f.config, { ...f.restored, verifiedArtifactCount: 999 }, f.acceptance, now));
});
test("signature, expiry, accepted digest, role, authoritative zone and DNS drift failures cause no change", async () => {
  for (const alter of [
    (f) => { f.aws.verifySignature = async () => false; },
    (f) => { f.approval.expiresAt = new Date(now - 1).toISOString(); },
    (f) => { f.approval.planDigest = "b".repeat(64); },
    (f) => { f.aws.identity = async () => ({ Account: account, Arn: `arn:aws:sts::${account}:assumed-role/customer/session` }); },
    (f) => { f.aws.zone = async () => ({ Id: "/hostedzone/ZDIFFERENT", Name: f.config.zoneName, Config: { PrivateZone: false } }); },
    (f) => { f.records.set(f.config.mappings[0].name, f.config.mappings[0].after); },
  ]) { const f = fixture(); alter(f); await assert.rejects(executeCutover(f.plan, f.signature, f.approval, f.plan.planDigest, f.aws, now)); assert.equal(f.writes.length, 0); }
  const f = fixture(); await assert.rejects(executeCutover(f.plan, f.signature, f.approval, "not-accepted", f.aws, now)); assert.equal(f.writes.length, 0);
});
test("accepted cutover submits exactly one atomic preimage-delete/target-create batch and observes INSYNC", async () => {
  const f = fixture(); await verifyCutover(f.plan, f.signature, f.aws, now); assert.equal(f.writes.length, 0);
  const submitted = await executeCutover(f.plan, f.signature, f.approval, f.plan.planDigest, f.aws, now);
  assert.equal(f.writes.length, 1); assert.deepEqual(f.writes[0].ChangeBatch.Changes, [{ Action: "DELETE", ResourceRecordSet: f.config.mappings[0].before }, { Action: "CREATE", ResourceRecordSet: f.config.mappings[0].after }]);
  assert.deepEqual(new Set(f.signatureKeys), new Set([f.config.acceptanceKeyArn, f.config.approvalKeyArn]));
  const receipt = await cutoverReceipt(f.plan, submitted, f.aws); assert.equal(receipt.status, "DNS_INSYNC"); assert.equal(receipt.applicationHealthVerified, false);
  await assert.rejects(executeCutover(f.plan, f.signature, f.approval, f.plan.planDigest, f.aws, now)); assert.equal(f.writes.length, 1);
});
test("operator adapter exposes only exact DNS change, read and KMS Verify; no automatic retry/rollback", async () => {
  const source = await readFile(new URL("../runtime/cutover-operator/index.mjs", import.meta.url), "utf8");
  assert.match(source, /ChangeResourceRecordSetsCommand/); assert.match(source, /MaxItems: 1/); assert.match(source, /MessageType: "DIGEST"/);
  assert.match(source, /maxAttempts: 1/);
  assert.doesNotMatch(source, /SignCommand|PutItemCommand|DeleteObjectCommand|StartRestoreJobCommand/);
  const workflow = await readFile(new URL("../runtime/cutover-operator/workflow.mjs", import.meta.url), "utf8");
  assert.equal([...workflow.matchAll(/await aws\.change\(/g)].length, 1);
});

test("approval expiring during read-only preflight cannot authorize the later DNS write", async () => {
  const f = fixture(), originalClock = Date.now;
  let wall = originalClock(); Date.now = () => wall;
  const read = f.aws.record;
  f.aws.record = async (...args) => { wall += 1200000; return read(...args); };
  try { await assert.rejects(executeCutover(f.plan, f.signature, f.approval, f.plan.planDigest, f.aws, now)); assert.equal(f.writes.length, 0); }
  finally { Date.now = originalClock; }
});
