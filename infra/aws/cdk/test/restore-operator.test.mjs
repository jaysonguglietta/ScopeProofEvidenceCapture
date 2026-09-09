import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { createPlan, hash, approvalMessage } from "../runtime/restore-operator/contract.mjs";
import { verifyRecovery, startIsolatedRestore, attachIsolatedWriter, isolatedReceipt } from "../runtime/restore-operator/workflow.mjs";
const now = Date.parse("2026-09-08T12:00:00Z"), account = "111111111111", tenant = `ten_${"a".repeat(32)}`;
const key = (name) => `arn:aws:kms:us-west-2:${account}:key/${name}`;
function fixture() {
  const config = { schemaVersion: 1, account, primaryRegion: "us-east-1", recoveryRegion: "us-west-2", sourceClusterArn: `arn:aws:rds:us-east-1:${account}:cluster:scopeproof-source`,
    recoveryVaultName: "scopeproof-dev-recovery", recoveryPointArn: `arn:aws:rds:us-west-2:${account}:cluster-snapshot:awsbackup:fixture`, backupKeyArn: key("backup"),
    restoreRoleArn: `arn:aws:iam::${account}:role/scopeproof/recovery/restore`, operatorRoleArn: `arn:aws:iam::${account}:role/scopeproof/recovery/operator`, approvalKeyArn: key("approval"), inventorySigningKeyArn: key("inventory"),
    targetClusterIdentifier: "scopeproof-restore-drill", targetInstanceClass: "db.t4g.medium", targetSubnetGroup: "scopeproof-isolated", targetSecurityGroupIds: ["sg-aaaaaaaa"], targetVpcId: "vpc-aaaaaaaa", tenantIds: [tenant],
    buckets: [{ name: "recovery-audit-fixture", kmsKeyArn: key("audit"), prefix: `AWSLogs/${account}/` }, { name: "recovery-tenant-fixture", kmsKeyArn: key("evidence"), prefix: `tenants/${tenant}/` }], maxRecoveryAgeSeconds: 86400 };
  const artifacts = ["CLOUDTRAIL_LOG", "CLOUDTRAIL_DIGEST", "COMPLETENESS_RECEIPT", "CLOUDTRAIL_VALIDATION_RECEIPT", "EVIDENCE"].map((kind) => ({ kind, bucket: kind === "EVIDENCE" ? config.buckets[1].name : config.buckets[0].name,
    key: `${kind === "EVIDENCE" ? config.buckets[1].prefix : config.buckets[0].prefix}${kind}`, versionId: `version-${kind}`, sha256: hash(kind), bytes: kind.length, retainUntil: "2027-09-08T12:00:00.000Z", legalHold: "OFF" }));
  const manifest = { schemaVersion: 1, sourceClusterArn: config.sourceClusterArn, recoveryPointArn: config.recoveryPointArn, inventoryAt: new Date(now).toISOString(), tenantIds: [tenant], artifacts,
    completenessReceiptSha256: hash("COMPLETENESS_RECEIPT"), cloudTrailValidationReceiptSha256: hash("CLOUDTRAIL_VALIDATION_RECEIPT") };
  const plan = createPlan(config, manifest, now), calls = [];
  const cluster = { DBClusterArn: `arn:aws:rds:us-west-2:${account}:cluster:${config.targetClusterIdentifier}`, DBClusterIdentifier: config.targetClusterIdentifier, Status: "available", Engine: "aurora-postgresql",
    StorageEncrypted: true, KmsKeyId: config.backupKeyArn, DBSubnetGroup: config.targetSubnetGroup, HttpEndpointEnabled: false, VpcSecurityGroups: [{ VpcSecurityGroupId: "sg-aaaaaaaa" }], DBClusterMembers: [] };
  const aws = {
    identity: async () => ({ Account: account, Arn: `arn:aws:sts::${account}:assumed-role/operator/drill` }),
    verifySignature: async () => true,
    recoveryPoint: async () => ({ RecoveryPointArn: config.recoveryPointArn, ResourceArn: config.sourceClusterArn, ResourceType: "Aurora", Status: "COMPLETED", IsEncrypted: true, EncryptionKeyArn: config.backupKeyArn, CompletionDate: new Date(now - 60000) }),
    network: async () => ({ subnetGroup: { VpcId: config.targetVpcId, SubnetGroupStatus: "Complete", Subnets: [{ SubnetIdentifier: "subnet-a" }, { SubnetIdentifier: "subnet-b" }] },
      subnets: ["a", "b"].map((id) => ({ SubnetId: `subnet-${id}`, VpcId: config.targetVpcId, AvailabilityZone: `us-west-2${id}`, MapPublicIpOnLaunch: false, State: "available" })),
      securityGroups: [{ GroupId: "sg-aaaaaaaa", VpcId: config.targetVpcId, IpPermissions: [], IpPermissionsEgress: [] }] }),
    cluster: async () => undefined,
    bucketRegion: async () => "us-west-2",
    head: async (a) => ({ VersionId: a.versionId, ContentLength: a.bytes, ServerSideEncryption: "aws:kms", SSEKMSKeyId: config.buckets.find((b) => b.name === a.bucket).kmsKeyArn,
      ObjectLockMode: "COMPLIANCE", ObjectLockLegalHoldStatus: a.legalHold, ObjectLockRetainUntilDate: new Date(a.retainUntil) }),
    objectSha256: async (a) => a.sha256,
    startRestore: async (r) => { calls.push(r); return { RestoreJobId: "job-fixture" }; },
    restoreJob: async () => ({ RestoreJobId: "job-fixture", Status: "COMPLETED", RecoveryPointArn: config.recoveryPointArn, IamRoleArn: config.restoreRoleArn, CreatedResourceArn: cluster.DBClusterArn }),
    attachWriter: async (r) => { calls.push(r); },
    writer: async () => ({ DBInstanceStatus: "available", DBClusterIdentifier: config.targetClusterIdentifier, PubliclyAccessible: false, DBInstanceClass: config.targetInstanceClass, StorageEncrypted: true, KmsKeyId: config.backupKeyArn }),
  };
  const approval = (phase) => ({ schemaVersion: 1, decision: "APPROVED", phase, planDigest: plan.planDigest, operatorRoleArn: config.operatorRoleArn,
    approvedAt: new Date(now - 60000).toISOString(), expiresAt: new Date(now + 600000).toISOString(), signature: "A".repeat(88) });
  return { plan, config, manifest, aws, calls, cluster, approval, signature: "A".repeat(88) };
}
test("offline plan binds exact cross-region artifacts, tenant inventory, isolation and metadata", () => {
  const f = fixture();
  assert.equal(f.plan.dnsMutation, false);
  for (const config of [{ ...f.config, recoveryRegion: "us-east-1" }, { ...f.config, targetClusterIdentifier: "production" }, { ...f.config, unknown: true }]) assert.throws(() => createPlan(config, f.manifest, now));
  assert.throws(() => createPlan(f.config, { ...f.manifest, artifacts: f.manifest.artifacts.slice(1) }, now));
  assert.throws(() => approvalMessage(f.plan, { ...f.approval("START_CLUSTER"), expiresAt: new Date(now + 1800000).toISOString() }, "START_CLUSTER", now));
});
test("no restore write occurs on failed signature, artifact, network, tenant, expiry, identity or accepted digest", async () => {
  const scenarios = [
    (f) => { f.aws.verifySignature = async () => false; },
    (f) => { f.aws.objectSha256 = async () => "f".repeat(64); },
    (f) => { f.aws.bucketRegion = async () => "us-east-1"; },
    (f) => { f.aws.cluster = async () => f.cluster; },
    (f) => { const n = f.aws.network; f.aws.network = async () => { const v = await n(); v.securityGroups[0].IpPermissions = [{}]; return v; }; },
    (f) => { f.aws.identity = async () => ({ Account: account, Arn: `arn:aws:sts::${account}:assumed-role/tenant-runtime/drill` }); },
    (f) => { f.plan.config.tenantIds = [`ten_${"b".repeat(32)}`]; },
    (f) => { const h = f.aws.head; f.aws.head = async (a) => ({ ...await h(a), ObjectLockMode: "GOVERNANCE" }); },
  ];
  for (const alter of scenarios) { const f = fixture(); alter(f); await assert.rejects(startIsolatedRestore(f.plan, f.signature, f.approval("START_CLUSTER"), f.plan.planDigest, f.aws, now)); assert.equal(f.calls.length, 0); }
  const f = fixture(); await assert.rejects(startIsolatedRestore(f.plan, f.signature, f.approval("START_CLUSTER"), "wrong", f.aws, now)); assert.equal(f.calls.length, 0);
});
test("verified isolated restore and separately approved writer lead only to a non-cutover receipt", async () => {
  const f = fixture();
  await verifyRecovery(f.plan, f.signature, f.aws, { now }); assert.equal(f.calls.length, 0);
  const result = await startIsolatedRestore(f.plan, f.signature, f.approval("START_CLUSTER"), f.plan.planDigest, f.aws, now);
  assert.equal(result.status, "RESTORE_SUBMITTED"); assert.equal(f.calls.length, 1); assert.equal(f.calls[0].IdempotencyToken, f.plan.planDigest);
  assert.equal(f.calls[0].Metadata.DBSubnetGroupName, f.config.targetSubnetGroup);
  f.aws.cluster = async () => f.cluster;
  await assert.rejects(attachIsolatedWriter(f.plan, f.signature, "job-fixture", f.approval("START_CLUSTER"), f.plan.planDigest, f.aws, now));
  await attachIsolatedWriter(f.plan, f.signature, "job-fixture", f.approval("ATTACH_WRITER"), f.plan.planDigest, f.aws, now);
  assert.equal(f.calls.length, 2); assert.equal(f.calls[1].PubliclyAccessible, false);
  f.cluster.DBClusterMembers = [{ DBInstanceIdentifier: `${f.config.targetClusterIdentifier}-writer`, IsClusterWriter: true }];
  const receipt = await isolatedReceipt(f.plan, f.signature, "job-fixture", f.aws, now);
  assert.equal(receipt.cutoverAuthorized, false); assert.equal(receipt.dnsMutation, false); assert.equal(receipt.verifiedArtifactCount, 5); assert.match(receipt.receiptSha256, /^[a-f0-9]{64}$/);
});
test("real AWS adapter has no DNS/delete API and signs bounded digests", async () => {
  const source = await readFile(new URL("../runtime/restore-operator/index.mjs", import.meta.url), "utf8");
  assert.doesNotMatch(source, /route-53|ChangeResourceRecordSets|DeleteDB|DeleteObject|shell:\s*true/);
  assert.match(source, /MessageType: "DIGEST"/); assert.match(source, /ExpectedBucketOwner/); assert.match(source, /VersionId: a.versionId/);
});

test("approval expiring during artifact verification cannot authorize a later restore write", async () => {
  const f = fixture(), originalClock = Date.now;
  let wall = originalClock(); Date.now = () => wall;
  f.aws.objectSha256 = async (artifact) => { wall += 1200000; return artifact.sha256; };
  try { await assert.rejects(startIsolatedRestore(f.plan, f.signature, f.approval("START_CLUSTER"), f.plan.planDigest, f.aws, now)); assert.equal(f.calls.length, 0); }
  finally { Date.now = originalClock; }
});
