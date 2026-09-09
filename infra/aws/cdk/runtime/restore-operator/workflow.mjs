import { createPlan, canonical, approvalMessage, restoreRequest, hash, exactOperatorIdentity } from "./contract.mjs";

// Adapter contract is implemented by the real AWS SDK/CLI in index.mjs. Tests
// exercise ordering/failure boundaries with a fake adapter, not a live restore.
export async function verifyRecovery(planInput, inventorySignature, aws, { requireAbsent = true, now = Date.now() } = {}) {
  const plan = createPlan(planInput.config, planInput.manifest, now);
  if (canonical(plan) !== canonical(planInput)) throw new Error("Plan changed after review.");
  const c = plan.config;
  const identity = await aws.identity();
  if (!exactOperatorIdentity(identity, c.account, c.operatorRoleArn)) throw new Error("Use the exact recovery operator role.");
  if (typeof inventorySignature !== "string" || !/^[A-Za-z0-9+/]{40,2048}={0,2}$/.test(inventorySignature) ||
      !(await aws.verifySignature(c.inventorySigningKeyArn, Buffer.from(`scopeproof-recovery-inventory-v1\n${canonical(plan.manifest)}`), Buffer.from(inventorySignature, "base64")))) throw new Error("Recovery inventory signature is invalid.");
  const point = await aws.recoveryPoint(c);
  if (point.RecoveryPointArn !== c.recoveryPointArn || point.ResourceArn !== c.sourceClusterArn || point.Status !== "COMPLETED" || point.ResourceType !== "Aurora" ||
      point.IsEncrypted !== true || point.EncryptionKeyArn !== c.backupKeyArn || !point.CompletionDate ||
      !Number.isFinite(new Date(point.CompletionDate).getTime()) || now - new Date(point.CompletionDate).getTime() > c.maxRecoveryAgeSeconds * 1000 || new Date(point.CompletionDate).getTime() > now) throw new Error("Recovery point is not exact, complete, fresh and encrypted.");
  const network = await aws.network(c);
  if (network.subnetGroup?.VpcId !== c.targetVpcId || network.subnetGroup.SubnetGroupStatus !== "Complete" || !network.subnets?.length || network.subnets.length < 2 ||
      new Set(network.subnets.map((s) => s.AvailabilityZone)).size < 2 || network.subnets.some((s) => s.VpcId !== c.targetVpcId || s.MapPublicIpOnLaunch !== false || s.State !== "available") ||
      canonical(network.subnets.map((s) => s.SubnetId).sort()) !== canonical(network.subnetGroup.Subnets.map((s) => s.SubnetIdentifier).sort()) ||
      !network.securityGroups || canonical(network.securityGroups.map((s) => s.GroupId).sort()) !== canonical([...c.targetSecurityGroupIds].sort()) ||
      network.securityGroups.some((s) => s.VpcId !== c.targetVpcId || s.IpPermissions?.length !== 0 || s.IpPermissionsEgress?.length !== 0)) throw new Error("Restore requires isolated private subnets and deny-all security groups.");
  const existing = await aws.cluster(c);
  if (requireAbsent && existing) throw new Error("Target cluster already exists; no overwrite is permitted.");
  for (const bucket of c.buckets) if (await aws.bucketRegion(bucket.name, c.account) !== c.recoveryRegion) throw new Error("Recovery artifact bucket is in the wrong region.");
  for (const artifact of plan.manifest.artifacts) {
    const bucket = c.buckets.find((b) => b.name === artifact.bucket);
    const head = await aws.head(artifact, c.account);
    if (head.VersionId !== artifact.versionId || head.ContentLength !== artifact.bytes || head.ServerSideEncryption !== "aws:kms" || head.SSEKMSKeyId !== bucket.kmsKeyArn ||
        head.ObjectLockMode !== "COMPLIANCE" || head.ObjectLockLegalHoldStatus !== artifact.legalHold ||
        !head.ObjectLockRetainUntilDate || !Number.isFinite(new Date(head.ObjectLockRetainUntilDate).getTime()) || new Date(head.ObjectLockRetainUntilDate).getTime() < Date.parse(artifact.retainUntil)) throw new Error("Exact artifact version, KMS, hold or retention differs.");
    if (await aws.objectSha256(artifact, c.account) !== artifact.sha256) throw new Error("Exact recovery artifact bytes differ from the signed inventory.");
  }
  return { plan, point, existing };
}

async function approved(plan, approval, phase, acceptedDigest, aws, now) {
  if (acceptedDigest !== plan.planDigest) throw new Error("Explicit accepted plan digest is required for mutation.");
  const bytes = approvalMessage(plan, approval, phase, now);
  if (!(await aws.verifySignature(plan.config.approvalKeyArn, bytes, Buffer.from(approval.signature, "base64")))) throw new Error("Independent recovery approval is invalid.");
}
export async function startIsolatedRestore(plan, inventorySignature, approval, acceptedDigest, aws, now = Date.now()) {
  const startedAt = Date.now();
  await approved(plan, approval, "START_CLUSTER", acceptedDigest, aws, now);
  await verifyRecovery(plan, inventorySignature, aws, { now });
  const mutationTime = now + Math.max(0, Date.now() - startedAt);
  createPlan(plan.config, plan.manifest, mutationTime);
  approvalMessage(plan, approval, "START_CLUSTER", mutationTime);
  // All checks occur before the only write. AWS Backup idempotency binds retry
  // to this exact plan; a changed plan is a different explicitly approved job.
  const job = await aws.startRestore(restoreRequest(plan));
  if (!/^[A-Za-z0-9-]{1,100}$/.test(job.RestoreJobId ?? "")) throw new Error("Restore submission returned no bounded job id; reconcile by idempotency token, do not change the plan.");
  return { schemaVersion: 1, status: "RESTORE_SUBMITTED", planDigest: plan.planDigest, restoreJobId: job.RestoreJobId, dnsMutation: false };
}
export async function attachIsolatedWriter(plan, inventorySignature, jobId, approval, acceptedDigest, aws, now = Date.now()) {
  const startedAt = Date.now();
  await approved(plan, approval, "ATTACH_WRITER", acceptedDigest, aws, now);
  const { existing } = await verifyRecovery(plan, inventorySignature, aws, { requireAbsent: false, now });
  const job = await verifyJob(plan, jobId, aws);
  verifyCluster(plan, existing);
  if (existing.DBClusterMembers?.length) throw new Error("Restored cluster already has members; use receipt verification, never add another writer automatically.");
  const c = plan.config;
  const mutationTime = now + Math.max(0, Date.now() - startedAt);
  createPlan(plan.config, plan.manifest, mutationTime);
  approvalMessage(plan, approval, "ATTACH_WRITER", mutationTime);
  await aws.attachWriter({ DBInstanceIdentifier: `${c.targetClusterIdentifier}-writer`, DBClusterIdentifier: c.targetClusterIdentifier,
    Engine: "aurora-postgresql", DBInstanceClass: c.targetInstanceClass, PubliclyAccessible: false, AutoMinorVersionUpgrade: true, CopyTagsToSnapshot: true });
  return { schemaVersion: 1, status: "WRITER_SUBMITTED", planDigest: plan.planDigest, restoreJobId: job.RestoreJobId, dnsMutation: false };
}
async function verifyJob(plan, jobId, aws) {
  if (!/^[A-Za-z0-9-]{1,100}$/.test(jobId)) throw new Error("Invalid restore job id.");
  const job = await aws.restoreJob(jobId);
  if (job.RestoreJobId !== jobId || job.Status !== "COMPLETED" || job.RecoveryPointArn !== plan.config.recoveryPointArn ||
      job.IamRoleArn !== plan.config.restoreRoleArn || job.CreatedResourceArn !== targetArn(plan)) throw new Error("Restore job is not complete for this exact approved target.");
  return job;
}
const targetArn = (plan) => `arn:aws:rds:${plan.config.recoveryRegion}:${plan.config.account}:cluster:${plan.config.targetClusterIdentifier}`;
function verifyCluster(plan, cluster) {
  const c = plan.config;
  if (!cluster || cluster.DBClusterArn !== targetArn(plan) || cluster.DBClusterIdentifier !== c.targetClusterIdentifier || cluster.Status !== "available" || cluster.Engine !== "aurora-postgresql" ||
      cluster.StorageEncrypted !== true || cluster.KmsKeyId !== c.backupKeyArn || cluster.DBSubnetGroup !== c.targetSubnetGroup || cluster.HttpEndpointEnabled !== false ||
      canonical(cluster.VpcSecurityGroups?.map((s) => s.VpcSecurityGroupId).sort()) !== canonical([...c.targetSecurityGroupIds].sort())) throw new Error("Restored cluster is not the exact isolated encrypted target.");
}
export async function isolatedReceipt(plan, inventorySignature, jobId, aws, now = Date.now()) {
  const { existing } = await verifyRecovery(plan, inventorySignature, aws, { requireAbsent: false, now });
  await verifyJob(plan, jobId, aws); verifyCluster(plan, existing);
  const instance = await aws.writer(plan.config);
  if (existing.DBClusterMembers?.length !== 1 || existing.DBClusterMembers[0].DBInstanceIdentifier !== `${plan.config.targetClusterIdentifier}-writer` || !existing.DBClusterMembers[0].IsClusterWriter ||
      instance?.DBInstanceStatus !== "available" || instance.DBClusterIdentifier !== plan.config.targetClusterIdentifier || instance.PubliclyAccessible !== false || instance.DBInstanceClass !== plan.config.targetInstanceClass || instance.StorageEncrypted !== true || instance.KmsKeyId !== plan.config.backupKeyArn) throw new Error("Exact isolated writer is not ready.");
  const receipt = { schemaVersion: 1, status: "ISOLATED_INFRASTRUCTURE_RESTORED", planDigest: plan.planDigest, restoreJobId: jobId, targetClusterArn: targetArn(plan),
    verifiedAt: new Date(now).toISOString(), verifiedArtifactCount: plan.manifest.artifacts.length, dnsMutation: false,
    cutoverAuthorized: false, remainingGates: ["Database schema/tenant/session reconciliation", "Evidence and audit application reconciliation", "Independent application acceptance", "Separately authorized cutover"] };
  return { ...receipt, receiptSha256: hash(`scopeproof-isolated-restore-receipt-v1\n${canonical(receipt)}`) };
}
