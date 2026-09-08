import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { pathToFileURL } from "node:url";
import { BackupClient, DescribeRecoveryPointCommand, StartRestoreJobCommand, DescribeRestoreJobCommand } from "@aws-sdk/client-backup";
import { S3Client, GetBucketLocationCommand, HeadObjectCommand, GetObjectCommand } from "@aws-sdk/client-s3";
import { KMSClient, VerifyCommand } from "@aws-sdk/client-kms";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { createPlan, validateConfig } from "./contract.mjs";
import { verifyRecovery, startIsolatedRestore, attachIsolatedWriter, isolatedReceipt } from "./workflow.mjs";

const run = promisify(execFile);
export function awsAdapter(configInput) {
  const c = validateConfig(configInput), region = c.recoveryRegion;
  const backup = new BackupClient({ region, maxAttempts: 1 }), s3 = new S3Client({ region }), kms = new KMSClient({ region }), sts = new STSClient({ region });
  // Existing pinned SDK lacks RDS/EC2 clients. Use installed AWS CLI v2 with
  // fixed service/operation allowlists, JSON stdin-free args and no shell.
  const cli = async (service, operation, input) => {
    if (!new Set(["rds/describe-db-subnet-groups", "rds/describe-db-clusters", "rds/describe-db-instances", "rds/create-db-instance", "ec2/describe-subnets", "ec2/describe-security-groups"]).has(`${service}/${operation}`)) throw new Error("Unapproved recovery CLI operation.");
    const { stdout } = await run("aws", [service, operation, "--region", region, "--output", "json", "--no-cli-pager", "--cli-input-json", JSON.stringify(input)], { timeout: 60000, maxBuffer: 2000000, env: { ...process.env, AWS_PAGER: "", AWS_CLI_AUTO_PROMPT: "off", AWS_MAX_ATTEMPTS: "1" } });
    return JSON.parse(stdout);
  };
  return {
    identity: () => sts.send(new GetCallerIdentityCommand({})),
    verifySignature: async (key, message, signature) => (await kms.send(new VerifyCommand({ KeyId: key, Message: createHash("sha256").update(message).digest(), MessageType: "DIGEST", Signature: signature, SigningAlgorithm: "ECDSA_SHA_256" }))).SignatureValid === true,
    recoveryPoint: () => backup.send(new DescribeRecoveryPointCommand({ BackupVaultName: c.recoveryVaultName, BackupVaultAccountId: c.account, RecoveryPointArn: c.recoveryPointArn })),
    network: async () => {
      const group = (await cli("rds", "describe-db-subnet-groups", { DBSubnetGroupName: c.targetSubnetGroup })).DBSubnetGroups?.[0];
      if (!group?.Subnets?.length || group.Subnets.length > 20) throw new Error("Bounded recovery subnet group is missing.");
      return { subnetGroup: group, subnets: (await cli("ec2", "describe-subnets", { SubnetIds: group.Subnets.map((s) => s.SubnetIdentifier) })).Subnets,
        securityGroups: (await cli("ec2", "describe-security-groups", { GroupIds: c.targetSecurityGroupIds })).SecurityGroups };
    },
    cluster: async () => {
      try { return (await cli("rds", "describe-db-clusters", { DBClusterIdentifier: c.targetClusterIdentifier })).DBClusters?.[0]; }
      catch (error) { if (/\(DBClusterNotFoundFault\)/.test(error.stderr ?? "")) return undefined; throw error; }
    },
    writer: async () => (await cli("rds", "describe-db-instances", { DBInstanceIdentifier: `${c.targetClusterIdentifier}-writer` })).DBInstances?.[0],
    bucketRegion: async (bucket, account) => (await s3.send(new GetBucketLocationCommand({ Bucket: bucket, ExpectedBucketOwner: account }))).LocationConstraint ?? "us-east-1",
    head: (a, account) => s3.send(new HeadObjectCommand({ Bucket: a.bucket, Key: a.key, VersionId: a.versionId, ExpectedBucketOwner: account })),
    objectSha256: async (a, account) => {
      const result = await s3.send(new GetObjectCommand({ Bucket: a.bucket, Key: a.key, VersionId: a.versionId, ExpectedBucketOwner: account }));
      if (result.VersionId !== a.versionId || result.ContentLength !== a.bytes || !result.Body) throw new Error("Exact artifact body is missing.");
      const digest = createHash("sha256"); let bytes = 0;
      try { for await (const chunk of result.Body) { bytes += chunk.length; if (bytes > a.bytes) throw new Error("Artifact exceeds reviewed size."); digest.update(chunk); } }
      finally { result.Body.destroy?.(); }
      if (bytes !== a.bytes) throw new Error("Artifact body length changed.");
      return digest.digest("hex");
    },
    startRestore: (request) => backup.send(new StartRestoreJobCommand(request)),
    restoreJob: (jobId) => backup.send(new DescribeRestoreJobCommand({ RestoreJobId: jobId })),
    attachWriter: (request) => cli("rds", "create-db-instance", request),
  };
}

async function json(path) { if (!path) throw new Error("Required local JSON artifact is missing."); const value = await readFile(path, "utf8"); if (value.length > 15000000) throw new Error("Recovery JSON exceeds bound."); return JSON.parse(value); }
export async function main(args) {
  const [mode, first, second, third, fourth, fifth, ...extra] = args;
  if (extra.length) throw new Error("Unexpected recovery arguments.");
  // The default documented entry point is offline. SDK clients are not even
  // created until an explicit verify/start/attach/receipt mode is selected.
  if (mode === "plan") {
    if (third || fourth || fifth) throw new Error("Usage: plan config.json inventory.json");
    return createPlan(await json(first), await json(second));
  }
  const plan = await json(first), inventory = await json(second);
  if (!inventory || Object.keys(inventory).join() !== "signature") throw new Error("Inventory signature envelope must contain only signature.");
  const aws = awsAdapter(plan.config);
  if (mode === "verify" && !third && !fourth && !fifth) { await verifyRecovery(plan, inventory.signature, aws); return { status: "VERIFIED_PLAN_ONLY", planDigest: plan.planDigest, dnsMutation: false }; }
  if (mode === "start" && !fifth) return startIsolatedRestore(plan, inventory.signature, await json(third), fourth, aws);
  if (mode === "attach") return attachIsolatedWriter(plan, inventory.signature, third, await json(fourth), fifth, aws);
  if (mode === "receipt" && !fourth && !fifth) return isolatedReceipt(plan, inventory.signature, third, aws);
  throw new Error("Usage: plan config inventory | verify plan inventory-signature | start plan inventory-signature approval accepted-digest | attach plan inventory-signature job-id approval accepted-digest | receipt plan inventory-signature job-id");
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.stdout.write(JSON.stringify(await main(process.argv.slice(2)), null, 2) + "\n"); }
  catch { process.stderr.write("Recovery operation failed closed. Reconcile exact plan/job state; no DNS operation exists in this tool.\n"); process.exitCode = 1; }
}
