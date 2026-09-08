import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { Route53Client, GetHostedZoneCommand, ListResourceRecordSetsCommand, ChangeResourceRecordSetsCommand, GetChangeCommand } from "@aws-sdk/client-route-53";
import { KMSClient, VerifyCommand } from "@aws-sdk/client-kms";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { createCutoverPlan } from "./contract.mjs";
import { verifyCutover, executeCutover, cutoverReceipt } from "./workflow.mjs";
export function cutoverAwsAdapter(config) {
  const route53 = new Route53Client({ region: "us-east-1", maxAttempts: 1 }), kms = new KMSClient({ region: config.recoveryRegion }), sts = new STSClient({ region: config.recoveryRegion });
  return {
    identity: () => sts.send(new GetCallerIdentityCommand({})),
    verifySignature: async (key, message, signature) => (await kms.send(new VerifyCommand({ KeyId: key, Message: createHash("sha256").update(message).digest(), MessageType: "DIGEST", SigningAlgorithm: "ECDSA_SHA_256", Signature: signature }))).SignatureValid === true,
    zone: async (id) => (await route53.send(new GetHostedZoneCommand({ Id: id }))).HostedZone,
    record: async (id, expected) => (await route53.send(new ListResourceRecordSetsCommand({ HostedZoneId: id, StartRecordName: expected.Name, StartRecordType: expected.Type, MaxItems: 1 }))).ResourceRecordSets?.[0],
    change: async (request) => (await route53.send(new ChangeResourceRecordSetsCommand(request))).ChangeInfo,
    changeStatus: async (id) => (await route53.send(new GetChangeCommand({ Id: id }))).ChangeInfo,
  };
}
async function json(path) { if (!path) throw new Error("Required reviewed JSON artifact is missing."); const raw = await readFile(path, "utf8"); if (raw.length > 250000) throw new Error("Cutover JSON exceeds safety bound."); return JSON.parse(raw); }
export async function main(args) {
  const [mode, first, second, third, fourth, ...extra] = args;
  if (extra.length) throw new Error("Unexpected cutover arguments.");
  if (mode === "plan" && !fourth) return createCutoverPlan(await json(first), await json(second), await json(third));
  if (!["verify", "execute", "receipt"].includes(mode)) throw new Error("Usage: plan mapping restore-receipt acceptance | verify plan acceptance-signature | execute plan acceptance-signature approval accepted-digest | receipt plan submitted-receipt");
  const plan = await json(first), aws = cutoverAwsAdapter(plan.config);
  if (mode === "receipt" && !third && !fourth) return cutoverReceipt(plan, await json(second), aws);
  const envelope = await json(second);
  if (!envelope || Object.keys(envelope).join() !== "signature") throw new Error("Acceptance signature envelope must contain only signature.");
  if (mode === "verify" && !third && !fourth) return verifyCutover(plan, envelope.signature, aws);
  if (mode === "execute") return executeCutover(plan, envelope.signature, await json(third), fourth, aws);
  throw new Error("Invalid cutover command arguments.");
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { process.stdout.write(JSON.stringify(await main(process.argv.slice(2)), null, 2) + "\n"); }
  catch { process.stderr.write("Cutover failed or its outcome is uncertain. Inspect exact DNS and change state; no automatic retry or rollback was attempted.\n"); process.exitCode = 1; }
}
