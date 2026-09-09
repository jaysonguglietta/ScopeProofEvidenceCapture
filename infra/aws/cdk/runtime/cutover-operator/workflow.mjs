import { canonical, createCutoverPlan, cutoverApprovalMessage, cutoverRequest } from "./contract.mjs";
import { hash, exactOperatorIdentity } from "../restore-operator/contract.mjs";

export async function verifyCutover(plan, acceptanceSignature, aws, now = Date.now()) {
  if (canonical(createCutoverPlan(plan.config, plan.restoreReceipt, plan.acceptance, now)) !== canonical(plan)) throw new Error("Cutover plan changed after acceptance.");
  if (!/^[A-Za-z0-9+/]{40,2048}={0,2}$/.test(acceptanceSignature) || !await aws.verifySignature(plan.config.acceptanceKeyArn,
    Buffer.from(`scopeproof-cutover-acceptance-v1\n${canonical(plan.acceptance)}`), Buffer.from(acceptanceSignature, "base64"))) throw new Error("Independent application acceptance signature is invalid.");
  const who = await aws.identity();
  if (!exactOperatorIdentity(who, plan.config.account, plan.config.operatorRoleArn)) throw new Error("Use the exact cutover operator role.");
  const zone = await aws.zone(plan.config.hostedZoneId);
  if (zone.Id?.replace(/^\/hostedzone\//, "") !== plan.config.hostedZoneId || zone.Name !== plan.config.zoneName || zone.Config?.PrivateZone !== false) throw new Error("Authoritative zone differs from the approved mapping.");
  for (const m of plan.config.mappings) if (canonical(await aws.record(plan.config.hostedZoneId, m.before)) !== canonical(m.before)) throw new Error("Current DNS differs from the reviewed preimage; refresh acceptance, never overwrite drift.");
  return { status: "VERIFIED_CUTOVER_PLAN_ONLY", planDigest: plan.planDigest, dnsMutation: false };
}
export async function executeCutover(plan, acceptanceSignature, approval, acceptedDigest, aws, now = Date.now()) {
  const startedAt = Date.now();
  if (acceptedDigest !== plan.planDigest) throw new Error("Explicit accepted cutover plan digest is required.");
  const message = cutoverApprovalMessage(plan, approval, now);
  if (!await aws.verifySignature(plan.config.approvalKeyArn, message, Buffer.from(approval.signature, "base64"))) throw new Error("Independent DNS cutover approval is invalid.");
  await verifyCutover(plan, acceptanceSignature, aws, now);
  const mutationTime = now + Math.max(0, Date.now() - startedAt);
  createCutoverPlan(plan.config, plan.restoreReceipt, plan.acceptance, mutationTime);
  cutoverApprovalMessage(plan, approval, mutationTime);
  // DELETE exact preimage + CREATE target is a single transactional batch. It
  // also fails if DNS changes after preflight: no blind UPSERT race.
  const info = await aws.change(cutoverRequest(plan));
  if (!/^\/change\/[A-Z0-9]{1,64}$/.test(info.Id ?? "") || !["PENDING", "INSYNC"].includes(info.Status)) throw new Error("Cutover submission outcome is uncertain; inspect exact DNS/change state without resubmitting or rolling back.");
  return { schemaVersion: 1, status: "CUTOVER_SUBMITTED", planDigest: plan.planDigest, changeId: info.Id, dnsMutation: true, applicationHealthVerified: false };
}
export async function cutoverReceipt(plan, submitted, aws) {
  if (canonical(createCutoverPlan(plan.config, plan.restoreReceipt, plan.acceptance, Date.parse(plan.acceptance.acceptedAt))) !== canonical(plan)) throw new Error("Reviewed cutover plan changed.");
  if (submitted.planDigest !== plan.planDigest || !/^\/change\/[A-Z0-9]{1,64}$/.test(submitted.changeId ?? "")) throw new Error("Cutover submission receipt differs.");
  const info = await aws.changeStatus(submitted.changeId);
  if (info.Id !== submitted.changeId || info.Status !== "INSYNC" || info.Comment !== `Scopeproof accepted cutover ${plan.planDigest}`) throw new Error("Exact cutover change has not reached INSYNC.");
  for (const m of plan.config.mappings) if (canonical(await aws.record(plan.config.hostedZoneId, m.after)) !== canonical(m.after)) throw new Error("DNS differs after cutover.");
  const receipt = { schemaVersion: 1, status: "DNS_INSYNC", planDigest: plan.planDigest, changeId: submitted.changeId, recordsVerified: plan.config.mappings.length, dnsMutation: true, applicationHealthVerified: false };
  return { ...receipt, receiptSha256: hash(`scopeproof-cutover-receipt-v1\n${canonical(receipt)}`) };
}
