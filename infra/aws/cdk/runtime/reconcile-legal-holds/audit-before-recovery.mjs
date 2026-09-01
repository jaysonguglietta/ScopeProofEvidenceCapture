/**
 * Security boundary for post-S3 legal-hold finalization. Recovery publication
 * is unreachable until the authoritative signed audit receipt is durable.
 */
export async function commitAuditBeforeRecovery(input) {
  if (typeof input?.commitAudit !== "function" || typeof input?.publishRecovery !== "function") {
    throw new Error("Legal-hold audit publication boundary is invalid.");
  }
  const committedAudit = await input.commitAudit();
  if (!committedAudit?.receipt || typeof committedAudit.eventHash !== "string") {
    throw new Error("Committed legal-hold audit receipt is invalid.");
  }
  await input.publishRecovery(committedAudit);
  return committedAudit;
}
