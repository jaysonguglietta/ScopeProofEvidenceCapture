export type ReviewAction = "approve" | "reject" | "return" | "reopen" | "supersede";

/** UI guidance only; mutation handlers re-check authoritative state at commit. */
export function evidenceReviewPolicy(input: {
  role: string; actorId: string; creatorId: string; status: string; expiresAt: string;
  inScope: boolean; coverage: string; safetyReady: boolean; provenanceReady: boolean;
}, now = Date.now()): { allowedActions: ReviewAction[]; reviewBlockers: string[] } {
  if (!["reviewer", "admin"].includes(input.role)) return { allowedActions: [], reviewBlockers: ["INDEPENDENT_REVIEW_ROLE_REQUIRED"] };
  if (!input.creatorId || input.creatorId === input.actorId) return { allowedActions: [], reviewBlockers: ["INDEPENDENT_REVIEWER_REQUIRED"] };
  const expires = Date.parse(input.expiresAt);
  if (!Number.isFinite(expires) || expires <= now || ["purged", "expired"].includes(input.status)) return { allowedActions: [], reviewBlockers: ["EVIDENCE_EXPIRED"] };
  const blockers = [!input.inScope ? "OUT_OF_SCOPE" : null, input.coverage === "partial" ? "PARTIAL_COVERAGE" : null,
    !input.safetyReady ? "SAFETY_PENDING" : null, !input.provenanceReady ? "PROVENANCE_PENDING" : null].filter((value): value is string => Boolean(value));
  const allowedActions: ReviewAction[] = input.status === "needs_review" ? [...(!blockers.length ? ["approve" as const] : []), "reject", "return"]
    : ["rejected", "returned"].includes(input.status) ? ["reopen"] : input.status === "approved" ? ["supersede"] : [];
  return { allowedActions, reviewBlockers: blockers };
}
