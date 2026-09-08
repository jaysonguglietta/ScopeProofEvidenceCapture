/** Pure policy shared with tests; no provider exception text enters the ledger. */
export const MAXIMUM_REPAIR_ATTEMPTS = 8;
export const REPAIR_HORIZON_MS = 14 * 24 * 60 * 60 * 1_000;

export function repairFailure(attemptCount: number, now: Date): Readonly<{
  attemptCount: number; status: "RETRY" | "ACTION_REQUIRED"; retryAt: string;
}> {
  if (!Number.isSafeInteger(attemptCount) || attemptCount < 0 || attemptCount > MAXIMUM_REPAIR_ATTEMPTS || !Number.isFinite(now.getTime())) {
    throw new Error("Invalid repair failure state.");
  }
  const next = Math.min(attemptCount + 1, MAXIMUM_REPAIR_ATTEMPTS);
  return Object.freeze({
    attemptCount: next,
    status: next === MAXIMUM_REPAIR_ATTEMPTS ? "ACTION_REQUIRED" : "RETRY",
    retryAt: new Date(now.getTime() + Math.min(3_600_000, 30_000 * 2 ** next)).toISOString(),
  });
}

export function repairDue(input: Readonly<{ status?: string; retryAt?: string }>, now: Date): boolean {
  if (input.status === "ACTION_REQUIRED") return false;
  if (input.retryAt === undefined) return true;
  const retryAt = Date.parse(input.retryAt);
  if (!Number.isFinite(retryAt) || new Date(retryAt).toISOString() !== input.retryAt) throw new Error("Invalid repair retry time.");
  return retryAt <= now.getTime();
}
