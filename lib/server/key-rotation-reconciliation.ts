export type ObjectRotationState = Readonly<{
  currentKey: string;
  encryptionKeyId: string;
  pendingKey: string | null;
  previousKey: string | null;
}>;

export type ExpectedObjectRotation = Readonly<{
  nextKey: string;
  nextEncryptionKeyId: string;
}>;

export type ObjectRotationDisposition = "committed" | "still_referenced" | "proven_loser";

export const MAX_ROTATION_ATTEMPT_COUNT = 1_000_000;

export type RotationAttemptState = Readonly<{
  attemptCount: number;
  status: "retrying" | "action_required" | "resolved";
  lastAttemptId: string;
}>;

export type NextRotationFailureState = Readonly<{
  attemptCount: number;
  status: "retrying" | "action_required";
  nextAttemptAt: string;
}>;

export function nextRotationFailureState(
  previous: RotationAttemptState | null,
  attemptedAtMs: number,
  actionRequiredAfter: number,
): NextRotationFailureState {
  const rawCount = previous?.status === "resolved" ? 1 : Number(previous?.attemptCount || 0) + 1;
  const attemptCount = Math.min(Math.max(rawCount, 1), MAX_ROTATION_ATTEMPT_COUNT);
  const delayMinutes = Math.min(24 * 60, 5 * (2 ** Math.min(attemptCount, 9)));
  return {
    attemptCount,
    status: attemptCount >= actionRequiredAfter ? "action_required" : "retrying",
    nextAttemptAt: new Date(attemptedAtMs + delayMinutes * 60_000).toISOString(),
  };
}

/**
 * Classify an object written during copy-switch-delete rotation using a strong,
 * authoritative database read. A key is deletable only when no persisted
 * rotation field references it. Unknown/read-error state is handled by the
 * caller and must never be converted to `proven_loser`.
 */
export function classifyObjectRotation(
  state: ObjectRotationState | null,
  expected: ExpectedObjectRotation,
): ObjectRotationDisposition {
  if (state?.currentKey === expected.nextKey && state.encryptionKeyId === expected.nextEncryptionKeyId) return "committed";
  if (state && [state.currentKey, state.pendingKey, state.previousKey].includes(expected.nextKey)) return "still_referenced";
  return "proven_loser";
}

export function jiraRotationReachedActiveState(
  state: Readonly<{ tokenKeyId: string; tokenVersion: number }> | null,
  activeKeyId: string,
  minimumTokenVersion: number,
): boolean {
  return Boolean(state && state.tokenKeyId === activeKeyId && Number.isSafeInteger(state.tokenVersion) && state.tokenVersion >= minimumTokenVersion);
}
