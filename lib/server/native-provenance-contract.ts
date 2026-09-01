// Shared by native artifact storage and the reconciliation worker. The sparse
// queue due time must use exactly the same grace authority as the scheduler.
export const NATIVE_ORPHAN_GRACE_MS = 10 * 60_000;
