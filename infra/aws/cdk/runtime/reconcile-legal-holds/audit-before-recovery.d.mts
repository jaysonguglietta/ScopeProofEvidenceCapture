export function commitAuditBeforeRecovery<T extends Readonly<{ eventHash: string; receipt: object }>>(input: Readonly<{
  commitAudit(): Promise<T>;
  publishRecovery(committed: T): Promise<unknown>;
}>): Promise<T>;
