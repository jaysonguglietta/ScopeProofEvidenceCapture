export interface PromotionLease {
  readonly attemptId: string;
  readonly fence: number;
  readonly leaseExpiresAt: string;
  readonly now: string;
}

export const promotionLeaseDurationMilliseconds: number;

export function derivePromotionLease(input: Readonly<{
  tenantId: string;
  intentId: string;
  leaseId: string;
  sourceVersionId: string;
  currentFence?: number;
  now: string;
}>): PromotionLease;

export function assertActivePromotionLease(
  snapshot: Readonly<{ leaseId: string; attemptId: string; fence: number; leaseExpiresAt: string }>,
  expected: Readonly<{ leaseId: string; attemptId: string; fence: number }>,
  now: string,
): Readonly<{ leaseId: string; attemptId: string; fence: number; leaseExpiresAt: string }>;

export function buildPromotionCopyAttemptItem(input: Readonly<Record<string, unknown>>): Readonly<Record<string, Readonly<{ S?: string; N?: string }>>>;
export function promotionCopyAttemptSortKey(receiptHash: string, fence: number): string;
export function promotionCopyMetadata(input: Readonly<{ attemptId: string; fence: number }>): Readonly<Record<string, string>>;

export function createOrAdoptImmutableDestination<TCreate, TDestination>(input: Readonly<{
  createDestination: () => Promise<TCreate>;
  isConditionalConflict: (error: unknown) => boolean;
  readWinner: () => Promise<TDestination | undefined>;
}>): Promise<Readonly<
  | { created: true; destination: undefined; result: TCreate }
  | { created: false; destination: TDestination; result: undefined }
>>;
