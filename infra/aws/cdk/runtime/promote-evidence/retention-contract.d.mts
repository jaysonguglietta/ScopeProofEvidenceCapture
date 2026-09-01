export interface PromotionRetentionInput {
  readonly requiredRetentionUntil: string;
  readonly uploadedAt: string;
  readonly retentionDays: number;
}

export interface PromotionRetentionResult {
  readonly retainUntil: Date;
  readonly requiredRetentionUntil: string;
  readonly uploadedAt: string;
  readonly uploadRetentionUntil: string;
}

export function derivePromotionRetention(input: PromotionRetentionInput): PromotionRetentionResult;
