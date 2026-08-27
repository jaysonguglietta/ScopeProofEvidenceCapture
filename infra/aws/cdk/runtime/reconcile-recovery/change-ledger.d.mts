export interface DynamoAttribute {
  readonly S?: string;
  readonly N?: string;
}

export interface ExactVersionLegalHoldRecoveryOperation {
  readonly schemaVersion: 2;
  readonly operationId: string;
  readonly holdId: string;
  readonly tenantId: string;
  readonly controlId: string;
  readonly evidenceId: string;
  readonly bucket: string;
  readonly key: string;
  readonly versionId: string;
  readonly status: "ON" | "OFF";
  readonly kind: "LEGAL" | "AUDIT" | "SECURITY_INCIDENT";
  readonly reason: string;
  readonly requestedBy: string;
  readonly expectedHoldRevision: number;
  readonly changedAt: string;
  readonly canonicalRequest: string;
  readonly requestDigest: string;
}

export interface RecoveryLedgerAwsClient {
  send(command: unknown): Promise<unknown>;
}

export interface RecoveryLedgerCommandConstructor {
  new(input: never): unknown;
}

export interface LegalHoldRecoveryPublishInput {
  readonly client: RecoveryLedgerAwsClient;
  readonly GetItemCommand: RecoveryLedgerCommandConstructor;
  readonly TransactWriteItemsCommand: RecoveryLedgerCommandConstructor;
  readonly tableName: string;
  readonly tenantId: string;
  readonly operation: ExactVersionLegalHoldRecoveryOperation;
  readonly appliedAt: string;
  readonly now: Date;
  readonly audit: Readonly<{
    readonly canonicalPayload: string;
    readonly eventHash: string;
    readonly keyArn: string;
    readonly payloadSha256: string;
    readonly signature: string;
    readonly signingAlgorithm: "RSASSA_PSS_SHA_256";
  }>;
}

export function recoveryPartitionKey(tenantId: string): string;
export function recoveryChangeBounds(afterIso: string, cutoffIso: string): Readonly<{
  after: string;
  cutoff: string;
}>;
export function legalHoldRecoveryCurrentKey(input: Readonly<{
  tenantId: string;
  bucket: string;
  key: string;
  versionId: string;
}>): string;
export function buildPromotionRecoveryChangeItem(input: Readonly<{
  tenantId: string;
  receiptHash: string;
  publishedAt: string;
  facts: Readonly<Record<string, unknown>>;
}>): Readonly<Record<string, DynamoAttribute>>;
export function parseRecoveryChangeItem(
  item: Readonly<Record<string, DynamoAttribute>>,
  expected: Readonly<{ tenantId: string; sourceBucket: string }>,
): Readonly<Record<string, string>>;
export function parseLegalHoldRecoveryCurrentItem(
  item: Readonly<Record<string, DynamoAttribute>>,
  expected: Readonly<{ tenantId: string; sourceBucket: string; key: string; versionId: string }>,
): Readonly<Record<string, string>>;
export function publishLegalHoldRecoveryChange(input: LegalHoldRecoveryPublishInput): Promise<Readonly<{
  changeKey: string;
  publishedAt: string;
}>>;
