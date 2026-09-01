export interface CommittedPromotionReceiptSnapshot {
  readonly evidenceRevision: number;
  readonly facts: Readonly<Record<string, unknown>>;
  readonly idempotencyDigest: string;
  readonly outcome: "applied" | "already_applied";
  readonly receiptDigest: string;
  readonly receiptId: string;
  readonly signature: Uint8Array;
  readonly signingKeyArn: string;
  readonly signedAt: string;
  readonly uploadRevision: number;
}

export interface PromotionReceiptVerificationInput {
  readonly KeyId: string;
  readonly Message: Uint8Array;
  readonly MessageType: "DIGEST";
  readonly Signature: Uint8Array;
  readonly SigningAlgorithm: "RSASSA_PSS_SHA_256";
}

export function parseCommittedPromotionReceipt(
  formattedRecords: string,
  expected: Readonly<Record<string, unknown>>,
): CommittedPromotionReceiptSnapshot | undefined;

export function verifyCommittedPromotionReceipt(
  snapshot: CommittedPromotionReceiptSnapshot,
  verify: (input: PromotionReceiptVerificationInput) => Promise<{
    readonly KeyId?: string;
    readonly SigningAlgorithm?: string;
    readonly SignatureValid?: boolean;
  }>,
): Promise<void>;

export interface DynamoPromotionReceiptAttribute {
  readonly S?: string;
  readonly N?: string;
}

export function buildAuthoritativePromotionReceiptItem(input: Readonly<{
  tenantId: string;
  receiptHash: string;
  publishedAt: string;
  snapshot: CommittedPromotionReceiptSnapshot;
}>): Readonly<Record<string, DynamoPromotionReceiptAttribute>>;

export function parseAuthoritativePromotionReceiptItem(
  item: Readonly<Record<string, DynamoPromotionReceiptAttribute>>,
  expected: Readonly<{
    tenantId: string;
    receiptHash: string;
    signingKeyArn: string;
    verificationTime: string;
  }>,
): Readonly<{
  publishedAt: string;
  receipt: Readonly<Record<string, unknown>>;
  snapshot: CommittedPromotionReceiptSnapshot;
}>;

export function stableJson(value: unknown): string;
export function digestHex(value: string | Uint8Array): string;
