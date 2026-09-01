export type UploadIdempotencySecretStage = "AWSCURRENT" | "AWSPREVIOUS";

export interface UploadIdempotencySecretVersionReader {
  getSecretValue(stage: UploadIdempotencySecretStage): Promise<Readonly<{ SecretString?: string }>>;
}

export interface RotatingUploadIdempotencySecrets {
  readonly current: Uint8Array<ArrayBuffer>;
  readonly previous: readonly Uint8Array<ArrayBuffer>[];
}

/**
 * Loads the active HMAC key and the single Secrets Manager rollback stage.
 * AWSCURRENT is resolved first. Only AWS's precise "AWSPREVIOUS staging label
 * is absent" response is optional; authorization, transport, throttling,
 * deletion, and malformed-response failures always propagate.
 */
export async function loadRotatingUploadIdempotencySecrets(
  reader: UploadIdempotencySecretVersionReader,
): Promise<RotatingUploadIdempotencySecrets> {
  if (!reader || typeof reader.getSecretValue !== "function") {
    throw new Error("Upload idempotency secret reader is required.");
  }
  const current = parseUploadIdempotencySecret(
    (await reader.getSecretValue("AWSCURRENT")).SecretString,
  );
  let previous: Uint8Array<ArrayBuffer> | undefined;
  try {
    previous = parseUploadIdempotencySecret(
      (await reader.getSecretValue("AWSPREVIOUS")).SecretString,
    );
  } catch (error) {
    if (!isMissingPreviousVersion(error)) {
      current.fill(0);
      throw error;
    }
  }
  return Object.freeze({
    current,
    previous: Object.freeze(previous ? [previous] : []),
  });
}

export function parseUploadIdempotencySecret(secretString: string | undefined): Uint8Array<ArrayBuffer> {
  if (!secretString || secretString.length > 1_024) throw new Error("Upload idempotency secret is invalid.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(secretString);
  } catch {
    throw new Error("Upload idempotency secret is invalid.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Upload idempotency secret is invalid.");
  }
  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (
    keys.length !== 2 ||
    keys[0] !== "hmacKey" ||
    keys[1] !== "schemaVersion" ||
    record.schemaVersion !== 1 ||
    typeof record.hmacKey !== "string" ||
    !/^[A-Za-z0-9]{64}$/.test(record.hmacKey)
  ) {
    throw new Error("Upload idempotency secret is invalid.");
  }
  return new TextEncoder().encode(record.hmacKey) as Uint8Array<ArrayBuffer>;
}

function isMissingPreviousVersion(error: unknown): boolean {
  if (!error || typeof error !== "object") return false;
  const record = error as Record<string, unknown>;
  const metadata = record.$metadata;
  if (!metadata || typeof metadata !== "object") return false;
  const message = typeof record.message === "string" ? record.message : "";
  return record.name === "ResourceNotFoundException" &&
    (metadata as Record<string, unknown>).httpStatusCode === 400 &&
    /\bAWSPREVIOUS\b/.test(message) &&
    /(?:staging label|version stage|secret version)/i.test(message);
}
