import assert from "node:assert/strict";
import test from "node:test";

import {
  asSha256,
  TenantSecurityError,
} from "../lib/aws-runtime/contracts.ts";
import {
  UploadIntentIssuer,
  checksumHeaderValue,
  generateUploadIdempotencyKey,
  type ConditionalUploadIntentStore,
  type ControlledUploadIntent,
  type ExactPresignedPutObject,
  type ExactPutObjectPresignInput,
  type ExactPutObjectPresigner,
} from "../lib/aws-runtime/evidence/index.ts";

const TENANT = `ten_${"a".repeat(32)}`;
const USER = `usr_${"b".repeat(32)}`;
const EVIDENCE = `evd_${"c".repeat(32)}`;
const SHA256 = "d".repeat(64);
const KMS_ARN = "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const NOW = new Date("2026-08-27T16:00:00.000Z");
const IDEMPOTENCY_KEY = Buffer.alloc(32, 7).toString("base64url");
const IDEMPOTENCY_SECRET = new Uint8Array(32).fill(19);

function hasCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof TenantSecurityError);
    assert.equal(error.code, code);
    return true;
  };
}

class RecordingStore implements ConditionalUploadIntentStore {
  readonly records: ControlledUploadIntent[] = [];
  readonly recoveryAttempts: ControlledUploadIntent[] = [];
  readonly saved = new Map<string, ControlledUploadIntent>();

  async recoverExact(intent: ControlledUploadIntent) {
    this.recoveryAttempts.push(intent);
    const prior = this.saved.get(intent.id);
    return prior ? { outcome: "existing" as const, intent: prior } : undefined;
  }

  async reserve(intent: ControlledUploadIntent) {
    this.records.push(intent);
    const prior = this.saved.get(intent.id);
    if (prior) return { outcome: "existing" as const, intent: prior };
    this.saved.set(intent.id, intent);
    return { outcome: "created" as const, intent };
  }
}

class RecordingPresigner implements ExactPutObjectPresigner {
  readonly inputs: ExactPutObjectPresignInput[] = [];
  mutate?: (value: ExactPresignedPutObject) => ExactPresignedPutObject;

  async presignPutObject(input: ExactPutObjectPresignInput): Promise<ExactPresignedPutObject> {
    this.inputs.push(input);
    const url = new URL(`https://scopeproof-quarantine.s3.us-east-1.amazonaws.com/${input.key}`);
    url.searchParams.set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
    url.searchParams.set("X-Amz-Credential", "ASIAEXAMPLE12345678/20260827/us-east-1/s3/aws4_request");
    url.searchParams.set("X-Amz-Date", input.signingAt.replace(/[-:]|\.\d{3}/g, ""));
    url.searchParams.set("X-Amz-Expires", String(input.expiresInSeconds));
    url.searchParams.set("X-Amz-Security-Token", "temporary-session-token");
    url.searchParams.set("X-Amz-Signature", "a".repeat(64));
    url.searchParams.set("X-Amz-SignedHeaders", ["host", ...Object.keys(input.headers)].sort().join(";"));
    const value: ExactPresignedPutObject = {
      method: "PUT",
      url: url.toString(),
      bucket: input.bucket,
      key: input.key,
      expiresAt: input.expiresAt,
      requiredHeaders: input.headers,
    };
    return this.mutate?.(value) ?? value;
  }
}

function issuer(overrides: {
  store?: ConditionalUploadIntentStore;
  presigner?: ExactPutObjectPresigner;
  clock?: () => Date;
  idempotencySecret?: Uint8Array;
  previousIdempotencySecrets?: readonly Uint8Array[];
} = {}): UploadIntentIssuer {
  return new UploadIntentIssuer({
    store: overrides.store ?? new RecordingStore(),
    presigner: overrides.presigner ?? new RecordingPresigner(),
    idempotencySecret: overrides.idempotencySecret ?? IDEMPOTENCY_SECRET,
    previousIdempotencySecrets: overrides.previousIdempotencySecrets,
    clock: overrides.clock ?? (() => NOW),
    configuration: {
      quarantineBucket: "scopeproof-quarantine",
      quarantineKmsKeyArn: KMS_ARN,
    },
  });
}

function request(overrides: Record<string, unknown> = {}) {
  return {
    idempotencyKey: IDEMPOTENCY_KEY,
    tenantId: TENANT,
    requestedBy: USER,
    controlId: "PCI-DSS-10.2.1",
    evidenceId: EVIDENCE,
    expectedSha256: SHA256,
    expectedSize: 1_024,
    contentType: "image/png",
    requiredRetentionUntil: new Date("2027-08-27T16:05:00.000Z"),
    ...overrides,
  };
}

test("issuer reserves a one-time intent and signs every security-relevant upload field", async () => {
  const store = new RecordingStore();
  const presigner = new RecordingPresigner();
  const result = await issuer({ store, presigner }).issue(request());

  assert.match(result.intent.id, /^upl_[a-f0-9]{32}$/);
  assert.match(result.nonce, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(result.intent.quarantineKey, `tenants/${TENANT}/controls/PCI-DSS-10.2.1/quarantine/${result.intent.id}.upload`);
  assert.equal(result.intent.finalKey, `tenants/${TENANT}/controls/PCI-DSS-10.2.1/evidence/${EVIDENCE}.png`);
  assert.equal(store.records.length, 1);
  assert.equal(JSON.stringify(store.records[0]).includes(result.nonce), false, "raw nonce must never be persisted");
  assert.equal(JSON.stringify(store.records[0]).includes(IDEMPOTENCY_KEY), false, "raw idempotency key must never be persisted");
  assert.equal(store.records[0].nonceDigest.length, 64);
  assert.equal(store.records[0].idempotencyDigest.length, 64);
  assert.equal(store.records[0].requestFingerprint.length, 64);
  assert.deepEqual(presigner.inputs[0].headers, {
    "content-length": "1024",
    "content-type": "image/png",
    "x-amz-checksum-sha256": checksumHeaderValue(asSha256(SHA256)),
    "x-amz-meta-control-id": "PCI-DSS-10.2.1",
    "x-amz-meta-evidence-id": EVIDENCE,
    "x-amz-meta-expected-sha256": SHA256,
    "x-amz-meta-tenant-id": TENANT,
    "x-amz-meta-upload-intent-id": result.intent.id,
    "x-amz-server-side-encryption": "aws:kms",
    "x-amz-server-side-encryption-aws-kms-key-id": KMS_ARN,
    "x-amz-server-side-encryption-context": Buffer.from(JSON.stringify({
      scopeproofPurpose: "quarantine",
      scopeproofTenantId: TENANT,
    })).toString("base64"),
  });
  assert.equal(result.upload.expiresAt, "2026-08-27T16:05:00.000Z");
});

test("client helper emits a canonical 256-bit idempotency key", () => {
  const key = generateUploadIdempotencyKey({ randomBytes: (length) => new Uint8Array(length).fill(23) });
  assert.equal(key, Buffer.alloc(32, 23).toString("base64url"));
  assert.match(key, /^[A-Za-z0-9_-]{43}$/);
  assert.throws(() => generateUploadIdempotencyKey({ randomBytes: () => new Uint8Array(31) }), /invalid idempotency key/);
});

test("issuer rejects traversal, unsupported MIME, invalid checksum, size, and TTL before persistence", async () => {
  const store = new RecordingStore();
  const service = issuer({ store });
  await assert.rejects(service.issue(request({ controlId: "../other-customer" })), hasCode("INVALID_OBJECT_KEY"));
  await assert.rejects(service.issue(request({ contentType: "text/html" })), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(service.issue(request({ expectedSha256: "A".repeat(64) })), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(service.issue(request({ expectedSize: 0 })), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(service.issue(request({ ttlMs: 29_000 })), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(service.issue(request({ ttlMs: 600_001 })), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(service.issue(request({ idempotencyKey: "predictable" })), hasCode("INVALID_UPLOAD_INTENT"));
  await assert.rejects(service.issue(request({ idempotencyKey: `${IDEMPOTENCY_KEY}=` })), hasCode("INVALID_UPLOAD_INTENT"));
  assert.equal(store.records.length, 0);
});

test("issuer fails closed when the presigner weakens or changes the exact contract", async () => {
  const store = new RecordingStore();
  const presigner = new RecordingPresigner();
  presigner.mutate = (value) => ({
    ...value,
    requiredHeaders: Object.fromEntries(Object.entries(value.requiredHeaders).filter(([name]) => name !== "x-amz-checksum-sha256")),
  });
  await assert.rejects(issuer({ store, presigner }).issue(request()), hasCode("INVALID_UPLOAD_INTENT"));
  assert.equal(store.records.length, 1, "a failed presign leaves only a recoverable, unusable reservation");

  presigner.mutate = (value) => {
    const url = new URL(value.url);
    url.searchParams.set(
      "X-Amz-SignedHeaders",
      (url.searchParams.get("X-Amz-SignedHeaders") ?? "").split(";").filter((name) => name !== "content-length").join(";"),
    );
    return { ...value, url: url.toString() };
  };
  await assert.rejects(issuer({ store, presigner }).issue(request()), hasCode("INVALID_UPLOAD_INTENT"));
  assert.equal(store.records.length, 2, "unsigned size constraints must not be accepted or returned");

  presigner.mutate = (value) => ({ ...value, url: "http://scopeproof-quarantine.example/upload" });
  await assert.rejects(issuer({ store, presigner }).issue(request()), hasCode("INVALID_UPLOAD_INTENT"));
  assert.equal(store.records.length, 3);

  presigner.mutate = (value) => ({ ...value, url: `https://attacker.example/${value.key}?X-Amz-Signature=stolen` });
  await assert.rejects(issuer({ store, presigner }).issue(request()), hasCode("INVALID_UPLOAD_INTENT"));
  assert.equal(store.records.length, 4);
});

test("same-key retries reconstruct the exact intent while changed facts and expiry fail closed", async () => {
  const store = new RecordingStore();
  const presigner = new RecordingPresigner();
  let current = NOW;
  const service = issuer({ store, presigner, clock: () => current });
  const first = await service.issue(request());
  current = new Date("2026-08-27T16:02:00.000Z");
  const retry = await service.issue(request());
  assert.equal(store.records.length, 2);
  assert.deepEqual(retry.intent, first.intent);
  assert.equal(retry.nonce, first.nonce);
  assert.equal(retry.intent.issuedAt, "2026-08-27T16:00:00.000Z");
  assert.equal(retry.intent.expiresAt, "2026-08-27T16:05:00.000Z");
  assert.equal(presigner.inputs[1].signingAt, "2026-08-27T16:02:00.000Z");
  assert.equal(presigner.inputs[1].expiresInSeconds, 180);

  await assert.rejects(service.issue(request({ expectedSize: 2_048 })), hasCode("UPLOAD_MISMATCH"));
  current = new Date("2026-08-27T16:05:00.000Z");
  await assert.rejects(service.issue(request()), hasCode("UPLOAD_INTENT_EXPIRED"));
});

test("rotation strongly recovers an old-key retry without creating a current-key intent", async () => {
  const oldSecret = new Uint8Array(32).fill(31);
  const currentSecret = new Uint8Array(32).fill(47);
  const store = new RecordingStore();
  let current = NOW;
  const first = await issuer({ store, clock: () => current, idempotencySecret: oldSecret }).issue(request());

  current = new Date("2026-08-27T16:01:00.000Z");
  const recovered = await issuer({
    store,
    clock: () => current,
    idempotencySecret: currentSecret,
    previousIdempotencySecrets: [oldSecret],
  }).issue(request());

  assert.deepEqual(recovered.intent, first.intent);
  assert.equal(recovered.nonce, first.nonce);
  assert.equal(store.records.length, 1, "the current key must not reserve after previous-key recovery");
  assert.equal(store.recoveryAttempts.length, 1);
  assert.equal(store.recoveryAttempts[0].id, first.intent.id);
});

test("a previous key can only recover and never creates a new reservation", async () => {
  const oldSecret = new Uint8Array(32).fill(31);
  const currentSecret = new Uint8Array(32).fill(47);
  const store = new RecordingStore();
  const rotated = await issuer({
    store,
    idempotencySecret: currentSecret,
    previousIdempotencySecrets: [oldSecret],
  }).issue(request());
  const currentOnly = await issuer({
    store: new RecordingStore(),
    idempotencySecret: currentSecret,
  }).issue(request());

  assert.equal(store.recoveryAttempts.length, 1);
  assert.equal(store.records.length, 1);
  assert.equal(rotated.intent.id, currentOnly.intent.id);
  assert.notEqual(store.recoveryAttempts[0].id, rotated.intent.id);
});

test("rotation fails closed on changed facts instead of falling through to the current key", async () => {
  const oldSecret = new Uint8Array(32).fill(31);
  const currentSecret = new Uint8Array(32).fill(47);
  const store = new RecordingStore();
  await issuer({ store, idempotencySecret: oldSecret }).issue(request());

  await assert.rejects(issuer({
    store,
    idempotencySecret: currentSecret,
    previousIdempotencySecrets: [oldSecret],
  }).issue(request({ expectedSize: 2_048 })), hasCode("UPLOAD_MISMATCH"));
  assert.equal(store.records.length, 1);
  assert.equal(store.recoveryAttempts.length, 1);
});

test("previous idempotency keys are deduplicated, current-key duplicates ignored, and distinct history bounded", async () => {
  const oldSecret = new Uint8Array(32).fill(31);
  const currentSecret = new Uint8Array(32).fill(47);
  const store = new RecordingStore();
  await issuer({
    store,
    idempotencySecret: currentSecret,
    previousIdempotencySecrets: [oldSecret, oldSecret.slice(), currentSecret, oldSecret.slice()],
  }).issue(request());
  assert.equal(store.recoveryAttempts.length, 1);
  assert.equal(store.records.length, 1);

  assert.throws(() => issuer({
    idempotencySecret: currentSecret,
    previousIdempotencySecrets: [oldSecret, new Uint8Array(32).fill(63)],
  }), /At most 1 distinct previous/);
  assert.throws(() => issuer({
    idempotencySecret: currentSecret,
    previousIdempotencySecrets: Array.from({ length: 9 }, () => oldSecret),
  }), /At most 8 previous/);
});

test("presigner and persistence failures never return a usable upload capability", async () => {
  const presigner: ExactPutObjectPresigner = {
    async presignPutObject(): Promise<ExactPresignedPutObject> {
      throw new Error("kms unavailable");
    },
  };
  const store = new RecordingStore();
  await assert.rejects(issuer({ store, presigner }).issue(request()), /kms unavailable/);
  assert.equal(store.records.length, 1);

  const failingStore: ConditionalUploadIntentStore = {
    async recoverExact() { return undefined; },
    async reserve() {
      throw new Error("transaction rolled back");
    },
  };
  await assert.rejects(issuer({ store: failingStore }).issue(request()), /transaction rolled back/);
});
