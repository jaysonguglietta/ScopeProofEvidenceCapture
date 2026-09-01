import { createHash } from "node:crypto";

export const PROMOTION_RECEIPT_DOMAIN = "scopeproof-promotion-receipt-v1";
export const PROMOTION_RECONCILIATION_DOMAIN = "scopeproof-promotion-reconciliation-v1";
export const PROMOTION_SIGNING_ALGORITHM = "RSASSA_PSS_SHA_256";

const exactFactKeys = [
  "byteSize", "contentType", "controlId", "copyAttemptId", "copyFence", "evidenceBucket", "evidenceId", "evidenceKey",
  "evidenceVersionId", "kmsKeyArn", "objectLockMode", "promotedAt", "providerRequestId",
  "dlpPolicyVersion", "dlpReceiptSha256", "dlpScannedAt", "dlpScannerRequestId",
  "promotionAttemptId", "promotionFence", "quarantineBucket", "quarantineKey", "quarantineVersionId", "retainUntil", "schemaVersion",
  "sha256", "tenantId", "uploadedAt", "uploadIntentId",
].sort();

export function parseCommittedPromotionReceipt(formattedRecords, expected) {
  if (typeof formattedRecords !== "string" || formattedRecords.length > 65_536) {
    throw new Error("The promotion database response is invalid.");
  }
  let rows;
  try { rows = JSON.parse(formattedRecords); } catch { throw new Error("The promotion database response is invalid."); }
  if (!Array.isArray(rows) || rows.length > 1) throw new Error("The promotion database response is invalid.");
  if (rows.length === 0) {
    if (expected.allowMissing === true) return undefined;
    throw new Error("The promotion database response is incomplete.");
  }
  const row = rows[0];
  if (!row || typeof row !== "object" || Array.isArray(row)) throw new Error("The promotion database response is invalid.");

  let facts = row.committed_promotion_facts;
  if (typeof facts === "string") {
    try { facts = JSON.parse(facts); } catch { throw new Error("The committed promotion facts are invalid."); }
  }
  if (!facts || typeof facts !== "object" || Array.isArray(facts)) throw new Error("The committed promotion facts are invalid.");
  const canonicalFacts = stableJson(facts);
  if (
    typeof row.committed_canonical_receipt !== "string" ||
    row.committed_canonical_receipt !== canonicalFacts ||
    Object.keys(facts).sort().join("\0") !== exactFactKeys.join("\0")
  ) {
    throw new Error("The committed promotion receipt is not canonical.");
  }

  const receiptDigest = digestHex(`${PROMOTION_RECEIPT_DOMAIN}\n${canonicalFacts}`);
  const idempotencyDigest = digestHex(`${PROMOTION_RECONCILIATION_DOMAIN}\n${canonicalFacts}`);
  const receiptId = `rcp_${digestHex(`scopeproof-promotion-receipt-id-v1\n${canonicalFacts}`).slice(0, 32)}`;
  const signedAt = canonicalInstant(row.committed_signed_at, "Committed promotion receipt time");
  const promotedAt = canonicalInstant(facts.promotedAt, "Committed promotion time");
  const verificationTime = canonicalInstant(expected.verificationTime, "Promotion verification time");
  const signature = canonicalRsa3072Signature(row.committed_signature);
  if (
    (expected.requireOutcome === true && typeof row.was_created !== "boolean") ||
    row.receipt_id !== receiptId ||
    row.committed_idempotency_digest !== idempotencyDigest ||
    row.committed_receipt_sha256 !== receiptDigest ||
    row.committed_signing_key_arn !== expected.signingKeyArn ||
    row.committed_signing_algorithm !== PROMOTION_SIGNING_ALGORITHM ||
    row.committed_upload_revision !== expected.uploadRevision ||
    row.committed_evidence_revision !== expected.evidenceRevision ||
    Date.parse(signedAt) < Date.parse(promotedAt) ||
    Date.parse(signedAt) > Date.parse(verificationTime) + 5 * 60_000
  ) {
    throw new Error("The promotion database returned conflicting receipt state.");
  }
  if (expected.canonicalFacts !== undefined && canonicalFacts !== expected.canonicalFacts) {
    throw new Error("The promotion database returned conflicting immutable facts.");
  }
  if (expected.invariants !== undefined) assertPromotionInvariants(facts, expected.invariants);
  return Object.freeze({
    evidenceRevision: row.committed_evidence_revision,
    facts: Object.freeze(facts),
    idempotencyDigest,
    outcome: row.was_created === true ? "applied" : "already_applied",
    receiptDigest,
    receiptId,
    signature,
    signingKeyArn: expected.signingKeyArn,
    signedAt,
    uploadRevision: row.committed_upload_revision,
  });
}

export async function verifyCommittedPromotionReceipt(snapshot, verify) {
  const result = await verify({
    KeyId: snapshot.signingKeyArn,
    Message: Buffer.from(snapshot.receiptDigest, "hex"),
    MessageType: "DIGEST",
    Signature: snapshot.signature,
    SigningAlgorithm: PROMOTION_SIGNING_ALGORITHM,
  });
  if (
    result?.KeyId !== snapshot.signingKeyArn ||
    result?.SigningAlgorithm !== PROMOTION_SIGNING_ALGORITHM ||
    result?.SignatureValid !== true
  ) {
    throw new Error("KMS did not verify the committed promotion receipt signature.");
  }
}

const authoritativeRecordKeys = [
  "PK", "SK", "canonicalFacts", "databaseEvidenceRevision", "databaseIdempotencyDigest",
  "databaseReceiptId", "databaseReceiptSha256", "databaseUploadRevision", "kind", "publishedAt",
  "receiptHash", "schemaVersion", "signature", "signedAt", "signingAlgorithm", "signingKeyArn",
  "tenantId",
].sort();

/**
 * Builds the tenant-API-inaccessible DynamoDB projection of the authoritative
 * database receipt. This is written atomically with the promoted lifecycle and
 * append-only recovery change record; it is never a replacement for the
 * signed database row.
 */
export function buildAuthoritativePromotionReceiptItem(input) {
  const tenantId = String(input?.tenantId ?? "");
  const receiptHash = String(input?.receiptHash ?? "");
  const publishedAt = canonicalInstant(input?.publishedAt, "Promotion recovery publication time");
  const snapshot = input?.snapshot;
  const canonicalFacts = stableJson(snapshot?.facts);
  const expectedHash = digestHex(`${tenantId}\0${snapshot?.facts?.uploadIntentId}\0${snapshot?.facts?.quarantineVersionId}`);
  const signature = snapshot?.signature instanceof Uint8Array
    ? Buffer.from(snapshot.signature).toString("base64")
    : "";
  if (
    !/^ten_[a-f0-9]{32}$/.test(tenantId) ||
    !/^[a-f0-9]{64}$/.test(receiptHash) || receiptHash !== expectedHash ||
    snapshot?.facts?.tenantId !== tenantId ||
    !/^rcp_[a-f0-9]{32}$/.test(String(snapshot?.receiptId ?? "")) ||
    !/^[a-f0-9]{64}$/.test(String(snapshot?.receiptDigest ?? "")) ||
    !/^[a-f0-9]{64}$/.test(String(snapshot?.idempotencyDigest ?? "")) ||
    !Number.isSafeInteger(snapshot?.uploadRevision) || snapshot.uploadRevision < 1 ||
    !Number.isSafeInteger(snapshot?.evidenceRevision) || snapshot.evidenceRevision < 1 ||
    canonicalRsa3072Signature(signature).byteLength !== 384 ||
    canonicalInstant(snapshot?.signedAt, "Committed promotion receipt time") !== snapshot.signedAt ||
    Date.parse(publishedAt) < Date.parse(snapshot.signedAt) ||
    typeof snapshot?.signingKeyArn !== "string" ||
    digestHex(`${PROMOTION_RECEIPT_DOMAIN}\n${canonicalFacts}`) !== snapshot.receiptDigest ||
    digestHex(`${PROMOTION_RECONCILIATION_DOMAIN}\n${canonicalFacts}`) !== snapshot.idempotencyDigest
  ) {
    throw new Error("The authoritative promotion recovery receipt is invalid.");
  }
  return Object.freeze({
    PK: { S: `RECOVERY#TENANT#${tenantId}` },
    SK: { S: `PROMOTION#${receiptHash}` },
    canonicalFacts: { S: canonicalFacts },
    databaseEvidenceRevision: { N: String(snapshot.evidenceRevision) },
    databaseIdempotencyDigest: { S: snapshot.idempotencyDigest },
    databaseReceiptId: { S: snapshot.receiptId },
    databaseReceiptSha256: { S: snapshot.receiptDigest },
    databaseUploadRevision: { N: String(snapshot.uploadRevision) },
    kind: { S: "EvidencePromotionRecoveryReceipt" },
    publishedAt: { S: publishedAt },
    receiptHash: { S: receiptHash },
    schemaVersion: { N: "1" },
    signature: { S: signature },
    signedAt: { S: snapshot.signedAt },
    signingAlgorithm: { S: PROMOTION_SIGNING_ALGORITHM },
    signingKeyArn: { S: snapshot.signingKeyArn },
    tenantId: { S: tenantId },
  });
}

/** Parses, re-canonicalizes, and domain-separates the immutable Dynamo record. */
export function parseAuthoritativePromotionReceiptItem(item, expected) {
  if (!item || typeof item !== "object" || Array.isArray(item) ||
      Object.keys(item).sort().join("\0") !== authoritativeRecordKeys.join("\0")) {
    throw new Error("The authoritative promotion recovery receipt is invalid.");
  }
  const string = (name) => {
    const attribute = item[name];
    if (!attribute || Object.keys(attribute).length !== 1 || typeof attribute.S !== "string") {
      throw new Error("The authoritative promotion recovery receipt is invalid.");
    }
    return attribute.S;
  };
  const integer = (name) => {
    const attribute = item[name];
    if (!attribute || Object.keys(attribute).length !== 1 || !/^[1-9][0-9]*$/.test(String(attribute.N ?? ""))) {
      throw new Error("The authoritative promotion recovery receipt is invalid.");
    }
    const value = Number(attribute.N);
    if (!Number.isSafeInteger(value)) throw new Error("The authoritative promotion recovery receipt is invalid.");
    return value;
  };
  const tenantId = string("tenantId");
  const receiptHash = string("receiptHash");
  const publishedAt = canonicalInstant(string("publishedAt"), "Promotion recovery publication time");
  const canonicalFacts = string("canonicalFacts");
  let facts;
  try { facts = JSON.parse(canonicalFacts); } catch { throw new Error("The authoritative promotion recovery receipt is invalid."); }
  if (
    string("PK") !== `RECOVERY#TENANT#${tenantId}` ||
    string("SK") !== `PROMOTION#${receiptHash}` ||
    string("kind") !== "EvidencePromotionRecoveryReceipt" || integer("schemaVersion") !== 1 ||
    tenantId !== expected?.tenantId || receiptHash !== expected?.receiptHash ||
    string("signingKeyArn") !== expected?.signingKeyArn ||
    string("signingAlgorithm") !== PROMOTION_SIGNING_ALGORITHM ||
    stableJson(facts) !== canonicalFacts ||
    digestHex(`${tenantId}\0${facts?.uploadIntentId}\0${facts?.quarantineVersionId}`) !== receiptHash
  ) {
    throw new Error("The authoritative promotion recovery receipt is invalid.");
  }
  const snapshot = parseCommittedPromotionReceipt(JSON.stringify([{
    receipt_id: string("databaseReceiptId"),
    was_created: false,
    committed_upload_revision: integer("databaseUploadRevision"),
    committed_evidence_revision: integer("databaseEvidenceRevision"),
    committed_idempotency_digest: string("databaseIdempotencyDigest"),
    committed_promotion_facts: facts,
    committed_canonical_receipt: canonicalFacts,
    committed_receipt_sha256: string("databaseReceiptSha256"),
    committed_signing_key_arn: string("signingKeyArn"),
    committed_signing_algorithm: string("signingAlgorithm"),
    committed_signature: string("signature"),
    committed_signed_at: string("signedAt"),
  }]), {
    canonicalFacts,
    evidenceRevision: integer("databaseEvidenceRevision"),
    requireOutcome: true,
    signingKeyArn: expected.signingKeyArn,
    uploadRevision: integer("databaseUploadRevision"),
    verificationTime: expected.verificationTime,
  });
  if (!snapshot || Date.parse(publishedAt) < Date.parse(snapshot.signedAt)) {
    throw new Error("The authoritative promotion recovery receipt is invalid.");
  }
  return Object.freeze({
    publishedAt,
    receipt: Object.freeze({
      byteSize: facts.byteSize,
      contentType: facts.contentType,
      controlId: facts.controlId,
      databaseIdempotencyDigest: snapshot.idempotencyDigest,
      databaseReceiptId: snapshot.receiptId,
      destinationBucket: facts.evidenceBucket,
      destinationKey: facts.evidenceKey,
      destinationVersionId: facts.evidenceVersionId,
      evidenceId: facts.evidenceId,
      intentId: facts.uploadIntentId,
      kind: "EvidencePromotionReceipt",
      kmsKeyArn: facts.kmsKeyArn,
      objectLockMode: facts.objectLockMode,
      receiptHash,
      retainUntil: facts.retainUntil,
      sha256: facts.sha256,
      sourceVersionId: facts.quarantineVersionId,
      status: "COMPLETE",
      tenantId,
      uploadedAt: facts.uploadedAt,
    }),
    snapshot,
  });
}

function assertPromotionInvariants(facts, expected) {
  const exact = {
    schemaVersion: 1,
    tenantId: expected.tenantId,
    uploadIntentId: expected.uploadIntentId,
    evidenceId: expected.evidenceId,
    controlId: expected.controlId,
    quarantineBucket: expected.quarantineBucket,
    quarantineKey: expected.quarantineKey,
    quarantineVersionId: expected.quarantineVersionId,
    evidenceBucket: expected.evidenceBucket,
    evidenceKey: expected.evidenceKey,
    evidenceVersionId: expected.evidenceVersionId,
    sha256: expected.sha256,
    byteSize: expected.byteSize,
    contentType: expected.contentType,
    copyAttemptId: expected.copyAttemptId,
    copyFence: expected.copyFence,
    kmsKeyArn: expected.kmsKeyArn,
    objectLockMode: expected.objectLockMode,
    promotionAttemptId: expected.promotionAttemptId,
    promotionFence: expected.promotionFence,
    dlpPolicyVersion: expected.dlpPolicyVersion,
    dlpReceiptSha256: expected.dlpReceiptSha256,
    dlpScannedAt: expected.dlpScannedAt,
    dlpScannerRequestId: expected.dlpScannerRequestId,
    retainUntil: expected.retainUntil === undefined
      ? undefined
      : canonicalInstant(expected.retainUntil, "Expected retention time"),
    uploadedAt: expected.uploadedAt === undefined
      ? undefined
      : canonicalInstant(expected.uploadedAt, "Expected source upload time"),
  };
  for (const [name, value] of Object.entries(exact)) {
    if (value !== undefined && facts[name] !== value) {
      throw new Error("The committed promotion facts conflict with immutable S3 or upload-intent state.");
    }
  }
  const retainUntil = canonicalInstant(facts.retainUntil, "Committed retention time");
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/.test(String(facts.evidenceVersionId ?? "")) ||
    !/^[A-Za-z0-9][A-Za-z0-9_.:+/-]{2,199}$/.test(String(facts.providerRequestId ?? "")) ||
    !/^pat_[a-f0-9]{32}$/.test(String(facts.copyAttemptId ?? "")) ||
    !Number.isSafeInteger(facts.copyFence) || facts.copyFence < 1 ||
    !/^pat_[a-f0-9]{32}$/.test(String(facts.promotionAttemptId ?? "")) ||
    !Number.isSafeInteger(facts.promotionFence) || facts.promotionFence < facts.copyFence ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(String(facts.dlpPolicyVersion ?? "")) ||
    !/^[a-f0-9]{64}$/.test(String(facts.dlpReceiptSha256 ?? "")) ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(String(facts.dlpScannerRequestId ?? "")) ||
    Date.parse(canonicalInstant(facts.dlpScannedAt, "Committed DLP scan time")) >
      Date.parse(canonicalInstant(facts.promotedAt, "Committed promotion time")) ||
    Date.parse(canonicalInstant(facts.dlpScannedAt, "Committed DLP scan time")) <
      Date.parse(canonicalInstant(facts.uploadedAt, "Committed source upload time")) ||
    (expected.minimumRetainUntil !== undefined &&
      Date.parse(retainUntil) < Date.parse(canonicalInstant(expected.minimumRetainUntil, "Minimum retention time"))) ||
    Date.parse(canonicalInstant(facts.promotedAt, "Committed promotion time")) <
      Date.parse(canonicalInstant(facts.uploadedAt, "Committed source upload time"))
  ) {
    throw new Error("The committed promotion provenance is invalid.");
  }
}

function canonicalRsa3072Signature(value) {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("The committed promotion signature is not canonical base64.");
  }
  const signature = Buffer.from(value, "base64");
  if (signature.byteLength !== 384 || signature.toString("base64") !== value) {
    throw new Error("The committed promotion signature is not a canonical RSA-3072 signature.");
  }
  return signature;
}

function canonicalInstant(value, label) {
  if (typeof value !== "string") throw new Error(`${label} is invalid.`);
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime())) throw new Error(`${label} is invalid.`);
  return parsed.toISOString();
}

export function stableJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
}

export function digestHex(value) {
  return createHash("sha256").update(value).digest("hex");
}
