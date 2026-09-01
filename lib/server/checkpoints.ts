import { base64ToBytes, randomId, sha256, signPackage, stableJson } from "./crypto";
import { getEnv, requireEnv } from "./env";
import { auditCheckpointEndpoint } from "./external-trust-config";
import { boundedFetch } from "./outbound";

export { validateAuditCheckpointConfiguration } from "./external-trust-config";

type AuditHead = { sequence: number; event_hash: string; hmac_key_id: string };
const exactBuffer = (bytes: Uint8Array): ArrayBuffer => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
export type AuditCheckpoint = {
  id: string;
  sequence: number;
  eventHash: string;
  eventCount: number;
  hmacKeyId: string;
  checkpointSha256: string;
  signature: string;
  publicKey: string;
  publicKeyFingerprint: string;
  r2Key: string;
  externalStatus: "delivered" | "not_configured" | "failed";
  externalReceipt: string | null;
  externalReceiptSha256: string | null;
  externalReceiptSignature: string | null;
  externalReceiptR2Key: string | null;
  createdAt: string;
};

type ExternalCheckpointReceipt = { version: 1; checkpointSha256: string; sequence: number; receivedAt: string; receiptId: string; signature: string };

async function verifyP256Signature(publicKeyBase64: string, signatureBase64: string, payload: string): Promise<boolean> {
  try {
    const signature = base64ToBytes(signatureBase64);
    if (signature.byteLength !== 64) return false;
    const key = await crypto.subtle.importKey("spki", exactBuffer(base64ToBytes(publicKeyBase64)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, exactBuffer(signature), exactBuffer(new TextEncoder().encode(payload)));
  } catch { return false; }
}

async function verifyExternalReceipt(receipt: ExternalCheckpointReceipt, checkpointSha256: string, sequence: number): Promise<boolean> {
  if (receipt.version !== 1 || receipt.checkpointSha256 !== checkpointSha256 || receipt.sequence !== sequence
    || !/^receipt_[A-Za-z0-9._:-]{8,160}$/.test(receipt.receiptId) || !Number.isFinite(Date.parse(receipt.receivedAt))) return false;
  const unsigned = stableJson({ version: receipt.version, checkpointSha256: receipt.checkpointSha256, sequence: receipt.sequence, receivedAt: receipt.receivedAt, receiptId: receipt.receiptId });
  return verifyP256Signature(requireEnv("AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY"), receipt.signature, unsigned);
}

async function deliverCheckpoint(url: URL, token: string | undefined, body: string, checkpointSha256: string, sequence: number): Promise<ExternalCheckpointReceipt> {
  const response = await boundedFetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body,
  }, { label: "Audit checkpoint", allowedOrigins: [url.origin], maximumBytes: 64_000, timeoutMs: 15_000 });
  if (!response.ok) throw new Error(`Audit checkpoint endpoint returned HTTP ${response.status}.`);
  const text = await response.text();
  if (text.length > 8_000) throw new Error("Audit checkpoint receipt exceeds the validation limit.");
  let parsed: unknown;
  try { parsed = JSON.parse(text); } catch { throw new Error("Audit checkpoint endpoint returned an invalid signed receipt."); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Audit checkpoint endpoint returned an invalid signed receipt.");
  const value = parsed as Record<string, unknown>;
  if (Object.keys(value).some((key) => !["version", "checkpointSha256", "sequence", "receivedAt", "receiptId", "signature"].includes(key))) throw new Error("Audit checkpoint receipt contains unsupported fields.");
  const receipt: ExternalCheckpointReceipt = { version: Number(value.version) as 1, checkpointSha256: String(value.checkpointSha256 || ""), sequence: Number(value.sequence), receivedAt: String(value.receivedAt || ""), receiptId: String(value.receiptId || ""), signature: String(value.signature || "") };
  if (!await verifyExternalReceipt(receipt, checkpointSha256, sequence)) throw new Error("Audit checkpoint receipt signature or binding is invalid.");
  return receipt;
}

export async function createAuditCheckpoint(now = new Date()): Promise<AuditCheckpoint | null> {
  const env = getEnv();
  const head = await env.DB.prepare("SELECT sequence, event_hash, hmac_key_id FROM audit_events ORDER BY sequence DESC LIMIT 1").first<AuditHead>();
  if (!head) return null;
  const existing = await env.DB.prepare("SELECT id FROM audit_checkpoints WHERE sequence = ?").bind(head.sequence).first();
  if (existing) return getLatestAuditCheckpoint();
  const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE sequence <= ?").bind(head.sequence).first<{ count: number }>();
  const createdAt = now.toISOString();
  const id = randomId("checkpoint");
  const unsigned = {
    version: 1,
    id,
    sequence: head.sequence,
    eventHash: head.event_hash,
    eventCount: Number(count?.count || 0),
    hmacKeyId: head.hmac_key_id || "legacy-v1",
    createdAt,
  };
  const canonical = stableJson(unsigned);
  const checkpointSha256 = await sha256(canonical);
  const signed = await signPackage(canonical);
  const publicKeyFingerprint = await sha256(signed.publicKey);
  const envelope = stableJson({ ...unsigned, checkpointSha256, signatureAlgorithm: "ECDSA_P256_SHA256", signature: signed.signature, publicKey: signed.publicKey, publicKeyFingerprint });
  const month = createdAt.slice(0, 7);
  const r2Key = `audit-checkpoints/${month}/${id}.json`;
  await env.EVIDENCE_BUCKET.put(r2Key, envelope, {
    httpMetadata: { contentType: "application/json" },
    customMetadata: { checkpointSha256, sequence: String(head.sequence), publicKeyFingerprint },
  });

  let externalStatus: AuditCheckpoint["externalStatus"] = "not_configured";
  let externalReceipt: string | null = null;
  let externalReceiptSha256: string | null = null;
  let externalReceiptSignature: string | null = null;
  let externalReceiptR2Key: string | null = null;
  try {
    const endpoint = auditCheckpointEndpoint(getEnv());
    if (endpoint) {
      const verifiedReceipt = await deliverCheckpoint(endpoint.url, endpoint.token, envelope, checkpointSha256, head.sequence);
      externalReceipt = stableJson(verifiedReceipt);
      const receiptBinding = { version: 1, checkpointId: id, checkpointSha256, sequence: head.sequence, externalReceipt: verifiedReceipt, boundAt: new Date().toISOString() };
      const receiptCanonical = stableJson(receiptBinding);
      const receiptSigned = await signPackage(receiptCanonical);
      const receiptEnvelope = stableJson({ ...receiptBinding, signatureAlgorithm: "ECDSA_P256_SHA256", signature: receiptSigned.signature, publicKey: receiptSigned.publicKey });
      externalReceiptSha256 = await sha256(receiptEnvelope);
      externalReceiptSignature = receiptSigned.signature;
      externalReceiptR2Key = `audit-checkpoints/${month}/${id}.external-receipt.json`;
      await env.EVIDENCE_BUCKET.put(externalReceiptR2Key, receiptEnvelope, {
        httpMetadata: { contentType: "application/json" }, customMetadata: { checkpointSha256, externalReceiptSha256, sequence: String(head.sequence) },
      });
      externalStatus = "delivered";
    }
  } catch (error) {
    if (externalReceiptR2Key) await env.EVIDENCE_BUCKET.delete(externalReceiptR2Key);
    externalStatus = "failed";
    externalReceipt = (error instanceof Error ? error.message : String(error)).slice(0, 1_000);
    externalReceiptSha256 = null;
    externalReceiptSignature = null;
    externalReceiptR2Key = null;
    console.error("scopeproof_audit_checkpoint_delivery_failure", { id, sequence: head.sequence, error: externalReceipt });
  }

  try {
    await env.DB.prepare(`INSERT INTO audit_checkpoints
      (id, sequence, event_hash, event_count, hmac_key_id, checkpoint_sha256, signature, public_key_fingerprint, r2_key, external_status, external_receipt, external_receipt_sha256, external_receipt_signature, external_receipt_r2_key, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, head.sequence, head.event_hash, unsigned.eventCount, unsigned.hmacKeyId, checkpointSha256, signed.signature, publicKeyFingerprint, r2Key, externalStatus, externalReceipt, externalReceiptSha256, externalReceiptSignature, externalReceiptR2Key, createdAt).run();
  } catch (error) {
    const winner = await env.DB.prepare("SELECT id FROM audit_checkpoints WHERE sequence = ?").bind(head.sequence).first();
    if (!winner) throw error;
    await env.EVIDENCE_BUCKET.delete(r2Key);
    if (externalReceiptR2Key) await env.EVIDENCE_BUCKET.delete(externalReceiptR2Key);
    return getLatestAuditCheckpoint();
  }
  return { ...unsigned, checkpointSha256, signature: signed.signature, publicKey: signed.publicKey, publicKeyFingerprint, r2Key, externalStatus, externalReceipt, externalReceiptSha256, externalReceiptSignature, externalReceiptR2Key };
}

export async function getLatestAuditCheckpoint(): Promise<AuditCheckpoint | null> {
  const row = await getEnv().DB.prepare(`SELECT id, sequence, event_hash, event_count, hmac_key_id, checkpoint_sha256, signature,
    public_key_fingerprint, r2_key, external_status, external_receipt, external_receipt_sha256, external_receipt_signature, external_receipt_r2_key, created_at FROM audit_checkpoints ORDER BY sequence DESC LIMIT 1`).first<Record<string, unknown>>();
  if (!row) return null;
  const object = await getEnv().EVIDENCE_BUCKET.get(String(row.r2_key));
  let publicKey = "";
  if (object) {
    try { publicKey = String((JSON.parse(await object.text()) as { publicKey?: string }).publicKey || ""); } catch { publicKey = ""; }
  }
  return {
    id: String(row.id), sequence: Number(row.sequence), eventHash: String(row.event_hash), eventCount: Number(row.event_count),
    hmacKeyId: String(row.hmac_key_id), checkpointSha256: String(row.checkpoint_sha256), signature: String(row.signature),
    publicKey, publicKeyFingerprint: String(row.public_key_fingerprint), r2Key: String(row.r2_key),
    externalStatus: String(row.external_status) as AuditCheckpoint["externalStatus"], externalReceipt: row.external_receipt ? String(row.external_receipt) : null,
    externalReceiptSha256: row.external_receipt_sha256 ? String(row.external_receipt_sha256) : null,
    externalReceiptSignature: row.external_receipt_signature ? String(row.external_receipt_signature) : null,
    externalReceiptR2Key: row.external_receipt_r2_key ? String(row.external_receipt_r2_key) : null,
    createdAt: String(row.created_at),
  };
}

export async function verifyLatestAuditCheckpoint(): Promise<{ valid: boolean; reason?: string; sequence?: number }> {
  const env = getEnv();
  const row = await env.DB.prepare(`SELECT id, sequence, event_hash, event_count, hmac_key_id, checkpoint_sha256, signature,
    public_key_fingerprint, r2_key, external_status, external_receipt, external_receipt_sha256, external_receipt_signature, external_receipt_r2_key, created_at FROM audit_checkpoints ORDER BY sequence DESC LIMIT 1`).first<Record<string, unknown>>();
  if (!row) return { valid: false, reason: "missing_checkpoint" };
  if (String(row.external_status) !== "delivered") return { valid: false, reason: "checkpoint_not_independently_delivered", sequence: Number(row.sequence) };
  const anchor = await env.DB.prepare("SELECT event_hash, hmac_key_id FROM audit_events WHERE sequence = ?").bind(row.sequence).first<{ event_hash: string; hmac_key_id: string }>();
  const actualCount = await env.DB.prepare("SELECT COUNT(*) AS count FROM audit_events WHERE sequence <= ?").bind(row.sequence).first<{ count: number }>();
  if (!anchor || anchor.event_hash !== String(row.event_hash) || anchor.hmac_key_id !== String(row.hmac_key_id) || Number(actualCount?.count || 0) !== Number(row.event_count)) {
    return { valid: false, reason: "checkpoint_audit_anchor_mismatch", sequence: Number(row.sequence) };
  }
  const object = await env.EVIDENCE_BUCKET.get(String(row.r2_key));
  if (!object) return { valid: false, reason: "missing_checkpoint_object", sequence: Number(row.sequence) };
  let envelope: Record<string, unknown>;
  try { envelope = JSON.parse(await object.text()) as Record<string, unknown>; }
  catch { return { valid: false, reason: "invalid_checkpoint_json", sequence: Number(row.sequence) }; }
  const unsigned = { version: envelope.version, id: envelope.id, sequence: envelope.sequence, eventHash: envelope.eventHash, eventCount: envelope.eventCount, hmacKeyId: envelope.hmacKeyId, createdAt: envelope.createdAt };
  const canonical = stableJson(unsigned);
  const digest = await sha256(canonical);
  const publicKey = String(envelope.publicKey || "");
  if (publicKey !== requireEnv("PACKAGE_SIGNING_PUBLIC_KEY")) return { valid: false, reason: "untrusted_checkpoint_signing_key", sequence: Number(row.sequence) };
  const fingerprint = await sha256(publicKey);
  if (String(envelope.id) !== String(row.id) || Number(envelope.sequence) !== Number(row.sequence) || String(envelope.eventHash) !== String(row.event_hash)
    || Number(envelope.eventCount) !== Number(row.event_count) || String(envelope.hmacKeyId) !== String(row.hmac_key_id) || String(envelope.createdAt) !== String(row.created_at)
    || digest !== String(row.checkpoint_sha256) || digest !== String(envelope.checkpointSha256) || String(envelope.signature) !== String(row.signature)
    || fingerprint !== String(row.public_key_fingerprint) || fingerprint !== String(envelope.publicKeyFingerprint)) {
    return { valid: false, reason: "checkpoint_record_mismatch", sequence: Number(row.sequence) };
  }
  try {
    const key = await crypto.subtle.importKey("spki", exactBuffer(base64ToBytes(publicKey)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const valid = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, exactBuffer(base64ToBytes(String(envelope.signature))), exactBuffer(new TextEncoder().encode(canonical)));
    if (!valid) return { valid: false, reason: "invalid_checkpoint_signature", sequence: Number(row.sequence) };
    if (!row.external_receipt || !row.external_receipt_sha256 || !row.external_receipt_signature || !row.external_receipt_r2_key) return { valid: false, reason: "missing_signed_external_receipt", sequence: Number(row.sequence) };
    let externalReceipt: ExternalCheckpointReceipt;
    try { externalReceipt = JSON.parse(String(row.external_receipt)) as ExternalCheckpointReceipt; }
    catch { return { valid: false, reason: "invalid_external_receipt_json", sequence: Number(row.sequence) }; }
    if (!await verifyExternalReceipt(externalReceipt, String(row.checkpoint_sha256), Number(row.sequence))) return { valid: false, reason: "invalid_external_receipt_signature", sequence: Number(row.sequence) };
    const receiptObject = await env.EVIDENCE_BUCKET.get(String(row.external_receipt_r2_key));
    if (!receiptObject) return { valid: false, reason: "missing_external_receipt_object", sequence: Number(row.sequence) };
    const receiptText = await receiptObject.text();
    if (await sha256(receiptText) !== String(row.external_receipt_sha256)) return { valid: false, reason: "external_receipt_digest_mismatch", sequence: Number(row.sequence) };
    let receiptEnvelope: Record<string, unknown>;
    try { receiptEnvelope = JSON.parse(receiptText) as Record<string, unknown>; }
    catch { return { valid: false, reason: "invalid_external_receipt_envelope", sequence: Number(row.sequence) }; }
    const receiptBinding = { version: receiptEnvelope.version, checkpointId: receiptEnvelope.checkpointId, checkpointSha256: receiptEnvelope.checkpointSha256, sequence: receiptEnvelope.sequence, externalReceipt: receiptEnvelope.externalReceipt, boundAt: receiptEnvelope.boundAt };
    const receiptCanonical = stableJson(receiptBinding);
    if (String(receiptEnvelope.checkpointId) !== String(row.id) || String(receiptEnvelope.checkpointSha256) !== String(row.checkpoint_sha256)
      || Number(receiptEnvelope.sequence) !== Number(row.sequence) || stableJson(receiptEnvelope.externalReceipt) !== String(row.external_receipt)
      || String(receiptEnvelope.signature) !== String(row.external_receipt_signature) || String(receiptEnvelope.publicKey) !== publicKey
      || !await verifyP256Signature(publicKey, String(receiptEnvelope.signature || ""), receiptCanonical)) {
      return { valid: false, reason: "external_receipt_binding_mismatch", sequence: Number(row.sequence) };
    }
    return { valid: true, sequence: Number(row.sequence) };
  } catch { return { valid: false, reason: "invalid_checkpoint_key", sequence: Number(row.sequence) }; }
}
