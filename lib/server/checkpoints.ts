import { base64ToBytes, randomId, sha256, signPackage, stableJson } from "./crypto";
import { getEnv } from "./env";
import { boundedFetch } from "./outbound";

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
  createdAt: string;
};

function checkpointEndpoint(): { url: URL; token?: string } | null {
  const env = getEnv();
  if (!env.AUDIT_CHECKPOINT_ENDPOINT) return null;
  let url: URL;
  try { url = new URL(env.AUDIT_CHECKPOINT_ENDPOINT); } catch { throw new Error("AUDIT_CHECKPOINT_ENDPOINT is invalid."); }
  const hosts = new Set(String(env.AUDIT_CHECKPOINT_ALLOWED_HOSTS || "").split(",").map((value) => value.trim().toLowerCase()).filter(Boolean));
  if (url.protocol !== "https:" || url.username || url.password || url.hash || !hosts.has(url.hostname.toLowerCase())) {
    throw new Error("Audit checkpoint delivery is not restricted to an approved HTTPS host.");
  }
  return { url, token: env.AUDIT_CHECKPOINT_TOKEN };
}

async function deliverCheckpoint(url: URL, token: string | undefined, body: string): Promise<string> {
  const response = await boundedFetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body,
  }, { label: "Audit checkpoint", allowedOrigins: [url.origin], maximumBytes: 64_000, timeoutMs: 15_000 });
  const receipt = (await response.text()).slice(0, 8_000);
  if (!response.ok) throw new Error(`Audit checkpoint endpoint returned HTTP ${response.status}.`);
  return receipt || stableJson({ status: response.status, deliveredAt: new Date().toISOString() });
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
  try {
    const endpoint = checkpointEndpoint();
    if (endpoint) {
      externalReceipt = await deliverCheckpoint(endpoint.url, endpoint.token, envelope);
      externalStatus = "delivered";
    }
  } catch (error) {
    externalStatus = "failed";
    externalReceipt = (error instanceof Error ? error.message : String(error)).slice(0, 1_000);
    console.error("scopeproof_audit_checkpoint_delivery_failure", { id, sequence: head.sequence, error: externalReceipt });
  }

  try {
    await env.DB.prepare(`INSERT INTO audit_checkpoints
      (id, sequence, event_hash, event_count, hmac_key_id, checkpoint_sha256, signature, public_key_fingerprint, r2_key, external_status, external_receipt, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).bind(id, head.sequence, head.event_hash, unsigned.eventCount, unsigned.hmacKeyId, checkpointSha256, signed.signature, publicKeyFingerprint, r2Key, externalStatus, externalReceipt, createdAt).run();
  } catch (error) {
    const winner = await env.DB.prepare("SELECT id FROM audit_checkpoints WHERE sequence = ?").bind(head.sequence).first();
    if (!winner) throw error;
    await env.EVIDENCE_BUCKET.delete(r2Key);
    return getLatestAuditCheckpoint();
  }
  return { ...unsigned, checkpointSha256, signature: signed.signature, publicKey: signed.publicKey, publicKeyFingerprint, r2Key, externalStatus, externalReceipt };
}

export async function getLatestAuditCheckpoint(): Promise<AuditCheckpoint | null> {
  const row = await getEnv().DB.prepare(`SELECT id, sequence, event_hash, event_count, hmac_key_id, checkpoint_sha256, signature,
    public_key_fingerprint, r2_key, external_status, external_receipt, created_at FROM audit_checkpoints ORDER BY sequence DESC LIMIT 1`).first<Record<string, unknown>>();
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
    createdAt: String(row.created_at),
  };
}

export async function verifyLatestAuditCheckpoint(): Promise<{ valid: boolean; reason?: string; sequence?: number }> {
  const env = getEnv();
  const row = await env.DB.prepare(`SELECT id, sequence, event_hash, event_count, hmac_key_id, checkpoint_sha256, signature,
    public_key_fingerprint, r2_key, created_at FROM audit_checkpoints ORDER BY sequence DESC LIMIT 1`).first<Record<string, unknown>>();
  if (!row) return { valid: false, reason: "missing_checkpoint" };
  const object = await env.EVIDENCE_BUCKET.get(String(row.r2_key));
  if (!object) return { valid: false, reason: "missing_checkpoint_object", sequence: Number(row.sequence) };
  let envelope: Record<string, unknown>;
  try { envelope = JSON.parse(await object.text()) as Record<string, unknown>; }
  catch { return { valid: false, reason: "invalid_checkpoint_json", sequence: Number(row.sequence) }; }
  const unsigned = { version: envelope.version, id: envelope.id, sequence: envelope.sequence, eventHash: envelope.eventHash, eventCount: envelope.eventCount, hmacKeyId: envelope.hmacKeyId, createdAt: envelope.createdAt };
  const canonical = stableJson(unsigned);
  const digest = await sha256(canonical);
  const publicKey = String(envelope.publicKey || "");
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
    return valid ? { valid: true, sequence: Number(row.sequence) } : { valid: false, reason: "invalid_checkpoint_signature", sequence: Number(row.sequence) };
  } catch { return { valid: false, reason: "invalid_checkpoint_key", sequence: Number(row.sequence) }; }
}
