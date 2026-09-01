import { getEnv, requireEnv } from "./env";

const encoder = new TextEncoder();
const aesKeyCache = new Map<string, { material: string; key: CryptoKey }>();
const hmacKeyCache = new Map<string, { material: string; key: CryptoKey }>();

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  if (!value || value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error("Key or signature material is not canonical base64.");
  let binary: string;
  try { binary = atob(value); } catch { throw new Error("Key or signature material is not valid base64."); }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytesToBase64(bytes) !== value) throw new Error("Key or signature material is not canonical base64.");
  return bytes;
}

export async function sha256(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const digest = await crypto.subtle.digest("SHA-256", asArrayBuffer(bytes));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function parseKeyring(json: string | undefined, legacy: string | undefined, activeId: string | undefined, label: string): { activeId: string; values: Record<string, string> } {
  let values: Record<string, string> = {};
  if (json) {
    let parsed: unknown; try { parsed = JSON.parse(json); } catch { throw new Error(`${label} keyring is not valid JSON.`); }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(`${label} keyring must be a JSON object.`);
    values = Object.fromEntries(Object.entries(parsed as Record<string, unknown>).map(([id, value]) => {
      if (!/^[A-Za-z0-9._-]{1,64}$/.test(id) || typeof value !== "string" || !value) throw new Error(`${label} keyring contains an invalid entry.`);
      const raw = base64ToBytes(value);
      if (label === "Audit HMAC" ? raw.byteLength < 32 : raw.byteLength !== 32) throw new Error(label === "Audit HMAC" ? `${label} keys must be canonical base64 with at least 32 random bytes.` : `${label} keys must be canonical base64 encoding exactly 32 bytes.`);
      return [id, value];
    }));
  }
  if (legacy) {
    const raw = base64ToBytes(legacy);
    if (label === "Audit HMAC" ? raw.byteLength < 32 : raw.byteLength !== 32) throw new Error(label === "Audit HMAC" ? `${label} keys must be canonical base64 with at least 32 random bytes.` : `${label} keys must be canonical base64 encoding exactly 32 bytes.`);
    values["legacy-v1"] ||= legacy;
  }
  const selected = activeId || "legacy-v1";
  if (!values[selected]) throw new Error(`${label} active key ${selected} is not present in the retained keyring.`);
  return { activeId: selected, values };
}

function evidenceKeyring() { const env = getEnv(); return parseKeyring(env.EVIDENCE_KEYRING_JSON, env.EVIDENCE_ENCRYPTION_KEY, env.EVIDENCE_ACTIVE_KEY_ID, "Evidence encryption"); }
function auditKeyring() { const env = getEnv(); return parseKeyring(env.AUDIT_KEYRING_JSON, env.AUDIT_HMAC_KEY, env.AUDIT_ACTIVE_KEY_ID, "Audit HMAC"); }

export function activeEvidenceKeyId(): string { return evidenceKeyring().activeId; }
export function availableEvidenceKeyIds(): string[] { return Object.keys(evidenceKeyring().values).sort(); }
export function availableAuditKeyIds(): string[] { return Object.keys(auditKeyring().values).sort(); }

async function importAesKey(keyId: string): Promise<CryptoKey> {
  const value = evidenceKeyring().values[keyId];
  if (!value) throw new Error(`Evidence encryption key ${keyId} is unavailable; retained evidence cannot be decrypted.`);
  const cached = aesKeyCache.get(`evidence:${keyId}`);
  if (cached?.material === value) return cached.key;
  const raw = base64ToBytes(value);
  if (raw.byteLength !== 32) throw new Error("EVIDENCE_ENCRYPTION_KEY must be a base64-encoded 32-byte key.");
  const key = await crypto.subtle.importKey("raw", asArrayBuffer(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
  aesKeyCache.set(`evidence:${keyId}`, { material: value, key });
  return key;
}

async function importNamedAesKey(base64: string, name: string): Promise<CryptoKey> {
  const cacheId = `named:${name}`;
  const cached = aesKeyCache.get(cacheId);
  if (cached?.material === base64) return cached.key;
  const raw = base64ToBytes(base64);
  if (raw.byteLength !== 32) throw new Error(`${name} must be a base64-encoded 32-byte key.`);
  const key = await crypto.subtle.importKey("raw", asArrayBuffer(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
  aesKeyCache.set(cacheId, { material: base64, key });
  return key;
}

export async function encryptEvidence(plain: Uint8Array, associatedData: string): Promise<{ ciphertext: Uint8Array; iv: string; keyId: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const keyId = evidenceKeyring().activeId;
  const key = await importAesKey(keyId);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: asArrayBuffer(iv), additionalData: asArrayBuffer(encoder.encode(associatedData)), tagLength: 128 }, key, asArrayBuffer(plain));
  return { ciphertext: new Uint8Array(encrypted), iv: bytesToBase64(iv), keyId };
}

export async function decryptEvidence(ciphertext: Uint8Array, iv: string, associatedData: string, keyId = "legacy-v1"): Promise<Uint8Array> {
  const key = await importAesKey(keyId);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: asArrayBuffer(base64ToBytes(iv)), additionalData: asArrayBuffer(encoder.encode(associatedData)), tagLength: 128 }, key, asArrayBuffer(ciphertext));
  return new Uint8Array(decrypted);
}

export async function encryptSecret(value: string, keyBase64: string, keyName: string, associatedData: string): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await importNamedAesKey(keyBase64, keyName);
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: asArrayBuffer(iv), additionalData: asArrayBuffer(encoder.encode(associatedData)), tagLength: 128 }, key, asArrayBuffer(encoder.encode(value)));
  return { ciphertext: bytesToBase64(new Uint8Array(encrypted)), iv: bytesToBase64(iv) };
}

export async function decryptSecret(ciphertext: string, iv: string, keyBase64: string, keyName: string, associatedData: string): Promise<string> {
  const key = await importNamedAesKey(keyBase64, keyName);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: asArrayBuffer(base64ToBytes(iv)), additionalData: asArrayBuffer(encoder.encode(associatedData)), tagLength: 128 }, key, asArrayBuffer(base64ToBytes(ciphertext)));
  return new TextDecoder().decode(decrypted);
}

export function activeAuditKeyId(): string { return auditKeyring().activeId; }

export async function hmac(value: string, keyId = activeAuditKeyId()): Promise<string> {
  const secret = auditKeyring().values[keyId];
  if (!secret) throw new Error(`Audit HMAC key ${keyId} is unavailable; retained history cannot be verified.`);
  const cached = hmacKeyCache.get(keyId);
  let key = cached?.material === secret ? cached.key : null;
  if (!key) {
    const raw = base64ToBytes(secret);
    if (raw.byteLength < 32) throw new Error("Audit HMAC keys must contain at least 32 random bytes encoded as canonical base64.");
    key = await crypto.subtle.importKey("raw", asArrayBuffer(raw), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    hmacKeyCache.set(keyId, { material: secret, key });
  }
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return bytesToBase64(new Uint8Array(signature));
}

export function rotatingSecretKeyring(json: string | undefined, legacy: string | undefined, activeId: string | undefined, label: string): { activeId: string; values: Record<string, string> } {
  return parseKeyring(json, legacy, activeId, label);
}

export async function validateConfiguredKeyMaterial(): Promise<{ evidenceKeyIds: string[]; auditKeyIds: string[] }> {
  const evidence = evidenceKeyring();
  for (const keyId of Object.keys(evidence.values)) await importAesKey(keyId);
  const audit = auditKeyring();
  for (const keyId of Object.keys(audit.values)) await hmac("scopeproof-audit-key-self-test-v1", keyId);
  return { evidenceKeyIds: Object.keys(evidence.values).sort(), auditKeyIds: Object.keys(audit.values).sort() };
}

export async function signPackage(value: string): Promise<{ signature: string; publicKey: string }> {
  const privateKey = await crypto.subtle.importKey("pkcs8", asArrayBuffer(base64ToBytes(requireEnv("PACKAGE_SIGNING_PRIVATE_KEY"))), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, asArrayBuffer(encoder.encode(value)));
  const publicKey = requireEnv("PACKAGE_SIGNING_PUBLIC_KEY");
  const verifier = await crypto.subtle.importKey("spki", asArrayBuffer(base64ToBytes(publicKey)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  if (!await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, verifier, signature, asArrayBuffer(encoder.encode(value)))) {
    throw new Error("Package signing public key does not match the configured private key.");
  }
  return { signature: bytesToBase64(new Uint8Array(signature)), publicKey };
}

export async function validatePackageSigningKeyPair(): Promise<boolean> {
  try {
    await signPackage("scopeproof-package-signing-key-self-test-v1");
    return true;
  } catch {
    return false;
  }
}

export function randomId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replaceAll("-", "")}`;
}

export { stableJson } from "./canonical-json";
