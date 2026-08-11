import { requireEnv } from "./env";

const encoder = new TextEncoder();

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export async function sha256(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  const digest = await crypto.subtle.digest("SHA-256", asArrayBuffer(bytes));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function importAesKey(): Promise<CryptoKey> {
  const raw = base64ToBytes(requireEnv("EVIDENCE_ENCRYPTION_KEY"));
  if (raw.byteLength !== 32) throw new Error("EVIDENCE_ENCRYPTION_KEY must be a base64-encoded 32-byte key.");
  return crypto.subtle.importKey("raw", asArrayBuffer(raw), "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptEvidence(plain: Uint8Array, associatedData: string): Promise<{ ciphertext: Uint8Array; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await importAesKey();
  const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv: asArrayBuffer(iv), additionalData: asArrayBuffer(encoder.encode(associatedData)), tagLength: 128 }, key, asArrayBuffer(plain));
  return { ciphertext: new Uint8Array(encrypted), iv: bytesToBase64(iv) };
}

export async function decryptEvidence(ciphertext: Uint8Array, iv: string, associatedData: string): Promise<Uint8Array> {
  const key = await importAesKey();
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv: asArrayBuffer(base64ToBytes(iv)), additionalData: asArrayBuffer(encoder.encode(associatedData)), tagLength: 128 }, key, asArrayBuffer(ciphertext));
  return new Uint8Array(decrypted);
}

export async function hmac(value: string): Promise<string> {
  const secret = requireEnv("AUDIT_HMAC_KEY");
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(value));
  return bytesToBase64(new Uint8Array(signature));
}

export async function signPackage(value: string): Promise<{ signature: string; publicKey: string }> {
  const privateKey = await crypto.subtle.importKey("pkcs8", asArrayBuffer(base64ToBytes(requireEnv("PACKAGE_SIGNING_PRIVATE_KEY"))), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, privateKey, asArrayBuffer(encoder.encode(value)));
  return { signature: bytesToBase64(new Uint8Array(signature)), publicKey: requireEnv("PACKAGE_SIGNING_PUBLIC_KEY") };
}

export function randomId(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replaceAll("-", "")}`;
}

export { stableJson } from "./canonical-json";
