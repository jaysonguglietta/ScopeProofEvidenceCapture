import { base64ToBytes, bytesToBase64, sha256, stableJson } from "./crypto";
import { getEnv } from "./env";

function derLength(length: number): Uint8Array {
  if (length < 0x80) return Uint8Array.of(length);
  const bytes: number[] = [];
  for (let value = length; value > 0; value >>>= 8) bytes.unshift(value & 0xff);
  return Uint8Array.of(0x80 | bytes.length, ...bytes);
}

function der(tag: number, ...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(1 + derLength(length).length + length);
  output[0] = tag;
  const encodedLength = derLength(length);
  output.set(encodedLength, 1);
  let offset = 1 + encodedLength.length;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
}

function hexBytes(value: string): Uint8Array {
  if (!/^[a-f0-9]{64}$/i.test(value)) throw new Error("RFC 3161 timestamp requires a SHA-256 digest.");
  return Uint8Array.from(value.match(/.{2}/g) || [], (pair) => Number.parseInt(pair, 16));
}

function hex(bytes: Uint8Array): string { return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(""); }
function arrayBuffer(bytes: Uint8Array): ArrayBuffer { return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer; }

function timestampRequest(digest: string): { body: Uint8Array; nonceHex: string } {
  const version = der(0x02, Uint8Array.of(0x01));
  const sha256OID = der(0x06, Uint8Array.of(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01));
  const algorithm = der(0x30, sha256OID, der(0x05, new Uint8Array()));
  const imprint = der(0x30, algorithm, der(0x04, hexBytes(digest)));
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = der(0x02, nonceBytes[0] & 0x80 ? Uint8Array.of(0, ...nonceBytes) : nonceBytes);
  return { body: der(0x30, version, imprint, nonce, der(0x01, Uint8Array.of(0xff))), nonceHex: hex(nonceBytes) };
}

export type VerifiedTimestampAttestation = {
  version: 1;
  status: "granted";
  digestSha256: string;
  nonceHex: string;
  tokenSha256: string;
  tsaOrigin: string;
  generatedAt: string;
  verifiedAt: string;
  messageImprintAlgorithm: "sha256";
  tsaExtendedKeyUsage: "timeStamping";
  signerCertificateSha256: string;
  trustAnchorSha256: string;
  certificateChainSha256: string[];
  chainValidUntil: string;
  revocationStatus: "good";
  policyOid: string;
  serialNumber: string;
};

function verifierEndpoint(): URL {
  const env = getEnv();
  if (!env.RFC3161_VERIFIER_URL || !env.RFC3161_VERIFIER_ALLOWED_HOSTS) throw new Error("RFC 3161 verifier is not configured.");
  const url = new URL(env.RFC3161_VERIFIER_URL);
  const hosts = new Set(env.RFC3161_VERIFIER_ALLOWED_HOSTS.split(",").map((value) => value.trim().toLowerCase()).filter(Boolean));
  if (url.protocol !== "https:" || url.username || url.password || url.hash || !hosts.has(url.hostname.toLowerCase())) throw new Error("RFC 3161 verifier must use an explicitly allowed HTTPS host.");
  return url;
}

function validateAttestationShape(value: unknown): value is VerifiedTimestampAttestation & { signatureBase64: string } {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  const allowed = new Set(["version", "status", "digestSha256", "nonceHex", "tokenSha256", "tsaOrigin", "generatedAt", "verifiedAt", "messageImprintAlgorithm", "tsaExtendedKeyUsage", "signerCertificateSha256", "trustAnchorSha256", "certificateChainSha256", "chainValidUntil", "revocationStatus", "policyOid", "serialNumber", "signatureBase64"]);
  const digest = (field: string) => typeof item[field] === "string" && /^[a-f0-9]{64}$/.test(String(item[field]));
  return Object.keys(item).every((key) => allowed.has(key)) && item.version === 1 && item.status === "granted" && item.messageImprintAlgorithm === "sha256" && item.tsaExtendedKeyUsage === "timeStamping" && item.revocationStatus === "good"
    && digest("digestSha256") && digest("tokenSha256") && digest("signerCertificateSha256") && digest("trustAnchorSha256")
    && typeof item.nonceHex === "string" && /^[a-f0-9]{32}$/.test(item.nonceHex) && typeof item.tsaOrigin === "string"
    && typeof item.generatedAt === "string" && typeof item.verifiedAt === "string" && typeof item.chainValidUntil === "string"
    && typeof item.policyOid === "string" && /^\d+(?:\.\d+)+$/.test(item.policyOid) && typeof item.serialNumber === "string" && /^[A-Fa-f0-9]{1,80}$/.test(item.serialNumber)
    && Array.isArray(item.certificateChainSha256) && item.certificateChainSha256.length >= 1 && item.certificateChainSha256.length <= 10 && item.certificateChainSha256.every((entry) => typeof entry === "string" && /^[a-f0-9]{64}$/.test(entry))
    && typeof item.signatureBase64 === "string" && item.signatureBase64.length <= 512;
}

async function verifyAttestation(value: VerifiedTimestampAttestation & { signatureBase64: string }): Promise<boolean> {
  const { signatureBase64, ...attestation } = value;
  const publicKeys = String(getEnv().RFC3161_VERIFIER_PUBLIC_KEYS || getEnv().RFC3161_VERIFIER_PUBLIC_KEY || "").split(",").map((value) => value.trim()).filter(Boolean);
  if (!publicKeys.length || publicKeys.length > 5) throw new Error("One to five RFC 3161 verifier public keys must be configured.");
  for (const publicKey of publicKeys) {
    try {
      const key = await crypto.subtle.importKey("spki", arrayBuffer(base64ToBytes(publicKey)), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      if (await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, arrayBuffer(base64ToBytes(signatureBase64)), new TextEncoder().encode(stableJson(attestation)))) return true;
    } catch { /* Try the next explicitly configured rotation key. */ }
  }
  return false;
}

export async function requestTrustedTimestamp(digestSha256: string): Promise<{ authority: string; format: string; tokenBase64: string; verification: VerifiedTimestampAttestation & { signatureBase64: string } } | null> {
  const env = getEnv();
  if (!env.RFC3161_TSA_URL) return null;
  const tsaUrl = new URL(env.RFC3161_TSA_URL);
  if (tsaUrl.protocol !== "https:" || tsaUrl.username || tsaUrl.password || tsaUrl.hash) throw new Error("RFC3161_TSA_URL must use HTTPS without credentials or fragments.");
  const request = timestampRequest(digestSha256);
  const response = await fetch(tsaUrl, { method: "POST", headers: { "content-type": "application/timestamp-query", accept: "application/timestamp-reply" }, body: arrayBuffer(request.body), signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new Error(`Timestamp authority returned HTTP ${response.status}.`);
  const token = new Uint8Array(await response.arrayBuffer());
  if (token.length < 16 || token.length > 256 * 1024) throw new Error("Timestamp authority returned an invalid-size RFC 3161 response.");
  const tokenSha256 = await sha256(token);
  const verifierUrl = verifierEndpoint();
  if (!env.RFC3161_VERIFIER_TOKEN) throw new Error("RFC 3161 verifier token is not configured.");
  const verificationResponse = await fetch(verifierUrl, {
    method: "POST", headers: { authorization: `Bearer ${env.RFC3161_VERIFIER_TOKEN}`, "content-type": "application/json", accept: "application/json" }, signal: AbortSignal.timeout(30_000),
    body: JSON.stringify({ version: 1, digestSha256, nonceHex: request.nonceHex, tsaOrigin: tsaUrl.origin, tokenBase64: bytesToBase64(token) }),
  });
  if (!verificationResponse.ok) throw new Error(`RFC 3161 verifier returned HTTP ${verificationResponse.status}.`);
  const verificationText = await verificationResponse.text();
  if (verificationText.length > 32 * 1024) throw new Error("RFC 3161 verifier response is too large.");
  let verification: unknown;
  try { verification = JSON.parse(verificationText); } catch { throw new Error("RFC 3161 verifier returned invalid JSON."); }
  if (!validateAttestationShape(verification)) throw new Error("RFC 3161 verifier returned an invalid attestation.");
  const now = Date.now();
  const generatedAt = Date.parse(verification.generatedAt);
  const verifiedAt = Date.parse(verification.verifiedAt);
  const validUntil = Date.parse(verification.chainValidUntil);
  const anchors = new Set(String(env.RFC3161_TSA_TRUST_ANCHOR_SHA256 || "").split(",").map((value) => value.trim().toLowerCase()).filter(Boolean));
  if (verification.digestSha256 !== digestSha256 || verification.nonceHex !== request.nonceHex || verification.tokenSha256 !== tokenSha256 || verification.tsaOrigin !== tsaUrl.origin
    || !anchors.has(verification.trustAnchorSha256) || !Number.isFinite(generatedAt) || Math.abs(now - generatedAt) > 24 * 60 * 60_000
    || !Number.isFinite(verifiedAt) || Math.abs(now - verifiedAt) > 10 * 60_000 || !Number.isFinite(validUntil) || validUntil <= now
    || !await verifyAttestation(verification)) throw new Error("RFC 3161 timestamp attestation failed cryptographic or policy validation.");
  return { authority: `Verified RFC 3161 · ${tsaUrl.origin}`, format: "RFC3161-TimeStampResp-DER+Pinned-Verifier-Attestation-v1", tokenBase64: bytesToBase64(token), verification };
}

export function decodeTrustedTimestamp(value: string): Uint8Array { return base64ToBytes(value); }
