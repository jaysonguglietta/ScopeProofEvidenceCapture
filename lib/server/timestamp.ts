import { base64ToBytes, bytesToBase64 } from "./crypto";
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

function timestampRequest(sha256: string): Uint8Array {
  const version = der(0x02, Uint8Array.of(0x01));
  const sha256OID = der(0x06, Uint8Array.of(0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01));
  const algorithm = der(0x30, sha256OID, der(0x05, new Uint8Array()));
  const imprint = der(0x30, algorithm, der(0x04, hexBytes(sha256)));
  const nonceBytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = der(0x02, nonceBytes[0] & 0x80 ? Uint8Array.of(0, ...nonceBytes) : nonceBytes);
  const certReq = der(0x01, Uint8Array.of(0xff));
  return der(0x30, version, imprint, nonce, certReq);
}

export async function requestTrustedTimestamp(sha256: string): Promise<{ authority: string; format: string; tokenBase64: string } | null> {
  const endpoint = getEnv().RFC3161_TSA_URL;
  if (!endpoint) return null;
  const url = new URL(endpoint);
  if (url.protocol !== "https:") throw new Error("RFC3161_TSA_URL must use HTTPS.");
  const requestBody = new Uint8Array(timestampRequest(sha256)).buffer;
  const response = await fetch(url, { method: "POST", headers: { "content-type": "application/timestamp-query", accept: "application/timestamp-reply" }, body: requestBody });
  if (!response.ok) throw new Error(`Timestamp authority returned HTTP ${response.status}.`);
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length < 16 || bytes.length > 256 * 1024 || bytes[0] !== 0x30) throw new Error("Timestamp authority returned an invalid RFC 3161 response.");
  return { authority: url.origin, format: "RFC3161-TimeStampResp-DER", tokenBase64: bytesToBase64(bytes) };
}

export function decodeTrustedTimestamp(value: string): Uint8Array { return base64ToBytes(value); }
