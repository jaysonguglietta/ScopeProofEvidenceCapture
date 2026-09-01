import { stableJson } from "./canonical-json.ts";
import type { ScopeproofEnv } from "./env.ts";
import {
  EvidenceSafetyScanError,
  evidenceSafetyScannerEndpoint,
  evidenceSafetyScannerToken,
} from "./image-safety-config.ts";
import { validatePng } from "./native-manifest.ts";
import { boundedFetch } from "./outbound.ts";
import { redactText } from "./redaction.ts";

export {
  EvidenceSafetyScanError,
  evidenceSafetyScannerEndpoint,
  evidenceSafetyScannerToken,
  validateEvidenceSafetyScannerConfiguration,
} from "./image-safety-config.ts";

const MAXIMUM_IMAGE_BYTES = 15 * 1024 * 1024;
const MAXIMUM_RESPONSE_BYTES = 2 * 1024 * 1024;
const MAXIMUM_RECOGNIZED_TEXT = 1_500_000;

export type EvidenceSafetyScan = {
  digest: string;
  policy: string;
  completedAt: string;
  scannerOrigin: string;
  receiptSha256: string;
  responseBytes: number;
};

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 32_768) binary += String.fromCharCode(...bytes.subarray(offset, offset + 32_768));
  return btoa(binary);
}

async function sha256(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function evidenceSafetyReceiptSha256(scan: { digest: string; policy: string; completedAt: string; scannerOrigin: string }): Promise<string> {
  return sha256(stableJson({
    version: 1,
    sha256: scan.digest,
    policyVersion: scan.policy,
    completedAt: scan.completedAt,
    scannerOrigin: scan.scannerOrigin,
    findingCount: 0,
  }));
}

export async function scanExactEvidencePixels(image: Uint8Array, env: ScopeproofEnv): Promise<EvidenceSafetyScan> {
  if (image.byteLength > MAXIMUM_IMAGE_BYTES) throw new EvidenceSafetyScanError("The screenshot exceeds the independent safety scanner limit.", "INVALID_RESPONSE", false);
  await validatePng(image);
  const digest = await sha256(image);
  const endpoint = evidenceSafetyScannerEndpoint(env);
  let response: Response;
  try {
    response = await boundedFetch(endpoint, {
      method: "POST",
      headers: { authorization: `Bearer ${evidenceSafetyScannerToken(env)}`, "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({ version: 1, sha256: digest, contentType: "image/png", imageBase64: base64(image) }),
    }, { label: "Independent evidence OCR scan", allowedOrigins: [endpoint.origin], maximumBytes: MAXIMUM_RESPONSE_BYTES, timeoutMs: 60_000 });
  } catch (error) {
    if (error instanceof EvidenceSafetyScanError) throw error;
    throw new EvidenceSafetyScanError("The independent evidence safety scanner is unavailable.", "UNAVAILABLE", true);
  }
  if (!response.ok || response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") {
    throw new EvidenceSafetyScanError("The independent evidence safety scanner returned an invalid response.", response.status >= 500 || response.status === 429 ? "UNAVAILABLE" : "INVALID_RESPONSE", response.status >= 500 || response.status === 429);
  }
  const responseBytes = new Uint8Array(await response.arrayBuffer());
  let payload: unknown;
  try { payload = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(responseBytes)); }
  catch { throw new EvidenceSafetyScanError("The independent evidence safety scanner returned invalid JSON.", "INVALID_RESPONSE", false); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new EvidenceSafetyScanError("The independent evidence safety scanner returned an invalid result.", "INVALID_RESPONSE", false);
  const result = payload as Record<string, unknown>;
  if (Object.keys(result).some((key) => !["sha256", "text", "policyVersion"].includes(key)) || result.sha256 !== digest
    || typeof result.text !== "string" || result.text.length > MAXIMUM_RECOGNIZED_TEXT
    || typeof result.policyVersion !== "string" || !/^[A-Za-z0-9._-]{1,100}$/.test(result.policyVersion)) {
    throw new EvidenceSafetyScanError("The independent evidence safety result is not bound to the submitted screenshot.", "INVALID_RESPONSE", false);
  }
  const sensitive = redactText(result.text);
  if (sensitive.total > 0) throw new EvidenceSafetyScanError("The independent evidence safety scanner detected sensitive content. Redact and recapture before upload.", "SENSITIVE_CONTENT", false);
  const completedAt = new Date().toISOString();
  const receiptFields = { digest, policy: result.policyVersion, completedAt, scannerOrigin: endpoint.origin };
  return { ...receiptFields, receiptSha256: await evidenceSafetyReceiptSha256(receiptFields), responseBytes: responseBytes.byteLength };
}
