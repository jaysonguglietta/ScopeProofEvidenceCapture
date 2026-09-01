import type { RedactionFinding, RedactionKind } from "./redaction";
import { stableJson } from "./canonical-json.ts";

const redactionKinds = new Set<RedactionKind>(["pan", "aws_access_key", "github_token", "api_token", "jwt", "private_key", "authorization"]);
const digestPattern = /^[a-f0-9]{64}$/;
const evidenceIdPattern = /^EV-[A-Z0-9]{10,32}$/;
const jiraIssuePattern = /^[A-Z][A-Z0-9_]{1,31}-[1-9][0-9]*$/;
const MAXIMUM_FUTURE_CAPTURE_SKEW_MS = 5 * 60_000;
const MAXIMUM_NATIVE_CAPTURE_AGE_MS = 30 * 24 * 60 * 60_000;
const encoder = new TextEncoder();
const allowedManifestKeys = new Set([
  "schemaVersion", "evidenceID", "capturedAt", "localTimestamp", "timezone", "sourceURL", "sourceHost", "browser", "windowTitle",
  "screenshotFilename", "sha256", "pixelWidth", "pixelHeight", "captureMethod", "timestampAuthority", "safetyStatus",
  "redactionFindings", "redactedRegions", "safetyScanSha256", "safetyScanPolicy", "safetyScanCompletedAt", "sessionID", "sessionName", "controlID", "title", "system", "environment",
  "assessmentPeriod", "description", "complianceArea", "controlTitle", "customFileName", "catalogVersion", "evidenceOwner", "tags",
  "expectedEvidence", "mappedControls", "manualRedactions", "reviewerNote", "jiraIssueKey", "jiraIssueURL", "chainPreviousHash", "chainEventHash",
  "tenantID", "workspaceID", "chainSequence", "provenance",
]);
const tenantBindingPattern = /^[a-z0-9](?:[a-z0-9_-]{0,62}[a-z0-9])?$/;

export type NativeControlMapping = { framework: string; controlID: string; relationship: string };
export type NativeCaptureManifest = {
  schemaVersion: 8;
  evidenceID: string;
  capturedAt: string;
  sourceURL: string;
  sourceHost: string;
  screenshotFilename: string;
  sha256: string;
  pixelWidth: number;
  pixelHeight: number;
  safetyStatus: "passed" | "redacted";
  redactionFindings: RedactionFinding[];
  redactedRegions: number;
  safetyScanSha256: string;
  safetyScanPolicy: string;
  safetyScanCompletedAt: string;
  sessionID: string;
  sessionName: string;
  controlID: string;
  title: string;
  system: string;
  environment: string;
  assessmentPeriod: string;
  description: string;
  complianceArea: string;
  catalogVersion: string;
  evidenceOwner: string;
  tags: string[];
  expectedEvidence: string;
  mappedControls: NativeControlMapping[];
  manualRedactions: number;
  jiraIssueKey: string;
  jiraIssueURL: string;
  tenantID: string;
  workspaceID: string;
  chainPreviousHash: string;
  chainEventHash: string;
  chainSequence: number;
  provenance: { algorithm: "ECDSA-P256-SHA256"; keyID: string; publicKeyX963Base64: string; valueDERBase64: string };
  provenancePayload: string;
};

export class NativeManifestError extends Error {}

function strictBase64(value: string): Uint8Array {
  if (!value || value.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new NativeManifestError("Manifest provenance key or signature is not canonical base64.");
  let binary: string;
  try { binary = atob(value); } catch { throw new NativeManifestError("Manifest provenance key or signature is invalid base64."); }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function hexSha256(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer);
  return [...new Uint8Array(digest)].map((value) => value.toString(16).padStart(2, "0")).join("");
}

function record(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) return null;
  return value as Record<string, unknown>;
}

function text(source: Record<string, unknown>, key: string, maximum: number, required = false): string {
  const value = source[key];
  if (value === undefined || value === null) {
    if (required) throw new NativeManifestError(`Manifest field ${key} is required.`);
    return "";
  }
  if (typeof value !== "string") throw new NativeManifestError(`Manifest field ${key} must be text.`);
  const normalized = value.trim();
  const hasUnsafeControl = Array.from(normalized).some((character) => {
    const code = character.charCodeAt(0);
    return code < 32 && code !== 9 && code !== 10 && code !== 13;
  });
  if ((required && !normalized) || normalized.length > maximum || hasUnsafeControl) throw new NativeManifestError(`Manifest field ${key} is invalid.`);
  return normalized;
}

function integer(source: Record<string, unknown>, key: string, minimum: number, maximum: number): number {
  const value = source[key];
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) throw new NativeManifestError(`Manifest field ${key} is invalid.`);
  return Number(value);
}

function stringArray(source: Record<string, unknown>, key: string, maximumItems: number, maximumLength: number): string[] {
  const value = source[key];
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > maximumItems) throw new NativeManifestError(`Manifest field ${key} is invalid.`);
  const result = value.map((item) => {
    if (typeof item !== "string") throw new NativeManifestError(`Manifest field ${key} is invalid.`);
    const normalized = item.trim();
    if (!normalized || normalized.length > maximumLength) throw new NativeManifestError(`Manifest field ${key} is invalid.`);
    return normalized;
  });
  return Array.from(new Set(result));
}

function parseFindings(source: Record<string, unknown>): RedactionFinding[] {
  const value = source.redactionFindings;
  if (!Array.isArray(value) || value.length > redactionKinds.size) throw new NativeManifestError("Manifest redaction findings are invalid.");
  return value.map((item) => {
    const finding = record(item);
    if (!finding || Object.keys(finding).some((key) => !["kind", "count"].includes(key)) || !redactionKinds.has(finding.kind as RedactionKind) || !Number.isInteger(finding.count) || Number(finding.count) < 1 || Number(finding.count) > 1_000) {
      throw new NativeManifestError("Manifest redaction findings are invalid.");
    }
    return { kind: finding.kind as RedactionKind, count: Number(finding.count) };
  });
}

function parseMappings(source: Record<string, unknown>): NativeControlMapping[] {
  const value = source.mappedControls;
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value) || value.length > 100) throw new NativeManifestError("Manifest control mappings are invalid.");
  return value.map((item) => {
    const mapping = record(item);
    if (!mapping || Object.keys(mapping).some((key) => !["framework", "controlID", "relationship"].includes(key))) throw new NativeManifestError("Manifest control mappings are invalid.");
    return {
      framework: text(mapping, "framework", 100, true),
      controlID: text(mapping, "controlID", 80, true),
      relationship: text(mapping, "relationship", 80, true),
    };
  });
}

function parseProvenance(source: Record<string, unknown>): NativeCaptureManifest["provenance"] {
  const value = record(source.provenance);
  if (!value || Object.keys(value).some((key) => !["algorithm", "keyID", "publicKeyX963Base64", "valueDERBase64"].includes(key))) throw new NativeManifestError("Manifest provenance signature is invalid.");
  const algorithm = text(value, "algorithm", 32, true);
  const keyID = text(value, "keyID", 64, true).toLowerCase();
  const publicKeyX963Base64 = text(value, "publicKeyX963Base64", 128, true);
  const valueDERBase64 = text(value, "valueDERBase64", 128, true);
  if (algorithm !== "ECDSA-P256-SHA256" || !digestPattern.test(keyID)) throw new NativeManifestError("Manifest provenance signature is invalid.");
  return { algorithm, keyID, publicKeyX963Base64, valueDERBase64 };
}

function cleanJiraUrl(value: string, issueKey: string): boolean {
  if (!value) return !issueKey;
  try {
    const url = new URL(value);
    const host = url.hostname.toLowerCase();
    return Boolean(issueKey) && url.protocol === "https:" && host.endsWith(".atlassian.net") && host !== ".atlassian.net" && !url.port && !url.username && !url.password && !url.search && !url.hash && url.pathname === `/browse/${issueKey}`;
  } catch { return false; }
}

function cleanSourceUrl(value: string, sourceHost: string): boolean {
  if (!value) return !sourceHost;
  try {
    const url = new URL(value);
    if (!["http:", "https:"].includes(url.protocol) || !url.hostname || url.username || url.password || url.port || url.href.length > 2_048) return false;
    if (url.hostname.toLowerCase() !== sourceHost.toLowerCase()) return false;
    // Native evidence provenance is origin-only. A compromised client must not
    // be able to smuggle path, query, or fragment data across this boundary.
    return (url.pathname === "/" || url.pathname === "") && !url.search && !url.hash && (value === url.origin || value === `${url.origin}/`);
  } catch { return false; }
}

export function parseNativeManifest(bytes: Uint8Array): NativeCaptureManifest {
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); } catch { throw new NativeManifestError("Manifest must be valid UTF-8 JSON."); }
  const source = record(parsed);
  if (!source || Object.keys(source).some((key) => !allowedManifestKeys.has(key))) throw new NativeManifestError("Manifest schema contains unsupported fields.");
  if (source.schemaVersion !== 8) throw new NativeManifestError("Only signed schema-8 tenant-bound evidence can be uploaded. Recapture legacy evidence with the current Scopeproof Capture application.");
  const evidenceID = text(source, "evidenceID", 35, true);
  if (!evidenceIdPattern.test(evidenceID)) throw new NativeManifestError("Manifest evidence ID is invalid.");
  const capturedAt = text(source, "capturedAt", 64, true);
  const capturedMillis = Date.parse(capturedAt);
  const captureAge = Date.now() - capturedMillis;
  if (!Number.isFinite(capturedMillis) || captureAge < -MAXIMUM_FUTURE_CAPTURE_SKEW_MS || captureAge > MAXIMUM_NATIVE_CAPTURE_AGE_MS) {
    throw new NativeManifestError("Manifest capture time is outside the accepted upload window.");
  }
  const sha256 = text(source, "sha256", 64, true).toLowerCase();
  if (!digestPattern.test(sha256)) throw new NativeManifestError("Manifest image digest is invalid.");
  const safetyScanSha256 = text(source, "safetyScanSha256", 64, true).toLowerCase();
  if (safetyScanSha256 !== sha256) throw new NativeManifestError("Final-image safety scan is not bound to the uploaded screenshot digest.");
  const safetyScanPolicy = text(source, "safetyScanPolicy", 100, true);
  if (safetyScanPolicy !== "vision-ocr-sensitive-patterns-v1") throw new NativeManifestError("Manifest safety scanner policy is not supported.");
  const safetyScanCompletedAt = text(source, "safetyScanCompletedAt", 64, true);
  const scanMillis = Date.parse(safetyScanCompletedAt);
  if (!Number.isFinite(scanMillis) || Math.abs(scanMillis - capturedMillis) > 5 * 60_000) throw new NativeManifestError("Manifest safety scan time is invalid.");
  const safetyStatus = text(source, "safetyStatus", 16, true);
  if (safetyStatus !== "passed" && safetyStatus !== "redacted") throw new NativeManifestError("Manifest safety claim is invalid.");
  const jiraIssueKey = text(source, "jiraIssueKey", 80).toUpperCase();
  if (jiraIssueKey && !jiraIssuePattern.test(jiraIssueKey)) throw new NativeManifestError("Manifest Jira issue key is invalid.");
  const jiraIssueURL = text(source, "jiraIssueURL", 500);
  if (!cleanJiraUrl(jiraIssueURL, jiraIssueKey)) throw new NativeManifestError("Manifest Jira URL does not match its issue key.");
  const sourceURL = text(source, "sourceURL", 2_048);
  const sourceHost = text(source, "sourceHost", 253);
  if (!cleanSourceUrl(sourceURL, sourceHost)) throw new NativeManifestError("Manifest source URL is invalid or does not match its source host.");
  const tenantID = text(source, "tenantID", 64, true);
  const workspaceID = text(source, "workspaceID", 64, true);
  if (source.tenantID !== tenantID || source.workspaceID !== workspaceID ||
      !tenantBindingPattern.test(tenantID) || !tenantBindingPattern.test(workspaceID)) {
    throw new NativeManifestError("Manifest tenant or workspace binding is invalid.");
  }
  const chainPreviousHash = text(source, "chainPreviousHash", 128, true);
  const chainEventHash = text(source, "chainEventHash", 128, true);
  if ((chainPreviousHash !== "GENESIS" && !digestPattern.test(chainPreviousHash)) || !digestPattern.test(chainEventHash)) throw new NativeManifestError("Manifest capture-chain hashes are invalid.");
  const chainSequence = integer(source, "chainSequence", 1, 2_147_483_647);
  const provenance = parseProvenance(source);
  const unsignedManifest = { ...source };
  delete unsignedManifest.provenance;
  let provenancePayload: string;
  try { provenancePayload = stableJson(unsignedManifest); } catch { throw new NativeManifestError("Manifest provenance payload is not canonicalizable JSON."); }
  return {
    schemaVersion: 8,
    evidenceID,
    capturedAt,
    sourceURL,
    sourceHost,
    screenshotFilename: text(source, "screenshotFilename", 240, true),
    sha256,
    pixelWidth: integer(source, "pixelWidth", 1, 16_384),
    pixelHeight: integer(source, "pixelHeight", 1, 16_384),
    safetyStatus,
    redactionFindings: parseFindings(source),
    redactedRegions: integer(source, "redactedRegions", 0, 10_000),
    safetyScanSha256,
    safetyScanPolicy,
    safetyScanCompletedAt,
    sessionID: text(source, "sessionID", 96, true),
    sessionName: text(source, "sessionName", 160, true),
    controlID: text(source, "controlID", 80, true),
    title: text(source, "title", 180, true),
    system: text(source, "system", 180, true),
    environment: text(source, "environment", 80, true),
    assessmentPeriod: text(source, "assessmentPeriod", 80, true),
    description: text(source, "description", 2_000),
    complianceArea: text(source, "complianceArea", 100) || "PCI DSS 4.0.1",
    catalogVersion: text(source, "catalogVersion", 80),
    evidenceOwner: text(source, "evidenceOwner", 160),
    tags: stringArray(source, "tags", 30, 80),
    expectedEvidence: text(source, "expectedEvidence", 1_000),
    mappedControls: parseMappings(source),
    manualRedactions: source.manualRedactions === undefined || source.manualRedactions === null ? 0 : integer(source, "manualRedactions", 0, 10_000),
    jiraIssueKey,
    jiraIssueURL,
    tenantID,
    workspaceID,
    chainPreviousHash,
    chainEventHash,
    chainSequence,
    provenance,
    provenancePayload,
  };
}

export function derEcdsaToP1363(der: Uint8Array): Uint8Array {
  if (der.length < 8 || der.length > 72 || der[0] !== 0x30 || der[1] !== der.length - 2) throw new NativeManifestError("Manifest provenance signature encoding is invalid.");
  let offset = 2;
  const readInteger = (): Uint8Array => {
    if (der[offset] !== 0x02) throw new NativeManifestError("Manifest provenance signature encoding is invalid.");
    const length = der[offset + 1];
    offset += 2;
    if (!length || length > 33 || offset + length > der.length) throw new NativeManifestError("Manifest provenance signature encoding is invalid.");
    let value = der.subarray(offset, offset + length);
    offset += length;
    if (value[0] === 0) {
      // DER requires one sign byte whenever the minimal unsigned magnitude starts
      // with a high bit, including magnitudes shorter than the curve width.
      if (value.length < 2 || (value[1] & 0x80) === 0) throw new NativeManifestError("Manifest provenance signature encoding is invalid.");
      value = value.subarray(1);
    } else if ((value[0] & 0x80) !== 0) {
      // Reject negative INTEGERs and positive values missing their sign padding.
      throw new NativeManifestError("Manifest provenance signature encoding is invalid.");
    }
    if (value.length > 32 || value.every((byte) => byte === 0)) throw new NativeManifestError("Manifest provenance signature encoding is invalid.");
    const padded = new Uint8Array(32);
    padded.set(value, 32 - value.length);
    return padded;
  };
  const r = readInteger();
  const s = readInteger();
  if (offset !== der.length) throw new NativeManifestError("Manifest provenance signature encoding is invalid.");
  const signature = new Uint8Array(64);
  signature.set(r, 0);
  signature.set(s, 32);
  return signature;
}

export async function verifyNativeManifestProvenance(manifest: NativeCaptureManifest): Promise<boolean> {
  try {
    const publicKeyBytes = strictBase64(manifest.provenance.publicKeyX963Base64);
    if (publicKeyBytes.length !== 65 || publicKeyBytes[0] !== 0x04 || await hexSha256(publicKeyBytes) !== manifest.provenance.keyID) return false;
    const publicKey = await crypto.subtle.importKey("raw", publicKeyBytes.buffer as ArrayBuffer, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    const der = strictBase64(manifest.provenance.valueDERBase64);
    const signature = derEcdsaToP1363(der);
    const domain = "scopeproof-local-capture-manifest-v1";
    const payload = encoder.encode(manifest.provenancePayload);
    const prefix = encoder.encode(`${encoder.encode(domain).byteLength}:${domain}\n${payload.byteLength}:`);
    const signed = new Uint8Array(prefix.byteLength + payload.byteLength);
    signed.set(prefix, 0);
    signed.set(payload, prefix.byteLength);
    return await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, publicKey, signature.buffer as ArrayBuffer, signed.buffer as ArrayBuffer);
  } catch {
    return false;
  }
}

function u32(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] * 0x1000000) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3]) >>> 0;
}

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let value = 0; value < table.length; value += 1) {
    let crc = value;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
    table[value] = crc >>> 0;
  }
  return table;
})();

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ byte) & 0xff];
  return (crc ^ 0xffffffff) >>> 0;
}

export async function validatePng(bytes: Uint8Array): Promise<{ width: number; height: number }> {
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length < 57 || signature.some((value, index) => bytes[index] !== value)) throw new NativeManifestError("Screenshot is not a valid PNG.");
  let offset = 8;
  let width = 0;
  let height = 0;
  let bitsPerPixel = 0;
  let colorType = -1;
  let sawHeader = false;
  let sawPalette = false;
  let sawData = false;
  let endedData = false;
  let sawEnd = false;
  let chunkCount = 0;
  let ancillaryBytes = 0;
  let compressedLength = 0;
  const idat: Uint8Array[] = [];
  while (offset < bytes.length) {
    chunkCount += 1;
    if (chunkCount > 4_096) throw new NativeManifestError("PNG contains too many chunks.");
    if (bytes.length - offset < 12) throw new NativeManifestError("PNG chunk framing is truncated.");
    const length = u32(bytes, offset);
    if (length > 15 * 1024 * 1024 || length + 12 > bytes.length - offset) throw new NativeManifestError("PNG chunk length is invalid.");
    const typeBytes = bytes.subarray(offset + 4, offset + 8);
    const type = new TextDecoder("ascii", { fatal: true }).decode(typeBytes);
    const data = bytes.subarray(offset + 8, offset + 8 + length);
    const expectedCrc = u32(bytes, offset + 8 + length);
    const crcInput = bytes.subarray(offset + 4, offset + 8 + length);
    if (crc32(crcInput) !== expectedCrc) throw new NativeManifestError("PNG chunk checksum is invalid.");
    if (!sawHeader && type !== "IHDR") throw new NativeManifestError("PNG header must be the first chunk.");
    if (type === "IHDR") {
      if (sawHeader || length !== 13) throw new NativeManifestError("PNG header is invalid.");
      sawHeader = true;
      width = u32(data, 0);
      height = u32(data, 4);
      const depth = data[8];
      colorType = data[9];
      const channels = colorType === 0 ? 1 : colorType === 2 ? 3 : colorType === 3 ? 1 : colorType === 4 ? 2 : colorType === 6 ? 4 : 0;
      const allowedDepths: Record<number, number[]> = { 0: [1, 2, 4, 8, 16], 2: [8, 16], 3: [1, 2, 4, 8], 4: [8, 16], 6: [8, 16] };
      if (!width || !height || width > 16_384 || height > 16_384 || width * height > 16_000_000 || !channels || !allowedDepths[colorType]?.includes(depth) || data[10] !== 0 || data[11] !== 0 || data[12] !== 0) throw new NativeManifestError("PNG dimensions or encoding are not supported.");
      bitsPerPixel = channels * depth;
    } else if (type === "PLTE") {
      if (sawPalette || sawData || [0, 4].includes(colorType) || length < 3 || length > 768 || length % 3 !== 0) throw new NativeManifestError("PNG palette is invalid or out of order.");
      sawPalette = true;
    } else if (type === "IDAT") {
      if (!sawHeader || sawEnd || endedData || (colorType === 3 && !sawPalette)) throw new NativeManifestError("PNG image data is out of order.");
      sawData = true;
      compressedLength += data.byteLength;
      if (compressedLength > 15 * 1024 * 1024) throw new NativeManifestError("PNG compressed image data exceeds the capture limit.");
      idat.push(data);
    } else if (type === "IEND") {
      if (!sawData || sawEnd || length !== 0) throw new NativeManifestError("PNG end marker is invalid.");
      sawEnd = true;
      offset += length + 12;
      if (offset !== bytes.length) throw new NativeManifestError("PNG contains trailing data.");
      break;
    } else if ((typeBytes[0] & 0x20) === 0) {
      throw new NativeManifestError("PNG contains an unsupported critical chunk.");
    } else {
      ancillaryBytes += data.byteLength;
      if (ancillaryBytes > 1024 * 1024) throw new NativeManifestError("PNG ancillary metadata exceeds the capture limit.");
    }
    if (sawData && type !== "IDAT" && type !== "IEND") endedData = true;
    offset += length + 12;
  }
  if (!sawHeader || !sawData || !sawEnd) throw new NativeManifestError("PNG is incomplete.");
  const rowBytes = Math.ceil(width * bitsPerPixel / 8);
  const expectedInflated = (rowBytes + 1) * height;
  if (expectedInflated > 64 * 1024 * 1024) throw new NativeManifestError("PNG decoded size exceeds the capture limit.");
  let inflatedLength = 0;
  let nextFilterOffset = 0;
  try {
    const compressedStream = new ReadableStream<BufferSource>({
      start(controller) {
        for (const chunk of idat) controller.enqueue(chunk as Uint8Array<ArrayBuffer>);
        controller.close();
      },
    });
    const stream = compressedStream.pipeThrough(new DecompressionStream("deflate"));
    for await (const chunk of stream as unknown as AsyncIterable<Uint8Array>) {
      const chunkStart = inflatedLength;
      inflatedLength += chunk.byteLength;
      if (inflatedLength > expectedInflated) throw new NativeManifestError("PNG expands beyond its declared dimensions.");
      while (nextFilterOffset < inflatedLength) {
        const index = nextFilterOffset - chunkStart;
        if (index < 0 || index >= chunk.byteLength || chunk[index] > 4) throw new NativeManifestError("PNG uses an invalid scanline filter.");
        nextFilterOffset += rowBytes + 1;
      }
    }
  } catch (error) {
    if (error instanceof NativeManifestError) throw error;
    throw new NativeManifestError("PNG image data cannot be decoded.");
  }
  if (inflatedLength !== expectedInflated || nextFilterOffset !== expectedInflated) throw new NativeManifestError("PNG decoded size does not match its dimensions.");
  return { width, height };
}
