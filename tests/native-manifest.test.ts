import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { derEcdsaToP1363, NativeManifestError, parseNativeManifest, validatePng, verifyNativeManifestProvenance } from "../lib/server/native-manifest.ts";
import { stableJson } from "../lib/server/canonical-json.ts";

function manifest(overrides: Record<string, unknown> = {}): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    schemaVersion: 8,
    evidenceID: "EV-0123456789",
    capturedAt: new Date().toISOString(),
    localTimestamp: "2026-08-11 16:00:00 EDT",
    timezone: "America/New_York",
    sourceURL: "https://admin.example.com",
    sourceHost: "admin.example.com",
    browser: "Safari",
    windowTitle: "Evidence",
    screenshotFilename: "capture.png",
    sha256: "a".repeat(64),
    pixelWidth: 1,
    pixelHeight: 1,
    captureMethod: "ScreenCaptureKit",
    timestampAuthority: "Local clock",
    safetyStatus: "passed",
    redactionFindings: [],
    redactedRegions: 0,
    safetyScanSha256: "a".repeat(64),
    safetyScanPolicy: "vision-ocr-sensitive-patterns-v1",
    safetyScanCompletedAt: new Date().toISOString(),
    sessionID: "session-1",
    sessionName: "PCI review",
    controlID: "8.3.1",
    title: "Authentication evidence",
    system: "Production portal",
    environment: "Production",
    assessmentPeriod: "2026 Q3",
    description: "MFA configuration",
    complianceArea: "PCI DSS 4.0.1",
    catalogVersion: "2026.08",
    evidenceOwner: "Security",
    tags: ["mfa"],
    expectedEvidence: "MFA policy",
    mappedControls: [],
    manualRedactions: 0,
    tenantID: "customer-a",
    workspaceID: "pci-2026",
    chainPreviousHash: "GENESIS",
    chainEventHash: "b".repeat(64),
    chainSequence: 1,
    provenance: { algorithm: "ECDSA-P256-SHA256", keyID: "c".repeat(64), publicKeyX963Base64: "BA==", valueDERBase64: "MAYCAQECAQE=" },
    ...overrides,
  }));
}

test("native ingestion compares signed schema-8 binding to the isolated deployment", async () => {
  const [route, uploader] = await Promise.all([
    readFile(new URL("../app/api/native/evidence/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../macos/ScopeproofCapture/Sources/ScopeproofCapture/UploadService.swift", import.meta.url), "utf8"),
  ]);
  assert.match(route, /validateLegacyTenantBinding\(getEnv\(\)\.LEGACY_TENANT_ID, getEnv\(\)\.LEGACY_WORKSPACE_ID\)/);
  assert.match(route, /manifest\.tenantID !== expectedBinding\.tenantID/);
  assert.match(route, /manifest\.workspaceID !== expectedBinding\.workspaceID/);
  assert.ok(route.indexOf("manifest.tenantID !== expectedBinding.tenantID") < route.indexOf("scanExactEvidencePixels(image"));
  assert.match(uploader, /guard manifestModel\.schemaVersion == 8 else \{ throw UploadFailure\.hostedSchemaRequired \}/);
});

test("native manifest parser accepts schema-8 tenant binding and rejects ambiguity", () => {
  const parsed = parseNativeManifest(manifest());
  assert.equal(parsed.schemaVersion, 8);
  assert.equal(parsed.controlID, "8.3.1");
  assert.equal(parsed.sourceURL, "https://admin.example.com");
  assert.deepEqual({ tenantID: parsed.tenantID, workspaceID: parsed.workspaceID }, { tenantID: "customer-a", workspaceID: "pci-2026" });
  assert.throws(() => parseNativeManifest(manifest({ unsupported: true })), NativeManifestError);
  assert.throws(() => parseNativeManifest(manifest({ safetyStatus: "passed", pixelWidth: 20_000 })), NativeManifestError);
  assert.throws(() => parseNativeManifest(manifest({ safetyScanSha256: "c".repeat(64) })), /not bound/);
  assert.throws(() => parseNativeManifest(manifest({ jiraIssueKey: "PCI-12", jiraIssueURL: "https://evil.example/browse/PCI-12" })), NativeManifestError);
  assert.throws(() => parseNativeManifest(manifest({ sourceURL: "https://admin.example.com/settings", sourceHost: "evil.example" })), NativeManifestError);
  assert.throws(() => parseNativeManifest(manifest({ sourceURL: "https://admin.example.com/settings", sourceHost: "admin.example.com" })), NativeManifestError);
  assert.throws(() => parseNativeManifest(manifest({ sourceURL: "https://admin.example.com/settings?token=secret-value", sourceHost: "admin.example.com" })), NativeManifestError);
  assert.throws(() => parseNativeManifest(manifest({ schemaVersion: 7 })), /schema-8/);
  assert.throws(() => parseNativeManifest(manifest({ tenantID: "Customer A" })), /tenant or workspace/);
  assert.throws(() => parseNativeManifest(manifest({ tenantID: " customer-a" })), /tenant or workspace/);
  assert.throws(() => parseNativeManifest(manifest({ workspaceID: "../other" })), /tenant or workspace/);
  assert.throws(() => parseNativeManifest(manifest({ tenantID: undefined })), /tenantID is required/);
});

function p1363ToDer(signature: Uint8Array): Uint8Array {
  const integer = (value: Uint8Array): Uint8Array => {
    let offset = 0;
    while (offset < value.length - 1 && value[offset] === 0) offset += 1;
    const body = value.subarray(offset);
    const prefix = (body[0] & 0x80) !== 0 ? 1 : 0;
    const result = new Uint8Array(2 + prefix + body.length);
    result[0] = 0x02;
    result[1] = prefix + body.length;
    if (prefix) result[2] = 0;
    result.set(body, 2 + prefix);
    return result;
  };
  const r = integer(signature.subarray(0, 32));
  const s = integer(signature.subarray(32));
  const der = new Uint8Array(2 + r.length + s.length);
  der[0] = 0x30;
  der[1] = r.length + s.length;
  der.set(r, 2);
  der.set(s, 2 + r.length);
  return der;
}

test("ECDSA DER parser accepts required short sign padding and rejects non-canonical integers", () => {
  const shortSignPadding = Uint8Array.of(0x30, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01);
  const converted = derEcdsaToP1363(shortSignPadding);
  assert.equal(converted.byteLength, 64);
  assert.equal(converted[31], 0x80);
  assert.equal(converted[63], 0x01);
  assert.ok(converted.subarray(0, 31).every((value) => value === 0));
  assert.ok(converted.subarray(32, 63).every((value) => value === 0));

  const shortSignPaddingInS = derEcdsaToP1363(Uint8Array.of(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80));
  assert.equal(shortSignPaddingInS[31], 0x01);
  assert.equal(shortSignPaddingInS[63], 0x80);

  const fullWidthInteger = Uint8Array.of(0x02, 0x21, 0x00, 0x80, ...new Uint8Array(31));
  const maximumLengthSignature = new Uint8Array(72);
  maximumLengthSignature.set([0x30, 0x46]);
  maximumLengthSignature.set(fullWidthInteger, 2);
  maximumLengthSignature.set(fullWidthInteger, 2 + fullWidthInteger.byteLength);
  const maximumConverted = derEcdsaToP1363(maximumLengthSignature);
  assert.equal(maximumConverted[0], 0x80);
  assert.equal(maximumConverted[32], 0x80);

  assert.throws(
    () => derEcdsaToP1363(Uint8Array.of(0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01)),
    NativeManifestError,
  );
  assert.throws(
    () => derEcdsaToP1363(Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01)),
    NativeManifestError,
  );
  assert.throws(
    () => derEcdsaToP1363(Uint8Array.of(0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01)),
    NativeManifestError,
  );
  assert.throws(
    () => derEcdsaToP1363(Uint8Array.of(0x30, 0x08, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x01, 0x00)),
    NativeManifestError,
  );
});

test("schema-8 device provenance binds the exact tenant and workspace", async () => {
  const unsigned = JSON.parse(new TextDecoder().decode(manifest())) as Record<string, unknown>;
  delete unsigned.provenance;
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", keys.publicKey));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey));
  const keyID = [...digest].map((value) => value.toString(16).padStart(2, "0")).join("");
  const payload = new TextEncoder().encode(stableJson(unsigned));
  const domain = "scopeproof-local-capture-manifest-v1";
  const prefix = new TextEncoder().encode(`${domain.length}:${domain}\n${payload.byteLength}:`);
  const signed = new Uint8Array(prefix.byteLength + payload.byteLength);
  signed.set(prefix); signed.set(payload, prefix.byteLength);
  let p1363: Uint8Array | null = null;
  for (let attempt = 0; attempt < 64; attempt += 1) {
    const candidate = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, signed));
    assert.equal(candidate.byteLength, 64, "P-256 WebCrypto signatures must use fixed-width IEEE-P1363 encoding");
    if ((candidate[0] & 0x80) !== 0 || (candidate[32] & 0x80) !== 0) { p1363 = candidate; break; }
  }
  assert.ok(p1363, "test fixture should exercise DER's required positive-integer sign padding");
  unsigned.provenance = {
    algorithm: "ECDSA-P256-SHA256", keyID,
    publicKeyX963Base64: Buffer.from(publicKey).toString("base64"),
    valueDERBase64: Buffer.from(p1363ToDer(p1363)).toString("base64"),
  };
  const parsed = parseNativeManifest(new TextEncoder().encode(JSON.stringify(unsigned)));
  assert.equal(await verifyNativeManifestProvenance(parsed), true);
  const tampered = parseNativeManifest(new TextEncoder().encode(JSON.stringify({ ...unsigned, title: "Tampered after signing" })));
  assert.equal(await verifyNativeManifestProvenance(tampered), false);
  const rebound = parseNativeManifest(new TextEncoder().encode(JSON.stringify({ ...unsigned, workspaceID: "other-workspace" })));
  assert.equal(await verifyNativeManifestProvenance(rebound), false);
});

test("PNG validator decodes image data and rejects CRC/trailing-data tampering", async () => {
  const valid = Uint8Array.from(Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64"));
  assert.deepEqual(await validatePng(valid), { width: 1, height: 1 });
  const badCrc = valid.slice();
  badCrc[20] ^= 1;
  await assert.rejects(validatePng(badCrc), /checksum|encoding|dimensions/);
  const trailing = new Uint8Array(valid.length + 1);
  trailing.set(valid);
  await assert.rejects(validatePng(trailing), /trailing data/);
});

test("PNG validator rejects aggregate ancillary metadata before decompression", async () => {
  const valid = Uint8Array.from(Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64"));
  const data = new Uint8Array(1024 * 1024 + 1);
  const type = new TextEncoder().encode("tEXt");
  const crcInput = new Uint8Array(type.length + data.length);
  crcInput.set(type); crcInput.set(data, type.length);
  let crc = 0xffffffff;
  for (const byte of crcInput) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0);
  }
  crc = (crc ^ 0xffffffff) >>> 0;
  const chunk = new Uint8Array(12 + data.length);
  new DataView(chunk.buffer).setUint32(0, data.length);
  chunk.set(type, 4); chunk.set(data, 8); new DataView(chunk.buffer).setUint32(8 + data.length, crc);
  const oversized = new Uint8Array(valid.length + chunk.length);
  oversized.set(valid.subarray(0, 33)); oversized.set(chunk, 33); oversized.set(valid.subarray(33), 33 + chunk.length);
  await assert.rejects(validatePng(oversized), /ancillary metadata/);
});
