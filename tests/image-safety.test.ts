import assert from "node:assert/strict";
import test from "node:test";
import { EvidenceSafetyScanError, evidenceSafetyReceiptSha256, evidenceSafetyScannerEndpoint, scanExactEvidencePixels } from "../lib/server/image-safety.ts";
import type { ScopeproofEnv } from "../lib/server/env.ts";

const png = Uint8Array.from(Buffer.from("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=", "base64"));
const env = {
  BROWSER_OCR_ENDPOINT: "https://scanner.example.test/v1/scan",
  BROWSER_OCR_ALLOWED_HOSTS: "scanner.example.test",
  BROWSER_OCR_TOKEN: "test-token-not-a-secret",
} as ScopeproofEnv;

test("independent screenshot scanner is exact-host, digest-bound, and fail-closed", async () => {
  assert.equal(evidenceSafetyScannerEndpoint(env).toString(), "https://scanner.example.test/v1/scan");
  for (const unsafe of [
    { ...env, BROWSER_OCR_ENDPOINT: "http://scanner.example.test/v1/scan" },
    { ...env, BROWSER_OCR_ENDPOINT: "https://scanner.example.test/v1/scan?redirect=evil" },
    { ...env, BROWSER_OCR_ENDPOINT: "https://other.example.test/v1/scan" },
    { ...env, BROWSER_OCR_ALLOWED_HOSTS: "scanner.example.test,127.0.0.1" },
  ]) assert.throws(() => evidenceSafetyScannerEndpoint(unsafe), EvidenceSafetyScanError);

  const originalFetch = globalThis.fetch;
  let responseMode: "safe" | "sensitive" | "mismatch" = "safe";
  globalThis.fetch = async (input, init) => {
    assert.equal(String(input), "https://scanner.example.test/v1/scan");
    assert.equal(new Headers(init?.headers).get("authorization"), "Bearer test-token-not-a-secret");
    const body = JSON.parse(String(init?.body)) as { version: number; sha256: string; contentType: string; imageBase64: string };
    assert.equal(body.version, 1);
    assert.equal(body.contentType, "image/png");
    assert.deepEqual(Uint8Array.from(Buffer.from(body.imageBase64, "base64")), png);
    const result = responseMode === "sensitive"
      ? { sha256: body.sha256, text: "authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signaturevalue", policyVersion: "ocr-dlp-v2" }
      : { sha256: responseMode === "mismatch" ? "0".repeat(64) : body.sha256, text: "MFA policy enabled for administrators", policyVersion: "ocr-dlp-v2" };
    return new Response(JSON.stringify(result), { status: 200, headers: { "content-type": "application/json" } });
  };
  try {
    const scan = await scanExactEvidencePixels(png, env);
    assert.match(scan.digest, /^[a-f0-9]{64}$/);
    assert.equal(scan.policy, "ocr-dlp-v2");
    assert.equal(scan.scannerOrigin, "https://scanner.example.test");
    assert.match(scan.receiptSha256, /^[a-f0-9]{64}$/);
    assert.equal(await evidenceSafetyReceiptSha256(scan), scan.receiptSha256);
    assert.notEqual(await evidenceSafetyReceiptSha256({ ...scan, policy: "tampered-policy" }), scan.receiptSha256);
    responseMode = "sensitive";
    await assert.rejects(scanExactEvidencePixels(png, env), (error: unknown) => error instanceof EvidenceSafetyScanError && error.code === "SENSITIVE_CONTENT");
    responseMode = "mismatch";
    await assert.rejects(scanExactEvidencePixels(png, env), (error: unknown) => error instanceof EvidenceSafetyScanError && error.code === "INVALID_RESPONSE");
  } finally {
    globalThis.fetch = originalFetch;
  }
});
