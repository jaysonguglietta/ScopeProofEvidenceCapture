import assert from "node:assert/strict";
import test from "node:test";
import { NativeManifestError, parseNativeManifest, validatePng } from "../lib/server/native-manifest.ts";

function manifest(overrides: Record<string, unknown> = {}): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    schemaVersion: 5,
    evidenceID: "EV-0123456789",
    capturedAt: new Date().toISOString(),
    localTimestamp: "2026-08-11 16:00:00 EDT",
    timezone: "America/New_York",
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
    chainPreviousHash: "GENESIS",
    chainEventHash: "b".repeat(64),
    ...overrides,
  }));
}

test("native manifest parser accepts the versioned schema and rejects ambiguity", () => {
  const parsed = parseNativeManifest(manifest());
  assert.equal(parsed.schemaVersion, 5);
  assert.equal(parsed.controlID, "8.3.1");
  assert.throws(() => parseNativeManifest(manifest({ unsupported: true })), NativeManifestError);
  assert.throws(() => parseNativeManifest(manifest({ safetyStatus: "passed", pixelWidth: 20_000 })), NativeManifestError);
  assert.throws(() => parseNativeManifest(manifest({ jiraIssueKey: "PCI-12", jiraIssueURL: "https://evil.example/browse/PCI-12" })), NativeManifestError);
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
