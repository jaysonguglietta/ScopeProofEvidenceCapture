import assert from "node:assert/strict";
import test from "node:test";

import { stableJson, type JsonValue } from "../lib/aws-runtime/contracts.ts";
import { verifyDeviceUploadManifest, type DeviceUploadManifest } from "../lib/aws-runtime/evidence/device-upload-manifest.ts";
import type { VerifiedCognitoAccessToken } from "../lib/aws-runtime/http/jwt.ts";
import type { TenantActor } from "../lib/aws-runtime/tenancy.ts";

const TENANT = `ten_${"a".repeat(32)}`;
const USER = `usr_${"b".repeat(32)}`;
const DEVICE = `dev_${"c".repeat(32)}`;
const ASSESSMENT = `asm_${"d".repeat(32)}`;
const EVIDENCE = `evd_${"e".repeat(32)}`;
const NONCE = "N".repeat(43);

function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

test("device upload manifests bind the Cognito challenge, nonce, sequence, request facts, and enrolled P-256 key", async () => {
  const keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicKeySpki = toBase64(new Uint8Array(await crypto.subtle.exportKey("spki", keys.publicKey)));
  const manifest: DeviceUploadManifest = {
    schemaVersion: 1,
    tenantId: TENANT,
    userId: USER,
    deviceId: DEVICE,
    assessmentId: ASSESSMENT,
    controlId: "PCI-DSS-10.2.1",
    evidenceId: EVIDENCE,
    expectedSha256: "f".repeat(64),
    expectedSize: 4096,
    contentType: "image/png",
    capturedAt: "2026-08-27T16:00:00.000Z",
    challenge: "token-id-12345678",
    nonce: NONCE,
    sequence: 42,
    signedAt: "2026-08-27T16:00:01.000Z",
  };
  const canonical = stableJson(manifest as unknown as JsonValue);
  const signature = toBase64Url(new Uint8Array(await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    keys.privateKey,
    new TextEncoder().encode(`scopeproof-device-upload-manifest-v1\n${canonical}`),
  )));
  const actor: TenantActor = {
    tenantId: TENANT as TenantActor["tenantId"],
    tenantHostname: "api-acme.example.com" as TenantActor["tenantHostname"],
    userId: USER as TenantActor["userId"],
    membershipId: `mem_${"1".repeat(32)}` as TenantActor["membershipId"],
    subject: "cognito-subject-12345678",
    role: "collector",
  };
  const identity: VerifiedCognitoAccessToken = {
    signatureVerified: true,
    issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_example",
    subject: actor.subject,
    clientId: "client-12345678",
    tokenUse: "access",
    issuedAt: "2026-08-27T15:59:00.000Z",
    authenticatedAt: "2026-08-27T15:59:00.000Z",
    expiresAt: "2026-08-27T16:14:00.000Z",
    scopes: ["scopeproof/evidence.collect"],
    jwtId: manifest.challenge,
  };
  const base = {
    actor,
    identity,
    manifest,
    publicKeySpki,
    signature,
    request: {
      idempotencyKey: NONCE,
      deviceId: DEVICE,
      assessmentId: ASSESSMENT,
      controlId: manifest.controlId,
      evidenceId: EVIDENCE,
      expectedSha256: manifest.expectedSha256,
      expectedSize: manifest.expectedSize,
      contentType: manifest.contentType,
      capturedAt: manifest.capturedAt,
    },
    now: new Date("2026-08-27T16:00:02.000Z"),
  } as const;
  const proof = await verifyDeviceUploadManifest(base);
  assert.equal(proof.sequence, 42);
  assert.equal(proof.canonicalManifest, canonical);
  assert.equal(proof.signature, signature);
  assert.match(proof.publicKeySha256, /^[a-f0-9]{64}$/);
  assert.match(proof.challengeDigest, /^[a-f0-9]{64}$/);
  assert.match(proof.nonceDigest, /^[a-f0-9]{64}$/);

  await assert.rejects(
    verifyDeviceUploadManifest({ ...base, request: { ...base.request, evidenceId: `evd_${"9".repeat(32)}` } }),
    /does not match/,
  );
  await assert.rejects(
    verifyDeviceUploadManifest({ ...base, manifest: { ...manifest, sequence: 43 } }),
    /signature is invalid/,
  );
});
