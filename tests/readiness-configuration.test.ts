import assert from "node:assert/strict";
import test from "node:test";
import { validateBootstrapAdministratorAllowlist, validateTrustedApplicationOrigins } from "../lib/server/identity-config.ts";
import {
  validateAuditCheckpointConfiguration,
  validateSecurityMonitoringConfiguration,
  validateTrustedTimestampConfiguration,
} from "../lib/server/external-trust-config.ts";
import type { ScopeproofEnv } from "../lib/server/env.ts";
import { validateEvidenceSafetyScannerConfiguration } from "../lib/server/image-safety-config.ts";

async function publicKeySpkiBase64(): Promise<string> {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"],
  ) as CryptoKeyPair;
  return Buffer.from(await crypto.subtle.exportKey("spki", pair.publicKey)).toString("base64");
}

function env(values: Partial<ScopeproofEnv>): ScopeproofEnv {
  return values as ScopeproofEnv;
}

test("legacy runtime readiness uses the same exact-origin and bootstrap parsers as requests", () => {
  assert.deepEqual([...validateTrustedApplicationOrigins("https://scopeproof.example")], ["https://scopeproof.example"]);
  for (const value of [
    "https://one.example,https://two.example",
    "http://scopeproof.example",
    "https://user:password@scopeproof.example",
    "https://scopeproof.example/path",
    "https://scopeproof.example?query=1",
  ]) assert.throws(() => validateTrustedApplicationOrigins(value), /trusted application origin|safely configured/i);
  assert.deepEqual([...validateTrustedApplicationOrigins("http://localhost:3000")], ["http://localhost:3000"]);
  assert.throws(
    () => validateTrustedApplicationOrigins("http://localhost:3000", { allowLoopbackHttp: false }),
    /safely configured/i,
  );

  assert.deepEqual([...validateBootstrapAdministratorAllowlist("security@example.com")], ["security@example.com"]);
  for (const value of ["", "*@example.com", "not-an-email", `${"a".repeat(250)}@example.com`]) {
    assert.throws(() => validateBootstrapAdministratorAllowlist(value), /bootstrap allowlist/i);
  }
});

test("screenshot scanner configuration rejects unsafe authorization tokens", () => {
  const configured = env({
    BROWSER_OCR_ENDPOINT: "https://scanner.example/v1/scan",
    BROWSER_OCR_ALLOWED_HOSTS: "scanner.example",
    BROWSER_OCR_TOKEN: "short-lived-scanner-token",
  });
  assert.deepEqual(validateEvidenceSafetyScannerConfiguration(configured), { origin: "https://scanner.example" });
  for (const token of ["short", " token-with-leading-space", "token-with-newline\nvalue", "x".repeat(4_097)]) {
    assert.throws(
      () => validateEvidenceSafetyScannerConfiguration(env({ ...configured, BROWSER_OCR_TOKEN: token })),
      /BROWSER_OCR_TOKEN/,
    );
  }
});

test("checkpoint readiness validates the exact HTTPS boundary and receipt key before the first audit event", async () => {
  const publicKey = await publicKeySpkiBase64();
  const configured = env({
    AUDIT_CHECKPOINT_ENDPOINT: "https://witness.example/v1/checkpoints",
    AUDIT_CHECKPOINT_ALLOWED_HOSTS: "witness.example",
    AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY: publicKey,
  });
  assert.deepEqual(await validateAuditCheckpointConfiguration(configured), { origin: "https://witness.example" });
  await assert.rejects(
    validateAuditCheckpointConfiguration(env({ ...configured, AUDIT_CHECKPOINT_ENDPOINT: "http://witness.example/v1/checkpoints" })),
    /allowed HTTPS host/,
  );
  await assert.rejects(
    validateAuditCheckpointConfiguration(env({ ...configured, AUDIT_CHECKPOINT_ALLOWED_HOSTS: "other.example" })),
    /allowed HTTPS host/,
  );
  await assert.rejects(
    validateAuditCheckpointConfiguration(env({ ...configured, AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY: "not-base64" })),
    /P-256 SPKI public key/,
  );
  for (const token of ["short", " token-with-leading-space", "token-with-newline\nvalue", "x".repeat(4_097)]) {
    await assert.rejects(
      validateAuditCheckpointConfiguration(env({ ...configured, AUDIT_CHECKPOINT_TOKEN: token })),
      /AUDIT_CHECKPOINT_TOKEN/,
    );
  }
});

test("security monitoring readiness rejects unsafe endpoints and header tokens", () => {
  const configured = env({
    SECURITY_EVENT_ENDPOINT: "https://monitor.example/v1/events",
    SECURITY_EVENT_ALLOWED_HOSTS: "monitor.example",
    SECURITY_EVENT_TOKEN: "short-lived-monitor-token",
  });
  assert.deepEqual(validateSecurityMonitoringConfiguration(configured), { origin: "https://monitor.example" });
  for (const environment of [
    env({ ...configured, SECURITY_EVENT_TOKEN: undefined }),
    env({ ...configured, SECURITY_EVENT_ENDPOINT: "http://monitor.example/v1/events" }),
    env({ ...configured, SECURITY_EVENT_ALLOWED_HOSTS: "other.example" }),
    env({ ...configured, SECURITY_EVENT_TOKEN: "short" }),
    env({ ...configured, SECURITY_EVENT_TOKEN: "token-with-newline\nvalue" }),
  ]) assert.throws(() => validateSecurityMonitoringConfiguration(environment), /HTTPS host|SECURITY_EVENT_TOKEN/);
});

test("timestamp readiness validates endpoints, verifier keys, token, and trust anchors without network access", async () => {
  const publicKey = await publicKeySpkiBase64();
  const configured = env({
    RFC3161_TSA_URL: "https://tsa.example/v1/timestamp",
    RFC3161_VERIFIER_URL: "https://verifier.example/v1/verify",
    RFC3161_VERIFIER_ALLOWED_HOSTS: "verifier.example",
    RFC3161_VERIFIER_TOKEN: "short-lived-verifier-token",
    RFC3161_VERIFIER_PUBLIC_KEYS: publicKey,
    RFC3161_TSA_TRUST_ANCHOR_SHA256: "a".repeat(64),
  });
  assert.deepEqual(await validateTrustedTimestampConfiguration(configured), {
    tsaOrigin: "https://tsa.example",
    verifierOrigin: "https://verifier.example",
    verifierKeyCount: 1,
    trustAnchorCount: 1,
  });
  await assert.rejects(
    validateTrustedTimestampConfiguration(env({ ...configured, RFC3161_TSA_URL: "http://tsa.example/v1/timestamp" })),
    /HTTPS host/,
  );
  await assert.rejects(
    validateTrustedTimestampConfiguration(env({ ...configured, RFC3161_VERIFIER_ALLOWED_HOSTS: "other.example" })),
    /allowed HTTPS host/,
  );
  await assert.rejects(
    validateTrustedTimestampConfiguration(env({ ...configured, RFC3161_VERIFIER_PUBLIC_KEYS: "not-base64" })),
    /P-256 SPKI public key/,
  );
  await assert.rejects(
    validateTrustedTimestampConfiguration(env({ ...configured, RFC3161_TSA_TRUST_ANCHOR_SHA256: "abcd" })),
    /trust-anchor fingerprints/,
  );
  await assert.rejects(
    validateTrustedTimestampConfiguration(env({ ...configured, RFC3161_VERIFIER_TOKEN: "token\nvalue" })),
    /TOKEN is missing or invalid/,
  );
});
