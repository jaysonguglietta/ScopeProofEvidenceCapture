#!/usr/bin/env node

import { ECDH, createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const keyIdPattern = /^[A-Za-z0-9._-]{1,64}$/;
const exactFields = ["keyId", "notAfter", "notBefore", "publicKeyX963Base64"];
const exactEnvelopeFields = ["manifest", "publicKeySpkiSha256", "publicKeyX963Base64", "releaseArtifact", "signatureDERBase64"];
const exactManifestFields = ["byteSize", "designatedRequirement", "downloadUrl", "expiresAt", "keyId", "minimumSystemVersion", "notes", "publishedAt", "schemaVersion", "sequence", "sha256", "teamIdentifier", "version"];
const maximumInputBytes = 128 * 1024;

function fail(message) {
  throw new Error(message);
}

function canonicalInstant(value, label) {
  if (typeof value !== "string") fail(`${label} is invalid.`);
  const time = Date.parse(value);
  if (!Number.isFinite(time) || new Date(time).toISOString() !== value) {
    fail(`${label} must be a canonical UTC timestamp.`);
  }
  return time;
}

function validateEntry(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) ||
      JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(exactFields)) {
    fail("Update key metadata has an invalid shape.");
  }
  if (!keyIdPattern.test(value.keyId)) fail("Update key ID is invalid.");
  if (typeof value.publicKeyX963Base64 !== "string" ||
      !/^[A-Za-z0-9+/]{87}=$/.test(value.publicKeyX963Base64)) {
    fail("Update public key must be canonical base64 P-256 X9.63 data.");
  }
  const raw = Buffer.from(value.publicKeyX963Base64, "base64");
  if (raw.length !== 65 || raw[0] !== 0x04 || raw.toString("base64") !== value.publicKeyX963Base64) {
    fail("Update public key must be a 65-byte uncompressed P-256 point.");
  }
  let normalized;
  try {
    normalized = Buffer.from(ECDH.convertKey(raw, "prime256v1", undefined, undefined, "uncompressed"));
  } catch {
    fail("Update public key is not a valid P-256 point.");
  }
  if (!normalized.equals(raw)) fail("Update public key is not canonical P-256 data.");
  const notBefore = canonicalInstant(value.notBefore, "Update key not-before");
  const notAfter = canonicalInstant(value.notAfter, "Update key not-after");
  if (notBefore >= notAfter) fail("Update key validity window is empty or reversed.");
  return Object.freeze({ ...value, notAfterTime: notAfter, notBeforeTime: notBefore });
}

export function validateUpdateKeyEntries(values, options = {}) {
  const {
    expectedKeyId,
    expectedPublicKey,
    validationTime,
    requiredWindow,
  } = options;
  if ((expectedKeyId === undefined) !== (expectedPublicKey === undefined)) {
    fail("The selected update key ID and public key must be provided together.");
  }
  if (!Array.isArray(values) || values.length < 1 || values.length > 8) {
    fail("One to eight update-signing keys are required.");
  }
  const entries = values.map(validateEntry);
  const ids = new Set();
  for (const entry of entries) {
    if (ids.has(entry.keyId)) fail("Duplicate update key IDs are not allowed.");
    ids.add(entry.keyId);
  }
  const selected = expectedKeyId === undefined
    ? undefined
    : entries.find((entry) => entry.keyId === expectedKeyId && entry.publicKeyX963Base64 === expectedPublicKey);
  if (expectedKeyId !== undefined && !selected) {
    fail("The selected update-signing key is not compiled into the application.");
  }

  if (requiredWindow !== undefined) {
    if (!requiredWindow || typeof requiredWindow !== "object" || Array.isArray(requiredWindow) ||
        Object.keys(requiredWindow).sort().join(",") !== "expiresAt,publishedAt") {
      fail("The required release validity window is invalid.");
    }
    if (!selected) fail("A selected update-signing key is required for release-window validation.");
    const publishedAt = canonicalInstant(requiredWindow.publishedAt, "Release published-at");
    const expiresAt = canonicalInstant(requiredWindow.expiresAt, "Release expires-at");
    if (publishedAt >= expiresAt) fail("The release validity window is empty or reversed.");
    if (selected.notBeforeTime > publishedAt || selected.notAfterTime < expiresAt) {
      fail("The selected update-signing key does not cover the complete release validity window.");
    }
  } else {
    const at = validationTime === undefined
      ? Date.now()
      : canonicalInstant(validationTime, "Update key validation time");
    const candidates = selected ? [selected] : entries;
    if (!candidates.some((entry) => entry.notBeforeTime <= at && at < entry.notAfterTime)) {
      const timeLabel = validationTime === undefined ? "now" : "at the validation time";
      fail(selected
        ? `The selected update-signing key is not valid ${timeLabel}.`
        : `At least one update-signing key must be valid ${timeLabel}.`);
    }
  }
  return entries;
}

async function readStandardInput() {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > maximumInputBytes) fail("Update key metadata is too large.");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function parseJson(source, message) {
  try {
    return JSON.parse(source);
  } catch (error) {
    if (error instanceof SyntaxError) fail(message);
    throw error;
  }
}

async function readReleaseWindow(envelopePath, expectedKeyId, expectedPublicKey) {
  let source;
  try {
    source = await readFile(resolve(envelopePath), "utf8");
  } catch {
    fail("The signed release envelope could not be read.");
  }
  if (Buffer.byteLength(source, "utf8") > maximumInputBytes) fail("The signed release envelope is too large.");
  const envelope = parseJson(source, "The signed release envelope is not valid JSON.");
  if (!envelope || typeof envelope !== "object" || Array.isArray(envelope) ||
      Object.keys(envelope).sort().join(",") !== exactEnvelopeFields.join(",") ||
      !envelope.manifest || typeof envelope.manifest !== "object" || Array.isArray(envelope.manifest) ||
      Object.keys(envelope.manifest).sort().join(",") !== exactManifestFields.join(",")) {
    fail("The signed release envelope has an invalid shape.");
  }
  const manifest = envelope.manifest;
  const artifactName = `Scopeproof-Capture-${manifest.version}.zip`;
  let downloadUrl;
  try {
    downloadUrl = new URL(manifest.downloadUrl);
  } catch {
    fail("The signed release envelope has an invalid immutable download URL.");
  }
  if (manifest.schemaVersion !== 1 || typeof manifest.version !== "string" || !/^\d+\.\d+\.\d+$/.test(manifest.version) ||
      !Number.isSafeInteger(manifest.sequence) || manifest.sequence < 1 ||
      typeof manifest.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(manifest.sha256) ||
      !Number.isSafeInteger(manifest.byteSize) || manifest.byteSize < 1 || manifest.byteSize > 500 * 1024 * 1024 ||
      typeof manifest.minimumSystemVersion !== "string" || !/^\d+\.\d+(?:\.\d+)?$/.test(manifest.minimumSystemVersion) ||
      typeof manifest.teamIdentifier !== "string" || !/^[A-Z0-9]{10}$/.test(manifest.teamIdentifier) ||
      typeof manifest.designatedRequirement !== "string" || !/^[\x20-\x7e]{20,2048}$/.test(manifest.designatedRequirement) ||
      typeof manifest.notes !== "string" || Buffer.byteLength(manifest.notes, "utf8") > 8 * 1024 ||
      envelope.releaseArtifact !== artifactName ||
      downloadUrl.protocol !== "https:" || downloadUrl.username || downloadUrl.password || downloadUrl.port || downloadUrl.search || downloadUrl.hash ||
      downloadUrl.pathname !== `/macos/${manifest.version}/${artifactName}`) {
    fail("The signed release envelope metadata is invalid.");
  }
  if (manifest.keyId !== expectedKeyId || envelope.publicKeyX963Base64 !== expectedPublicKey) {
    fail("The signed release envelope does not use the selected update-signing key.");
  }
  if (typeof envelope.signatureDERBase64 !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(envelope.signatureDERBase64)) {
    fail("The signed release envelope has an invalid signature encoding.");
  }
  const signature = Buffer.from(envelope.signatureDERBase64, "base64");
  if (signature.length < 64 || signature.length > 80 || signature.toString("base64") !== envelope.signatureDERBase64) {
    fail("The signed release envelope has an invalid signature encoding.");
  }
  const rawPublicKey = Buffer.from(expectedPublicKey, "base64");
  const publicKey = createPublicKey({
    key: {
      kty: "EC",
      crv: "P-256",
      x: rawPublicKey.subarray(1, 33).toString("base64url"),
      y: rawPublicKey.subarray(33, 65).toString("base64url"),
    },
    format: "jwk",
  });
  const spkiDigest = createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex");
  if (envelope.publicKeySpkiSha256 !== spkiDigest) {
    fail("The signed release envelope public-key digest is invalid.");
  }
  const notesBase64 = Buffer.from(manifest.notes, "utf8").toString("base64");
  const payload = ["scopeproof-update-manifest-v1", manifest.schemaVersion, manifest.version, manifest.sequence, manifest.downloadUrl, manifest.sha256, manifest.byteSize, manifest.publishedAt, manifest.expiresAt, manifest.minimumSystemVersion, manifest.teamIdentifier, manifest.designatedRequirement, manifest.keyId, notesBase64].join("\n");
  if (!verifySignature("sha256", Buffer.from(payload), publicKey, signature)) {
    fail("The signed release envelope signature is invalid.");
  }
  return {
    publishedAt: manifest.publishedAt,
    expiresAt: manifest.expiresAt,
  };
}

export async function runUpdateKeyValidatorCli(arguments_) {
  const [mode, ...values_] = arguments_;
  if (mode === "single") {
    if (values_.length !== 4) fail("Single-key validation arguments are invalid.");
    const [keyId, publicKeyX963Base64, notBefore, notAfter] = values_;
    validateUpdateKeyEntries([{ keyId, publicKeyX963Base64, notBefore, notAfter }]);
    return;
  }
  if (mode === "json" || mode === "json-at") {
    const validationTime = mode === "json-at" ? values_.shift() : undefined;
    if ((mode === "json-at" && validationTime === undefined) || ![0, 2].includes(values_.length)) {
      fail("JSON-key validation arguments are invalid.");
    }
    const metadata = parseJson(await readStandardInput(), "Update key metadata is not valid JSON.");
    validateUpdateKeyEntries(metadata, {
      expectedKeyId: values_[0],
      expectedPublicKey: values_[1],
      validationTime,
    });
    return;
  }
  if (mode === "envelope") {
    if (values_.length !== 3) fail("Release-envelope validation arguments are invalid.");
    const [expectedKeyId, expectedPublicKey, envelopePath] = values_;
    const metadata = parseJson(await readStandardInput(), "Update key metadata is not valid JSON.");
    const requiredWindow = await readReleaseWindow(envelopePath, expectedKeyId, expectedPublicKey);
    validateUpdateKeyEntries(metadata, { expectedKeyId, expectedPublicKey, requiredWindow });
    return;
  }
  fail("Usage: validate_macos_update_keys.mjs single <id> <x963-base64> <not-before> <not-after> | json [<expected-id> <expected-x963-base64>] | json-at <validation-time> [<expected-id> <expected-x963-base64>] | envelope <expected-id> <expected-x963-base64> <signed-envelope>");
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : "";
if (import.meta.url === invokedPath) {
  try {
    await runUpdateKeyValidatorCli(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : "Update key validation failed.");
    process.exitCode = 1;
  }
}
