#!/usr/bin/env node

import { ECDH } from "node:crypto";

const keyIdPattern = /^[A-Za-z0-9._-]{1,64}$/;
const exactFields = ["keyId", "notAfter", "notBefore", "publicKeyX963Base64"];
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

function validateEntries(values, expectedKeyId, expectedPublicKey) {
  if (!Array.isArray(values) || values.length < 1 || values.length > 8) {
    fail("One to eight update-signing keys are required.");
  }
  const entries = values.map(validateEntry);
  const ids = new Set();
  for (const entry of entries) {
    if (ids.has(entry.keyId)) fail("Duplicate update key IDs are not allowed.");
    ids.add(entry.keyId);
  }
  const now = Date.now();
  if (!entries.some((entry) => entry.notBeforeTime <= now && now < entry.notAfterTime)) {
    fail("At least one update-signing key must be valid now.");
  }
  if (expectedKeyId !== undefined &&
      !entries.some((entry) => entry.keyId === expectedKeyId && entry.publicKeyX963Base64 === expectedPublicKey)) {
    fail("The selected update-signing key is not compiled into the application.");
  }
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

const [mode, ...arguments_] = process.argv.slice(2);
if (mode === "single") {
  if (arguments_.length !== 4) fail("Single-key validation arguments are invalid.");
  const [keyId, publicKeyX963Base64, notBefore, notAfter] = arguments_;
  validateEntries([{ keyId, publicKeyX963Base64, notBefore, notAfter }]);
} else if (mode === "json") {
  if (![0, 2].includes(arguments_.length)) fail("JSON-key validation arguments are invalid.");
  let values;
  try {
    values = JSON.parse(await readStandardInput());
  } catch (error) {
    if (error instanceof SyntaxError) fail("Update key metadata is not valid JSON.");
    throw error;
  }
  validateEntries(values, arguments_[0], arguments_[1]);
} else {
  fail("Usage: validate_macos_update_keys.mjs single <id> <x963-base64> <not-before> <not-after> | json [<expected-id> <expected-x963-base64>]");
}
