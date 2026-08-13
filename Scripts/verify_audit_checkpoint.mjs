#!/usr/bin/env node
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}

const path = process.argv[2];
if (!path) {
  console.error("Usage: node Scripts/verify_audit_checkpoint.mjs checkpoint.json");
  process.exit(2);
}

const checkpoint = JSON.parse(await readFile(path, "utf8"));
const unsigned = {
  version: checkpoint.version,
  id: checkpoint.id,
  sequence: checkpoint.sequence,
  eventHash: checkpoint.eventHash,
  eventCount: checkpoint.eventCount,
  hmacKeyId: checkpoint.hmacKeyId,
  createdAt: checkpoint.createdAt,
};
const payload = canonical(unsigned);
const digest = createHash("sha256").update(payload).digest("hex");
const fingerprint = createHash("sha256").update(String(checkpoint.publicKey)).digest("hex");
const publicKey = createPublicKey({ key: Buffer.from(String(checkpoint.publicKey), "base64"), format: "der", type: "spki" });
const validSignature = verify("sha256", Buffer.from(payload), { key: publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(String(checkpoint.signature), "base64"));
const valid = digest === checkpoint.checkpointSha256 && fingerprint === checkpoint.publicKeyFingerprint && validSignature;
console.log(JSON.stringify({ valid, digestMatches: digest === checkpoint.checkpointSha256, fingerprintMatches: fingerprint === checkpoint.publicKeyFingerprint, signatureMatches: validSignature, sequence: checkpoint.sequence }, null, 2));
process.exit(valid ? 0 : 1);
