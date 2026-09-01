#!/usr/bin/env node
import { pathToFileURL } from "node:url";

const allowedEntitlements = Object.freeze({
  "com.apple.security.cs.allow-jit": false,
  "com.apple.security.cs.allow-unsigned-executable-memory": false,
  "com.apple.security.cs.disable-library-validation": false,
});

export function validateReleaseEntitlements(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Release entitlements must be a JSON object.");
  }
  const actualKeys = Object.keys(value).sort();
  const allowedKeys = Object.keys(allowedEntitlements).sort();
  if (actualKeys.length !== allowedKeys.length || actualKeys.some((key, index) => key !== allowedKeys[index])) {
    const unexpected = actualKeys.filter((key) => !Object.hasOwn(allowedEntitlements, key));
    const missing = allowedKeys.filter((key) => !Object.hasOwn(value, key));
    throw new Error(`Release entitlement allowlist mismatch (unexpected: ${unexpected.join(", ") || "none"}; missing: ${missing.join(", ") || "none"}).`);
  }
  for (const [key, expected] of Object.entries(allowedEntitlements)) {
    if (value[key] !== expected) throw new Error(`Release entitlement ${key} must be ${String(expected)}.`);
  }
  return true;
}

async function main() {
  const chunks = [];
  let byteLength = 0;
  for await (const chunk of process.stdin) {
    byteLength += chunk.length;
    if (byteLength > 64 * 1024) throw new Error("Release entitlement input exceeds 64 KiB.");
    chunks.push(chunk);
  }
  const source = Buffer.concat(chunks).toString("utf8");
  if (!source.trim()) throw new Error("Release entitlement input is empty.");
  validateReleaseEntitlements(JSON.parse(source));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
