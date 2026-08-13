#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const manifestPath = resolve(process.argv[2] || "");
if (!process.argv[2]) { console.error("Usage: node Scripts/verify_backup_manifest.mjs backup-manifest.json"); process.exit(2); }
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
if (manifest.schemaVersion !== 1 || !Array.isArray(manifest.files) || !manifest.files.length) throw new Error("Backup manifest schema is invalid.");
const root = dirname(manifestPath);
const results = [];
for (const item of manifest.files) {
  if (!item || typeof item.path !== "string" || item.path.startsWith("/") || item.path.split("/").includes("..") || !/^[a-f0-9]{64}$/.test(item.sha256)) throw new Error("Backup manifest contains an unsafe file entry.");
  const data = await readFile(resolve(root, item.path));
  const digest = createHash("sha256").update(data).digest("hex");
  results.push({ path: item.path, valid: digest === item.sha256, byteSize: data.byteLength });
}
const valid = results.every((item) => item.valid);
console.log(JSON.stringify({ valid, verifiedAt: new Date().toISOString(), results }, null, 2));
process.exit(valid ? 0 : 1);
