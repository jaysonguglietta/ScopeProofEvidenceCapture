#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const [manifestInput, lockInput, outputInput] = process.argv.slice(2);
if (!manifestInput || !lockInput || !outputInput) throw new Error("Usage: pnpm_lock_to_cyclonedx.mjs <package.json> <pnpm-lock.yaml> <output.json>");
const manifest = JSON.parse(await readFile(resolve(manifestInput), "utf8"));
const lockSource = await readFile(resolve(lockInput), "utf8");
if (!/^lockfileVersion:\s*'9\.0'\s*$/m.test(lockSource)) throw new Error("Only pnpm lockfile version 9.0 is supported.");
const packagesSource = lockSource.split(/^packages:\s*$/m)[1]?.split(/^snapshots:\s*$/m)[0];
if (!packagesSource) throw new Error("pnpm lockfile has no packages inventory.");

const components = [];
const refs = new Set();
const entries = [...packagesSource.matchAll(/^(?: {2})(?:'([^']+)'|([^' \n][^:\n]*)):\n([\s\S]*?)(?=^(?: {2})(?:'[^']+'|[^' \n][^:\n]*):\n|\s*$)/gm)];
for (const [, quotedKey, bareKey, body] of entries) {
  const lockedKey = quotedKey || bareKey;
  const separator = lockedKey.lastIndexOf("@");
  if (separator <= 0) throw new Error(`Unsupported pnpm package key: ${lockedKey}`);
  const name = lockedKey.slice(0, separator);
  const version = lockedKey.slice(separator + 1).replace(/\(.*/, "");
  if (!name || !/^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/.test(version)) throw new Error(`Unsupported pnpm package version: ${lockedKey}`);
  const purlName = name.startsWith("@") ? `%40${name.slice(1).split("/").map(encodeURIComponent).join("/")}` : encodeURIComponent(name);
  const ref = `pkg:npm/${purlName}@${encodeURIComponent(version)}`;
  if (refs.has(ref)) continue;
  refs.add(ref);
  const integrity = body.match(/integrity:\s*sha512-([A-Za-z0-9+/=]+)/)?.[1];
  components.push({
    type: "library",
    "bom-ref": ref,
    name,
    version,
    purl: ref,
    ...(integrity ? { hashes: [{ alg: "SHA-512", content: Buffer.from(integrity, "base64").toString("hex") }] } : {}),
  });
}
if (components.length === 0) throw new Error("No packages were parsed from the pnpm lockfile.");
components.sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"]));

const directRefs = [];
for (const [name, version] of Object.entries({ ...manifest.dependencies, ...manifest.devDependencies, ...manifest.optionalDependencies })) {
  const normalized = String(version).replace(/^[~^]/, "");
  const purlName = name.startsWith("@") ? `%40${name.slice(1).split("/").map(encodeURIComponent).join("/")}` : encodeURIComponent(name);
  const ref = `pkg:npm/${purlName}@${encodeURIComponent(normalized)}`;
  if (!refs.has(ref)) throw new Error(`Direct dependency is absent from the lock inventory: ${name}@${normalized}`);
  directRefs.push(ref);
}
const rootRef = `pkg:npm/${encodeURIComponent(manifest.name)}@${encodeURIComponent(manifest.version)}`;
const sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  version: 1,
  metadata: { component: { type: "application", "bom-ref": rootRef, name: manifest.name, version: manifest.version, purl: rootRef } },
  components,
  dependencies: [{ ref: rootRef, dependsOn: directRefs.sort() }],
};
await writeFile(resolve(outputInput), `${JSON.stringify(sbom, null, 2)}\n`, { mode: 0o600, flag: "wx" });
console.log(resolve(outputInput));
