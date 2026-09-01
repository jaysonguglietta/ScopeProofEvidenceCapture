#!/usr/bin/env node
import { readFile, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";

const [manifestInput, lockInput, outputInput] = process.argv.slice(2);
if (!manifestInput || !lockInput || !outputInput) {
  throw new Error("Usage: pnpm_lock_to_cyclonedx.mjs <package.json> <pnpm-lock.yaml> <output.json>");
}

const manifestPath = resolve(manifestInput);
const lockPath = resolve(lockInput);
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const lockSource = await readFile(lockPath, "utf8");
if (!/^lockfileVersion:\s*'9\.0'\s*$/m.test(lockSource)) {
  throw new Error("Only pnpm lockfile version 9.0 is supported.");
}

function sectionBetween(source, start, end) {
  const afterStart = source.split(new RegExp(`^${start}:\\s*$`, "m"))[1];
  if (!afterStart) throw new Error(`pnpm lockfile has no ${start} section.`);
  return end ? afterStart.split(new RegExp(`^${end}:\\s*$`, "m"))[0] : afterStart;
}

function unquote(value) {
  const trimmed = String(value).trim();
  if (trimmed.startsWith("'") && trimmed.endsWith("'")) {
    return trimmed.slice(1, -1).replaceAll("''", "'");
  }
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) return JSON.parse(trimmed);
  return trimmed;
}

function parseEntries(sectionSource) {
  const entries = [];
  let current;
  for (const line of sectionSource.split(/\r?\n/)) {
    const header = line.match(/^ {2}(\S.+):(?:\s*\{\})?\s*$/);
    if (header) {
      if (current) entries.push(current);
      current = { key: unquote(header[1]), lines: [] };
    } else if (current) {
      current.lines.push(line);
    } else if (line.trim()) {
      throw new Error(`Unsupported pnpm lockfile content before the first entry: ${line}`);
    }
  }
  if (current) entries.push(current);
  return entries;
}

const exactVersion = /^\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?$/;
function parsePackageKey(lockedKey) {
  const withoutPeers = lockedKey.replace(/\(.*/, "");
  const separator = withoutPeers.lastIndexOf("@");
  if (separator <= 0) throw new Error(`Unsupported pnpm package key: ${lockedKey}`);
  const name = withoutPeers.slice(0, separator);
  const version = withoutPeers.slice(separator + 1);
  if (!name || !exactVersion.test(version)) throw new Error(`Unsupported pnpm package version: ${lockedKey}`);
  return { name, version };
}

function purlFor(name, version) {
  const purlName = name.startsWith("@")
    ? `%40${name.slice(1).split("/").map(encodeURIComponent).join("/")}`
    : encodeURIComponent(name);
  return `pkg:npm/${purlName}@${encodeURIComponent(version)}`;
}

function dependencyRef(name, rawVersion) {
  let resolvedName = name;
  let version = unquote(rawVersion).replace(/\(.*/, "");
  if (version.startsWith("npm:")) {
    const target = parsePackageKey(version.slice(4));
    resolvedName = target.name;
    version = target.version;
  }
  if (!exactVersion.test(version)) {
    throw new Error(`Unsupported resolved pnpm dependency: ${name}@${rawVersion}`);
  }
  return purlFor(resolvedName, version);
}

function bundledDependencies(lines) {
  const bundled = [];
  let inBundledDependencies = false;
  for (const line of lines) {
    if (/^ {4}bundledDependencies:\s*$/.test(line)) {
      inBundledDependencies = true;
      continue;
    }
    if (/^ {4}\S/.test(line)) inBundledDependencies = false;
    const item = inBundledDependencies && line.match(/^ {6}-\s+(.+)\s*$/);
    if (item) bundled.push(unquote(item[1]));
  }
  return bundled.sort();
}

const packageEntries = parseEntries(sectionBetween(lockSource, "packages", "snapshots"));
const componentsByRef = new Map();
for (const { key, lines } of packageEntries) {
  const { name, version } = parsePackageKey(key);
  const ref = purlFor(name, version);
  const body = lines.join("\n");
  const integrity = body.match(/integrity:\s*sha512-([A-Za-z0-9+/=]+)/)?.[1];
  const bundled = bundledDependencies(lines);
  const component = componentsByRef.get(ref) ?? {
    type: "library",
    "bom-ref": ref,
    name,
    version,
    purl: ref,
  };
  if (!integrity) throw new Error(`Package is missing a SHA-512 integrity: ${ref}.`);
  const digest = Buffer.from(integrity, "base64");
  if (digest.length !== 64 || digest.toString("base64") !== integrity) {
    throw new Error(`Invalid SHA-512 integrity for ${ref}.`);
  }
  const hash = digest.toString("hex");
  if (component.hashes && component.hashes[0].content !== hash) {
    throw new Error(`Conflicting integrity hashes for ${ref}.`);
  }
  component.hashes = [{ alg: "SHA-512", content: hash }];
  if (bundled.length) {
    component.properties = [{ name: "scopeproof:pnpmBundledDependencies", value: bundled.join(",") }];
  }
  componentsByRef.set(ref, component);
}
if (componentsByRef.size === 0) throw new Error("No packages were parsed from the pnpm lockfile.");

const graph = new Map([...componentsByRef.keys()].map((ref) => [ref, new Map()]));
for (const { key, lines } of parseEntries(sectionBetween(lockSource, "snapshots"))) {
  const { name, version } = parsePackageKey(key);
  const parentRef = purlFor(name, version);
  if (!graph.has(parentRef)) throw new Error(`Snapshot is absent from package inventory: ${key}`);
  let dependencyKind;
  for (const line of lines) {
    const section = line.match(/^ {4}(dependencies|optionalDependencies):\s*$/);
    if (section) {
      dependencyKind = section[1];
      continue;
    }
    if (/^ {4}\S/.test(line)) dependencyKind = undefined;
    if (!dependencyKind) continue;
    const dependency = line.match(/^ {6}(?:'((?:''|[^'])+)'|([^:]+)):\s+(.+)\s*$/);
    if (!dependency) {
      if (line.trim()) throw new Error(`Unsupported ${dependencyKind} entry for ${key}: ${line}`);
      continue;
    }
    const dependencyName = unquote(dependency[1] ?? dependency[2]);
    const ref = dependencyRef(dependencyName, dependency[3]);
    if (!componentsByRef.has(ref)) throw new Error(`Dependency is absent from package inventory: ${key} -> ${ref}`);
    const existingOptional = graph.get(parentRef).get(ref);
    graph.get(parentRef).set(ref, existingOptional === false ? false : dependencyKind === "optionalDependencies");
  }
}

const directScopes = [
  [manifest.dependencies ?? {}, "required"],
  [manifest.optionalDependencies ?? {}, "optional"],
  [manifest.devDependencies ?? {}, "excluded"],
];
const directRefs = new Set();
const scopeRank = { excluded: 1, optional: 2, required: 3 };
const scopes = new Map();
const queue = [];
function assignScope(ref, scope) {
  if (!componentsByRef.has(ref)) throw new Error(`Direct dependency is absent from the lock inventory: ${ref}`);
  if ((scopeRank[scopes.get(ref)] ?? 0) >= scopeRank[scope]) return;
  scopes.set(ref, scope);
  queue.push(ref);
}
for (const [dependencies, scope] of directScopes) {
  for (const [name, version] of Object.entries(dependencies)) {
    const normalized = String(version).replace(/^[~^]/, "");
    if (!exactVersion.test(normalized)) throw new Error(`Direct dependency is not exact-pinned: ${name}@${version}`);
    const ref = purlFor(name, normalized);
    directRefs.add(ref);
    assignScope(ref, scope);
  }
}
while (queue.length) {
  const parentRef = queue.shift();
  const parentScope = scopes.get(parentRef);
  for (const [ref, optional] of graph.get(parentRef) ?? []) {
    const childScope = parentScope === "excluded" ? "excluded" : optional ? "optional" : parentScope;
    assignScope(ref, childScope);
  }
}

const components = [...componentsByRef.values()]
  .map((component) => ({ ...component, scope: scopes.get(component["bom-ref"]) ?? "excluded" }))
  .sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"]));
const rootRef = purlFor(manifest.name, manifest.version);
const dependencies = [
  { ref: rootRef, dependsOn: [...directRefs].sort() },
  ...[...graph.entries()]
    .map(([ref, edges]) => ({ ref, dependsOn: [...edges.keys()].sort() }))
    .sort((left, right) => left.ref.localeCompare(right.ref)),
];
const sbom = {
  bomFormat: "CycloneDX",
  specVersion: "1.6",
  version: 1,
  metadata: {
    tools: {
      components: [{
        type: "application",
        "bom-ref": "pkg:generic/scopeproof-pnpm-lock-to-cyclonedx@2",
        name: "scopeproof-pnpm-lock-to-cyclonedx",
        version: "2",
      }],
    },
    component: {
      type: "application",
      "bom-ref": rootRef,
      name: manifest.name,
      version: manifest.version,
      purl: rootRef,
      properties: [
        { name: "scopeproof:packageManager", value: manifest.packageManager ?? "pnpm" },
        { name: "scopeproof:lockfile", value: basename(lockPath) },
        { name: "scopeproof:lockfileVersion", value: "9.0" },
      ],
    },
    properties: [
      { name: "scopeproof:dependencyGraph", value: "complete-for-pnpm-snapshots" },
      { name: "scopeproof:bundledDependencyRepresentation", value: "component-property-when-version-is-not-in-lockfile" },
    ],
  },
  components,
  dependencies,
};
await writeFile(resolve(outputInput), `${JSON.stringify(sbom, null, 2)}\n`, { mode: 0o600, flag: "wx" });
console.log(resolve(outputInput));
