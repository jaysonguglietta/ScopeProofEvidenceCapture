import { SbomError } from "./sbom-input.ts";

export type SbomComponent = { name: string; version: string; ecosystem: string; purl: string; direct: boolean; directKnown?: boolean; manifests: string[] };
export type SbomComparison = { baseline: boolean; previousJobId?: string; added: number; removed: number; changed: number; addedComponents: string[]; removedComponents: string[]; changedComponents: string[]; versionChanges: Array<{ name: string; previous: string[]; current: string[] }>; detailsTruncated: boolean };
export type ManifestCoverage = { path: string; parser: string; complete: boolean; componentCount: number; warnings: string[] };
export const SBOM_GENERATOR_NAME = "scopeproof-static-sbom";
export const SBOM_GENERATOR_VERSION = "1.1.0";
const MAX_COMPONENTS = 5_000;
const basename = (path: string): string => path.toLowerCase().split("/").pop() || "";

function purl(ecosystem: string, name: string, version: string): string {
  const type: Record<string, string> = { npm: "npm", PyPI: "pypi", cargo: "cargo", golang: "golang", gem: "gem", composer: "composer" };
  return `pkg:${type[ecosystem] || ecosystem.toLowerCase()}/${name.split("/").map(encodeURIComponent).join("/")}@${encodeURIComponent(version)}`;
}

function component(name: string, version: unknown, ecosystem: string, direct: boolean, manifest: string): SbomComponent | null {
  const normalizedName = String(name || "").trim();
  const normalizedVersion = String(version || "").trim().replace(/^=+/, "");
  if (!normalizedName || !normalizedVersion || normalizedName.length > 300 || normalizedVersion.length > 200 || [...normalizedName + normalizedVersion].some((character) => character.charCodeAt(0) < 32)) return null;
  return { name: normalizedName, version: normalizedVersion, ecosystem, purl: purl(ecosystem, normalizedName, normalizedVersion), direct, manifests: [manifest] };
}

function parseJson(text: string, path: string): Record<string, unknown> {
  try { const value = JSON.parse(text); if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(); return value as Record<string, unknown>; }
  catch { throw new SbomError(`${path} is malformed JSON.`, "INVALID_MANIFEST", false, 422); }
}

function packageLock(path: string, text: string, warnings: string[]): SbomComponent[] {
  const data = parseJson(text, path);
  const version = Number(data.lockfileVersion);
  if (![1, 2, 3].includes(version)) throw new SbomError(`${path} uses an unsupported npm lockfile version. Supported versions are 1, 2 and 3.`, "UNSUPPORTED_MANIFEST_VERSION", false, 422);
  const found: SbomComponent[] = [];
  const add = (name: string, raw: unknown, direct: boolean) => {
    if (typeof raw !== "string" || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u.test(raw)) {
      warnings.push("Non-registry, unpinned or malformed dependency versions were not inventoried.");
      return;
    }
    const item = component(name, raw, "npm", direct, path);
    if (item) { item.directKnown = version !== 1; found.push(item); } else warnings.push("A dependency has an invalid component identity.");
    if (found.length > MAX_COMPONENTS * 2) throw new SbomError("Repository dependency inventory exceeds the component safety limit.", "COMPONENT_LIMIT_EXCEEDED", false, 413);
  };
  if (version === 1) {
    const visit = (dependencies: unknown, depth: number) => {
      if (depth > 100) throw new SbomError(`${path} exceeds the dependency nesting limit.`, "MANIFEST_COMPLEXITY_LIMIT", false, 413);
      if (!dependencies || typeof dependencies !== "object" || Array.isArray(dependencies)) {
        warnings.push("Dependency entries have an unsupported structure."); return;
      }
      for (const [name, raw] of Object.entries(dependencies)) {
        if (!raw || typeof raw !== "object" || Array.isArray(raw)) { warnings.push("A dependency entry is malformed."); continue; }
        const value = raw as Record<string, unknown>;
        // npm v1 lists hoisted transitive packages at the root too. Without
        // package.json, directness is unknown rather than inferred from depth.
        add(name, value.version, false);
        if (value.dependencies !== undefined) visit(value.dependencies, depth + 1);
      }
    };
    if (data.dependencies !== undefined) visit(data.dependencies, 0);
    else warnings.push("The legacy lockfile has no dependency collection.");
  } else {
    if (!data.packages || typeof data.packages !== "object" || Array.isArray(data.packages)) throw new SbomError(`${path} is missing its npm packages map.`, "INVALID_MANIFEST", false, 422);
    const packages = data.packages as Record<string, unknown>;
    if (!packages[""] || typeof packages[""] !== "object" || Array.isArray(packages[""])) warnings.push("The npm packages map has no valid root dependency metadata.");
    const root = packages[""] && typeof packages[""] === "object" ? packages[""] as Record<string, unknown> : {};
    const directNames = new Set(["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"].flatMap((key) => Object.keys(root[key] && typeof root[key] === "object" ? root[key] as object : {})));
    for (const [location, raw] of Object.entries(packages)) {
      if (!location) continue;
      if (!raw || typeof raw !== "object" || Array.isArray(raw)) { warnings.push("A packages-map entry is malformed."); continue; }
      const value = raw as Record<string, unknown>;
      if (value.link === true) { warnings.push("Workspace or linked dependencies require additional reviewed inventory."); continue; }
      const marker = "/node_modules/";
      const name = String(value.name || (location.includes(marker) ? location.slice(location.lastIndexOf(marker) + marker.length) : location.replace(/^node_modules\//, "")));
      add(name, value.version, directNames.has(name) && location === `node_modules/${name}`);
    }
  }
  return found;
}

function jsonDependencies(path: string, text: string): SbomComponent[] {
  const data = parseJson(text, path);
  if (basename(path) === "pipfile.lock") return ["default", "develop"].flatMap((group) => Object.entries((data[group] || {}) as Record<string, Record<string, unknown>>).map(([name, value]) => component(name, value.version, "PyPI", true, path)).filter(Boolean) as SbomComponent[]);
  const rootRequires = new Set(Object.keys((data.require && typeof data.require === "object" ? data.require : {}) as object));
  return ["packages", "packages-dev"].flatMap((group) => Array.isArray(data[group]) ? (data[group] as Array<Record<string, unknown>>).map((value) => component(String(value.name || ""), String(value.version || "").replace(/^v/, ""), "composer", rootRequires.has(String(value.name)), path)).filter(Boolean) as SbomComponent[] : []);
}

function blockPackages(path: string, text: string, ecosystem: "cargo" | "PyPI"): SbomComponent[] {
  const found: SbomComponent[] = [];
  for (const block of text.split(/^\s*\[\[package\]\]\s*$/m).slice(1)) {
    const name = block.match(/^name\s*=\s*["']([^"']+)["']/m)?.[1];
    const version = block.match(/^version\s*=\s*["']([^"']+)["']/m)?.[1];
    const item = component(name || "", version, ecosystem, false, path); if (item) found.push(item);
  }
  return found;
}

function lineManifest(path: string, text: string): SbomComponent[] {
  const name = basename(path);
  const found: SbomComponent[] = [];
  if (name === "requirements.txt") for (const line of text.split(/\r?\n/)) { const match = line.trim().match(/^([A-Za-z0-9_.-]+)\s*={2,3}\s*([^\s;#]+)/); const item = match && component(match[1], match[2], "PyPI", true, path); if (item) found.push(item); }
  if (name === "go.sum") for (const line of text.split(/\r?\n/)) { const [module, raw] = line.trim().split(/\s+/); if (!module || !raw || raw.endsWith("/go.mod")) continue; const item = component(module, raw, "golang", false, path); if (item) found.push(item); }
  if (name === "gemfile.lock") { let specs = false; for (const line of text.split(/\r?\n/)) { if (/^\s{2}specs:/.test(line)) { specs = true; continue; } if (specs && /^\S/.test(line)) specs = false; const match = specs && line.match(/^\s{4}([^ (]+) \(([^ )]+)\)/); const item = match && component(match[1], match[2], "gem", false, path); if (item) found.push(item); } }
  if (name === "yarn.lock") for (const block of text.split(/\n(?=[^ \n][^\n]*:\n)/)) { const header = block.match(/^([^\n]+):\n/)?.[1]; const version = block.match(/^\s{2}version\s+["']?([^"'\s]+)["']?/m)?.[1]; if (!header || !version) continue; const first = header.split(",")[0].trim().replace(/^['"]|['"]$/g, ""); const packageName = first.startsWith("@") ? first.slice(0, first.indexOf("@", 1)) : first.split("@")[0]; const item = component(packageName, version, "npm", false, path); if (item) found.push(item); }
  if (name === "pnpm-lock.yaml") for (const line of text.split(/\r?\n/)) { const match = line.match(/^\s{2,}["']?\/?((?:@[^/@\s]+\/)?[^@:'"\s]+)@([^:'"\s(]+)["']?:/); const item = match && component(match[1], match[2], "npm", false, path); if (item) found.push(item); }
  return found;
}

export function analyzeDependencyManifests(manifests: Array<{ path: string; text: string }>, maximumComponents = MAX_COMPONENTS): { components: SbomComponent[]; complete: boolean; manifests: ManifestCoverage[]; warnings: string[] } {
  const all: SbomComponent[] = [];
  const coverage: ManifestCoverage[] = [];
  for (const manifest of manifests) {
    const name = basename(manifest.path);
    const warnings: string[] = [];
    let parsed: SbomComponent[];
    if (["package-lock.json", "npm-shrinkwrap.json"].includes(name)) parsed = packageLock(manifest.path, manifest.text, warnings);
    else {
      // These legacy static parsers remain useful review aids, but do not prove
      // full format/edge/direct-dependency coverage. Never silently approve them.
      warnings.push("Static parser coverage is partial for this format; independently validated replacement inventory is required for assessor approval.");
      if (["pipfile.lock", "composer.lock"].includes(name)) parsed = jsonDependencies(manifest.path, manifest.text);
      else if (name === "cargo.lock") parsed = blockPackages(manifest.path, manifest.text, "cargo");
      else if (name === "poetry.lock") parsed = blockPackages(manifest.path, manifest.text, "PyPI");
      else if (["requirements.txt", "go.sum", "gemfile.lock", "yarn.lock", "pnpm-lock.yaml"].includes(name)) parsed = lineManifest(manifest.path, manifest.text);
      else throw new SbomError(`Unsupported manifest ${manifest.path}.`, "UNSUPPORTED_MANIFEST_FORMAT", false, 422);
    }
    if (!parsed.length) warnings.push("No pinned components were extracted from this recognized manifest.");
    all.push(...parsed);
    coverage.push({ path: manifest.path, parser: `${SBOM_GENERATOR_NAME}@${SBOM_GENERATOR_VERSION}`, complete: !warnings.length, componentCount: parsed.length, warnings: [...new Set(warnings)] });
    if (all.length > maximumComponents * 2) throw new SbomError("Repository dependency inventory exceeds the component safety limit.", "COMPONENT_LIMIT_EXCEEDED", false, 413);
  }
  const merged = new Map<string, SbomComponent>();
  for (const item of all) {
    const existing = merged.get(item.purl);
    if (existing) { existing.direct ||= item.direct; existing.manifests = [...new Set([...existing.manifests, ...item.manifests])].sort(); }
    else merged.set(item.purl, { ...item });
  }
  const components = [...merged.values()].sort((a, b) => a.purl.localeCompare(b.purl));
  if (components.length > maximumComponents) throw new SbomError("Repository dependency inventory exceeds the component safety limit.", "COMPONENT_LIMIT_EXCEEDED", false, 413);
  return { components, complete: coverage.length > 0 && coverage.every((item) => item.complete), manifests: coverage, warnings: coverage.flatMap((item) => item.warnings.map((warning) => `${item.path}: ${warning}`)) };
}

export function parseDependencyManifests(manifests: Array<{ path: string; text: string }>): SbomComponent[] {
  return analyzeDependencyManifests(manifests).components;
}

export function comparison(current: SbomComponent[], previous: SbomComponent[] | null, previousJobId?: string, detailLimit = 100): SbomComparison {
  if (!Number.isSafeInteger(detailLimit) || detailLimit < 1 || detailLimit > 5000) throw new Error("SBOM comparison detail limit is invalid.");
  if (!previous) return { baseline: true, added: 0, removed: 0, changed: 0, addedComponents: [], removedComponents: [], changedComponents: [], versionChanges: [], detailsTruncated: false };
  const groupVersions = (items: SbomComponent[]) => {
    const groups = new Map<string, Set<string>>();
    for (const item of items) {
      const key = `${item.ecosystem}:${item.name}`;
      const versions = groups.get(key) || new Set<string>();
      versions.add(item.version); groups.set(key, versions);
    }
    return groups;
  };
  const currentPurls = new Set(current.map((item) => item.purl));
  const previousPurls = new Set(previous.map((item) => item.purl));
  const added = [...currentPurls].filter((key) => !previousPurls.has(key)).sort();
  const removed = [...previousPurls].filter((key) => !currentPurls.has(key)).sort();
  const currentByName = groupVersions(current); const previousByName = groupVersions(previous);
  const versionChanges = [...currentByName.keys()].filter((key) => previousByName.has(key)).sort().flatMap((name) => {
    const before = [...previousByName.get(name)!].sort(); const after = [...currentByName.get(name)!].sort();
    return JSON.stringify(before) === JSON.stringify(after) ? [] : [{ name, previous: before, current: after }];
  });
  // Compute counts from full version sets, but bound list-page payloads.
  // A visible truncation marker distinguishes previews from complete detail.
  return { baseline: false, previousJobId, added: added.length, removed: removed.length, changed: versionChanges.length,
    addedComponents: added.slice(0, detailLimit), removedComponents: removed.slice(0, detailLimit), changedComponents: versionChanges.slice(0, detailLimit).map((item) => item.name), versionChanges: versionChanges.slice(0, detailLimit), detailsTruncated: added.length > detailLimit || removed.length > detailLimit || versionChanges.length > detailLimit };
}

export function buildCycloneDx(repo: string, commit: string, generatedAt: string, archiveDigest: string, manifests: string[], components: SbomComponent[]) {
  return { bomFormat: "CycloneDX", specVersion: "1.6", serialNumber: `urn:uuid:${crypto.randomUUID()}`, version: 1, metadata: { timestamp: generatedAt, tools: { components: [{ type: "application", name: SBOM_GENERATOR_NAME, version: SBOM_GENERATOR_VERSION }] }, component: { type: "application", name: repo, version: commit, "bom-ref": `repository:${repo}@${commit}` }, properties: [{ name: "scopeproof:repository", value: `https://github.com/${repo}` }, { name: "scopeproof:commit", value: commit }, { name: "scopeproof:sourceArchiveSha256", value: archiveDigest }, { name: "scopeproof:manifests", value: manifests.join(",") }] }, components: components.map((item) => ({ type: "library", name: item.name, version: item.version, purl: item.purl, "bom-ref": item.purl, properties: [{ name: "scopeproof:direct", value: item.directKnown === false ? "unknown" : String(item.direct) }, { name: "scopeproof:manifests", value: item.manifests.join(",") }] })) };
}

function spdxId(value: string, index: number): string { return `SPDXRef-Package-${index}-${value.replace(/[^A-Za-z0-9.-]+/g, "-").slice(0, 80)}`; }
export function buildSpdx(repo: string, commit: string, generatedAt: string, archiveDigest: string, manifests: string[], components: SbomComponent[]) {
  const repoId = "SPDXRef-Repository";
  const packages = components.map((item, index) => ({ SPDXID: spdxId(item.name, index), name: item.name, versionInfo: item.version, downloadLocation: "NOASSERTION", filesAnalyzed: false, externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: item.purl }], annotations: [{ annotationType: "OTHER", annotator: `Tool: ${SBOM_GENERATOR_NAME}-${SBOM_GENERATOR_VERSION}`, annotationDate: generatedAt, comment: `direct=${item.directKnown === false ? "unknown" : item.direct}; manifests=${item.manifests.join(",")}` }] }));
  return { spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", name: `${repo}-${commit.slice(0, 12)}-sbom`, documentNamespace: `https://scopeproof.local/sbom/${crypto.randomUUID()}`, creationInfo: { created: generatedAt, creators: [`Tool: ${SBOM_GENERATOR_NAME}-${SBOM_GENERATOR_VERSION}`], comment: `Repository https://github.com/${repo}; commit ${commit}; source archive SHA-256 ${archiveDigest}; manifests ${manifests.join(",")}` }, packages: [{ SPDXID: repoId, name: repo, versionInfo: commit, downloadLocation: `https://github.com/${repo}`, filesAnalyzed: false }, ...packages], relationships: [{ spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: repoId }, ...packages.map((item) => ({ spdxElementId: repoId, relationshipType: "DEPENDS_ON", relatedSpdxElement: item.SPDXID }))] };
}
