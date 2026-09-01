import { unzipSync } from "fflate";
import { assertPermission, loadActiveUser, type AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { randomId, sha256, stableJson } from "./crypto";
import { getAssessment } from "./assessments";
import { getEnv } from "./env";
import { storeEvidence } from "./evidence";
import { isValidGitHubOwner, isValidGitRef, isValidRepositoryName, SbomError, validateOneTimeGitHubToken } from "./sbom-input";

export { parseGitHubRepositoryUrl, SbomError, validateOneTimeGitHubToken } from "./sbom-input";

export type SbomFormat = "cyclonedx_json" | "spdx_json";
export type SbomComponent = { name: string; version: string; ecosystem: string; purl: string; direct: boolean; manifests: string[] };
export type SbomComparison = { baseline: boolean; previousJobId?: string; added: number; removed: number; changed: number; addedComponents: string[]; removedComponents: string[]; changedComponents: string[] };
export type SbomCredential = { mode: "managed" | "one_time"; owner: string; token?: string };

const API_VERSION = "2022-11-28";
const GENERATOR_NAME = "scopeproof-static-sbom";
const GENERATOR_VERSION = "1.0.0";
const sbomSystemActor: AuthenticatedUser = { id: "system:scheduler", email: "scheduler@scopeproof.internal", displayName: "Scopeproof Scheduler", role: "admin" };
const MAX_ARCHIVE_BYTES = 20 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES = 5_000;
const MAX_MANIFESTS = 100;
const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;
const MAX_SELECTED_BYTES = 8 * 1024 * 1024;
const MAX_COMPONENTS = 5_000;
const REPOSITORY_CACHE_TTL_MS = 5 * 60_000;
let repositoryCache: { organization: string; expiresAt: number; repositories: Array<{ name: string; fullName: string; defaultBranch: string; private: boolean; archived: boolean }> } | null = null;
const manifestNames = new Set(["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "pipfile.lock", "poetry.lock", "cargo.lock", "go.sum", "gemfile.lock", "composer.lock"]);

function configured(value: string | undefined, name: string): string {
  if (!value) throw new SbomError(`${name} is not configured.`, "NOT_CONFIGURED", false, 503);
  return value;
}

function githubHeaders(token?: string): Record<string, string> {
  return { authorization: `Bearer ${token || configured(getEnv().GITHUB_TOKEN, "GITHUB_TOKEN")}`, accept: "application/vnd.github+json", "x-github-api-version": API_VERSION, "user-agent": "Scopeproof-SBOM" };
}

async function boundedFetch(url: string, init: RequestInit, label: string, maximumBytes: number, accepted: number[] = []): Promise<Response> {
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.hash || !["api.github.com", "codeload.github.com"].includes(parsed.hostname)) throw new SbomError(`${label} attempted an unapproved network destination.`, "UNSAFE_PROVIDER_URL", false, 502);
  const response = await fetch(parsed, { ...init, redirect: "manual", signal: AbortSignal.timeout(60_000) });
  if (response.status >= 300 && response.status < 400) return response;
  const declared = Number(response.headers.get("content-length") || 0);
  if (declared > maximumBytes) throw new SbomError(`${label} exceeds the ${maximumBytes}-byte safety limit.`, "PROVIDER_RESPONSE_TOO_LARGE", false, 413);
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  if (reader) while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maximumBytes) { await reader.cancel("size limit"); throw new SbomError(`${label} exceeds the ${maximumBytes}-byte safety limit.`, "PROVIDER_RESPONSE_TOO_LARGE", false, 413); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const bounded = new Response(bytes, { status: response.status, statusText: response.statusText, headers: response.headers });
  if (bounded.ok || accepted.includes(bounded.status)) return bounded;
  const retryable = bounded.status === 429 || bounded.status >= 500;
  const code = bounded.status === 401 || bounded.status === 403 ? "GITHUB_AUTH_FAILED" : bounded.status === 404 ? "REPOSITORY_OR_REF_NOT_FOUND" : "GITHUB_API_ERROR";
  throw new SbomError(`${label} returned ${bounded.status}.`, code, retryable, bounded.status);
}

async function githubJson<T>(path: string, label: string, maximumBytes = 2 * 1024 * 1024, token?: string): Promise<T> {
  const response = await boundedFetch(`https://api.github.com${path}`, { headers: githubHeaders(token) }, label, maximumBytes);
  try { return await response.json() as T; }
  catch { throw new SbomError(`${label} returned invalid JSON.`, "GITHUB_INVALID_RESPONSE", false, 502); }
}

export async function listSbomRepositories(): Promise<Array<{ name: string; fullName: string; defaultBranch: string; private: boolean; archived: boolean }>> {
  const org = configured(getEnv().GITHUB_ORG, "GITHUB_ORG");
  const repos: Array<{ name: string; full_name: string; default_branch: string; private: boolean; archived: boolean }> = [];
  for (let page = 1; page <= 3 && repos.length < 250; page += 1) {
    const batch = await githubJson<typeof repos>(`/orgs/${encodeURIComponent(org)}/repos?per_page=100&page=${page}&type=all&sort=full_name`, `GitHub repository inventory page ${page}`, 5 * 1024 * 1024);
    if (!Array.isArray(batch)) throw new SbomError("GitHub returned an invalid repository inventory.", "GITHUB_INVALID_RESPONSE", false, 502);
    repos.push(...batch.slice(0, 250 - repos.length));
    if (batch.length < 100) break;
  }
  return repos.map((repo) => ({ name: repo.name, fullName: repo.full_name, defaultBranch: repo.default_branch, private: repo.private, archived: repo.archived }));
}

export async function listSbomRepositoriesCached(now = Date.now()): Promise<Array<{ name: string; fullName: string; defaultBranch: string; private: boolean; archived: boolean }>> {
  const organization = configured(getEnv().GITHUB_ORG, "GITHUB_ORG");
  if (repositoryCache?.organization === organization && repositoryCache.expiresAt > now) return repositoryCache.repositories;
  const repositories = await listSbomRepositories();
  repositoryCache = { organization, expiresAt: now + REPOSITORY_CACHE_TTL_MS, repositories };
  return repositories;
}

function basename(path: string): string { return path.toLowerCase().split("/").pop() || ""; }
function manifestPath(path: string): string { const parts = path.split("/"); return parts.length > 1 ? parts.slice(1).join("/") : path; }

function inspectZip(bytes: Uint8Array): Set<string> {
  if (bytes.byteLength < 22 || bytes[0] !== 0x50 || bytes[1] !== 0x4b) throw new SbomError("GitHub returned an invalid ZIP archive.", "INVALID_ARCHIVE", false, 422);
  let eocd = -1;
  for (let index = bytes.length - 22; index >= Math.max(0, bytes.length - 65_557); index -= 1) {
    if (bytes[index] === 0x50 && bytes[index + 1] === 0x4b && bytes[index + 2] === 0x05 && bytes[index + 3] === 0x06) { eocd = index; break; }
  }
  if (eocd < 0) throw new SbomError("GitHub ZIP archive is missing its directory record.", "INVALID_ARCHIVE", false, 422);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const count = view.getUint16(eocd + 10, true);
  const directorySize = view.getUint32(eocd + 12, true);
  let offset = view.getUint32(eocd + 16, true);
  if (count > MAX_ARCHIVE_ENTRIES || offset + directorySize > bytes.byteLength) throw new SbomError("Repository archive exceeds the entry safety limit.", "ARCHIVE_LIMIT_EXCEEDED", false, 413);
  const selected = new Set<string>();
  let selectedBytes = 0;
  for (let index = 0; index < count; index += 1) {
    if (offset + 46 > bytes.byteLength || view.getUint32(offset, true) !== 0x02014b50) throw new SbomError("Repository ZIP directory is malformed.", "INVALID_ARCHIVE", false, 422);
    const compressed = view.getUint32(offset + 20, true);
    const original = view.getUint32(offset + 24, true);
    const nameLength = view.getUint16(offset + 28, true);
    const extraLength = view.getUint16(offset + 30, true);
    const commentLength = view.getUint16(offset + 32, true);
    const end = offset + 46 + nameLength + extraLength + commentLength;
    if (end > bytes.byteLength) throw new SbomError("Repository ZIP directory is malformed.", "INVALID_ARCHIVE", false, 422);
    const name = new TextDecoder().decode(bytes.subarray(offset + 46, offset + 46 + nameLength));
    if (manifestNames.has(basename(name))) {
      if (original > MAX_MANIFEST_BYTES || (compressed > 0 && original / compressed > 100)) throw new SbomError(`Dependency manifest ${manifestPath(name)} exceeds decompression limits.`, "ARCHIVE_LIMIT_EXCEEDED", false, 413);
      selectedBytes += original;
      selected.add(name);
    }
    offset = end;
  }
  if (selected.size > MAX_MANIFESTS || selectedBytes > MAX_SELECTED_BYTES) throw new SbomError("Repository contains too many dependency manifests for one bounded scan.", "ARCHIVE_LIMIT_EXCEEDED", false, 413);
  return selected;
}

export function extractDependencyManifests(bytes: Uint8Array): Array<{ path: string; text: string }> {
  const selected = inspectZip(bytes);
  if (!selected.size) return [];
  let extracted: Record<string, Uint8Array>;
  try { extracted = unzipSync(bytes, { filter: (file) => selected.has(file.name) && file.originalSize <= MAX_MANIFEST_BYTES && file.size > 0 && file.originalSize / file.size <= 100 }); }
  catch { throw new SbomError("Repository dependency manifests could not be safely extracted.", "INVALID_ARCHIVE", false, 422); }
  const decoder = new TextDecoder("utf-8", { fatal: true });
  return Object.entries(extracted).map(([path, data]) => {
    if (data.byteLength > MAX_MANIFEST_BYTES || data.includes(0)) throw new SbomError(`Dependency manifest ${manifestPath(path)} is not safe text.`, "INVALID_MANIFEST", false, 422);
    try { return { path: manifestPath(path), text: decoder.decode(data) }; }
    catch { throw new SbomError(`Dependency manifest ${manifestPath(path)} is not valid UTF-8.`, "INVALID_MANIFEST", false, 422); }
  }).sort((a, b) => a.path.localeCompare(b.path));
}

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

function packageLock(path: string, text: string): SbomComponent[] {
  const data = parseJson(text, path);
  const root = (data.packages && typeof data.packages === "object" ? (data.packages as Record<string, Record<string, unknown>>)[""] : undefined) || data;
  const directNames = new Set(["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"].flatMap((key) => Object.keys((root[key] && typeof root[key] === "object" ? root[key] : {}) as object)));
  const found: SbomComponent[] = [];
  if (data.packages && typeof data.packages === "object") for (const [location, value] of Object.entries(data.packages as Record<string, Record<string, unknown>>)) {
    if (!location || !value || typeof value !== "object") continue;
    const marker = "/node_modules/";
    const name = String(value.name || (location.includes(marker) ? location.slice(location.lastIndexOf(marker) + marker.length) : location.replace(/^node_modules\//, "")));
    const item = component(name, value.version, "npm", directNames.has(name), path); if (item) found.push(item);
  }
  if (!found.length && data.dependencies && typeof data.dependencies === "object") for (const [name, value] of Object.entries(data.dependencies as Record<string, Record<string, unknown>>)) { const item = component(name, value?.version, "npm", directNames.has(name), path); if (item) found.push(item); }
  return found;
}

function jsonDependencies(path: string, text: string): SbomComponent[] {
  const data = parseJson(text, path);
  if (basename(path) === "pipfile.lock") return ["default", "develop"].flatMap((group) => Object.entries((data[group] || {}) as Record<string, Record<string, unknown>>).map(([name, value]) => component(name, value.version, "PyPI", true, path)).filter(Boolean) as SbomComponent[]);
  const rootRequires = new Set(Object.keys((data.require && typeof data.require === "object" ? data.require : {}) as object));
  return ["packages", "packages-dev"].flatMap((group) => Array.isArray(data[group]) ? (data[group] as Array<Record<string, unknown>>).map((value) => component(String(value.name || "").replace(/^v/, ""), String(value.version || "").replace(/^v/, ""), "composer", rootRequires.has(String(value.name)), path)).filter(Boolean) as SbomComponent[] : []);
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

export function parseDependencyManifests(manifests: Array<{ path: string; text: string }>): SbomComponent[] {
  const all: SbomComponent[] = [];
  for (const manifest of manifests) {
    const name = basename(manifest.path);
    if (["package-lock.json", "npm-shrinkwrap.json"].includes(name)) all.push(...packageLock(manifest.path, manifest.text));
    else if (["pipfile.lock", "composer.lock"].includes(name)) all.push(...jsonDependencies(manifest.path, manifest.text));
    else if (name === "cargo.lock") all.push(...blockPackages(manifest.path, manifest.text, "cargo"));
    else if (name === "poetry.lock") all.push(...blockPackages(manifest.path, manifest.text, "PyPI"));
    else all.push(...lineManifest(manifest.path, manifest.text));
    if (all.length > MAX_COMPONENTS * 2) throw new SbomError("Repository dependency inventory exceeds the component safety limit.", "COMPONENT_LIMIT_EXCEEDED", false, 413);
  }
  const merged = new Map<string, SbomComponent>();
  for (const item of all) {
    const existing = merged.get(item.purl);
    if (existing) { existing.direct ||= item.direct; existing.manifests = [...new Set([...existing.manifests, ...item.manifests])].sort(); }
    else merged.set(item.purl, { ...item });
  }
  const result = [...merged.values()].sort((a, b) => a.purl.localeCompare(b.purl));
  if (result.length > MAX_COMPONENTS) throw new SbomError("Repository dependency inventory exceeds the 5,000-component safety limit.", "COMPONENT_LIMIT_EXCEEDED", false, 413);
  return result;
}

function comparison(current: SbomComponent[], previous: SbomComponent[] | null, previousJobId?: string): SbomComparison {
  if (!previous) return { baseline: true, added: 0, removed: 0, changed: 0, addedComponents: [], removedComponents: [], changedComponents: [] };
  const currentByName = new Map(current.map((item) => [`${item.ecosystem}:${item.name}`, item.version]));
  const previousByName = new Map(previous.map((item) => [`${item.ecosystem}:${item.name}`, item.version]));
  const added = [...currentByName.keys()].filter((key) => !previousByName.has(key));
  const removed = [...previousByName.keys()].filter((key) => !currentByName.has(key));
  const changed = [...currentByName.keys()].filter((key) => previousByName.has(key) && previousByName.get(key) !== currentByName.get(key));
  return { baseline: false, previousJobId, added: added.length, removed: removed.length, changed: changed.length, addedComponents: added.slice(0, 100), removedComponents: removed.slice(0, 100), changedComponents: changed.slice(0, 100) };
}

function buildCycloneDx(repo: string, commit: string, generatedAt: string, archiveDigest: string, manifests: string[], components: SbomComponent[]) {
  return { bomFormat: "CycloneDX", specVersion: "1.6", serialNumber: `urn:uuid:${crypto.randomUUID()}`, version: 1, metadata: { timestamp: generatedAt, tools: { components: [{ type: "application", name: GENERATOR_NAME, version: GENERATOR_VERSION }] }, component: { type: "application", name: repo, version: commit, bom_ref: `repository:${repo}@${commit}` }, properties: [{ name: "scopeproof:repository", value: `https://github.com/${repo}` }, { name: "scopeproof:commit", value: commit }, { name: "scopeproof:sourceArchiveSha256", value: archiveDigest }, { name: "scopeproof:manifests", value: manifests.join(",") }] }, components: components.map((item) => ({ type: "library", name: item.name, version: item.version, purl: item.purl, bom_ref: item.purl, properties: [{ name: "scopeproof:direct", value: String(item.direct) }, { name: "scopeproof:manifests", value: item.manifests.join(",") }] })) };
}

function spdxId(value: string, index: number): string { return `SPDXRef-Package-${index}-${value.replace(/[^A-Za-z0-9.-]+/g, "-").slice(0, 80)}`; }
function buildSpdx(repo: string, commit: string, generatedAt: string, archiveDigest: string, manifests: string[], components: SbomComponent[]) {
  const repoId = "SPDXRef-Repository";
  const packages = components.map((item, index) => ({ SPDXID: spdxId(item.name, index), name: item.name, versionInfo: item.version, downloadLocation: "NOASSERTION", filesAnalyzed: false, externalRefs: [{ referenceCategory: "PACKAGE-MANAGER", referenceType: "purl", referenceLocator: item.purl }], annotations: [{ annotationType: "OTHER", annotator: `Tool: ${GENERATOR_NAME}-${GENERATOR_VERSION}`, annotationDate: generatedAt, comment: `direct=${item.direct}; manifests=${item.manifests.join(",")}` }] }));
  return { spdxVersion: "SPDX-2.3", dataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT", name: `${repo}-${commit.slice(0, 12)}-sbom`, documentNamespace: `https://scopeproof.local/sbom/${crypto.randomUUID()}`, creationInfo: { created: generatedAt, creators: [`Tool: ${GENERATOR_NAME}-${GENERATOR_VERSION}`], comment: `Repository https://github.com/${repo}; commit ${commit}; source archive SHA-256 ${archiveDigest}; manifests ${manifests.join(",")}` }, packages: [{ SPDXID: repoId, name: repo, versionInfo: commit, downloadLocation: `https://github.com/${repo}`, filesAnalyzed: false }, ...packages], relationships: [{ spdxElementId: "SPDXRef-DOCUMENT", relationshipType: "DESCRIBES", relatedSpdxElement: repoId }, ...packages.map((item) => ({ spdxElementId: repoId, relationshipType: "DEPENDS_ON", relatedSpdxElement: item.SPDXID }))] };
}

async function downloadArchive(owner: string, repository: string, commit: string, token?: string): Promise<Uint8Array> {
  const first = await boundedFetch(`https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/zipball/${commit}`, { headers: githubHeaders(token) }, "GitHub repository archive", 64 * 1024);
  if (first.status < 300 || first.status >= 400) return new Uint8Array(await first.arrayBuffer());
  const location = first.headers.get("location");
  if (!location) throw new SbomError("GitHub repository archive redirect is missing.", "GITHUB_INVALID_RESPONSE", false, 502);
  const second = await boundedFetch(location, { headers: { accept: "application/zip", "user-agent": "Scopeproof-SBOM" } }, "GitHub repository archive", MAX_ARCHIVE_BYTES);
  return new Uint8Array(await second.arrayBuffer());
}

export async function queueSbom(input: { assessmentId: string; owner?: string; repository: string; ref: string; format: SbomFormat; credentialMode?: "managed" | "one_time" }, actor: AuthenticatedUser): Promise<string> {
  const env = getEnv();
  const owner = (input.owner || configured(env.GITHUB_ORG, "GITHUB_ORG")).trim();
  const repository = input.repository.trim();
  const ref = input.ref.trim();
  const credentialMode = input.credentialMode === "one_time" ? "one_time" : "managed";
  if (!/^asm_[a-f0-9]{32}$/.test(input.assessmentId) || !isValidGitHubOwner(owner) || !isValidRepositoryName(repository) || !isValidGitRef(ref) || !["cyclonedx_json", "spdx_json"].includes(input.format)) throw new SbomError("Assessment, repository, ref, and SBOM format are required.", "INVALID_REQUEST");
  const assessment = await getAssessment(input.assessmentId);
  if (!assessment || assessment.status !== "active") throw new SbomError("SBOM generation requires an active assessment.", "ASSESSMENT_NOT_ACTIVE", false, 409);
  const controls = assessment.controls as string[];
  if (controls.length && !controls.includes("6.3.2")) throw new SbomError("The assessment does not include PCI DSS control 6.3.2.", "OUT_OF_SCOPE", false, 422);
  const fullName = `${owner}/${repository}`;
  const systems = assessment.systems as string[];
  if (systems.length && !systems.some((value) => [fullName, owner, "github"].includes(value.toLowerCase() === "github" ? "github" : value))) throw new SbomError(`Repository ${fullName} is outside the assessment system scope. Add ${fullName}, ${owner}, or GitHub to a new assessment scope.`, "OUT_OF_SCOPE", false, 422);
  const id = randomId("sbom");
  await executeAuditedBatch(actor, "sbom.queued", "sbom_job", id, { assessmentId: input.assessmentId, repository: fullName, requestedRef: ref, format: input.format, credentialMode }, [
    env.DB.prepare("INSERT INTO sbom_jobs (id, requested_by, assessment_id, repository_owner, repository_name, repository_full_name, requested_ref, format, max_attempts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(id, actor.id, input.assessmentId, owner, repository, fullName, ref, input.format, credentialMode === "one_time" ? 1 : 3),
  ]);
  return id;
}

export async function processSbom(jobId: string, actor: AuthenticatedUser, credential?: SbomCredential): Promise<Record<string, unknown>> {
  const env = getEnv();
  const job = await env.DB.prepare("SELECT * FROM sbom_jobs WHERE id = ?").bind(jobId).first<Record<string, unknown>>();
  if (!job) throw new SbomError("SBOM job not found.", "NOT_FOUND", false, 404);
  const currentActor = await loadActiveUser(String(job.requested_by || ""));
  try {
    if (!currentActor || currentActor.id !== actor.id) throw new Error("requester mismatch");
    assertPermission(currentActor, "generate_sbom");
  } catch {
    const completedAt = new Date().toISOString();
    await executeAuditedBatch(sbomSystemActor, "sbom.authorization_revoked", "sbom_job", jobId, { requestedBy: job.requested_by, code: "AUTHORIZATION_REVOKED" }, [
      env.DB.prepare("UPDATE sbom_jobs SET status = 'failed', error_code = 'AUTHORIZATION_REVOKED', error_message = 'The requesting user is no longer authorized to generate SBOMs.', completed_at = ?, lease_id = NULL, lease_expires_at = NULL WHERE id = ? AND status IN ('queued', 'retrying', 'running')").bind(completedAt, jobId),
    ], { sql: "EXISTS (SELECT 1 FROM sbom_jobs WHERE id = ? AND status = 'failed' AND error_code = 'AUTHORIZATION_REVOKED')", bindings: [jobId] });
    return (await getSbomJob(jobId)) || {};
  }
  actor = currentActor;
  const attempt = Number(job.attempt || 0) + 1;
  const leaseId = randomId("lease");
  const now = new Date().toISOString();
  const leaseExpires = new Date(Date.now() + 10 * 60_000).toISOString();
  const [claim] = await executeAuditedBatch(actor, "sbom.started", "sbom_job", jobId, { attempt, leaseId }, [env.DB.prepare("UPDATE sbom_jobs SET status = 'running', attempt = ?, started_at = ?, lease_id = ?, lease_expires_at = ?, error_code = NULL, error_message = NULL WHERE id = ? AND (status = 'queued' OR (status = 'retrying' AND next_attempt_at <= ?) OR (status = 'running' AND lease_expires_at < ?))").bind(attempt, now, leaseId, leaseExpires, jobId, now, now)], { sql: "EXISTS (SELECT 1 FROM sbom_jobs WHERE id = ? AND lease_id = ?)", bindings: [jobId, leaseId] });
  if (!claim.meta.changes) return job;
  try {
    const owner = String(job.repository_owner); const repository = String(job.repository_name); const fullName = String(job.repository_full_name);
    const credentialMode = credential?.mode || "managed";
    if (credential && credential.owner !== owner) throw new SbomError("The one-time credential does not match the queued repository owner.", "CREDENTIAL_SCOPE_MISMATCH", false, 422);
    const token = credentialMode === "one_time" ? validateOneTimeGitHubToken(credential?.token || "") : undefined;
    const commit = await githubJson<{ sha: string }>(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repository)}/commits/${encodeURIComponent(String(job.requested_ref))}`, "GitHub commit resolution", 2 * 1024 * 1024, token);
    if (!/^[a-f0-9]{40}$/.test(commit.sha)) throw new SbomError("GitHub returned an invalid commit identifier.", "GITHUB_INVALID_RESPONSE", false, 502);
    const archive = await downloadArchive(owner, repository, commit.sha, token);
    const archiveDigest = await sha256(archive);
    const manifests = extractDependencyManifests(archive);
    if (!manifests.length) throw new SbomError("No supported dependency lockfiles were found in this repository ref.", "NO_SUPPORTED_MANIFESTS", false, 422);
    const components = parseDependencyManifests(manifests);
    if (!components.length) throw new SbomError("Supported lockfiles were found, but no pinned dependency versions could be parsed.", "NO_COMPONENTS", false, 422);
    const previous = await env.DB.prepare("SELECT id, components_json FROM sbom_jobs WHERE assessment_id = ? AND repository_full_name = ? AND status = 'completed' AND id != ? ORDER BY completed_at DESC LIMIT 1").bind(job.assessment_id, fullName, jobId).first<{ id: string; components_json: string }>();
    const delta = comparison(components, previous ? JSON.parse(previous.components_json) as SbomComponent[] : null, previous?.id);
    const generatedAt = new Date().toISOString();
    const document = String(job.format) === "spdx_json" ? buildSpdx(fullName, commit.sha, generatedAt, archiveDigest, manifests.map((item) => item.path), components) : buildCycloneDx(fullName, commit.sha, generatedAt, archiveDigest, manifests.map((item) => item.path), components);
    const bytes = new TextEncoder().encode(`${JSON.stringify(document, null, 2)}\n`);
    const assessment = await getAssessment(String(job.assessment_id));
    if (!assessment) throw new SbomError("Assessment no longer exists.", "ASSESSMENT_NOT_FOUND", false, 409);
    const systems = assessment.systems as string[];
    const system = systems.find((value) => value === fullName) || systems.find((value) => value === owner) || systems.find((value) => value.toLowerCase() === "github") || fullName;
    const stored = await storeEvidence({ controlId: "6.3.2", framework: String(assessment.framework), title: `${String(job.format) === "spdx_json" ? "SPDX" : "CycloneDX"} SBOM — ${fullName}@${commit.sha.slice(0, 12)}`, description: `Static, non-executing dependency inventory generated from ${manifests.length} lockfile(s) at immutable Git commit ${commit.sha}.`, type: "report", source: "Scopeproof SBOM", system, environment: "source repository", assessmentPeriod: `${assessment.period_start} – ${assessment.period_end}`, evidenceOwner: actor.email, tags: ["SBOM", String(job.format) === "spdx_json" ? "SPDX 2.3" : "CycloneDX 1.6", `repository:${fullName}`, `commit:${commit.sha}`, `credential:${credentialMode}`, `generator:${GENERATOR_NAME}@${GENERATOR_VERSION}`], expectedEvidence: "Software inventory with immutable source provenance for PCI DSS 6.3.2.", contentType: String(job.format) === "spdx_json" ? "application/spdx+json" : "application/vnd.cyclonedx+json", bytes, jobId, capturedAt: generatedAt, validityDays: 365, createdBy: actor, assessmentId: String(job.assessment_id), coverageStatus: "complete", coverage: { complete: true, repository: fullName, requestedRef: job.requested_ref, resolvedCommitSha: commit.sha, sourceArchiveSha256: archiveDigest, manifests: manifests.map((item) => item.path), componentCount: components.length, directDependencyCount: components.filter((item) => item.direct).length, credentialMode, generator: `${GENERATOR_NAME}@${GENERATOR_VERSION}`, comparison: delta } });
    const completedAt = new Date().toISOString();
    await executeAuditedBatch(actor, "sbom.completed", "sbom_job", jobId, { repository: fullName, resolvedCommitSha: commit.sha, evidenceId: stored.id, artifactSha256: stored.sha256, componentCount: components.length, manifestCount: manifests.length, credentialMode, comparison: delta }, [env.DB.prepare("UPDATE sbom_jobs SET status = 'completed', resolved_commit_sha = ?, evidence_id = ?, previous_job_id = ?, component_count = ?, direct_dependency_count = ?, manifest_count = ?, source_archive_sha256 = ?, artifact_sha256 = ?, manifests_json = ?, components_json = ?, comparison_json = ?, completed_at = ?, lease_id = NULL, lease_expires_at = NULL WHERE id = ? AND status = 'running' AND lease_id = ?").bind(commit.sha, stored.id, previous?.id || null, components.length, components.filter((item) => item.direct).length, manifests.length, archiveDigest, stored.sha256, stableJson(manifests.map((item) => item.path)), stableJson(components), stableJson(delta), completedAt, jobId, leaseId)], { sql: "EXISTS (SELECT 1 FROM sbom_jobs WHERE id = ? AND status = 'completed' AND evidence_id = ?)", bindings: [jobId, stored.id] });
    return (await getSbomJob(jobId)) || {};
  } catch (error) {
    const failure = error instanceof SbomError ? error : new SbomError(error instanceof Error ? error.message : "SBOM generation failed.", "INTERNAL_ERROR", true, 500);
    const retry = failure.retryable && attempt < Number(job.max_attempts || 3);
    const retryAt = retry ? new Date(Date.now() + Math.min(60 * 60_000, 2 ** attempt * 60_000)).toISOString() : null;
    await executeAuditedBatch(actor, retry ? "sbom.retry_scheduled" : "sbom.failed", "sbom_job", jobId, { attempt, code: failure.code, retryAt }, [env.DB.prepare("UPDATE sbom_jobs SET status = ?, next_attempt_at = ?, error_code = ?, error_message = ?, completed_at = ?, lease_id = NULL, lease_expires_at = NULL WHERE id = ? AND status = 'running' AND lease_id = ?").bind(retry ? "retrying" : "failed", retryAt, failure.code, failure.message.slice(0, 1000), retry ? null : new Date().toISOString(), jobId, leaseId)]);
    return (await getSbomJob(jobId)) || {};
  }
}

export async function getSbomJob(id: string): Promise<Record<string, unknown> | null> {
  if (!/^sbom_[a-f0-9]{32}$/.test(id)) return null;
  const row = await getEnv().DB.prepare("SELECT id, requested_by, assessment_id, repository_full_name, requested_ref, resolved_commit_sha, format, status, attempt, max_attempts, evidence_id, previous_job_id, component_count, direct_dependency_count, manifest_count, source_archive_sha256, artifact_sha256, generator_name, generator_version, manifests_json, comparison_json, error_code, error_message, created_at, started_at, completed_at FROM sbom_jobs WHERE id = ?").bind(id).first<Record<string, unknown>>();
  return row ? { ...row, manifests: JSON.parse(String(row.manifests_json || "[]")), comparison: JSON.parse(String(row.comparison_json || "{}")), manifests_json: undefined, comparison_json: undefined } : null;
}

export async function listSbomJobs(assessmentId?: string): Promise<Array<Record<string, unknown>>> {
  const query = assessmentId ? getEnv().DB.prepare("SELECT id FROM sbom_jobs WHERE assessment_id = ? ORDER BY created_at DESC LIMIT 100").bind(assessmentId) : getEnv().DB.prepare("SELECT id FROM sbom_jobs ORDER BY created_at DESC LIMIT 100");
  const ids = (await query.all<{ id: string }>()).results;
  return (await Promise.all(ids.map((row) => getSbomJob(row.id)))).filter((row): row is Record<string, unknown> => Boolean(row));
}

export async function processDueSbomWork(now = new Date()): Promise<void> {
  const env = getEnv();
  const exhausted = (await env.DB.prepare("SELECT id, requested_by FROM sbom_jobs WHERE status = 'running' AND lease_expires_at < ? AND attempt >= max_attempts ORDER BY lease_expires_at LIMIT 3").bind(now.toISOString()).all<{ id: string; requested_by: string }>()).results;
  for (const job of exhausted) await executeAuditedBatch(sbomSystemActor, "sbom.failed", "sbom_job", job.id, { code: "LEASE_EXPIRED", retryAt: null, requestedBy: job.requested_by }, [env.DB.prepare("UPDATE sbom_jobs SET status = 'failed', error_code = 'LEASE_EXPIRED', error_message = 'The SBOM job ended before completion and no retry attempt remains. Start a new job.', completed_at = ?, lease_id = NULL, lease_expires_at = NULL WHERE id = ? AND status = 'running' AND lease_expires_at < ? AND attempt >= max_attempts").bind(now.toISOString(), job.id, now.toISOString())], { sql: "EXISTS (SELECT 1 FROM sbom_jobs WHERE id = ? AND status = 'failed' AND error_code = 'LEASE_EXPIRED')", bindings: [job.id] });
  const jobs = (await env.DB.prepare("SELECT id, requested_by FROM sbom_jobs WHERE (status = 'retrying' AND next_attempt_at <= ? AND attempt < max_attempts) OR (status = 'running' AND lease_expires_at < ? AND attempt < max_attempts) ORDER BY next_attempt_at LIMIT 3").bind(now.toISOString(), now.toISOString()).all<{ id: string; requested_by: string }>()).results;
  for (const job of jobs) {
    const user = await loadActiveUser(job.requested_by);
    if (user) await processSbom(job.id, user);
    else await processSbom(job.id, { id: job.requested_by, email: "revoked@scopeproof.invalid", displayName: "Revoked requester", role: "auditor" });
  }
}
