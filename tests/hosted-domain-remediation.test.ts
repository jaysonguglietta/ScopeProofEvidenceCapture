import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";
import { analyzeDependencyManifests, comparison, buildCycloneDx, buildSpdx, type SbomComponent } from "../lib/server/sbom-inventory.ts";
import { evidenceWithinAssessmentScopeSql } from "../lib/server/assessment-scope.ts";
import { evidenceReviewPolicy } from "../lib/server/evidence-review-policy.ts";
import * as jobWatch from "../lib/server/job-watch.ts";
import { PACKAGE_ELIGIBILITY_COUNTS_SQL, PACKAGE_ELIGIBLE_EVIDENCE_SQL, PACKAGE_ELIGIBILITY_PUBLISH_FENCE_SQL, packageEligibilityBindings, packageEligibilityPublishFenceBindings } from "../lib/server/package-eligibility.ts";

async function isolatedModule(path: string, dependencies: Record<string, unknown>, globals: Record<string, unknown> = {}): Promise<Record<string, (...args: unknown[]) => Promise<unknown>>> {
  const source = await readFile(new URL(`../${path}`, import.meta.url), "utf8");
  const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  const exports = {};
  const context = vm.createContext({ exports, require: (name: string) => dependencies[name] || {}, Response, Request, URL, TextEncoder, TextDecoder, AbortSignal, crypto, console, ...globals });
  new vm.Script(js, { filename: path }).runInContext(context);
  return exports as Record<string, (...args: unknown[]) => Promise<unknown>>;
}

test("npm v1 traverses nested dependencies and preserves simultaneous versions", () => {
  const result = analyzeDependencyManifests([{ path: "package-lock.json", text: JSON.stringify({ lockfileVersion: 1, dependencies: {
    alpha: { version: "1.0.0", dependencies: { beta: { version: "2.0.0" }, alpha: { version: "0.9.0" } } },
  } }) }]);
  assert.equal(result.complete, true);
  assert.deepEqual(result.components.map((item) => item.purl), ["pkg:npm/alpha@0.9.0", "pkg:npm/alpha@1.0.0", "pkg:npm/beta@2.0.0"]);
  assert.equal(result.components.find((item) => item.version === "0.9.0")?.direct, false);
});

test("npm modern inventories are versioned, linked/malformed entries cannot imply completeness", () => {
  for (const lockfileVersion of [2, 3]) {
    const result = analyzeDependencyManifests([{ path: "package-lock.json", text: JSON.stringify({ lockfileVersion, packages: {
      "": { dependencies: { alpha: "1.0.0" } }, "node_modules/alpha": { version: "1.0.0" }, "node_modules/alpha/node_modules/alpha": { version: "0.9.0" },
    } }) }]);
    assert.equal(result.complete, true);
    assert.equal(result.components.filter((item) => item.direct).length, 1);
  }
  assert.throws(() => analyzeDependencyManifests([{ path: "package-lock.json", text: '{"lockfileVersion":99}' }]), /unsupported npm lockfile version/);
  const linked = analyzeDependencyManifests([{ path: "package-lock.json", text: '{"lockfileVersion":3,"packages":{"node_modules/a":{"link":true},"node_modules/b":{"version":"git+https://example.invalid/b"}}}' }]);
  assert.equal(linked.complete, false);
  assert.ok(linked.warnings.length);
  const mixed = analyzeDependencyManifests([{ path: "package-lock.json", text: '{"lockfileVersion":1,"dependencies":{"a":{"version":"1.0.0"}}}' }, { path: "yarn.lock", text: "__metadata:\n  version: 8\n" }]);
  assert.equal(mixed.complete, false);
  assert.equal(mixed.manifests[1].componentCount, 0);
  assert.ok(mixed.manifests[1].warnings.length);
});

test("SBOM delta compares full version identities, reports bounded previews, and is deterministic", () => {
  const component = (version: string, name = "alpha"): SbomComponent => ({ name, version, purl: `pkg:npm/${name}@${version}`, ecosystem: "npm", direct: false, manifests: ["package-lock.json"] });
  const result = comparison([component("2.0.0")], [component("1.0.0"), component("2.0.0")], "baseline");
  assert.equal(result.removed, 1);
  assert.equal(result.changed, 1);
  assert.deepEqual(result.removedComponents, ["pkg:npm/alpha@1.0.0"]);
  assert.deepEqual(result.versionChanges, [{ name: "npm:alpha", previous: ["1.0.0", "2.0.0"], current: ["2.0.0"] }]);
  const added = comparison(Array.from({ length: 150 }, (_, i) => component("1.0.0", `package-${i}`)), []);
  assert.equal(added.added, 150);
  assert.equal(added.addedComponents.length, 100);
  assert.equal(added.detailsTruncated, true);
  assert.deepEqual(comparison([component("2.0.0"), component("1.0.0")], [component("1.0.0"), component("2.0.0")]).versionChanges, []);
});

test("SBOM format builders use the CycloneDX bom-ref spelling and consistent purl identities", () => {
  const components = analyzeDependencyManifests([{ path: "package-lock.json", text: '{"lockfileVersion":1,"dependencies":{"alpha":{"version":"1.0.0"}}}' }]).components;
  const bom = buildCycloneDx("org/repo", "a".repeat(40), "2026-09-08T00:00:00.000Z", "b".repeat(64), ["package-lock.json"], components);
  assert.equal(bom.metadata.component["bom-ref"], `repository:org/repo@${"a".repeat(40)}`);
  assert.equal(bom.components[0]["bom-ref"], components[0].purl);
  assert.ok(!JSON.stringify(bom).includes("bom_ref"));
  assert.equal(buildSpdx("org/repo", "a".repeat(40), "2026-09-08T00:00:00.000Z", "b".repeat(64), [], components).packages.length, 2);
});

test("current scope governs real SQLite package selection, counts, byte preflight and publication", () => {
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE assessments(id TEXT PRIMARY KEY, framework TEXT, scope_mode TEXT, catalog_id TEXT, systems_json TEXT, controls_json TEXT);
    INSERT INTO assessments VALUES ('asm_test','PCI DSS 4.0.1','explicit','catalog','["A","B"]','["1.2.5","6.3.2"]');
    CREATE TABLE evidence_artifacts(id TEXT PRIMARY KEY, assessment_id TEXT, framework TEXT, system TEXT, control_id TEXT, byte_size INTEGER, type TEXT, device_id TEXT, sha256 TEXT, manifest_sha256 TEXT, chain_event_hash TEXT, source TEXT, environment TEXT, assessment_period TEXT, collector_id TEXT, server_safety_scan_sha256 TEXT, server_safety_scan_policy TEXT, server_safety_scan_completed_at TEXT, server_safety_scanner_origin TEXT, server_safety_receipt_sha256 TEXT);
    CREATE TABLE evidence_occurrences(id TEXT PRIMARY KEY, artifact_id TEXT, status TEXT, expires_at TEXT, coverage_status TEXT, received_at TEXT, captured_at TEXT);
    CREATE TABLE native_evidence_manifests(artifact_id TEXT, device_id TEXT, image_sha256 TEXT, manifest_sha256 TEXT, chain_sequence INTEGER, chain_event_hash TEXT, provenance_key_id TEXT);
    CREATE TABLE capture_devices(id TEXT, provenance_key_id TEXT, chain_sequence INTEGER);`);
  for (const [id, system, control, bytes] of [["a", "A", "1.2.5", 100], ["b", "B", "6.3.2", 200]] as const) {
    db.prepare("INSERT INTO evidence_artifacts(id,assessment_id,framework,system,control_id,byte_size,type) VALUES (?,'asm_test','PCI DSS 4.0.1',?,?,?,'report')").run(id, system, control, bytes);
    db.prepare("INSERT INTO evidence_occurrences VALUES (?,?, 'approved','2030-01-01','complete','2026-01-01','2026-01-01')").run(`occ-${id}`, id);
  }
  const at = "2026-09-08T00:00:00.000Z";
  const counts = () => db.prepare(PACKAGE_ELIGIBILITY_COUNTS_SQL).get(...packageEligibilityBindings("asm_test", at))!;
  assert.equal(counts().eligible, 2);
  assert.equal(counts().eligible_bytes, 300);
  db.exec(`UPDATE assessments SET systems_json='["A"]',controls_json='["1.2.5"]'`);
  assert.equal(counts().total, 2);
  assert.equal(counts().eligible, 1);
  assert.equal(counts().out_of_scope, 1);
  assert.equal(counts().eligible_bytes, 100);
  const selected = db.prepare(`SELECT e.id FROM evidence_artifacts e JOIN evidence_occurrences o ON o.artifact_id=e.id WHERE e.assessment_id=? AND ${PACKAGE_ELIGIBLE_EVIDENCE_SQL}`).all("asm_test", at);
  assert.deepEqual(selected.map((row) => row.id), ["a"]);
  const fence = () => db.prepare(`SELECT ${PACKAGE_ELIGIBILITY_PUBLISH_FENCE_SQL} AS allowed`).get(...packageEligibilityPublishFenceBindings("asm_test", at, 2, 1) as Array<string | number>)!.allowed;
  assert.equal(fence(), 1);
  db.exec(`UPDATE evidence_artifacts SET byte_size=26214401 WHERE id='a'`);
  assert.equal(fence(), 0);
  db.exec(`UPDATE assessments SET systems_json='not-json'`);
  assert.equal(counts().eligible, 0);
  assert.equal(fence(), 0);
  assert.throws(() => evidenceWithinAssessmentScopeSql("e; DROP TABLE evidence_artifacts"));
  db.close();
});

test("review affordances use independent latest creator and only legal current-state actions", () => {
  const base = { role: "reviewer", actorId: "reviewer", creatorId: "collector", status: "needs_review", expiresAt: "2030-01-01", inScope: true, coverage: "complete", safetyReady: true, provenanceReady: true };
  assert.deepEqual(evidenceReviewPolicy(base).allowedActions, ["approve", "reject", "return"]);
  assert.deepEqual(evidenceReviewPolicy({ ...base, creatorId: "reviewer" }).allowedActions, []);
  assert.deepEqual(evidenceReviewPolicy({ ...base, status: "rejected" }).allowedActions, ["reopen"]);
  assert.deepEqual(evidenceReviewPolicy({ ...base, status: "approved" }).allowedActions, ["supersede"]);
  assert.ok(!evidenceReviewPolicy({ ...base, inScope: false }).allowedActions.includes("approve"));
  assert.ok(!evidenceReviewPolicy({ ...base, coverage: "partial" }).allowedActions.includes("approve"));
});

test("actual SBOM route polling never performs discovery or consumes its hourly quota", async () => {
  const quotas: string[] = []; let discoveries = 0;
  const mod = await isolatedModule("app/api/sboms/route.ts", {
    "../../../lib/server/auth": { requireApiUser: async () => ({ id: "operator" }), assertPermission: () => undefined, jsonError: (error: unknown) => { throw error; } },
    "../../../lib/server/env": { getEnv: () => ({ GITHUB_TOKEN: "synthetic", GITHUB_ORG: "org" }) },
    "../../../lib/server/job-watch": jobWatch,
    "../../../lib/server/rate-limit": { enforceRateLimit: async (_request: unknown, _user: unknown, route: string) => { quotas.push(route); } },
    "../../../lib/server/sbom": { listSbomJobsPage: async () => ({ jobs: [], summary: { active: 3 } }), listSbomRepositoriesCached: async () => { discoveries += 1; return []; }, SbomError: class extends Error {} },
  });
  for (let i = 0; i < 20; i += 1) {
    const response = await mod.GET(new Request("https://workspace.example/api/sboms")) as Response;
    assert.equal(response.status, 200); assert.equal((await response.json() as { activeCount: number }).activeCount, 3);
  }
  assert.equal(discoveries, 0);
  assert.equal(quotas.filter((name) => name === "sbom:repository-discovery").length, 0);
  assert.equal((await mod.GET(new Request("https://workspace.example/api/sboms?discoverRepositories=true")) as Response).status, 200);
  assert.equal(discoveries, 1);
});

test("actual Cloudflare collector visits each selected zone once across every batch boundary", async () => {
  for (const size of [1, 5, 6, 10, 11, 250]) {
    const ids = Array.from({ length: size }, (_, i) => `zone-${i}`); const visited: string[] = [];
    const mod = await isolatedModule("lib/server/collectors.ts", { "./env": { getEnv: () => ({ CLOUDFLARE_API_TOKEN: "synthetic", CLOUDFLARE_ACCOUNT_ID: "account", CLOUDFLARE_ZONE_IDS: ids.join(",") }) } }, {
      fetch: async (url: string) => { visited.push(new URL(url).pathname.split("/")[4]); return Response.json({ result: {} }); },
    });
    const result = await mod.runCollector("cloudflare", { config: {}, actor: {} }) as { coverage: { complete: boolean } };
    assert.equal(result.coverage.complete, true);
    assert.deepEqual(visited, ids);
  }
});

test("actual approval route returns conflict and authoritative evidence when no mutation occurred", async () => {
  const mod = await isolatedModule("app/api/evidence/[id]/route.ts", {
    "../../../../lib/server/auth": { requireSameOrigin: () => undefined, requireApiPermission: async () => ({ id: "reviewer" }), jsonError: (error: unknown) => { throw error; } },
    "../../../../lib/server/rate-limit": { enforceRateLimit: async () => undefined, requireBoundedContentLength: () => undefined },
    "../../../../lib/server/evidence": { approveEvidence: async () => false, getEvidenceMetadata: async () => ({ id: "evidence", status: "rejected", allowedActions: ["reopen"] }) },
  });
  const response = await mod.PATCH(new Request("https://workspace.example/api/evidence/evidence", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "approve", confirmedActualArtifact: true }) }), { params: Promise.resolve({ id: "evidence" }) }) as Response;
  assert.equal(response.status, 409);
  const body = await response.json() as { changed: boolean; evidence: { status: string } }; assert.equal(body.changed, false); assert.equal(body.evidence.status, "rejected");
});
