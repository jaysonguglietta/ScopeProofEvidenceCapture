import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import vm from "node:vm";
import ts from "typescript";
import { comparison, type SbomComponent } from "../lib/server/sbom-inventory.ts";

test("full SBOM detail enforces repository/assessment, reviewer and expiry boundaries and reconciles deltas", async () => {
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE sbom_jobs(id TEXT,evidence_id TEXT,assessment_id TEXT,repository_full_name TEXT,status TEXT,resolved_commit_sha TEXT,generator_name TEXT,generator_version TEXT,components_json TEXT,comparison_json TEXT);
    CREATE TABLE evidence_artifacts(id TEXT,status TEXT);
    CREATE TABLE evidence_occurrences(id TEXT,artifact_id TEXT,expires_at TEXT,status TEXT,received_at TEXT);`);
  const first = `sbom_${"a".repeat(32)}`, second = `sbom_${"b".repeat(32)}`, foreign = `sbom_${"c".repeat(32)}`;
  const components = (v: string): SbomComponent[] => Array.from({ length: 151 }, (_, i) => ({ name: `dep${i}`, ecosystem: "npm", version: v, purl: `pkg:npm/dep${i}@${v}`, direct: false, manifests: ["package-lock.json"] }));
  for (const [id, assessment, repo, version] of [[first, "A", "org/repo", "1.0.0"], [second, "A", "org/repo", "2.0.0"], [foreign, "B", "org/foreign", "1.0.0"]]) {
    db.prepare("INSERT INTO sbom_jobs VALUES (?,?,?,?,?,?,?,?,?,?)").run(id,id,assessment,repo,"completed","a".repeat(40),"scopeproof","2",JSON.stringify(components(version)),"{}");
    db.prepare("INSERT INTO evidence_artifacts VALUES (?, 'needs_review')").run(id);
    db.prepare("INSERT INTO evidence_occurrences VALUES (?,?,'2030-01-01','needs_review','2026-01-01')").run(id,id);
  }
  const DB = { prepare: (sql: string) => ({ bind: (...values: Array<string | number>) => ({ first: async () => db.prepare(sql).get(...values) || null }) }) };
  const exports: { sbomDetail?: (id: string, baseline: string | undefined, actor: { role: string }) => Promise<{ components: unknown[]; comparison: { added: number; addedComponents: unknown[]; changed: number; versionChanges: unknown[]; detailsTruncated: boolean } }> } = {};
  const source = readFileSync(new URL("../lib/server/sbom-detail.ts", import.meta.url), "utf8");
  const code = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  new vm.Script(code).runInContext(vm.createContext({ exports, require: (name: string) => name === "./env" ? { getEnv: () => ({ DB }) } : { comparison }, Response, Date, Set }));
  const detail = await exports.sbomDetail!(second, first, { role: "reviewer" });
  assert.equal(detail.comparison.added, 151); assert.equal(detail.comparison.addedComponents.length, 151);
  assert.equal(detail.comparison.changed, 151); assert.equal(detail.comparison.versionChanges.length, 151); assert.equal(detail.comparison.detailsTruncated, false);
  const baseline = await exports.sbomDetail!(second, undefined, { role: "reviewer" });
  assert.equal(baseline.comparison.added, 0); assert.equal(baseline.comparison.addedComponents.length, 0);
  await assert.rejects(exports.sbomDetail!(second, foreign, { role: "reviewer" }), (error: unknown) => error instanceof Response && error.status === 422);
  await assert.rejects(exports.sbomDetail!(second, undefined, { role: "auditor" }), (error: unknown) => error instanceof Response && error.status === 404);
  db.prepare("UPDATE evidence_occurrences SET status='approved' WHERE id=?").run(second);
  assert.equal((await exports.sbomDetail!(second, undefined, { role: "auditor" })).components.length, 151);
  db.prepare("UPDATE evidence_occurrences SET expires_at='2000-01-01' WHERE id=?").run(second);
  await assert.rejects(exports.sbomDetail!(second, undefined, { role: "reviewer" }), (error: unknown) => error instanceof Response && error.status === 404);
  db.close();
});
