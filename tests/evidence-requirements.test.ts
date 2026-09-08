import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync, type SQLInputValue } from "node:sqlite";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";
import { PACKAGE_ELIGIBLE_EVIDENCE_SQL } from "../lib/server/package-eligibility.ts";

async function fixture() {
  const db = new DatabaseSync(":memory:");
  const journal = JSON.parse(await readFile(new URL("../drizzle/meta/_journal.json", import.meta.url), "utf8")) as { entries: Array<{ tag: string }> };
  for (const entry of journal.entries) db.exec(await readFile(new URL(`../drizzle/${entry.tag}.sql`, import.meta.url), "utf8"));
  const sql = (query: string) => {
    let bindings: SQLInputValue[] = [];
    const statement = { bind: (...values: SQLInputValue[]) => { bindings = values; return statement; },
      first: async () => db.prepare(query).get(...bindings) || null,
      all: async () => ({ results: db.prepare(query).all(...bindings) }),
      run: () => ({ meta: { changes: Number(db.prepare(query).run(...bindings).changes) } }) };
    return statement;
  };
  let ids = 0;
  const dependencies: Record<string, unknown> = {
    "./env": { getEnv: () => ({ DB: { prepare: sql } }) },
    "./assessments": { getAssessment: async (id: string) => {
      const row = db.prepare("SELECT * FROM assessments WHERE id = ?").get(id);
      return row ? { ...row, controls: JSON.parse(String(row.controls_json)), systems: JSON.parse(String(row.systems_json)) } : null;
    } },
    "./crypto": { randomId: () => `req_${++ids}` },
    "./audit": { executeAuditedBatch: async (_actor: unknown, _action: unknown, _type: unknown, _id: unknown, _details: unknown, statements: Array<{ run: () => unknown }>) => statements.map((statement) => statement.run()) },
    "./package-eligibility": { PACKAGE_ELIGIBLE_EVIDENCE_SQL },
  };
  const exports: Record<string, (...args: unknown[]) => Promise<unknown>> = {};
  const source = await readFile(new URL("../lib/server/evidence-requirements.ts", import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  new vm.Script(compiled).runInContext(vm.createContext({ exports, require: (name: string) => dependencies[name], Response, Date, console }));
  db.exec(`INSERT INTO users(id,email,display_name,role,status) VALUES ('owner','owner@example.test','Owner','compliance_lead','active');
    INSERT INTO assessments(id,name,framework,period_start,period_end,systems_json,controls_json,catalog_id,scope_mode,owner_id,status)
    VALUES ('assessment','Audit','PCI DSS 4.0.1','2026-01-01','2026-12-31','["A","B"]','["1.2.5"]','catalog','explicit','owner','active');`);
  return { db, api: exports };
}

test("requirements retain revisions, reject stale or foreign edits, and preserve per-system ownership gaps", async () => {
  const { db, api } = await fixture();
  try {
    const input = { assessmentId: "assessment", controlId: "1.2.5", system: "A", expectedRevision: 0, minimumArtifacts: 1, ownerId: "owner", reason: "Owner confirms the evidence expectation for system A." };
    await api.reviseEvidenceRequirement({ id: "owner" }, input);
    await assert.rejects(api.reviseEvidenceRequirement({ id: "owner" }, input), (error: unknown) => error instanceof Response && error.status === 409);
    await api.reviseEvidenceRequirement({ id: "owner" }, { ...input, expectedRevision: 1, minimumArtifacts: 2, reason: "Two independent artifacts are needed for this system." });
    assert.equal(db.prepare("SELECT COUNT(*) AS n FROM evidence_requirements").get()!.n, 2);
    const result = await api.listEvidenceRequirements("assessment") as { requirements: Array<{ system: string; minimumArtifacts: number; revision: number; ownerMissing: boolean; satisfied: boolean }>; summary: { satisfied: number } };
    assert.equal(result.requirements[0].revision, 2);
    assert.equal(result.requirements[0].minimumArtifacts, 2);
    assert.equal(result.requirements[1].ownerMissing, true);
    assert.equal(result.summary.satisfied, 0);
    await assert.rejects(api.reviseEvidenceRequirement({ id: "owner" }, { ...input, system: "customer-B-secret" }), (error: unknown) => error instanceof Response && error.status === 422);
    db.exec("UPDATE users SET status='suspended' WHERE id='owner'");
    const suspended = await api.listEvidenceRequirements("assessment") as { requirements: Array<{ ownerMissing: boolean }> };
    assert.equal(suspended.requirements[0].ownerMissing, true);
    db.exec("UPDATE assessments SET status='closed'");
    await assert.rejects(api.reviseEvidenceRequirement({ id: "owner" }, { ...input, expectedRevision: 2 }), (error: unknown) => error instanceof Response && error.status === 409);
  } finally { db.close(); }
});

test("requirement satisfaction never borrows eligible artifacts from another system or substitutes a missing owner", async () => {
  const { db, api } = await fixture();
  try {
    const evaluate = api.requirementResult;
    assert.equal((await evaluate({ eligible: 1, minimumArtifacts: 1, ownerId: "owner", ownerActive: true }) as { satisfied: boolean }).satisfied, true);
    assert.equal((await evaluate({ eligible: 0, minimumArtifacts: 1, ownerId: "owner", ownerActive: true }) as { satisfied: boolean }).satisfied, false);
    assert.equal((await evaluate({ eligible: 3, minimumArtifacts: 1, ownerId: null, ownerActive: false }) as { satisfied: boolean }).satisfied, false);
    for (const system of ["A", "B"]) await api.reviseEvidenceRequirement({ id: "owner" }, { assessmentId: "assessment", controlId: "1.2.5", system, expectedRevision: 0, minimumArtifacts: 1, ownerId: "owner", reason: "Each system must independently satisfy this expectation." });
    db.exec(`INSERT INTO evidence_artifacts(id,control_id,title,type,source,system,r2_key,content_type,byte_size,sha256,encryption_iv,captured_at,expires_at,created_by,assessment_id)
      VALUES ('evidence-A','1.2.5','System A evidence','report','manual','A','test/a','text/plain',1,'hash','iv','2026-01-01','2030-01-01','collector','assessment');
      INSERT INTO evidence_occurrences(id,artifact_id,created_by,captured_at,received_at,expires_at,status,coverage_status)
      VALUES ('occ-A','evidence-A','collector','2026-01-01','2026-01-01','2030-01-01','approved','complete');`);
    const result = await api.listEvidenceRequirements("assessment") as { requirements: Array<{ system: string; eligible: number; satisfied: boolean }> };
    assert.equal(result.requirements.find((item) => item.system === "A")!.satisfied, true);
    assert.equal(result.requirements.find((item) => item.system === "B")!.satisfied, false);
    assert.equal(result.requirements.find((item) => item.system === "B")!.eligible, 0);
    db.exec("UPDATE evidence_occurrences SET status='superseded'");
    const superseded = await api.listEvidenceRequirements("assessment") as { requirements: Array<{ eligible: number }> };
    assert.equal(superseded.requirements[0].eligible, 0);
  } finally { db.close(); }
});
