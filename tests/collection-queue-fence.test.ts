import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";

type Binding = string | number | null;
type Result = { meta: { changes: number } };
type Statement = { bind: (...bindings: Binding[]) => Statement; first: () => Promise<unknown>; run: () => Promise<Result> };
const assessmentId = `asm_${"a".repeat(32)}`;
const actor = { id: "owner", email: "owner@example.test", displayName: "Owner", role: "compliance_lead" };

function loadModule(path: string, dependencies: Record<string, unknown>) {
  const source = readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
  const output = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  const exports: Record<string, (...args: unknown[]) => Promise<unknown>> = {};
  new vm.Script(output, { filename: path }).runInContext(vm.createContext({ exports, require: (name: string) => dependencies[name] || {}, Response, console, Date }));
  return exports;
}

function fixture() {
  const sqlite = new DatabaseSync(":memory:");
  const journal = JSON.parse(readFileSync(new URL("../drizzle/meta/_journal.json", import.meta.url), "utf8")) as { entries: Array<{ tag: string }> };
  for (const entry of journal.entries) sqlite.exec(readFileSync(new URL(`../drizzle/${entry.tag}.sql`, import.meta.url), "utf8"));
  sqlite.exec(`INSERT INTO users(id,email,display_name,role,status) VALUES ('owner','owner@example.test','Owner','compliance_lead','active');
    INSERT INTO assessments(id,name,framework,period_start,period_end,systems_json,controls_json,catalog_id,scope_mode,owner_id,status)
    VALUES ('${assessmentId}','Assessment','PCI DSS 4.0.1','2026-01-01','2026-12-31','["A"]','["6.3.2"]','catalog','explicit','owner','active');
    INSERT INTO collectors(id,provider,display_name,enabled,schedule_cron,scheduled_assessment_id,created_by)
    VALUES ('collector_github','github','GitHub',1,'0 7 * * *','${assessmentId}','owner');`);
  let beforeBatch: (() => void) | undefined;
  const DB = {
    prepare: (sql: string): Statement => {
      const statement = sqlite.prepare(sql);
      let bindings: Binding[] = [];
      const handle: Statement = {
        bind: (...values) => { bindings = values; return handle; },
        first: async () => statement.get(...bindings) || null,
        run: async () => ({ meta: { changes: Number(statement.run(...bindings).changes) } }),
      };
      return handle;
    },
    batch: async (statements: Statement[]) => {
      const race = beforeBatch; beforeBatch = undefined; race?.();
      sqlite.exec("BEGIN");
      try { const results = []; for (const statement of statements) results.push(await statement.run()); sqlite.exec("COMMIT"); return results; }
      catch (error) { sqlite.exec("ROLLBACK"); throw error; }
    },
  };
  let id = 0;
  const dependencies = {
    "./env": { getEnv: () => ({ DB }) },
    "./crypto": {
      randomId: (prefix: string) => `${prefix}_${(++id).toString(16).padStart(32, "0")}`,
      stableJson: JSON.stringify,
      sha256: async (value: string) => createHash("sha256").update(value).digest("hex"),
      activeAuditKeyId: () => "fixture-audit-v1",
      hmac: async (value: string) => createHmac("sha256", "offline-test-only").update(value).digest("hex"),
    },
  };
  // Execute the actual audited transaction implementation, including its change
  // guard and conditional immutable audit INSERT, against migrated SQLite.
  const audit = loadModule("lib/server/audit.ts", dependencies);
  const jobs = loadModule("lib/server/jobs.ts", { ...dependencies, "./audit": audit });
  return { sqlite, queue: jobs.queueCollection, race: (mutate: () => void) => { beforeBatch = mutate; } };
}

test("successful manual and scheduled queues persist real jobs and matching immutable audit events", async () => {
  const { sqlite, queue } = fixture();
  try {
    for (const trigger of ["manual", "scheduled", "retry"]) {
      const id = await queue("collector_github", actor, trigger, assessmentId) as string;
      const row = sqlite.prepare("SELECT assessment_id,trigger_type,status FROM collection_jobs WHERE id=?").get(id);
      assert.equal(row?.assessment_id, assessmentId); assert.equal(row?.trigger_type, trigger); assert.equal(row?.status, "queued");
      assert.equal(sqlite.prepare("SELECT action FROM audit_events WHERE resource_id=?").get(id)?.action, "collection.queued");
    }
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get()?.n, 3);
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM audit_batch_guards").get()?.n, 0);
  } finally { sqlite.close(); }
});

test("executed commit races return409 without phantom jobs or audit success for every non-null assessment queue", async () => {
  const mutations = [
    "UPDATE collectors SET enabled=0",
    "UPDATE assessments SET status='closed'",
    "UPDATE assessments SET status='draft'",
    "UPDATE assessments SET scope_mode='legacy_unbounded'",
    "UPDATE assessments SET catalog_id=NULL",
    "UPDATE assessments SET systems_json='[]'",
    "UPDATE assessments SET controls_json='[]'",
    "DELETE FROM assessments",
  ];
  for (const trigger of ["manual", "retry", "scheduled"]) for (const mutation of mutations) {
    const { sqlite, queue, race } = fixture();
    try {
      let ran = false;
      race(() => { ran = true; sqlite.exec(mutation); });
      await assert.rejects(() => queue("collector_github", actor, trigger, assessmentId), (error: unknown) => error instanceof Response && error.status === 409, `${trigger}: ${mutation}`);
      assert.equal(ran, true, "mutation must execute after both validation reads and immediately before the audited write");
      assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM collection_jobs").get()?.n, 0);
      assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get()?.n, 0, "no false collection.queued audit event");
      assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM audit_batch_guards").get()?.n, 0);
    } finally { sqlite.close(); }
  }
});

test("scheduled reassignment and disabled schedules are fenced while manual null-assessment compatibility remains", async () => {
  for (const mutation of ["UPDATE collectors SET scheduled_assessment_id=NULL", "UPDATE collectors SET scheduled_assessment_id='another-assessment'", "UPDATE collectors SET schedule_cron=NULL"]) {
    const { sqlite, queue, race } = fixture();
    try {
      race(() => sqlite.exec(mutation));
      await assert.rejects(() => queue("collector_github", actor, "scheduled", assessmentId), (error: unknown) => error instanceof Response && error.status === 409);
      assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM collection_jobs").get()?.n, 0);
      assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM audit_events").get()?.n, 0);
    } finally { sqlite.close(); }
  }
  const { sqlite, queue } = fixture();
  try {
    const id = await queue("collector_github", actor, "manual") as string;
    assert.equal(sqlite.prepare("SELECT assessment_id FROM collection_jobs WHERE id=?").get(id)?.assessment_id, null);
    assert.equal(sqlite.prepare("SELECT action FROM audit_events WHERE resource_id=?").get(id)?.action, "collection.queued");
    await assert.rejects(() => queue("collector_github", actor, "scheduled"), (error: unknown) => error instanceof Response && error.status === 409);
    assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM collection_jobs").get()?.n, 1, "only the explicit legacy-compatible manual job exists");
  } finally { sqlite.close(); }
});
