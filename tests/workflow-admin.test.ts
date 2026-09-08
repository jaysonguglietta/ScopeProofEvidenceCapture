import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import vm from "node:vm";
import ts from "typescript";
import React from "react";
import * as jsxRuntime from "react/jsx-runtime";
import { renderToStaticMarkup } from "react-dom/server";
import * as validation from "../lib/server/workflow-validation.ts";
import * as pagination from "../lib/server/pagination.ts";
import * as packageEligibility from "../lib/server/package-eligibility.ts";

async function moduleFrom(path: string, dependencies: Record<string, unknown>) {
  const source = await readFile(new URL(`../${path}`, import.meta.url), "utf8");
  const code = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } }).outputText;
  const exports: Record<string, unknown> = {};
  new vm.Script(code, { filename: path }).runInContext(vm.createContext({ exports, require: (name: string) => dependencies[name] || {}, Response, Request, URL, TextEncoder, TextDecoder, crypto, console, setTimeout, clearTimeout, AbortController }));
  return exports as Record<string, (...args: unknown[]) => unknown>;
}

const assessmentId = `asm_${"a".repeat(32)}`;
const actor = { id: "user:lead", email: "lead@example.test", role: "compliance_lead" };
const assertPermission = (user: { role: string }, permission: string) => { if (user.role === "auditor" || (user.role === "reviewer" && permission === "dispose_findings")) throw new Response(null, { status: 403 }); };
const rejectsStatus = (status: number) => (error: unknown) => error instanceof Response && error.status === status;

function database() {
  const sqlite = new DatabaseSync(":memory:");
  sqlite.exec(`CREATE TABLE users(id TEXT PRIMARY KEY, email TEXT, display_name TEXT, status TEXT, role TEXT);
    INSERT INTO users VALUES ('user:lead','lead@example.test','Lead','active','compliance_lead'),('user:reviewer','review@example.test','Reviewer','active','reviewer'),('user:auditor','audit@example.test','Auditor','active','auditor'),('user:suspended','suspended@example.test','Suspended','suspended','reviewer');
    CREATE TABLE assessments(id TEXT PRIMARY KEY,name TEXT,framework TEXT,period_start TEXT,period_end TEXT,systems_json TEXT,controls_json TEXT,catalog_id TEXT,scope_mode TEXT,owner_id TEXT,status TEXT,created_at TEXT,updated_at TEXT);
    CREATE TABLE control_catalogs(id TEXT PRIMARY KEY,framework TEXT,version TEXT,title TEXT,controls_json TEXT,digest_sha256 TEXT,status TEXT);
    INSERT INTO control_catalogs VALUES('test-catalog','PCI DSS','4.0.1','PCI test','[{"id":"1.2.5","title":"Network controls","requirement":"Review network"},{"id":"6.3.2","title":"Inventory","requirement":"Review dependencies"}]','digest','active');
    INSERT INTO assessments VALUES('${assessmentId}','Test assessment','PCI DSS 4.0.1','2026-01-01','2026-12-31','["A","B"]','["1.2.5","6.3.2"]','test-catalog','explicit','user:lead','draft','2026-01-01T00:00:00.000Z','2026-01-01T00:00:00.000Z');
    CREATE TABLE evidence_artifacts(id TEXT PRIMARY KEY,assessment_id TEXT,control_id TEXT DEFAULT '6.3.2',framework TEXT DEFAULT 'PCI DSS 4.0.1',system TEXT DEFAULT 'A',type TEXT DEFAULT 'report',status TEXT DEFAULT 'approved',sha256 TEXT DEFAULT '${"a".repeat(64)}',title TEXT DEFAULT 'Verified remediation evidence',created_at TEXT DEFAULT '2026-01-01T00:00:00.000Z',device_id TEXT,manifest_sha256 TEXT,chain_event_hash TEXT,server_safety_scan_sha256 TEXT,server_safety_scan_policy TEXT,server_safety_scan_completed_at TEXT,server_safety_scanner_origin TEXT,server_safety_receipt_sha256 TEXT);
    CREATE TABLE evidence_occurrences(id TEXT PRIMARY KEY,artifact_id TEXT,status TEXT DEFAULT 'approved',expires_at TEXT DEFAULT '2099-01-01T00:00:00.000Z',coverage_status TEXT DEFAULT 'complete',created_by TEXT DEFAULT 'user:lead',approved_by TEXT DEFAULT 'user:reviewer',approved_at TEXT DEFAULT '2026-01-02T00:00:00.000Z',received_at TEXT DEFAULT '2026-01-01T00:00:00.000Z');
    CREATE TABLE native_evidence_manifests(artifact_id TEXT,device_id TEXT,image_sha256 TEXT,manifest_sha256 TEXT,chain_sequence INTEGER,chain_event_hash TEXT,provenance_key_id TEXT);
    CREATE TABLE capture_devices(id TEXT,provenance_key_id TEXT,chain_sequence INTEGER);
    CREATE TABLE collection_jobs(id TEXT PRIMARY KEY,assessment_id TEXT);
    CREATE TABLE findings(id TEXT PRIMARY KEY, assessment_id TEXT,control_id TEXT,evidence_id TEXT,job_id TEXT,title TEXT,description TEXT,severity TEXT,status TEXT DEFAULT 'open',owner_id TEXT,due_at TEXT,resolution TEXT,resolution_evidence_json TEXT NOT NULL DEFAULT '[]',created_by TEXT,resolved_by TEXT,created_at TEXT,updated_at TEXT,resolved_at TEXT);
    CREATE TABLE finding_events(id TEXT PRIMARY KEY,finding_id TEXT,action TEXT,actor_id TEXT,details_json TEXT,created_at TEXT);
    CREATE TABLE collectors(id TEXT PRIMARY KEY,provider TEXT,display_name TEXT,enabled INTEGER,schedule_cron TEXT,status TEXT,last_run_at TEXT,last_error TEXT,updated_at TEXT,scheduled_assessment_id TEXT);
    INSERT INTO collectors VALUES('collector_github','github','GitHub',1,'0 7 * * *','healthy',NULL,NULL,'2026-01-01T00:00:00.000Z',NULL);`);
  const DB = { prepare: (sql: string) => {
    const statement = sqlite.prepare(sql);
    let bindings: Array<string | number | null> = [];
    const handle = {
      bind: (...values: Array<string | number | null>) => { bindings = values; return handle; },
      first: async () => statement.get(...bindings) || null,
      all: async () => ({ results: statement.all(...bindings) }),
      run: async () => ({ meta: { changes: Number(statement.run(...bindings).changes) } }),
    };
    return handle;
  } };
  let id = 0;
  const dependencies = {
    "./env": { getEnv: () => ({ DB }) }, "./auth": { assertPermission },
    "./pagination": pagination, "./workflow-validation": validation, "./package-eligibility": packageEligibility,
    "../control-catalogs": { controlCatalogs: [] },
    "./crypto": { randomId: (prefix: string) => `${prefix}_${(++id).toString(16).padStart(32, "0")}`, stableJson: JSON.stringify, sha256: async () => "digest" },
    "./audit": { executeAuditedBatch: async (_actor: unknown, _action: unknown, _resource: unknown, _id: unknown, _details: unknown, statements: Array<{ run: () => Promise<unknown> }>) => {
      sqlite.exec("BEGIN"); try { const results = []; for (const statement of statements) results.push(await statement.run()); sqlite.exec("COMMIT"); return results; } catch (error) { sqlite.exec("ROLLBACK"); throw error; }
    } },
  };
  return { sqlite, DB, dependencies };
}

test("workflow validators reject impossible dates, permissive coercion and unsupported schedules", () => {
  assert.equal(validation.normalizeFindingDueAt("2028-02-29", Date.parse("2026-01-01")), "2028-02-29T23:59:59.999Z");
  for (const date of ["2026-02-29", "2026-04-31", "2026-12-01T24:00:00Z", "2026-12-01T12:00:00-04:00", true]) assert.throws(() => validation.normalizeFindingDueAt(date), rejectsStatus(400));
  assert.equal(validation.normalizeFindingDueAt(null), null);
  assert.equal(validation.nextWorkflowTimestamp("2026-01-01 12:00:00", Date.parse("2026-01-01T12:00:00Z")), "2026-01-01T12:00:00.001Z", "SQLite timestamps are UTC, not the host timezone");
  assert.equal(validation.normalizeCollectorSchedule("00 09 * * 1"), "0 9 * * 1");
  assert.equal(validation.normalizeCollectorSchedule("45 * * * *"), "45 * * * *");
  assert.equal(validation.normalizeCollectorSchedule(null), null);
  for (const value of ["99 99 * * *", "* * * * *", "0 24 * * *", "0 7 1 * *", "0 7 * * 7", "0/5 * * * *", {}, false]) assert.throws(() => validation.normalizeCollectorSchedule(value), rejectsStatus(400));
  for (const value of [[], null, { role: "admin" }]) assert.throws(() => validation.workflowBody(value, ["id"]), rejectsStatus(400));
});

test("actual finding lifecycle persists assignment/deadline changes, immutable history and paginated filters", async () => {
  const { sqlite, dependencies } = database();
  const assessments = await moduleFrom("lib/server/assessments.ts", dependencies);
  const proof = await moduleFrom("lib/server/finding-resolution.ts", dependencies);
  const findings = await moduleFrom("lib/server/findings.ts", { ...dependencies, "./assessments": assessments, "./finding-resolution": proof });
  const create = { assessmentId, title: "Unassigned TLS gap", description: "The production endpoint needs an independently verified TLS configuration update.", severity: "high", dueAt: "2026-01-02" };
  const finding = await findings.createFinding(actor, create) as Record<string, unknown>;
  await assert.rejects(async () => findings.createFinding(actor, { ...create, ownerId: "user:auditor" }), rejectsStatus(422));
  await assert.rejects(async () => findings.createFinding({ ...actor, role: "auditor" }, create), rejectsStatus(403));
  const changed = await findings.updateFinding(actor, finding.id, { ownerId: "user:reviewer", dueAt: "2026-01-03", expectedUpdatedAt: finding.updated_at }) as Record<string, unknown>;
  assert.equal(changed.owner_id, "user:reviewer"); assert.equal(changed.due_at, "2026-01-03T23:59:59.999Z");
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM finding_events").get()?.n, 2);
  const history = await findings.getFindingHistory(finding.id, { limit: "1" }) as { events: Array<{ details: Record<string, unknown> }>; page: { hasMore: boolean; nextCursor: string } };
  assert.equal(history.events[0].details.previousOwnerId, null); assert.equal(history.events[0].details.ownerId, "user:reviewer"); assert.equal(history.page.hasMore, true);
  const older = await findings.getFindingHistory(finding.id, { cursor: history.page.nextCursor }) as { events: Array<{ action: string }> };
  assert.equal(older.events[0].action, "created");
  await assert.rejects(async () => findings.updateFinding(actor, finding.id, { dueAt: null, expectedUpdatedAt: finding.updated_at }), rejectsStatus(409));
  await assert.rejects(async () => findings.updateFinding(actor, finding.id, { ownerId: "user:suspended" }), rejectsStatus(422));
  const filtered = await findings.listFindings({ assessmentId, due: "overdue", ownerId: "user:reviewer", severity: "high", q: "TLS" }) as { findings: unknown[]; page: { total: number } };
  assert.equal(filtered.page.total, 1); assert.equal(filtered.findings.length, 1);
  assert.equal((await findings.listFindings({ assessmentId, q: "%" }) as { page: { total: number } }).page.total, 0, "LIKE wildcard must be literal user text");
  const assignees = await findings.listFindingAssignees(actor, "") as { assignees: Array<{ id: string }> };
  assert.deepEqual(Array.from(assignees.assignees, (user) => user.id), ["user:lead", "user:reviewer"]);
  await assert.rejects(async () => findings.updateFinding({ ...actor, role: "reviewer" }, finding.id, { status: "accepted", resolution: "Risk disposition approved by the compliance owner." }), rejectsStatus(403));
  const evidenceId = `ev_${"b".repeat(32)}`;
  sqlite.prepare("INSERT INTO evidence_artifacts(id,assessment_id) VALUES (?,?)").run(evidenceId, assessmentId);
  sqlite.prepare("INSERT INTO evidence_occurrences(id,artifact_id) VALUES (?,?)").run(`occ_${"c".repeat(32)}`, evidenceId);
  await assert.rejects(async () => findings.updateFinding(actor, finding.id, { status: "resolved", resolution: "A text assertion without evidence cannot prove this remediation." }), rejectsStatus(422));
  await findings.updateFinding(actor, finding.id, { status: "resolved", resolution: "Verified corrected endpoint configuration and attached evidence.", resolutionEvidenceIds: [evidenceId] });
  await findings.updateFinding(actor, finding.id, { status: "closed", resolution: "Independent review confirmed remediation and disposition closure." });
  await assert.rejects(async () => findings.updateFinding(actor, finding.id, { ownerId: null }), rejectsStatus(409));
  sqlite.close();
});

test("finding resolution rejects stale or unrelated proof, fences capture races, and flags ineligible owners", async () => {
  const { sqlite, dependencies } = database();
  const assessments = await moduleFrom("lib/server/assessments.ts", dependencies);
  const evidence = await moduleFrom("lib/server/finding-resolution.ts", dependencies);
  const findingModule = await moduleFrom("lib/server/findings.ts", { ...dependencies, "./assessments": assessments, "./finding-resolution": evidence });
  const finding = await findingModule.createFinding(actor, { assessmentId, controlId: "6.3.2", ownerId: "user:reviewer", title: "Dependency inventory gap", description: "Remediation requires independently approved software inventory evidence from the assessed system.", severity: "high" }) as Record<string, unknown>;
  sqlite.exec("UPDATE users SET status='suspended' WHERE id='user:reviewer'");
  const queue = await findingModule.listFindings({ assessmentId, ownerId: "reassignment_needed" }) as { findings: Array<Record<string, unknown>>; page: { total: number } };
  assert.equal(queue.page.total, 1); assert.equal(queue.findings[0].reassignment_needed, true); assert.equal(queue.findings[0].owner_status, "suspended");
  await findingModule.updateFinding(actor, finding.id, { ownerId: "user:lead" });
  assert.equal((await findingModule.listFindings({ assessmentId, ownerId: "reassignment_needed" }) as { page: { total: number } }).page.total, 0);
  sqlite.exec("UPDATE users SET status='active' WHERE id='user:reviewer'");
  const evidenceId = `ev_${"b".repeat(32)}`, occurrenceId = `occ_${"c".repeat(32)}`;
  sqlite.prepare("INSERT INTO evidence_artifacts(id,assessment_id) VALUES (?,?)").run(evidenceId, assessmentId);
  sqlite.prepare("INSERT INTO evidence_occurrences(id,artifact_id) VALUES (?,?)").run(occurrenceId, evidenceId);
  const resolution = { status: "resolved", resolution: "An independent reviewer confirmed the corrected software inventory.", resolutionEvidenceIds: [evidenceId] };
  for (const [column, bad, original] of [["coverage_status", "partial", "complete"], ["status", "needs_review", "approved"], ["expires_at", "2020-01-01T00:00:00.000Z", "2099-01-01T00:00:00.000Z"], ["approved_by", "user:lead", "user:reviewer"]]) {
    sqlite.prepare(`UPDATE evidence_occurrences SET ${column}=? WHERE id=?`).run(bad, occurrenceId);
    await assert.rejects(async () => findingModule.updateFinding(actor, finding.id, resolution), rejectsStatus(422));
    sqlite.prepare(`UPDATE evidence_occurrences SET ${column}=? WHERE id=?`).run(original, occurrenceId);
  }
  sqlite.prepare("UPDATE evidence_artifacts SET control_id='1.2.5' WHERE id=?").run(evidenceId);
  await assert.rejects(async () => findingModule.updateFinding(actor, finding.id, resolution), rejectsStatus(422));
  sqlite.prepare("UPDATE evidence_artifacts SET control_id='6.3.2',assessment_id=? WHERE id=?").run(`asm_${"f".repeat(32)}`, evidenceId);
  await assert.rejects(async () => findingModule.updateFinding(actor, finding.id, resolution), rejectsStatus(422));
  sqlite.prepare("UPDATE evidence_artifacts SET assessment_id=? WHERE id=?").run(assessmentId, evidenceId);
  const choices = await evidence.listFindingResolutionEvidence(finding.id, { limit: "1", q: "Verified" }) as { evidence: Array<Record<string, unknown>>; page: { total: number } };
  assert.equal(choices.page.total, 1); assert.equal(choices.evidence[0].occurrenceId, occurrenceId);
  const realBatch = dependencies["./audit"].executeAuditedBatch;
  const racingDependencies = { ...dependencies, "./audit": { executeAuditedBatch: async (...args: Parameters<typeof realBatch>) => {
    sqlite.prepare("UPDATE evidence_occurrences SET status='needs_review' WHERE id=?").run(occurrenceId);
    return realBatch(...args);
  } } };
  const racing = await moduleFrom("lib/server/findings.ts", { ...racingDependencies, "./assessments": assessments, "./finding-resolution": evidence });
  await assert.rejects(async () => racing.updateFinding(actor, finding.id, resolution), rejectsStatus(409));
  assert.equal(sqlite.prepare("SELECT status FROM findings WHERE id=?").get(String(finding.id))?.status, "open");
  assert.equal(sqlite.prepare("SELECT COUNT(*) AS n FROM finding_events WHERE action='resolved'").get()?.n, 0);
  sqlite.prepare("UPDATE evidence_occurrences SET status='approved' WHERE id=?").run(occurrenceId);
  const resolved = await findingModule.updateFinding(actor, finding.id, resolution) as { resolutionEvidence: Array<Record<string, unknown>> };
  assert.equal(resolved.resolutionEvidence[0].occurrenceId, occurrenceId); assert.equal(resolved.resolutionEvidence[0].sha256, "a".repeat(64));
  const history = await findingModule.getFindingHistory(finding.id) as { events: Array<{ details: { resolutionEvidence?: Array<Record<string, unknown>> } }> };
  assert.equal(history.events[0].details.resolutionEvidence?.[0].occurrenceId, occurrenceId);
  sqlite.prepare("INSERT INTO evidence_occurrences(id,artifact_id,status,received_at) VALUES(?,?,'needs_review','2026-12-01T00:00:00.000Z')").run(`occ_${"d".repeat(32)}`, evidenceId);
  await assert.rejects(async () => findingModule.updateFinding(actor, finding.id, { status: "closed", resolution: "The original resolution needs fresh independent review before closing." }), rejectsStatus(422));
  await findingModule.updateFinding(actor, finding.id, { status: "in_progress" });
  assert.equal(sqlite.prepare("SELECT resolution_evidence_json FROM findings WHERE id=?").get(String(finding.id))?.resolution_evidence_json, "[]");
  await findingModule.updateFinding(actor, finding.id, { status: "accepted", resolution: "The compliance lead explicitly accepts the residual risk for this assessment." });
  await findingModule.updateFinding(actor, finding.id, { status: "closed", resolution: "Risk acceptance was independently considered and permanently documented." });
  sqlite.close();
});

test("resolution evidence controls render explicit proof requirements and immutable identity", async () => {
  const components = await moduleFrom("app/components/finding-evidence.tsx", { "react": React, "react/jsx-runtime": jsxRuntime, "./workflow-admin.module.css": { default: new Proxy({}, { get: (_target, name) => String(name) }) } });
  const Picker = components.FindingEvidencePicker as unknown as React.ComponentType<Record<string, unknown>>;
  const Links = components.FindingEvidenceLinks as unknown as React.ComponentType<Record<string, unknown>>;
  const picker = renderToStaticMarkup(React.createElement(Picker, { findingId: `fnd_${"a".repeat(32)}`, value: [], onChange: () => {} }));
  assert.match(picker, /<fieldset/); assert.match(picker, /<legend>Evidence proving remediation/); assert.match(picker, /Find approved evidence/); assert.match(picker, /role="status"/);
  const empty = renderToStaticMarkup(React.createElement(Links, { evidence: [] })); assert.match(empty, /not proof of remediation/);
  const linked = renderToStaticMarkup(React.createElement(Links, { evidence: [{ evidenceId: `ev_${"b".repeat(32)}`, occurrenceId: `occ_${"c".repeat(32)}`, sha256: "a".repeat(64), title: "Approved report", system: "Payments", controlId: "6.3.2", approvedAt: "2026-01-01T00:00:00.000Z", linkedAt: "2026-01-02T00:00:00.000Z" }] }));
  assert.match(linked, /Recorded evidence identity/); assert.match(linked, /rel="noreferrer"/); assert.match(linked, /SHA-256/);
});

test("actual assessment draft edits validate dates, enforce compare-and-set, activate and lock after evidence", async () => {
  const { sqlite, dependencies } = database();
  const assessments = await moduleFrom("lib/server/assessments.ts", dependencies);
  await assert.rejects(async () => assessments.updateAssessment(actor, { id: assessmentId, periodStart: "2026-02-30" }), rejectsStatus(400));
  const draft = await assessments.updateAssessment(actor, { id: assessmentId, name: "Reviewed scope", systems: ["A"], controls: ["1.2.5"], periodStart: "2026-02-01" }) as Record<string, unknown>;
  assert.equal(draft.name, "Reviewed scope"); assert.equal(draft.period_start, "2026-02-01");
  await assert.rejects(async () => assessments.updateAssessment(actor, { id: assessmentId, name: "Stale update", expectedUpdatedAt: "old" }), rejectsStatus(409));
  await assessments.updateAssessment(actor, { id: assessmentId, status: "active" });
  await assert.rejects(async () => assessments.updateAssessment(actor, { id: assessmentId, name: "Wrong historical title" }), rejectsStatus(409));
  sqlite.prepare("INSERT INTO evidence_artifacts(id,assessment_id) VALUES ('evidence',?)").run(assessmentId);
  assert.equal((await assessments.getAssessment(assessmentId) as Record<string, unknown>).scope_locked, true);
  await assert.rejects(async () => assessments.updateAssessment(actor, { id: assessmentId, systems: ["B"] }), rejectsStatus(409));
  const closed = await assessments.updateAssessment(actor, { id: assessmentId, status: "closed" }) as Record<string, unknown>;
  assert.equal(closed.status, "closed");
  await assert.rejects(async () => assessments.updateAssessment(actor, { id: assessmentId, status: "active" }), rejectsStatus(409));
  sqlite.close();
});

test("actual collector API supports explicit schedule removal, rejects malformed schedules and stale edits", async () => {
  const { sqlite, DB, dependencies } = database();
  const route = await moduleFrom("app/api/collectors/route.ts", {
    "../../../lib/server/auth": { requireSameOrigin: () => {}, requireApiPermission: async () => actor, requireApiUser: async () => actor, jsonError: (error: unknown) => error instanceof Response ? error : Response.json({ error: String(error) }, { status: 500 }) },
    "../../../lib/server/env": { getEnv: () => ({ DB }) }, "../../../lib/server/audit": dependencies["./audit"],
    "../../../lib/server/jobs": { ensureDefaultCollectors: async () => {} }, "../../../lib/server/collectors": { collectorConfiguration: () => ({ configured: true, missing: [] }) },
    "../../../lib/server/rate-limit": { enforceRateLimit: async () => {}, requireBoundedContentLength: () => {} },
    "../../../lib/server/workflow-validation": validation,
  });
  const send = (body: unknown) => route.PATCH(new Request("https://example.test/api/collectors", { method: "PATCH", body: JSON.stringify(body) })) as Promise<Response>;
  assert.equal((await send({ id: "collector_github", scheduleCron: "99 99 * * *" })).status, 400);
  assert.equal((await send({ id: "collector_github", enabled: "false" })).status, 400);
  assert.equal((await send({ id: "collector_github", enabled: true, scheduleCron: "0 7 * * *", scheduledAssessmentId: assessmentId })).status, 409, "draft cannot receive scheduled collection");
  sqlite.prepare("UPDATE assessments SET status='active' WHERE id=?").run(assessmentId);
  assert.equal((await send({ id: "collector_github", enabled: true, scheduleCron: "0 7 * * *", scheduledAssessmentId: null })).status, 409, "no implicit latest-assessment fallback");
  assert.equal((await send({ id: "collector_github", scheduleCron: null, enabled: false, expectedUpdatedAt: "2026-01-01T00:00:00.000Z" })).status, 200);
  const row = sqlite.prepare("SELECT * FROM collectors").get(); assert.equal(row?.schedule_cron, null); assert.equal(row?.enabled, 0);
  assert.equal((await send({ id: "collector_github", enabled: true, expectedUpdatedAt: "2026-01-01T00:00:00.000Z" })).status, 409);
  assert.equal((await send({ id: "collector_github", enabled: true, scheduleCron: "0 7 * * *", scheduledAssessmentId: assessmentId })).status, 200);
  assert.equal(sqlite.prepare("SELECT scheduled_assessment_id FROM collectors").get()?.scheduled_assessment_id, assessmentId);
  sqlite.prepare("UPDATE assessments SET status='closed' WHERE id=?").run(assessmentId);
  assert.equal((await send({ id: "collector_github", enabled: true, scheduleCron: "0 8 * * *", scheduledAssessmentId: assessmentId })).status, 409);
  sqlite.close();
});

test("workflow panels render semantic labeled controls, read-only boundaries and confirmation copy", async () => {
  const components = await moduleFrom("app/components/workflow-admin.tsx", { react: React, "react/jsx-runtime": jsxRuntime, "./workflow-admin.module.css": { default: new Proxy({}, { get: (_target, name) => String(name) }) } });
  const Component = components.AssessmentLifecyclePanel as unknown as React.ComponentType<Record<string, unknown>>;
  const assessment = { id: assessmentId, name: "Audit assessment", status: "active", systems: ["A"], controls: ["1.2.5"], catalog_id: "test-catalog", period_start: "2026-01-01", period_end: "2026-12-31", updated_at: "now", scope_locked: true };
  const html = renderToStaticMarkup(React.createElement(Component, { assessment, catalogs: [], canManage: true, onChanged: () => {} }));
  assert.match(html, /<fieldset disabled=""/); assert.match(html, /Close assessment permanently/); assert.match(html, /I understand closing prevents future collection and edits/);
  assert.match(html, /<label[^>]*>Period start<input[^>]*type="date"/);
  const readOnly = renderToStaticMarkup(React.createElement(Component, { assessment, catalogs: [], canManage: false, onChanged: () => {} }));
  assert.doesNotMatch(readOnly, /Close assessment permanently/);
  const Assignment = components.FindingAssignmentFields as unknown as React.ComponentType<Record<string, unknown>>;
  const fields = renderToStaticMarkup(React.createElement(Assignment)); assert.match(fields, /name="ownerId"/); assert.match(fields, /name="dueAt"/); assert.match(fields, /end of day UTC/);
});
