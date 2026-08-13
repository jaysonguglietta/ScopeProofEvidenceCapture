import type { AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { randomId, stableJson } from "./crypto";
import { getEnv } from "./env";

export type AssessmentStatus = "draft" | "active" | "closed";

function boundedList(value: unknown, maximum: number, pattern: RegExp): string[] {
  if (!Array.isArray(value) || value.length > maximum) throw new Response(JSON.stringify({ error: "Assessment scope is invalid." }), { status: 400, headers: { "content-type": "application/json" } });
  const items = [...new Set(value.map((item) => String(item).trim()).filter(Boolean))];
  if (items.some((item) => item.length > 180 || !pattern.test(item))) throw new Response(JSON.stringify({ error: "Assessment scope contains an invalid value." }), { status: 400, headers: { "content-type": "application/json" } });
  return items;
}

export async function listAssessments(): Promise<Array<Record<string, unknown>>> {
  const rows = (await getEnv().DB.prepare("SELECT id, name, framework, period_start, period_end, systems_json, controls_json, owner_id, status, created_at, updated_at FROM assessments ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'draft' THEN 1 ELSE 2 END, period_end DESC LIMIT 100").all<Record<string, unknown>>()).results;
  return rows.map(({ systems_json, controls_json, ...row }) => ({ ...row, systems: JSON.parse(String(systems_json || "[]")), controls: JSON.parse(String(controls_json || "[]")) }));
}

export async function createAssessment(actor: AuthenticatedUser, input: Record<string, unknown>): Promise<Record<string, unknown>> {
  const name = String(input.name || "").trim();
  const framework = String(input.framework || "PCI DSS 4.0.1").trim();
  const periodStart = String(input.periodStart || "");
  const periodEnd = String(input.periodEnd || "");
  const systems = boundedList(input.systems || [], 250, /^[\p{L}\p{N} ._:/-]+$/u);
  const controls = boundedList(input.controls || [], 500, /^[A-Za-z0-9 ._:-]+$/);
  const status = String(input.status || "draft") as AssessmentStatus;
  if (name.length < 3 || name.length > 180 || framework.length < 2 || framework.length > 100 || !/^\d{4}-\d{2}-\d{2}$/.test(periodStart) || !/^\d{4}-\d{2}-\d{2}$/.test(periodEnd) || periodStart > periodEnd || !["draft", "active"].includes(status)) {
    throw new Response(JSON.stringify({ error: "Name, framework, valid period, and supported status are required." }), { status: 400, headers: { "content-type": "application/json" } });
  }
  const id = randomId("asm");
  const now = new Date().toISOString();
  await executeAuditedBatch(actor, "assessment.created", "assessment", id, { name, framework, periodStart, periodEnd, systems, controls, status }, [
    getEnv().DB.prepare("INSERT INTO assessments (id, name, framework, period_start, period_end, systems_json, controls_json, owner_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(id, name, framework, periodStart, periodEnd, stableJson(systems), stableJson(controls), actor.id, status, now, now),
  ]);
  return { id, name, framework, period_start: periodStart, period_end: periodEnd, systems, controls, owner_id: actor.id, status, created_at: now, updated_at: now };
}

export async function getAssessment(id: string): Promise<Record<string, unknown> | null> {
  if (!/^asm_[a-f0-9]{32}$/.test(id)) return null;
  const row = await getEnv().DB.prepare("SELECT * FROM assessments WHERE id = ?").bind(id).first<Record<string, unknown>>();
  if (!row) return null;
  return { ...row, systems: JSON.parse(String(row.systems_json || "[]")), controls: JSON.parse(String(row.controls_json || "[]")), systems_json: undefined, controls_json: undefined };
}

export async function updateAssessment(actor: AuthenticatedUser, input: Record<string, unknown>): Promise<Record<string, unknown>> {
  const id = String(input.id || "");
  const current = await getAssessment(id);
  if (!current) throw new Response(JSON.stringify({ error: "Assessment not found." }), { status: 404, headers: { "content-type": "application/json" } });
  if (current.status === "closed") throw new Response(JSON.stringify({ error: "Closed assessments are immutable." }), { status: 409, headers: { "content-type": "application/json" } });
  const status = String(input.status || current.status) as AssessmentStatus;
  if (!['draft', 'active', 'closed'].includes(status)) throw new Response(JSON.stringify({ error: "Assessment status is invalid." }), { status: 400, headers: { "content-type": "application/json" } });
  const existingSystems = current.systems as string[];
  const existingControls = current.controls as string[];
  const systems = input.systems === undefined ? existingSystems : boundedList(input.systems, 250, /^[\p{L}\p{N} ._:/-]+$/u);
  const controls = input.controls === undefined ? existingControls : boundedList(input.controls, 500, /^[A-Za-z0-9 ._:-]+$/);
  if ((existingSystems.length && systems.some((item) => !existingSystems.includes(item))) || (existingControls.length && controls.some((item) => !existingControls.includes(item)))) {
    throw new Response(JSON.stringify({ error: "An active assessment may be narrowed, but not expanded. Create a new assessment for broader scope." }), { status: 409, headers: { "content-type": "application/json" } });
  }
  const updatedAt = new Date().toISOString();
  await executeAuditedBatch(actor, status === "closed" ? "assessment.closed" : "assessment.scope_narrowed", "assessment", id, { previousStatus: current.status, status, systems, controls }, [
    getEnv().DB.prepare("UPDATE assessments SET systems_json = ?, controls_json = ?, status = ?, updated_at = ? WHERE id = ? AND status != 'closed'").bind(stableJson(systems), stableJson(controls), status, updatedAt, id),
  ]);
  return { ...current, systems, controls, status, updated_at: updatedAt };
}
