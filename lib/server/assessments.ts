import { controlCatalogs, type CatalogControl, type ControlCatalog } from "../control-catalogs";
import type { AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { randomId, sha256, stableJson } from "./crypto";
import { getEnv } from "./env";
import { decodePageCursor, pageLimit, pageMeta, type PageMeta } from "./pagination";

export type AssessmentStatus = "draft" | "active" | "closed";
export type AssessmentScopeMode = "explicit";

type StoredCatalog = ControlCatalog & { digestSha256: string; status: "active" | "retired" };

export type AssessmentRecord = Record<string, unknown> & {
  id: string;
  systems: string[];
  controls: string[];
  catalog: { id: string; framework: string; version: string; title: string; controls: CatalogControl[] } | null;
};

function inputError(message: string, status = 400): Response {
  return new Response(JSON.stringify({ error: message }), { status, headers: { "content-type": "application/json" } });
}

function boundedList(value: unknown, maximum: number, pattern: RegExp): string[] {
  if (!Array.isArray(value) || value.length > maximum) throw inputError("Assessment scope is invalid.");
  const items = [...new Set(value.map((item) => String(item).trim()).filter(Boolean))];
  if (items.some((item) => item.length > 180 || !pattern.test(item))) throw inputError("Assessment scope contains an invalid value.");
  return items;
}

function parseJsonList(value: unknown): string[] {
  try {
    const parsed = JSON.parse(String(value || "[]"));
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch { return []; }
}

async function ensureBuiltInCatalogs(): Promise<void> {
  for (const catalog of controlCatalogs) {
    const controlsJson = stableJson(catalog.controls);
    const digest = await sha256(controlsJson);
    await getEnv().DB.prepare(`INSERT INTO control_catalogs (id, framework, version, title, controls_json, digest_sha256, status)
      VALUES (?, ?, ?, ?, ?, ?, 'active') ON CONFLICT(id) DO NOTHING`)
      .bind(catalog.id, catalog.framework, catalog.version, catalog.title, controlsJson, digest).run();
    const stored = await getEnv().DB.prepare("SELECT framework, version, title, controls_json, digest_sha256, status FROM control_catalogs WHERE id = ?")
      .bind(catalog.id).first<{ framework: string; version: string; title: string; controls_json: string; digest_sha256: string; status: string }>();
    if (!stored || stored.framework !== catalog.framework || stored.version !== catalog.version || stored.title !== catalog.title ||
        stored.controls_json !== controlsJson || stored.digest_sha256 !== digest || !["active", "retired"].includes(stored.status)) {
      throw new Error(`Built-in control catalog ${catalog.id} does not match the reviewed source definition.`);
    }
  }
}

async function loadCatalog(id: string, includeRetired = false): Promise<StoredCatalog | null> {
  if (!/^[a-z0-9][a-z0-9._-]{2,119}$/u.test(id)) return null;
  await ensureBuiltInCatalogs();
  const row = await getEnv().DB.prepare("SELECT id, framework, version, title, controls_json, digest_sha256, status FROM control_catalogs WHERE id = ?")
    .bind(id).first<{ id: string; framework: string; version: string; title: string; controls_json: string; digest_sha256: string; status: "active" | "retired" }>();
  if (!row || (!includeRetired && row.status !== "active")) return null;
  let controls: CatalogControl[];
  try { controls = JSON.parse(row.controls_json) as CatalogControl[]; }
  catch { throw new Error(`Control catalog ${id} contains invalid JSON.`); }
  if (!Array.isArray(controls) || controls.some((control) => !control?.id || !control.title || !control.requirement)) throw new Error(`Control catalog ${id} is structurally invalid.`);
  if (await sha256(stableJson(controls)) !== row.digest_sha256) throw new Error(`Control catalog ${id} failed its immutable digest check.`);
  return { id: row.id, framework: row.framework, version: row.version, title: row.title, controls, digestSha256: row.digest_sha256, status: row.status };
}

export async function listControlCatalogs(): Promise<Array<Omit<StoredCatalog, "digestSha256" | "status"> & { digestSha256: string }>> {
  await ensureBuiltInCatalogs();
  const rows = (await getEnv().DB.prepare("SELECT id FROM control_catalogs WHERE status = 'active' ORDER BY framework, version, id").all<{ id: string }>()).results;
  const catalogs = await Promise.all(rows.map((row) => loadCatalog(row.id)));
  return catalogs.filter((catalog): catalog is StoredCatalog => Boolean(catalog)).map((catalog) => ({
    id: catalog.id,
    framework: catalog.framework,
    version: catalog.version,
    title: catalog.title,
    controls: catalog.controls,
    digestSha256: catalog.digestSha256,
  }));
}

function scopedCatalog(catalog: StoredCatalog | null, controls: string[]): AssessmentRecord["catalog"] {
  if (!catalog) return null;
  const selected = new Set(controls);
  return { id: catalog.id, framework: catalog.framework, version: catalog.version, title: catalog.title, controls: catalog.controls.filter((control) => selected.has(control.id)) };
}

async function mapAssessment(row: Record<string, unknown>): Promise<AssessmentRecord> {
  const systems = parseJsonList(row.systems_json);
  const controls = parseJsonList(row.controls_json);
  const catalog = row.catalog_id ? await loadCatalog(String(row.catalog_id), true) : null;
  const clean = { ...row };
  delete clean.systems_json;
  delete clean.controls_json;
  return { ...clean, id: String(row.id), systems, controls, catalog: scopedCatalog(catalog, controls) } as AssessmentRecord;
}

export async function listAssessments(input: { cursor?: string; limit?: string; status?: string } = {}): Promise<{ assessments: AssessmentRecord[]; page: PageMeta }> {
  const limit = pageLimit(input.limit, 50, 100);
  const cursor = decodePageCursor(input.cursor, /^asm_[a-f0-9]{32}$/u);
  const status = input.status && ["draft", "active", "closed"].includes(input.status) ? input.status : null;
  if (input.status && !status) throw inputError("Assessment status filter is invalid.");
  const conditions: string[] = [];
  const bindings: unknown[] = [];
  if (status) { conditions.push("status = ?"); bindings.push(status); }
  if (cursor) { conditions.push("(created_at < ? OR (created_at = ? AND id < ?))"); bindings.push(cursor.sortValue, cursor.sortValue, cursor.id); }
  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const countWhere = status ? "WHERE status = ?" : "";
  const countBindings = status ? [status] : [];
  const totalRow = await getEnv().DB.prepare(`SELECT COUNT(*) AS total FROM assessments ${countWhere}`).bind(...countBindings).first<{ total: number }>();
  const rows = (await getEnv().DB.prepare(`SELECT id, name, framework, period_start, period_end, systems_json, controls_json, catalog_id, scope_mode, owner_id, status, created_at, updated_at
    FROM assessments ${where} ORDER BY created_at DESC, id DESC LIMIT ?`).bind(...bindings, limit + 1).all<Record<string, unknown>>()).results;
  const mapped = await Promise.all(rows.map(mapAssessment));
  const result = pageMeta(mapped, limit, Number(totalRow?.total || 0), "created_at", "id");
  return { assessments: result.items as AssessmentRecord[], page: result.page };
}

function validateExplicitScope(status: AssessmentStatus, scopeMode: string, systems: string[], controls: string[], catalog: StoredCatalog): void {
  if (scopeMode !== "explicit") throw inputError("Assessment scopeMode must be explicit; implicit all-systems or all-controls scope is not supported.");
  const knownControls = new Set(catalog.controls.map((control) => control.id));
  const unknown = controls.filter((control) => !knownControls.has(control));
  if (unknown.length) throw inputError(`Control scope contains values outside catalog ${catalog.id}: ${unknown.slice(0, 10).join(", ")}.`, 422);
  if (status === "active" && (!systems.length || !controls.length)) throw inputError("An active assessment requires at least one explicitly named system and one control from its versioned catalog.", 422);
}

export async function createAssessment(actor: AuthenticatedUser, input: Record<string, unknown>): Promise<AssessmentRecord> {
  const name = String(input.name || "").trim();
  const periodStart = String(input.periodStart || "");
  const periodEnd = String(input.periodEnd || "");
  const systems = boundedList(input.systems || [], 250, /^[\p{L}\p{N} ._:/-]+$/u);
  const controls = boundedList(input.controls || [], 500, /^[A-Za-z0-9 ._:-]+$/u);
  const status = String(input.status || "draft") as AssessmentStatus;
  const scopeMode = String(input.scopeMode || "") as AssessmentScopeMode;
  const catalogId = String(input.catalogId || "");
  const catalog = await loadCatalog(catalogId);
  if (!catalog) throw inputError("Select an active versioned control catalog.", 422);
  if (name.length < 3 || name.length > 180 || !/^\d{4}-\d{2}-\d{2}$/u.test(periodStart) || !/^\d{4}-\d{2}-\d{2}$/u.test(periodEnd) || periodStart > periodEnd || !["draft", "active"].includes(status)) {
    throw inputError("Name, valid period, and supported status are required.");
  }
  validateExplicitScope(status, scopeMode, systems, controls, catalog);
  const id = randomId("asm");
  const now = new Date().toISOString();
  await executeAuditedBatch(actor, "assessment.created", "assessment", id, { name, catalogId, catalogDigest: catalog.digestSha256, periodStart, periodEnd, scopeMode, systems, controls, status }, [
    getEnv().DB.prepare("INSERT INTO assessments (id, name, framework, period_start, period_end, systems_json, controls_json, catalog_id, scope_mode, owner_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(id, name, `${catalog.framework} ${catalog.version}`, periodStart, periodEnd, stableJson(systems), stableJson(controls), catalog.id, scopeMode, actor.id, status, now, now),
  ]);
  return (await getAssessment(id))!;
}

export async function getAssessment(id: string): Promise<AssessmentRecord | null> {
  if (!/^asm_[a-f0-9]{32}$/u.test(id)) return null;
  const row = await getEnv().DB.prepare("SELECT * FROM assessments WHERE id = ?").bind(id).first<Record<string, unknown>>();
  return row ? mapAssessment(row) : null;
}

export async function updateAssessment(actor: AuthenticatedUser, input: Record<string, unknown>): Promise<AssessmentRecord> {
  const id = String(input.id || "");
  const current = await getAssessment(id);
  if (!current) throw inputError("Assessment not found.", 404);
  if (current.status === "closed") throw inputError("Closed assessments are immutable.", 409);
  const currentStatus = String(current.status) as AssessmentStatus;
  const status = String(input.status || currentStatus) as AssessmentStatus;
  if (!["draft", "active", "closed"].includes(status) || (currentStatus === "active" && status === "draft")) throw inputError("Assessment status transition is invalid.");
  const existingSystems = current.systems;
  const existingControls = current.controls;
  const systems = input.systems === undefined ? existingSystems : boundedList(input.systems, 250, /^[\p{L}\p{N} ._:/-]+$/u);
  const controls = input.controls === undefined ? existingControls : boundedList(input.controls, 500, /^[A-Za-z0-9 ._:-]+$/u);
  const requestedCatalogId = String(input.catalogId || current.catalog_id || "");
  if (currentStatus === "active" && requestedCatalogId !== current.catalog_id) throw inputError("An active assessment cannot change its catalog. Create a new assessment for another catalog version.", 409);
  const catalog = await loadCatalog(requestedCatalogId, currentStatus === "active");
  if (!catalog) throw inputError("The selected control catalog is unavailable.", 422);
  const scopeMode = String(input.scopeMode || current.scope_mode || "") as AssessmentScopeMode;
  validateExplicitScope(status === "closed" ? "active" : status, scopeMode, systems, controls, catalog);
  if (currentStatus === "active" && (systems.some((item) => !existingSystems.includes(item)) || controls.some((item) => !existingControls.includes(item)))) {
    throw inputError("An active assessment may be narrowed, but not expanded. Create a new assessment for broader scope.", 409);
  }
  const updatedAt = new Date().toISOString();
  const action = currentStatus === "draft" && status === "active"
    ? "assessment.activated"
    : status === "closed"
      ? "assessment.closed"
      : currentStatus === "active"
        ? "assessment.scope_narrowed"
        : "assessment.scope_updated";
  const [result] = await executeAuditedBatch(actor, action, "assessment", id, { previousStatus: currentStatus, status, catalogId: catalog.id, catalogDigest: catalog.digestSha256, scopeMode, systems, controls, previousUpdatedAt: current.updated_at, updatedAt }, [
    getEnv().DB.prepare("UPDATE assessments SET framework = ?, systems_json = ?, controls_json = ?, catalog_id = ?, scope_mode = ?, status = ?, updated_at = ? WHERE id = ? AND status = ? AND updated_at = ?")
      .bind(`${catalog.framework} ${catalog.version}`, stableJson(systems), stableJson(controls), catalog.id, scopeMode, status, updatedAt, id, currentStatus, current.updated_at),
  ], { sql: "EXISTS (SELECT 1 FROM assessments WHERE id = ? AND status = ? AND updated_at = ?)", bindings: [id, status, updatedAt] });
  if (!result.meta.changes) throw inputError("Assessment changed concurrently. Reload it before updating scope.", 409);
  return (await getAssessment(id))!;
}
