"use client";

import { useCallback, useEffect, useId, useRef, useState } from "react";
import type { ControlCatalog } from "../../lib/control-catalogs";
import { nextCollectorRun } from "../../lib/server/workflow-validation";
import styles from "./workflow-admin.module.css";
import { FindingEvidenceLinks, FindingEvidencePicker } from "./finding-evidence";
import type { FindingEvidenceSnapshot } from "../../lib/server/finding-resolution";

type Page = { total: number; hasMore: boolean; nextCursor: string | null };
type Assignee = { id: string; email: string; display_name: string };
type Finding = { id: string; title: string; description: string; status: string; severity: string; owner_id: string | null; owner_email: string | null; owner_status?: string | null; reassignment_needed?: boolean; resolutionEvidence?: FindingEvidenceSnapshot[]; due_at: string | null; resolution: string | null; updated_at: string; control_id?: string | null };
type FindingEvent = { id: string; action: string; actor_email: string; created_at: string; details: Record<string, unknown> };
export type WorkflowAssessment = { id: string; name: string; status: string; systems: string[]; controls: string[]; catalog_id?: string | null; period_start: string; period_end: string; updated_at: string; scope_locked?: boolean };
type Collector = { id: string; display_name: string; enabled: number; schedule_cron: string | null; scheduled_assessment_id: string | null; nextRunAt: string | null; updated_at: string; status: string; configuration: { configured: boolean; missing: string[] } };
const button = `${styles.button} ${styles.primary}`;
const label = (value: string) => value.replaceAll("_", " ");
const date = (value: string) => new Date(value).toLocaleString();
const errorMessage = (error: unknown) => error instanceof Error ? error.message : "The request failed. Retry or reload before making another change.";

async function request<T>(url: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(url, { ...options, cache: "no-store" });
  const body = await response.json() as T & { error?: string };
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status}).`);
  return body;
}
const patch = <T,>(url: string, body: unknown) => request<T>(url, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

function AssigneeSelect({ value, onChange, currentEmail, name = "ownerId" }: { value: string; onChange: (value: string) => void; currentEmail?: string | null; name?: string }) {
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<Assignee[]>([]);
  const [state, setState] = useState("Loading eligible assignees…");
  useEffect(() => {
    const controller = new AbortController();
    const timer = setTimeout(() => { void request<{ assignees: Assignee[]; hasMore: boolean }>(`/api/findings/assignees?q=${encodeURIComponent(query)}`, { signal: controller.signal }).then((data) => { setItems(data.assignees); setState(data.hasMore ? "More than 100 matches. Refine your search to find the right owner." : "Only active users who can manage findings are assignable."); }).catch((error) => { if (!controller.signal.aborted) setState(errorMessage(error)); }); }, 200);
    return () => { controller.abort(); clearTimeout(timer); };
  }, [query]);
  return <div className={styles.grid}><label className={styles.field}>Find an assignee<input className={styles.control} value={query} onChange={(event) => setQuery(event.target.value)} maxLength={120} placeholder="Name or email" /></label><label className={styles.field}>Assignee<select className={styles.control} name={name} value={value} onChange={(event) => onChange(event.target.value)}><option value="">Unassigned</option>{value && !items.some((item) => item.id === value) && <option value={value}>{currentEmail || value} (current owner)</option>}{items.map((item) => <option key={item.id} value={item.id}>{item.display_name || item.email} · {item.email}</option>)}</select><small role="status">{state}</small></label></div>;
}

/** Drop into the existing create-finding form; fields use ownerId and dueAt. */
export function FindingAssignmentFields({ ownerId = "", dueAt = "" }: { ownerId?: string; dueAt?: string }) {
  const [owner, setOwner] = useState(ownerId);
  return <><AssigneeSelect value={owner} onChange={setOwner} /><label className={styles.field}>Due date (end of day UTC)<input className={styles.control} name="dueAt" type="date" defaultValue={dueAt.slice(0, 10)} /><small>Leave blank when no deadline has been agreed.</small></label></>;
}

function FindingDetail({ finding, canManage, canDispose, onSaved }: { finding: Finding; canManage: boolean; canDispose: boolean; onSaved: () => void }) {
  const [owner, setOwner] = useState(finding.owner_id || "");
  const [status, setStatus] = useState(finding.status);
  const [due, setDue] = useState(finding.due_at?.slice(0, 10) || "");
  const [resolution, setResolution] = useState(finding.resolution || "");
  const [resolutionEvidenceIds, setResolutionEvidenceIds] = useState((finding.resolutionEvidence || []).map((item) => item.evidenceId));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [events, setEvents] = useState<FindingEvent[]>([]);
  const [page, setPage] = useState<Page | null>(null);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [confirmClose, setConfirmClose] = useState(false);
  const errorId = useId();
  const requiresEvidence = status === "resolved" || (status === "closed" && finding.status === "resolved");
  const transitions: Record<string, string[]> = { open: ["open", "in_progress", "accepted", "resolved"], in_progress: ["open", "in_progress", "accepted", "resolved"], accepted: ["accepted", "in_progress", "closed"], resolved: ["resolved", "in_progress", "closed"], closed: ["closed"] };
  async function loadHistory(cursor?: string | null) {
    setHistoryBusy(true); setError("");
    try {
      const data = await request<{ events: FindingEvent[]; page: Page }>(`/api/findings/${finding.id}?limit=25${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
      setEvents((previous) => cursor ? [...previous, ...data.events.filter((item) => !previous.some((old) => old.id === item.id))] : data.events); setPage(data.page);
    } catch (failure) { setError(errorMessage(failure)); } finally { setHistoryBusy(false); }
  }
  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    try {
      await patch(`/api/findings/${finding.id}`, { ownerId: owner || null, ...(due !== (finding.due_at?.slice(0, 10) || "") ? { dueAt: due || null } : {}), status, ...(finding.status === "accepted" && status === "accepted" && !canDispose ? {} : { resolution: resolution || null }), ...(requiresEvidence ? { resolutionEvidenceIds } : {}), expectedUpdatedAt: finding.updated_at });
      onSaved();
    } catch (failure) { setError(errorMessage(failure)); } finally { setBusy(false); }
  }
  return <div><p>{finding.description}</p>{finding.reassignment_needed && <p className={styles.error} role="status">Reassignment needed: the current owner is suspended, removed, or no longer permitted to manage findings.</p>}<FindingEvidenceLinks evidence={finding.resolutionEvidence || []} />{canManage && finding.status !== "closed" ? <form onSubmit={save} aria-describedby={error ? errorId : undefined}><AssigneeSelect value={owner} onChange={setOwner} currentEmail={finding.owner_email} /><div className={styles.grid}><label className={styles.field}>Due date (end of day UTC)<input className={styles.control} type="date" value={due} onChange={(event) => setDue(event.target.value)} /></label><label className={styles.field}>Status<select className={styles.control} value={status} onChange={(event) => setStatus(event.target.value)}>{(transitions[finding.status] || [finding.status]).filter((value) => canDispose || !["accepted", "closed"].includes(value) || value === finding.status).map((value) => <option key={value} value={value}>{label(value)}</option>)}</select></label><label className={`${styles.field} ${styles.full}`}>Disposition / remediation notes<textarea className={styles.control} value={resolution} onChange={(event) => setResolution(event.target.value)} maxLength={4000} minLength={["accepted", "resolved", "closed"].includes(status) ? 20 : undefined} required={["accepted", "resolved", "closed"].includes(status)} disabled={finding.status === "accepted" && status === "accepted" && !canDispose} /><small>Accepted, resolved, and closed findings require at least 20 characters. Only compliance leads and administrators can accept risk or close a finding.</small></label></div>{requiresEvidence && <FindingEvidencePicker findingId={finding.id} value={resolutionEvidenceIds} onChange={setResolutionEvidenceIds} initialEvidence={finding.resolutionEvidence} />}{status === "closed" && <label className={styles.check}><input type="checkbox" required checked={confirmClose} onChange={(event) => setConfirmClose(event.target.checked)} />I confirm permanent closure; this finding will become read-only.</label>}<div className={styles.actions}><button className={button} disabled={busy || (requiresEvidence && resolutionEvidenceIds.length === 0) || (status === "closed" && !confirmClose)}>{busy ? "Saving…" : status === "closed" ? "Close finding permanently" : "Save finding"}</button></div></form> : <p className={styles.notice}>{finding.resolution || "Read-only finding. An authorized reviewer or compliance lead can manage remediation in an open assessment."}</p>}{error && <p id={errorId} className={styles.error} role="alert">{error}</p>}<div className={styles.actions}><button className={styles.button} type="button" disabled={historyBusy} onClick={() => void loadHistory()}>{historyBusy ? "Loading history…" : page ? "Refresh history" : "View event history"}</button></div>{page && <><p className={styles.muted}>{events.length} of {page.total} recorded events</p><ol className={styles.history}>{events.map((item) => <li key={item.id}><strong>{label(item.action)}</strong> · {item.actor_email || "Former user"}<br /><time dateTime={item.created_at}>{date(item.created_at)}</time><dl>{[["Status", item.details.previousStatus, item.details.status], ["Assignee", item.details.previousOwnerId, item.details.ownerId], ["Due date", item.details.previousDueAt, item.details.dueAt], ["Disposition", item.details.previousResolution, item.details.resolution]].map(([name, before, after]) => after !== undefined && <div key={String(name)}><dt>{String(name)}</dt><dd>{before === undefined ? "" : `${before || "None"} → `}{String(after || "None")}</dd></div>)}</dl>{Array.isArray(item.details.resolutionEvidence) && item.details.resolutionEvidence.length > 0 && <FindingEvidenceLinks evidence={item.details.resolutionEvidence as FindingEvidenceSnapshot[]} />}</li>)}</ol>{page.hasMore && <button className={styles.button} disabled={historyBusy} onClick={() => void loadHistory(page.nextCursor)}>Load older events</button>}</>}</div>;
}

export function FindingWorkflowPanel({ assessmentId, canManage, canDispose, currentUserId, assessmentClosed = false, onChanged }: { assessmentId: string; canManage: boolean; canDispose: boolean; currentUserId?: string; assessmentClosed?: boolean; onChanged?: () => void }) {
  const [filters, setFilters] = useState({ q: "", status: "", severity: "", ownerId: "", due: "" });
  const [applied, setApplied] = useState(filters);
  const [items, setItems] = useState<Finding[]>([]);
  const [page, setPage] = useState<Page | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [openFindings, setOpenFindings] = useState<string[]>([]);
  const [asOf, setAsOf] = useState(() => Date.now());
  const requestVersion = useRef(0);
  const load = useCallback(async (cursor?: string | null, signal?: AbortSignal) => {
    if (!assessmentId) return;
    const version = ++requestVersion.current;
    setBusy(true); setError("");
    try {
      const query = new URLSearchParams({ assessmentId, limit: "25", ...applied }); if (cursor) query.set("cursor", cursor);
      const data = await request<{ findings: Finding[]; page: Page }>(`/api/findings?${query}`, { signal });
      if (version !== requestVersion.current || signal?.aborted) return;
      setItems((current) => cursor ? [...current, ...data.findings.filter((item) => !current.some((old) => old.id === item.id))] : data.findings); setPage(data.page); setAsOf(Date.now());
    } catch (failure) { if (!signal?.aborted && version === requestVersion.current) setError(errorMessage(failure)); } finally { if (!signal?.aborted && version === requestVersion.current) setBusy(false); }
  }, [assessmentId, applied]);
  useEffect(() => { const controller = new AbortController(); const timer = setTimeout(() => void load(null, controller.signal), 0); return () => { controller.abort(); clearTimeout(timer); }; }, [load]);
  return <section className={styles.panel} aria-label="Finding workflow"><div className={styles.header}><div><h2>Remediation work queue</h2><p className={styles.muted}>Filter the full assessment, assign accountable owners, and inspect disposition history.</p></div><button className={styles.button} disabled={busy || !assessmentId} onClick={() => void load()}>Refresh findings</button></div><form onSubmit={(event) => { event.preventDefault(); setApplied({ ...filters }); }} className={styles.grid}><label className={styles.field}>Search title or description<input className={styles.control} value={filters.q} maxLength={120} onChange={(event) => setFilters({ ...filters, q: event.target.value })} /></label><label className={styles.field}>Status<select className={styles.control} value={filters.status} onChange={(event) => setFilters({ ...filters, status: event.target.value })}><option value="">All statuses</option>{["open", "in_progress", "accepted", "resolved", "closed"].map((value) => <option value={value} key={value}>{label(value)}</option>)}</select></label><label className={styles.field}>Severity<select className={styles.control} value={filters.severity} onChange={(event) => setFilters({ ...filters, severity: event.target.value })}><option value="">All severities</option>{["critical", "high", "medium", "low"].map((value) => <option value={value} key={value}>{value}</option>)}</select></label><label className={styles.field}>Ownership<select className={styles.control} value={filters.ownerId} onChange={(event) => setFilters({ ...filters, ownerId: event.target.value })}><option value="">All owners</option><option value="unassigned">Unassigned</option><option value="reassignment_needed">Reassignment needed</option>{currentUserId && <option value={currentUserId}>Assigned to me</option>}</select></label><label className={styles.field}>Deadline<select className={styles.control} value={filters.due} onChange={(event) => setFilters({ ...filters, due: event.target.value })}><option value="">All due dates</option><option value="overdue">Overdue and actionable</option><option value="undated">No due date</option></select></label><div className={styles.actions}><button className={button} disabled={busy || !assessmentId}>Apply filters</button></div></form>{error && <p className={styles.error} role="alert">{error}</p>}<p role="status" className={styles.muted}>{busy ? "Loading findings…" : notice || (page ? `${items.length} of ${page.total} matching findings` : "Choose an assessment to view findings.")}</p>{!busy && page?.total === 0 && <p className={styles.notice}>No findings match these filters. Clear filters to inspect the rest of this assessment.</p>}{items.map((finding) => <details className={styles.card} key={finding.id} onToggle={(event) => { const open = event.currentTarget.open; setOpenFindings((current) => open ? [...new Set([...current, finding.id])] : current.filter((id) => id !== finding.id)); }}><summary><span className={styles.badge}>{finding.severity}</span>{finding.title}<small>{label(finding.status)} · {finding.owner_email || "Unassigned"}{finding.reassignment_needed ? " · Reassignment needed" : ""} · {finding.control_id || "Assessment-wide"} · {finding.due_at ? <span className={new Date(finding.due_at).getTime() < asOf && ["open", "in_progress"].includes(finding.status) ? styles.overdue : undefined}>Due {finding.due_at.slice(0, 10)} UTC</span> : "No due date"}</small></summary>{openFindings.includes(finding.id) && <FindingDetail key={finding.updated_at} finding={finding} canManage={canManage && !assessmentClosed} canDispose={canDispose} onSaved={() => { setNotice("Finding saved. The work queue is up to date."); void load(); onChanged?.(); }} />}</details>)}{page?.hasMore && <div className={styles.actions}><button className={styles.button} disabled={busy} onClick={() => void load(page.nextCursor)}>Load more findings</button></div>}</section>;
}

function CollectorEditor({ collector, canManage, assessments, onSaved }: { collector: Collector; canManage: boolean; assessments: WorkflowAssessment[]; onSaved: () => void }) {
  const [enabled, setEnabled] = useState(Boolean(collector.enabled));
  const [schedule, setSchedule] = useState(collector.schedule_cron || "");
  const [assessmentId, setAssessmentId] = useState(collector.scheduled_assessment_id || "");
  const [asOf] = useState(() => new Date());
  const preview = nextCollectorRun(schedule, asOf);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const disabling = Boolean(collector.enabled) && !enabled;
  const clearing = Boolean(collector.schedule_cron) && !schedule.trim();
  const helpId = useId();
  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    try { await patch("/api/collectors", { id: collector.id, enabled, scheduleCron: schedule.trim() || null, scheduledAssessmentId: assessmentId || null, expectedUpdatedAt: collector.updated_at }); onSaved(); }
    catch (failure) { setError(errorMessage(failure)); } finally { setBusy(false); }
  }
  return <form className={styles.card} onSubmit={save}><h3>{collector.display_name}</h3><p className={styles.muted}>{label(collector.status)} · {collector.configuration.configured ? "Credentials configured" : `Not configured: ${collector.configuration.missing.join(", ")}`}</p><fieldset disabled={!canManage || busy} style={{ border: 0, padding: 0, margin: 0 }}><legend className={styles.muted}>Collection settings</legend><label className={styles.field}>Scheduled assessment<select className={styles.control} value={assessmentId} onChange={(event) => setAssessmentId(event.target.value)} required={enabled && Boolean(schedule.trim())}><option value="">Select an active assessment</option>{assessmentId && !assessments.some((item) => item.id === assessmentId) && <option value={assessmentId}>{assessmentId} (not loaded or no longer active)</option>}{assessments.filter((item) => item.status === "active").map((item) => <option key={item.id} value={item.id}>{item.name} · {item.period_end}</option>)}</select><small>No automatic fallback. Closing this assessment pauses scheduled collection until another active scope is explicitly saved.</small></label><label className={styles.check}><input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} />Enabled for manual and scheduled collection</label><div className={styles.grid}><label className={styles.field}>UTC schedule<input className={styles.control} value={schedule} onChange={(event) => setSchedule(event.target.value)} maxLength={32} placeholder="0 7 * * *" aria-describedby={helpId} /><small id={helpId}>Minute (0, 15, 30 or 45), hour (0–23 or *), * *, weekday (0–6 or *). Leave blank for manual-only collection. Minutes must align with the hosted 15-minute tick.</small></label><div className={styles.actions}><button className={styles.button} type="button" onClick={() => setSchedule("0 * * * *")}>Hourly</button><button className={styles.button} type="button" onClick={() => setSchedule("0 7 * * *")}>Daily 07:00 UTC</button><button className={styles.button} type="button" onClick={() => setSchedule("")}>Manual only</button></div></div><p className={styles.muted}>Next UTC schedule match: {enabled && assessmentId && preview ? preview : "Not scheduled (select an active assessment and valid schedule)." } This is a preview, not proof of scheduler delivery.</p>{(disabling || clearing) && <label className={styles.check}><input type="checkbox" required checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} />I confirm this stops future {disabling ? "collection requests" : "scheduled runs"}; jobs already queued or running are not canceled.</label>}{canManage && <div className={styles.actions}><button className={button} disabled={busy || ((disabling || clearing) && !confirmed)}>{busy ? "Saving…" : "Save collector settings"}</button></div>}</fieldset>{error && <p className={styles.error} role="alert">{error}</p>}</form>;
}

export function CollectorAdminPanel({ canManage, onChanged }: { canManage: boolean; onChanged?: () => void }) {
  const [items, setItems] = useState<Collector[]>([]);
  const [state, setState] = useState("Loading collectors…");
  const [error, setError] = useState("");
  const [assessments, setAssessments] = useState<WorkflowAssessment[]>([]);
  const [assessmentCursor, setAssessmentCursor] = useState<string | null>(null);
  async function loadAssessments(cursor?: string | null) {
    try { const data = await request<{ assessments: WorkflowAssessment[]; page: Page }>(`/api/assessments?status=active&limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`); setAssessments((current) => cursor ? [...current, ...data.assessments.filter((item) => !current.some((old) => old.id === item.id))] : data.assessments); setAssessmentCursor(data.page.nextCursor); }
    catch (failure) { setError(errorMessage(failure)); }
  }
  useEffect(() => { const timer = setTimeout(() => void loadAssessments(), 0); return () => clearTimeout(timer); }, []);
  const load = useCallback(async (signal?: AbortSignal) => {
    try { const data = await request<{ collectors: Collector[] }>("/api/collectors", { signal }); setItems(data.collectors); setState(data.collectors.length ? "Collector settings loaded." : "No collectors have been initialized."); setError(""); }
    catch (failure) { if (!signal?.aborted) { setError(errorMessage(failure)); setState(""); } }
  }, []);
  useEffect(() => { const controller = new AbortController(); const timer = setTimeout(() => void load(controller.signal), 0); return () => { controller.abort(); clearTimeout(timer); }; }, [load]);
  return <section className={styles.panel} aria-label="Collector scheduling"><div className={styles.header}><h2>Collector scheduling</h2><button className={styles.button} onClick={() => void load()}>Refresh collectors</button></div><p className={styles.notice}>Schedules use UTC and run at most hourly, only into the explicitly selected active assessment. Older schedules without a selection are paused. A closed or unavailable assessment never causes automatic reassignment.</p>{!canManage && <p className={styles.muted}>Only compliance leads and administrators can change collector settings.</p>}<p role="status" className={styles.muted}>{state}</p>{error && <p className={styles.error} role="alert">{error}</p>}<div className={styles.actions}><button type="button" className={styles.button} onClick={() => void loadAssessments()}>Refresh active assessments</button>{assessmentCursor && <button type="button" className={styles.button} onClick={() => void loadAssessments(assessmentCursor)}>Load more active assessments</button>}</div>{items.map((item) => <CollectorEditor key={`${item.id}:${item.updated_at}`} collector={item} canManage={canManage} assessments={assessments} onSaved={() => { void load(); onChanged?.(); }} />)}</section>;
}

export function AssessmentLifecyclePanel({ assessment, catalogs, canManage, onChanged }: { assessment: WorkflowAssessment | null; catalogs: ControlCatalog[]; canManage: boolean; onChanged: () => void }) {
  if (!assessment) return <section className={styles.panel}><h2>Assessment lifecycle</h2><p>Choose an assessment to view its lifecycle and versioned scope.</p></section>;
  return <AssessmentEditor key={`${assessment.id}:${assessment.updated_at}`} assessment={assessment} catalogs={catalogs} canManage={canManage} onChanged={onChanged} />;
}

function AssessmentEditor({ assessment, catalogs, canManage, onChanged }: { assessment: WorkflowAssessment; catalogs: ControlCatalog[]; canManage: boolean; onChanged: () => void }) {
  const [catalogId, setCatalogId] = useState(assessment.catalog_id || "");
  const [controls, setControls] = useState(assessment.controls);
  const [confirmClose, setConfirmClose] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const editable = canManage && assessment.status === "draft" && !assessment.scope_locked;
  const catalog = catalogs.find((item) => item.id === catalogId);
  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setError("");
    const form = new FormData(event.currentTarget);
    const targetStatus = (event.nativeEvent as SubmitEvent).submitter?.getAttribute("value") || assessment.status;
    const body: Record<string, unknown> = { id: assessment.id, status: targetStatus, expectedUpdatedAt: assessment.updated_at };
    if (editable) Object.assign(body, { name: form.get("name"), periodStart: form.get("periodStart"), periodEnd: form.get("periodEnd"), catalogId, scopeMode: "explicit", systems: String(form.get("systems") || "").split(/[,\n]/u).map((item) => item.trim()).filter(Boolean), controls });
    try { await patch("/api/assessments", body); setMessage(targetStatus === "closed" ? "Assessment closed; historical scope is immutable." : targetStatus === "active" ? "Assessment activated." : "Draft assessment saved."); onChanged(); }
    catch (failure) { setError(errorMessage(failure)); } finally { setBusy(false); }
  }
  return <section className={styles.panel} aria-label="Assessment lifecycle"><h2>Assessment lifecycle</h2><p className={styles.muted}>{assessment.name} · {label(assessment.status)}</p><p className={styles.notice}>Drafts can be edited before collection. After the first evidence capture, scope is locked. Activation requires named systems and catalog controls; closure is permanent.</p><form onSubmit={save}><fieldset disabled={!editable || busy} style={{ border: 0, padding: 0, margin: 0 }}><legend>Assessment definition</legend><div className={styles.grid}><label className={`${styles.field} ${styles.full}`}>Name<input className={styles.control} name="name" required minLength={3} maxLength={180} defaultValue={assessment.name} /></label><label className={styles.field}>Period start<input className={styles.control} name="periodStart" type="date" required defaultValue={assessment.period_start} /></label><label className={styles.field}>Period end<input className={styles.control} name="periodEnd" type="date" required defaultValue={assessment.period_end} /></label><label className={`${styles.field} ${styles.full}`}>Versioned catalog<select className={styles.control} value={catalogId} onChange={(event) => { setCatalogId(event.target.value); setControls([]); }} required><option value="" disabled>Select catalog</option>{!catalog && catalogId && <option value={catalogId}>{catalogId} (retired)</option>}{catalogs.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}</select></label><label className={`${styles.field} ${styles.full}`}>Systems in scope<textarea className={styles.control} name="systems" defaultValue={assessment.systems.join("\n")} /><small>Use exact system names, separated by commas or new lines. Maximum 250.</small></label><fieldset className={styles.full} style={{ border: 0, padding: 0 }}><legend>Controls in scope ({controls.length})</legend><div className={styles.checks}>{(catalog?.controls || assessment.controls.map((id) => ({ id, title: id }))).map((item) => <label className={styles.check} key={item.id}><input type="checkbox" checked={controls.includes(item.id)} onChange={(event) => setControls((current) => event.target.checked ? [...current, item.id] : current.filter((value) => value !== item.id))} />{item.id} · {item.title}</label>)}</div></fieldset></div></fieldset>{canManage && assessment.status !== "closed" && <div className={styles.actions}>{editable && <button className={styles.button} value="draft" disabled={busy}>Save draft</button>}{assessment.status === "draft" && <button className={button} value="active" disabled={busy || !catalogId || !controls.length}>Activate assessment</button>}{assessment.status === "active" && <><label className={styles.check}><input type="checkbox" checked={confirmClose} onChange={(event) => setConfirmClose(event.target.checked)} />I understand closing prevents future collection and edits.</label><button className={`${styles.button} ${styles.danger}`} value="closed" disabled={busy || !confirmClose}>Close assessment permanently</button></>}</div>}{error && <p className={styles.error} role="alert">{error}</p>}<p className={styles.success} role="status">{busy ? "Saving assessment…" : message}</p></form></section>;
}
