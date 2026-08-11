"use client";

import { useEffect, useMemo, useState } from "react";
import { controls, evidence as seedEvidence, findings, requirementCoverage, runs as seedRuns } from "../lib/data";
import type { CollectionRun, Evidence, EvidenceStatus } from "../lib/types";

type View = "Overview" | "Controls" | "Evidence" | "Collection runs" | "Findings" | "Connections" | "Settings" | "Help";
type Modal = "run" | "add" | "export" | "device" | null;

const nav: { label: View; mark: string; section: "workspace" | "manage" }[] = [
  { label: "Overview", mark: "⌂", section: "workspace" },
  { label: "Controls", mark: "◎", section: "workspace" },
  { label: "Evidence", mark: "▱", section: "workspace" },
  { label: "Collection runs", mark: "↻", section: "workspace" },
  { label: "Findings", mark: "◇", section: "workspace" },
  { label: "Connections", mark: "⌘", section: "manage" },
  { label: "Settings", mark: "⚙", section: "manage" },
  { label: "Help", mark: "?", section: "manage" },
];

const sources = [
  { id: "collector_aws", name: "AWS", detail: "Config and EC2 controls", status: "Not configured", mark: "AW" },
  { id: "collector_github", name: "GitHub", detail: "Inventory and branch protection", status: "Not configured", mark: "GH" },
  { id: "collector_okta", name: "Okta", detail: "MFA policies and access groups", status: "Not configured", mark: "OK" },
  { id: "collector_cloudflare", name: "Cloudflare", detail: "WAF managed rulesets", status: "Not configured", mark: "CF" },
  { id: "collector_browser", name: "Browser capture", detail: "Sensitive-data preflight screenshots", status: "Not configured", mark: "BR" },
];

type ApiCollector = { id: string; provider: string; display_name: string; enabled: number; schedule_cron: string | null; status: string; last_run_at: string | null; last_error: string | null; configuration: { configured: boolean; missing: string[] } };
type ApiUser = { id: string; email: string; displayName: string; role: string };
type ApiDevice = { id: string; display_name: string; platform: string; status: string; app_version: string | null; last_seen_at: string | null; created_at: string; revoked_at: string | null };

function cls(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(" ");
}

function titleCase(value: string): string { return value.split(/[_ ]/).map((part) => part ? `${part[0].toUpperCase()}${part.slice(1)}` : "").join(" "); }
function formatDate(value: unknown): string { const date = new Date(String(value)); return Number.isNaN(date.getTime()) ? String(value || "—") : date.toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit" }); }
async function apiError(response: Response): Promise<string> { try { const data = await response.json() as { error?: string }; return data.error || `Request failed (${response.status})`; } catch { return `Request failed (${response.status})`; } }

function mapApiEvidence(row: Record<string, unknown>): Evidence {
  const type = titleCase(String(row.type)) as Evidence["type"];
  const statusMap: Record<string, EvidenceStatus> = { approved: "Approved", needs_review: "Needs review", expiring: "Expiring", rejected: "Failed" };
  const redactionCount = Number(row.redaction_count || 0);
  const framework = String(row.framework || "PCI DSS 4.0.1");
  const sourceTags = Array.isArray(row.tags) ? row.tags.filter((value): value is string => typeof value === "string") : [];
  return {
    id: String(row.id), title: String(row.title), control: String(row.control_id), framework, requirement: framework,
    type, source: String(row.source), system: String(row.system), capturedAt: formatDate(row.captured_at), expiresAt: formatDate(row.expires_at), status: statusMap[String(row.status)] || "Needs review",
    owner: String(row.evidence_owner || "Unassigned"), environment: String(row.environment || "Unspecified"), assessmentPeriod: String(row.assessment_period || "Unspecified"),
    mappedControls: Array.isArray(row.mapped_controls) ? row.mapped_controls as Evidence["mappedControls"] : [],
    collector: String(row.collector_id || "Manual submission"), checksum: `sha256:${String(row.sha256).slice(0, 12)}…`, description: String(row.description || ""),
    code: ["Code", "Configuration"].includes(type) ? "Encrypted artifact\nIntegrity verified on access\nOpen or export to inspect contents" : undefined,
    language: type === "Code" ? "Protected source" : type === "Configuration" ? "Protected config" : undefined,
    accent: redactionCount ? "amber" : "emerald", tags: [...sourceTags, "Encrypted", "Server-backed", redactionCount ? `${redactionCount + Number(row.manual_redactions || 0)} value(s) redacted` : "Sensitive-data scan passed"],
  };
}

function mapApiRun(row: Record<string, unknown>): CollectionRun {
  const statusMap: Record<string, CollectionRun["status"]> = { completed: "Completed", partial: "Partial", running: "Running", queued: "Running", retrying: "Partial", failed: "Failed" };
  const started = row.started_at ? new Date(String(row.started_at)).getTime() : 0;
  const completed = row.completed_at ? new Date(String(row.completed_at)).getTime() : 0;
  const duration = started && completed ? `${Math.max(1, Math.round((completed - started) / 1000))}s` : row.status === "running" ? "In progress" : "—";
  return { id: String(row.id), source: String(row.display_name || row.provider || row.collector_id), startedAt: formatDate(row.created_at), status: statusMap[String(row.status)] || "Failed", artifacts: Number(row.artifact_count || 0), controls: Number(row.artifact_count || 0), duration, note: row.error_message ? String(row.error_message) : row.status === "retrying" ? `Retry ${row.attempt}/${row.max_attempts}` : undefined };
}

function StatusPill({ status }: { status: string }) {
  const key = status.toLowerCase().replaceAll(" ", "-");
  return <span className={`status status-${key}`}><i />{status}</span>;
}

function Ring({ value, label }: { value: number; label: string }) {
  return (
    <div className="ring" style={{ "--ring-value": `${value * 3.6}deg` } as React.CSSProperties}>
      <div><strong>{value}%</strong><span>{label}</span></div>
    </div>
  );
}

function EvidenceVisual({ item, compact = false }: { item: Evidence; compact?: boolean }) {
  if (item.code) {
    return (
      <div className={cls("code-preview", compact && "compact")}>
        <div className="code-top"><span>{item.language}</span><b>•••</b></div>
        <pre>{item.code}</pre>
      </div>
    );
  }
  return (
    <div className={cls("screen-preview", `accent-${item.accent || "blue"}`, compact && "compact")} aria-label={`Screenshot preview for ${item.title}`}>
      <div className="browser-bar"><span /><span /><span /><b /></div>
      <div className="fake-app">
        <div className="fake-sidebar"><i /><i /><i /><i /></div>
        <div className="fake-content"><em /><i className="fake-title" /><p /><div className="fake-grid"><i /><i /><i /></div><div className="fake-table"><span /><span /><span /></div></div>
      </div>
      <span className="capture-stamp">CAPTURED</span>
    </div>
  );
}

function EmptyState({ message, action, onAction }: { message: string; action?: string; onAction?: () => void }) {
  return <div className="empty-state"><span>⌕</span><h3>Nothing to show</h3><p>{message}</p>{action && <button className="button secondary" onClick={onAction}>{action}</button>}</div>;
}

export function EvidenceConsole() {
  const [view, setView] = useState<View>("Overview");
  const [modal, setModal] = useState<Modal>(null);
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("All statuses");
  const [typeFilter, setTypeFilter] = useState("All types");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [evidenceItems, setEvidenceItems] = useState<Evidence[]>(seedEvidence);
  const [runItems, setRunItems] = useState<CollectionRun[]>(seedRuns);
  const [collectorItems, setCollectorItems] = useState<ApiCollector[]>([]);
  const [deviceItems, setDeviceItems] = useState<ApiDevice[]>([]);
  const [deviceToken, setDeviceToken] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<ApiUser | null>(null);
  const [auditIntegrity, setAuditIntegrity] = useState<{ valid: boolean; checked: number } | null>(null);
  const [backendState, setBackendState] = useState<"loading" | "live" | "unavailable">("loading");
  const [busy, setBusy] = useState(false);
  const [redaction, setRedaction] = useState(true);
  const [notifications, setNotifications] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [meResponse, evidenceResponse, runsResponse, collectorsResponse, auditResponse] = await Promise.all([fetch("/api/me"), fetch("/api/evidence"), fetch("/api/runs"), fetch("/api/collectors"), fetch("/api/audit")]);
        if (!meResponse.ok || !evidenceResponse.ok || !runsResponse.ok || !collectorsResponse.ok) throw new Error("Backend unavailable");
        const [me, evidenceData, runData, collectorData, auditData] = await Promise.all([meResponse.json(), evidenceResponse.json(), runsResponse.json(), collectorsResponse.json(), auditResponse.ok ? auditResponse.json() : Promise.resolve(null)]) as [{ user: ApiUser }, { evidence: Array<Record<string, unknown>> }, { runs: Array<Record<string, unknown>> }, { collectors: ApiCollector[] }, { integrity: { valid: boolean; checked: number } } | null];
        if (cancelled) return;
        setCurrentUser(me.user);
        setEvidenceItems((evidenceData.evidence as Array<Record<string, unknown>>).map(mapApiEvidence));
        setRunItems((runData.runs as Array<Record<string, unknown>>).map(mapApiRun));
        setCollectorItems(collectorData.collectors);
        setAuditIntegrity(auditData?.integrity || null);
        const deviceResponse = await fetch("/api/devices");
        if (deviceResponse.ok) setDeviceItems(((await deviceResponse.json()) as { devices: ApiDevice[] }).devices);
        setBackendState("live");
      } catch {
        if (!cancelled) setBackendState("unavailable");
      }
    };
    void load();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    if (toast) {
      const timer = window.setTimeout(() => setToast(null), 3200);
      return () => window.clearTimeout(timer);
    }
  }, [toast]);

  useEffect(() => {
    const close = (event: KeyboardEvent) => {
      if (event.key === "Escape") { setModal(null); setSelectedEvidence(null); setSidebarOpen(false); }
    };
    window.addEventListener("keydown", close);
    return () => window.removeEventListener("keydown", close);
  }, []);

  const filteredEvidence = useMemo(() => evidenceItems.filter((item) => {
    const q = search.trim().toLowerCase();
    const matchesQuery = !q || [item.title, item.control, item.source, item.system, item.tags.join(" ")].join(" ").toLowerCase().includes(q);
    return matchesQuery && (statusFilter === "All statuses" || item.status === statusFilter) && (typeFilter === "All types" || item.type === typeFilter);
  }), [evidenceItems, search, statusFilter, typeFilter]);

  function navigate(next: View) {
    setView(next); setSidebarOpen(false); setSearch("");
  }

  async function approveEvidence(item: Evidence) {
    setBusy(true);
    try {
      const response = await fetch(`/api/evidence/${encodeURIComponent(item.id)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "approve" }) });
      if (!response.ok) throw new Error(await apiError(response));
      const next = evidenceItems.map((entry) => entry.id === item.id ? { ...entry, status: "Approved" as EvidenceStatus } : entry);
      setEvidenceItems(next); setSelectedEvidence({ ...item, status: "Approved" }); setToast(`${item.id} approved and written to the immutable audit chain.`);
    } catch (error) { setToast(error instanceof Error ? error.message : "Approval failed."); }
    finally { setBusy(false); }
  }

  async function handleRun(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const selected = form.getAll("source").map(String);
    if (!selected.length) { setToast("Select at least one evidence source."); return; }
    setBusy(true);
    const newRun: CollectionRun = { id: `pending-${Date.now()}`, source: selected.length === 1 ? `${selected[0].replace("collector_", "")} on-demand collection` : `On-demand collection · ${selected.length} sources`, startedAt: "Just now", status: "Running", artifacts: 0, controls: 0, duration: "In progress" };
    setRunItems((items) => [newRun, ...items]);
    try {
      const response = await fetch("/api/runs", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ collectorIds: selected }) });
      const data = await response.json() as { error?: string; results: Array<{ artifacts: number; status: string }> };
      if (!response.ok && response.status !== 207) throw new Error(data.error || "Collection failed.");
      const refreshed = await fetch("/api/runs").then((result) => result.json()) as { runs: Array<Record<string, unknown>> };
      setRunItems((refreshed.runs as Array<Record<string, unknown>>).map(mapApiRun));
      const captured = (data.results as Array<{ artifacts: number }>).reduce((sum, result) => sum + result.artifacts, 0);
      const failures = (data.results as Array<{ status: string }>).filter((result) => result.status !== "completed").length;
      setModal(null); setToast(failures ? `Collection finished with ${failures} source issue(s). Review run details.` : `Collection complete: ${captured} new artifacts captured.`); setView("Collection runs");
    } catch (error) { setRunItems((items) => items.filter((run) => run.id !== newRun.id)); setToast(error instanceof Error ? error.message : "Collection failed."); }
    finally { setBusy(false); }
  }

  async function handleAdd(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    try {
      const response = await fetch("/api/evidence", { method: "POST", body: form });
      if (!response.ok) throw new Error(await apiError(response));
      const refreshed = await fetch("/api/evidence").then((result) => result.json()) as { evidence: Array<Record<string, unknown>> };
      setEvidenceItems((refreshed.evidence as Array<Record<string, unknown>>).map(mapApiEvidence));
      const result = await response.json() as { id: string; deduplicated: boolean };
      setModal(null); setToast(result.deduplicated ? "Matching evidence already exists; no duplicate was stored." : `${result.id} encrypted and added to the review queue.`); setView("Evidence");
    } catch (error) { setToast(error instanceof Error ? error.message : "Evidence upload failed."); }
    finally { setBusy(false); }
  }

  async function exportPackage() {
    setBusy(true);
    try {
      const response = await fetch("/api/packages", { method: "POST" });
      if (!response.ok) throw new Error(await apiError(response));
      const data = await response.json() as { package: { id: string; evidenceCount: number } };
      window.location.assign(`/api/packages/${encodeURIComponent(data.package.id)}`);
      setModal(null); setToast(`Signed package ready with ${data.package.evidenceCount} encrypted artifacts.`);
    } catch (error) { setToast(error instanceof Error ? error.message : "Package generation failed."); }
    finally { setBusy(false); }
  }

  async function enrollDevice(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const displayName = String(new FormData(event.currentTarget).get("displayName") || "").trim();
    if (!displayName) return;
    setBusy(true);
    try {
      const response = await fetch("/api/devices", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ displayName }) });
      if (!response.ok) throw new Error(await apiError(response));
      const data = await response.json() as { token: string; device: ApiDevice };
      setDeviceToken(data.token);
      const refreshed = await fetch("/api/devices").then((result) => result.json()) as { devices: ApiDevice[] };
      setDeviceItems(refreshed.devices);
      setToast(`${displayName} enrolled. Copy the token now; Scopeproof will not show it again.`);
    } catch (error) { setToast(error instanceof Error ? error.message : "Device enrollment failed."); }
    finally { setBusy(false); }
  }

  async function revokeDevice(id: string) {
    setBusy(true);
    try {
      const response = await fetch("/api/devices", { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ id }) });
      if (!response.ok) throw new Error(await apiError(response));
      setDeviceItems((items) => items.map((item) => item.id === id ? { ...item, status: "revoked", revoked_at: new Date().toISOString() } : item));
      setToast("Capture device revoked. Its token can no longer upload evidence.");
    } catch (error) { setToast(error instanceof Error ? error.message : "Device revocation failed."); }
    finally { setBusy(false); }
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <aside className={cls("sidebar", sidebarOpen && "open")}>
        <div className="brand"><div className="brand-mark">S</div><div><strong>Scopeproof</strong><span>PCI operations</span></div></div>
        <div className="workspace-switch"><span>AC</span><div><strong>Acme Commerce</strong><small>PCI DSS 4.0.1</small></div><b>⌄</b></div>
        <nav aria-label="Primary navigation">
          <span className="nav-label">Workspace</span>
          {nav.filter((item) => item.section === "workspace").map((item) => <button key={item.label} className={view === item.label ? "active" : ""} onClick={() => navigate(item.label)}><i>{item.mark}</i>{item.label}{item.label === "Findings" && <em>4</em>}</button>)}
          <span className="nav-label manage">Manage</span>
          {nav.filter((item) => item.section === "manage").map((item) => <button key={item.label} className={view === item.label ? "active" : ""} onClick={() => navigate(item.label)}><i>{item.mark}</i>{item.label}</button>)}
        </nav>
        <div className="assessment-card"><div><span>Q3 assessment</span><strong>82%</strong></div><progress value="82" max="100" /><p>18 days until review</p></div>
        <div className="profile"><span>{(currentUser?.displayName || "M C").split(/\s|@/).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("")}</span><div><strong>{currentUser?.displayName || "Authenticated user"}</strong><small>{currentUser?.role?.replaceAll("_", " ") || "Loading access…"}</small></div><button aria-label="Open profile menu" onClick={() => setToast("Identity is provided by your private Sites access policy.")}>•••</button></div>
      </aside>
      {sidebarOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}

      <main id="main-content">
        <header className="topbar">
          <button className="mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="Open navigation">☰</button>
          <div className="breadcrumbs"><span>Acme Commerce</span><b>/</b><strong>{view}</strong></div>
          <div className="top-actions">
            <button className="icon-button" aria-label="Notifications" onClick={() => setToast("You’re all caught up. No new notifications.")}>♢<i /></button>
            <button className="button secondary" onClick={() => setModal("export")}>↓ <span>Export package</span></button>
            <button className="button primary" onClick={() => setModal("run")}>＋ <span>Run collection</span></button>
          </div>
        </header>

        <section className="page-wrap">
          <div className={cls("security-strip", backendState)}><span>{backendState === "live" ? "✓" : backendState === "loading" ? "↻" : "!"}</span><div><strong>{backendState === "live" ? "Protected evidence workspace" : backendState === "loading" ? "Connecting to protected storage…" : "Protected services unavailable"}</strong><p>{backendState === "live" ? `AES-256-GCM storage · ${currentUser?.role?.replaceAll("_", " ")} access · audit chain ${auditIntegrity?.valid ? `verified (${auditIntegrity.checked} events)` : "pending"}` : backendState === "unavailable" ? "The interface is showing non-authoritative sample data until authenticated storage reconnects." : "Authenticating and verifying storage bindings."}</p></div></div>
          {view === "Overview" && <Overview evidenceItems={evidenceItems} runItems={runItems} onNavigate={navigate} onSelect={setSelectedEvidence} onRun={() => setModal("run")} />}
          {view === "Controls" && <ControlsView onNavigate={navigate} />}
          {view === "Evidence" && <EvidenceView items={filteredEvidence} search={search} setSearch={setSearch} status={statusFilter} setStatus={setStatusFilter} type={typeFilter} setType={setTypeFilter} onSelect={setSelectedEvidence} onAdd={() => setModal("add")} />}
          {view === "Collection runs" && <RunsView items={runItems} onRun={() => setModal("run")} onToast={setToast} />}
          {view === "Findings" && <FindingsView />}
          {view === "Connections" && <ConnectionsView collectors={collectorItems} devices={deviceItems} onEnroll={() => { setDeviceToken(null); setModal("device"); }} onRevoke={revokeDevice} onToast={setToast} />}
          {view === "Settings" && <SettingsView redaction={redaction} setRedaction={setRedaction} notifications={notifications} setNotifications={setNotifications} auditIntegrity={auditIntegrity} role={currentUser?.role || "auditor"} onToast={setToast} />}
          {view === "Help" && <HelpView onNavigate={navigate} />}
        </section>
      </main>

      {selectedEvidence && <EvidenceDrawer item={selectedEvidence} onClose={() => setSelectedEvidence(null)} onApprove={approveEvidence} onToast={setToast} />}
      {modal && <Modal type={modal} collectors={collectorItems} deviceToken={deviceToken} onClose={() => !busy && setModal(null)} onRun={handleRun} onAdd={handleAdd} onExport={exportPackage} onDevice={enrollDevice} busy={busy} />}
      {toast && <div className="toast" role="status"><span>✓</span>{toast}</div>}
    </div>
  );
}

function PageTitle({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description: string; actions?: React.ReactNode }) {
  return <div className="page-title"><div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h1>{title}</h1><p>{description}</p></div>{actions && <div className="page-actions">{actions}</div>}</div>;
}

function Overview({ evidenceItems, runItems, onNavigate, onSelect, onRun }: { evidenceItems: Evidence[]; runItems: CollectionRun[]; onNavigate: (view: View) => void; onSelect: (item: Evidence) => void; onRun: () => void }) {
  const queue = evidenceItems.filter((item) => item.status !== "Approved");
  return <>
    <PageTitle eyebrow="Friday, August 7" title="Good morning, Maya" description="Your PCI evidence program is healthy. Here’s what needs attention before the next review." actions={<><button className="button secondary mobile-hide" onClick={() => onNavigate("Evidence")}>Review evidence</button><button className="button primary mobile-hide" onClick={onRun}>＋ Run collection</button></>} />
    <div className="attention-banner"><span>!</span><div><strong>{queue.length + 5} items need attention</strong><p>4 evidence items are awaiting review, 2 controls have gaps, and 1 connection requires action.</p></div><button onClick={() => onNavigate("Evidence")}>Open review queue <b>→</b></button></div>
    <div className="metrics-grid">
      <article className="metric-card featured"><Ring value={82} label="readiness" /><div><span>Assessment readiness</span><strong>On track for Q3</strong><p><b>↑ 6%</b> since last week</p></div></article>
      <article className="metric-card"><div className="metric-icon blue">▱</div><span>Evidence coverage</span><strong>91 <small>/ 108</small></strong><p>84% of scoped controls</p></article>
      <article className="metric-card"><div className="metric-icon violet">↻</div><span>Automated evidence</span><strong>76%</strong><p><b>82 collectors</b> running</p></article>
      <article className="metric-card"><div className="metric-icon amber">◇</div><span>Open findings</span><strong>4</strong><p><em>1 high severity</em></p></article>
    </div>
    <div className="dashboard-grid">
      <section className="panel coverage-panel"><div className="panel-head"><div><h2>Control coverage</h2><p>PCI DSS 4.0.1 requirements in scope</p></div><button onClick={() => onNavigate("Controls")}>View controls →</button></div>
        <div className="coverage-list">{requirementCoverage.map((item) => <div className="coverage-row" key={item.req}><span className="req-badge">{item.req}</span><div><strong>{item.name}</strong><div className="progress-line"><i style={{ width: `${item.value}%` }} /></div></div><b className={item.value < 70 ? "low" : ""}>{item.value}%</b></div>)}</div>
      </section>
      <section className="panel activity-panel"><div className="panel-head"><div><h2>Collection activity</h2><p>Latest automation runs</p></div><button onClick={() => onNavigate("Collection runs")}>View all →</button></div>
        <div className="activity-list">{runItems.slice(0, 4).map((run) => <div className="activity-item" key={run.id}><div className={cls("source-dot", run.status.toLowerCase())}>{run.source.slice(0, 2).toUpperCase()}</div><div><strong>{run.source}</strong><span>{run.artifacts ? `${run.artifacts} artifacts · ` : ""}{run.startedAt}</span></div><StatusPill status={run.status} /></div>)}</div>
        <button className="full-button" onClick={onRun}>＋ Run a new collection</button>
      </section>
    </div>
    <section className="panel recent-panel"><div className="panel-head"><div><h2>Recent evidence</h2><p>New artifacts collected across your environment</p></div><button onClick={() => onNavigate("Evidence")}>View evidence library →</button></div>
      <div className="evidence-row">{evidenceItems.slice(0, 4).map((item) => <button className="evidence-card" key={item.id} onClick={() => onSelect(item)}><EvidenceVisual item={item} compact /><div className="evidence-card-body"><div><span className="type-label">{item.type}</span><StatusPill status={item.status} /></div><strong>{item.title}</strong><p><b>{item.control}</b> · {item.source}</p><small>{item.capturedAt}</small></div></button>)}</div>
    </section>
  </>;
}

function ControlsView({ onNavigate }: { onNavigate: (view: View) => void }) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("All");
  const items = controls.filter((control) => (!query || `${control.id} ${control.title} ${control.owner}`.toLowerCase().includes(query.toLowerCase())) && (filter === "All" || control.status === filter));
  return <><PageTitle eyebrow="PCI DSS 4.0.1" title="Control workspace" description="Track coverage, ownership, and collection automation for every control in scope." actions={<button className="button primary" onClick={() => onNavigate("Evidence")}>Review evidence</button>} />
    <div className="summary-strip"><div><strong>108</strong><span>Controls in scope</span></div><div><strong>91</strong><span>Fully covered</span></div><div><strong>11</strong><span>Partially covered</span></div><div><strong>6</strong><span>Evidence gaps</span></div></div>
    <section className="panel table-panel"><div className="toolbar"><label className="search-box"><span>⌕</span><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search control, owner, or requirement…" /></label><div className="segmented">{["All", "Covered", "Partial", "Gap"].map((item) => <button className={filter === item ? "active" : ""} key={item} onClick={() => setFilter(item)}>{item}</button>)}</div></div>
      {items.length ? <div className="data-table controls-table"><div className="table-header"><span>Control</span><span>Owner</span><span>Coverage</span><span>Automation</span><span>Next due</span><span /></div>{items.map((control) => <div className="table-row" key={control.id}><div><span className="control-id">{control.id}</span><strong>{control.title}</strong><small>{control.systems.join(" · ")}</small></div><span>{control.owner}</span><div><StatusPill status={control.status} /><small>{control.evidenceCount} artifacts</small></div><div className="automation-cell"><strong>{control.automation}%</strong><div><i style={{ width: `${control.automation}%` }} /></div></div><span className={control.nextDue === "Overdue" ? "danger-text" : ""}>{control.nextDue}</span><button aria-label={`View control ${control.id}`} onClick={() => onNavigate("Evidence")}>→</button></div>)}</div> : <EmptyState message="Try a different control search or coverage filter." />}
    </section>
  </>;
}

function EvidenceView({ items, search, setSearch, status, setStatus, type, setType, onSelect, onAdd }: { items: Evidence[]; search: string; setSearch: (v: string) => void; status: string; setStatus: (v: string) => void; type: string; setType: (v: string) => void; onSelect: (item: Evidence) => void; onAdd: () => void }) {
  return <><PageTitle eyebrow="Evidence library" title="Collected evidence" description="Review, validate, and trace every artifact back to its source and PCI requirement." actions={<button className="button primary" onClick={onAdd}>＋ Add evidence</button>} />
    <section className="panel evidence-library"><div className="toolbar"><label className="search-box wide"><span>⌕</span><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search evidence, control, system, or tag…" /></label><select aria-label="Filter by evidence type" value={type} onChange={(e) => setType(e.target.value)}><option>All types</option><option>Screenshot</option><option>Code</option><option>Configuration</option><option>Report</option></select><select aria-label="Filter by review status" value={status} onChange={(e) => setStatus(e.target.value)}><option>All statuses</option><option>Approved</option><option>Needs review</option><option>Expiring</option><option>Failed</option></select></div>
      <div className="library-subhead"><span>{items.length} artifacts</span><span>Sorted by <b>most recent</b></span></div>
      {items.length ? <div className="library-grid">{items.map((item) => <button className="library-card" key={item.id} onClick={() => onSelect(item)}><EvidenceVisual item={item} /><div className="library-body"><div><span className="type-label">{item.type}</span><StatusPill status={item.status} /></div><h3>{item.title}</h3><p>{item.description}</p><div className="artifact-meta"><span><b>{item.control}</b> · {item.requirement}</span><span>{item.source} / {item.system}</span><span>{item.capturedAt}</span></div></div></button>)}</div> : <EmptyState message="No evidence matches these filters." action="Clear filters" onAction={() => { setSearch(""); setStatus("All statuses"); setType("All types"); }} />}
    </section>
  </>;
}

function RunsView({ items, onRun, onToast }: { items: CollectionRun[]; onRun: () => void; onToast: (message: string) => void }) {
  return <><PageTitle eyebrow="Automation" title="Collection runs" description="Monitor scheduled and on-demand collectors, captured artifacts, and failures." actions={<button className="button primary" onClick={onRun}>＋ Run collection</button>} />
    {items[0]?.status === "Running" && <div className="running-banner"><span className="spinner" /><div><strong>Collection in progress</strong><p>Authenticating sources and capturing evidence. You can safely leave this page.</p></div><b>Running</b></div>}
    <section className="panel table-panel"><div className="panel-head padded"><div><h2>Run history</h2><p>90-day operational record</p></div><select aria-label="Filter run history"><option>All sources</option><option>AWS</option><option>GitHub</option><option>Okta</option></select></div>
      <div className="data-table runs-table"><div className="table-header"><span>Run</span><span>Status</span><span>Artifacts</span><span>Controls</span><span>Duration</span><span /></div>{items.map((run) => <div className="table-row" key={run.id}><div><strong>{run.source}</strong><small>{run.id} · {run.startedAt}</small></div><div><StatusPill status={run.status} />{run.note && <small>{run.note}</small>}</div><strong>{run.artifacts || "—"}</strong><span>{run.controls || "—"}</span><span>{run.duration}</span><button aria-label={`More options for ${run.id}`} onClick={() => onToast(`${run.id} log and artifact manifest opened.`)}>•••</button></div>)}</div>
    </section>
    <div className="info-callout"><span>i</span><div><strong>Evidence integrity is preserved automatically</strong><p>Every artifact receives a SHA-256 checksum, source timestamp, collector identity, and immutable audit event.</p></div></div>
  </>;
}

function FindingsView() {
  const [items, setItems] = useState(findings);
  return <><PageTitle eyebrow="Remediation" title="Findings" description="Resolve evidence gaps and collection failures before they become assessment exceptions." />
    <div className="finding-stats"><article><span className="severity-dot high" /><strong>1</strong><p>High severity</p></article><article><span className="severity-dot medium" /><strong>2</strong><p>Medium severity</p></article><article><span className="severity-dot low" /><strong>1</strong><p>Low severity</p></article><article><strong>11 days</strong><p>Average time to close</p></article></div>
    <section className="panel finding-list"><div className="panel-head padded"><div><h2>Active findings</h2><p>Prioritized by severity and due date</p></div></div>{items.map((item) => <div className="finding-row" key={item.id}><span className={`severity-flag ${item.severity.toLowerCase()}`}>{item.severity}</span><div><strong>{item.title}</strong><p>{item.id} · Control {item.control}</p></div><div><small>Owner</small><span>{item.owner}</span></div><div><small>Due</small><span>{item.due}</span></div><select aria-label={`Update status for ${item.title}`} value={item.status} onChange={(e) => setItems((current) => current.map((finding) => finding.id === item.id ? { ...finding, status: e.target.value as typeof item.status } : finding))}><option>Open</option><option>In progress</option><option>Accepted</option><option>Resolved</option></select></div>)}</section>
  </>;
}

function ConnectionsView({ collectors, devices, onEnroll, onRevoke, onToast }: { collectors: ApiCollector[]; devices: ApiDevice[]; onEnroll: () => void; onRevoke: (id: string) => void; onToast: (message: string) => void }) {
  const cards = sources.map((source) => {
    const collector = collectors.find((item) => item.id === source.id);
    return { ...source, status: collector?.configuration.configured ? titleCase(collector.status) : "Not configured", detail: collector?.configuration.configured ? source.detail : `Missing ${collector?.configuration.missing.join(", ") || "hosted secrets"}`, lastRun: collector?.last_run_at ? formatDate(collector.last_run_at) : "Never", error: collector?.last_error };
  });
  const attention = cards.filter((card) => card.status !== "Healthy");
  return <><PageTitle eyebrow="Data sources" title="Connections" description="Manage the systems Scopeproof uses to collect trustworthy compliance evidence." actions={<button className="button primary" onClick={() => onToast("Add provider credentials as encrypted hosted environment variables; they are never stored in the application database.")}>＋ Configure source</button>} />
    {attention.length > 0 && <div className="connection-alert"><span>!</span><div><strong>{attention.length} collector{attention.length === 1 ? "" : "s"} need configuration</strong><p>Provider credentials are missing or the latest live API call failed. Scheduled collection remains paused for affected sources.</p></div><button onClick={() => onToast("Open hosted environment settings to add the missing secret values from .env.example.")}>Configuration guide</button></div>}
    <div className="connections-grid">{cards.map((source) => <article className="connection-card" key={source.name}><div className="connection-head"><span>{source.mark}</span><button aria-label={`Options for ${source.name}`} onClick={() => onToast(`${source.name} runs ${collectors.find((item) => item.id === source.id)?.schedule_cron || "without a schedule"} in UTC.`)}>•••</button></div><h3>{source.name}</h3><p>{source.detail}</p><StatusPill status={source.status} /><div><span>Last successful run</span><b>{source.lastRun}</b></div><button onClick={() => onToast(source.status === "Healthy" ? `${source.name} is configured. Use Run collection to execute a live test.` : `${source.name}: ${source.error || source.detail}`)}>Inspect configuration</button></article>)}</div>
    <section className="panel device-panel"><div className="panel-head"><div><h2>Mac capture devices</h2><p>Revocable device identities for locally reviewed screenshot uploads</p></div><button className="button primary" onClick={onEnroll}>＋ Enroll Mac</button></div>
      {devices.length ? <div className="device-list">{devices.map((device) => <div className="device-row" key={device.id}><span className="device-icon">⌘</span><div><strong>{device.display_name}</strong><small>{device.platform} · {device.app_version ? `v${device.app_version}` : "Not connected yet"} · {device.last_seen_at ? `Seen ${formatDate(device.last_seen_at)}` : "Awaiting first upload"}</small></div><StatusPill status={titleCase(device.status)} /><button className="button secondary" disabled={device.status === "revoked"} onClick={() => onRevoke(device.id)}>{device.status === "revoked" ? "Revoked" : "Revoke"}</button></div>)}</div> : <EmptyState message="No Mac capture devices are enrolled. Create a one-time token, then paste it into Scopeproof Capture Settings." action="Enroll first Mac" onAction={onEnroll} />}
    </section>
  </>;
}

function SettingsView({ redaction, setRedaction, notifications, setNotifications, auditIntegrity, role, onToast }: { redaction: boolean; setRedaction: (value: boolean) => void; notifications: boolean; setNotifications: (value: boolean) => void; auditIntegrity: { valid: boolean; checked: number } | null; role: string; onToast: (message: string) => void }) {
  void redaction;
  return <><PageTitle eyebrow="Workspace" title="Settings" description="Configure evidence retention, capture safety, and reviewer notifications." />
    <div className="settings-layout"><nav><button className="active">Evidence policy</button><button onClick={() => onToast(`Your effective role is ${role.replaceAll("_", " ")}. Role changes require an administrator.`)}>Team & access</button><button onClick={() => onToast(auditIntegrity?.valid ? `Audit chain verified across ${auditIntegrity.checked} event(s).` : "Audit chain verification is pending.")}>Audit log</button></nav><section className="panel settings-panel"><h2>Evidence policy</h2><p>Enforced protections for automated and manual evidence.</p><div className="integrity-setting"><span>{auditIntegrity?.valid ? "✓" : "↻"}</span><div><strong>{auditIntegrity?.valid ? "Immutable audit chain verified" : "Verifying audit chain"}</strong><p>{auditIntegrity?.valid ? `${auditIntegrity.checked} signed event(s) validated from genesis.` : "Integrity verification runs server-side."}</p></div></div><div className="setting-row"><div><strong>Sensitive-data redaction</strong><span>Luhn-validated PAN, access tokens, API secrets, JWTs, private keys, and authorization headers are scanned before encryption. This control is mandatory in production.</span></div><button role="switch" aria-label="Sensitive-data redaction is enforced" aria-checked="true" className="switch on" onClick={() => onToast("Redaction is a mandatory server-side control and cannot be disabled.")}><i /></button></div><div className="setting-row"><div><strong>Reviewer notifications</strong><span>Notify control owners when evidence is ready, expiring, or has failed collection.</span></div><button role="switch" aria-label="Toggle reviewer notifications" aria-checked={notifications} className={cls("switch", notifications && "on")} onClick={() => setNotifications(!notifications)}><i /></button></div><label className="field"><span>Default evidence validity</span><select><option>90 days</option><option>30 days</option><option>180 days</option><option>1 year</option></select><small>Control-specific schedules override this value.</small></label><label className="field"><span>Retention period</span><select><option>13 months</option><option>2 years</option><option>3 years</option><option>7 years</option></select><small>Deletion is blocked while an artifact belongs to an active assessment.</small></label><div className="settings-actions"><button className="button secondary" onClick={() => { setRedaction(true); setNotifications(true); onToast("Unsaved settings discarded."); }}>Discard</button><button className="button primary" onClick={() => onToast("Local notification preference saved. Security controls remain enforced server-side.")}>Save changes</button></div></section></div>
  </>;
}

function HelpView({ onNavigate }: { onNavigate: (view: View) => void }) {
  return <><PageTitle eyebrow="Product guide" title="Help & how to use Scopeproof" description="Follow the evidence lifecycle from a live source to a signed assessor package." />
    <section className="help-steps" aria-label="Evidence workflow">
      {[['1', 'Connect sources', 'Configure least-privilege provider credentials or enroll a Mac capture device.', 'Connections'], ['2', 'Collect safely', 'Run an API collector or review a locally scanned screenshot before it enters Scopeproof.', 'Collection runs'], ['3', 'Review evidence', 'Confirm control mapping, scope, freshness, redactions, and integrity before approval.', 'Evidence'], ['4', 'Export for assessment', 'Generate a signed ZIP with embedded artifacts, a PDF index, hashes, and verification material.', 'Overview']].map(([number, title, copy, destination]) => <article key={number}><span>{number}</span><div><h2>{title}</h2><p>{copy}</p><button onClick={() => onNavigate(destination as View)}>Open {destination} →</button></div></article>)}
    </section>
    <div className="help-grid">
      <section className="panel help-panel"><h2>Mac screenshot quick start</h2><ol><li>Open <strong>Connections</strong>, enroll a Mac, and copy the one-time token.</li><li>In the Scopeproof shield menu, open <strong>Capture Settings</strong>; enter this workspace’s HTTPS URL and token.</li><li>Select PCI DSS, HIPAA, FedRAMP, SOC 2, ISO 27001, or an imported catalog; then choose the control, system, owner, period, and evidence title.</li><li>Select an exact window. Scopeproof runs local OCR, masks PANs and credentials, lets you add manual redactions, stamps the image, and shows a preview.</li><li>Use <strong>Search Evidence</strong> on the Mac to tag, review, and approve artifacts before building an assessor package.</li></ol><button className="button secondary" onClick={() => onNavigate('Connections')}>Manage capture devices</button></section>
      <section className="panel help-panel"><h2>What proves integrity</h2><dl><div><dt>Visible stamp</dt><dd>Local date, time, timezone, control, system, environment, period, and evidence ID.</dd></div><div><dt>Local manifest</dt><dd>PNG SHA-256, source metadata, redaction counts, and previous/current chain hashes.</dd></div><div><dt>Server receipt</dt><dd>Signed server time, device identity, audit event, and optional RFC 3161 timestamp token.</dd></div><div><dt>Assessor package</dt><dd>ECDSA-signed manifest, public key, independent hashes, embedded evidence, and PDF index.</dd></div></dl></section>
      <section className="panel help-panel"><h2>Safety & privacy</h2><ul><li>Captured OCR text is processed on the Mac and is not retained.</li><li>Device tokens are shown once, hashed server-side, stored in Keychain, and revocable.</li><li>Artifacts are encrypted with AES-256-GCM before R2 persistence.</li><li>Every material action is written to a tamper-evident, append-only audit chain.</li><li>Scopeproof never captures the screen without an explicit menu action.</li></ul></section>
      <section className="panel help-panel"><h2>Troubleshooting</h2><dl><div><dt>Capture permission fails</dt><dd>Open the shield menu → Screen Recording Settings, enable Scopeproof Capture, then fully quit and reopen it.</dd></div><div><dt>Upload is pending</dt><dd>Confirm the HTTPS server URL and active device token, then choose Retry Pending Uploads.</dd></div><div><dt>A collector is paused</dt><dd>Open Connections and inspect its missing hosted secret or most recent provider error.</dd></div><div><dt>Evidence was blocked</dt><dd>Remove cardholder data or credentials from the source and collect again; unsafe automated captures are not stored.</dd></div></dl></section>
    </div>
  </>;
}

function EvidenceDrawer({ item, onClose, onApprove, onToast }: { item: Evidence; onClose: () => void; onApprove: (item: Evidence) => void; onToast: (message: string) => void }) {
  return <><button className="drawer-scrim" aria-label="Close evidence details" onClick={onClose} /><aside className="drawer" aria-label="Evidence details"><div className="drawer-head"><div><span>{item.id}</span><StatusPill status={item.status} /></div><button aria-label="Close evidence details" onClick={onClose}>×</button></div><div className="drawer-scroll"><span className="eyebrow">{item.type} evidence</span><h2>{item.title}</h2><p className="drawer-description">{item.description}</p><EvidenceVisual item={item} /><div className="integrity-banner"><span>✓</span><div><strong>Integrity verified</strong><p>{item.checksum} · Source unchanged</p></div></div><section className="detail-section"><h3>Evidence mapping</h3><dl><div><dt>Compliance control</dt><dd>{item.framework || item.requirement} · {item.control}</dd></div><div><dt>Source</dt><dd>{item.source} / {item.system}</dd></div><div><dt>Owner</dt><dd>{item.owner || "Unassigned"}</dd></div><div><dt>Scope</dt><dd>{item.environment || "Unspecified"} · {item.assessmentPeriod || "Unspecified"}</dd></div><div><dt>Captured</dt><dd>{item.capturedAt}</dd></div><div><dt>Valid until</dt><dd>{item.expiresAt}</dd></div><div><dt>Collector</dt><dd>{item.collector}</dd></div></dl></section>{item.mappedControls?.length ? <section className="detail-section"><h3>Related controls</h3><div className="tag-row">{item.mappedControls.map((mapping) => <span key={`${mapping.framework}-${mapping.controlID}`}>{mapping.framework} · {mapping.controlID}</span>)}</div></section> : null}<section className="detail-section"><h3>Protection checks</h3><div className="check-row"><span>✓</span><div><strong>Secret scan passed</strong><p>No credentials or access tokens detected</p></div></div><div className="check-row"><span>✓</span><div><strong>Cardholder data scan passed</strong><p>No PAN or sensitive authentication data detected</p></div></div></section><section className="detail-section"><h3>Tags</h3><div className="tag-row">{item.tags.map((tag) => <span key={tag}>{tag}</span>)}</div></section></div><div className="drawer-actions"><button className="button secondary" onClick={() => onToast(`${item.id} flagged for follow-up.`)}>Flag issue</button><button className="button primary" disabled={item.status === "Approved"} onClick={() => onApprove(item)}>{item.status === "Approved" ? "✓ Approved" : "Approve evidence"}</button></div></aside></>;
}

function Modal({ type, collectors, deviceToken, onClose, onRun, onAdd, onExport, onDevice, busy }: { type: Exclude<Modal, null>; collectors: ApiCollector[]; deviceToken: string | null; onClose: () => void; onRun: (e: React.FormEvent<HTMLFormElement>) => void; onAdd: (e: React.FormEvent<HTMLFormElement>) => void; onExport: () => void; onDevice: (e: React.FormEvent<HTMLFormElement>) => void; busy: boolean }) {
  const titles = { run: "Run evidence collection", add: "Add manual evidence", export: "Export evidence package", device: "Enroll Mac capture device" };
  return <div className="modal-layer" role="dialog" aria-modal="true" aria-labelledby="modal-title"><button className="modal-scrim" onClick={onClose} aria-label="Close dialog" /><section className="modal"><div className="modal-head"><div><span className="eyebrow">Scopeproof</span><h2 id="modal-title">{titles[type]}</h2></div><button onClick={onClose} aria-label="Close dialog">×</button></div>
    {type === "run" && <form onSubmit={onRun}><p className="modal-intro">Select configured sources to query now. Provider responses are scanned, encrypted, checksum de-duplicated, and written to the audit chain.</p><fieldset className="source-select"><legend>Live evidence sources</legend>{sources.map((source, index) => { const collector = collectors.find((item) => item.id === source.id); const configured = collector?.configuration.configured === true; return <label key={source.name} className={!configured ? "disabled" : ""}><input type="checkbox" name="source" value={source.id} defaultChecked={configured && index < 3} disabled={!configured} /><span>{source.mark}</span><div><strong>{source.name}</strong><small>{configured ? `${source.detail} · ${collector?.schedule_cron || "On demand"} UTC` : `Missing ${collector?.configuration.missing.join(", ") || "hosted credentials"}`}</small></div></label>; })}</fieldset><label className="checkbox-line"><input type="checkbox" checked readOnly /> Enforce PAN, secret, and token scanning before encryption</label><div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={busy}>{busy ? <><span className="button-spinner" /> Collecting live evidence…</> : "Start live collection"}</button></div></form>}
    {type === "add" && <form onSubmit={onAdd} className="evidence-form"><div className="form-grid"><label className="field full"><span>Evidence title</span><input name="title" required placeholder="e.g. Production database encryption settings" /></label><label className="field"><span>PCI control</span><select name="control" required defaultValue=""><option value="" disabled>Select control</option>{controls.map((control) => <option key={control.id} value={control.id}>{control.id} — {control.title}</option>)}</select></label><label className="field"><span>Evidence type</span><select name="type"><option value="code">Code</option><option value="configuration">Configuration</option><option value="report">Text report</option></select></label><label className="field"><span>System or asset</span><input name="system" required placeholder="payments-production" /></label><label className="field"><span>Code language</span><select name="language"><option>Text</option><option>HCL</option><option>YAML</option><option>JSON</option><option>Shell</option><option>TypeScript</option></select></label><label className="field full"><span>Description</span><textarea name="description" rows={3} placeholder="What this evidence proves and where it came from" /></label><label className="field full"><span>Code or configuration excerpt</span><textarea name="code" className="mono-input" rows={5} required placeholder="# Paste the focused excerpt here; server-side redaction runs before encryption" /></label></div><div className="upload-zone"><span>↑</span><div><strong>Attach an optional text-based artifact</strong><p>TXT, JSON, XML, or YAML up to 10 MB · screenshots must use the preflight browser collector</p></div><label className="choose-file">Choose file<input name="attachment" type="file" accept="text/*,application/json,application/xml,application/yaml" /></label></div><div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={busy}>{busy ? "Encrypting…" : "Scan, encrypt & add"}</button></div></form>}
    {type === "export" && <div><p className="modal-intro">Generate a signed, framework-aware assessor package containing every approved artifact, a CSV/PDF evidence index, SHA-256 manifest, and integrity attestation.</p><div className="export-summary"><div><span>▣</span><p><strong>Approved evidence across configured frameworks</strong><small>Organized by framework and control · encrypted while stored</small></p></div><StatusPill status="Ready" /></div><label className="checkbox-line"><input type="checkbox" checked readOnly /> Embed decrypted artifacts into the protected ZIP</label><label className="checkbox-line"><input type="checkbox" checked readOnly /> ECDSA-sign manifest and include public verification key</label><div className="privacy-note"><span>i</span><p>The package is generated server-side, integrity-checked after decryption, and expires after seven days. Downloads are recorded in the immutable audit chain.</p></div><div className="modal-actions"><button className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={busy} onClick={onExport}>{busy ? "Building signed package…" : "↓ Generate signed ZIP"}</button></div></div>}
    {type === "device" && (deviceToken ? <div><p className="modal-intro">This token is shown once. Copy it into the Mac app under <strong>Scopeproof shield → Capture Settings</strong>, then close this dialog.</p><div className="token-reveal"><code>{deviceToken}</code><button className="button secondary" onClick={() => void navigator.clipboard.writeText(deviceToken)}>Copy token</button></div><div className="privacy-note"><span>!</span><p>Treat this token like a password. It is stored hashed on the server and in the Mac login Keychain. Revoke the device immediately if the token is exposed.</p></div><div className="modal-actions"><button className="button primary" onClick={onClose}>I saved the token</button></div></div> : <form onSubmit={onDevice}><p className="modal-intro">Create a revocable identity for one Mac. Evidence uploaded by this device is attributed to your user and written to the immutable audit chain.</p><label className="field"><span>Device name</span><input name="displayName" required maxLength={100} defaultValue="Jayson’s Mac" placeholder="e.g. Compliance MacBook Pro" /></label><div className="privacy-note"><span>i</span><p>The token is displayed only once. The Mac stores it in Keychain and sends it only to your configured Scopeproof server.</p></div><div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={busy}>{busy ? "Creating secure token…" : "Create device token"}</button></div></form>)}
  </section></div>;
}
