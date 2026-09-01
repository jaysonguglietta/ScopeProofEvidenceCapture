"use client";

import { useEffect, useMemo, useState } from "react";
import Image from "next/image";
import { controls } from "../lib/data";
import type { CollectionRun, Evidence, EvidenceStatus } from "../lib/types";

type View = "Overview" | "Controls" | "Evidence" | "SBOMs" | "Collection runs" | "Findings" | "Connections" | "Settings" | "Help";
type Modal = "run" | "add" | "sbom" | "export" | "device" | "assessment" | null;

const nav: { label: View; mark: string; section: "workspace" | "manage" }[] = [
  { label: "Overview", mark: "⌂", section: "workspace" },
  { label: "Controls", mark: "◎", section: "workspace" },
  { label: "Evidence", mark: "▱", section: "workspace" },
  { label: "SBOMs", mark: "◫", section: "workspace" },
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
type ApiMember = { id: string; email: string; display_name: string; role: string; status: "active" | "suspended" | "revoked"; invited_by: string | null; created_at: string; last_seen_at: string };
type ApiInvitation = { id: string; email: string; role: string; status: "pending" | "accepted" | "revoked" | "expired"; invited_by: string; expires_at: string; accepted_user_id?: string | null; created_at: string };
type ApiAuditEvent = { sequence: number; id: string; occurred_at: string; actor_email: string; action: string; resource_type: string; resource_id: string; event_hash: string };
type ApiDevice = { id: string; display_name: string; platform: string; status: string; app_version: string | null; last_seen_at: string | null; token_issued_at: string; token_expires_at: string; token_last_rotated_at: string | null; token_expired: number; created_at: string; revoked_at: string | null };
type ApiJiraConnection = { connected: boolean; configured: boolean; id?: string; siteUrl?: string; siteName?: string; allowedProjects?: string[]; status?: "active" | "reauthorization_required"; lastTestedAt?: string | null; updatedAt?: string };
type ApiAssessment = { id: string; name: string; framework: string; period_start: string; period_end: string; systems: string[]; controls: string[]; owner_id: string; status: "draft" | "active" | "closed"; created_at: string; updated_at: string };
type ApiRepository = { name: string; fullName: string; defaultBranch: string; private: boolean; archived: boolean };
type ApiSbom = { id: string; assessment_id: string; repository_full_name: string; requested_ref: string; resolved_commit_sha: string | null; format: "cyclonedx_json" | "spdx_json"; status: "queued" | "running" | "completed" | "retrying" | "failed"; attempt: number; max_attempts: number; evidence_id: string | null; component_count: number; direct_dependency_count: number; manifest_count: number; source_archive_sha256: string | null; artifact_sha256: string | null; generator_name: string; generator_version: string; manifests: string[]; comparison: { baseline?: boolean; previousJobId?: string; added?: number; removed?: number; changed?: number; addedComponents?: string[]; removedComponents?: string[]; changedComponents?: string[] }; error_code: string | null; error_message: string | null; created_at: string; completed_at: string | null };

function cls(...values: Array<string | false | null | undefined>) {
  return values.filter(Boolean).join(" ");
}

function titleCase(value: string): string { return value.split(/[_ ]/).map((part) => part ? `${part[0].toUpperCase()}${part.slice(1)}` : "").join(" "); }
function formatDate(value: unknown): string { const date = new Date(String(value)); return Number.isNaN(date.getTime()) ? String(value || "—") : date.toLocaleString("en-US", { month: "short", day: "numeric", year: "numeric", hour: "numeric", minute: "2-digit" }); }
async function apiError(response: Response): Promise<string> { try { const data = await response.json() as { error?: string }; return data.error || `Request failed (${response.status})`; } catch { return `Request failed (${response.status})`; } }

function mapApiEvidence(row: Record<string, unknown>): Evidence {
  const type = titleCase(String(row.type)) as Evidence["type"];
  const statusMap: Record<string, EvidenceStatus> = { approved: "Approved", needs_review: "Needs review", expiring: "Expiring", expired: "Expired", rejected: "Failed" };
  const redactionCount = Number(row.redaction_count || 0);
  const framework = String(row.framework || "PCI DSS 4.0.1");
  const sourceTags = Array.isArray(row.tags) ? row.tags.filter((value): value is string => typeof value === "string") : [];
  const occurrenceCount = Math.max(1, Number(row.occurrence_count || 1));
  const serverSafetyStatus = (["verified", "pending", "not_applicable"].includes(String(row.server_safety_status)) ? String(row.server_safety_status) : "not_applicable") as Evidence["serverSafetyStatus"];
  const nativeProvenanceStatus = (["verified", "pending", "not_applicable"].includes(String(row.native_provenance_status)) ? String(row.native_provenance_status) : "not_applicable") as Evidence["nativeProvenanceStatus"];
  const trustTags = [
    type === "Screenshot" ? serverSafetyStatus === "verified" ? "Independent server safety verified" : "Safety verification pending · quarantined" : null,
    nativeProvenanceStatus === "verified" ? "Signed device chain finalized" : nativeProvenanceStatus === "pending" ? "Device provenance pending · quarantined" : null,
  ].filter((value): value is string => Boolean(value));
  return {
    id: String(row.id), title: String(row.title), control: String(row.control_id), framework, requirement: framework,
    type, source: String(row.source), system: String(row.system), capturedAt: formatDate(row.captured_at), expiresAt: formatDate(row.expires_at), status: statusMap[String(row.status)] || "Needs review",
    owner: String(row.evidence_owner || "Unassigned"), environment: String(row.environment || "Unspecified"), assessmentPeriod: String(row.assessment_period || "Unspecified"),
    mappedControls: Array.isArray(row.mapped_controls) ? row.mapped_controls as Evidence["mappedControls"] : [],
    jiraIssueKey: row.jira_issue_key ? String(row.jira_issue_key) : undefined, jiraIssueURL: String(row.jira_issue_url || "").startsWith("https://") ? String(row.jira_issue_url) : undefined,
    assessmentId: row.assessment_id ? String(row.assessment_id) : undefined,
    occurrenceCount, lastObservedAt: row.last_observed_at ? formatDate(row.last_observed_at) : undefined,
    serverSafetyStatus, nativeProvenanceStatus,
    collector: String(row.collector_id || "Manual submission"), checksum: `sha256:${String(row.sha256)}`, sha256: String(row.sha256), createdBy: String(row.created_by || ""), approvedBy: row.approved_by ? String(row.approved_by) : undefined, description: String(row.description || ""),
    code: ["Code", "Configuration"].includes(type) ? "Encrypted artifact\nIntegrity verified on access\nOpen or export to inspect contents" : undefined,
    language: type === "Code" ? "Protected source" : type === "Configuration" ? "Protected config" : undefined,
    accent: serverSafetyStatus === "pending" || nativeProvenanceStatus === "pending" || redactionCount ? "amber" : "emerald", tags: [...sourceTags, "Encrypted", "Server-backed", `${occurrenceCount} collection occurrence${occurrenceCount === 1 ? "" : "s"}`, ...trustTags, redactionCount ? `${redactionCount + Number(row.manual_redactions || 0)} value(s) redacted` : "No redactions reported"],
  };
}

function mapApiRun(row: Record<string, unknown>): CollectionRun {
  const statusMap: Record<string, CollectionRun["status"]> = { completed: "Completed", partial: "Partial", running: "Running", queued: "Running", retrying: "Partial", failed: "Failed" };
  const started = row.started_at ? new Date(String(row.started_at)).getTime() : 0;
  const completed = row.completed_at ? new Date(String(row.completed_at)).getTime() : 0;
  const duration = started && completed ? `${Math.max(1, Math.round((completed - started) / 1000))}s` : row.status === "running" ? "In progress" : "—";
  return { id: String(row.id), source: String(row.display_name || row.provider || row.collector_id), startedAt: formatDate(row.created_at), status: statusMap[String(row.status)] || "Failed", artifacts: Number(row.artifact_count || 0), controls: Number(row.artifact_count || 0), duration, note: row.error_message ? String(row.error_message) : row.status === "retrying" ? `Retry ${row.attempt}/${row.max_attempts}` : undefined, assessmentId: row.assessment_id ? String(row.assessment_id) : undefined };
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
  const [evidenceItems, setEvidenceItems] = useState<Evidence[]>([]);
  const [runItems, setRunItems] = useState<CollectionRun[]>([]);
  const [assessmentItems, setAssessmentItems] = useState<ApiAssessment[]>([]);
  const [sbomItems, setSbomItems] = useState<ApiSbom[]>([]);
  const [repositoryItems, setRepositoryItems] = useState<ApiRepository[]>([]);
  const [sbomConfigured, setSbomConfigured] = useState(false);
  const [sbomManagedError, setSbomManagedError] = useState<string | null>(null);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState("");
  const [collectorItems, setCollectorItems] = useState<ApiCollector[]>([]);
  const [deviceItems, setDeviceItems] = useState<ApiDevice[]>([]);
  const [deviceToken, setDeviceToken] = useState<string | null>(null);
  const [jiraConnection, setJiraConnection] = useState<ApiJiraConnection | null>(null);
  const [currentUser, setCurrentUser] = useState<ApiUser | null>(null);
  const [auditIntegrity, setAuditIntegrity] = useState<{ valid: boolean; checked: number } | null>(null);
  const [backendState, setBackendState] = useState<"loading" | "live" | "unavailable">("loading");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [meResponse, evidenceResponse, runsResponse, collectorsResponse, auditResponse, assessmentsResponse, sbomsResponse] = await Promise.all([fetch("/api/me"), fetch("/api/evidence"), fetch("/api/runs"), fetch("/api/collectors"), fetch("/api/audit"), fetch("/api/assessments"), fetch("/api/sboms")]);
        if (!meResponse.ok || !evidenceResponse.ok || !runsResponse.ok || !collectorsResponse.ok || !assessmentsResponse.ok || !sbomsResponse.ok) throw new Error("Backend unavailable");
        const [me, evidenceData, runData, collectorData, auditData, assessmentData, sbomData] = await Promise.all([meResponse.json(), evidenceResponse.json(), runsResponse.json(), collectorsResponse.json(), auditResponse.ok ? auditResponse.json() : Promise.resolve(null), assessmentsResponse.json(), sbomsResponse.json()]) as [{ user: ApiUser }, { evidence: Array<Record<string, unknown>> }, { runs: Array<Record<string, unknown>> }, { collectors: ApiCollector[] }, { integrity: { valid: boolean; checked: number } } | null, { assessments: ApiAssessment[] }, { jobs: ApiSbom[]; repositories: ApiRepository[]; configured: boolean; managedError: string | null }];
        if (cancelled) return;
        setCurrentUser(me.user);
        setEvidenceItems((evidenceData.evidence as Array<Record<string, unknown>>).map(mapApiEvidence));
        setRunItems((runData.runs as Array<Record<string, unknown>>).map(mapApiRun));
        setCollectorItems(collectorData.collectors);
        setAssessmentItems(assessmentData.assessments);
        setSbomItems(sbomData.jobs);
        setRepositoryItems(sbomData.repositories);
        setSbomConfigured(sbomData.configured);
        setSbomManagedError(sbomData.managedError);
        setSelectedAssessmentId(assessmentData.assessments.find((item) => item.status === "active")?.id || "");
        setAuditIntegrity(auditData?.integrity || null);
        if (["compliance_lead", "admin"].includes(me.user.role)) {
          const deviceResponse = await fetch("/api/devices");
          if (deviceResponse.ok) setDeviceItems(((await deviceResponse.json()) as { devices: ApiDevice[] }).devices);
          const jiraResponse = await fetch("/api/jira/connection");
          if (jiraResponse.ok) setJiraConnection(((await jiraResponse.json()) as { connection: ApiJiraConnection }).connection);
        }
        setBackendState("live");
      } catch {
        if (!cancelled) { setEvidenceItems([]); setRunItems([]); setCollectorItems([]); setAssessmentItems([]); setSbomItems([]); setRepositoryItems([]); setSbomManagedError(null); setCurrentUser(null); setAuditIntegrity(null); setBackendState("unavailable"); }
      }
    };
    void load();
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    const query = new URLSearchParams(window.location.search);
    const jira = query.get("jira");
    if (!jira) return;
    window.history.replaceState({}, "", window.location.pathname);
    const timer = window.setTimeout(() => {
      setView("Connections");
      if (jira === "connected") setToast("Jira Cloud connected. Test the connection before sending evidence.");
      else setToast(query.get("reason") === "consent_denied" ? "Jira Cloud authorization was cancelled." : "Jira Cloud could not be connected. Review the OAuth configuration and try again.");
    }, 0);
    return () => window.clearTimeout(timer);
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

  const scopedEvidence = useMemo(() => evidenceItems.filter((item) => item.assessmentId === selectedAssessmentId), [evidenceItems, selectedAssessmentId]);
  const scopedRuns = useMemo(() => runItems.filter((item) => item.assessmentId === selectedAssessmentId), [runItems, selectedAssessmentId]);
  const scopedSboms = useMemo(() => sbomItems.filter((item) => item.assessment_id === selectedAssessmentId), [sbomItems, selectedAssessmentId]);
  const filteredEvidence = useMemo(() => scopedEvidence.filter((item) => {
    const q = search.trim().toLowerCase();
    const matchesQuery = !q || [item.title, item.control, item.source, item.system, item.jiraIssueKey || "", item.tags.join(" ")].join(" ").toLowerCase().includes(q);
    return matchesQuery && (statusFilter === "All statuses" || item.status === statusFilter) && (typeFilter === "All types" || item.type === typeFilter);
  }), [scopedEvidence, search, statusFilter, typeFilter]);

  function navigate(next: View) {
    setView(next); setSidebarOpen(false); setSearch("");
  }

  async function approveEvidence(item: Evidence, rationale: string) {
    setBusy(true);
    try {
      const response = await fetch(`/api/evidence/${encodeURIComponent(item.id)}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ action: "approve", expectedSha256: item.sha256, rationale, confirmedActualArtifact: true }) });
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
    const newRun: CollectionRun = { id: `pending-${Date.now()}`, source: selected.length === 1 ? `${selected[0].replace("collector_", "")} on-demand collection` : `On-demand collection · ${selected.length} sources`, startedAt: "Just now", status: "Running", artifacts: 0, controls: 0, duration: "In progress", assessmentId: selectedAssessmentId };
    setRunItems((items) => [newRun, ...items]);
    try {
      const assessmentId = String(form.get("assessmentId") || selectedAssessmentId);
      const response = await fetch("/api/runs", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ collectorIds: selected, assessmentId }) });
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

  async function handleSbom(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const formElement = event.currentTarget;
    const form = new FormData(formElement);
    const sourceMode = String(form.get("sourceMode") || "managed");
    const payload = { assessmentId: form.get("assessmentId"), sourceMode, repository: form.get("repository"), repositoryUrl: form.get("repositoryUrl"), githubToken: form.get("githubToken"), ref: form.get("ref"), format: form.get("format") };
    const tokenInput = formElement.elements.namedItem("githubToken");
    if (tokenInput instanceof HTMLInputElement) tokenInput.value = "";
    setBusy(true);
    try {
      const response = await fetch("/api/sboms", { method: "POST", cache: "no-store", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
      const data = await response.json() as { job?: ApiSbom; error?: string };
      if (!response.ok || !data.job || data.job.status !== "completed") throw new Error(data.job?.error_message || data.error || "SBOM generation failed.");
      const [sboms, evidence] = await Promise.all([fetch("/api/sboms").then((result) => result.json()) as Promise<{ jobs: ApiSbom[] }>, fetch("/api/evidence").then((result) => result.json()) as Promise<{ evidence: Array<Record<string, unknown>> }>]);
      setSbomItems(sboms.jobs); setEvidenceItems(evidence.evidence.map(mapApiEvidence)); setModal(null); setView("SBOMs");
      setToast(`${data.job.repository_full_name} SBOM generated with ${data.job.component_count} components and added to evidence review.`);
    } catch (error) { setToast(error instanceof Error ? error.message : "SBOM generation failed."); }
    finally { setBusy(false); }
  }

  async function handleAdd(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const assessment = assessmentItems.find((item) => item.id === String(form.get("assessmentId")));
    if (!assessment) { setToast("Select an open assessment."); return; }
    form.set("framework", assessment.framework); form.set("assessmentPeriod", `${assessment.period_start} – ${assessment.period_end}`);
    setBusy(true);
    try {
      const response = await fetch("/api/evidence", { method: "POST", body: form });
      if (!response.ok) throw new Error(await apiError(response));
      const refreshed = await fetch("/api/evidence").then((result) => result.json()) as { evidence: Array<Record<string, unknown>> };
      setEvidenceItems((refreshed.evidence as Array<Record<string, unknown>>).map(mapApiEvidence));
      const result = await response.json() as { id: string; deduplicated: boolean };
      setModal(null); setToast(result.deduplicated ? "Matching bytes were reused and a new collection occurrence was recorded." : `${result.id} encrypted and added to the review queue.`); setView("Evidence");
    } catch (error) { setToast(error instanceof Error ? error.message : "Evidence upload failed."); }
    finally { setBusy(false); }
  }

  async function exportPackage() {
    setBusy(true);
    try {
      const response = await fetch("/api/packages", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ assessmentId: selectedAssessmentId }) });
      if (!response.ok) throw new Error(await apiError(response));
      const data = await response.json() as { package: { id: string; evidenceCount: number } };
      const download = document.createElement("a");
      download.href = `/api/packages/${encodeURIComponent(data.package.id)}`;
      download.setAttribute("download", "");
      document.body.appendChild(download);
      download.click();
      download.remove();
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

  async function createAssessment(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); const form = new FormData(event.currentTarget); setBusy(true);
    try {
      const response = await fetch("/api/assessments", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ name: form.get("name"), framework: form.get("framework"), periodStart: form.get("periodStart"), periodEnd: form.get("periodEnd"), systems: String(form.get("systems") || "").split(/[,\n]/).map((v) => v.trim()).filter(Boolean), controls: String(form.get("controls") || "").split(/[,\n]/).map((v) => v.trim()).filter(Boolean), status: "active" }) });
      if (!response.ok) throw new Error(await apiError(response));
      const data = await response.json() as { assessment: ApiAssessment }; setAssessmentItems((items) => [data.assessment, ...items]); setSelectedAssessmentId(data.assessment.id); setModal(null); setToast(`${data.assessment.name} is now the active evidence scope.`);
    } catch (error) { setToast(error instanceof Error ? error.message : "Assessment could not be created."); }
    finally { setBusy(false); }
  }

  async function closeAssessment() {
    if (!activeAssessment || activeAssessment.status !== "active" || !window.confirm(`Close ${activeAssessment.name}? New evidence can no longer be collected into it.`)) return;
    setBusy(true);
    try {
      const response = await fetch("/api/assessments", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ id: activeAssessment.id, status: "closed" }) });
      if (!response.ok) throw new Error(await apiError(response));
      const data = await response.json() as { assessment: ApiAssessment };
      setAssessmentItems((items) => items.map((item) => item.id === data.assessment.id ? data.assessment : item));
      setToast(`${data.assessment.name} is closed and its scope is immutable.`);
    } catch (error) { setToast(error instanceof Error ? error.message : "Assessment could not be closed."); }
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

  async function rotateDevice(id: string) {
    if (!window.confirm("Rotate this device token? The current token will stop working immediately.")) return;
    setBusy(true);
    try {
      const response = await fetch("/api/devices", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ id }) });
      if (!response.ok) throw new Error(await apiError(response));
      const data = await response.json() as { token: string; tokenExpiresAt: string };
      setDeviceToken(data.token); setModal("device");
      const refreshed = await fetch("/api/devices").then((result) => result.json()) as { devices: ApiDevice[] };
      setDeviceItems(refreshed.devices); setToast("Device token rotated. Copy the replacement now; the previous token is invalid.");
    } catch (error) { setToast(error instanceof Error ? error.message : "Device token rotation failed."); }
    finally { setBusy(false); }
  }

  async function connectJira(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const siteUrl = String(form.get("siteUrl") || "").trim();
    const allowedProjects = String(form.get("allowedProjects") || "").split(/[\s,]+/).map((value) => value.trim()).filter(Boolean);
    setBusy(true);
    try {
      const response = await fetch("/api/jira/oauth/start", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ siteUrl, allowedProjects }) });
      if (!response.ok) throw new Error(await apiError(response));
      const data = await response.json() as { authorizeUrl: string };
      window.location.assign(data.authorizeUrl);
    } catch (error) { setToast(error instanceof Error ? error.message : "Jira Cloud authorization could not start."); setBusy(false); }
  }

  async function testJira() {
    setBusy(true);
    try {
      const response = await fetch("/api/jira/connection", { method: "POST" });
      if (!response.ok) throw new Error(await apiError(response));
      const data = await response.json() as { connection: ApiJiraConnection };
      setJiraConnection(data.connection); setToast(`Connected to ${data.connection.siteName || "Jira Cloud"}.`);
    } catch (error) { setToast(error instanceof Error ? error.message : "Jira Cloud connection test failed."); }
    finally { setBusy(false); }
  }

  async function disconnectJiraConnection() {
    if (!window.confirm("Disconnect Jira Cloud? Scopeproof will delete the encrypted OAuth tokens. Existing Jira attachments and audit receipts are not removed.")) return;
    setBusy(true);
    try {
      const response = await fetch("/api/jira/connection", { method: "DELETE" });
      if (!response.ok) throw new Error(await apiError(response));
      setJiraConnection({ connected: false, configured: true }); setToast("Jira Cloud disconnected and its stored OAuth tokens were deleted.");
    } catch (error) { setToast(error instanceof Error ? error.message : "Jira Cloud could not be disconnected."); }
    finally { setBusy(false); }
  }

  const activeAssessment = assessmentItems.find((item) => item.id === selectedAssessmentId);
  const canCollect = backendState === "live" && activeAssessment?.status === "active" && ["compliance_lead", "admin"].includes(currentUser?.role || "");
  const canExport = backendState === "live" && Boolean(activeAssessment) && ["reviewer", "compliance_lead", "admin"].includes(currentUser?.role || "");
  const canManageOperations = ["compliance_lead", "admin"].includes(currentUser?.role || "");

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to content</a>
      <aside className={cls("sidebar", sidebarOpen && "open")}>
        <div className="brand"><div className="brand-mark">S</div><div><strong>Scopeproof</strong><span>PCI operations</span></div></div>
        <div className="workspace-switch"><span>AS</span><div><label className="sr-only" htmlFor="assessment-workspace">Assessment workspace</label><select id="assessment-workspace" value={selectedAssessmentId} onChange={(event) => setSelectedAssessmentId(event.target.value)}><option value="">No assessment selected</option>{assessmentItems.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.status}</option>)}</select><small>{activeAssessment?.framework || "Create a scope to begin"}</small></div>{activeAssessment?.status === "active" && canManageOperations ? <button disabled={busy} onClick={closeAssessment} title="Close this assessment">×</button> : <b>⌄</b>}</div>
        <nav aria-label="Primary navigation">
          <span className="nav-label">Workspace</span>
          {nav.filter((item) => item.section === "workspace").map((item) => <button key={item.label} className={view === item.label ? "active" : ""} onClick={() => navigate(item.label)}><i>{item.mark}</i>{item.label}{item.label === "Findings" && <em>{scopedEvidence.filter((entry) => entry.status !== "Approved").length + scopedRuns.filter((run) => ["Failed", "Partial"].includes(run.status)).length}</em>}</button>)}
          <span className="nav-label manage">Manage</span>
          {nav.filter((item) => item.section === "manage").map((item) => <button key={item.label} className={view === item.label ? "active" : ""} onClick={() => navigate(item.label)}><i>{item.mark}</i>{item.label}</button>)}
        </nav>
        <div className="assessment-card"><div><span>{activeAssessment?.status || "Not configured"}</span><strong>{scopedEvidence.filter((item) => item.status === "Approved").length}</strong></div><progress value={scopedEvidence.filter((item) => item.status === "Approved").length} max={Math.max(1, scopedEvidence.length)} /><p>{activeAssessment ? `${activeAssessment.period_start} – ${activeAssessment.period_end}` : "Create an assessment scope"}</p></div>
        <div className="profile"><span>{(currentUser?.displayName || "M C").split(/\s|@/).slice(0, 2).map((part) => part[0]?.toUpperCase()).join("")}</span><div><strong>{currentUser?.displayName || "Authenticated user"}</strong><small>{currentUser?.role?.replaceAll("_", " ") || "Loading access…"}</small></div><button aria-label="Open profile menu" onClick={() => setToast("Identity is provided by your private Sites access policy.")}>•••</button></div>
      </aside>
      {sidebarOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />}

      <main id="main-content">
        <header className="topbar">
          <button className="mobile-menu" onClick={() => setSidebarOpen(true)} aria-label="Open navigation">☰</button>
          <div className="breadcrumbs"><span>{activeAssessment?.name || "Scopeproof"}</span><b>/</b><strong>{view}</strong></div>
          <div className="top-actions">
            <button className="icon-button" aria-label="Open findings requiring attention" onClick={() => navigate("Findings")}>♢{scopedEvidence.some((item) => item.status !== "Approved") || scopedRuns.some((run) => ["Failed", "Partial"].includes(run.status)) ? <i /> : null}</button>
            <button className="button secondary" disabled={!canExport} title={!canExport ? "Reviewer or evidence-operations access is required." : undefined} onClick={() => setModal("export")}>↓ <span>Export package</span></button>
            <button className="button primary" disabled={!canCollect} title={!canCollect ? "Evidence-operations access is required." : undefined} onClick={() => setModal("run")}>＋ <span>Run collection</span></button>
          </div>
        </header>

        <section className="page-wrap">
          <div className={cls("security-strip", backendState)}><span>{backendState === "live" ? "✓" : backendState === "loading" ? "↻" : "!"}</span><div><strong>{backendState === "live" ? "Protected evidence workspace" : backendState === "loading" ? "Connecting to protected storage…" : "Protected services unavailable"}</strong><p>{backendState === "live" ? `AES-256-GCM storage · ${currentUser?.role?.replaceAll("_", " ")} access · audit chain ${auditIntegrity?.valid ? `verified (${auditIntegrity.checked} events)` : "pending"}` : backendState === "unavailable" ? "Authoritative data is hidden until authentication and protected storage recover." : "Authenticating and verifying storage bindings."}</p></div></div>
          {backendState !== "live" ? <EmptyState message={backendState === "loading" ? "Authenticating and loading authoritative evidence…" : "Scopeproof could not verify the protected backend. Reload after restoring authentication or storage; no sample compliance data is displayed."} /> : <>
          {view === "Overview" && <Overview evidenceItems={scopedEvidence} runItems={scopedRuns} collectors={collectorItems} assessment={activeAssessment} user={currentUser} canCollect={canCollect} onNavigate={navigate} onSelect={setSelectedEvidence} onRun={() => activeAssessment ? setModal("run") : setModal("assessment")} onCreateAssessment={() => setModal("assessment")} />}
          {view === "Controls" && <ControlsView evidenceItems={scopedEvidence} onNavigate={navigate} />}
          {view === "Evidence" && <EvidenceView items={filteredEvidence} canCollect={canCollect} search={search} setSearch={setSearch} status={statusFilter} setStatus={setStatusFilter} type={typeFilter} setType={setTypeFilter} onSelect={setSelectedEvidence} onAdd={() => setModal("add")} />}
          {view === "SBOMs" && <SbomView items={scopedSboms} configured={sbomConfigured} managedError={sbomManagedError} canGenerate={canCollect} onGenerate={() => setModal("sbom")} onOpenEvidence={(id) => { const item = evidenceItems.find((entry) => entry.id === id); if (item) setSelectedEvidence(item); else setToast("The evidence record is unavailable. Reload and try again."); }} />}
          {view === "Collection runs" && <RunsView items={scopedRuns} canCollect={canCollect} onRun={() => setModal("run")} onToast={setToast} />}
          {view === "Findings" && <FindingsView evidenceItems={scopedEvidence} runItems={scopedRuns} />}
          {view === "Connections" && <ConnectionsView collectors={collectorItems} devices={deviceItems} jira={jiraConnection} canManageJira={canManageOperations} busy={busy} onConnectJira={connectJira} onTestJira={testJira} onDisconnectJira={disconnectJiraConnection} onEnroll={() => { setDeviceToken(null); setModal("device"); }} onRotate={rotateDevice} onRevoke={revokeDevice} onToast={setToast} />}
          {view === "Settings" && <SettingsView auditIntegrity={auditIntegrity} currentUser={currentUser} onToast={setToast} />}
          {view === "Help" && <HelpView onNavigate={navigate} />}</>}
        </section>
      </main>

      {selectedEvidence && <EvidenceDrawer key={selectedEvidence.id} item={selectedEvidence} currentUser={currentUser} onClose={() => setSelectedEvidence(null)} onApprove={approveEvidence} onToast={setToast} />}
      {modal && <Modal type={modal} collectors={collectorItems} repositories={repositoryItems} assessments={assessmentItems} selectedAssessmentId={selectedAssessmentId} setSelectedAssessmentId={setSelectedAssessmentId} deviceToken={deviceToken} onClose={() => !busy && setModal(null)} onRun={handleRun} onSbom={handleSbom} onAdd={handleAdd} onExport={exportPackage} onDevice={enrollDevice} onAssessment={createAssessment} busy={busy} />}
      {toast && <div className="toast" role="status"><span>✓</span>{toast}</div>}
    </div>
  );
}

function PageTitle({ eyebrow, title, description, actions }: { eyebrow?: string; title: string; description: string; actions?: React.ReactNode }) {
  return <div className="page-title"><div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h1>{title}</h1><p>{description}</p></div>{actions && <div className="page-actions">{actions}</div>}</div>;
}

function Overview({ evidenceItems, runItems, collectors, assessment, user, canCollect, onNavigate, onSelect, onRun, onCreateAssessment }: { evidenceItems: Evidence[]; runItems: CollectionRun[]; collectors: ApiCollector[]; assessment?: ApiAssessment; user: ApiUser | null; canCollect: boolean; onNavigate: (view: View) => void; onSelect: (item: Evidence) => void; onRun: () => void; onCreateAssessment: () => void }) {
  const queue = evidenceItems.filter((item) => item.status !== "Approved");
  const approved = evidenceItems.filter((item) => item.status === "Approved").length;
  const coveredControls = new Set(evidenceItems.filter((item) => item.status === "Approved").map((item) => item.control)).size;
  const scopedControls = assessment?.controls.length || new Set(evidenceItems.map((item) => item.control)).size;
  const readiness = scopedControls ? Math.round(coveredControls / scopedControls * 100) : 0;
  const configuredCollectors = collectors.filter((item) => item.configuration.configured).length;
  const collectorAttention = collectors.filter((item) => item.status === "action_needed" || !item.configuration.configured).length;
  const firstName = (user?.displayName || user?.email || "Operator").split(/[ @]/)[0];
  return <>
    <PageTitle eyebrow={new Date().toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric" })} title={`Welcome, ${firstName}`} description={assessment ? `Authoritative status for ${assessment.name}.` : "Create an assessment before collecting or exporting evidence."} actions={<>{!assessment && <button className="button primary mobile-hide" onClick={onCreateAssessment}>＋ Create assessment</button>}<button className="button secondary mobile-hide" onClick={() => onNavigate("Evidence")}>Review evidence</button><button className="button primary mobile-hide" disabled={!canCollect} title={!canCollect ? "An active assessment and evidence-operations access are required." : undefined} onClick={onRun}>＋ Run collection</button></>} />
    <div className="attention-banner"><span>!</span><div><strong>{queue.length + collectorAttention} items need attention</strong><p>{queue.length} evidence item(s) await review and {collectorAttention} collector(s) are incomplete or unconfigured.</p></div><button onClick={() => onNavigate(queue.length ? "Evidence" : "Connections")}>Review details <b>→</b></button></div>
    <div className="metrics-grid">
      <article className="metric-card featured"><Ring value={readiness} label="coverage" /><div><span>Assessment evidence coverage</span><strong>{assessment ? `${coveredControls} of ${scopedControls} controls` : "No active scope"}</strong><p>Approved evidence only</p></div></article>
      <article className="metric-card"><div className="metric-icon blue">▱</div><span>Approved evidence</span><strong>{approved} <small>/ {evidenceItems.length}</small></strong><p>{queue.length} awaiting action</p></article>
      <article className="metric-card"><div className="metric-icon violet">↻</div><span>Configured collectors</span><strong>{configuredCollectors} <small>/ {collectors.length}</small></strong><p>{runItems.filter((item) => item.status === "Partial" || item.status === "Failed").length} run issue(s)</p></article>
      <article className="metric-card"><div className="metric-icon amber">◇</div><span>Coverage gaps</span><strong>{Math.max(0, scopedControls - coveredControls)}</strong><p><em>Derived from active scope</em></p></article>
    </div>
    <div className="dashboard-grid">
      <section className="panel coverage-panel"><div className="panel-head"><div><h2>Control coverage</h2><p>PCI DSS 4.0.1 requirements in scope</p></div><button onClick={() => onNavigate("Controls")}>View controls →</button></div>
        <div className="coverage-list">{(assessment?.controls || []).slice(0, 12).map((controlId) => { const count = evidenceItems.filter((item) => item.control === controlId && item.status === "Approved").length; const value = count ? 100 : 0; return <div className="coverage-row" key={controlId}><span className="req-badge">{controlId}</span><div><strong>{controls.find((item) => item.id === controlId)?.title || "Scoped control"}</strong><div className="progress-line"><i style={{ width: `${value}%` }} /></div></div><b className={!value ? "low" : ""}>{value}%</b></div>; })}{!assessment?.controls.length && <EmptyState message="No control list is defined for the active assessment." />}</div>
      </section>
      <section className="panel activity-panel"><div className="panel-head"><div><h2>Collection activity</h2><p>Latest automation runs</p></div><button onClick={() => onNavigate("Collection runs")}>View all →</button></div>
        <div className="activity-list">{runItems.slice(0, 4).map((run) => <div className="activity-item" key={run.id}><div className={cls("source-dot", run.status.toLowerCase())}>{run.source.slice(0, 2).toUpperCase()}</div><div><strong>{run.source}</strong><span>{run.artifacts ? `${run.artifacts} artifacts · ` : ""}{run.startedAt}</span></div><StatusPill status={run.status} /></div>)}</div>
        <button className="full-button" disabled={!canCollect} title={!canCollect ? "Evidence-operations access is required." : undefined} onClick={onRun}>＋ Run a new collection</button>
      </section>
    </div>
    <section className="panel recent-panel"><div className="panel-head"><div><h2>Recent evidence</h2><p>New artifacts collected across your environment</p></div><button onClick={() => onNavigate("Evidence")}>View evidence library →</button></div>
      <div className="evidence-row">{evidenceItems.slice(0, 4).map((item) => <button className="evidence-card" key={item.id} onClick={() => onSelect(item)}><EvidenceVisual item={item} compact /><div className="evidence-card-body"><div><span className="type-label">{item.type}</span><StatusPill status={item.status} /></div><strong>{item.title}</strong><p><b>{item.control}</b> · {item.source}</p><small>{item.capturedAt}</small></div></button>)}</div>
    </section>
  </>;
}

function ControlsView({ evidenceItems, onNavigate }: { evidenceItems: Evidence[]; onNavigate: (view: View) => void }) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("All");
  const liveControls = controls.map((control) => { const related = evidenceItems.filter((item) => item.control === control.id); const approved = related.filter((item) => item.status === "Approved").length; return { ...control, evidenceCount: related.length, status: approved ? "Covered" : related.length ? "Partial" : "Gap", automation: related.length ? Math.round(related.filter((item) => item.collector !== "Manual submission").length / related.length * 100) : 0, nextDue: related.map((item) => item.expiresAt).sort()[0] || "No evidence" }; });
  const items = liveControls.filter((control) => (!query || `${control.id} ${control.title} ${control.owner}`.toLowerCase().includes(query.toLowerCase())) && (filter === "All" || control.status === filter));
  const covered = liveControls.filter((item) => item.status === "Covered").length; const partial = liveControls.filter((item) => item.status === "Partial").length; const gaps = liveControls.filter((item) => item.status === "Gap").length;
  return <><PageTitle eyebrow="PCI DSS 4.0.1" title="Control workspace" description="Track coverage, ownership, and collection automation for every control in scope." actions={<button className="button primary" onClick={() => onNavigate("Evidence")}>Review evidence</button>} />
    <div className="summary-strip"><div><strong>{liveControls.length}</strong><span>Catalog controls</span></div><div><strong>{covered}</strong><span>Fully covered</span></div><div><strong>{partial}</strong><span>Partially covered</span></div><div><strong>{gaps}</strong><span>Evidence gaps</span></div></div>
    <section className="panel table-panel"><div className="toolbar"><label className="search-box"><span>⌕</span><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search control, owner, or requirement…" /></label><div className="segmented">{["All", "Covered", "Partial", "Gap"].map((item) => <button className={filter === item ? "active" : ""} key={item} onClick={() => setFilter(item)}>{item}</button>)}</div></div>
      {items.length ? <div className="data-table controls-table"><div className="table-header"><span>Control</span><span>Owner</span><span>Coverage</span><span>Automation</span><span>Next due</span><span /></div>{items.map((control) => <div className="table-row" key={control.id}><div><span className="control-id">{control.id}</span><strong>{control.title}</strong><small>{control.systems.join(" · ")}</small></div><span>{control.owner}</span><div><StatusPill status={control.status} /><small>{control.evidenceCount} artifacts</small></div><div className="automation-cell"><strong>{control.automation}%</strong><div><i style={{ width: `${control.automation}%` }} /></div></div><span className={control.nextDue === "Overdue" ? "danger-text" : ""}>{control.nextDue}</span><button aria-label={`View control ${control.id}`} onClick={() => onNavigate("Evidence")}>→</button></div>)}</div> : <EmptyState message="Try a different control search or coverage filter." />}
    </section>
  </>;
}

function EvidenceView({ items, canCollect, search, setSearch, status, setStatus, type, setType, onSelect, onAdd }: { items: Evidence[]; canCollect: boolean; search: string; setSearch: (v: string) => void; status: string; setStatus: (v: string) => void; type: string; setType: (v: string) => void; onSelect: (item: Evidence) => void; onAdd: () => void }) {
  return <><PageTitle eyebrow="Evidence library" title="Collected evidence" description="Review, validate, and trace every artifact back to its source and PCI requirement." actions={<button className="button primary" disabled={!canCollect} title={!canCollect ? "Evidence-operations access is required." : undefined} onClick={onAdd}>＋ Add evidence</button>} />
    <section className="panel evidence-library"><div className="toolbar"><label className="search-box wide"><span>⌕</span><input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search evidence, control, system, or tag…" /></label><select aria-label="Filter by evidence type" value={type} onChange={(e) => setType(e.target.value)}><option>All types</option><option>Screenshot</option><option>Code</option><option>Configuration</option><option>Report</option></select><select aria-label="Filter by review status" value={status} onChange={(e) => setStatus(e.target.value)}><option>All statuses</option><option>Approved</option><option>Needs review</option><option>Expiring</option><option>Expired</option><option>Failed</option></select></div>
      <div className="library-subhead"><span>{items.length} artifacts</span><span>Sorted by <b>most recent</b></span></div>
      {items.length ? <div className="library-grid">{items.map((item) => <button className="library-card" key={item.id} onClick={() => onSelect(item)}><EvidenceVisual item={item} /><div className="library-body"><div><span className="type-label">{item.type}</span><StatusPill status={item.status} /></div><h3>{item.title}</h3><p>{item.description}</p><div className="artifact-meta"><span><b>{item.control}</b> · {item.requirement}</span><span>{item.source} / {item.system}</span><span>{item.lastObservedAt || item.capturedAt}{(item.occurrenceCount || 1) > 1 ? ` · ${item.occurrenceCount} observations` : ""}</span></div></div></button>)}</div> : <EmptyState message="No evidence matches these filters." action="Clear filters" onAction={() => { setSearch(""); setStatus("All statuses"); setType("All types"); }} />}
    </section>
  </>;
}

function SbomView({ items, configured, managedError, canGenerate, onGenerate, onOpenEvidence }: { items: ApiSbom[]; configured: boolean; managedError: string | null; canGenerate: boolean; onGenerate: () => void; onOpenEvidence: (id: string) => void }) {
  const complete = items.filter((item) => item.status === "completed");
  const latest = complete[0];
  return <>
    <PageTitle eyebrow="Software supply chain" title="SBOM workspace" description="Generate auditor-ready software inventories from an immutable GitHub commit without executing repository code." actions={<button className="button primary" disabled={!canGenerate} title={!canGenerate ? "An active assessment and SBOM permission are required." : undefined} onClick={onGenerate}>＋ Generate SBOM</button>} />
    {!configured && <div className="connection-alert optional"><span>i</span><div><strong>{managedError ? "Managed GitHub connection needs attention" : "Managed GitHub connection is optional"}</strong><p>{managedError ? `${managedError} One-time generation remains available.` : "Generate a one-time SBOM with an exact GitHub repository URL and short-lived read-only token. Scopeproof does not save that token."}</p></div></div>}
    <div className="summary-strip sbom-summary"><div><strong>{complete.length}</strong><span>Completed inventories</span></div><div><strong>{new Set(complete.map((item) => item.repository_full_name)).size}</strong><span>Repositories inventoried</span></div><div><strong>{latest?.component_count || 0}</strong><span>Components in latest</span></div><div><strong>{items.filter((item) => item.status === "failed" || item.status === "retrying").length}</strong><span>Jobs needing attention</span></div></div>
    <div className="info-callout"><span>i</span><div><strong>Auditable by design</strong><p>Every run records the requested ref, resolved 40-character commit SHA, source archive hash, generator version, parsed manifests, artifact hash, and differences from the prior inventory.</p></div></div>
    <section className="panel sbom-panel"><div className="panel-head"><div><h2>Generated inventories</h2><p>CycloneDX 1.6 and SPDX 2.3 evidence mapped to PCI DSS 6.3.2</p></div></div>
      {items.length ? <div className="sbom-list">{items.map((item) => { const delta = item.comparison || {}; return <article className="sbom-row" key={item.id}>
        <div className="sbom-icon">{item.format === "spdx_json" ? "SP" : "CX"}</div>
        <div className="sbom-main"><div><strong>{item.repository_full_name}</strong><StatusPill status={titleCase(item.status)} /></div><p><code>{item.resolved_commit_sha ? item.resolved_commit_sha.slice(0, 12) : item.requested_ref}</code> · {item.format === "spdx_json" ? "SPDX 2.3 JSON" : "CycloneDX 1.6 JSON"} · {formatDate(item.created_at)}</p>{item.error_message && <small className="danger-text">{item.error_message}</small>}</div>
        <dl><div><dt>Components</dt><dd>{item.component_count}</dd></div><div><dt>Direct</dt><dd>{item.direct_dependency_count}</dd></div><div><dt>Manifests</dt><dd>{item.manifest_count}</dd></div></dl>
        <div className="sbom-delta"><span className={delta.baseline ? "neutral" : "added"}>+{delta.added || 0}</span><span className={delta.baseline ? "neutral" : "changed"}>~{delta.changed || 0}</span><span className={delta.baseline ? "neutral" : "removed"}>−{delta.removed || 0}</span><small>{delta.baseline ? "Baseline" : "Since prior"}</small></div>
        <div className="sbom-actions">{item.evidence_id && <><button className="button secondary" onClick={() => onOpenEvidence(item.evidence_id!)}>Review</button><a className="button secondary" href={`/api/evidence/${encodeURIComponent(item.evidence_id)}`} download>↓ JSON</a></>}</div>
      </article>; })}</div> : <EmptyState message={configured ? "No SBOM has been generated for this assessment. Create a baseline from a managed or one-time GitHub repository." : "Generate a one-time inventory with a repository URL and short-lived token."} action={canGenerate ? "Generate baseline" : undefined} onAction={canGenerate ? onGenerate : undefined} />}
    </section>
  </>;
}

function RunsView({ items, canCollect, onRun, onToast }: { items: CollectionRun[]; canCollect: boolean; onRun: () => void; onToast: (message: string) => void }) {
  return <><PageTitle eyebrow="Automation" title="Collection runs" description="Monitor scheduled and on-demand collectors, captured artifacts, and failures." actions={<button className="button primary" disabled={!canCollect} title={!canCollect ? "Evidence-operations access is required." : undefined} onClick={onRun}>＋ Run collection</button>} />
    {items[0]?.status === "Running" && <div className="running-banner"><span className="spinner" /><div><strong>Collection in progress</strong><p>Authenticating sources and capturing evidence. You can safely leave this page.</p></div><b>Running</b></div>}
    <section className="panel table-panel"><div className="panel-head padded"><div><h2>Run history</h2><p>90-day operational record</p></div><select aria-label="Filter run history"><option>All sources</option><option>AWS</option><option>GitHub</option><option>Okta</option></select></div>
      <div className="data-table runs-table"><div className="table-header"><span>Run</span><span>Status</span><span>Artifacts</span><span>Controls</span><span>Duration</span><span /></div>{items.map((run) => <div className="table-row" key={run.id}><div><strong>{run.source}</strong><small>{run.id} · {run.startedAt}</small></div><div><StatusPill status={run.status} />{run.note && <small>{run.note}</small>}</div><strong>{run.artifacts || "—"}</strong><span>{run.controls || "—"}</span><span>{run.duration}</span><button aria-label={`More options for ${run.id}`} onClick={() => onToast(`${run.id} log and artifact manifest opened.`)}>•••</button></div>)}</div>
    </section>
    <div className="info-callout"><span>i</span><div><strong>Evidence integrity is preserved automatically</strong><p>Every artifact receives a SHA-256 checksum, source timestamp, collector identity, and immutable audit event.</p></div></div>
  </>;
}

function FindingsView({ evidenceItems, runItems }: { evidenceItems: Evidence[]; runItems: CollectionRun[] }) {
  const items = [
    ...evidenceItems.filter((item) => item.status !== "Approved").map((item) => ({ id: `evidence:${item.id}`, severity: item.status === "Failed" ? "High" : item.status === "Expiring" ? "Medium" : "Low", title: `${item.status}: ${item.title}`, control: item.control, owner: item.owner || "Unassigned", due: item.expiresAt, status: "Open" })),
    ...runItems.filter((item) => item.status === "Failed" || item.status === "Partial").map((item) => ({ id: `run:${item.id}`, severity: item.status === "Failed" ? "High" : "Medium", title: `${item.status} collection: ${item.source}`, control: "Collector", owner: "Compliance operations", due: "Investigate now", status: "Open" })),
  ];
  const high = items.filter((item) => item.severity === "High").length; const medium = items.filter((item) => item.severity === "Medium").length; const low = items.filter((item) => item.severity === "Low").length;
  return <><PageTitle eyebrow="Remediation" title="Findings" description="Resolve evidence gaps and collection failures before they become assessment exceptions." />
    <div className="finding-stats"><article><span className="severity-dot high" /><strong>{high}</strong><p>High severity</p></article><article><span className="severity-dot medium" /><strong>{medium}</strong><p>Medium severity</p></article><article><span className="severity-dot low" /><strong>{low}</strong><p>Low severity</p></article><article><strong>{items.length}</strong><p>Authoritative open items</p></article></div>
    <section className="panel finding-list"><div className="panel-head padded"><div><h2>Active findings</h2><p>Derived from evidence and collection state</p></div></div>{items.length ? items.map((item) => <div className="finding-row" key={item.id}><span className={`severity-flag ${item.severity.toLowerCase()}`}>{item.severity}</span><div><strong>{item.title}</strong><p>{item.id} · Control {item.control}</p></div><div><small>Owner</small><span>{item.owner}</span></div><div><small>Due</small><span>{item.due}</span></div><StatusPill status={item.status} /></div>) : <EmptyState message="No evidence or collection exceptions are currently recorded." />}</section>
  </>;
}

function ConnectionsView({ collectors, devices, jira, canManageJira, busy, onConnectJira, onTestJira, onDisconnectJira, onEnroll, onRotate, onRevoke, onToast }: { collectors: ApiCollector[]; devices: ApiDevice[]; jira: ApiJiraConnection | null; canManageJira: boolean; busy: boolean; onConnectJira: (event: React.FormEvent<HTMLFormElement>) => void; onTestJira: () => void; onDisconnectJira: () => void; onEnroll: () => void; onRotate: (id: string) => void; onRevoke: (id: string) => void; onToast: (message: string) => void }) {
  const cards = sources.map((source) => {
    const collector = collectors.find((item) => item.id === source.id);
    return { ...source, status: collector?.configuration.configured ? titleCase(collector.status) : "Not configured", detail: collector?.configuration.configured ? source.detail : `Missing ${collector?.configuration.missing.join(", ") || "hosted secrets"}`, lastRun: collector?.last_run_at ? formatDate(collector.last_run_at) : "Never", error: collector?.last_error };
  });
  const attention = cards.filter((card) => card.status !== "Healthy");
  return <><PageTitle eyebrow="Data sources" title="Connections" description="Manage the systems Scopeproof uses to collect trustworthy compliance evidence." actions={<button className="button primary" onClick={() => onToast("Add provider credentials as encrypted hosted environment variables; they are never stored in the application database.")}>＋ Configure source</button>} />
    {attention.length > 0 && <div className="connection-alert"><span>!</span><div><strong>{attention.length} collector{attention.length === 1 ? "" : "s"} need configuration</strong><p>Provider credentials are missing or the latest live API call failed. Scheduled collection remains paused for affected sources.</p></div><button onClick={() => onToast("Open hosted environment settings to add the missing secret values from .env.example.")}>Configuration guide</button></div>}
    <div className="connections-grid">{cards.map((source) => <article className="connection-card" key={source.name}><div className="connection-head"><span>{source.mark}</span><button aria-label={`Options for ${source.name}`} onClick={() => onToast(`${source.name} runs ${collectors.find((item) => item.id === source.id)?.schedule_cron || "without a schedule"} in UTC.`)}>•••</button></div><h3>{source.name}</h3><p>{source.detail}</p><StatusPill status={source.status} /><div><span>Last successful run</span><b>{source.lastRun}</b></div><button onClick={() => onToast(source.status === "Healthy" ? `${source.name} is configured. Use Run collection to execute a live test.` : `${source.name}: ${source.error || source.detail}`)}>Inspect configuration</button></article>)}</div>
    <section className="panel jira-cloud-panel"><div className="panel-head"><div><h2>Jira Cloud</h2><p>OAuth connection used by enrolled Macs for explicit, approved evidence uploads</p></div>{jira?.connected ? <StatusPill status="Connected" /> : jira?.status === "reauthorization_required" ? <StatusPill status="Action needed" /> : <StatusPill status="Not connected" />}</div>
      {!canManageJira ? <div className="jira-access-note"><strong>Evidence-operations access required</strong><p>An administrator or compliance lead must connect Jira Cloud. Reviewers remain independent from collection and disclosure operations.</p></div> : jira?.connected ? <div className="jira-connected"><div className="jira-site-mark">JI</div><div><strong>{jira.siteName}</strong><a href={jira.siteUrl} target="_blank" rel="noreferrer">{jira.siteUrl} ↗</a><small>Allowed projects: {jira.allowedProjects?.join(", ") || "None"} · {jira.lastTestedAt ? `Tested ${formatDate(jira.lastTestedAt)}` : "Not tested yet"}</small></div><div className="jira-actions"><button className="button secondary" disabled={busy} onClick={onTestJira}>{busy ? "Testing…" : "Test connection"}</button><button className="button secondary danger" disabled={busy} onClick={onDisconnectJira}>Disconnect</button></div></div> : <form className="jira-connect-form" onSubmit={onConnectJira}><label className="field"><span>Jira Cloud site URL</span><input name="siteUrl" type="url" required defaultValue={jira?.siteUrl || ""} placeholder="https://your-company.atlassian.net" autoComplete="url" /></label><label className="field"><span>Allowed project keys</span><input name="allowedProjects" required defaultValue={jira?.allowedProjects?.join(", ") || ""} placeholder="GRC, PCI" autoCapitalize="characters" /><small>Only these projects may receive evidence from Scopeproof.</small></label><div className="jira-connect-copy"><strong>Secure OAuth connection</strong><p>You will continue to Atlassian to choose the site and approve access. Scopeproof stores encrypted rotating tokens in the hosted service; Jira credentials never enter the Mac app.</p></div><button className="button primary" disabled={busy || jira?.configured === false}>{busy ? "Preparing Atlassian authorization…" : "Connect Jira Cloud"}</button>{jira?.configured === false && <p className="field-error">A platform administrator must configure the four JIRA_OAUTH_* hosted secrets first.</p>}</form>}
    </section>
    <section className="panel device-panel"><div className="panel-head"><div><h2>Mac capture devices</h2><p>Revocable device identities for locally reviewed screenshot uploads</p></div><button className="button primary" disabled={!canManageJira} title={!canManageJira ? "Evidence-operations access is required." : undefined} onClick={onEnroll}>＋ Enroll Mac</button></div>
      {!canManageJira ? <div className="jira-access-note"><strong>Independent reviewer boundary</strong><p>Reviewers can inspect and approve evidence but cannot enroll collection devices.</p></div> : devices.length ? <div className="device-list">{devices.map((device) => { const expired = Boolean(device.token_expired); return <div className="device-row" key={device.id}><span className="device-icon">⌘</span><div><strong>{device.display_name}</strong><small>{device.platform} · {device.app_version ? `v${device.app_version}` : "Not connected yet"} · {device.last_seen_at ? `Seen ${formatDate(device.last_seen_at)}` : "Awaiting first upload"}</small><small className={expired ? "danger-text" : undefined}>Token {expired ? "expired" : `expires ${formatDate(device.token_expires_at)}`}{device.token_last_rotated_at ? ` · Rotated ${formatDate(device.token_last_rotated_at)}` : ""}</small></div><StatusPill status={device.status === "active" && expired ? "Expired" : titleCase(device.status)} /><div className="device-actions"><button className="button secondary" disabled={busy || device.status === "revoked"} onClick={() => onRotate(device.id)}>Rotate</button><button className="button secondary danger" disabled={busy || device.status === "revoked"} onClick={() => onRevoke(device.id)}>{device.status === "revoked" ? "Revoked" : "Revoke"}</button></div></div>; })}</div> : <EmptyState message="No Mac capture devices are enrolled. Create a one-time token, then paste it into Scopeproof Capture & Jira Settings." action="Enroll first Mac" onAction={onEnroll} />}
    </section>
  </>;
}

function SettingsView({ auditIntegrity, currentUser, onToast }: { auditIntegrity: { valid: boolean; checked: number } | null; currentUser: ApiUser | null; onToast: (message: string) => void }) {
  const [tab, setTab] = useState<"policy" | "team" | "audit">("policy");
  const [members, setMembers] = useState<ApiMember[]>([]);
  const [invitations, setInvitations] = useState<ApiInvitation[]>([]);
  const [auditEvents, setAuditEvents] = useState<ApiAuditEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [working, setWorking] = useState(false);
  const canReadTeam = ["admin", "compliance_lead"].includes(currentUser?.role || "");
  const canManageTeam = currentUser?.role === "admin";

  async function loadTeam() {
    if (!canReadTeam) return;
    setLoading(true);
    try {
      const response = await fetch("/api/users", { cache: "no-store" });
      if (!response.ok) throw new Error(await apiError(response));
      const data = await response.json() as { users: ApiMember[]; invitations: ApiInvitation[] };
      setMembers(data.users); setInvitations(data.invitations);
    } catch (error) { onToast(error instanceof Error ? error.message : "Team access could not be loaded."); }
    finally { setLoading(false); }
  }

  async function openTeam() {
    setTab("team");
    if (!members.length) await loadTeam();
  }

  async function openAudit() {
    setTab("audit");
    if (auditEvents.length) return;
    setLoading(true);
    try {
      const response = await fetch("/api/audit", { cache: "no-store" });
      if (!response.ok) throw new Error(await apiError(response));
      const data = await response.json() as { events: ApiAuditEvent[] };
      setAuditEvents(data.events);
    } catch (error) { onToast(error instanceof Error ? error.message : "Audit events could not be loaded."); }
    finally { setLoading(false); }
  }

  async function inviteMember(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    setWorking(true);
    try {
      const response = await fetch("/api/users", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: values.get("email"), role: values.get("role"), expiresInDays: Number(values.get("expiresInDays")) }) });
      if (!response.ok) throw new Error(await apiError(response));
      form.reset(); await loadTeam(); onToast("Invitation created. Access begins only after the invited identity signs in before expiration.");
    } catch (error) { onToast(error instanceof Error ? error.message : "Invitation could not be created."); }
    finally { setWorking(false); }
  }

  async function changeMember(member: ApiMember, patch: { role?: string; status?: string }) {
    const change = patch.role ? `change ${member.email} to ${patch.role.replaceAll("_", " ")}` : `${patch.status} ${member.email}`;
    if (!window.confirm(`Confirm: ${change}? Queued collection and SBOM retries re-check this membership.`)) return;
    setWorking(true);
    try {
      const response = await fetch("/api/users", { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ userId: member.id, ...patch }) });
      if (!response.ok) throw new Error(await apiError(response));
      await loadTeam(); onToast(`Membership updated for ${member.email}.`);
    } catch (error) { onToast(error instanceof Error ? error.message : "Membership could not be updated."); }
    finally { setWorking(false); }
  }

  async function revokeInvitation(invitation: ApiInvitation) {
    if (!window.confirm(`Revoke the pending invitation for ${invitation.email}?`)) return;
    setWorking(true);
    try {
      const response = await fetch("/api/users", { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ invitationId: invitation.id }) });
      if (!response.ok) throw new Error(await apiError(response));
      await loadTeam(); onToast(`Invitation revoked for ${invitation.email}.`);
    } catch (error) { onToast(error instanceof Error ? error.message : "Invitation could not be revoked."); }
    finally { setWorking(false); }
  }

  return <><PageTitle eyebrow="Workspace" title="Settings" description="Inspect enforced evidence policy, manage membership, and verify the audit record." />
    <div className="settings-layout"><nav aria-label="Settings sections"><button className={tab === "policy" ? "active" : ""} onClick={() => setTab("policy")}>Evidence policy</button><button className={tab === "team" ? "active" : ""} onClick={() => void openTeam()}>Team & access</button><button className={tab === "audit" ? "active" : ""} onClick={() => void openAudit()}>Audit log</button></nav>
      {tab === "policy" && <section className="panel settings-panel"><h2>Evidence policy</h2><p>These are enforced server-side and cannot be weakened from the browser.</p><div className="integrity-setting"><span>{auditIntegrity?.valid ? "✓" : "↻"}</span><div><strong>{auditIntegrity?.valid ? "Tamper-evident audit tail verified" : "Audit verification pending"}</strong><p>{auditIntegrity?.valid ? `${auditIntegrity.checked} event(s) verified from the latest signed checkpoint.` : "Production readiness fails until the chain and independent checkpoint verify."}</p></div></div><div className="setting-row"><div><strong>Sensitive-data redaction</strong><span>Luhn-validated PAN, access tokens, API secrets, JWTs, private keys, and authorization headers are scanned before encryption. Screenshot approval additionally requires digest-bound exact-pixel scan metadata.</span></div><StatusPill status="Enforced" /></div><div className="setting-row"><div><strong>Evidence validity</strong><span>New evidence defaults to 90 days. Expired evidence cannot be approved or exported as current.</span></div><strong>90 days</strong></div><div className="setting-row"><div><strong>Retention and holds</strong><span>Expired bytes are retained while their assessment is draft or active, or while an explicit retention hold remains valid. Purge actions and failures are audited.</span></div><StatusPill status="Fail closed" /></div><div className="setting-row"><div><strong>Tenant boundary</strong><span>The legacy hosted runtime accepts exactly one canonical origin and one isolated D1/R2/key boundary. Multi-customer operation requires the tenant-aware AWS runtime.</span></div><StatusPill status="Single tenant" /></div></section>}
      {tab === "team" && <section className="panel settings-panel"><h2>Team & access</h2><p>Invitation-only membership with server-enforced roles, suspension, revocation, and final-administrator protection.</p>{!canReadTeam ? <div className="jira-access-note"><strong>Your role is {currentUser?.role?.replaceAll("_", " ") || "unknown"}</strong><p>An administrator or compliance lead can view membership. Only an administrator can invite people or change access.</p></div> : <>{canManageTeam && <form className="invite-form" onSubmit={inviteMember}><label className="field"><span>Email address</span><input name="email" type="email" required maxLength={254} autoComplete="off" placeholder="reviewer@example.com" /></label><label className="field"><span>Role</span><select name="role" defaultValue="auditor"><option value="auditor">Auditor</option><option value="reviewer">Reviewer</option><option value="compliance_lead">Compliance lead</option><option value="admin">Administrator</option></select></label><label className="field"><span>Expires</span><select name="expiresInDays" defaultValue="7"><option value="1">1 day</option><option value="7">7 days</option><option value="14">14 days</option><option value="30">30 days</option></select></label><button className="button primary" disabled={working}>Create invitation</button></form>}{loading ? <div className="artifact-state">Loading membership…</div> : <div className="member-list">{members.map((member) => <div className="member-row" key={member.id}><div><strong>{member.display_name || member.email}</strong><small>{member.email} · Last seen {formatDate(member.last_seen_at)}</small></div>{canManageTeam ? <select aria-label={`Role for ${member.email}`} value={member.role} disabled={working || member.status !== "active"} onChange={(event) => void changeMember(member, { role: event.target.value })}><option value="auditor">Auditor</option><option value="reviewer">Reviewer</option><option value="compliance_lead">Compliance lead</option><option value="admin">Administrator</option></select> : <span>{titleCase(member.role)}</span>}<StatusPill status={titleCase(member.status)} />{canManageTeam && <div className="member-actions"><button className="button secondary" disabled={working || member.status === "revoked"} onClick={() => void changeMember(member, { status: member.status === "active" ? "suspended" : "active" })}>{member.status === "active" ? "Suspend" : "Activate"}</button><button className="button secondary danger" disabled={working || member.status === "revoked" || member.id === currentUser?.id} onClick={() => void changeMember(member, { status: "revoked" })}>Revoke</button></div>}</div>)}</div>}{canManageTeam && invitations.filter((item) => item.status === "pending").length > 0 && <div className="pending-invitations"><h3>Pending invitations</h3>{invitations.filter((item) => item.status === "pending").map((invitation) => <div key={invitation.id}><span><strong>{invitation.email}</strong><small>{titleCase(invitation.role)} · Expires {formatDate(invitation.expires_at)}</small></span><button className="button secondary danger" disabled={working} onClick={() => void revokeInvitation(invitation)}>Revoke</button></div>)}</div>}</>}</section>}
      {tab === "audit" && <section className="panel settings-panel"><h2>Audit log</h2><p>The newest 250 material actions. Integrity is verified from the latest signed external checkpoint through the current tail.</p><div className="integrity-setting"><span>{auditIntegrity?.valid ? "✓" : "!"}</span><div><strong>{auditIntegrity?.valid ? "Audit verification passed" : "Audit verification has not passed"}</strong><p>{auditIntegrity ? `${auditIntegrity.checked} total event(s) covered by the verified chain.` : "Reload after protected services recover."}</p></div></div>{loading ? <div className="artifact-state">Loading audited actions…</div> : auditEvents.length ? <div className="audit-event-list">{auditEvents.map((event) => <div key={event.id}><span>{event.sequence}</span><div><strong>{event.action.replaceAll("_", " ")}</strong><small>{event.actor_email} · {event.resource_type}:{event.resource_id}</small></div><time dateTime={event.occurred_at}>{formatDate(event.occurred_at)}</time><code>{event.event_hash.slice(0, 12)}</code></div>)}</div> : <EmptyState message="No audit events are available yet." />}</section>}
    </div>
  </>;
}

function HelpView({ onNavigate }: { onNavigate: (view: View) => void }) {
  return <><PageTitle eyebrow="Product guide" title="Help & how to use Scopeproof" description="Follow the evidence lifecycle from a live source to a signed assessor package." />
    <section className="help-steps" aria-label="Evidence workflow">
      {[['1', 'Connect sources', 'Configure least-privilege provider credentials or enroll a Mac capture device.', 'Connections'], ['2', 'Collect safely', 'Run an API collector or review a locally scanned screenshot before it enters Scopeproof.', 'Collection runs'], ['3', 'Review evidence', 'Confirm control mapping, scope, freshness, redactions, and integrity before approval.', 'Evidence'], ['4', 'Export for assessment', 'Generate a signed ZIP with embedded artifacts, a PDF index, hashes, and verification material.', 'Overview']].map(([number, title, copy, destination]) => <article key={number}><span>{number}</span><div><h2>{title}</h2><p>{copy}</p><button onClick={() => onNavigate(destination as View)}>Open {destination} →</button></div></article>)}
    </section>
    <div className="help-grid">
      <section className="panel help-panel"><h2>Mac screenshot quick start</h2><ol><li>Open <strong>Connections</strong>, enroll a Mac, and copy the one-time token.</li><li>In the Scopeproof shield menu, open <strong>Capture & Jira Settings</strong>; enter this workspace’s HTTPS URL and token.</li><li>Select PCI DSS, HIPAA, FedRAMP, SOC 2, ISO 27001, or an imported catalog; then choose the control, system, owner, period, evidence title, and optional Jira issue.</li><li>Select an exact window. Scopeproof runs local OCR, masks PANs and credentials, lets you add manual redactions, stamps the image, and shows a preview.</li><li>Use <strong>Search Evidence</strong> on the Mac to tag, review, approve, and copy a Jira-ready comment before building an assessor package.</li></ol><button className="button secondary" onClick={() => onNavigate('Connections')}>Manage capture devices</button></section>
      <section className="panel help-panel"><h2>Jira Cloud evidence handoff</h2><ol><li>Open <strong>Connections → Jira Cloud</strong>, enter the site and allowed projects, then authorize Scopeproof through Atlassian OAuth.</li><li>Assign the destination issue key during capture; it flows into the banner, filename, manifest, search, and package index.</li><li>Approve the evidence locally, upload those exact bytes to Scopeproof, and have an authenticated web reviewer approve the hosted artifact.</li><li>Select it in <strong>Search Evidence</strong> and explicitly choose <strong>Upload to Jira Cloud</strong>. Scopeproof verifies both approvals, the issue, project allowlist, PNG hash, redaction status, and lifecycle chain before sending the complete evidence set and recording a signed receipt.</li></ol><p>The manual Copy Jira Comment workflow remains available. Confirm ticket permissions, classification, and retention before disclosure.</p></section>
      <section className="panel help-panel"><h2>What proves integrity</h2><dl><div><dt>Visible stamp</dt><dd>Local date, time, timezone, control, system, environment, period, and evidence ID.</dd></div><div><dt>Local manifest</dt><dd>PNG SHA-256, source metadata, redaction counts, and previous/current chain hashes.</dd></div><div><dt>Server receipt</dt><dd>Signed server time, device identity, audit event, and optional RFC 3161 timestamp token.</dd></div><div><dt>Assessor package</dt><dd>ECDSA-signed manifest, public key, independent hashes, embedded evidence, and PDF index.</dd></div></dl></section>
      <section className="panel help-panel"><h2>Safety & privacy</h2><ul><li>Captured OCR text is processed on the Mac and is not retained.</li><li>Device tokens are shown once, hashed server-side, stored in Keychain, and revocable.</li><li>Artifacts are encrypted with AES-256-GCM before R2 persistence.</li><li>Every material action is written to a tamper-evident, append-only audit chain.</li><li>Scopeproof never captures the screen without an explicit menu action.</li></ul></section>
      <section className="panel help-panel"><h2>Troubleshooting</h2><dl><div><dt>Capture permission fails</dt><dd>Open the shield menu → Screen Recording Settings, enable Scopeproof Capture, then fully quit and reopen it.</dd></div><div><dt>Upload is pending</dt><dd>Confirm the HTTPS server URL and active device token, then choose Retry Pending Uploads.</dd></div><div><dt>A collector is paused</dt><dd>Open Connections and inspect its missing hosted secret or most recent provider error.</dd></div><div><dt>Evidence was blocked</dt><dd>Remove cardholder data or credentials from the source and collect again; unsafe automated captures are not stored.</dd></div></dl></section>
    </div>
  </>;
}

function EvidenceDrawer({ item, currentUser, onClose, onApprove, onToast }: { item: Evidence; currentUser: ApiUser | null; onClose: () => void; onApprove: (item: Evidence, rationale: string) => void; onToast: (message: string) => void }) {
  const [artifact, setArtifact] = useState<{ state: "loading" | "ready" | "error"; url?: string; text?: string; error?: string }>({ state: "loading" });
  const [rationale, setRationale] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  useEffect(() => {
    let cancelled = false;
    let objectUrl: string | undefined;
    void fetch(`/api/evidence/${encodeURIComponent(item.id)}?view=inline`, { cache: "no-store" }).then(async (response) => {
      if (!response.ok) throw new Error(await apiError(response));
      const serverDigest = response.headers.get("x-scopeproof-sha256");
      if (!item.sha256 || serverDigest !== item.sha256) throw new Error("The server returned an unexpected artifact digest.");
      const blob = await response.blob();
      if (cancelled) return;
      if (item.type === "Screenshot") {
        objectUrl = URL.createObjectURL(blob);
        setArtifact({ state: "ready", url: objectUrl });
      } else {
        const value = await blob.text();
        if (!cancelled) setArtifact({ state: "ready", text: value.slice(0, 1_000_000) });
      }
    }).catch((error) => { if (!cancelled) setArtifact({ state: "error", error: error instanceof Error ? error.message : "Artifact could not be loaded." }); });
    return () => { cancelled = true; if (objectUrl) URL.revokeObjectURL(objectUrl); };
  }, [item.id, item.sha256, item.type]);
  const roleMayApprove = currentUser ? ["reviewer", "admin"].includes(currentUser.role) : false;
  const independentReviewer = Boolean(currentUser && item.createdBy && currentUser.id !== item.createdBy);
  const serverSafetyReady = item.type !== "Screenshot" || item.serverSafetyStatus === "verified";
  const nativeProvenanceReady = item.nativeProvenanceStatus !== "pending";
  const canApprove = roleMayApprove && independentReviewer && serverSafetyReady && nativeProvenanceReady && artifact.state === "ready" && confirmed && rationale.trim().length >= 20 && item.status !== "Approved";
  return <>
    <button className="drawer-scrim" aria-label="Close evidence details" onClick={onClose} />
    <aside className="drawer" aria-label="Evidence details">
      <div className="drawer-head"><div><span>{item.id}</span><StatusPill status={item.status} /></div><button aria-label="Close evidence details" onClick={onClose}>×</button></div>
      <div className="drawer-scroll">
        <span className="eyebrow">{item.type} evidence</span><h2>{item.title}</h2><p className="drawer-description">{item.description}</p>
        <div className="actual-evidence" aria-live="polite">
          {artifact.state === "loading" ? <div className="artifact-state">Decrypting and verifying the actual artifact…</div> : artifact.state === "error" ? <div className="artifact-state error">{artifact.error}</div> : item.type === "Screenshot" && artifact.url ? <Image src={artifact.url} alt={`Actual evidence artifact for ${item.title}`} width={1600} height={900} unoptimized /> : <pre>{artifact.text}</pre>}
        </div>
        <div className={cls("integrity-banner", artifact.state !== "ready" && "pending")}><span>{artifact.state === "ready" ? "✓" : "↻"}</span><div><strong>{artifact.state === "ready" ? "Stored bytes decrypted and digest verified" : "Artifact verification required"}</strong><p>{item.checksum}</p></div></div>
        <section className="detail-section"><h3>Evidence mapping</h3><dl><div><dt>Compliance control</dt><dd>{item.framework || item.requirement} · {item.control}</dd></div>{item.jiraIssueKey ? <div><dt>Jira issue</dt><dd>{item.jiraIssueURL ? <a href={item.jiraIssueURL} target="_blank" rel="noreferrer">{item.jiraIssueKey} ↗</a> : item.jiraIssueKey}</dd></div> : null}<div><dt>Source</dt><dd>{item.source} / {item.system}</dd></div><div><dt>Owner</dt><dd>{item.owner || "Unassigned"}</dd></div><div><dt>Scope</dt><dd>{item.environment || "Unspecified"} · {item.assessmentPeriod || "Unspecified"}</dd></div><div><dt>First captured</dt><dd>{item.capturedAt}</dd></div><div><dt>Last observed</dt><dd>{item.lastObservedAt || item.capturedAt} · {item.occurrenceCount || 1} occurrence(s)</dd></div><div><dt>Valid until</dt><dd>{item.expiresAt}</dd></div><div><dt>Collector</dt><dd>{item.collector}</dd></div></dl></section>
        {item.mappedControls?.length ? <section className="detail-section"><h3>Related controls</h3><div className="tag-row">{item.mappedControls.map((mapping) => <span key={`${mapping.framework}-${mapping.controlID}`}>{mapping.framework} · {mapping.controlID}</span>)}</div></section> : null}
        <section className="detail-section"><h3>Safety and provenance</h3>
          {item.type === "Screenshot" ? <div className={cls("check-row", !serverSafetyReady && "warning")}><span>{serverSafetyReady ? "✓" : "!"}</span><div><strong>{serverSafetyReady ? "Independent server safety receipt verified" : "Screenshot is quarantined"}</strong><p>{serverSafetyReady ? "The stored screenshot digest is bound to the server-side OCR/DLP policy receipt. Scan results are supporting claims, not a substitute for reviewer inspection, because OCR can miss sensitive pixels." : "This legacy or incomplete screenshot cannot be opened, approved, packaged, or disclosed. Recollect browser evidence or retry the original Mac upload."}</p></div></div> : null}
          {item.nativeProvenanceStatus !== "not_applicable" ? <div className={cls("check-row", !nativeProvenanceReady && "warning")}><span>{nativeProvenanceReady ? "✓" : "!"}</span><div><strong>{nativeProvenanceReady ? "Signed device chain finalized" : "Device provenance is pending"}</strong><p>{nativeProvenanceReady ? "The exact manifest and image digest are linked to the server-maintained monotonic device chain." : "Retry the exact original Mac upload. Scopeproof does not grandfather or manually promote unlinked native evidence."}</p></div></div> : null}
          {item.type !== "Screenshot" ? <div className="check-row"><span>i</span><div><strong>Server redaction completed before encryption</strong><p>Inspect the actual text above. Pattern matching supports—but does not replace—reviewer judgment.</p></div></div> : null}
        </section>
        <section className="detail-section"><h3>Tags</h3><div className="tag-row">{item.tags.map((tag) => <span key={tag}>{tag}</span>)}</div></section>
        {item.status !== "Approved" && <section className="detail-section review-attestation"><h3>Independent review attestation</h3>{!roleMayApprove ? <p className="review-blocked">A reviewer or administrator role is required to approve evidence.</p> : !independentReviewer ? <p className="review-blocked">You collected or uploaded this artifact. A different reviewer must approve it.</p> : <><label className="field"><span>Review rationale</span><textarea value={rationale} onChange={(event) => setRationale(event.target.value)} minLength={20} maxLength={1000} rows={4} placeholder="Explain what you inspected, what this proves, and why the scope and redactions are acceptable." /></label><label className="checkbox-line"><input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.target.checked)} /> I inspected the actual artifact above, confirmed its digest, scope, freshness, and redactions, and understand this approval is audited.</label></>}</section>}
      </div>
      <div className="drawer-actions"><button className="button secondary" onClick={() => onToast(`${item.id} flagged for follow-up.`)}>Flag issue</button><button className="button primary" disabled={!canApprove} onClick={() => onApprove(item, rationale.trim())}>{item.status === "Approved" ? "✓ Approved" : !serverSafetyReady || !nativeProvenanceReady ? "Quarantined" : artifact.state !== "ready" ? "Verify artifact first" : "Approve evidence"}</button></div>
    </aside>
  </>;
}

function Modal({ type, collectors, repositories, assessments, selectedAssessmentId, setSelectedAssessmentId, deviceToken, onClose, onRun, onSbom, onAdd, onExport, onDevice, onAssessment, busy }: { type: Exclude<Modal, null>; collectors: ApiCollector[]; repositories: ApiRepository[]; assessments: ApiAssessment[]; selectedAssessmentId: string; setSelectedAssessmentId: (id: string) => void; deviceToken: string | null; onClose: () => void; onRun: (e: React.FormEvent<HTMLFormElement>) => void; onSbom: (e: React.FormEvent<HTMLFormElement>) => void; onAdd: (e: React.FormEvent<HTMLFormElement>) => void; onExport: () => void; onDevice: (e: React.FormEvent<HTMLFormElement>) => void; onAssessment: (e: React.FormEvent<HTMLFormElement>) => void; busy: boolean }) {
  const [sbomRepository, setSbomRepository] = useState(repositories.find((item) => !item.archived)?.name || "");
  const [sbomRef, setSbomRef] = useState(repositories.find((item) => !item.archived)?.defaultBranch || "main");
  const [sbomSourceMode, setSbomSourceMode] = useState<"managed" | "one_time">(repositories.length ? "managed" : "one_time");
  const titles = { run: "Run evidence collection", sbom: "Generate repository SBOM", add: "Add manual evidence", export: "Export evidence package", device: "Enroll Mac capture device", assessment: "Create assessment scope" };
  return <div className="modal-layer" role="dialog" aria-modal="true" aria-labelledby="modal-title"><button className="modal-scrim" onClick={onClose} aria-label="Close dialog" /><section className="modal"><div className="modal-head"><div><span className="eyebrow">Scopeproof</span><h2 id="modal-title">{titles[type]}</h2></div><button onClick={onClose} aria-label="Close dialog">×</button></div>
    {type === "run" && <form onSubmit={onRun}><p className="modal-intro">Select configured sources to query. Scope, pagination, omissions, and API versions are recorded with every artifact.</p><label className="field"><span>Assessment</span><select name="assessmentId" required value={selectedAssessmentId} onChange={(e) => setSelectedAssessmentId(e.target.value)}>{assessments.filter((item) => item.status === "active").map((item) => <option value={item.id} key={item.id}>{item.name} · {item.period_start}–{item.period_end}</option>)}</select></label><fieldset className="source-select"><legend>Live evidence sources</legend>{sources.map((source, index) => { const collector = collectors.find((item) => item.id === source.id); const configured = collector?.configuration.configured === true; return <label key={source.name} className={!configured ? "disabled" : ""}><input type="checkbox" name="source" value={source.id} defaultChecked={configured && index < 3} disabled={!configured} /><span>{source.mark}</span><div><strong>{source.name}</strong><small>{configured ? `${source.detail} · ${collector?.schedule_cron || "On demand"} UTC` : `Missing ${collector?.configuration.missing.join(", ") || "hosted credentials"}`}</small></div></label>; })}</fieldset><label className="checkbox-line"><input type="checkbox" checked readOnly /> Block approval and export when provider coverage is partial</label><div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={busy || !selectedAssessmentId}>{busy ? <><span className="button-spinner" /> Collecting live evidence…</> : "Start live collection"}</button></div></form>}
    {type === "sbom" && <form onSubmit={onSbom} autoComplete="off">
      <p className="modal-intro">Scopeproof resolves the selected ref to an immutable Git commit, downloads a bounded ZIP, and parses supported lockfiles. Build scripts, package managers, hooks, and repository code are never executed.</p>
      <input type="hidden" name="sourceMode" value={sbomSourceMode} />
      <fieldset className="credential-choice">
        <legend>Repository access</legend>
        <label className={repositories.length ? "" : "disabled"}>
          <input type="radio" aria-label="Managed organization" checked={sbomSourceMode === "managed"} onChange={() => setSbomSourceMode("managed")} disabled={!repositories.length} />
          <span><strong>Managed organization</strong><small>{repositories.length ? "Choose from the administrator-configured GitHub organization." : "No managed GitHub connection is configured."}</small></span>
        </label>
        <label>
          <input type="radio" aria-label="One-time repository" checked={sbomSourceMode === "one_time"} onChange={() => { setSbomSourceMode("one_time"); setSbomRef("main"); }} />
          <span><strong>One-time repository</strong><small>Paste one GitHub URL and a short-lived token for this run only.</small></span>
        </label>
      </fieldset>
      <div className="form-grid">
        <label className="field full"><span>Assessment</span><select name="assessmentId" required value={selectedAssessmentId} onChange={(event) => setSelectedAssessmentId(event.target.value)}>{assessments.filter((item) => item.status === "active").map((item) => <option value={item.id} key={item.id}>{item.name} · {item.framework}</option>)}</select></label>
        {sbomSourceMode === "managed" ? <label className="field full"><span>GitHub repository</span><select name="repository" required value={sbomRepository} onChange={(event) => { const repo = repositories.find((item) => item.name === event.target.value); setSbomRepository(event.target.value); if (repo) setSbomRef(repo.defaultBranch); }}><option value="" disabled>Select repository</option>{repositories.map((item) => <option value={item.name} key={item.fullName} disabled={item.archived}>{item.fullName}{item.private ? " · Private" : ""}{item.archived ? " · Archived" : ""}</option>)}</select></label> : <>
          <label className="field full"><span>GitHub repository URL</span><input name="repositoryUrl" type="url" required maxLength={300} inputMode="url" placeholder="https://github.com/owner/repository" autoCapitalize="none" autoCorrect="off" spellCheck={false} /><small>Exact HTTPS github.com URL only. Query strings, credentials in URLs, and non-GitHub hosts are rejected.</small></label>
          <label className="field full"><span>One-time GitHub token</span><input name="githubToken" type="password" required minLength={20} maxLength={512} autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} data-1p-ignore="true" data-lpignore="true" /><small>Use a repository-scoped token with Metadata: read and Contents: read. The field is cleared when submitted; Scopeproof never saves the token.</small></label>
        </>}
        <label className="field"><span>Branch, tag, or commit</span><input name="ref" required maxLength={200} value={sbomRef} onChange={(event) => setSbomRef(event.target.value)} autoCapitalize="none" autoCorrect="off" spellCheck={false} /></label>
        <label className="field"><span>Output format</span><select name="format" defaultValue="cyclonedx_json"><option value="cyclonedx_json">CycloneDX 1.6 JSON</option><option value="spdx_json">SPDX 2.3 JSON</option></select></label>
      </div>
      <div className="privacy-note"><span>✓</span><p>{sbomSourceMode === "one_time" ? "The token is used in memory for this request, is never written to Scopeproof storage or logs, and cannot be used for an automatic retry. Revoke it after the run." : "The generated file is encrypted, mapped to PCI DSS 6.3.2, independently reviewable, and eligible for the assessor package after approval."}</p></div>
      <div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={busy || !selectedAssessmentId || (sbomSourceMode === "managed" && !sbomRepository)}>{busy ? <><span className="button-spinner" /> Resolving and generating…</> : "Generate & add to evidence"}</button></div>
    </form>}
    {type === "add" && <form onSubmit={onAdd} className="evidence-form"><div className="form-grid"><label className="field full"><span>Assessment</span><select name="assessmentId" required value={selectedAssessmentId} onChange={(e) => setSelectedAssessmentId(e.target.value)}>{assessments.filter((item) => item.status !== "closed").map((item) => <option value={item.id} key={item.id}>{item.name}</option>)}</select></label><label className="field full"><span>Evidence title</span><input name="title" required placeholder="e.g. Production database encryption settings" /></label><label className="field"><span>Control</span><select name="control" required defaultValue=""><option value="" disabled>Select control</option>{controls.map((control) => <option key={control.id} value={control.id}>{control.id} — {control.title}</option>)}</select></label><label className="field"><span>Evidence type</span><select name="type"><option value="code">Code</option><option value="configuration">Configuration</option><option value="report">Text report</option></select></label><label className="field"><span>System or asset</span><input name="system" required placeholder="payments-production" /></label><label className="field"><span>Code language</span><select name="language"><option>Text</option><option>HCL</option><option>YAML</option><option>JSON</option><option>Shell</option><option>TypeScript</option></select></label><label className="field full"><span>Description</span><textarea name="description" rows={3} placeholder="What this evidence proves and where it came from" /></label><label className="field full"><span>Code or configuration excerpt</span><textarea name="code" className="mono-input" rows={5} required placeholder="# Paste the focused excerpt here; server-side redaction runs before encryption" /></label></div><div className="upload-zone"><span>↑</span><div><strong>Attach an optional text-based artifact</strong><p>TXT, JSON, XML, or YAML up to 10 MB</p></div><label className="choose-file">Choose file<input name="attachment" type="file" accept="text/*,application/json,application/xml,application/yaml" /></label></div><div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={busy || !selectedAssessmentId}>{busy ? "Encrypting…" : "Scan, encrypt & add"}</button></div></form>}
    {type === "export" && <div><p className="modal-intro">Generate a signed package for one explicit assessment. Scope and inclusion counts are bound into the manifest; truncation is forbidden.</p><label className="field"><span>Assessment</span><select required value={selectedAssessmentId} onChange={(e) => setSelectedAssessmentId(e.target.value)}>{assessments.filter((item) => item.status !== "draft").map((item) => <option value={item.id} key={item.id}>{item.name} · {item.framework}</option>)}</select></label><div className="export-summary"><div><span>▣</span><p><strong>{assessments.find((item) => item.id === selectedAssessmentId)?.name || "Select an assessment"}</strong><small>Approved, unexpired evidence with complete coverage only</small></p></div><StatusPill status={selectedAssessmentId ? "Ready" : "Blocked"} /></div><label className="checkbox-line"><input type="checkbox" checked readOnly /> Refuse partial or silently truncated evidence sets</label><label className="checkbox-line"><input type="checkbox" checked readOnly /> ECDSA-sign manifest and include public verification key</label><div className="privacy-note"><span>i</span><p>The package expires after seven days and every download is audited.</p></div><div className="modal-actions"><button className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={busy || !selectedAssessmentId} onClick={onExport}>{busy ? "Building signed package…" : "↓ Generate signed ZIP"}</button></div></div>}
    {type === "assessment" && <form onSubmit={onAssessment} className="evidence-form"><p className="modal-intro">Define the authoritative framework, period, systems, and controls before collecting evidence.</p><div className="form-grid"><label className="field full"><span>Assessment name</span><input name="name" required minLength={3} maxLength={180} placeholder="2026 PCI DSS annual assessment" /></label><label className="field"><span>Framework</span><select name="framework"><option>PCI DSS 4.0.1</option><option>HIPAA</option><option>FedRAMP</option><option>SOC 2</option><option>ISO 27001</option></select></label><label className="field"><span>Period start</span><input name="periodStart" type="date" required /></label><label className="field"><span>Period end</span><input name="periodEnd" type="date" required /></label><label className="field full"><span>Systems in scope</span><textarea name="systems" rows={3} required placeholder="payments-production, identity-production" /><small>Comma or line separated; collection outside this list is rejected.</small></label><label className="field full"><span>Control IDs</span><textarea name="controls" rows={3} required placeholder="1.2.5, 2.2.1, 6.3.2" /><small>Comma or line separated; evidence outside this list is rejected.</small></label></div><div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={busy}>{busy ? "Creating scope…" : "Create active assessment"}</button></div></form>}
    {type === "device" && (deviceToken ? <div><p className="modal-intro">This token is shown once. Copy it into the Mac app under <strong>Scopeproof shield → Capture & Jira Settings</strong>, then close this dialog.</p><div className="token-reveal"><code>{deviceToken}</code><button className="button secondary" onClick={() => void navigator.clipboard.writeText(deviceToken)}>Copy token</button></div><div className="privacy-note"><span>!</span><p>Treat this token like a password. It is stored hashed on the server and in the Mac login Keychain. Revoke the device immediately if the token is exposed.</p></div><div className="modal-actions"><button className="button primary" onClick={onClose}>I saved the token</button></div></div> : <form onSubmit={onDevice}><p className="modal-intro">Create a revocable identity for one Mac. Evidence uploaded by this device is attributed to your user and written to the immutable audit chain.</p><label className="field"><span>Device name</span><input name="displayName" required maxLength={100} defaultValue="Jayson’s Mac" placeholder="e.g. Compliance MacBook Pro" /></label><div className="privacy-note"><span>i</span><p>The token is displayed only once. The Mac stores it in Keychain and sends it only to your configured Scopeproof server.</p></div><div className="modal-actions"><button type="button" className="button secondary" onClick={onClose}>Cancel</button><button className="button primary" disabled={busy}>{busy ? "Creating secure token…" : "Create device token"}</button></div></form>)}
  </section></div>;
}
