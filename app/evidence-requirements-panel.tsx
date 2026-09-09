"use client";
import { useEffect, useState } from "react";

type Requirement = { controlId: string; system: string; revision: number; minimumArtifacts: number; ownerId: string | null; ownerEmail: string | null; reason: string; eligible: number; expired: number; partial: number; needsReview: number; satisfied: boolean; missingArtifacts: number; ownerMissing: boolean };
type RequirementData = { requirements: Requirement[]; owners: Array<{ id: string; email: string }>; canEdit: boolean; interpretation: string; summary: { total: number; satisfied: number } };
export function EvidenceRequirementsPanel({ assessmentId, onInspect }: { assessmentId: string; onInspect: (control: string, system: string) => void }) {
  const [data, setData] = useState<RequirementData | null>(null), [error, setError] = useState("");
  const [revision, setRevision] = useState(0), [filter, setFilter] = useState(""), [onlyGaps, setOnlyGaps] = useState(true);
  const [selected, setSelected] = useState<Requirement | null>(null), [busy, setBusy] = useState(false);
  useEffect(() => {
    let cancelled = false;
    void fetch(`/api/requirements?assessmentId=${encodeURIComponent(assessmentId)}`, { cache: "no-store" }).then(async (response) => {
      const value = await response.json() as RequirementData & { error?: string };
      if (!response.ok) throw new Error(value.error || "Requirements could not be loaded.");
      if (!cancelled) { setData(value); setError(""); }
    }).catch((failure) => { if (!cancelled) setError(failure instanceof Error ? failure.message : "Requirements unavailable."); });
    return () => { cancelled = true; };
  }, [assessmentId, revision]);
  async function save(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!selected) return;
    const form = new FormData(event.currentTarget); setBusy(true); setError("");
    try {
      const response = await fetch("/api/requirements", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({
        assessmentId, controlId: selected.controlId, system: selected.system, expectedRevision: selected.revision,
        minimumArtifacts: Number(form.get("minimumArtifacts")), ownerId: form.get("ownerId"), reason: form.get("reason"),
      }) });
      if (!response.ok) throw new Error((await response.json() as { error: string }).error);
      setSelected(null); setRevision((value) => value + 1);
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Requirement could not be revised."); }
    finally { setBusy(false); }
  }
  const items = data?.requirements.filter((item) => (!onlyGaps || !item.satisfied) && `${item.controlId} ${item.system} ${item.ownerEmail || ""}`.toLowerCase().includes(filter.toLowerCase())) || [];
  return <section className="panel requirements-panel"><div className="panel-head padded"><div><h2>Evidence requirements</h2><p>{data ? `${data.summary.satisfied} of ${data.summary.total} control/system expectations satisfied` : "Loading authoritative expectations…"}</p></div><button className="button secondary" disabled={busy} onClick={() => setRevision((value) => value + 1)}>Refresh</button></div>
    <p className="panel-body">{data?.interpretation || "One eligible artifact and an accountable owner are required per scoped control/system pair by default."}</p>
    {error && <p role="alert" className="workspace-error">{error}</p>}
    <div className="toolbar"><label className="field"><span>Find control, system or owner</span><input value={filter} onChange={(event) => setFilter(event.target.value)} /></label><label className="checkbox-line"><input type="checkbox" checked={onlyGaps} onChange={(event) => setOnlyGaps(event.target.checked)} /> Only unmet expectations</label></div>
    {selected && <form onSubmit={save} className="requirement-edit"><h3>Revise {selected.controlId} · {selected.system}</h3><p>Revision {selected.revision}; previous expectations and audit history are retained.</p><label className="field"><span>Accountable owner</span><select name="ownerId" defaultValue={selected.ownerId || ""}><option value="">Unassigned — remains a gap</option>{data?.owners.map((owner) => <option key={owner.id} value={owner.id}>{owner.email}</option>)}</select></label><label className="field"><span>Minimum independently approved artifacts</span><input name="minimumArtifacts" type="number" min={1} max={25} required defaultValue={selected.minimumArtifacts} /></label><label className="field"><span>Reason for change</span><textarea name="reason" minLength={20} maxLength={1000} required rows={3} /></label><div className="modal-actions"><button type="button" className="button secondary" disabled={busy} onClick={() => setSelected(null)}>Cancel</button><button className="button primary" disabled={busy}>{busy ? "Recording revision…" : "Save audited revision"}</button></div></form>}
    <div className="requirements-table-scroll"><table className="requirements-table"><caption className="sr-only">Current control and system evidence expectations</caption><thead><tr><th>Control / system</th><th>Owner</th><th>Eligible / required</th><th>Blockers</th><th>Actions</th></tr></thead><tbody>{items.slice(0, 250).map((item) => <tr key={`${item.controlId}:${item.system}`}><th scope="row">{item.controlId}<small>{item.system}</small></th><td>{item.ownerEmail || "Unassigned"}{item.ownerMissing && <small>Active owner required</small>}</td><td>{item.eligible} / {item.minimumArtifacts}</td><td>{item.satisfied ? "Expectations satisfied" : `${item.missingArtifacts} missing · ${item.needsReview} need review · ${item.partial} partial · ${item.expired} expired`}</td><td><button className="button secondary" onClick={() => onInspect(item.controlId, item.system)}>Inspect evidence</button>{data?.canEdit && <button className="button secondary" disabled={busy} onClick={() => setSelected(item)}>Revise</button>}</td></tr>)}</tbody></table></div>
    {items.length > 250 && <p className="panel-body">Showing 250 of {items.length} matching requirements. Narrow the search to inspect the remainder; the summary includes all requirements.</p>}
    {data && !items.length && <p className="panel-body">No requirements match this filter.</p>}
  </section>;
}
