"use client";
import { useEffect, useState } from "react";
type HoldData = { actorId: string; hold: { owner_id: string; reason: string; expires_at: string } | null; releases: Array<{ id: string; requested_by: string; reason: string; request_digest: string; canApprove: boolean; status: string; expires_at: string }> };
export function EvidenceHoldPanel({ evidenceId }: { evidenceId: string }) {
  const [data, setData] = useState<HoldData | null>(null), [error, setError] = useState("");
  const [revision, setRevision] = useState(0), [busy, setBusy] = useState(false);
  useEffect(() => {
    let cancelled = false;
    void fetch(`/api/evidence/${encodeURIComponent(evidenceId)}/retention`, { cache: "no-store" }).then(async (response) => {
      const result = await response.json() as HoldData & { error?: string };
      if (!response.ok) throw new Error(result.error || "Hold status unavailable.");
      if (!cancelled) { setData(result); setError(""); }
    }).catch((failure) => { if (!cancelled) setError(failure instanceof Error ? failure.message : "Hold status unavailable."); });
    return () => { cancelled = true; };
  }, [evidenceId, revision]);
  async function mutate(method: "PUT" | "DELETE", body: Record<string, unknown>) {
    setBusy(true); setError("");
    try {
      const response = await fetch(`/api/evidence/${encodeURIComponent(evidenceId)}/retention`, { method, headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      if (!response.ok) throw new Error((await response.json() as { error: string }).error);
      setRevision((value) => value + 1);
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Hold operation failed."); }
    finally { setBusy(false); }
  }
  return <section className="detail-section"><h3>Retention hold</h3><p>Hosted retention protection. This is not a direct-S3 Object Lock control.</p>{error && <p role="alert">{error}</p>}{data?.hold ? <p><strong>Active until {new Date(data.hold.expires_at).toLocaleString()}</strong><br />{data.hold.reason}</p> : <p>{data ? "No active hosted hold." : "Loading hold state…"}</p>}
    {data && <form onSubmit={(event) => { event.preventDefault(); const form = new FormData(event.currentTarget); const method = data.hold ? "DELETE" : "PUT"; if (window.confirm(data.hold ? "Request hold release? Another administrator must approve it." : "Place this retention hold?")) void mutate(method, data.hold ? { reason: form.get("reason") } : { reason: form.get("reason"), expiresAt: new Date(String(form.get("expiresAt"))).toISOString() }); }}><label className="field"><span>{data.hold ? "Release request rationale" : "Hold rationale"}</span><textarea name="reason" minLength={20} maxLength={1000} required rows={3} /></label>{!data.hold && <label className="field"><span>Expires (within one year)</span><input name="expiresAt" type="datetime-local" required /></label>}<button className="button secondary" disabled={busy}>{busy ? "Recording…" : data.hold ? "Request independent release" : "Place hold"}</button></form>}
    {data?.releases.map((release) => <article className="review-event" key={release.id}><strong>{release.status} release request</strong><p>{release.reason}</p><small>Expires {new Date(release.expires_at).toLocaleString()}</small>{release.status === "pending" && <button className="button secondary danger" disabled={busy || !release.canApprove} title={release.requested_by === data.actorId ? "A different administrator must approve your request." : "Verify this rationale before approving release."} onClick={() => { if (window.confirm(`Release the hold for this exact request? ${release.reason}`)) void mutate("DELETE", { requestId: release.id, requestDigest: release.request_digest }); }}>Approve release</button>}</article>)}
  </section>;
}
