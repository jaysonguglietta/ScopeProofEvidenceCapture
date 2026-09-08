"use client";
import { useState } from "react";
type Check = { id: string; status: "pass" | "warn" | "fail"; summary: string };
export function ReadinessPanel() {
  const [result, setResult] = useState<{ ready: boolean; checkedAt: string; checks: Check[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  async function check() {
    setBusy(true); setError(null);
    try {
      const response = await fetch("/api/admin/readiness", { cache: "no-store" });
      const data = await response.json() as { ready: boolean; checkedAt: string; checks: Check[]; error?: string };
      if (!Array.isArray(data.checks) || typeof data.ready !== "boolean") throw new Error(data.error || "Readiness service unavailable.");
      setResult(data);
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Readiness check failed."); }
    finally { setBusy(false); }
  }
  return <section className="panel readiness-panel"><div className="panel-head padded"><div><h2>Operational readiness</h2><p>Read-only checks. A passing configuration check is not proof of live recovery or regulatory compliance.</p></div><button className="button secondary" disabled={busy} onClick={() => void check()}>{busy ? "Checking…" : "Run readiness checks"}</button></div>
    {error && <p className="field-error" role="alert">{error} Retry after restoring the protected service.</p>}
    {result && <><p className="panel-body" role="status">{result.ready ? "Configured checks passed" : "Production readiness is blocked"} · Checked {new Date(result.checkedAt).toLocaleString()}</p><ul className="readiness-checks">{result.checks.map((item) => <li key={item.id}><strong>{item.status.toUpperCase()}: {item.id.replaceAll("_", " ")}</strong><p>{item.summary}</p></li>)}</ul></>}
    <p className="panel-body"><a href="https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/main/docs/GETTING_STARTED.md" target="_blank" rel="noreferrer">Installation and operator documentation ↗</a></p>
  </section>;
}
