"use client";

import { useEffect, useState } from "react";
import type { FindingEvidenceSnapshot } from "../../lib/server/finding-resolution";
import styles from "./workflow-admin.module.css";

type Candidate = Omit<FindingEvidenceSnapshot, "linkedAt">;
type Page = { total: number; hasMore: boolean; nextCursor: string | null };

export function FindingEvidenceLinks({ evidence }: { evidence: FindingEvidenceSnapshot[] }) {
  if (!evidence.length) return <p className={styles.notice}>No evidence-backed resolution has been recorded. Risk acceptance and historical text-only disposition are not proof of remediation.</p>;
  return <ul>{evidence.map((item) => <li key={`${item.evidenceId}:${item.occurrenceId}`}><a href={`/api/evidence/${encodeURIComponent(item.evidenceId)}?view=inline`} target="_blank" rel="noreferrer">Inspect {item.title || item.evidenceId}</a><br /><small>{item.controlId} · {item.system} · Approved {item.approvedAt ? new Date(item.approvedAt).toLocaleString() : "previously"}</small><details><summary>Recorded evidence identity</summary><p>Occurrence: <code>{item.occurrenceId}</code><br />SHA-256: <code style={{ overflowWrap: "anywhere" }}>{item.sha256}</code></p></details></li>)}</ul>;
}

export function FindingEvidencePicker({ findingId, value, onChange, initialEvidence = [] }: { findingId: string; value: string[]; onChange: (value: string[]) => void; initialEvidence?: FindingEvidenceSnapshot[] }) {
  const [query, setQuery] = useState("");
  const [items, setItems] = useState<Candidate[]>([]);
  const [known, setKnown] = useState<Candidate[]>(initialEvidence);
  const [page, setPage] = useState<Page | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    const timer = setTimeout(() => { setBusy(true); setError(""); void (async () => {
      try {
        const params = new URLSearchParams({ q: query, limit: "25" }); if (cursor) params.set("cursor", cursor);
        const response = await fetch(`/api/findings/${findingId}/resolution-evidence?${params}`, { cache: "no-store", signal: controller.signal });
        const body = await response.json() as { evidence: Candidate[]; page: Page; error?: string };
        if (!response.ok) throw new Error(body.error || "Evidence choices could not be loaded.");
        if (controller.signal.aborted) return;
        setItems((old) => cursor ? [...old, ...body.evidence.filter((item) => !old.some((existing) => existing.evidenceId === item.evidenceId))] : body.evidence);
        setKnown((old) => [...old.filter((item) => !body.evidence.some((incoming) => incoming.evidenceId === item.evidenceId)), ...body.evidence]); setPage(body.page);
      } catch (failure) { if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : "Evidence search failed. Retry the search."); }
      finally { if (!controller.signal.aborted) setBusy(false); }
    })(); }, 200);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [findingId, query, cursor, retry]);
  return <fieldset className={styles.card}><legend>Evidence proving remediation</legend><p>Select 1–10 independently approved, current artifacts. Only complete, scope-matched evidence is offered. The server rechecks the exact occurrence and digest when you save.</p><label className={styles.field}>Find approved evidence<input className={styles.control} value={query} maxLength={120} onChange={(event) => { setQuery(event.target.value); setCursor(null); }} placeholder="Evidence title or exact identifier" /></label><p role="status">{busy ? "Loading eligible evidence…" : `${value.length} selected · ${page?.total || 0} matching artifacts`}</p>{error && <div><p className={styles.error} role="alert">{error}</p><button className={styles.button} type="button" disabled={busy} onClick={() => setRetry((count) => count + 1)}>Retry evidence search</button></div>}{value.length > 0 && <ul aria-label="Selected resolution evidence">{value.map((id) => <li key={id}>{known.find((item) => item.evidenceId === id)?.title || id} <button className={styles.button} type="button" onClick={() => onChange(value.filter((item) => item !== id))}>Remove <span className={styles.muted}>{id.slice(-6)}</span></button></li>)}</ul>}{!busy && !error && items.length === 0 && <p className={styles.notice}>No eligible evidence matches. Capture and independently review remediation evidence for this assessment and control, then search again.</p>}{items.map((item) => <div key={item.evidenceId}><label className={styles.check}><input type="checkbox" checked={value.includes(item.evidenceId)} disabled={!value.includes(item.evidenceId) && value.length >= 10} onChange={(event) => onChange(event.target.checked ? [...new Set([...value, item.evidenceId])] : value.filter((id) => id !== item.evidenceId))} /><span>{item.title}<small> · {item.controlId} · {item.system}</small></span></label><a href={`/api/evidence/${encodeURIComponent(item.evidenceId)}?view=inline`} target="_blank" rel="noreferrer">Inspect {item.title}</a></div>)}{page?.hasMore && <button className={styles.button} type="button" disabled={busy} onClick={() => setCursor(page.nextCursor)}>Load more eligible evidence</button>}</fieldset>;
}
