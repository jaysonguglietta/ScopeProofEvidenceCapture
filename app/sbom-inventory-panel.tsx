"use client";

import { useState } from "react";
import type { SbomComponent } from "../lib/server/sbom-inventory";
import styles from "./components/workflow-admin.module.css";

type Detail = { components: SbomComponent[]; comparison: { added: number; removed: number; changed: number }; job: { commit: string }; error?: string };
export function SbomInventoryPanel({ jobId }: { jobId: string }) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [baseline, setBaseline] = useState("");
  const [loadedBaseline, setLoadedBaseline] = useState("");
  const [query, setQuery] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const endpoint = `/api/sboms/${encodeURIComponent(jobId)}/inventory`;
  async function load() {
    setBusy(true); setError("");
    try {
      const response = await fetch(`${endpoint}?baseline=${encodeURIComponent(baseline.trim())}`, { cache: "no-store" });
      const data = await response.json() as Detail;
      if (!response.ok) throw new Error(data.error || "Inventory is unavailable.");
      setDetail(data); setLoadedBaseline(baseline.trim());
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Inventory could not be read."); }
    finally { setBusy(false); }
  }
  const matches = detail?.components.filter((item) => `${item.purl} ${item.manifests.join(" ")}`.toLowerCase().includes(query.toLowerCase())) || [];
  return <section className={styles.panel} aria-label="SBOM component inspector"><h3>Inspect complete inventory</h3><p>Inventory ID: <code>{jobId}</code></p><label className={styles.field}>Optional baseline inventory ID<input className={styles.control} value={baseline} onChange={(event) => setBaseline(event.target.value)} maxLength={37} placeholder="sbom_… from this repository and assessment" /></label><button className={styles.button} disabled={busy} onClick={() => void load()}>{busy ? "Loading components…" : "Load / compare inventory"}</button>{error && <p className={styles.error} role="alert">{error}</p>}{detail && <><p>{detail.components.length} components · +{detail.comparison.added} / −{detail.comparison.removed} / {detail.comparison.changed} version sets changed{!loadedBaseline && " · no comparison baseline selected"}</p><a className={styles.button} href={`${endpoint}?baseline=${encodeURIComponent(loadedBaseline)}&download=true`} download>Download full component and delta detail</a><label className={styles.field}>Search all components<input className={styles.control} value={query} onChange={(event) => setQuery(event.target.value)} maxLength={120} /></label><p role="status">{matches.length} matches. Showing {Math.min(matches.length, 100)}; refine search or download the full detail.</p><ul>{matches.slice(0, 100).map((item) => <li key={item.purl}><code>{item.purl}</code> · {item.directKnown === false ? "Directness unknown" : item.direct ? "Direct" : "Transitive"}<small>{item.manifests.join(", ")}</small></li>)}</ul></>}</section>;
}
