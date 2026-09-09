"use client";
import { useState } from "react";
import type { collectorScopeCompatibility } from "../lib/collector-scope";
import styles from "./components/workflow-admin.module.css";
export function ScopeCompatibilityPanel({ assessmentId }: { assessmentId: string }) {
  const [items, setItems] = useState<ReturnType<typeof collectorScopeCompatibility> | null>(null);
  const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  async function inspect() {
    setBusy(true); setError("");
    try { const response = await fetch(`/api/collectors/compatibility?assessmentId=${encodeURIComponent(assessmentId)}`, { cache: "no-store" }); const body = await response.json() as { previews?: ReturnType<typeof collectorScopeCompatibility>; error?: string }; if (!response.ok || !Array.isArray(body.previews)) throw new Error(body.error || "Compatibility preview failed."); setItems(body.previews); }
    catch (failure) { setError(failure instanceof Error ? failure.message : "Preview unavailable."); } finally { setBusy(false); }
  }
  return <section className={styles.panel}><h2>Source compatibility preview</h2><p>Checks the saved assessment against the current collector output labels, without contacting providers or exposing credentials. Save draft edits before checking. This is not a connectivity or completeness test.</p><button className={styles.button} disabled={busy} onClick={() => void inspect()}>{busy ? "Checking scope…" : "Check saved scope"}</button>{error && <p role="alert" className={styles.error}>{error}</p>}{items?.map((item) => <article className={styles.card} key={item.provider}><h3>{item.provider.toUpperCase()} · {item.compatible ? "Output labels fit saved scope" : "Scope needs attention"}</h3>{!item.known && <p>Configured target labels are unavailable or require provider discovery; compatibility cannot be asserted.</p>}<p>Emitted controls: {item.controls.join(", ")} · Systems: {item.systems.join(", ") || "Not known"}</p>{item.missingControls.length > 0 && <p>Not in saved scope: controls {item.missingControls.join(", ")}</p>}{item.missingSystems.length > 0 && <p>Not in saved scope: systems {item.missingSystems.join(", ")}</p>}<small>Only expand a draft when these systems really belong in the assessment. Otherwise leave this source unselected; runtime still rejects out-of-scope evidence.</small></article>)}</section>;
}
