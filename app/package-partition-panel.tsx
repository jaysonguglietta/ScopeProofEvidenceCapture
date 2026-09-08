"use client";

import { useState } from "react";
import type { PackagePlan } from "../lib/server/package-plan";
import styles from "./components/workflow-admin.module.css";

export function PackagePartitionPanel({ assessmentId, canExport, onChanged }: { assessmentId: string; canExport: boolean; onChanged: () => void }) {
  const [plan, setPlan] = useState<PackagePlan | null>(null);
  const [busy, setBusy] = useState<number | "plan" | null>(null);
  const [error, setError] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [built, setBuilt] = useState<Record<number, string>>({});
  async function prepare() {
    setBusy("plan"); setError("");
    try {
      const response = await fetch(`/api/packages/plan?assessmentId=${encodeURIComponent(assessmentId)}`, { cache: "no-store" });
      const data = await response.json() as { plan: PackagePlan; error?: string };
      if (!response.ok) throw new Error(data.error || "Package planning failed.");
      setPlan(data.plan); setConfirmed(false); setBuilt({});
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Could not plan this selection."); }
    finally { setBusy(null); }
  }
  async function build(index: number) {
    if (!plan || !confirmed) return;
    setBusy(index); setError("");
    try {
      const response = await fetch("/api/packages", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ assessmentId, partition: { digest: plan.digest, index } }) });
      const data = await response.json() as { package: { id: string }; error?: string };
      if (!response.ok) throw new Error(data.error || "Part build failed. Check package history before retrying an uncertain result.");
      setBuilt((current) => ({ ...current, [index]: data.package.id })); onChanged();
    } catch (failure) { setError(failure instanceof Error ? failure.message : "Build failed. Check history before retrying."); }
    finally { setBusy(null); }
  }
  return <section className={styles.panel} aria-label="Complete package partitioning"><h2>Large assessment handoff</h2><p>Plan the complete eligible selection into bounded parts: at most 100 artifacts and 25 MiB of evidence per ZIP. Evidence remains in its original assessment.</p><button className={styles.button} disabled={!canExport || !assessmentId || busy !== null} onClick={() => void prepare()}>{busy === "plan" ? "Planning…" : "Plan all package parts"}</button>{error && <p className={styles.error} role="alert">{error}</p>}{plan && <><p>{plan.total} records · {plan.eligible} eligible · {plan.exclusions.length} explicitly excluded · {plan.parts.length} parts</p><p style={{ overflowWrap: "anywhere" }}>Plan SHA-256: <code>{plan.digest}</code></p><p className={styles.notice}>Every part includes the same signed plan. Deliver all numbered parts with the same plan digest; a single part is not a complete assessment handoff. If evidence changes, regenerate the plan and rebuild all parts. Previously built parts remain in package history. At most ten builds per hour are permitted.</p><label className={styles.check}><input type="checkbox" checked={confirmed} disabled={busy !== null} onChange={(event) => setConfirmed(event.target.checked)} />I will deliver every part and reconcile the exclusions in the signed plan.</label>{plan.parts.map((part) => <article className={styles.card} key={part.index}><strong>Part {part.index} of {plan.parts.length}</strong><p>{part.evidenceIds.length} artifacts · {(part.bytes / 1_048_576).toFixed(1)} MiB</p>{built[part.index] ? <a className={styles.button} href={`/api/packages/${encodeURIComponent(built[part.index])}`} download>Download signed part</a> : <button className={styles.button} disabled={!confirmed || busy !== null} onClick={() => void build(part.index)}>{busy === part.index ? "Building…" : "Build this part"}</button>}</article>)}{plan.exclusions.length > 0 && <details><summary>Excluded records ({plan.exclusions.length})</summary><ul>{plan.exclusions.map((item) => <li key={item.evidenceId}>{item.evidenceId} — {item.reason}</li>)}</ul></details>}<p role="status">Built in this session: {Object.keys(built).length} / {plan.parts.length}. Use package history to recover earlier or interrupted builds.</p></>}</section>;
}
