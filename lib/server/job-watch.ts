export function watchedJobIds(raw: string | null, assessmentId: string, prefix: "job" | "sbom"): string[] {
  if (!raw) return [];
  const ids = raw.split(",");
  if (!/^asm_[a-f0-9]{32}$/u.test(assessmentId) || ids.length > 50 || new Set(ids).size !== ids.length || ids.some((id) => !new RegExp(`^${prefix}_[a-f0-9]{32}$`, "u").test(id))) throw new Response(JSON.stringify({ error: "Watched jobs require one assessment and at most 50 unique valid identifiers." }), { status: 400, headers: { "content-type": "application/json" } });
  return ids;
}

export function rotatingWatchBatch(ids: string[], iteration: number): string[] {
  if (!ids.length) return [];
  const start = (Math.max(0, iteration) * 50) % ids.length;
  return [...ids.slice(start), ...ids.slice(0, start)].slice(0, 50);
}
