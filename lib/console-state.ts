/** Pure, shared browser-state rules. These never grant server permissions. */
export function mergeRecords<T extends { id: string }>(current: T[], incoming: T[]): T[] {
  const replacements = new Map(incoming.map((item) => [item.id, item]));
  const known = new Set(current.map((item) => item.id));
  return [...incoming.filter((item) => !known.has(item.id)), ...current.map((item) => replacements.get(item.id) ?? item)];
}

export function evidenceQuery(assessmentId: string, filters: { search: string; status: string; type: string; controlId?: string; system?: string }, cursor?: string): URLSearchParams {
  const query = new URLSearchParams({ assessmentId, limit: "50" });
  if (filters.search.trim()) query.set("q", filters.search.trim());
  if (filters.controlId) query.set("controlId", filters.controlId);
  if (filters.system) query.set("system", filters.system);
  if (filters.status !== "All statuses") query.set("status", filters.status === "Needs review" ? "needs_review" : filters.status.toLowerCase());
  if (filters.type !== "All types") query.set("type", filters.type.toLowerCase());
  if (cursor) query.set("cursor", cursor);
  return query;
}

export function retryDelay(header: string | null, now = Date.now()): number {
  if (!header) return 5_000;
  const seconds = Number(header);
  const delay = Number.isFinite(seconds) ? seconds * 1_000 : Date.parse(header) - now;
  return Number.isFinite(delay) ? Math.max(1_000, Math.min(3_600_000, delay)) : 5_000;
}

export type ReviewAction = "approve" | "reject" | "return" | "reopen" | "supersede";
export function reviewActions(status: string): ReviewAction[] {
  if (status === "Needs review") return ["approve", "reject", "return"];
  if (status === "Rejected" || status === "Returned") return ["reopen"];
  if (status === "Approved") return ["supersede"];
  return [];
}
