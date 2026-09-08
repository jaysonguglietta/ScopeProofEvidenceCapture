export function workflowError(message: string, status = 400): Response {
  return new Response(JSON.stringify({ error: message }), { status, headers: { "content-type": "application/json" } });
}

export function workflowBody(value: unknown, allowed: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.keys(value).some((key) => !allowed.includes(key))) throw workflowError("Request contains unsupported fields or is not an object.");
  return value as Record<string, unknown>;
}

export function isCalendarDate(value: string): boolean {
  return /^\d{4}-\d{2}-\d{2}$/u.test(value) && Number.isFinite(Date.parse(`${value}T00:00:00.000Z`)) && new Date(`${value}T00:00:00.000Z`).toISOString().slice(0, 10) === value;
}

export function nextWorkflowTimestamp(previous: unknown, now = Date.now()): string {
  const raw = String(previous || "");
  const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/u.test(raw) ? `${raw.replace(" ", "T")}Z` : raw;
  const parsed = Date.parse(normalized);
  return new Date(Math.max(now, Number.isFinite(parsed) ? parsed + 1 : 0)).toISOString();
}

export function normalizeFindingDueAt(value: unknown, now = Date.now()): string | null {
  if (value === null || value === "") return null;
  if (typeof value !== "string" || !isCalendarDate(value.slice(0, 10))) throw workflowError("Use a valid calendar due date or UTC timestamp.");
  const input = value.length === 10 ? `${value}T23:59:59.999Z` : value;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u.test(input)) throw workflowError("Finding due timestamps must use UTC (Z).");
  const date = new Date(input);
  if (!Number.isFinite(date.getTime()) || date.toISOString().slice(0, 19) !== input.slice(0, 19) || date.getTime() > now + 10 * 366 * 24 * 60 * 60_000) throw workflowError("Finding due date is invalid or more than ten years away.");
  return date.toISOString();
}

export function normalizeCollectorSchedule(value: unknown): string | null {
  if (value === null || value === "") return null;
  if (typeof value !== "string" || value.length > 32) throw workflowError("Collector schedule must be a supported five-field UTC cron or null.");
  const match = value.trim().match(/^(\d{1,2}) (\*|\d{1,2}) \* \* (\*|[0-6])$/u);
  if (!match || ![0, 15, 30, 45].includes(Number(match[1])) || (match[2] !== "*" && Number(match[2]) > 23)) throw workflowError("Use minute 0, 15, 30 or 45, hour 0–23 or *, * * and weekday 0–6 or *. Schedules align to the hosted 15-minute tick and run at most hourly, in UTC.");
  return `${Number(match[1])} ${match[2] === "*" ? "*" : Number(match[2])} * * ${match[3]}`;
}

/** Preview only: no promise that an external scheduler will invoke on time. */
export function nextCollectorRun(value: unknown, now = new Date()): string | null {
  let expression: string | null;
  try { expression = normalizeCollectorSchedule(value); } catch { return null; }
  if (!expression || !Number.isFinite(now.getTime())) return null;
  const [minute, hour, , , weekday] = expression.split(" ");
  const next = new Date(Math.floor(now.getTime() / 60000) * 60000 + 60000);
  for (let step = 0; step <= 7 * 24 * 60; step++, next.setUTCMinutes(next.getUTCMinutes() + 1)) {
    if (next.getUTCMinutes() === Number(minute) && (hour === "*" || next.getUTCHours() === Number(hour)) && (weekday === "*" || next.getUTCDay() === Number(weekday))) return next.toISOString();
  }
  return null;
}
