export type PageCursor = Readonly<{ sortValue: string; id: string }>;

export type PageMeta = Readonly<{
  limit: number;
  total: number;
  hasMore: boolean;
  nextCursor: string | null;
}>;

function invalidCursor(): Response {
  return new Response(JSON.stringify({ error: "The page cursor is invalid or expired. Reload the first page." }), {
    status: 400,
    headers: { "content-type": "application/json" },
  });
}

export function pageLimit(value: string | null | undefined, fallback = 50, maximum = 100): number {
  if (!value) return fallback;
  if (!/^\d{1,3}$/.test(value)) throw new Response(JSON.stringify({ error: "Page size must be a whole number." }), { status: 400, headers: { "content-type": "application/json" } });
  const parsed = Number(value);
  if (parsed < 1 || parsed > maximum) throw new Response(JSON.stringify({ error: `Page size must be between 1 and ${maximum}.` }), { status: 400, headers: { "content-type": "application/json" } });
  return parsed;
}

export function encodePageCursor(cursor: PageCursor): string {
  const json = JSON.stringify({ v: 1, s: cursor.sortValue, i: cursor.id });
  const bytes = new TextEncoder().encode(json);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function decodePageCursor(value: string | null | undefined, idPattern: RegExp): PageCursor | null {
  if (!value) return null;
  if (value.length > 512 || !/^[A-Za-z0-9_-]+$/u.test(value)) throw invalidCursor();
  try {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
    const binary = atob(base64);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as Record<string, unknown>;
    const sortValue = String(parsed.s || "");
    const id = String(parsed.i || "");
    if (parsed.v !== 1 || !Number.isFinite(Date.parse(sortValue)) || !idPattern.test(id)) throw invalidCursor();
    return { sortValue, id };
  } catch (error) {
    if (error instanceof Response) throw error;
    throw invalidCursor();
  }
}

export function pageMeta<T extends Record<string, unknown>>(rows: T[], limit: number, total: number, sortColumn: keyof T, idColumn: keyof T): { items: T[]; page: PageMeta } {
  const hasMore = rows.length > limit;
  const items = hasMore ? rows.slice(0, limit) : rows;
  const last = items.at(-1);
  return {
    items,
    page: {
      limit,
      total,
      hasMore,
      nextCursor: hasMore && last ? encodePageCursor({ sortValue: String(last[sortColumn]), id: String(last[idColumn]) }) : null,
    },
  };
}
