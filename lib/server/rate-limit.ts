import { sha256 } from "./crypto";
import { getEnv } from "./env";

function clientAddress(request: Request): string {
  const value = String(request.headers.get("cf-connecting-ip") || "unknown").trim().slice(0, 64);
  return /^[A-Fa-f0-9:.]{3,64}$/.test(value) ? value.toLowerCase() : "unknown";
}

async function consume(scope: string, limit: number, windowSeconds: number): Promise<boolean> {
  const now = Math.floor(Date.now() / 1_000);
  const windowStart = Math.floor(now / windowSeconds) * windowSeconds;
  const expiresAt = windowStart + windowSeconds * 2;
  const keyHash = await sha256(`scopeproof-rate-v1\n${scope}\n${windowStart}`);
  const result = await getEnv().DB.prepare(`INSERT INTO rate_limit_buckets (key_hash, window_start, request_count, expires_at)
    VALUES (?, ?, 1, ?)
    ON CONFLICT(key_hash) DO UPDATE SET request_count = request_count + 1, expires_at = excluded.expires_at
    WHERE request_count < ?`).bind(keyHash, windowStart, expiresAt, limit).run();
  return Boolean(result.meta.changes);
}

export async function enforceRateLimit(request: Request, principalId: string, route: string, limit: number, windowSeconds: number): Promise<void> {
  if (!/^[a-z0-9_.:/-]{1,100}$/i.test(route) || limit < 1 || limit > 10_000 || windowSeconds < 1 || windowSeconds > 86_400) throw new Error("Invalid internal rate-limit policy.");
  const [principalAllowed, addressAllowed] = await Promise.all([
    consume(`principal:${route}:${principalId}`, limit, windowSeconds),
    consume(`address:${route}:${clientAddress(request)}`, Math.max(limit * 5, 25), windowSeconds),
  ]);
  if (!principalAllowed || !addressAllowed) {
    console.warn("scopeproof_rate_limited", { route, principalId: (await sha256(principalId)).slice(0, 16) });
    throw new Response(JSON.stringify({ error: "Request quota exceeded. Retry after the current rate-limit window." }), {
      status: 429,
      headers: { "content-type": "application/json", "retry-after": String(windowSeconds) },
    });
  }
}

export function requireBoundedContentLength(request: Request, maximum: number): number {
  const raw = request.headers.get("content-length");
  if (!raw || !/^\d{1,12}$/.test(raw)) throw new Response(JSON.stringify({ error: "A bounded Content-Length header is required." }), { status: 411, headers: { "content-type": "application/json" } });
  const length = Number(raw);
  if (!Number.isSafeInteger(length) || length <= 0 || length > maximum) throw new Response(JSON.stringify({ error: "Request body exceeds the route limit." }), { status: 413, headers: { "content-type": "application/json" } });
  return length;
}

export async function purgeRateLimitBuckets(now = Math.floor(Date.now() / 1_000)): Promise<void> {
  await getEnv().DB.prepare("DELETE FROM rate_limit_buckets WHERE expires_at < ?").bind(now).run();
}
