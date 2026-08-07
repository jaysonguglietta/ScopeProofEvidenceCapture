import { getEnv } from "./env";

export type Role = "admin" | "compliance_lead" | "reviewer" | "auditor";
export type AuthenticatedUser = { id: string; email: string; displayName: string; role: Role };
const roleRank: Record<Role, number> = { auditor: 0, reviewer: 1, compliance_lead: 2, admin: 3 };

function decodeName(request: Request): string | null {
  const encoded = request.headers.get("oai-authenticated-user-full-name");
  if (!encoded || request.headers.get("oai-authenticated-user-full-name-encoding") !== "percent-encoded-utf-8") return null;
  try { return decodeURIComponent(encoded); } catch { return null; }
}

export async function requireApiUser(request: Request, minimumRole: Role = "auditor"): Promise<AuthenticatedUser> {
  const id = request.headers.get("oai-authenticated-user-id");
  const email = request.headers.get("oai-authenticated-user-email")?.toLowerCase();
  if (!id || !email) throw new Response(JSON.stringify({ error: "Authentication required" }), { status: 401, headers: { "content-type": "application/json" } });
  const env = getEnv();
  const existing = await env.DB.prepare("SELECT id, email, display_name, role FROM users WHERE id = ?").bind(id).first<{ id: string; email: string; display_name: string; role: Role }>();
  let user: AuthenticatedUser;
  if (existing) {
    await env.DB.prepare("UPDATE users SET email = ?, display_name = ?, last_seen_at = CURRENT_TIMESTAMP WHERE id = ?").bind(email, decodeName(request) || email, id).run();
    user = { id, email, displayName: decodeName(request) || existing.display_name, role: existing.role };
  } else {
    const configuredAdmins = (env.BOOTSTRAP_ADMIN_EMAILS || "").split(",").map((entry) => entry.trim().toLowerCase()).filter(Boolean);
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM users").first<{ count: number }>();
    const role: Role = configuredAdmins.includes(email) || (!configuredAdmins.length && Number(count?.count || 0) === 0) ? "admin" : "auditor";
    const displayName = decodeName(request) || email;
    await env.DB.prepare("INSERT INTO users (id, email, display_name, role) VALUES (?, ?, ?, ?)").bind(id, email, displayName, role).run();
    user = { id, email, displayName, role };
  }
  if (roleRank[user.role] < roleRank[minimumRole]) throw new Response(JSON.stringify({ error: "Insufficient role", requiredRole: minimumRole }), { status: 403, headers: { "content-type": "application/json" } });
  return user;
}

export function requireSameOrigin(request: Request): void {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin) throw new Response(JSON.stringify({ error: "Cross-origin mutation denied" }), { status: 403, headers: { "content-type": "application/json" } });
}

export function jsonError(error: unknown): Response {
  if (error instanceof Response) return error;
  const requestId = crypto.randomUUID();
  console.error("scopeproof_api_error", { requestId, error: error instanceof Error ? error.message : String(error) });
  return Response.json({ error: "Request failed", requestId }, { status: 500 });
}
