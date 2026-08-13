import { activeAuditKeyId, hmac, randomId, sha256, stableJson } from "./crypto";
import { getEnv } from "./env";

export type Role = "admin" | "compliance_lead" | "reviewer" | "auditor";
export type Permission = "approve_evidence" | "collect_evidence" | "manage_collectors" | "manage_devices" | "manage_jira" | "export_packages" | "manage_users" | "manage_retention";
export type AuthenticatedUser = { id: string; email: string; displayName: string; role: Role };

const roleRank: Record<Role, number> = { auditor: 0, reviewer: 1, compliance_lead: 2, admin: 3 };
const rolePermissions: Record<Role, ReadonlySet<Permission>> = {
  auditor: new Set(),
  reviewer: new Set(["approve_evidence", "export_packages"]),
  compliance_lead: new Set(["collect_evidence", "manage_collectors", "manage_devices", "manage_jira", "export_packages"]),
  admin: new Set(["approve_evidence", "collect_evidence", "manage_collectors", "manage_devices", "manage_jira", "export_packages", "manage_users", "manage_retention"]),
};

function responseError(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), { status, headers: { "content-type": "application/json" } });
}

function decodeName(request: Request): string | null {
  const encoded = request.headers.get("oai-authenticated-user-full-name");
  if (!encoded || request.headers.get("oai-authenticated-user-full-name-encoding") !== "percent-encoded-utf-8") return null;
  try {
    const value = decodeURIComponent(encoded).trim();
    return value && value.length <= 160 ? value : null;
  } catch { return null; }
}

function configuredOrigins(): Set<string> {
  const raw = String(getEnv().TRUSTED_APP_ORIGINS || "");
  const values = raw.split(",").map((value) => value.trim()).filter(Boolean);
  if (!values.length || values.length > 10) throw responseError(503, "Trusted application origins are not safely configured.");
  const origins = new Set<string>();
  for (const value of values) {
    let url: URL;
    try { url = new URL(value); } catch { throw responseError(503, "Trusted application origins are not safely configured."); }
    const local = url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
    if ((!local && url.protocol !== "https:") || url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) throw responseError(503, "Trusted application origins are not safely configured.");
    origins.add(url.origin);
  }
  return origins;
}

export function assertTrustedRequestOrigin(request: Request): void {
  const requestOrigin = new URL(request.url).origin;
  if (!configuredOrigins().has(requestOrigin)) throw responseError(421, "This origin is not authorized for Scopeproof identity headers.");
}

function bootstrapAdmins(): Set<string> {
  const raw = String(getEnv().BOOTSTRAP_ADMIN_EMAILS || "");
  const values = raw.split(",").map((entry) => entry.trim().toLowerCase()).filter(Boolean);
  if (!values.length || values.length > 20 || values.some((value) => value.includes("*") || value.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value))) {
    throw responseError(503, "Administrator bootstrap allowlist is not safely configured.");
  }
  return new Set(values);
}

export function assertPermission(actor: AuthenticatedUser, permission: Permission): void {
  if (!rolePermissions[actor.role].has(permission)) throw responseError(403, `Permission ${permission} is required.`);
}

export async function requireApiUser(request: Request, minimumRole: Role = "auditor"): Promise<AuthenticatedUser> {
  assertTrustedRequestOrigin(request);
  const id = String(request.headers.get("oai-authenticated-user-id") || "").trim();
  const email = String(request.headers.get("oai-authenticated-user-email") || "").trim().toLowerCase();
  if (!/^[A-Za-z0-9_.:-]{3,200}$/.test(id) || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw responseError(401, "Authentication required");
  const env = getEnv();
  const configuredAdmins = bootstrapAdmins();
  let existing = await env.DB.prepare("SELECT id, email, display_name, role FROM users WHERE id = ?").bind(id).first<{ id: string; email: string; display_name: string; role: Role }>();
  if (!existing) {
    const displayName = decodeName(request) || email;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const previous = await env.DB.prepare("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").first<{ event_hash: string }>();
      const auditId = randomId("evt");
      const occurredAt = new Date().toISOString();
      const previousHash = previous?.event_hash || "GENESIS";
      const details = { email, method: "explicit_allowlist" };
      const canonical = stableJson({ id: auditId, occurredAt, actorId: id, actorEmail: email, action: "user.bootstrap_admin_granted", resourceType: "user", resourceId: id, details, previousHash });
      const eventHash = await sha256(canonical);
      const hmacKeyId = activeAuditKeyId();
      const signature = await hmac(eventHash, hmacKeyId);
      try {
        await env.DB.batch([
          env.DB.prepare(`INSERT OR IGNORE INTO users (id, email, display_name, role)
            VALUES (?, ?, ?, CASE WHEN ? = 1 AND NOT EXISTS (SELECT 1 FROM security_invariants WHERE key = 'admin_bootstrap') THEN 'admin' ELSE 'auditor' END)`)
            .bind(id, email, displayName, configuredAdmins.has(email) ? 1 : 0),
          env.DB.prepare(`INSERT OR IGNORE INTO security_invariants (key, value)
            SELECT 'admin_bootstrap', id FROM users WHERE id = ? AND role = 'admin'`).bind(id),
          env.DB.prepare(`INSERT INTO audit_events (id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature, hmac_key_id)
            SELECT ?, ?, ?, ?, 'user.bootstrap_admin_granted', 'user', ?, ?, ?, ?, ?, ?
            WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND role = 'admin')
              AND NOT EXISTS (SELECT 1 FROM audit_events WHERE action = 'user.bootstrap_admin_granted' AND resource_type = 'user' AND resource_id = ?)`)
            .bind(auditId, occurredAt, id, email, id, stableJson(details), previousHash, eventHash, signature, hmacKeyId, id, id),
        ]);
        break;
      } catch (error) {
        if (attempt === 2 || !String(error).includes("audit chain head changed")) throw error;
      }
    }
    existing = await env.DB.prepare("SELECT id, email, display_name, role FROM users WHERE id = ?").bind(id).first<{ id: string; email: string; display_name: string; role: Role }>();
    if (!existing) throw responseError(409, "The authenticated identity conflicts with an existing account.");
  } else {
    await env.DB.prepare("UPDATE users SET email = ?, display_name = ?, last_seen_at = CURRENT_TIMESTAMP WHERE id = ?").bind(email, decodeName(request) || existing.display_name, id).run();
  }
  const user: AuthenticatedUser = { id, email, displayName: decodeName(request) || existing.display_name, role: existing.role };
  if (roleRank[user.role] < roleRank[minimumRole]) throw responseError(403, "Insufficient role");
  return user;
}

export async function requireApiPermission(request: Request, permission: Permission): Promise<AuthenticatedUser> {
  const actor = await requireApiUser(request);
  assertPermission(actor, permission);
  return actor;
}

export function requireSameOrigin(request: Request): void {
  assertTrustedRequestOrigin(request);
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  if (origin !== new URL(request.url).origin || (fetchSite && fetchSite !== "same-origin")) throw responseError(403, "Same-origin mutation proof is required.");
}

export function jsonError(error: unknown): Response {
  if (error instanceof Response) return error;
  const requestId = crypto.randomUUID();
  console.error("scopeproof_api_error", { requestId, error: error instanceof Error ? error.message : String(error) });
  return Response.json({ error: "Request failed", requestId }, { status: 500 });
}
