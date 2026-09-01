import { activeAuditKeyId, hmac, randomId, sha256, stableJson } from "./crypto";
import { getEnv } from "./env";
import { validateBootstrapAdministratorAllowlist, validateTrustedApplicationOrigins } from "./identity-config";

export { validateBootstrapAdministratorAllowlist, validateTrustedApplicationOrigins } from "./identity-config";

export type Role = "admin" | "compliance_lead" | "reviewer" | "auditor";
export type Permission = "approve_evidence" | "collect_evidence" | "generate_sbom" | "manage_collectors" | "manage_devices" | "manage_jira" | "manage_findings" | "dispose_findings" | "export_packages" | "manage_users" | "manage_retention";
export type AuthenticatedUser = { id: string; email: string; displayName: string; role: Role };

const roleRank: Record<Role, number> = { auditor: 0, reviewer: 1, compliance_lead: 2, admin: 3 };
const rolePermissions: Record<Role, ReadonlySet<Permission>> = {
  auditor: new Set(),
  reviewer: new Set(["approve_evidence", "manage_findings", "export_packages"]),
  compliance_lead: new Set(["collect_evidence", "generate_sbom", "manage_collectors", "manage_devices", "manage_jira", "manage_findings", "dispose_findings", "export_packages"]),
  admin: new Set(["approve_evidence", "collect_evidence", "generate_sbom", "manage_collectors", "manage_devices", "manage_jira", "manage_findings", "dispose_findings", "export_packages", "manage_users", "manage_retention"]),
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
  try { return validateTrustedApplicationOrigins(getEnv().TRUSTED_APP_ORIGINS); }
  catch (error) { throw responseError(503, error instanceof Error ? error.message : "Trusted application origins are not safely configured."); }
}

export function assertTrustedRequestOrigin(request: Request): void {
  if (getEnv().LEGACY_SINGLE_TENANT_ACKNOWLEDGEMENT !== "single-tenant-only") throw responseError(503, "The legacy runtime is disabled until its single-tenant isolation boundary is explicitly acknowledged.");
  const requestOrigin = new URL(request.url).origin;
  if (!configuredOrigins().has(requestOrigin)) throw responseError(421, "This origin is not authorized for Scopeproof identity headers.");
}

function bootstrapAdmins(): Set<string> {
  try { return validateBootstrapAdministratorAllowlist(getEnv().BOOTSTRAP_ADMIN_EMAILS); }
  catch (error) { throw responseError(503, error instanceof Error ? error.message : "Administrator bootstrap allowlist is not safely configured."); }
}

export function assertPermission(actor: AuthenticatedUser, permission: Permission): void {
  if (!rolePermissions[actor.role].has(permission)) throw responseError(403, `Permission ${permission} is required.`);
}

export async function loadActiveUser(id: string): Promise<AuthenticatedUser | null> {
  const row = await getEnv().DB.prepare("SELECT id, email, display_name, role, status FROM users WHERE id = ?").bind(id).first<{ id: string; email: string; display_name: string; role: Role; status: string }>();
  if (!row || row.status !== "active") return null;
  return { id: row.id, email: row.email, displayName: row.display_name, role: row.role };
}

export async function requireApiUser(request: Request, minimumRole: Role = "auditor"): Promise<AuthenticatedUser> {
  assertTrustedRequestOrigin(request);
  const id = String(request.headers.get("oai-authenticated-user-id") || "").trim();
  const email = String(request.headers.get("oai-authenticated-user-email") || "").trim().toLowerCase();
  if (!/^[A-Za-z0-9_.:-]{3,200}$/.test(id) || email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw responseError(401, "Authentication required");
  const env = getEnv();
  const configuredAdmins = bootstrapAdmins();
  let existing = await env.DB.prepare("SELECT id, email, display_name, role, status FROM users WHERE id = ?").bind(id).first<{ id: string; email: string; display_name: string; role: Role; status: string }>();
  if (!existing) {
    const displayName = decodeName(request) || email;
    const invitation = await env.DB.prepare(`SELECT id, role, invited_by FROM user_invitations
      WHERE email = ? AND status = 'pending' AND expires_at > ? ORDER BY created_at DESC LIMIT 1`)
      .bind(email, new Date().toISOString()).first<{ id: string; role: Role; invited_by: string }>();
    const bootstrapEligible = configuredAdmins.has(email) && !(await env.DB.prepare("SELECT 1 FROM security_invariants WHERE key = 'admin_bootstrap'").first());
    if (!invitation && !bootstrapEligible) throw responseError(403, "An active Scopeproof invitation is required.");
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const previous = await env.DB.prepare("SELECT event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1").first<{ event_hash: string }>();
      const auditId = randomId("evt");
      const occurredAt = new Date().toISOString();
      const previousHash = previous?.event_hash || "GENESIS";
      const action = invitation ? "user.invitation_accepted" : "user.bootstrap_admin_granted";
      const details = invitation ? { email, invitationId: invitation.id, invitedBy: invitation.invited_by, role: invitation.role } : { email, method: "explicit_allowlist" };
      const canonical = stableJson({ id: auditId, occurredAt, actorId: id, actorEmail: email, action, resourceType: "user", resourceId: id, details, previousHash });
      const eventHash = await sha256(canonical);
      const hmacKeyId = activeAuditKeyId();
      const signature = await hmac(eventHash, hmacKeyId);
      try {
        const mutations: D1PreparedStatement[] = invitation ? [
          env.DB.prepare(`INSERT OR IGNORE INTO users (id, email, display_name, role, status, invited_by)
            SELECT ?, ?, ?, role, 'active', invited_by FROM user_invitations
            WHERE id = ? AND email = ? AND status = 'pending' AND expires_at > ?`)
            .bind(id, email, displayName, invitation.id, email, occurredAt),
          env.DB.prepare(`UPDATE user_invitations SET status = 'accepted', accepted_user_id = ?, accepted_at = ?
            WHERE id = ? AND email = ? AND status = 'pending' AND expires_at > ?
              AND EXISTS (SELECT 1 FROM users WHERE id = ? AND email = ? AND status = 'active')`)
            .bind(id, occurredAt, invitation.id, email, occurredAt, id, email),
        ] : [
          env.DB.prepare(`INSERT OR IGNORE INTO users (id, email, display_name, role, status)
            SELECT ?, ?, ?, 'admin', 'active' WHERE NOT EXISTS (SELECT 1 FROM security_invariants WHERE key = 'admin_bootstrap')`)
            .bind(id, email, displayName),
          env.DB.prepare(`INSERT OR IGNORE INTO security_invariants (key, value)
            SELECT 'admin_bootstrap', id FROM users WHERE id = ? AND role = 'admin'`).bind(id),
        ];
        await env.DB.batch([
          ...mutations,
          env.DB.prepare(`INSERT INTO audit_events (id, occurred_at, actor_id, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature, hmac_key_id)
            SELECT ?, ?, ?, ?, ?, 'user', ?, ?, ?, ?, ?, ?
            WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND status = 'active')
              AND NOT EXISTS (SELECT 1 FROM audit_events WHERE action = ? AND resource_type = 'user' AND resource_id = ?)`)
            .bind(auditId, occurredAt, id, email, action, id, stableJson(details), previousHash, eventHash, signature, hmacKeyId, id, action, id),
        ]);
        break;
      } catch (error) {
        if (attempt === 2 || !String(error).includes("audit chain head changed")) throw error;
      }
    }
    existing = await env.DB.prepare("SELECT id, email, display_name, role, status FROM users WHERE id = ?").bind(id).first<{ id: string; email: string; display_name: string; role: Role; status: string }>();
    if (!existing) throw responseError(409, "The invitation or administrator bootstrap claim could not be completed.");
  } else {
    if (existing.status !== "active") throw responseError(403, "This Scopeproof membership is not active.");
    await env.DB.prepare("UPDATE users SET email = ?, display_name = ?, last_seen_at = CURRENT_TIMESTAMP WHERE id = ?").bind(email, decodeName(request) || existing.display_name, id).run();
  }
  if (existing.status !== "active") throw responseError(403, "This Scopeproof membership is not active.");
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
