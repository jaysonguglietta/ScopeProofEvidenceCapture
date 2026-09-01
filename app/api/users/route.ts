import { executeAuditedBatch } from "../../../lib/server/audit";
import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin, type Role } from "../../../lib/server/auth";
import { randomId } from "../../../lib/server/crypto";
import { getEnv } from "../../../lib/server/env";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";

const roles: Role[] = ["admin", "compliance_lead", "reviewer", "auditor"];
const statuses = ["active", "suspended", "revoked"] as const;

export async function GET(request: Request) {
  try {
    const actor = await requireApiUser(request, "compliance_lead");
    await enforceRateLimit(request, actor.id, "user:list", 120, 60);
    const users = (await getEnv().DB.prepare("SELECT id, email, display_name, role, status, invited_by, created_at, last_seen_at FROM users ORDER BY email").all<Record<string, unknown>>()).results;
    const invitations = actor.role === "admin" ? (await getEnv().DB.prepare("SELECT id, email, role, status, invited_by, expires_at, accepted_user_id, created_at, accepted_at, revoked_at FROM user_invitations ORDER BY created_at DESC LIMIT 100").all<Record<string, unknown>>()).results : [];
    return Response.json({ users, invitations });
  } catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_users");
    await enforceRateLimit(request, actor.id, "user:invite", 20, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const body = await request.json() as Record<string, unknown>;
    if (Object.keys(body).some((key) => !["email", "role", "expiresInDays"].includes(key))) return Response.json({ error: "Invitation contains unsupported fields." }, { status: 400 });
    const email = String(body.email || "").trim().toLowerCase();
    const role = String(body.role || "auditor") as Role;
    const expiresInDays = Number(body.expiresInDays ?? 7);
    if (email.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !roles.includes(role) || !Number.isInteger(expiresInDays) || expiresInDays < 1 || expiresInDays > 30) {
      return Response.json({ error: "Enter a valid email, role, and expiration between 1 and 30 days." }, { status: 400 });
    }
    const existingMember = await getEnv().DB.prepare("SELECT status FROM users WHERE email = ?").bind(email).first<{ status: string }>();
    if (existingMember) return Response.json({ error: existingMember.status === "revoked" ? "That identity was permanently revoked. Use a different verified identity for a new membership." : "That person already has an active or suspended membership." }, { status: 409 });
    if (await getEnv().DB.prepare("SELECT 1 FROM user_invitations WHERE email = ? AND status = 'pending' AND expires_at > ?").bind(email, new Date().toISOString()).first()) return Response.json({ error: "A pending invitation already exists for that email." }, { status: 409 });
    const id = randomId("invite");
    const expiresAt = new Date(Date.now() + expiresInDays * 86_400_000).toISOString();
    await executeAuditedBatch(actor, "user.invited", "user_invitation", id, { email, role, expiresAt }, [
      getEnv().DB.prepare("UPDATE user_invitations SET status = 'expired' WHERE email = ? AND status = 'pending' AND expires_at <= ?").bind(email, new Date().toISOString()),
      getEnv().DB.prepare("INSERT INTO user_invitations (id, email, role, status, invited_by, expires_at) VALUES (?, ?, ?, 'pending', ?, ?)").bind(id, email, role, actor.id, expiresAt),
    ]);
    return Response.json({ invitation: { id, email, role, status: "pending", invited_by: actor.id, expires_at: expiresAt } }, { status: 201 });
  } catch (error) { return jsonError(error); }
}

export async function PATCH(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_users");
    await enforceRateLimit(request, actor.id, "user:role", 30, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const body = await request.json() as { userId?: string; role?: Role; status?: typeof statuses[number] };
    if (!body.userId || (!body.role && !body.status) || (body.role && !roles.includes(body.role)) || (body.status && !statuses.includes(body.status))) return Response.json({ error: "A valid user and role or status are required." }, { status: 400 });
    if (Object.keys(body).some((key) => !["userId", "role", "status"].includes(key))) return Response.json({ error: "Membership update contains unsupported fields." }, { status: 400 });
    const target = await getEnv().DB.prepare("SELECT id, email, role, status FROM users WHERE id = ?").bind(body.userId).first<{ id: string; email: string; role: Role; status: typeof statuses[number] }>();
    if (!target) return Response.json({ error: "User not found" }, { status: 404 });
    if (target.status === "revoked") return Response.json({ error: "Revocation is permanent. Create a membership for a different verified identity instead." }, { status: 409 });
    const nextRole = body.role || target.role;
    const nextStatus = body.status || target.status;
    if (target.id === actor.id && nextStatus !== "active") return Response.json({ error: "Use another administrator to suspend or revoke your membership." }, { status: 409 });
    if (target.role === "admin" && target.status === "active" && (nextRole !== "admin" || nextStatus !== "active")) {
      const admins = await getEnv().DB.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND status = 'active'").first<{ count: number }>();
      if (Number(admins?.count || 0) <= 1) return Response.json({ error: "The final administrator cannot be demoted." }, { status: 409 });
    }
    const revokedAt = nextStatus === "revoked" ? new Date().toISOString() : null;
    const mutations: D1PreparedStatement[] = [
      getEnv().DB.prepare("UPDATE users SET role = ?, status = ? WHERE id = ? AND role = ? AND status = ?").bind(nextRole, nextStatus, body.userId, target.role, target.status),
    ];
    if (revokedAt) {
      mutations.push(
        getEnv().DB.prepare("UPDATE capture_devices SET status = 'revoked', revoked_at = ?, token_hash = 'revoked:' || id || ':' || ? WHERE owner_id = ? AND status = 'active'").bind(revokedAt, revokedAt, body.userId),
        getEnv().DB.prepare("DELETE FROM jira_oauth_states WHERE user_id = ?").bind(body.userId),
        getEnv().DB.prepare("DELETE FROM jira_connections WHERE user_id = ?").bind(body.userId),
        getEnv().DB.prepare("UPDATE user_invitations SET status = 'revoked', revoked_at = ? WHERE email = ? AND status = 'pending'").bind(revokedAt, target.email),
      );
    }
    const [result] = await executeAuditedBatch(actor, "user.membership_changed", "user", body.userId, {
      email: target.email, previousRole: target.role, newRole: nextRole, previousStatus: target.status, newStatus: nextStatus,
      dependentCredentialsInvalidated: Boolean(revokedAt),
    }, mutations, { sql: "EXISTS (SELECT 1 FROM users WHERE id = ? AND role = ? AND status = ?)", bindings: [body.userId, nextRole, nextStatus] });
    if (!result.meta.changes) return Response.json({ error: "The user's role changed concurrently. Reload and try again." }, { status: 409 });
    return Response.json({ updated: true });
  } catch (error) { return jsonError(error); }
}

export async function DELETE(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_users");
    await enforceRateLimit(request, actor.id, "user:invite:revoke", 30, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const body = await request.json() as { invitationId?: string };
    if (!body.invitationId || !/^invite_[a-f0-9]{32}$/.test(body.invitationId) || Object.keys(body).some((key) => key !== "invitationId")) return Response.json({ error: "A valid invitation is required." }, { status: 400 });
    const invitation = await getEnv().DB.prepare("SELECT id, email, role, status FROM user_invitations WHERE id = ?").bind(body.invitationId).first<{ id: string; email: string; role: Role; status: string }>();
    if (!invitation) return Response.json({ error: "Invitation not found." }, { status: 404 });
    if (invitation.status !== "pending") return Response.json({ error: "Only pending invitations can be revoked." }, { status: 409 });
    const revokedAt = new Date().toISOString();
    const [result] = await executeAuditedBatch(actor, "user.invitation_revoked", "user_invitation", invitation.id, { email: invitation.email, role: invitation.role }, [
      getEnv().DB.prepare("UPDATE user_invitations SET status = 'revoked', revoked_at = ? WHERE id = ? AND status = 'pending'").bind(revokedAt, invitation.id),
    ], { sql: "EXISTS (SELECT 1 FROM user_invitations WHERE id = ? AND status = 'revoked' AND revoked_at = ?)", bindings: [invitation.id, revokedAt] });
    if (!result.meta.changes) return Response.json({ error: "Invitation changed concurrently. Reload and try again." }, { status: 409 });
    return Response.json({ revoked: true });
  } catch (error) { return jsonError(error); }
}
