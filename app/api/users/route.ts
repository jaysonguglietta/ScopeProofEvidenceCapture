import { appendAuditEvent } from "../../../lib/server/audit";
import { jsonError, requireApiPermission, requireApiUser, requireSameOrigin, type Role } from "../../../lib/server/auth";
import { getEnv } from "../../../lib/server/env";

const roles: Role[] = ["admin", "compliance_lead", "reviewer", "auditor"];

export async function GET(request: Request) {
  try {
    await requireApiUser(request, "compliance_lead");
    const users = (await getEnv().DB.prepare("SELECT id, email, display_name, role, created_at, last_seen_at FROM users ORDER BY email").all<Record<string, unknown>>()).results;
    return Response.json({ users });
  } catch (error) { return jsonError(error); }
}

export async function PATCH(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_users");
    const body = await request.json() as { userId?: string; role?: Role };
    if (!body.userId || !body.role || !roles.includes(body.role)) return Response.json({ error: "A valid user and role are required." }, { status: 400 });
    const target = await getEnv().DB.prepare("SELECT id, email, role FROM users WHERE id = ?").bind(body.userId).first<{ id: string; email: string; role: Role }>();
    if (!target) return Response.json({ error: "User not found" }, { status: 404 });
    if (target.role === "admin" && body.role !== "admin") {
      const admins = await getEnv().DB.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").first<{ count: number }>();
      if (Number(admins?.count || 0) <= 1) return Response.json({ error: "The final administrator cannot be demoted." }, { status: 409 });
    }
    await getEnv().DB.prepare("UPDATE users SET role = ? WHERE id = ?").bind(body.role, body.userId).run();
    await appendAuditEvent(actor, "user.role_changed", "user", body.userId, { email: target.email, previousRole: target.role, newRole: body.role });
    return Response.json({ updated: true });
  } catch (error) { return jsonError(error); }
}
