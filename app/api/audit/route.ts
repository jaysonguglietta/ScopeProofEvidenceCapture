import { jsonError, requireApiUser } from "../../../lib/server/auth";
import { verifyAuditChain } from "../../../lib/server/audit";
import { getEnv } from "../../../lib/server/env";

export async function GET(request: Request) {
  try {
    await requireApiUser(request, "auditor");
    const events = (await getEnv().DB.prepare("SELECT sequence, id, occurred_at, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature FROM audit_events ORDER BY sequence DESC LIMIT 250").all<Record<string, unknown>>()).results;
    return Response.json({ integrity: await verifyAuditChain(), events: events.map((event: Record<string, unknown>) => {
      const { details_json: detailsJson, ...fields } = event;
      try { return { ...fields, details: JSON.parse(String(detailsJson || "{}")) }; }
      catch { return { ...fields, details: null, detailsError: "Stored audit details are not valid JSON." }; }
    }) });
  } catch (error) { return jsonError(error); }
}
