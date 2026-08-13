import { jsonError, requireApiUser } from "../../../lib/server/auth";
import { verifyAuditChain } from "../../../lib/server/audit";
import { getLatestAuditCheckpoint } from "../../../lib/server/checkpoints";
import { getEnv } from "../../../lib/server/env";
import { enforceRateLimit } from "../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try {
    const actor = await requireApiUser(request, "auditor");
    await enforceRateLimit(request, actor.id, "audit:verify", 10, 60);
    const events = (await getEnv().DB.prepare("SELECT sequence, id, occurred_at, actor_email, action, resource_type, resource_id, details_json, previous_hash, event_hash, signature, hmac_key_id FROM audit_events ORDER BY sequence DESC LIMIT 250").all<Record<string, unknown>>()).results;
    return Response.json({ integrity: await verifyAuditChain(), checkpoint: await getLatestAuditCheckpoint(), events: events.map((event: Record<string, unknown>) => {
      const { details_json: detailsJson, ...fields } = event;
      try { return { ...fields, details: JSON.parse(String(detailsJson || "{}")) }; }
      catch { return { ...fields, details: null, detailsError: "Stored audit details are not valid JSON." }; }
    }) });
  } catch (error) { return jsonError(error); }
}
