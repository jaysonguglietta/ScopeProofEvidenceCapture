import { jsonError, requireApiPermission, requireSameOrigin } from "../../../lib/server/auth";
import { createCaptureDevice, listCaptureDevices, revokeCaptureDevice, rotateCaptureDeviceToken } from "../../../lib/server/devices";
import { enforceRateLimit, requireBoundedContentLength } from "../../../lib/server/rate-limit";

export async function GET(request: Request) {
  try { const actor = await requireApiPermission(request, "manage_devices"); await enforceRateLimit(request, actor.id, "device:list", 120, 60); return Response.json({ devices: await listCaptureDevices(actor) }); }
  catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_devices");
    await enforceRateLimit(request, actor.id, "device:enroll", 20, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const body = await request.json() as { displayName?: string };
    const displayName = String(body.displayName || "").trim().slice(0, 100);
    if (!displayName) return Response.json({ error: "A device name is required." }, { status: 400 });
    return Response.json(await createCaptureDevice(actor, displayName), { status: 201 });
  } catch (error) { return jsonError(error); }
}

export async function DELETE(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_devices");
    await enforceRateLimit(request, actor.id, "device:revoke", 20, 3_600);
    requireBoundedContentLength(request, 8 * 1024);
    const body = await request.json() as { id?: string };
    if (!body.id) return Response.json({ error: "A device id is required." }, { status: 400 });
    return Response.json({ revoked: await revokeCaptureDevice(actor, body.id) });
  } catch (error) { return jsonError(error); }
}

export async function PATCH(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiPermission(request, "manage_devices");
    await enforceRateLimit(request, actor.id, "device:rotate", 12, 3_600);
    requireBoundedContentLength(request, 4 * 1024);
    const body = await request.json() as { id?: string };
    if (!body.id || !/^dev_[a-f0-9]{32}$/.test(body.id) || Object.keys(body).some((key) => key !== "id")) return Response.json({ error: "A valid capture device is required." }, { status: 400 });
    return Response.json(await rotateCaptureDeviceToken(actor, body.id));
  } catch (error) { return jsonError(error); }
}
