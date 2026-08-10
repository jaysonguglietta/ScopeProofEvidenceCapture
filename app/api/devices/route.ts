import { jsonError, requireApiUser, requireSameOrigin } from "../../../lib/server/auth";
import { createCaptureDevice, listCaptureDevices, revokeCaptureDevice } from "../../../lib/server/devices";

export async function GET(request: Request) {
  try { return Response.json({ devices: await listCaptureDevices(await requireApiUser(request, "reviewer")) }); }
  catch (error) { return jsonError(error); }
}

export async function POST(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiUser(request, "reviewer");
    const body = await request.json() as { displayName?: string };
    const displayName = String(body.displayName || "").trim().slice(0, 100);
    if (!displayName) return Response.json({ error: "A device name is required." }, { status: 400 });
    return Response.json(await createCaptureDevice(actor, displayName), { status: 201 });
  } catch (error) { return jsonError(error); }
}

export async function DELETE(request: Request) {
  try {
    requireSameOrigin(request);
    const actor = await requireApiUser(request, "reviewer");
    const body = await request.json() as { id?: string };
    if (!body.id) return Response.json({ error: "A device id is required." }, { status: 400 });
    return Response.json({ revoked: await revokeCaptureDevice(actor, body.id) });
  } catch (error) { return jsonError(error); }
}
