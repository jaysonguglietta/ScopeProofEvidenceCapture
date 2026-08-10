import { appendAuditEvent } from "../../../../lib/server/audit";
import { jsonError } from "../../../../lib/server/auth";
import { sha256, signPackage, stableJson } from "../../../../lib/server/crypto";
import { requireCaptureDevice } from "../../../../lib/server/devices";
import { storeEvidence } from "../../../../lib/server/evidence";
import { getEnv } from "../../../../lib/server/env";
import type { RedactionFinding, RedactionKind } from "../../../../lib/server/redaction";
import { requestTrustedTimestamp } from "../../../../lib/server/timestamp";

const redactionKinds = new Set<RedactionKind>(["pan", "aws_access_key", "github_token", "api_token", "jwt", "private_key", "authorization"]);

function field(form: FormData, name: string, maximum: number): string { return String(form.get(name) || "").trim().slice(0, maximum); }

function findings(value: string): RedactionFinding[] {
  try {
    const parsed = JSON.parse(value) as Array<{ kind?: string; count?: number }>;
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item) => redactionKinds.has(item.kind as RedactionKind) && Number.isInteger(item.count) && Number(item.count) > 0)
      .map((item) => ({ kind: item.kind as RedactionKind, count: Math.min(Number(item.count), 1000) }));
  } catch { return []; }
}

export async function POST(request: Request) {
  try {
    const { device, actor } = await requireCaptureDevice(request);
    const form = await request.formData();
    const screenshot = form.get("screenshot");
    const manifestFile = form.get("manifest");
    if (!(screenshot instanceof File) || !(manifestFile instanceof File)) return Response.json({ error: "Screenshot and manifest files are required." }, { status: 400 });
    if (screenshot.size < 100 || screenshot.size > 15 * 1024 * 1024 || manifestFile.size > 256 * 1024) return Response.json({ error: "Capture payload size is invalid." }, { status: 413 });
    const image = new Uint8Array(await screenshot.arrayBuffer());
    if (image[0] !== 0x89 || image[1] !== 0x50 || image[2] !== 0x4e || image[3] !== 0x47) return Response.json({ error: "Only PNG capture evidence is accepted." }, { status: 415 });
    const manifestBytes = new Uint8Array(await manifestFile.arrayBuffer());
    let manifest: Record<string, unknown>;
    try { manifest = JSON.parse(new TextDecoder().decode(manifestBytes)) as Record<string, unknown>; } catch { return Response.json({ error: "Manifest JSON is invalid." }, { status: 400 }); }
    const imageDigest = await sha256(image);
    if (manifest.sha256 !== imageDigest) return Response.json({ error: "Screenshot integrity does not match its manifest." }, { status: 422 });
    const safetyStatus = field(form, "safetyStatus", 32);
    if (!["passed", "redacted"].includes(safetyStatus)) return Response.json({ error: "Capture must pass local sensitive-data review before upload." }, { status: 422 });
    const controlId = field(form, "controlId", 32);
    const system = field(form, "system", 180);
    const title = field(form, "title", 180);
    const environment = field(form, "environment", 80);
    const assessmentPeriod = field(form, "assessmentPeriod", 80);
    const sessionId = field(form, "sessionId", 96);
    if (!controlId || !system || !title || !environment || !assessmentPeriod || !sessionId) return Response.json({ error: "Control, system, title, environment, assessment period, and session are required." }, { status: 400 });
    await getEnv().DB.prepare(`INSERT INTO capture_sessions (id, display_name, control_id, system_name, environment, assessment_period, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`).bind(sessionId, field(form, "sessionName", 160) || `${controlId} — ${system}`, controlId, system, environment, assessmentPeriod, actor.id).run();
    const capturedAt = field(form, "capturedAt", 64);
    if (!capturedAt || !Number.isFinite(Date.parse(capturedAt))) return Response.json({ error: "A valid capture timestamp is required." }, { status: 400 });
    const localFindings = findings(field(form, "redactionFindings", 10000));
    const attestationBody = {
      version: 1, evidenceId: String(manifest.evidenceID || ""), imageSha256: imageDigest, manifestSha256: await sha256(manifestBytes),
      chainPreviousHash: field(form, "chainPreviousHash", 128) || "GENESIS", chainEventHash: field(form, "chainEventHash", 128),
      deviceId: device.id, capturedAt, receivedAt: new Date().toISOString(), controlId, system, environment, assessmentPeriod,
    };
    const signed = await signPackage(stableJson(attestationBody));
    let trustedTimestamp: Awaited<ReturnType<typeof requestTrustedTimestamp>> = null;
    let trustedTimestampError: string | null = null;
    try { trustedTimestamp = await requestTrustedTimestamp(imageDigest); } catch (error) { trustedTimestampError = error instanceof Error ? error.message.slice(0, 300) : "Timestamp authority unavailable"; }
    const timestampAuthority = trustedTimestamp?.authority || "Scopeproof signed server time";
    const timestampToken = JSON.stringify({ ...attestationBody, signature: signed.signature, publicKeySpkiBase64: signed.publicKey, algorithm: "ECDSA-P256-SHA256", trustedTimestamp, trustedTimestampError });
    const result = await storeEvidence({
      controlId, title, description: field(form, "description", 2000), type: "screenshot", source: `Scopeproof Capture / ${device.displayName}`, system,
      contentType: "image/png", bytes: image, sessionId, deviceId: device.id, capturedAt, createdBy: actor, preflightFindings: localFindings,
      manifestSha256: attestationBody.manifestSha256, chainPreviousHash: attestationBody.chainPreviousHash, chainEventHash: attestationBody.chainEventHash,
      timestampAuthority, timestampToken,
    });
    await appendAuditEvent(actor, "capture_device.uploaded", "evidence", result.id, { deviceId: device.id, sessionId, imageSha256: imageDigest, safetyStatus, redactionCount: localFindings.reduce((sum, item) => sum + item.count, 0) });
    return Response.json({ ...result, receipt: { evidenceId: result.id, deviceId: device.id, attestation: { ...attestationBody, signature: signed.signature, publicKeySpkiBase64: signed.publicKey, algorithm: "ECDSA-P256-SHA256", trustedTimestamp, trustedTimestampError } } }, { status: result.deduplicated ? 200 : 201 });
  } catch (error) { return jsonError(error); }
}
