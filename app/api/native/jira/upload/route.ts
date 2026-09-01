import { jsonError } from "../../../../../lib/server/auth";
import { sha256 } from "../../../../../lib/server/crypto";
import { requireCaptureDevice } from "../../../../../lib/server/devices";
import { getEnv } from "../../../../../lib/server/env";
import { evidenceSafetyReceiptSha256 } from "../../../../../lib/server/image-safety";
import { assertJiraOperator, normalizeJiraIssueKey, uploadJiraEvidence } from "../../../../../lib/server/jira";
import { NativeManifestError, parseNativeManifest, validatePng } from "../../../../../lib/server/native-manifest";
import { enforceRateLimit, requireBoundedContentLength } from "../../../../../lib/server/rate-limit";

type LifecycleEvent = { sequence?: unknown; occurredAt?: unknown; actor?: unknown; action?: unknown; note?: unknown; previousHash?: unknown; eventHash?: unknown };
type Lifecycle = { evidenceID?: unknown; status?: unknown; events?: unknown };

function jsonFile(form: FormData, name: string, maximum: number): File | null {
  const value = form.get(name);
  return value instanceof File && safeFile(value, maximum, ["application/json"]) ? value : null;
}

function safeFile(file: File, maximum: number, allowedTypes: string[]): boolean {
  const unsafeName = file.name.includes("/") || file.name.includes("\\") || Array.from(file.name).some((character) => character.charCodeAt(0) < 32);
  return file.size > 1 && file.size <= maximum && allowedTypes.includes(file.type) && file.name.length <= 240 && !unsafeName;
}

async function parseJson<T>(file: File): Promise<T | null> {
  try { return JSON.parse(await file.text()) as T; } catch { return null; }
}

async function verifyLifecycle(record: Lifecycle, evidenceId: string): Promise<boolean> {
  if (record.evidenceID !== evidenceId || record.status !== "Approved" || !Array.isArray(record.events) || !record.events.length || record.events.length > 1_000) return false;
  let previous = "GENESIS";
  for (let index = 0; index < record.events.length; index += 1) {
    const event = record.events[index] as LifecycleEvent;
    if (event.sequence !== index + 1 || event.previousHash !== previous || typeof event.occurredAt !== "string" || typeof event.actor !== "string" || typeof event.action !== "string" || typeof event.note !== "string" || typeof event.eventHash !== "string") return false;
    const expected = await sha256(`${previous}|${evidenceId}|${event.sequence}|${event.occurredAt}|${event.actor}|${event.action}|${event.note}`);
    if (event.eventHash !== expected) return false;
    previous = event.eventHash;
  }
  return (record.events.at(-1) as LifecycleEvent).action === "status.approved";
}

export async function POST(request: Request) {
  try {
    const { device, actor, verifyUploadSignature } = await requireCaptureDevice(request);
    assertJiraOperator(actor);
    await enforceRateLimit(request, device.id, "native-jira-upload", 20, 3_600);
    requireBoundedContentLength(request, 17 * 1024 * 1024);
    const form = await request.formData();
    const screenshot = form.get("screenshot");
    const manifestFile = jsonFile(form, "manifest", 256 * 1024);
    const lifecycleFile = jsonFile(form, "lifecycle", 256 * 1024);
    if (!(screenshot instanceof File) || !safeFile(screenshot, 15 * 1024 * 1024, ["image/png"]) || !manifestFile || !lifecycleFile) return Response.json({ error: "A PNG, capture manifest, and approved lifecycle file are required." }, { status: 400 });
    const [manifestBytes, lifecycle] = await Promise.all([manifestFile.arrayBuffer().then((bytes) => new Uint8Array(bytes)), parseJson<Lifecycle>(lifecycleFile)]);
    const manifest = parseNativeManifest(manifestBytes);
    if (!lifecycle) return Response.json({ error: "Evidence lifecycle is invalid JSON." }, { status: 400 });
    const evidenceId = manifest.evidenceID;
    const issueKey = normalizeJiraIssueKey(manifest.jiraIssueKey);
    if (!/^EV-[A-Z0-9]{10,32}$/.test(evidenceId) || !issueKey) return Response.json({ error: "The immutable manifest must contain a valid evidence ID and Jira issue key." }, { status: 422 });
    if (!['passed', 'redacted'].includes(manifest.safetyStatus)) return Response.json({ error: "Only evidence that passed local sensitive-data review can be sent to Jira." }, { status: 422 });
    if (manifest.screenshotFilename !== screenshot.name) return Response.json({ error: "The screenshot filename does not match its immutable manifest." }, { status: 422 });
    const imageBytes = new Uint8Array(await screenshot.arrayBuffer());
    const dimensions = await validatePng(imageBytes);
    if (dimensions.width !== manifest.pixelWidth || dimensions.height !== manifest.pixelHeight) return Response.json({ error: "Screenshot dimensions do not match its immutable manifest." }, { status: 422 });
    const imageSha256 = await sha256(imageBytes);
    const manifestSha256 = await sha256(manifestBytes);
    if (imageSha256 !== manifest.sha256) return Response.json({ error: "Screenshot integrity does not match its immutable manifest." }, { status: 422 });
    const signature = String(request.headers.get("x-scopeproof-upload-signature") || "").trim().toLowerCase();
    if (!await verifyUploadSignature(manifestSha256, imageSha256, signature)) return Response.json({ error: "Capture manifest signature is invalid." }, { status: 401 });
    if (!await verifyLifecycle(lifecycle, evidenceId)) return Response.json({ error: "Evidence must have a valid hash-chained Approved lifecycle record." }, { status: 422 });
    const hosted = await getEnv().DB.prepare(`SELECT e.id, e.status, e.timestamp_token, e.server_safety_scan_sha256,
        e.server_safety_scan_policy, e.server_safety_scan_completed_at, e.server_safety_scanner_origin, e.server_safety_receipt_sha256
      FROM native_evidence_manifests n
      JOIN evidence_artifacts e ON e.id = n.artifact_id
      JOIN capture_devices d ON d.id = n.device_id
      WHERE n.device_id = ? AND n.local_evidence_id = ? AND n.image_sha256 = ? AND n.manifest_sha256 = ? AND n.jira_issue_key = ?
        AND e.device_id = n.device_id AND e.created_by = ? AND e.sha256 = n.image_sha256 AND e.manifest_sha256 = n.manifest_sha256
        AND e.jira_issue_key = n.jira_issue_key AND e.expires_at > ?
        AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash
        AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence
        AND e.server_safety_scan_sha256 = e.sha256 AND e.server_safety_scan_policy IS NOT NULL AND e.server_safety_scan_completed_at IS NOT NULL
        AND e.server_safety_scanner_origin IS NOT NULL AND e.server_safety_receipt_sha256 IS NOT NULL`)
      .bind(device.id, evidenceId, imageSha256, manifestSha256, issueKey, actor.id, new Date().toISOString()).first<{ id: string; status: string; timestamp_token: string | null; server_safety_scan_sha256: string; server_safety_scan_policy: string; server_safety_scan_completed_at: string; server_safety_scanner_origin: string; server_safety_receipt_sha256: string }>();
    if (!hosted) return Response.json({ error: "Upload this exact evidence set to Scopeproof before sending it to Jira Cloud." }, { status: 409 });
    const hostedSafetyReceipt = await evidenceSafetyReceiptSha256({
      digest: hosted.server_safety_scan_sha256, policy: hosted.server_safety_scan_policy,
      completedAt: hosted.server_safety_scan_completed_at, scannerOrigin: hosted.server_safety_scanner_origin,
    });
    if (hostedSafetyReceipt !== hosted.server_safety_receipt_sha256) return Response.json({ error: "The hosted screenshot safety receipt is invalid. Re-upload and re-review the evidence before Jira disclosure." }, { status: 409 });
    if (hosted.status !== "approved") return Response.json({ error: "An authenticated Scopeproof reviewer must approve the hosted evidence before Jira disclosure." }, { status: 409 });
    if (!hosted.timestamp_token || hosted.timestamp_token.length > 256 * 1024) return Response.json({ error: "The hosted evidence is missing a valid signed Scopeproof attestation." }, { status: 409 });
    const signedAttestation = new File([hosted.timestamp_token], `${evidenceId}.receipt.json`, { type: "application/json" });
    const files = [screenshot, manifestFile, lifecycleFile, signedAttestation];
    const receipt = await uploadJiraEvidence(actor, device.id, evidenceId, issueKey, files);
    return Response.json({ receipt }, { status: 201 });
  } catch (error) {
    if (error instanceof NativeManifestError) return Response.json({ error: error.message }, { status: 422 });
    return jsonError(error);
  }
}
