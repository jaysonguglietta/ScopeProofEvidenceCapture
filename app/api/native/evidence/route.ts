import { appendAuditEvent } from "../../../../lib/server/audit";
import { assertPermission, jsonError } from "../../../../lib/server/auth";
import { sha256, signPackage, stableJson } from "../../../../lib/server/crypto";
import { requireCaptureDevice } from "../../../../lib/server/devices";
import { storeEvidence } from "../../../../lib/server/evidence";
import { getEnv } from "../../../../lib/server/env";
import { NativeManifestError, parseNativeManifest, validatePng } from "../../../../lib/server/native-manifest";
import { requestTrustedTimestamp } from "../../../../lib/server/timestamp";

export async function POST(request: Request) {
  try {
    const { device, actor, verifyUploadSignature } = await requireCaptureDevice(request);
    assertPermission(actor, "collect_evidence");
    const contentLength = Number(request.headers.get("content-length") || 0);
    if (!Number.isFinite(contentLength) || contentLength <= 0 || contentLength > 16 * 1024 * 1024) return Response.json({ error: "Capture payload size is invalid." }, { status: 413 });
    const form = await request.formData();
    if (Array.from(form.keys()).some((name) => name !== "screenshot" && name !== "manifest")) return Response.json({ error: "Capture metadata must come only from the signed manifest." }, { status: 422 });
    const screenshot = form.get("screenshot");
    const manifestFile = form.get("manifest");
    if (!(screenshot instanceof File) || !(manifestFile instanceof File)) return Response.json({ error: "Screenshot and manifest files are required." }, { status: 400 });
    if (screenshot.size < 100 || screenshot.size > 15 * 1024 * 1024 || manifestFile.size > 256 * 1024) return Response.json({ error: "Capture payload size is invalid." }, { status: 413 });
    const image = new Uint8Array(await screenshot.arrayBuffer());
    const manifestBytes = new Uint8Array(await manifestFile.arrayBuffer());
    const manifest = parseNativeManifest(manifestBytes);
    if (screenshot.type !== "image/png" || manifestFile.type !== "application/json" || screenshot.name !== manifest.screenshotFilename) return Response.json({ error: "Capture filenames or content types do not match the manifest." }, { status: 422 });
    const dimensions = await validatePng(image);
    if (dimensions.width !== manifest.pixelWidth || dimensions.height !== manifest.pixelHeight) return Response.json({ error: "Screenshot dimensions do not match the manifest." }, { status: 422 });
    const imageDigest = await sha256(image);
    if (manifest.sha256 !== imageDigest) return Response.json({ error: "Screenshot integrity does not match its manifest." }, { status: 422 });
    const manifestSha256 = await sha256(manifestBytes);
    const signature = String(request.headers.get("x-scopeproof-upload-signature") || "").trim().toLowerCase();
    if (!await verifyUploadSignature(manifestSha256, imageDigest, signature)) return Response.json({ error: "Capture manifest signature is invalid." }, { status: 401 });
    const expectedChainHash = await sha256(`${manifest.chainPreviousHash}|${imageDigest}|${manifest.evidenceID}|${manifest.capturedAt}|${manifest.sessionID}`);
    if (manifest.chainEventHash !== expectedChainHash) return Response.json({ error: "Capture-chain event does not match the signed manifest." }, { status: 422 });
    const { complianceArea, controlID: controlId, system, title, environment, assessmentPeriod, evidenceOwner, catalogVersion, expectedEvidence, jiraIssueKey, jiraIssueURL, manualRedactions, tags, mappedControls, sessionID: sessionId } = manifest;
    await getEnv().DB.prepare(`INSERT INTO capture_sessions (id, display_name, control_id, system_name, environment, assessment_period, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING`).bind(sessionId, manifest.sessionName, controlId, system, environment, assessmentPeriod, actor.id).run();
    const capturedAt = manifest.capturedAt;
    const localFindings = manifest.redactionFindings;
    const attestationBody = {
      version: 2, evidenceId: manifest.evidenceID, imageSha256: imageDigest, manifestSha256,
      chainPreviousHash: manifest.chainPreviousHash, chainEventHash: manifest.chainEventHash,
      deviceId: device.id, capturedAt, receivedAt: new Date().toISOString(), complianceArea, controlId, system, environment, assessmentPeriod,
      clientSafetyClaim: manifest.safetyStatus, manifestSchemaVersion: manifest.schemaVersion, jiraIssueKey: jiraIssueKey || null, jiraIssueURL: jiraIssueURL || null,
    };
    const signed = await signPackage(stableJson(attestationBody));
    let trustedTimestamp: Awaited<ReturnType<typeof requestTrustedTimestamp>> = null;
    let trustedTimestampError: string | null = null;
    try { trustedTimestamp = await requestTrustedTimestamp(imageDigest); } catch (error) { trustedTimestampError = error instanceof Error ? error.message.slice(0, 300) : "Timestamp authority unavailable"; }
    const timestampAuthority = trustedTimestamp?.authority || "Scopeproof signed server time";
    const timestampToken = JSON.stringify({ ...attestationBody, signature: signed.signature, publicKeySpkiBase64: signed.publicKey, algorithm: "ECDSA-P256-SHA256", trustedTimestamp, trustedTimestampError });
    const result = await storeEvidence({
      controlId, framework: complianceArea, catalogVersion, title, description: manifest.description, type: "screenshot", source: `Scopeproof Capture / ${device.displayName} / ${complianceArea}`, system,
      environment, assessmentPeriod, evidenceOwner, tags, expectedEvidence, mappedControls, jiraIssueKey, jiraIssueURL, manualRedactions,
      contentType: "image/png", bytes: image, sessionId, deviceId: device.id, capturedAt, createdBy: actor, preflightFindings: localFindings,
      manifestSha256: attestationBody.manifestSha256, chainPreviousHash: attestationBody.chainPreviousHash, chainEventHash: attestationBody.chainEventHash,
      timestampAuthority, timestampToken,
    });
    const hostedArtifact = await getEnv().DB.prepare("SELECT device_id, created_by, sha256, manifest_sha256, jira_issue_key FROM evidence_artifacts WHERE id = ?")
      .bind(result.id).first<{ device_id: string | null; created_by: string; sha256: string; manifest_sha256: string | null; jira_issue_key: string | null }>();
    if (!hostedArtifact || hostedArtifact.device_id !== device.id || hostedArtifact.created_by !== actor.id || hostedArtifact.sha256 !== imageDigest || hostedArtifact.manifest_sha256 !== attestationBody.manifestSha256 || String(hostedArtifact.jira_issue_key || "") !== jiraIssueKey) {
      return Response.json({ error: "Matching evidence already exists under different hosted provenance; the local identity was not linked." }, { status: 409 });
    }
    const manifestIdentity = `${device.id}:${manifest.evidenceID}`;
    const existingManifest = await getEnv().DB.prepare("SELECT artifact_id, manifest_sha256, image_sha256, jira_issue_key FROM native_evidence_manifests WHERE id = ?").bind(manifestIdentity).first<{ artifact_id: string; manifest_sha256: string; image_sha256: string; jira_issue_key: string | null }>();
    if (existingManifest && (existingManifest.artifact_id !== result.id || existingManifest.manifest_sha256 !== attestationBody.manifestSha256 || existingManifest.image_sha256 !== imageDigest || String(existingManifest.jira_issue_key || "") !== jiraIssueKey)) return Response.json({ error: "This local evidence identity is already bound to different hosted evidence." }, { status: 409 });
    if (!existingManifest) await getEnv().DB.prepare("INSERT INTO native_evidence_manifests (id, device_id, local_evidence_id, artifact_id, manifest_sha256, image_sha256, jira_issue_key) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(manifestIdentity, device.id, manifest.evidenceID, result.id, attestationBody.manifestSha256, imageDigest, jiraIssueKey || null).run();
    await appendAuditEvent(actor, "capture_device.uploaded", "evidence", result.id, { deviceId: device.id, sessionId, complianceArea, controlId, jiraIssueKey: jiraIssueKey || null, imageSha256: imageDigest, clientSafetyClaim: manifest.safetyStatus, redactionCount: localFindings.reduce((sum, item) => sum + item.count, 0) });
    return Response.json({ ...result, receipt: { evidenceId: result.id, deviceId: device.id, attestation: { ...attestationBody, signature: signed.signature, publicKeySpkiBase64: signed.publicKey, algorithm: "ECDSA-P256-SHA256", trustedTimestamp, trustedTimestampError } } }, { status: result.deduplicated ? 200 : 201 });
  } catch (error) {
    if (error instanceof NativeManifestError) return Response.json({ error: error.message }, { status: 422 });
    return jsonError(error);
  }
}
