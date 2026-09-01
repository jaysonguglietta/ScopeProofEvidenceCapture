import { executeAuditedBatch } from "../../../../lib/server/audit";
import { assertPermission, jsonError } from "../../../../lib/server/auth";
import { sha256, signPackage, stableJson } from "../../../../lib/server/crypto";
import { finalizeCaptureDeviceChain, requireCaptureDevice, reserveCaptureDeviceChain } from "../../../../lib/server/devices";
import { storeEvidence } from "../../../../lib/server/evidence";
import { getEnv } from "../../../../lib/server/env";
import { NativeManifestError, parseNativeManifest, validatePng, verifyNativeManifestProvenance } from "../../../../lib/server/native-manifest";
import { requestTrustedTimestamp } from "../../../../lib/server/timestamp";
import { classifyErrorForLogging, type SafeErrorClass } from "../../../../lib/server/safe-error";
import { enforceRateLimit, requireBoundedContentLength } from "../../../../lib/server/rate-limit";
import { EvidenceSafetyScanError, scanExactEvidencePixels } from "../../../../lib/server/image-safety";
import { validateLegacyTenantBinding } from "../../../../lib/server/identity-config";

export async function POST(request: Request) {
  try {
    const { device, actor, verifyUploadSignature } = await requireCaptureDevice(request);
    assertPermission(actor, "collect_evidence");
    await enforceRateLimit(request, device.id, "native:evidence", 30, 3_600);
    requireBoundedContentLength(request, 16 * 1024 * 1024);
    const form = await request.formData();
    if (Array.from(form.keys()).some((name) => name !== "screenshot" && name !== "manifest")) return Response.json({ error: "Capture metadata must come only from the signed manifest." }, { status: 422 });
    const screenshot = form.get("screenshot");
    const manifestFile = form.get("manifest");
    if (!(screenshot instanceof File) || !(manifestFile instanceof File)) return Response.json({ error: "Screenshot and manifest files are required." }, { status: 400 });
    if (screenshot.size < 100 || screenshot.size > 15 * 1024 * 1024 || manifestFile.size > 256 * 1024) return Response.json({ error: "Capture payload size is invalid." }, { status: 413 });
    const image = new Uint8Array(await screenshot.arrayBuffer());
    const manifestBytes = new Uint8Array(await manifestFile.arrayBuffer());
    const manifest = parseNativeManifest(manifestBytes);
    let expectedBinding: ReturnType<typeof validateLegacyTenantBinding>;
    try {
      expectedBinding = validateLegacyTenantBinding(getEnv().LEGACY_TENANT_ID, getEnv().LEGACY_WORKSPACE_ID);
    } catch {
      return Response.json({ error: "Native synchronization is disabled until the isolated tenant and workspace are configured." }, { status: 503 });
    }
    if (manifest.tenantID !== expectedBinding.tenantID || manifest.workspaceID !== expectedBinding.workspaceID) {
      return Response.json({ error: "Capture tenant or workspace does not match this isolated Scopeproof deployment." }, { status: 409 });
    }
    if (screenshot.type !== "image/png" || manifestFile.type !== "application/json" || screenshot.name !== manifest.screenshotFilename) return Response.json({ error: "Capture filenames or content types do not match the manifest." }, { status: 422 });
    const dimensions = await validatePng(image);
    if (dimensions.width !== manifest.pixelWidth || dimensions.height !== manifest.pixelHeight) return Response.json({ error: "Screenshot dimensions do not match the manifest." }, { status: 422 });
    const imageDigest = await sha256(image);
    if (manifest.sha256 !== imageDigest) return Response.json({ error: "Screenshot integrity does not match its manifest." }, { status: 422 });
    if (manifest.safetyScanSha256 !== imageDigest) return Response.json({ error: "Final-image safety scan does not match the uploaded screenshot." }, { status: 422 });
    const manifestSha256 = await sha256(manifestBytes);
    const signature = String(request.headers.get("x-scopeproof-upload-signature") || "").trim().toLowerCase();
    if (!await verifyUploadSignature(manifestSha256, imageDigest, signature)) return Response.json({ error: "Capture manifest signature is invalid." }, { status: 401 });
    const expectedChainHash = await sha256(`${manifest.chainPreviousHash}|${imageDigest}|${manifest.evidenceID}|${manifest.capturedAt}|${manifest.sessionID}`);
    if (manifest.chainEventHash !== expectedChainHash) return Response.json({ error: "Capture-chain event does not match the signed manifest." }, { status: 422 });
    if (!await verifyNativeManifestProvenance(manifest)) return Response.json({ error: "The schema-8 device provenance signature is invalid." }, { status: 401 });
    const { complianceArea, controlID: controlId, system, title, environment, assessmentPeriod, evidenceOwner, catalogVersion, expectedEvidence, jiraIssueKey, jiraIssueURL, manualRedactions, tags, mappedControls, sessionID: sessionId } = manifest;
    if (!/^[A-Za-z0-9._:-]{3,96}$/.test(sessionId)) return Response.json({ error: "Capture session identifier is invalid." }, { status: 422 });
    let session = await getEnv().DB.prepare("SELECT display_name, control_id, system_name, environment, assessment_period, created_by, status FROM capture_sessions WHERE id = ?")
      .bind(sessionId).first<{ display_name: string; control_id: string; system_name: string; environment: string; assessment_period: string; created_by: string; status: string }>();
    if (!session) {
      const [inserted] = await executeAuditedBatch(actor, "capture_session.created", "capture_session", sessionId, { displayName: manifest.sessionName, controlId, system, environment, assessmentPeriod }, [
        getEnv().DB.prepare(`INSERT INTO capture_sessions (id, display_name, control_id, system_name, environment, assessment_period, created_by)
          SELECT ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM capture_sessions WHERE id = ?)`)
          .bind(sessionId, manifest.sessionName, controlId, system, environment, assessmentPeriod, actor.id, sessionId),
      ], { sql: "EXISTS (SELECT 1 FROM capture_sessions WHERE id = ? AND created_by = ?)", bindings: [sessionId, actor.id] });
      if (!inserted.meta.changes) session = await getEnv().DB.prepare("SELECT display_name, control_id, system_name, environment, assessment_period, created_by, status FROM capture_sessions WHERE id = ?")
        .bind(sessionId).first<typeof session>();
      else session = { display_name: manifest.sessionName, control_id: controlId, system_name: system, environment, assessment_period: assessmentPeriod, created_by: actor.id, status: "open" };
    }
    if (!session || session.created_by !== actor.id || session.status !== "open" || session.display_name !== manifest.sessionName || session.control_id !== controlId
      || session.system_name !== system || session.environment !== environment || session.assessment_period !== assessmentPeriod) {
      return Response.json({ error: "Capture session ownership or scope does not match the signed manifest." }, { status: 409 });
    }
    const capturedAt = manifest.capturedAt;
    const localFindings = manifest.redactionFindings;
    const candidateAssessments = (await getEnv().DB.prepare(`SELECT id FROM assessments
      WHERE status = 'active' AND framework = ? AND scope_mode = 'explicit' AND catalog_id IS NOT NULL
        AND json_valid(systems_json) AND json_valid(controls_json)
        AND json_array_length(systems_json) > 0 AND json_array_length(controls_json) > 0
        AND EXISTS (SELECT 1 FROM json_each(assessments.systems_json) WHERE value = ?)
        AND EXISTS (SELECT 1 FROM json_each(assessments.controls_json) WHERE value = ?)
      ORDER BY period_end DESC, id DESC LIMIT 2`).bind(complianceArea, system, controlId).all<{ id: string }>()).results;
    if (candidateAssessments.length !== 1) return Response.json({ error: candidateAssessments.length ? "Capture matches multiple active assessments; close or narrow the overlapping scopes." : "Capture does not match an active assessment scope." }, { status: 409 });
    let serverSafetyScan: Awaited<ReturnType<typeof scanExactEvidencePixels>>;
    try { serverSafetyScan = await scanExactEvidencePixels(image, getEnv()); }
    catch (error) {
      const code = error instanceof EvidenceSafetyScanError ? error.code : "UNAVAILABLE";
      console.error("scopeproof_native_safety_scan_failed", { deviceId: device.id, evidenceId: manifest.evidenceID, code });
      if (error instanceof EvidenceSafetyScanError && error.code === "SENSITIVE_CONTENT") return Response.json({ error: error.message }, { status: 422 });
      return Response.json({ error: "Independent server-side screenshot safety verification is required and currently unavailable. The capture was not stored." }, { status: 503 });
    }
    const attestationBody = {
      version: 3, evidenceId: manifest.evidenceID, imageSha256: imageDigest, manifestSha256,
      chainPreviousHash: manifest.chainPreviousHash, chainEventHash: manifest.chainEventHash,
      chainSequence: manifest.chainSequence, provenanceKeyId: manifest.provenance.keyID,
      deviceId: device.id, capturedAt, receivedAt: new Date().toISOString(), complianceArea, controlId, system, environment, assessmentPeriod,
      clientSafetyClaim: manifest.safetyStatus, manifestSchemaVersion: manifest.schemaVersion, jiraIssueKey: jiraIssueKey || null, jiraIssueURL: jiraIssueURL || null,
      serverSafetyScan: { sha256: serverSafetyScan.digest, policyVersion: serverSafetyScan.policy, completedAt: serverSafetyScan.completedAt, scannerOrigin: serverSafetyScan.scannerOrigin, receiptSha256: serverSafetyScan.receiptSha256 },
    };
    const signed = await signPackage(stableJson(attestationBody));
    let trustedTimestamp: Awaited<ReturnType<typeof requestTrustedTimestamp>> = null;
    let trustedTimestampError: SafeErrorClass | null = null;
    try { trustedTimestamp = await requestTrustedTimestamp(imageDigest); } catch (error) { trustedTimestampError = classifyErrorForLogging(error); }
    const requireTrustedTimestamp = getEnv().REQUIRE_TRUSTED_TIMESTAMP !== "false";
    if (requireTrustedTimestamp && !trustedTimestamp) {
      console.error("scopeproof_trusted_timestamp_required", { deviceId: device.id, evidenceId: manifest.evidenceID, errorClass: trustedTimestampError || "not_configured" });
      return Response.json({ error: "Independent trusted timestamping is required and currently unavailable. The capture was not stored." }, { status: 503 });
    }
    const timestampAuthority = trustedTimestamp?.authority || "Scopeproof signed server time";
    const timestampToken = JSON.stringify({ ...attestationBody, signature: signed.signature, publicKeySpkiBase64: signed.publicKey, algorithm: "ECDSA-P256-SHA256", trustedTimestamp, trustedTimestampError });
    const chainLeaseId = await reserveCaptureDeviceChain(device, actor, {
      sequence: manifest.chainSequence, previousHash: manifest.chainPreviousHash, eventHash: manifest.chainEventHash,
      evidenceId: manifest.evidenceID, provenanceKeyId: manifest.provenance.keyID, provenancePublicKey: manifest.provenance.publicKeyX963Base64,
    });
    const result = await storeEvidence({
      controlId, framework: complianceArea, catalogVersion, title, description: manifest.description, type: "screenshot", source: `Scopeproof Capture / ${device.id} / ${manifest.evidenceID} / ${complianceArea}`, system,
      environment, assessmentPeriod, evidenceOwner, tags, expectedEvidence, mappedControls, jiraIssueKey, jiraIssueURL, manualRedactions,
      contentType: "image/png", bytes: image, sessionId, deviceId: device.id, capturedAt, createdBy: actor, preflightFindings: localFindings,
      manifestSha256: attestationBody.manifestSha256, chainPreviousHash: attestationBody.chainPreviousHash, chainEventHash: attestationBody.chainEventHash,
      timestampAuthority, timestampToken,
      safetyScanSha256: manifest.safetyScanSha256, safetyScanPolicy: manifest.safetyScanPolicy, safetyScanCompletedAt: manifest.safetyScanCompletedAt,
      serverSafetyScan,
      assessmentId: candidateAssessments[0].id,
    });
    const hostedArtifact = await getEnv().DB.prepare("SELECT device_id, created_by, sha256, manifest_sha256, jira_issue_key FROM evidence_artifacts WHERE id = ?")
      .bind(result.id).first<{ device_id: string | null; created_by: string; sha256: string; manifest_sha256: string | null; jira_issue_key: string | null }>();
    if (!hostedArtifact || hostedArtifact.device_id !== device.id || hostedArtifact.created_by !== actor.id || hostedArtifact.sha256 !== imageDigest || hostedArtifact.manifest_sha256 !== attestationBody.manifestSha256 || String(hostedArtifact.jira_issue_key || "") !== jiraIssueKey) {
      return Response.json({ error: "Matching evidence already exists under different hosted provenance; the local identity was not linked." }, { status: 409 });
    }
    await finalizeCaptureDeviceChain(actor, device, {
      leaseId: chainLeaseId, sequence: manifest.chainSequence, previousHash: manifest.chainPreviousHash, eventHash: manifest.chainEventHash,
      evidenceId: manifest.evidenceID, provenanceKeyId: manifest.provenance.keyID, provenancePublicKey: manifest.provenance.publicKeyX963Base64,
      artifactId: result.id, manifestSha256: attestationBody.manifestSha256, imageSha256: imageDigest, jiraIssueKey: jiraIssueKey || null,
    });
    return Response.json({ ...result, receipt: { evidenceId: result.id, deviceId: device.id, attestation: { ...attestationBody, signature: signed.signature, publicKeySpkiBase64: signed.publicKey, algorithm: "ECDSA-P256-SHA256", trustedTimestamp, trustedTimestampError } } }, { status: result.deduplicated ? 200 : 201 });
  } catch (error) {
    if (error instanceof NativeManifestError) return Response.json({ error: error.message }, { status: 422 });
    return jsonError(error);
  }
}
