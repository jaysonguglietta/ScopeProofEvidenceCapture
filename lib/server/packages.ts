import { strToU8, zipSync } from "fflate";
import type { AuthenticatedUser } from "./auth";
import { executeAuditedBatch } from "./audit";
import { decryptEvidence, encryptEvidence, randomId, sha256, signPackage, stableJson } from "./crypto";
import { getEnv } from "./env";
import { readEvidenceBytes } from "./evidence";
import { csvCell } from "./csv";

export type PackagePreflight = {
  ready: boolean;
  assessmentId: string;
  total: number;
  eligible: number;
  excluded: number;
  blockers: Array<{ code: string; count: number; message: string }>;
};

export async function preflightAssessorPackage(assessmentId: string): Promise<PackagePreflight> {
  if (!/^asm_[a-f0-9]{32}$/u.test(assessmentId)) throw new Response(JSON.stringify({ error: "A valid assessment is required." }), { status: 400, headers: { "content-type": "application/json" } });
  const assessment = await getEnv().DB.prepare("SELECT status FROM assessments WHERE id = ?").bind(assessmentId).first<{ status: string }>();
  if (!assessment) throw new Response(JSON.stringify({ error: "Assessment not found." }), { status: 404, headers: { "content-type": "application/json" } });
  const now = new Date().toISOString();
  const counts = await getEnv().DB.prepare(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN e.status = 'approved' AND e.expires_at > ? AND e.coverage_status != 'partial'
        AND (e.type != 'screenshot' OR (e.server_safety_scan_sha256 = e.sha256 AND e.server_safety_scan_policy IS NOT NULL AND e.server_safety_scan_completed_at IS NOT NULL AND e.server_safety_scanner_origin IS NOT NULL AND e.server_safety_receipt_sha256 IS NOT NULL))
        AND (e.device_id IS NULL OR EXISTS (SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id WHERE n.artifact_id = e.id AND n.device_id = e.device_id AND n.image_sha256 = e.sha256 AND n.manifest_sha256 = e.manifest_sha256 AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence)) THEN 1 ELSE 0 END) AS eligible,
      SUM(CASE WHEN e.coverage_status = 'partial' AND e.expires_at > ? AND e.status NOT IN ('rejected','returned','superseded','expired','purged') THEN 1 ELSE 0 END) AS partial,
      SUM(CASE WHEN e.type = 'screenshot' AND e.status = 'approved' AND e.expires_at > ? AND NOT (e.server_safety_scan_sha256 = e.sha256 AND e.server_safety_scan_policy IS NOT NULL AND e.server_safety_scan_completed_at IS NOT NULL AND e.server_safety_scanner_origin IS NOT NULL AND e.server_safety_receipt_sha256 IS NOT NULL) THEN 1 ELSE 0 END) AS pending_safety,
      SUM(CASE WHEN e.device_id IS NOT NULL AND e.status = 'approved' AND e.expires_at > ? AND NOT EXISTS (SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id WHERE n.artifact_id = e.id AND n.device_id = e.device_id AND n.image_sha256 = e.sha256 AND n.manifest_sha256 = e.manifest_sha256 AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence) THEN 1 ELSE 0 END) AS pending_native
    FROM evidence_artifacts e WHERE e.assessment_id = ?`).bind(now, now, now, now, assessmentId).first<Record<string, number>>();
  const total = Number(counts?.total || 0);
  const eligible = Number(counts?.eligible || 0);
  const blockers: PackagePreflight["blockers"] = [];
  if (assessment.status === "draft") blockers.push({ code: "ASSESSMENT_DRAFT", count: 1, message: "Activate or close the assessment before export." });
  if (!eligible) blockers.push({ code: "NO_ELIGIBLE_EVIDENCE", count: 0, message: "No approved, current, complete evidence is eligible." });
  if (eligible > 100) blockers.push({ code: "PACKAGE_LIMIT", count: eligible, message: "The package limit is 100 artifacts; split scope explicitly." });
  if (Number(counts?.partial || 0)) blockers.push({ code: "PARTIAL_COVERAGE", count: Number(counts?.partial || 0), message: "Recollect partial-coverage evidence." });
  if (Number(counts?.pending_safety || 0)) blockers.push({ code: "SAFETY_PENDING", count: Number(counts?.pending_safety || 0), message: "Complete independent screenshot safety verification." });
  if (Number(counts?.pending_native || 0)) blockers.push({ code: "PROVENANCE_PENDING", count: Number(counts?.pending_native || 0), message: "Finalize native device provenance." });
  return { ready: blockers.length === 0, assessmentId, total, eligible, excluded: total - eligible, blockers };
}

function safeName(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 80) || "evidence";
}

function extension(contentType: string): string {
  if (contentType.includes("png")) return "png";
  if (contentType.includes("jpeg")) return "jpg";
  if (contentType.includes("pdf")) return "pdf";
  if (contentType.includes("json")) return "json";
  if (contentType.includes("xml")) return "xml";
  if (contentType.includes("yaml")) return "yaml";
  return "txt";
}

function escapePdf(value: string): string { return value.replace(/[\\()]/g, "\\$&").replace(/[^\x20-\x7e]/g, "?"); }

function buildPdf(lines: string[]): Uint8Array {
  const chunks: string[][] = [];
  for (let index = 0; index < lines.length; index += 48) chunks.push(lines.slice(index, index + 48));
  const pages = chunks.length ? chunks : [["SCOPEPROOF ASSESSOR EVIDENCE REPORT"]];
  const fontId = 3 + pages.length * 2;
  const pageIds = pages.map((_, index) => 3 + index * 2);
  const objects: string[] = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`,
  ];
  pages.forEach((pageLines, index) => {
    const commands = ["BT", "/F1 10 Tf", "48 755 Td", "13 TL", ...pageLines.flatMap((line, lineIndex) => lineIndex === 0 ? [`(${escapePdf(line)}) Tj`] : ["T*", `(${escapePdf(line)}) Tj`]), "ET"].join("\n");
    objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 ${fontId} 0 R >> >> /Contents ${pageIds[index] + 1} 0 R >>`);
    objects.push(`<< /Length ${commands.length} >>\nstream\n${commands}\nendstream`);
  });
  objects.push("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>");
  let pdf = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((object, index) => { offsets.push(pdf.length); pdf += `${index + 1} 0 obj\n${object}\nendobj\n`; });
  const xref = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n${offsets.slice(1).map((offset) => `${String(offset).padStart(10, "0")} 00000 n `).join("\n")}\n`;
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return strToU8(pdf);
}

export async function buildAssessorPackage(actor: AuthenticatedUser, assessmentId: string): Promise<{ id: string; evidenceCount: number; excludedCount: number; sha256: string; signature: string }> {
  const env = getEnv();
  if (!/^asm_[a-f0-9]{32}$/.test(assessmentId)) throw new Response(JSON.stringify({ error: "A valid assessment is required." }), { status: 400, headers: { "content-type": "application/json" } });
  const assessment = await env.DB.prepare("SELECT id, name, framework, period_start, period_end, systems_json, controls_json, status, updated_at FROM assessments WHERE id = ?").bind(assessmentId).first<Record<string, unknown>>();
  if (!assessment || assessment.status === "draft") throw new Response(JSON.stringify({ error: "Only active or closed assessments can be exported." }), { status: 409, headers: { "content-type": "application/json" } });
  const id = randomId("pkg");
  let pendingR2Key: string | null = null;
  const selection = { assessmentId, name: assessment.name, framework: assessment.framework, periodStart: assessment.period_start, periodEnd: assessment.period_end, systems: JSON.parse(String(assessment.systems_json || "[]")), controls: JSON.parse(String(assessment.controls_json || "[]")), inclusion: "approved, unexpired, complete coverage" };
  await executeAuditedBatch(actor, "package.requested", "export_package", id, selection, [
    env.DB.prepare("INSERT INTO export_packages (id, requested_by, assessment_id, selection_json) VALUES (?, ?, ?, ?)").bind(id, actor.id, assessmentId, stableJson(selection)),
  ]);
  try {
    const generatedAt = new Date().toISOString();
    const counts = await env.DB.prepare(`SELECT COUNT(*) AS total,
      SUM(CASE WHEN e.status = 'approved' AND e.expires_at > ? AND e.coverage_status != 'partial'
        AND (e.type != 'screenshot' OR (
          e.server_safety_scan_sha256 = e.sha256 AND e.server_safety_scan_policy IS NOT NULL AND e.server_safety_scan_completed_at IS NOT NULL
          AND e.server_safety_scanner_origin IS NOT NULL AND e.server_safety_receipt_sha256 IS NOT NULL
        ))
        AND (e.device_id IS NULL OR EXISTS (
          SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
          WHERE n.artifact_id = e.id AND n.device_id = e.device_id AND n.image_sha256 = e.sha256 AND n.manifest_sha256 = e.manifest_sha256
            AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash
            AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence
        )) THEN 1 ELSE 0 END) AS eligible,
      SUM(CASE WHEN e.type = 'screenshot' AND e.status = 'approved' AND e.expires_at > ? AND e.coverage_status != 'partial'
        AND NOT (
          e.server_safety_scan_sha256 = e.sha256 AND e.server_safety_scan_policy IS NOT NULL AND e.server_safety_scan_completed_at IS NOT NULL
          AND e.server_safety_scanner_origin IS NOT NULL AND e.server_safety_receipt_sha256 IS NOT NULL
        ) THEN 1 ELSE 0 END) AS pending_safety,
      SUM(CASE WHEN e.device_id IS NOT NULL AND e.status = 'approved' AND e.expires_at > ? AND e.coverage_status != 'partial'
        AND NOT EXISTS (
          SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
          WHERE n.artifact_id = e.id AND n.device_id = e.device_id AND n.image_sha256 = e.sha256 AND n.manifest_sha256 = e.manifest_sha256
            AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash
            AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence
        ) THEN 1 ELSE 0 END) AS pending_native,
      SUM(CASE WHEN e.coverage_status = 'partial' AND e.status IN ('needs_review','expiring') AND e.expires_at > ?
        AND NOT EXISTS (SELECT 1 FROM evidence_artifacts newer WHERE newer.assessment_id = e.assessment_id AND newer.control_id = e.control_id
          AND newer.source = e.source AND newer.system = e.system AND newer.coverage_status != 'partial' AND newer.captured_at > e.captured_at
          AND newer.status NOT IN ('rejected','expired','purged') AND newer.expires_at > ?) THEN 1 ELSE 0 END) AS partial
      FROM evidence_artifacts e WHERE e.assessment_id = ?`).bind(generatedAt, generatedAt, generatedAt, generatedAt, generatedAt, assessmentId).first<{ total: number; eligible: number; pending_safety: number; pending_native: number; partial: number }>();
    const eligibleCount = Number(counts?.eligible || 0);
    const totalCount = Number(counts?.total || 0);
    const excludedCount = totalCount - eligibleCount;
    if (Number(counts?.pending_safety || 0) > 0) throw new Error("Assessment contains screenshot evidence without an independent digest-bound server safety receipt. Recollect browser evidence or retry the original device upload before export.");
    if (Number(counts?.pending_native || 0) > 0) throw new Error("Assessment contains native evidence whose signed device-chain link is not finalized. Retry those uploads before export.");
    if (Number(counts?.partial || 0) > 0) throw new Error("Assessment contains partial-coverage evidence. Recollect it completely before export.");
    if (eligibleCount > 100) throw new Error(`Assessment contains ${eligibleCount} eligible artifacts, exceeding the 100-artifact package limit. Split the assessment scope explicitly; Scopeproof will not truncate it.`);
    const rows = (await env.DB.prepare(`SELECT e.id, e.control_id, e.framework, e.catalog_version, e.title, e.description, e.type, e.source, e.system, e.environment, e.assessment_period, e.evidence_owner, e.tags_json, e.expected_evidence, e.mapped_controls_json, e.jira_issue_key, e.jira_issue_url, e.content_type, e.byte_size, e.sha256, e.captured_at, o.expires_at, e.redaction_count, e.manual_redactions, e.safety_scan_sha256, e.safety_scan_policy, e.safety_scan_completed_at, e.server_safety_scan_sha256, e.server_safety_scan_policy, e.server_safety_scan_completed_at, e.server_safety_scanner_origin, e.server_safety_receipt_sha256, o.approved_by, o.approved_at, o.coverage_status, o.coverage_json, o.id AS occurrence_id, o.received_at AS occurrence_received_at
      FROM evidence_artifacts e JOIN evidence_occurrences o ON o.id = (
        SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = e.id ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1
      ) WHERE e.assessment_id = ? AND o.status = 'approved' AND o.expires_at > ? AND o.coverage_status != 'partial'
        AND (e.type != 'screenshot' OR (
          e.server_safety_scan_sha256 = e.sha256 AND e.server_safety_scan_policy IS NOT NULL AND e.server_safety_scan_completed_at IS NOT NULL
          AND e.server_safety_scanner_origin IS NOT NULL AND e.server_safety_receipt_sha256 IS NOT NULL
        ))
        AND (e.device_id IS NULL OR EXISTS (
          SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
          WHERE n.artifact_id = e.id AND n.device_id = e.device_id AND n.image_sha256 = e.sha256 AND n.manifest_sha256 = e.manifest_sha256
            AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash
            AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence
        ))
      ORDER BY e.control_id, o.captured_at DESC, e.id`).bind(assessmentId, generatedAt).all<Record<string, unknown>>()).results;
    if (rows.length !== eligibleCount) throw new Error("Assessment evidence changed while the package was being selected. Retry the export.");
    if (!rows.length) throw new Error("No approved evidence is available for export.");
    const files: Record<string, Uint8Array> = {};
    let totalEvidenceBytes = 0;
    for (const row of rows) {
      const artifact = await readEvidenceBytes(String(row.id));
      if (!artifact) throw new Error(`Approved evidence ${String(row.id)} is missing its encrypted artifact.`);
      totalEvidenceBytes += artifact.bytes.byteLength;
      if (totalEvidenceBytes > 25 * 1024 * 1024) throw new Error("Approved evidence exceeds the 25 MB package safety limit.");
      files[`evidence/${safeName(String(row.framework || "PCI DSS 4.0.1"))}/${safeName(String(row.control_id))}/${String(row.id)}-${safeName(String(row.title))}.${extension(String(row.content_type))}`] = artifact.bytes;
    }
    const frameworks = [...new Set(rows.map((row) => String(row.framework || "PCI DSS 4.0.1")))].sort();
    const periods = [...new Set(rows.map((row) => String(row.assessment_period || "Unspecified")))].sort();
    const indexRows = [
      ["Evidence ID", "Framework", "Control", "Jira issue", "Jira URL", "Title", "System", "Environment", "Assessment period", "Owner", "Captured at", "Approved at", "Redactions", "SHA-256"].map(csvCell).join(","),
      ...rows.map((row) => [row.id, row.framework || "PCI DSS 4.0.1", row.control_id, row.jira_issue_key, row.jira_issue_url, row.title, row.system, row.environment, row.assessment_period, row.evidence_owner, row.captured_at, row.approved_at, Number(row.redaction_count || 0) + Number(row.manual_redactions || 0), row.sha256].map(csvCell).join(",")),
    ];
    files["01-Evidence-Index.csv"] = strToU8(`${indexRows.join("\n")}\n`);
    files["00-READ-ME.txt"] = strToU8(`SCOPEPROOF EXTERNAL ASSESSOR PACKAGE\n\nPackage ID: ${id}\nGenerated: ${generatedAt}\nPrepared by: ${actor.email}\nFrameworks: ${frameworks.join(", ")}\nAssessment periods: ${periods.join(", ")}\nApproved evidence: ${rows.length}\n\nSTART HERE\n1. Open 01-Evidence-Index.csv to browse the evidence by framework and control.\n2. Review artifacts under evidence/<framework>/<control>/.\n3. Use manifest.json and VERIFY.txt to validate SHA-256 hashes and the ECDSA signature.\n4. Follow 02-Jira-Handoff.txt before attaching artifacts to Jira.\n\nOnly evidence approved through Scopeproof review is included. Cross-framework mappings are informational and require assessor validation.\n`);
    const jiraAssignments = rows.filter((row) => row.jira_issue_key).map((row) => `- ${row.jira_issue_key}: ${row.id}${row.jira_issue_url ? ` · ${row.jira_issue_url}` : ""}`).join("\n") || "No Jira issue keys were assigned in this package.";
    files["02-Jira-Handoff.txt"] = strToU8(`SCOPEPROOF → JIRA HANDOFF GUIDE\n\nRECOMMENDED PROCESS\n1. Confirm the Jira project and issue are approved for this evidence classification and grant only the required auditor/reviewer access.\n2. Confirm the evidence is Approved and the issue key in 01-Evidence-Index.csv matches the intended ticket.\n3. Attach the assessor ZIP together with its separate SHA-256 checksum, or attach the complete evidence set required by your procedure.\n4. After attachment, download the file from Jira and verify its SHA-256 against manifest.json.\n5. Record the Jira ticket in the assessment workpapers and apply organizational retention policy.\n\nDO NOT ATTACH\n- Unredacted source screenshots\n- Passwords, browser cookies, tokens, private keys, PAN, or sensitive authentication data\n- Draft, rejected, or superseded evidence represented as current proof\n\nEVIDENCE ASSOCIATED WITH JIRA\n${jiraAssignments}\n`);
    const reportLines = [
      "SCOPEPROOF ASSESSOR EVIDENCE REPORT", "", `Frameworks: ${frameworks.join(", ")}`, `Assessment periods: ${periods.join(", ")}`, `Package: ${id}`, `Generated: ${generatedAt}`, `Prepared by: ${actor.email}`,
      `Approved evidence: ${rows.length}`, "", "INTEGRITY ATTESTATION", "This PDF and every evidence artifact are listed by SHA-256 digest in manifest.json.", "The manifest is digitally signed using ECDSA P-256 with SHA-256 and includes the", "public verification key for independent validation.", "", "EVIDENCE INDEX",
      ...rows.map((row: Record<string, unknown>) => `${String(row.framework || "PCI DSS 4.0.1").slice(0, 18)} | ${row.control_id} | ${row.id} | ${String(row.title).slice(0, 36)}`),
    ];
    files["assessor-report.pdf"] = buildPdf(reportLines);
    const evidence = rows.map((row) => {
      const { tags_json: tagsJson, mapped_controls_json: mappedControlsJson, coverage_json: coverageJson, ...signedFields } = row;
      return {
        ...signedFields,
        package_path: `evidence/${safeName(String(row.framework || "PCI DSS 4.0.1"))}/${safeName(String(row.control_id))}/${String(row.id)}-${safeName(String(row.title))}.${extension(String(row.content_type))}`,
        tags: JSON.parse(String(tagsJson || "[]")),
        mappedControls: JSON.parse(String(mappedControlsJson || "[]")),
        coverage: JSON.parse(String(coverageJson || "{}")),
      };
    });
    const manifest = { schemaVersion: 4, packageId: id, assessment: selection, frameworks, assessmentPeriods: periods, generatedAt, generatedBy: actor.email, selectionCounts: { total: totalCount, included: rows.length, excluded: excludedCount }, inclusionPolicy: { status: "approved", coverage: "complete_or_not_applicable", expiration: `after:${generatedAt}`, maximumArtifacts: 100, truncation: "forbidden" }, readme: { filename: "00-READ-ME.txt", sha256: await sha256(files["00-READ-ME.txt"]) }, report: { filename: "assessor-report.pdf", sha256: await sha256(files["assessor-report.pdf"]) }, index: { filename: "01-Evidence-Index.csv", sha256: await sha256(files["01-Evidence-Index.csv"]) }, jiraHandoff: { filename: "02-Jira-Handoff.txt", sha256: await sha256(files["02-Jira-Handoff.txt"]) }, evidence };
    const manifestCanonical = stableJson(manifest);
    const signed = await signPackage(manifestCanonical);
    const signature = signed.signature;
    const signedManifest = { ...manifest, signature: { algorithm: "ECDSA-P256-SHA256", value: signature, publicKeySpkiBase64: signed.publicKey, canonicalization: "RFC 8785 JCS" } };
    files["manifest.json"] = strToU8(JSON.stringify(signedManifest, null, 2));
    files["VERIFY.txt"] = strToU8(`Scopeproof External Assessor Evidence Package\nPackage ID: ${id}\nManifest algorithm: ECDSA-P256-SHA256\nCanonicalization: RFC 8785 JCS\nPublic key (SPKI base64): ${signed.publicKey}\nManifest signature: ${signature}\nArtifact integrity: verify every evidence file against its manifest.json SHA-256 value.\n`);
    const zip = zipSync(files, { level: 6 });
    const digest = await sha256(zip);
    const associatedData = stableJson({ id, type: "assessor_package" });
    const encrypted = await encryptEvidence(zip, associatedData);
    const r2Key = `exports/${id}.zip.enc`;
    pendingR2Key = r2Key;
    await env.EVIDENCE_BUCKET.put(r2Key, encrypted.ciphertext, { customMetadata: { packageId: id, sha256: digest, encryptionIv: encrypted.iv, encryptionVersion: "2", encryptionKeyId: encrypted.keyId } });
    const completedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 7 * 86_400_000).toISOString();
    const occurrenceConditions = rows.map(() => `EXISTS (SELECT 1 FROM evidence_occurrences selected
      WHERE selected.id = ? AND selected.artifact_id = ? AND selected.status = 'approved' AND selected.expires_at > ? AND selected.coverage_status != 'partial'
        AND selected.id = (SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = selected.artifact_id ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1)
        AND EXISTS (SELECT 1 FROM evidence_artifacts e WHERE e.id = selected.artifact_id
          AND (e.type != 'screenshot' OR (
            e.server_safety_scan_sha256 = e.sha256 AND e.server_safety_scan_policy IS NOT NULL AND e.server_safety_scan_completed_at IS NOT NULL
            AND e.server_safety_scanner_origin IS NOT NULL AND e.server_safety_receipt_sha256 IS NOT NULL
          ))
          AND (e.device_id IS NULL OR EXISTS (
          SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
          WHERE n.artifact_id = e.id AND n.device_id = e.device_id AND n.image_sha256 = e.sha256 AND n.manifest_sha256 = e.manifest_sha256
            AND n.chain_sequence IS NOT NULL AND n.chain_sequence > 0 AND n.chain_event_hash = e.chain_event_hash
            AND n.provenance_key_id IS NOT NULL AND d.provenance_key_id = n.provenance_key_id AND d.chain_sequence >= n.chain_sequence
        ))))`).join(" AND ");
    const occurrenceBindings = rows.flatMap((row) => [row.occurrence_id, row.id, completedAt]);
    const [published] = await executeAuditedBatch(actor, "package.created", "export_package", id, { evidenceCount: rows.length, occurrenceIds: rows.map((row) => row.occurrence_id), sha256: digest, byteSize: zip.byteLength, expiresAt }, [
      env.DB.prepare(`UPDATE export_packages SET status = 'ready', r2_key = ?, sha256 = ?, signature = ?, evidence_count = ?, excluded_count = ?, encryption_key_id = ?, byte_size = ?, completed_at = ?, expires_at = ?, error_message = NULL
        WHERE id = ? AND status = 'building'
          AND EXISTS (SELECT 1 FROM assessments WHERE id = ? AND status = ? AND updated_at = ?)
          AND ${occurrenceConditions}`)
        .bind(r2Key, digest, signature, rows.length, excludedCount, encrypted.keyId, zip.byteLength, completedAt, expiresAt, id,
          assessmentId, assessment.status, assessment.updated_at, ...occurrenceBindings),
    ], { sql: "EXISTS (SELECT 1 FROM export_packages WHERE id = ? AND status = 'ready' AND sha256 = ?)", bindings: [id, digest] });
    if (!published.meta.changes) throw new Error("Assessment scope or evidence approval changed while the package was being built. Retry the export.");
    return { id, evidenceCount: rows.length, excludedCount, sha256: digest, signature };
  } catch (error) {
    if (pendingR2Key) await env.EVIDENCE_BUCKET.delete(pendingR2Key);
    await executeAuditedBatch(actor, "package.failed", "export_package", id, { errorCode: "PACKAGE_GENERATION_FAILED" }, [
      env.DB.prepare("UPDATE export_packages SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ? AND status = 'building'").bind(error instanceof Error ? error.message.slice(0, 1000) : "Package generation failed", new Date().toISOString(), id),
    ]);
    throw error;
  }
}

export async function readAssessorPackage(id: string, actor: AuthenticatedUser): Promise<{ bytes: Uint8Array; sha256: string } | null> {
  const env = getEnv();
  const row = await env.DB.prepare("SELECT r2_key, sha256, expires_at, encryption_key_id FROM export_packages WHERE id = ? AND status = 'ready' AND (requested_by = ? OR ? = 'admin')").bind(id, actor.id, actor.role).first<{ r2_key: string; sha256: string; expires_at: string; encryption_key_id: string }>();
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) throw new Error("This package download has expired.");
  const object = await env.EVIDENCE_BUCKET.get(row.r2_key);
  if (!object) throw new Error("Encrypted package object is missing.");
  const iv = object.customMetadata?.encryptionIv;
  if (!iv) throw new Error("Package encryption metadata is missing.");
  const bytes = await decryptEvidence(new Uint8Array(await object.arrayBuffer()), iv, stableJson({ id, type: "assessor_package" }), row.encryption_key_id || object.customMetadata?.encryptionKeyId || "legacy-v1");
  if (await sha256(bytes) !== row.sha256) throw new Error("Package integrity verification failed.");
  return { bytes, sha256: row.sha256 };
}
