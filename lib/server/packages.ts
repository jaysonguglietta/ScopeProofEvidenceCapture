import { strToU8, zipSync } from "fflate";
import type { AuthenticatedUser } from "./auth";
import { appendAuditEvent } from "./audit";
import { decryptEvidence, encryptEvidence, randomId, sha256, signPackage, stableJson } from "./crypto";
import { getEnv } from "./env";
import { readEvidenceBytes } from "./evidence";

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

function csv(value: unknown): string { return `"${String(value ?? "").replaceAll('"', '""')}"`; }

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

export async function buildAssessorPackage(actor: AuthenticatedUser): Promise<{ id: string; evidenceCount: number; sha256: string; signature: string }> {
  const env = getEnv();
  const id = randomId("pkg");
  await env.DB.prepare("INSERT INTO export_packages (id, requested_by) VALUES (?, ?)").bind(id, actor.id).run();
  try {
    const rows = (await env.DB.prepare(`SELECT id, control_id, framework, catalog_version, title, description, type, source, system, environment, assessment_period, evidence_owner, tags_json, expected_evidence, mapped_controls_json, content_type, byte_size, sha256, captured_at, expires_at, redaction_count, manual_redactions, approved_by, approved_at
      FROM evidence_artifacts WHERE status = 'approved' ORDER BY control_id, captured_at DESC LIMIT 100`).all<Record<string, unknown>>()).results;
    if (!rows.length) throw new Error("No approved evidence is available for export.");
    const generatedAt = new Date().toISOString();
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
      ["Evidence ID", "Framework", "Control", "Title", "System", "Environment", "Assessment period", "Owner", "Captured at", "Approved at", "Redactions", "SHA-256"].map(csv).join(","),
      ...rows.map((row) => [row.id, row.framework || "PCI DSS 4.0.1", row.control_id, row.title, row.system, row.environment, row.assessment_period, row.evidence_owner, row.captured_at, row.approved_at, Number(row.redaction_count || 0) + Number(row.manual_redactions || 0), row.sha256].map(csv).join(",")),
    ];
    files["01-Evidence-Index.csv"] = strToU8(`${indexRows.join("\n")}\n`);
    files["00-READ-ME.txt"] = strToU8(`SCOPEPROOF EXTERNAL ASSESSOR PACKAGE\n\nPackage ID: ${id}\nGenerated: ${generatedAt}\nPrepared by: ${actor.email}\nFrameworks: ${frameworks.join(", ")}\nAssessment periods: ${periods.join(", ")}\nApproved evidence: ${rows.length}\n\nSTART HERE\n1. Open 01-Evidence-Index.csv to browse the evidence by framework and control.\n2. Review artifacts under evidence/<framework>/<control>/.\n3. Use manifest.json and VERIFY.txt to validate SHA-256 hashes and the ECDSA signature.\n\nOnly evidence approved through Scopeproof review is included. Cross-framework mappings are informational and require assessor validation.\n`);
    const reportLines = [
      "SCOPEPROOF ASSESSOR EVIDENCE REPORT", "", `Frameworks: ${frameworks.join(", ")}`, `Assessment periods: ${periods.join(", ")}`, `Package: ${id}`, `Generated: ${generatedAt}`, `Prepared by: ${actor.email}`,
      `Approved evidence: ${rows.length}`, "", "INTEGRITY ATTESTATION", "This PDF and every evidence artifact are listed by SHA-256 digest in manifest.json.", "The manifest is digitally signed using ECDSA P-256 with SHA-256 and includes the", "public verification key for independent validation.", "", "EVIDENCE INDEX",
      ...rows.map((row: Record<string, unknown>) => `${String(row.framework || "PCI DSS 4.0.1").slice(0, 18)} | ${row.control_id} | ${row.id} | ${String(row.title).slice(0, 36)}`),
    ];
    files["assessor-report.pdf"] = buildPdf(reportLines);
    const evidence = rows.map((row) => ({ ...row, package_path: `evidence/${safeName(String(row.framework || "PCI DSS 4.0.1"))}/${safeName(String(row.control_id))}/${String(row.id)}-${safeName(String(row.title))}.${extension(String(row.content_type))}`, tags: JSON.parse(String(row.tags_json || "[]")), mappedControls: JSON.parse(String(row.mapped_controls_json || "[]")), tags_json: undefined, mapped_controls_json: undefined }));
    const manifest = { schemaVersion: 2, packageId: id, frameworks, assessmentPeriods: periods, generatedAt, generatedBy: actor.email, inclusionPolicy: { status: "approved", maximumArtifacts: 100 }, readme: { filename: "00-READ-ME.txt", sha256: await sha256(files["00-READ-ME.txt"]) }, report: { filename: "assessor-report.pdf", sha256: await sha256(files["assessor-report.pdf"]) }, index: { filename: "01-Evidence-Index.csv", sha256: await sha256(files["01-Evidence-Index.csv"]) }, evidence };
    const manifestCanonical = stableJson(manifest);
    const signed = await signPackage(manifestCanonical);
    const signature = signed.signature;
    const signedManifest = { ...manifest, signature: { algorithm: "ECDSA-P256-SHA256", value: signature, publicKeySpkiBase64: signed.publicKey, canonicalization: "Scopeproof stable JSON v1" } };
    files["manifest.json"] = strToU8(JSON.stringify(signedManifest, null, 2));
    files["VERIFY.txt"] = strToU8(`Scopeproof External Assessor Evidence Package\nPackage ID: ${id}\nManifest algorithm: ECDSA-P256-SHA256\nCanonicalization: Scopeproof stable JSON v1\nPublic key (SPKI base64): ${signed.publicKey}\nManifest signature: ${signature}\nArtifact integrity: verify every evidence file against its manifest.json SHA-256 value.\n`);
    const zip = zipSync(files, { level: 6 });
    const digest = await sha256(zip);
    const associatedData = stableJson({ id, type: "assessor_package" });
    const encrypted = await encryptEvidence(zip, associatedData);
    const r2Key = `exports/${id}.zip.enc`;
    await env.EVIDENCE_BUCKET.put(r2Key, encrypted.ciphertext, { customMetadata: { packageId: id, sha256: digest, encryptionIv: encrypted.iv, encryptionVersion: "1" } });
    const completedAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 7 * 86_400_000).toISOString();
    await env.DB.prepare("UPDATE export_packages SET status = 'ready', r2_key = ?, sha256 = ?, signature = ?, evidence_count = ?, byte_size = ?, completed_at = ?, expires_at = ?, error_message = NULL WHERE id = ?").bind(r2Key, digest, signature, rows.length, zip.byteLength, completedAt, expiresAt, id).run();
    await appendAuditEvent(actor, "package.created", "export_package", id, { evidenceCount: rows.length, sha256: digest, byteSize: zip.byteLength, expiresAt });
    return { id, evidenceCount: rows.length, sha256: digest, signature };
  } catch (error) {
    await env.DB.prepare("UPDATE export_packages SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?").bind(error instanceof Error ? error.message.slice(0, 1000) : "Package generation failed", new Date().toISOString(), id).run();
    throw error;
  }
}

export async function readAssessorPackage(id: string, actor: AuthenticatedUser): Promise<{ bytes: Uint8Array; sha256: string } | null> {
  const env = getEnv();
  const row = await env.DB.prepare("SELECT r2_key, sha256, expires_at FROM export_packages WHERE id = ? AND status = 'ready' AND (requested_by = ? OR ? = 'admin')").bind(id, actor.id, actor.role).first<{ r2_key: string; sha256: string; expires_at: string }>();
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) throw new Error("This package download has expired.");
  const object = await env.EVIDENCE_BUCKET.get(row.r2_key);
  if (!object) throw new Error("Encrypted package object is missing.");
  const iv = object.customMetadata?.encryptionIv;
  if (!iv) throw new Error("Package encryption metadata is missing.");
  const bytes = await decryptEvidence(new Uint8Array(await object.arrayBuffer()), iv, stableJson({ id, type: "assessor_package" }));
  if (await sha256(bytes) !== row.sha256) throw new Error("Package integrity verification failed.");
  return { bytes, sha256: row.sha256 };
}
