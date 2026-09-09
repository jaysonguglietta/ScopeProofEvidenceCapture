import { getAssessment } from "./assessments";
import { getEnv } from "./env";
import { executeAuditedBatch } from "./audit";
import type { AuthenticatedUser } from "./auth";
import { randomId } from "./crypto";
import { PACKAGE_ELIGIBLE_EVIDENCE_SQL } from "./package-eligibility";

function failure(message: string, status = 400): Response { return Response.json({ error: message }, { status }); }

export function requirementResult(input: { eligible: number; minimumArtifacts: number; ownerId: string | null; ownerActive: boolean }) {
  const missingArtifacts = Math.max(0, input.minimumArtifacts - input.eligible);
  const ownerMissing = !input.ownerId || !input.ownerActive;
  return { satisfied: missingArtifacts === 0 && !ownerMissing, missingArtifacts, ownerMissing };
}

export async function listEvidenceRequirements(assessmentId: string) {
  const assessment = await getAssessment(assessmentId);
  if (!assessment) throw failure("Assessment not found.", 404);
  const controls = assessment.controls as string[], systems = assessment.systems as string[];
  if (controls.length * systems.length > 2500) throw failure("Requirement matrix exceeds 2,500 control/system pairs. Split this scope into explicitly separate assessments.", 422);
  const rows = (await getEnv().DB.prepare(`SELECT r.*, u.email AS owner_email, u.status AS owner_status FROM evidence_requirements r
    LEFT JOIN users u ON u.id = r.owner_id WHERE r.assessment_id = ? AND NOT EXISTS (
      SELECT 1 FROM evidence_requirements newer WHERE newer.assessment_id = r.assessment_id
      AND newer.control_id = r.control_id AND newer.system = r.system AND newer.revision > r.revision
    )`).bind(assessmentId).all<Record<string, unknown>>()).results;
  const counts = (await getEnv().DB.prepare(`SELECT e.control_id, e.system,
      SUM(CASE WHEN ${PACKAGE_ELIGIBLE_EVIDENCE_SQL} THEN 1 ELSE 0 END) AS eligible,
      SUM(CASE WHEN o.expires_at <= ? THEN 1 ELSE 0 END) AS expired,
      SUM(CASE WHEN o.coverage_status = 'partial' AND o.expires_at > ? THEN 1 ELSE 0 END) AS partial,
      SUM(CASE WHEN o.status = 'needs_review' AND o.expires_at > ? THEN 1 ELSE 0 END) AS needs_review
    FROM evidence_artifacts e JOIN evidence_occurrences o ON o.id = (
      SELECT latest.id FROM evidence_occurrences latest WHERE latest.artifact_id = e.id ORDER BY latest.received_at DESC, latest.id DESC LIMIT 1)
    WHERE e.assessment_id = ? GROUP BY e.control_id, e.system`).bind(...Array(4).fill(new Date().toISOString()), assessmentId).all<Record<string, unknown>>()).results;
  const requirements = controls.flatMap((controlId) => systems.map((system) => {
    const current = rows.find((row) => row.control_id === controlId && row.system === system);
    const count = counts.find((row) => row.control_id === controlId && row.system === system);
    const minimumArtifacts = Number(current?.minimum_artifacts || 1), eligible = Number(count?.eligible || 0);
    const ownerId = current?.owner_id ? String(current.owner_id) : null;
    return { controlId, system, revision: Number(current?.revision || 0), minimumArtifacts, ownerId,
      ownerEmail: current?.owner_email ? String(current.owner_email) : null, reason: String(current?.reason || "Default expectation: one eligible artifact and an accountable owner for this control/system pair."),
      eligible, expired: Number(count?.expired || 0), partial: Number(count?.partial || 0), needsReview: Number(count?.needs_review || 0),
      ...requirementResult({ eligible, minimumArtifacts, ownerId, ownerActive: current?.owner_status === "active" }) };
  }));
  return { assessmentId, requirements, summary: { total: requirements.length, satisfied: requirements.filter((item) => item.satisfied).length },
    interpretation: "Evidence expectations only; not a regulatory compliance determination. Scope and expectations require assessor validation." };
}

export async function reviseEvidenceRequirement(actor: AuthenticatedUser, input: Record<string, unknown>) {
  if (Object.keys(input).some((key) => !["assessmentId", "controlId", "system", "expectedRevision", "minimumArtifacts", "ownerId", "reason"].includes(key))) throw failure("Unsupported requirement fields.");
  const assessmentId = String(input.assessmentId || ""), controlId = String(input.controlId || ""), system = String(input.system || "");
  const assessment = await getAssessment(assessmentId);
  if (!assessment || assessment.status === "closed") throw failure("An open assessment is required.", 409);
  if (!(assessment.controls as string[]).includes(controlId) || !(assessment.systems as string[]).includes(system)) throw failure("Requirement is outside the assessment scope.", 422);
  const revision = input.expectedRevision, minimum = input.minimumArtifacts;
  const reason = String(input.reason || "").trim(), ownerId = String(input.ownerId || "").trim() || null;
  if (!Number.isSafeInteger(revision) || Number(revision) < 0 || Number(revision) >= 1_000_000 || !Number.isSafeInteger(minimum) || Number(minimum) < 1 || Number(minimum) > 25 || reason.length < 20 || reason.length > 1000) throw failure("Supply the current revision, 1–25 artifacts, and a 20–1,000 character rationale.");
  if (ownerId && !await getEnv().DB.prepare("SELECT 1 FROM users WHERE id = ? AND status = 'active'").bind(ownerId).first()) throw failure("Owner must be an active member.", 422);
  const id = randomId("req"), now = new Date().toISOString();
  const [result] = await executeAuditedBatch(actor, "requirement.revised", "assessment", assessmentId,
    { id, controlId, system, previousRevision: revision, revision: Number(revision) + 1, minimumArtifacts: minimum, ownerId, reason }, [
      getEnv().DB.prepare(`INSERT INTO evidence_requirements (id, assessment_id, control_id, system, revision, minimum_artifacts, owner_id, reason, created_by, created_at)
        SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE
        COALESCE((SELECT MAX(revision) FROM evidence_requirements WHERE assessment_id = ? AND control_id = ? AND system = ?), 0) = ?
        AND EXISTS (SELECT 1 FROM assessments WHERE id = ? AND status IN ('draft','active')
          AND EXISTS (SELECT 1 FROM json_each(controls_json) WHERE value = ?) AND EXISTS (SELECT 1 FROM json_each(systems_json) WHERE value = ?))
        AND (? IS NULL OR EXISTS (SELECT 1 FROM users WHERE id = ? AND status = 'active'))`)
        .bind(id, assessmentId, controlId, system, Number(revision) + 1, minimum, ownerId, reason, actor.id, now,
          assessmentId, controlId, system, revision, assessmentId, controlId, system, ownerId, ownerId),
    ], { sql: "EXISTS (SELECT 1 FROM evidence_requirements WHERE id = ?)", bindings: [id] });
  if (!result.meta.changes) throw failure("The requirement, owner or assessment changed. Reload before revising.", 409);
  return { id, revision: Number(revision) + 1 };
}
