import { verifyAuditChain } from "./audit";
import { validateBootstrapAdministratorAllowlist, validateLegacyTenantBinding, validateTrustedApplicationOrigins } from "./identity-config";
import { getLatestAuditCheckpoint, validateAuditCheckpointConfiguration, verifyLatestAuditCheckpoint } from "./checkpoints";
import { validateConfiguredKeyMaterial, validatePackageSigningKeyPair } from "./crypto";
import { getEnv } from "./env";
import { validateSecurityMonitoringConfiguration } from "./external-trust-config";
import { keyRotationBacklog, keyRotationRetrySummary, validateRetainedKeyReferences } from "./key-operations";
import { validateEvidenceSafetyScannerConfiguration } from "./image-safety";
import { validateTrustedTimestampConfiguration } from "./timestamp";

export type ReadinessCheck = { id: string; status: "pass" | "warn" | "fail"; summary: string; details?: unknown };

export async function productionReadiness(): Promise<{ ready: boolean; checkedAt: string; checks: ReadinessCheck[] }> {
  const env = getEnv();
  const checks: ReadinessCheck[] = [];
  const required = [
    ["evidence_keys", Boolean(env.EVIDENCE_KEYRING_JSON || env.EVIDENCE_ENCRYPTION_KEY), "Evidence encryption keyring is configured."],
    ["audit_keys", Boolean(env.AUDIT_KEYRING_JSON || env.AUDIT_HMAC_KEY), "Audit HMAC keyring is configured."],
    ["package_signing", Boolean(env.PACKAGE_SIGNING_PRIVATE_KEY && env.PACKAGE_SIGNING_PUBLIC_KEY), "Package signing keypair is configured."],
    ["independent_checkpoint_endpoint", Boolean(env.AUDIT_CHECKPOINT_ENDPOINT && env.AUDIT_CHECKPOINT_ALLOWED_HOSTS && env.AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY), "Independent audit checkpoint delivery and receipt verification are configured."],
    ["single_tenant_boundary", env.LEGACY_SINGLE_TENANT_ACKNOWLEDGEMENT === "single-tenant-only", "Legacy single-tenant isolation boundary is explicitly acknowledged."],
  ] as const;
  for (const [id, present, summary] of required) checks.push({ id, status: present ? "pass" : "fail", summary: present ? summary : `${summary.replace(" is configured.", "")} is missing.` });

  try {
    const origins = validateTrustedApplicationOrigins(env.TRUSTED_APP_ORIGINS, { allowLoopbackHttp: false });
    checks.push({ id: "trusted_origins", status: "pass", summary: "Exactly one structurally safe application origin is configured.", details: { origins: [...origins] } });
  } catch (error) {
    checks.push({ id: "trusted_origins", status: "fail", summary: "The trusted application origin is missing or unsafe.", details: error instanceof Error ? error.message : String(error) });
  }

  try {
    const binding = validateLegacyTenantBinding(env.LEGACY_TENANT_ID, env.LEGACY_WORKSPACE_ID);
    checks.push({ id: "legacy_tenant_binding", status: "pass", summary: "The legacy native-ingest customer/workspace boundary is explicitly configured.", details: binding });
  } catch (error) {
    checks.push({ id: "legacy_tenant_binding", status: "fail", summary: "The legacy native-ingest customer/workspace boundary is missing or unsafe.", details: error instanceof Error ? error.message : String(error) });
  }

  try {
    const admins = validateBootstrapAdministratorAllowlist(env.BOOTSTRAP_ADMIN_EMAILS);
    checks.push({ id: "bootstrap_admin", status: "pass", summary: "The bootstrap administrator allowlist is structurally valid.", details: { count: admins.size } });
  } catch (error) {
    checks.push({ id: "bootstrap_admin", status: "fail", summary: "The bootstrap administrator allowlist is missing or unsafe.", details: error instanceof Error ? error.message : String(error) });
  }

  if (env.AUDIT_CHECKPOINT_ENDPOINT || env.AUDIT_CHECKPOINT_ALLOWED_HOSTS || env.AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY) {
    try {
      const details = await validateAuditCheckpointConfiguration(env);
      checks.push({ id: "independent_checkpoint_boundary", status: "pass", summary: "The independent checkpoint endpoint and receipt-verification key are valid.", details });
    } catch (error) {
      checks.push({ id: "independent_checkpoint_boundary", status: "fail", summary: "The independent checkpoint endpoint or receipt-verification key is invalid.", details: error instanceof Error ? error.message : String(error) });
    }
  }

  try {
    const details = validateSecurityMonitoringConfiguration(env);
    checks.push({ id: "security_monitoring", status: "pass", summary: "Security monitoring uses one clean HTTPS endpoint, an exact host allowlist, and a bounded header-safe token when configured.", details });
  } catch (error) {
    checks.push({ id: "security_monitoring", status: "fail", summary: "Security monitoring delivery is missing or unsafe.", details: error instanceof Error ? error.message : String(error) });
  }

  try {
    const details = validateEvidenceSafetyScannerConfiguration(env);
    checks.push({ id: "independent_image_safety", status: "pass", summary: "The screenshot scanner uses one clean HTTPS endpoint, an exact host allowlist, and a bounded header-safe token.", details });
  } catch (error) {
    checks.push({ id: "independent_image_safety", status: "fail", summary: "The screenshot scanner endpoint, allowlist, or token is missing or unsafe.", details: error instanceof Error ? error.message : String(error) });
  }

  if ((env.EVIDENCE_KEYRING_JSON || env.EVIDENCE_ENCRYPTION_KEY) && (env.AUDIT_KEYRING_JSON || env.AUDIT_HMAC_KEY)) {
    try {
      const validated = await validateConfiguredKeyMaterial();
      checks.push({ id: "key_material", status: "pass", summary: "Every retained encryption and audit key is decodable and meets its cryptographic strength requirement.", details: validated });
    } catch (error) {
      checks.push({ id: "key_material", status: "fail", summary: "Encryption or audit key material is malformed or too weak.", details: error instanceof Error ? error.message : String(error) });
    }
  }

  if (env.PACKAGE_SIGNING_PRIVATE_KEY && env.PACKAGE_SIGNING_PUBLIC_KEY) {
    const validPair = await validatePackageSigningKeyPair();
    checks.push({ id: "package_signing_keypair", status: validPair ? "pass" : "fail", summary: validPair ? "Package signing private and public keys are cryptographically matched." : "Package signing keypair is invalid or mismatched." });
  }

  try {
    const references = await validateRetainedKeyReferences();
    checks.push({ id: "retained_keys", status: references.valid ? "pass" : "fail", summary: references.valid ? "Every retained encrypted or signed record has a retained key." : "Retained records reference unavailable keys.", details: references.missing });
  } catch (error) {
    checks.push({ id: "retained_keys", status: "fail", summary: "Key configuration could not be validated.", details: error instanceof Error ? error.message : String(error) });
  }

  try {
    const backlog = await keyRotationBacklog();
    const retries = await keyRotationRetrySummary();
    const status: ReadinessCheck["status"] = retries.actionRequired > 0 ? "fail" : backlog > 0 || retries.retrying > 0 ? "warn" : "pass";
    const summary = retries.actionRequired > 0
      ? `${retries.actionRequired} key-rotation record${retries.actionRequired === 1 ? " requires" : "s require"} operator action.`
      : backlog > 0
        ? `${backlog} stored records remain queued for key rotation.`
        : retries.retrying > 0
          ? `${retries.retrying} key-rotation failure${retries.retrying === 1 ? " is" : "s are"} waiting for a bounded retry.`
          : "Stored ciphertext uses the active encryption keys and no unresolved retry remains.";
    checks.push({ id: "key_rotation", status, summary, details: { backlog, retries } });
  } catch (error) {
    checks.push({ id: "key_rotation", status: "fail", summary: "Key-rotation backlog and retry state could not be validated.", details: error instanceof Error ? error.message : String(error) });
  }

  try {
    const integrity = await verifyAuditChain();
    checks.push({ id: "audit_integrity", status: integrity.valid ? "pass" : "fail", summary: integrity.valid ? `Audit chain verified across ${integrity.checked} events.` : "Audit chain verification failed.", details: integrity });
    const checkpoint = await getLatestAuditCheckpoint();
    const age = checkpoint ? Date.now() - Date.parse(checkpoint.createdAt) : Number.POSITIVE_INFINITY;
    const checkpointVerification = checkpoint ? await verifyLatestAuditCheckpoint() : { valid: false, reason: "missing_checkpoint" };
    const checkpointHealthy = integrity.checked === 0 || Boolean(checkpoint && age <= 30 * 60_000 && checkpointVerification.valid);
    checks.push({ id: "audit_checkpoint", status: checkpointHealthy ? "pass" : "fail", summary: integrity.checked === 0 ? "No audit events require a checkpoint yet." : checkpointHealthy ? `Latest audit checkpoint anchors sequence ${checkpoint?.sequence}.` : "The audit log lacks a recent, valid signed checkpoint.", details: checkpoint ? { sequence: checkpoint.sequence, createdAt: checkpoint.createdAt, externalStatus: checkpoint.externalStatus, publicKeyFingerprint: checkpoint.publicKeyFingerprint, verification: checkpointVerification } : checkpointVerification });
    if (checkpoint && checkpoint.externalStatus !== "delivered") checks.push({ id: "independent_checkpoint", status: "fail", summary: checkpoint.externalStatus === "failed" ? "Independent checkpoint delivery failed." : "Independent checkpoint delivery is not configured." });
  } catch (error) {
    checks.push({ id: "audit_integrity", status: "fail", summary: "Audit integrity could not be verified.", details: error instanceof Error ? error.message : String(error) });
  }

  const collectorCounts = await env.DB.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN status = 'healthy' THEN 1 ELSE 0 END) AS healthy, SUM(CASE WHEN status = 'action_needed' THEN 1 ELSE 0 END) AS action_needed FROM collectors WHERE enabled = 1").first<{ total: number; healthy: number; action_needed: number }>();
  const healthy = Number(collectorCounts?.healthy || 0);
  checks.push({ id: "collectors", status: healthy > 0 && Number(collectorCounts?.action_needed || 0) === 0 ? "pass" : "warn", summary: healthy > 0 ? `${healthy} evidence collectors are healthy.` : "No evidence collector is currently healthy.", details: collectorCounts });
  const activeAssessments = await env.DB.prepare("SELECT COUNT(*) AS count FROM assessments WHERE status = 'active'").first<{ count: number }>();
  checks.push({ id: "active_assessment", status: Number(activeAssessments?.count || 0) > 0 ? "pass" : "warn", summary: Number(activeAssessments?.count || 0) > 0 ? "At least one assessment is active." : "No assessment is active; scheduled collection will remain paused." });

  const jiraConfigured = Boolean(env.JIRA_OAUTH_CLIENT_ID && env.JIRA_OAUTH_CLIENT_SECRET && env.JIRA_OAUTH_CALLBACK_URL && (env.JIRA_OAUTH_KEYRING_JSON || env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY));
  checks.push({ id: "jira_cloud", status: jiraConfigured ? "pass" : "warn", summary: jiraConfigured ? "Jira Cloud OAuth is configured." : "Jira Cloud OAuth is not configured." });
  const timestampConfigured = Boolean(
    env.RFC3161_TSA_URL
      && env.RFC3161_VERIFIER_URL
      && env.RFC3161_VERIFIER_TOKEN
      && env.RFC3161_VERIFIER_ALLOWED_HOSTS
      && env.RFC3161_TSA_TRUST_ANCHOR_SHA256
      && (env.RFC3161_VERIFIER_PUBLIC_KEY || env.RFC3161_VERIFIER_PUBLIC_KEYS),
  );
  const timestampRequired = env.REQUIRE_TRUSTED_TIMESTAMP !== "false";
  const timestampFlagValid = env.REQUIRE_TRUSTED_TIMESTAMP === undefined || ["true", "false"].includes(env.REQUIRE_TRUSTED_TIMESTAMP);
  let timestampConfiguration: Awaited<ReturnType<typeof validateTrustedTimestampConfiguration>> | null = null;
  let timestampConfigurationError: string | null = null;
  if (timestampConfigured) {
    try { timestampConfiguration = await validateTrustedTimestampConfiguration(env); }
    catch (error) { timestampConfigurationError = error instanceof Error ? error.message : String(error); }
  }
  checks.push({ id: "trusted_timestamp_policy", status: timestampFlagValid && timestampRequired ? "pass" : "fail", summary: !timestampFlagValid ? "REQUIRE_TRUSTED_TIMESTAMP must be true or false." : timestampRequired ? "Native evidence fails closed unless an independent timestamp is verified." : "Trusted timestamp enforcement is disabled; production readiness cannot be asserted." });
  checks.push({ id: "trusted_timestamp", status: timestampConfigured && timestampConfiguration ? "pass" : "fail", summary: timestampConfigured && timestampConfiguration ? "Trusted timestamp issuance and verification are configured and structurally valid." : "External RFC 3161 timestamping is required for production readiness but is missing or invalid.", details: timestampConfiguration || timestampConfigurationError });
  return { ready: checks.every((check) => check.status !== "fail"), checkedAt: new Date().toISOString(), checks };
}
