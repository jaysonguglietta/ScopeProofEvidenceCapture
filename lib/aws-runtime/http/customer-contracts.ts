import { TenantSecurityError, assertSafeJson, type JsonValue } from "../contracts.ts";
import type { TenantPermission } from "../tenancy.ts";

/** Operator-assisted existing-Cognito-subject pilot; not email signup. */
export const customerRoutes = {
  "/v1/customer/members/search": { action: "members.search", permission: "tenant:manage", keys: ["cursor", "limit"] },
  "/v1/customer/invitations": { action: "members.invite", permission: "tenant:manage", keys: ["subject", "email", "displayName", "role"] },
  "/v1/customer/members/update": { action: "members.update", permission: "tenant:manage", keys: ["principalId", "expectedRevision", "status", "role"] },
  "/v1/customer/devices/search": { action: "devices.search", permission: "device:manage", keys: ["cursor", "limit"] },
  "/v1/customer/devices/enroll": { action: "devices.enroll", permission: "evidence:collect", keys: ["deviceId", "displayName", "publicKeySpki", "signature", "signedAt"] },
  "/v1/customer/devices/revoke": { action: "devices.revoke", permission: "device:manage", keys: ["deviceId", "expectedRevision"] },
  "/v1/customer/assessments/search": { action: "assessments.search", permission: "evidence:read", keys: ["cursor", "limit"] },
  "/v1/customer/collector-assessments/search": { action: "assessments.search", permission: "evidence:collect", keys: ["cursor", "limit"] },
  "/v1/customer/assessments/create": { action: "assessments.create", permission: "jobs:manage", keys: ["idempotencyKey", "name", "periodStart", "periodEnd", "catalogId", "systems", "controls", "status"] },
  "/v1/customer/assessments/update": { action: "assessments.update", permission: "jobs:manage", keys: ["assessmentId", "expectedRevision", "name", "periodStart", "periodEnd", "catalogId", "systems", "controls", "status"] },
  "/v1/customer/evidence/status": { action: "evidence.status", permission: "evidence:read", keys: ["evidenceId"] },
  "/v1/customer/collector-evidence/status": { action: "evidence.status", permission: "evidence:collect", keys: ["evidenceId"] },
  "/v1/customer/evidence/review": { action: "evidence.review", permission: "evidence:approve", keys: ["evidenceId", "expectedRevision", "decision", "reason"] },
} as const satisfies Record<string, { action: string; permission: TenantPermission; keys: readonly string[] }>;

export type CustomerRoute = typeof customerRoutes[keyof typeof customerRoutes];
export type CustomerAction = CustomerRoute["action"];
export type CustomerBody = Readonly<Record<string, JsonValue>>;
export type CustomerReply = Readonly<Record<string, JsonValue>>;

export function customerRoute(path: string): CustomerRoute | undefined { return customerRoutes[path as keyof typeof customerRoutes]; }

export function validateCustomerBody(value: unknown, keys: readonly string[]): CustomerBody {
  const safe = assertSafeJson(value, "Customer request");
  if (!safe || typeof safe !== "object" || Array.isArray(safe) || Object.keys(safe).length !== keys.length || Object.keys(safe).some((key) => !keys.includes(key))) throw new TenantSecurityError("INVALID_IDENTIFIER", "Customer request has missing or unsupported fields.");
  if (new TextEncoder().encode(JSON.stringify(safe)).byteLength > 16_384) throw new TenantSecurityError("INVALID_IDENTIFIER", "Customer request is too large.", 413);
  if ("limit" in safe && (!Number.isSafeInteger(safe.limit) || Number(safe.limit) < 1 || Number(safe.limit) > 100)) throw new TenantSecurityError("INVALID_IDENTIFIER", "Page size must be between one and 100.");
  if ("cursor" in safe && safe.cursor !== null && (typeof safe.cursor !== "string" || !/^(?:usr|dev|asm)_[a-f0-9]{32}$/.test(safe.cursor))) throw new TenantSecurityError("INVALID_IDENTIFIER", "Page cursor is invalid.");
  for (const key of ["expectedRevision", "expectedEvidenceRevision", "expectedHoldRevision"]) if (key in safe && (!Number.isSafeInteger(safe[key]) || Number(safe[key]) < 0)) throw new TenantSecurityError("INVALID_IDENTIFIER", "An expected revision is required.");
  return safe as CustomerBody;
}

export const customerAuditActions = ["customer.members_invited", "customer.members_updated", "customer.invitation_accepted", "customer.devices_enrolled", "customer.devices_revoked", "customer.assessments_created", "customer.assessments_updated", "customer.evidence_reviewed"] as const;
