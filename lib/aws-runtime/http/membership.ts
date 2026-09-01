import {
  asMembershipId,
  asTenantId,
  asUserId,
  assertBoundedText,
  TenantSecurityError,
  type TenantId,
} from "../contracts.ts";
import {
  authorizeTenantActor,
  type AuthenticatedPrincipal,
  type ResolvedTenantAuthority,
  type TenantActor,
  type TenantMembership,
  type TenantPermission,
} from "../tenancy.ts";
import type { VerifiedCognitoAccessToken } from "./jwt.ts";

export interface MembershipIdentityRecord {
  readonly tenantId: TenantId;
  readonly identitySubject: string;
  readonly membership: TenantMembership;
}

export interface TenantMembershipRepository {
  /** The implementation must parameterize both values and apply the tenant RLS context. */
  findActiveByIdentity(input: Readonly<{ tenantId: TenantId; identitySubject: string }>): Promise<MembershipIdentityRecord | null>;
}

export interface DataApiStringParameter {
  readonly name: string;
  readonly value: Readonly<{ stringValue: string }>;
}

export interface RdsDataApiExecutor {
  beginTransaction(input: Readonly<{ resourceArn: string; secretArn: string; database: string }>): Promise<Readonly<{ transactionId?: string }>>;
  executeStatement(input: Readonly<{
    resourceArn: string;
    secretArn: string;
    database: string;
    transactionId: string;
    sql: string;
    parameters: readonly DataApiStringParameter[];
    formatRecordsAs?: "JSON";
  }>): Promise<Readonly<{ formattedRecords?: string }>>;
  commitTransaction(input: Readonly<{ resourceArn: string; secretArn: string; transactionId: string }>): Promise<unknown>;
  rollbackTransaction(input: Readonly<{ resourceArn: string; secretArn: string; transactionId: string }>): Promise<unknown>;
}

export interface RdsDataMembershipRepositoryOptions {
  readonly executor: RdsDataApiExecutor;
  readonly resourceArn: string;
  readonly secretArn: string;
  readonly database: string;
  /**
   * Uses a tenant-scoped SECURITY DEFINER function instead of direct table
   * SELECTs. Public, operation-specific APIs should use this mode so their
   * database login can remain an execute-only allow list.
   */
  readonly lookupMode?: "direct_tables" | "security_definer_function";
}

interface MembershipJsonRow {
  readonly tenant_id: unknown;
  readonly identity_subject: unknown;
  readonly membership_id: unknown;
  readonly principal_id: unknown;
  readonly role: unknown;
}

const setTenantSql = "SELECT pg_catalog.set_config('scopeproof.tenant_id', :tenant_id, true)";
const findMembershipSql = [
  "SELECT m.tenant_id::text AS tenant_id, p.cognito_sub AS identity_subject,",
  "       m.id::text AS membership_id, p.id::text AS principal_id, m.role",
  "FROM scopeproof.memberships AS m",
  "JOIN scopeproof.principals AS p",
  "  ON p.tenant_id = m.tenant_id AND p.id = m.principal_id",
  "WHERE m.tenant_id = CAST(:tenant_id AS scopeproof.tenant_identifier)",
  "  AND p.cognito_sub = :identity_subject",
  "  AND p.status = 'ACTIVE' AND m.status = 'ACTIVE'",
  "LIMIT 2",
].join("\n");
const findMembershipFunctionSql = [
  "SELECT tenant_id::text AS tenant_id, identity_subject,",
  "       membership_id::text AS membership_id, principal_id::text AS principal_id, role",
  "FROM scopeproof.resolve_active_membership(:identity_subject)",
].join("\n");

function parseRows(value: string | undefined): readonly MembershipJsonRow[] {
  if (!value || value.length > 32_768) throw new TenantSecurityError("INVALID_PRINCIPAL", "Membership lookup response is invalid.", 500);
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new TenantSecurityError("INVALID_PRINCIPAL", "Membership lookup response is invalid.", 500);
  }
  if (!Array.isArray(parsed) || parsed.length > 2 || parsed.some((row) => !row || typeof row !== "object" || Array.isArray(row))) {
    throw new TenantSecurityError("INVALID_PRINCIPAL", "Membership lookup response is invalid.", 500);
  }
  return parsed as MembershipJsonRow[];
}

export class RdsDataMembershipRepository implements TenantMembershipRepository {
  readonly #executor: RdsDataApiExecutor;
  readonly #connection: Readonly<{ resourceArn: string; secretArn: string; database: string }>;
  readonly #lookupMode: "direct_tables" | "security_definer_function";

  constructor(options: RdsDataMembershipRepositoryOptions) {
    this.#executor = options.executor;
    const resourceArn = String(options.resourceArn || "");
    const secretArn = String(options.secretArn || "");
    const resource = /^arn:(aws|aws-us-gov|aws-cn):rds:([a-z0-9-]+):(\d{12}):cluster:[A-Za-z0-9-]{1,63}$/.exec(resourceArn);
    const secret = /^arn:(aws|aws-us-gov|aws-cn):secretsmanager:([a-z0-9-]+):(\d{12}):secret:[A-Za-z0-9/_+=.@-]{1,512}$/.exec(secretArn);
    if (!resource) throw new Error("RDS resource ARN is invalid.");
    if (!secret) throw new Error("RDS secret ARN is invalid.");
    if (resource[1] !== secret[1] || resource[2] !== secret[2] || resource[3] !== secret[3]) throw new Error("RDS cluster and secret must use the same partition, region, and account.");
    const database = String(options.database || "");
    if (!/^[A-Za-z][A-Za-z0-9_]{0,62}$/.test(database)) throw new Error("Database name is invalid.");
    // Public adapters should fail toward the execute-only database boundary.
    // Direct table reads remain an explicit opt-in for trusted maintenance
    // tooling and must never be selected accidentally by omitting an option.
    const lookupMode = options.lookupMode ?? "security_definer_function";
    if (lookupMode !== "direct_tables" && lookupMode !== "security_definer_function") {
      throw new Error("Membership lookup mode is invalid.");
    }
    this.#lookupMode = lookupMode;
    this.#connection = Object.freeze({
      resourceArn,
      secretArn,
      database,
    });
  }

  async findActiveByIdentity(input: Readonly<{ tenantId: TenantId; identitySubject: string }>): Promise<MembershipIdentityRecord | null> {
    const tenantId = asTenantId(input.tenantId);
    const identitySubject = assertBoundedText(input.identitySubject, "Identity subject", 3, 200);
    const transaction = await this.#executor.beginTransaction(this.#connection);
    if (!transaction.transactionId || !/^[A-Za-z0-9-]{8,256}$/.test(transaction.transactionId)) throw new TenantSecurityError("INVALID_PRINCIPAL", "Membership transaction could not be established.", 500);
    const transactionId = transaction.transactionId;
    try {
      await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql: setTenantSql,
        parameters: [{ name: "tenant_id", value: { stringValue: tenantId } }],
      });
      const result = await this.#executor.executeStatement({
        ...this.#connection,
        transactionId,
        sql: this.#lookupMode === "security_definer_function" ? findMembershipFunctionSql : findMembershipSql,
        parameters: this.#lookupMode === "security_definer_function"
          ? [{ name: "identity_subject", value: { stringValue: identitySubject } }]
          : [
              { name: "tenant_id", value: { stringValue: tenantId } },
              { name: "identity_subject", value: { stringValue: identitySubject } },
            ],
        formatRecordsAs: "JSON",
      });
      const rows = parseRows(result.formattedRecords);
      if (rows.length > 1) throw new TenantSecurityError("INVALID_PRINCIPAL", "Identity is assigned more than once.", 500);
      let record: MembershipIdentityRecord | null = null;
      if (rows.length === 1) {
        const row = rows[0];
        if (row.tenant_id !== tenantId || row.identity_subject !== identitySubject || typeof row.role !== "string" || !["admin", "compliance_lead", "reviewer", "auditor", "collector"].includes(row.role)) {
          throw new TenantSecurityError("INVALID_PRINCIPAL", "Membership lookup response is invalid.", 500);
        }
        const userId = asUserId(String(row.principal_id || ""));
        const membership: TenantMembership = Object.freeze({
          id: asMembershipId(String(row.membership_id || "")),
          tenantId,
          userId,
          role: row.role as TenantMembership["role"],
          status: "active",
        });
        record = Object.freeze({ tenantId, identitySubject, membership });
      }
      await this.#executor.commitTransaction({ resourceArn: this.#connection.resourceArn, secretArn: this.#connection.secretArn, transactionId });
      return record;
    } catch (error) {
      try {
        await this.#executor.rollbackTransaction({ resourceArn: this.#connection.resourceArn, secretArn: this.#connection.secretArn, transactionId });
      } catch {
        // Preserve the original failure. AWS monitoring must alert on rollback errors.
      }
      throw error;
    }
  }
}

export async function authorizeVerifiedTenantIdentity(input: Readonly<{
  resolved: ResolvedTenantAuthority;
  identity: VerifiedCognitoAccessToken;
  memberships: TenantMembershipRepository;
  permission: TenantPermission;
}>): Promise<Readonly<{ actor: TenantActor; principal: AuthenticatedPrincipal }>> {
  if (input.identity.signatureVerified !== true || input.identity.tokenUse !== "access") throw new TenantSecurityError("INVALID_PRINCIPAL", "Authentication token is invalid.", 401);
  const authorizedClients = input.resolved.tenant.appClientIds ?? [input.resolved.tenant.appClientId];
  if (!authorizedClients.includes(input.identity.clientId)) {
    throw new TenantSecurityError("INVALID_PRINCIPAL", "Authentication token is invalid for this tenant.", 401);
  }
  const record = await input.memberships.findActiveByIdentity({ tenantId: input.resolved.tenant.id, identitySubject: input.identity.subject });
  if (!record || record.tenantId !== input.resolved.tenant.id || record.identitySubject !== input.identity.subject) {
    throw new TenantSecurityError("MEMBERSHIP_REQUIRED", "Active tenant membership is required.", 403);
  }
  const principal: AuthenticatedPrincipal = Object.freeze({
    signatureVerified: true,
    userId: record.membership.userId,
    subject: input.identity.subject,
    issuer: input.identity.issuer,
    audience: input.identity.clientId,
    tokenUse: "access",
    authenticatedAt: input.identity.authenticatedAt,
    expiresAt: input.identity.expiresAt,
  });
  const actor = authorizeTenantActor({ resolved: input.resolved, principal, membership: record.membership, permission: input.permission });
  return Object.freeze({ actor, principal });
}
