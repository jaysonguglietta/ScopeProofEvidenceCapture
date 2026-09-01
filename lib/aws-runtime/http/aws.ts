import { asTenantId, assertBoundedText, sha256Hex, TenantSecurityError } from "../contracts.ts";
import {
  assertTenantCognitoClientId,
  canonicalAuthorityHostname,
  normalizedTenantCognitoClientIds,
  type HostAuthority,
  type ResolvedTenantAuthority,
  type TenantAuthorityResolver,
} from "../tenancy.ts";
import type { EdgeReplayNonceStore } from "./edge.ts";
import type { RdsDataApiExecutor } from "./membership.ts";

interface AwsCommandClient {
  send(command: unknown): Promise<unknown>;
}

interface AwsCommandConstructor<Input> {
  new(input: Input): unknown;
}

interface DynamoAttributeValue {
  readonly S?: string;
  readonly N?: string;
  readonly BOOL?: boolean;
  readonly SS?: readonly string[];
}

export interface DynamoTenantAuthorityCommandConstructors {
  readonly GetItemCommand: AwsCommandConstructor<Readonly<{
    TableName: string;
    Key: Readonly<Record<"PK" | "SK", Readonly<{ S: string }>>>;
    ConsistentRead: true;
    ProjectionExpression: string;
    ExpressionAttributeNames: Readonly<Record<string, string>>;
  }>>;
}

export interface DynamoTenantAuthorityResolverOptions {
  readonly client: AwsCommandClient;
  readonly commands: DynamoTenantAuthorityCommandConstructors;
  readonly tableName: string;
}

const tenantDomainProjectionNames = Object.freeze({
  "#pk": "PK",
  "#sk": "SK",
  "#kind": "kind",
  "#schema": "schemaVersion",
  "#tenant": "tenantId",
  "#host": "hostname",
  "#slug": "slug",
  "#name": "displayName",
  "#client": "appClientId",
  "#clients": "appClientIds",
  "#status": "status",
  "#canonical": "canonical",
});
const tenantDomainProjection = Object.keys(tenantDomainProjectionNames).join(", ");
const tenantSlugPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function unavailableTenant(): TenantSecurityError {
  // Missing and non-active tenants are deliberately indistinguishable.
  return new TenantSecurityError("TENANT_NOT_FOUND", "Tenant not found.", 404);
}

function malformedTenantRegistryRecord(): TenantSecurityError {
  // Do not echo registry values because hostnames and tenant metadata can be sensitive.
  return new TenantSecurityError("INVALID_IDENTIFIER", "Tenant registry record is invalid.", 500);
}

function exactAttributeKeys(value: DynamoAttributeValue, expected: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function exactStringAttribute(item: Readonly<Record<string, DynamoAttributeValue>>, name: string): string {
  const value = item[name];
  if (!value || typeof value.S !== "string" || !exactAttributeKeys(value, ["S"])) throw malformedTenantRegistryRecord();
  return value.S;
}

function exactStringSetAttribute(item: Readonly<Record<string, DynamoAttributeValue>>, name: string): readonly string[] {
  const value = item[name];
  if (!value || !Array.isArray(value.SS) || !exactAttributeKeys(value, ["SS"]) || value.SS.some((entry) => typeof entry !== "string")) {
    throw malformedTenantRegistryRecord();
  }
  return value.SS;
}

/**
 * Production tenant-authority adapter backed by the authoritative control table.
 *
 * Resolution is one strongly-consistent item read. The DOMAIN record therefore
 * duplicates only the non-secret tenant presentation fields and exact Cognito
 * client binding needed to authorize a request without a cross-item race.
 */
export class DynamoTenantAuthorityResolver implements TenantAuthorityResolver {
  readonly #client: AwsCommandClient;
  readonly #commands: DynamoTenantAuthorityCommandConstructors;
  readonly #tableName: string;

  constructor(options: DynamoTenantAuthorityResolverOptions) {
    const tableName = String(options.tableName || "");
    if (!options.client || typeof options.client.send !== "function") throw new Error("DynamoDB client is required.");
    if (!options.commands || typeof options.commands.GetItemCommand !== "function") throw new Error("DynamoDB GetItem command is required.");
    if (!/^[A-Za-z0-9_.-]{3,255}$/.test(tableName)) throw new Error("DynamoDB table name is invalid.");
    this.#client = options.client;
    this.#commands = options.commands;
    this.#tableName = tableName;
  }

  async resolve(authority: HostAuthority): Promise<ResolvedTenantAuthority> {
    const hostname = canonicalAuthorityHostname(authority);
    const partitionKey = `DOMAIN#${hostname}`;
    const response = await this.#client.send(new this.#commands.GetItemCommand({
      TableName: this.#tableName,
      Key: { PK: { S: partitionKey }, SK: { S: "METADATA" } },
      ConsistentRead: true,
      ProjectionExpression: tenantDomainProjection,
      ExpressionAttributeNames: tenantDomainProjectionNames,
    })) as Readonly<{ Item?: Readonly<Record<string, DynamoAttributeValue>> }>;
    const item = response?.Item;
    if (!item) throw unavailableTenant();

    // Check lifecycle state first so provisioning, failed, suspended, and closed
    // records are indistinguishable from an unassigned hostname.
    const status = exactStringAttribute(item, "status");
    if (!/^[A-Z][A-Z_]{1,31}$/.test(status)) throw malformedTenantRegistryRecord();
    if (status !== "ACTIVE") throw unavailableTenant();
    if (Object.keys(item).length !== Object.keys(tenantDomainProjectionNames).length) throw malformedTenantRegistryRecord();

    try {
      if (
        exactStringAttribute(item, "PK") !== partitionKey ||
        exactStringAttribute(item, "SK") !== "METADATA" ||
        exactStringAttribute(item, "kind") !== "TenantDomain" ||
        item.schemaVersion?.N !== "2" ||
        !exactAttributeKeys(item.schemaVersion, ["N"]) ||
        item.canonical?.BOOL !== true ||
        !exactAttributeKeys(item.canonical, ["BOOL"])
      ) {
        throw malformedTenantRegistryRecord();
      }
      const storedHostname = canonicalAuthorityHostname({ source: "direct", host: exactStringAttribute(item, "hostname") });
      const tenantId = asTenantId(exactStringAttribute(item, "tenantId"));
      const slug = exactStringAttribute(item, "slug");
      const rawDisplayName = exactStringAttribute(item, "displayName");
      const displayName = assertBoundedText(rawDisplayName, "Tenant name", 1, 160);
      const appClientId = assertTenantCognitoClientId(exactStringAttribute(item, "appClientId"));
      const appClientIds = normalizedTenantCognitoClientIds(exactStringSetAttribute(item, "appClientIds"), appClientId);
      if (storedHostname !== hostname || !tenantSlugPattern.test(slug) || slug.length > 63 || displayName !== rawDisplayName) {
        throw malformedTenantRegistryRecord();
      }
      return Object.freeze({
        tenant: Object.freeze({ id: tenantId, slug, displayName, appClientId, appClientIds, status: "active" as const }),
        domain: Object.freeze({ tenantId, hostname, status: "active" as const, canonical: true as const }),
      });
    } catch (error) {
      if (error instanceof TenantSecurityError && error.safeStatus === 500) throw error;
      throw malformedTenantRegistryRecord();
    }
  }
}

export interface RdsDataApiCommandConstructors {
  readonly BeginTransactionCommand: AwsCommandConstructor<Parameters<RdsDataApiExecutor["beginTransaction"]>[0]>;
  readonly ExecuteStatementCommand: AwsCommandConstructor<Parameters<RdsDataApiExecutor["executeStatement"]>[0]>;
  readonly CommitTransactionCommand: AwsCommandConstructor<Parameters<RdsDataApiExecutor["commitTransaction"]>[0]>;
  readonly RollbackTransactionCommand: AwsCommandConstructor<Parameters<RdsDataApiExecutor["rollbackTransaction"]>[0]>;
}

/**
 * Thin AWS SDK v3 bridge. Passing constructors explicitly keeps the security
 * boundary testable and prevents the browser/Sites bundle from importing the
 * privileged RDS SDK accidentally.
 */
export class AwsSdkV3RdsDataApiExecutor implements RdsDataApiExecutor {
  readonly #client: AwsCommandClient;
  readonly #commands: RdsDataApiCommandConstructors;

  constructor(client: AwsCommandClient, commands: RdsDataApiCommandConstructors) {
    if (!client || typeof client.send !== "function") throw new Error("RDS Data API client is required.");
    this.#client = client;
    this.#commands = commands;
  }

  async beginTransaction(input: Parameters<RdsDataApiExecutor["beginTransaction"]>[0]): ReturnType<RdsDataApiExecutor["beginTransaction"]> {
    return await this.#client.send(new this.#commands.BeginTransactionCommand(input)) as Awaited<ReturnType<RdsDataApiExecutor["beginTransaction"]>>;
  }

  async executeStatement(input: Parameters<RdsDataApiExecutor["executeStatement"]>[0]): ReturnType<RdsDataApiExecutor["executeStatement"]> {
    return await this.#client.send(new this.#commands.ExecuteStatementCommand(input)) as Awaited<ReturnType<RdsDataApiExecutor["executeStatement"]>>;
  }

  async commitTransaction(input: Parameters<RdsDataApiExecutor["commitTransaction"]>[0]): ReturnType<RdsDataApiExecutor["commitTransaction"]> {
    return await this.#client.send(new this.#commands.CommitTransactionCommand(input));
  }

  async rollbackTransaction(input: Parameters<RdsDataApiExecutor["rollbackTransaction"]>[0]): ReturnType<RdsDataApiExecutor["rollbackTransaction"]> {
    return await this.#client.send(new this.#commands.RollbackTransactionCommand(input));
  }
}

export interface DynamoReplayCommandConstructors {
  readonly PutItemCommand: AwsCommandConstructor<Readonly<{
    TableName: string;
    Item: Readonly<Record<string, Readonly<{ S?: string; N?: string }>>>;
    ConditionExpression: string;
    ExpressionAttributeNames: Readonly<Record<string, string>>;
  }>>;
}

export interface DynamoEdgeReplayNonceStoreOptions {
  readonly client: AwsCommandClient;
  readonly commands: DynamoReplayCommandConstructors;
  readonly tableName: string;
  readonly namespace?: string;
  readonly now?: () => Date;
}

/** Atomic replay protection backed by the shared DynamoDB control table. */
export class DynamoEdgeReplayNonceStore implements EdgeReplayNonceStore {
  readonly #client: AwsCommandClient;
  readonly #commands: DynamoReplayCommandConstructors;
  readonly #tableName: string;
  readonly #partitionKey: string;
  readonly #now: () => Date;

  constructor(options: DynamoEdgeReplayNonceStoreOptions) {
    const tableName = String(options.tableName || "");
    const namespace = String(options.namespace ?? "GLOBAL");
    if (!options.client || typeof options.client.send !== "function") throw new Error("DynamoDB client is required.");
    if (!/^[A-Za-z0-9_.-]{3,255}$/.test(tableName)) throw new Error("DynamoDB table name is invalid.");
    if (!/^[A-Z0-9][A-Z0-9_-]{1,63}$/.test(namespace)) throw new Error("Replay namespace is invalid.");
    this.#client = options.client;
    this.#commands = options.commands;
    this.#tableName = tableName;
    this.#partitionKey = `EDGE_REPLAY#${namespace}`;
    this.#now = options.now ?? (() => new Date());
  }

  async consume(nonce: string, expiresAtEpochSeconds: number): Promise<boolean> {
    if (!/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) throw new TenantSecurityError("UNTRUSTED_HOST_SOURCE", "Trusted-edge nonce is invalid.", 421);
    const now = Math.floor(this.#now().getTime() / 1_000);
    if (!Number.isSafeInteger(expiresAtEpochSeconds) || expiresAtEpochSeconds <= now || expiresAtEpochSeconds > now + 600) {
      throw new TenantSecurityError("UNTRUSTED_HOST_SOURCE", "Trusted-edge nonce expiry is invalid.", 421);
    }
    const digest = await sha256Hex(`scopeproof-edge-replay-v1\n${this.#partitionKey}\n${nonce}`);
    try {
      await this.#client.send(new this.#commands.PutItemCommand({
        TableName: this.#tableName,
        Item: {
          PK: { S: this.#partitionKey },
          SK: { S: `NONCE#${digest}` },
          kind: { S: "EdgeReplayNonce" },
          ttlEpochSeconds: { N: String(expiresAtEpochSeconds) },
        },
        ConditionExpression: "attribute_not_exists(#pk) AND attribute_not_exists(#sk)",
        ExpressionAttributeNames: { "#pk": "PK", "#sk": "SK" },
      }));
      return true;
    } catch (error) {
      if (error && typeof error === "object" && "name" in error && error.name === "ConditionalCheckFailedException") return false;
      throw error;
    }
  }
}
