import { createHash, createHmac, pbkdf2Sync, randomBytes } from "node:crypto";

export const roleKinds = Object.freeze(["provisioning", "runtime", "ingest", "control", "legalApi", "read", "apiAudit"]);
export function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
}
export function mappingDigest(mapping) { return createHash("sha256").update(`scopeproof-database-bootstrap-v1\n${canonical(validateMapping(mapping))}`).digest("hex"); }
export function mappingFromConfig(config) {
  return validateMapping({ schemaVersion: 1, tenantId: config.tenantId, revision: Number(config.bootstrapMappingRevision),
    account: config.awsAccountId, region: config.awsRegion, clusterArn: config.clusterArn, databaseName: config.databaseName,
    ownerUsername: config.databaseOwner, roles: roleKinds.map((kind) => ({ kind,
      username: config[kind === "runtime" ? "databaseUsername" : `${kind}DatabaseUsername`],
      secretArn: config[kind === "runtime" ? "databaseSecretArn" : `${kind}DatabaseSecretArn`],
    })) });
}
export function validateMapping(value) {
  exactKeys(value, ["schemaVersion", "tenantId", "revision", "account", "region", "clusterArn", "databaseName", "ownerUsername", "roles"]);
  if (value.schemaVersion !== 1 || !/^ten_[a-f0-9]{32}$/.test(value.tenantId) || !Number.isSafeInteger(value.revision) || value.revision < 1 || value.revision > 1_000_000 ||
      !/^\d{12}$/.test(value.account) || !/^us-east-1$/.test(value.region) ||
      !new RegExp(`^arn:aws:rds:${value.region}:${value.account}:cluster:[A-Za-z0-9-]{1,63}$`).test(value.clusterArn) ||
      !/^scopeproof_[a-z0-9_]{1,48}$/.test(value.databaseName) ||
      !/^scopeproof_[a-z0-9_]{1,46}_owner$/.test(value.ownerUsername) || !value.ownerUsername.includes(value.tenantId.slice(4)) ||
      !Array.isArray(value.roles) || value.roles.length !== roleKinds.length) throw new Error("Invalid compiled tenant bootstrap mapping.");
  const usernames = new Set([value.ownerUsername]);
  const secrets = new Set();
  for (let index = 0; index < roleKinds.length; index += 1) {
    const role = value.roles[index];
    exactKeys(role, ["kind", "username", "secretArn"]);
    if (role.kind !== roleKinds[index] || !/^[a-z_][a-z0-9_]{1,62}$/.test(role.username) || !role.username.includes(value.tenantId.slice(4)) || usernames.has(role.username) ||
        !new RegExp(`^arn:aws:secretsmanager:${value.region}:${value.account}:secret:[A-Za-z0-9/_+=.@-]{1,512}$`).test(role.secretArn) || secrets.has(role.secretArn)) throw new Error("Invalid or duplicate bootstrap role mapping.");
    usernames.add(role.username); secrets.add(role.secretArn);
  }
  return Object.freeze({ ...value, roles: Object.freeze(value.roles.map((role) => Object.freeze({ ...role }))) });
}
export function validateApproval(item, { mapping, executionId, now }) {
  exactKeys(item, ["PK", "SK", "kind", "decision", "mappingDigest", "executionId", "approvedAt", "expiresAt", "approvedBy"]);
  const start = Date.parse(item.approvedAt?.S ?? "");
  const end = Date.parse(item.expiresAt?.S ?? "");
  if (item.PK?.S !== `BOOTSTRAP#${mapping.tenantId}` || item.SK?.S !== executionId || item.kind?.S !== "DatabaseBootstrapApproval" ||
      item.decision?.S !== "APPROVED" || item.mappingDigest?.S !== mappingDigest(mapping) || item.executionId?.S !== executionId ||
      !new RegExp(`^arn:aws:iam::${mapping.account}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`).test(item.approvedBy?.S ?? "") ||
      !Number.isFinite(now) || !Number.isFinite(start) || !Number.isFinite(end) || start > now || end <= now || end > start + 900_000 || start < now - 900_000 ||
      new Date(start).toISOString() !== item.approvedAt.S || new Date(end).toISOString() !== item.expiresAt.S) throw new Error("Missing, expired, or mismatched bootstrap approval.");
  return true;
}
export function quoteIdentifier(value) { if (!/^[a-z_][a-z0-9_]{0,62}$/.test(value)) throw new Error("Unsafe database identifier."); return `"${value}"`; }
export function literal(value) { if (typeof value !== "string" || [...value].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127)) throw new Error("Unsafe SQL value."); return `'${value.replaceAll("'", "''")}'`; }
export function scramVerifier(password) {
  if (!/^[A-Za-z0-9]{32,128}$/.test(password)) throw new Error("Invalid bootstrap credential.");
  const salt = randomBytes(16), rounds = 4096;
  const salted = pbkdf2Sync(password, salt, rounds, 32, "sha256");
  const stored = createHash("sha256").update(createHmac("sha256", salted).update("Client Key").digest()).digest("base64");
  const server = createHmac("sha256", salted).update("Server Key").digest("base64");
  return `SCRAM-SHA-256$${rounds}:${salt.toString("base64")}$${stored}:${server}`;
}
function exactKeys(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(keys.sort())) throw new Error("Unexpected bootstrap fields.");
}
