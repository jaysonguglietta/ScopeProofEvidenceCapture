import { createHash } from "node:crypto";

const tenantIdPattern = /^ten_[a-f0-9]{32}$/;
const operationIdPattern = /^lho_[a-f0-9]{32}$/;
const evidenceIdPattern = /^evd_[a-f0-9]{32}$/;
const holdIdPattern = /^hld_[a-f0-9]{32}$/;
const userIdPattern = /^usr_[a-f0-9]{32}$/;
const bucketPattern = /^(?=.{3,63}$)(?!xn--)(?!.*\.\.)(?!.*-$)[a-z0-9][a-z0-9.-]*[a-z0-9]$/;
const controlIdPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const versionIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$/;
const tablePattern = /^[A-Za-z0-9_.-]{3,255}$/;
const sha256Pattern = /^[a-f0-9]{64}$/;

function stableJson(value) {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isSafeInteger(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(",")}}`;
  }
  throw new Error("Recovery ledger data is not canonical JSON.");
}

function digestHex(value) {
  return createHash("sha256").update(value).digest("hex");
}

function assertAuditProof(proof, tenantId, operationId) {
  exactObjectKeys(proof, ["canonicalPayload", "eventHash", "keyArn", "payloadSha256", "signature", "signingAlgorithm"], "Legal-hold audit proof");
  let payload;
  try { payload = JSON.parse(proof.canonicalPayload); } catch { throw new Error("Legal-hold audit proof is invalid."); }
  exactObjectKeys(payload, ["action", "domain", "eventHash", "eventId", "occurredAt", "outcome", "previousHash", "requestId", "resourceId", "resourceType", "schemaVersion", "sequence", "signedAt", "tenantId"], "Legal-hold audit receipt payload");
  const expectedEventId = `evt_${digestHex(`scopeproof-legal-hold-audit-v1\0${operationId}`).slice(0, 32)}`;
  if (
    stableJson(payload) !== proof.canonicalPayload || payload?.domain !== "scopeproof-audit-receipt-v1" ||
    payload?.schemaVersion !== 1 || payload?.tenantId !== tenantId || payload?.resourceId !== operationId ||
    payload?.action !== "evidence.legal_hold_applied" || payload?.outcome !== "succeeded" ||
    payload?.eventId !== expectedEventId || payload?.resourceType !== "legal_hold_operation" ||
    payload?.requestId !== `legal-hold-${operationId}` || !Number.isSafeInteger(payload?.sequence) || payload.sequence < 1 ||
    canonicalInstant(payload?.occurredAt, "Legal-hold audit occurrence time") !== payload.occurredAt ||
    canonicalInstant(payload?.signedAt, "Legal-hold audit signing time") !== payload.signedAt ||
    Date.parse(payload.signedAt) < Date.parse(payload.occurredAt) ||
    (payload.sequence === 1 ? payload.previousHash !== "GENESIS" : !sha256Pattern.test(payload.previousHash)) ||
    payload?.eventHash !== proof.eventHash || !sha256Pattern.test(proof.eventHash) ||
    digestHex(`scopeproof-audit-receipt-v1\0${proof.canonicalPayload}`) !== proof.payloadSha256 ||
    !sha256Pattern.test(proof.payloadSha256) ||
    !/^arn:(aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:\d{12}:key\/[0-9a-f-]{36}$/.test(proof.keyArn) ||
    proof.signingAlgorithm !== "RSASSA_PSS_SHA_256" ||
    typeof proof.signature !== "string" || proof.signature.length !== 512 || !/^[A-Za-z0-9+/]{512}$/.test(proof.signature)
  ) throw new Error("Legal-hold audit proof is invalid.");
  return Object.freeze(proof);
}

function canonicalInstant(value, label) {
  const date = value instanceof Date ? value : new Date(String(value ?? ""));
  if (!Number.isFinite(date.getTime()) || date.toISOString() !== (value instanceof Date ? date.toISOString() : value)) {
    throw new Error(`${label} is invalid.`);
  }
  return date.toISOString();
}

function exactObjectKeys(value, expected, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(`${label} is invalid.`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} is invalid.`);
  }
}

function attributeString(item, name) {
  const attribute = item?.[name];
  if (!attribute || Object.keys(attribute).length !== 1 || typeof attribute.S !== "string") {
    throw new Error("Recovery ledger record is invalid.");
  }
  return attribute.S;
}

function attributeNumber(item, name) {
  const attribute = item?.[name];
  if (!attribute || Object.keys(attribute).length !== 1 || !/^(?:0|[1-9][0-9]*)$/.test(String(attribute.N ?? ""))) {
    throw new Error("Recovery ledger record is invalid.");
  }
  const value = Number(attribute.N);
  if (!Number.isSafeInteger(value)) throw new Error("Recovery ledger record is invalid.");
  return value;
}

export function recoveryPartitionKey(tenantId) {
  if (!tenantIdPattern.test(String(tenantId ?? ""))) throw new Error("Recovery ledger tenant is invalid.");
  return `RECOVERY#TENANT#${tenantId}`;
}

export function recoveryChangeBounds(afterIso, cutoffIso) {
  const after = canonicalInstant(afterIso, "Recovery ledger lower bound");
  const cutoff = canonicalInstant(cutoffIso, "Recovery ledger cutoff");
  if (Date.parse(after) >= Date.parse(cutoff)) throw new Error("Recovery ledger interval is invalid.");
  return Object.freeze({
    after: `CHANGE#${after}~`,
    cutoff: `CHANGE#${cutoff}~`,
  });
}

export function legalHoldRecoveryCurrentKey(input) {
  const tenantId = String(input?.tenantId ?? "");
  const bucket = String(input?.bucket ?? "");
  const key = String(input?.key ?? "");
  const versionId = String(input?.versionId ?? "");
  if (
    !tenantIdPattern.test(tenantId) || !bucketPattern.test(bucket) ||
    !key.startsWith(`tenants/${tenantId}/controls/`) || key.length > 1_024 ||
    !versionIdPattern.test(versionId)
  ) {
    throw new Error("Legal-hold recovery target is invalid.");
  }
  const identity = stableJson({ bucket, key, tenantId, versionId });
  return `LEGAL_HOLD_VERSION#${digestHex(`scopeproof-legal-hold-recovery-version-v1\n${identity}`)}`;
}

export function buildPromotionRecoveryChangeItem(input) {
  const tenantId = String(input?.tenantId ?? "");
  const receiptHash = String(input?.receiptHash ?? "");
  const publishedAt = canonicalInstant(input?.publishedAt, "Promotion recovery publication time");
  const facts = input?.facts;
  if (
    !tenantIdPattern.test(tenantId) ||
    !sha256Pattern.test(receiptHash) ||
    !facts || typeof facts !== "object" || Array.isArray(facts) ||
    facts.tenantId !== tenantId ||
    !bucketPattern.test(String(facts.evidenceBucket ?? "")) ||
    !String(facts.evidenceKey ?? "").startsWith(`tenants/${tenantId}/controls/`) ||
    String(facts.evidenceKey).length > 1_024 ||
    !versionIdPattern.test(String(facts.evidenceVersionId ?? ""))
  ) {
    throw new Error("Promotion recovery change is invalid.");
  }
  return Object.freeze({
    PK: { S: recoveryPartitionKey(tenantId) },
    SK: { S: `CHANGE#${publishedAt}#PROMOTION#${receiptHash}` },
    bucket: { S: facts.evidenceBucket },
    changeType: { S: "PROMOTION" },
    key: { S: facts.evidenceKey },
    kind: { S: "EvidenceRecoveryChange" },
    publishedAt: { S: publishedAt },
    receiptHash: { S: receiptHash },
    schemaVersion: { N: "1" },
    tenantId: { S: tenantId },
    versionId: { S: facts.evidenceVersionId },
  });
}

export function parseRecoveryChangeItem(item, expected) {
  const changeType = attributeString(item, "changeType");
  const expectedKeys = changeType === "PROMOTION"
    ? ["PK", "SK", "bucket", "changeType", "key", "kind", "publishedAt", "receiptHash", "schemaVersion", "tenantId", "versionId"]
    : changeType === "LEGAL_HOLD"
      ? ["PK", "SK", "appliedAt", "auditCanonicalPayload", "auditEventHash", "auditKeyArn", "auditPayloadSha256", "auditSignature", "auditSigningAlgorithm", "bucket", "changeType", "currentKey", "key", "kind", "operationId", "publishedAt", "requestDigest", "schemaVersion", "status", "tenantId", "versionId"]
      : [];
  exactObjectKeys(item, expectedKeys, "Recovery ledger record");
  const tenantId = attributeString(item, "tenantId");
  const publishedAt = canonicalInstant(attributeString(item, "publishedAt"), "Recovery change publication time");
  const bucket = attributeString(item, "bucket");
  const key = attributeString(item, "key");
  const versionId = attributeString(item, "versionId");
  const identity = changeType === "PROMOTION"
    ? attributeString(item, "receiptHash")
    : attributeString(item, "operationId");
  const expectedSortKey = `CHANGE#${publishedAt}#${changeType}#${identity}`;
  if (
    expectedKeys.length === 0 ||
    attributeNumber(item, "schemaVersion") !== 1 ||
    tenantId !== expected?.tenantId ||
    attributeString(item, "PK") !== recoveryPartitionKey(tenantId) ||
    attributeString(item, "SK") !== expectedSortKey ||
    attributeString(item, "kind") !== "EvidenceRecoveryChange" ||
    bucket !== expected?.sourceBucket ||
    !key.startsWith(`tenants/${tenantId}/controls/`) || key.length > 1_024 ||
    !versionIdPattern.test(versionId) ||
    (changeType === "PROMOTION" && !sha256Pattern.test(identity)) ||
    (changeType === "LEGAL_HOLD" && (!operationIdPattern.test(identity) || !sha256Pattern.test(attributeString(item, "requestDigest"))))
  ) {
    throw new Error("Recovery ledger record is invalid.");
  }
  const result = {
    bucket,
    changeType,
    key,
    publishedAt,
    tenantId,
    versionId,
  };
  if (changeType === "PROMOTION") return Object.freeze({ ...result, receiptHash: identity });
  const appliedAt = canonicalInstant(attributeString(item, "appliedAt"), "Legal-hold application time");
  const currentKey = attributeString(item, "currentKey");
  const status = attributeString(item, "status");
  if (
    Date.parse(appliedAt) > Date.parse(publishedAt) ||
    !["ON", "OFF"].includes(status) ||
    currentKey !== legalHoldRecoveryCurrentKey({ bucket, key, tenantId, versionId })
  ) throw new Error("Recovery ledger record is invalid.");
  return Object.freeze({
    ...result,
    appliedAt,
    currentKey,
    operationId: identity,
    requestDigest: attributeString(item, "requestDigest"),
    status,
    audit: assertAuditProof({
      canonicalPayload: attributeString(item, "auditCanonicalPayload"),
      eventHash: attributeString(item, "auditEventHash"),
      keyArn: attributeString(item, "auditKeyArn"),
      payloadSha256: attributeString(item, "auditPayloadSha256"),
      signature: attributeString(item, "auditSignature"),
      signingAlgorithm: attributeString(item, "auditSigningAlgorithm"),
    }, tenantId, identity),
  });
}

function assertLegalHoldOperation(operation, tenantId) {
  const keys = [
    "bucket", "canonicalRequest", "changedAt", "controlId", "evidenceId", "expectedHoldRevision",
    "holdId", "key", "kind", "operationId", "reason", "requestDigest", "requestedBy",
    "schemaVersion", "status", "tenantId", "versionId",
  ];
  exactObjectKeys(operation, keys, "Legal-hold recovery operation");
  const canonicalFacts = {
    bucket: operation.bucket,
    changedAt: operation.changedAt,
    controlId: operation.controlId,
    evidenceId: operation.evidenceId,
    expectedHoldRevision: operation.expectedHoldRevision,
    holdId: operation.holdId,
    key: operation.key,
    kind: operation.kind,
    operationId: operation.operationId,
    reason: operation.reason,
    requestedBy: operation.requestedBy,
    schemaVersion: operation.schemaVersion,
    status: operation.status,
    tenantId: operation.tenantId,
    versionId: operation.versionId,
  };
  const canonicalRequest = stableJson(canonicalFacts);
  if (
    operation.schemaVersion !== 2 || operation.tenantId !== tenantId ||
    !tenantIdPattern.test(tenantId) || !operationIdPattern.test(operation.operationId) ||
    !holdIdPattern.test(operation.holdId) || !evidenceIdPattern.test(operation.evidenceId) ||
    !userIdPattern.test(operation.requestedBy) || !controlIdPattern.test(operation.controlId) ||
    !bucketPattern.test(operation.bucket) ||
    !operation.key.startsWith(`tenants/${tenantId}/controls/${operation.controlId}/evidence/${operation.evidenceId}.`) ||
    !/\.(?:png|json|spdx\.json|cdx\.json|txt|csv)$/.test(operation.key) || operation.key.length > 1_024 ||
    !versionIdPattern.test(operation.versionId) || !["ON", "OFF"].includes(operation.status) ||
    !["LEGAL", "AUDIT", "SECURITY_INCIDENT"].includes(operation.kind) ||
    typeof operation.reason !== "string" || operation.reason.length < 10 || operation.reason.length > 2_000 ||
    !Number.isSafeInteger(operation.expectedHoldRevision) || operation.expectedHoldRevision < 0 ||
    (operation.status === "ON" && operation.expectedHoldRevision !== 0) ||
    canonicalInstant(operation.changedAt, "Legal-hold change time") !== operation.changedAt ||
    operation.canonicalRequest !== canonicalRequest ||
    operation.requestDigest !== digestHex(`scopeproof-legal-hold-request-v2\n${canonicalRequest}`)
  ) {
    throw new Error("Legal-hold recovery operation failed integrity validation.");
  }
  return operation;
}

function legalPublicationItems(input, publishedAt) {
  const operation = assertLegalHoldOperation(input.operation, input.tenantId);
  const audit = assertAuditProof(input.audit, input.tenantId, operation.operationId);
  const appliedAt = canonicalInstant(input.appliedAt, "Legal-hold application time");
  if (Date.parse(appliedAt) > Date.parse(publishedAt)) {
    throw new Error("Legal-hold publication predates application.");
  }
  const partition = recoveryPartitionKey(input.tenantId);
  const authorityKey = `LEGAL_HOLD#${operation.operationId}`;
  const changeKey = `CHANGE#${publishedAt}#LEGAL_HOLD#${operation.operationId}`;
  const currentKey = legalHoldRecoveryCurrentKey(operation);
  const authority = Object.freeze({
    PK: { S: partition },
    SK: { S: authorityKey },
    appliedAt: { S: appliedAt },
    auditCanonicalPayload: { S: audit.canonicalPayload },
    auditEventHash: { S: audit.eventHash },
    auditKeyArn: { S: audit.keyArn },
    auditPayloadSha256: { S: audit.payloadSha256 },
    auditSignature: { S: audit.signature },
    auditSigningAlgorithm: { S: audit.signingAlgorithm },
    canonicalRequest: { S: operation.canonicalRequest },
    kind: { S: "EvidenceLegalHoldRecoveryPublication" },
    operationId: { S: operation.operationId },
    publishedAt: { S: publishedAt },
    requestDigest: { S: operation.requestDigest },
    schemaVersion: { N: "1" },
    tenantId: { S: input.tenantId },
  });
  const change = Object.freeze({
    PK: { S: partition },
    SK: { S: changeKey },
    appliedAt: { S: appliedAt },
    auditCanonicalPayload: { S: audit.canonicalPayload },
    auditEventHash: { S: audit.eventHash },
    auditKeyArn: { S: audit.keyArn },
    auditPayloadSha256: { S: audit.payloadSha256 },
    auditSignature: { S: audit.signature },
    auditSigningAlgorithm: { S: audit.signingAlgorithm },
    bucket: { S: operation.bucket },
    changeType: { S: "LEGAL_HOLD" },
    currentKey: { S: currentKey },
    key: { S: operation.key },
    kind: { S: "EvidenceRecoveryChange" },
    operationId: { S: operation.operationId },
    publishedAt: { S: publishedAt },
    requestDigest: { S: operation.requestDigest },
    schemaVersion: { N: "1" },
    status: { S: operation.status },
    tenantId: { S: input.tenantId },
    versionId: { S: operation.versionId },
  });
  const current = Object.freeze({
    PK: { S: partition },
    SK: { S: currentKey },
    appliedAt: { S: appliedAt },
    auditCanonicalPayload: { S: audit.canonicalPayload },
    auditEventHash: { S: audit.eventHash },
    auditKeyArn: { S: audit.keyArn },
    auditPayloadSha256: { S: audit.payloadSha256 },
    auditSignature: { S: audit.signature },
    auditSigningAlgorithm: { S: audit.signingAlgorithm },
    bucket: { S: operation.bucket },
    canonicalRequest: { S: operation.canonicalRequest },
    key: { S: operation.key },
    kind: { S: "EvidenceLegalHoldRecoveryCurrent" },
    operationId: { S: operation.operationId },
    publishedAt: { S: publishedAt },
    requestDigest: { S: operation.requestDigest },
    schemaVersion: { N: "1" },
    status: { S: operation.status },
    tenantId: { S: input.tenantId },
    versionId: { S: operation.versionId },
  });
  return Object.freeze({ authority, authorityKey, change, changeKey, current, currentKey, operation, appliedAt, publishedAt });
}

function assertStoredLegalPublication(item, input) {
  exactObjectKeys(item, [
    "PK", "SK", "appliedAt", "auditCanonicalPayload", "auditEventHash", "auditKeyArn", "auditPayloadSha256", "auditSignature", "auditSigningAlgorithm", "canonicalRequest", "kind", "operationId", "publishedAt",
    "requestDigest", "schemaVersion", "tenantId",
  ], "Legal-hold recovery publication");
  const publishedAt = canonicalInstant(attributeString(item, "publishedAt"), "Legal-hold publication time");
  const expected = legalPublicationItems(input, publishedAt);
  const comparable = {
    PK: attributeString(item, "PK"),
    SK: attributeString(item, "SK"),
    appliedAt: attributeString(item, "appliedAt"),
    auditCanonicalPayload: attributeString(item, "auditCanonicalPayload"),
    auditEventHash: attributeString(item, "auditEventHash"),
    auditKeyArn: attributeString(item, "auditKeyArn"),
    auditPayloadSha256: attributeString(item, "auditPayloadSha256"),
    auditSignature: attributeString(item, "auditSignature"),
    auditSigningAlgorithm: attributeString(item, "auditSigningAlgorithm"),
    canonicalRequest: attributeString(item, "canonicalRequest"),
    kind: attributeString(item, "kind"),
    operationId: attributeString(item, "operationId"),
    publishedAt,
    requestDigest: attributeString(item, "requestDigest"),
    schemaVersion: attributeNumber(item, "schemaVersion"),
    tenantId: attributeString(item, "tenantId"),
  };
  const expectedComparable = Object.fromEntries(Object.entries(expected.authority).map(([name, value]) => [name, value.S ?? Number(value.N)]));
  if (stableJson(comparable) !== stableJson(expectedComparable)) {
    throw new Error("Legal-hold recovery publication conflicts with the durable operation.");
  }
  return expected;
}

export function parseLegalHoldRecoveryCurrentItem(item, expected) {
  exactObjectKeys(item, [
    "PK", "SK", "appliedAt", "auditCanonicalPayload", "auditEventHash", "auditKeyArn", "auditPayloadSha256", "auditSignature", "auditSigningAlgorithm", "bucket", "canonicalRequest", "key", "kind", "operationId",
    "publishedAt", "requestDigest", "schemaVersion", "status", "tenantId", "versionId",
  ], "Current legal-hold recovery projection");
  const tenantId = attributeString(item, "tenantId");
  const canonicalRequest = attributeString(item, "canonicalRequest");
  const requestDigest = attributeString(item, "requestDigest");
  let facts;
  try { facts = JSON.parse(canonicalRequest); } catch {
    throw new Error("Current legal-hold recovery projection is invalid.");
  }
  const operation = Object.freeze({ ...facts, canonicalRequest, requestDigest });
  assertLegalHoldOperation(operation, tenantId);
  const audit = assertAuditProof({
    canonicalPayload: attributeString(item, "auditCanonicalPayload"),
    eventHash: attributeString(item, "auditEventHash"),
    keyArn: attributeString(item, "auditKeyArn"),
    payloadSha256: attributeString(item, "auditPayloadSha256"),
    signature: attributeString(item, "auditSignature"),
    signingAlgorithm: attributeString(item, "auditSigningAlgorithm"),
  }, tenantId, operation.operationId);
  const bucket = attributeString(item, "bucket");
  const key = attributeString(item, "key");
  const versionId = attributeString(item, "versionId");
  const currentKey = legalHoldRecoveryCurrentKey({ bucket, key, tenantId, versionId });
  const appliedAt = canonicalInstant(attributeString(item, "appliedAt"), "Current legal-hold application time");
  const publishedAt = canonicalInstant(attributeString(item, "publishedAt"), "Current legal-hold publication time");
  const status = attributeString(item, "status");
  if (
    attributeNumber(item, "schemaVersion") !== 1 ||
    attributeString(item, "PK") !== recoveryPartitionKey(tenantId) ||
    attributeString(item, "SK") !== currentKey ||
    attributeString(item, "kind") !== "EvidenceLegalHoldRecoveryCurrent" ||
    tenantId !== expected?.tenantId || bucket !== expected?.sourceBucket ||
    key !== expected?.key || versionId !== expected?.versionId ||
    attributeString(item, "operationId") !== operation.operationId ||
    status !== operation.status || appliedAt > publishedAt
  ) {
    throw new Error("Current legal-hold recovery projection is invalid.");
  }
  return Object.freeze({
    appliedAt,
    bucket,
    currentKey,
    key,
    operationId: operation.operationId,
    publishedAt,
    requestDigest,
    status,
    tenantId,
    versionId,
    audit,
  });
}

async function getItem(input, key) {
  const response = await input.client.send(new input.GetItemCommand({
    ConsistentRead: true,
    Key: { PK: { S: recoveryPartitionKey(input.tenantId) }, SK: { S: key } },
    TableName: input.tableName,
  }));
  return response?.Item;
}

async function readExistingLegalPublication(input) {
  const authorityKey = `LEGAL_HOLD#${input.operation.operationId}`;
  const authority = await getItem(input, authorityKey);
  if (!authority) return undefined;
  const expected = assertStoredLegalPublication(authority, input);
  const change = await getItem(input, expected.changeKey);
  if (!change) throw new Error("Legal-hold recovery publication is missing its atomic change record.");
  const parsed = parseRecoveryChangeItem(change, {
    sourceBucket: expected.operation.bucket,
    tenantId: input.tenantId,
  });
  if (
    parsed.changeType !== "LEGAL_HOLD" ||
    parsed.operationId !== expected.operation.operationId ||
    parsed.requestDigest !== expected.operation.requestDigest ||
    parsed.appliedAt !== expected.appliedAt ||
    parsed.status !== expected.operation.status ||
    parsed.currentKey !== expected.currentKey ||
    parsed.audit.eventHash !== input.audit.eventHash ||
    parsed.audit.payloadSha256 !== input.audit.payloadSha256 ||
    parsed.audit.signature !== input.audit.signature
  ) {
    throw new Error("Legal-hold recovery change conflicts with its authoritative publication.");
  }
  const currentItem = await getItem(input, expected.currentKey);
  if (!currentItem) throw new Error("Legal-hold recovery publication is missing its current-state projection.");
  const current = parseLegalHoldRecoveryCurrentItem(currentItem, {
    key: expected.operation.key,
    sourceBucket: expected.operation.bucket,
    tenantId: input.tenantId,
    versionId: expected.operation.versionId,
  });
  if (
    Date.parse(current.appliedAt) < Date.parse(expected.appliedAt) ||
    (current.operationId === expected.operation.operationId &&
      (current.requestDigest !== expected.operation.requestDigest || current.publishedAt !== expected.publishedAt))
      || (current.operationId === expected.operation.operationId &&
        (current.audit.eventHash !== input.audit.eventHash || current.audit.payloadSha256 !== input.audit.payloadSha256 ||
          current.audit.signature !== input.audit.signature))
  ) {
    throw new Error("Legal-hold recovery current state conflicts with the durable operation.");
  }
  return Object.freeze({ changeKey: expected.changeKey, publishedAt: expected.publishedAt });
}

export async function publishLegalHoldRecoveryChange(input) {
  if (
    !input?.client || typeof input.client.send !== "function" ||
    typeof input.GetItemCommand !== "function" || typeof input.TransactWriteItemsCommand !== "function" ||
    !tablePattern.test(String(input.tableName ?? "")) || !tenantIdPattern.test(String(input.tenantId ?? ""))
  ) {
    throw new Error("Legal-hold recovery publisher is not safely configured.");
  }
  assertLegalHoldOperation(input.operation, input.tenantId);
  canonicalInstant(input.appliedAt, "Legal-hold application time");
  const existing = await readExistingLegalPublication(input);
  if (existing) return existing;

  const operation = assertLegalHoldOperation(input.operation, input.tenantId);
  const targetCurrentKey = legalHoldRecoveryCurrentKey(operation);
  const priorCurrentItem = await getItem(input, targetCurrentKey);
  const priorCurrent = priorCurrentItem
    ? parseLegalHoldRecoveryCurrentItem(priorCurrentItem, {
        key: operation.key,
        sourceBucket: operation.bucket,
        tenantId: input.tenantId,
        versionId: operation.versionId,
      })
    : undefined;
  const appliedAt = canonicalInstant(input.appliedAt, "Legal-hold application time");
  if (
    priorCurrent && Date.parse(priorCurrent.appliedAt) === Date.parse(appliedAt) &&
    priorCurrent.operationId !== operation.operationId
  ) {
    throw new Error("Legal-hold recovery operations have an ambiguous application order.");
  }
  const shouldAdvanceCurrent = !priorCurrent || Date.parse(priorCurrent.appliedAt) < Date.parse(appliedAt);

  // This timestamp is intentionally selected for the actual write attempt, not
  // copied from the mutable S3 change. The verifier's safety lag is greater
  // than the publisher Lambda timeout, so a lost response and retry cannot
  // make a newly visible record appear behind an already-advanced watermark.
  let publishedAt = canonicalInstant(input.now, "Legal-hold publication time");
  if (shouldAdvanceCurrent && priorCurrent && Date.parse(publishedAt) <= Date.parse(priorCurrent.publishedAt)) {
    publishedAt = new Date(Date.parse(priorCurrent.publishedAt) + 1).toISOString();
  }
  const records = legalPublicationItems(input, publishedAt);
  const absent = "attribute_not_exists(#pk) AND attribute_not_exists(#sk)";
  const names = { "#pk": "PK", "#sk": "SK" };
  try {
    const transactItems = [
        { Put: { ConditionExpression: absent, ExpressionAttributeNames: names, Item: records.authority, TableName: input.tableName } },
        { Put: { ConditionExpression: absent, ExpressionAttributeNames: names, Item: records.change, TableName: input.tableName } },
    ];
    if (shouldAdvanceCurrent) {
      transactItems.push({ Put: priorCurrent
        ? {
            ConditionExpression: "#operationId = :operationId AND #publishedAt = :publishedAt AND #requestDigest = :requestDigest",
            ExpressionAttributeNames: {
              "#operationId": "operationId",
              "#publishedAt": "publishedAt",
              "#requestDigest": "requestDigest",
            },
            ExpressionAttributeValues: {
              ":operationId": { S: priorCurrent.operationId },
              ":publishedAt": { S: priorCurrent.publishedAt },
              ":requestDigest": { S: priorCurrent.requestDigest },
            },
            Item: records.current,
            TableName: input.tableName,
          }
        : {
            ConditionExpression: absent,
            ExpressionAttributeNames: names,
            Item: records.current,
            TableName: input.tableName,
          } });
    }
    await input.client.send(new input.TransactWriteItemsCommand({
      TransactItems: transactItems,
    }));
    return Object.freeze({ changeKey: records.changeKey, publishedAt });
  } catch (error) {
    const recovered = await readExistingLegalPublication(input);
    if (recovered) return recovered;
    throw error;
  }
}
