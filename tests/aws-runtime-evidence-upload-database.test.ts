import assert from "node:assert/strict";
import test from "node:test";

import type { RdsDataApiExecutor } from "../lib/aws-runtime/http/membership.ts";
import {
  DynamoAndRdsUploadIntentStore,
  RdsDataUploadIntentProjection,
  type ConditionalUploadIntentStore,
  type ControlledUploadIntent,
  type UploadIntentEvidenceProjection,
} from "../lib/aws-runtime/evidence/index.ts";

const TENANT = `ten_${"a".repeat(32)}`;
const USER = `usr_${"b".repeat(32)}`;
const DEVICE = `dev_${"c".repeat(32)}`;
const ASSESSMENT = `asm_${"d".repeat(32)}`;
const INTENT = `upl_${"e".repeat(32)}`;
const EVIDENCE = `evd_${"f".repeat(32)}`;
const CONTROL = "PCI-DSS-10.2.1";

function intent(): ControlledUploadIntent {
  return {
    schemaVersion: 1,
    id: INTENT as ControlledUploadIntent["id"],
    tenantId: TENANT as ControlledUploadIntent["tenantId"],
    requestedBy: USER as ControlledUploadIntent["requestedBy"],
    resourceId: EVIDENCE as ControlledUploadIntent["resourceId"],
    controlId: CONTROL,
    expectedSha256: "1".repeat(64) as ControlledUploadIntent["expectedSha256"],
    expectedSize: 4_096,
    contentType: "image/png",
    nonceDigest: "2".repeat(64) as ControlledUploadIntent["nonceDigest"],
    quarantineBucket: "scopeproof-quarantine",
    quarantineKmsKeyArn: "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    quarantineKey: `tenants/${TENANT}/controls/${CONTROL}/quarantine/${INTENT}.upload` as ControlledUploadIntent["quarantineKey"],
    finalKey: `tenants/${TENANT}/controls/${CONTROL}/evidence/${EVIDENCE}.png` as ControlledUploadIntent["finalKey"],
    issuedAt: "2026-08-27T16:00:00.000Z",
    expiresAt: "2026-08-27T16:05:00.000Z",
    requiredRetentionUntil: "2027-08-27T16:05:00.000Z",
    idempotencyDigest: "3".repeat(64) as ControlledUploadIntent["idempotencyDigest"],
    requestFingerprint: "4".repeat(64) as ControlledUploadIntent["requestFingerprint"],
    revision: 0,
    status: "issued",
  };
}

function evidence(overrides: Partial<UploadIntentEvidenceProjection> = {}): UploadIntentEvidenceProjection {
  return {
    deviceId: DEVICE,
    assessmentId: ASSESSMENT,
    title: "Quarterly administrator access review",
    description: "Redacted evidence collected from the approved administration surface.",
    evidenceType: "SCREENSHOT",
    source: "Scopeproof Capture",
    systemName: "Production identity provider",
    capturedAt: "2026-08-27T15:59:30.000Z",
    artifactExpiresAt: "2027-08-27T16:00:00.000Z",
    metadata: { catalogVersion: "pci-dss-v4.0.1", tags: ["quarterly", "access-review"] },
    ...overrides,
  };
}

class ProjectionExecutor implements RdsDataApiExecutor {
  readonly calls: Array<{ kind: string; input: Record<string, unknown> }> = [];
  malformed = false;

  async beginTransaction(input: Record<string, string>) {
    this.calls.push({ kind: "begin", input });
    return { transactionId: "transaction-12345678" };
  }

  async executeStatement(input: Parameters<RdsDataApiExecutor["executeStatement"]>[0]) {
    this.calls.push({ kind: "execute", input: input as unknown as Record<string, unknown> });
    if (!input.sql.includes("create_upload_intent")) return {};
    if (this.malformed) return { formattedRecords: "[{\"upload_intent_id\":\"upl_wrong\"}]" };
    return { formattedRecords: JSON.stringify([{
      upload_intent_id: INTENT,
      evidence_id: EVIDENCE,
      was_created: true,
    }]) };
  }

  async commitTransaction(input: Record<string, string>) { this.calls.push({ kind: "commit", input }); }
  async rollbackTransaction(input: Record<string, string>) { this.calls.push({ kind: "rollback", input }); }
}

function projection(executor: RdsDataApiExecutor): RdsDataUploadIntentProjection {
  return new RdsDataUploadIntentProjection({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:tenant-runtime-AbCd",
    database: "scopeproof_acme",
  });
}

test("RDS upload projection calls only the tenant-scoped idempotent procedure with bound data", async () => {
  const executor = new ProjectionExecutor();
  const result = await projection(executor).project(intent(), evidence());
  assert.deepEqual(result, { outcome: "created", uploadIntentId: INTENT, evidenceId: EVIDENCE });
  assert.deepEqual(executor.calls.map((call) => call.kind), ["begin", "execute", "execute", "commit"]);
  const statement = executor.calls[2].input;
  assert.match(String(statement.sql), /scopeproof\.create_upload_intent/);
  assert.doesNotMatch(String(statement.sql), new RegExp(TENANT));
  const parameters = statement.parameters as Array<{ name: string; value: { stringValue: string } }>;
  assert.equal(parameters.find((parameter) => parameter.name === "device_id")?.value.stringValue, DEVICE);
  assert.equal(parameters.find((parameter) => parameter.name === "assessment_id")?.value.stringValue, ASSESSMENT);
  assert.deepEqual(JSON.parse(parameters.find((parameter) => parameter.name === "metadata")!.value.stringValue), evidence().metadata);
});

test("malformed database results roll back and never create a usable reservation", async () => {
  const executor = new ProjectionExecutor();
  executor.malformed = true;
  await assert.rejects(projection(executor).project(intent(), evidence()), /conflicting state/);
  assert.equal(executor.calls.at(-1)?.kind, "rollback");
});

test("Dynamo and RDS composition reprojects exact retries and fails closed at the database boundary", async () => {
  const calls: string[] = [];
  const retry: ConditionalUploadIntentStore = {
    async recoverExact() { return undefined; },
    async reserve(value, recovery) {
      calls.push("dynamo-existing");
      assert.ok(recovery);
      assert.equal(recovery.evidenceProjectionDigest.length, 64);
      assert.equal(JSON.parse(recovery.canonicalEvidenceProjection).deviceId, DEVICE);
      assert.equal(recovery.canonicalEvidenceProjection.includes("idempotency"), false);
      return { outcome: "existing", intent: value };
    },
  };
  const retryExecutor = new ProjectionExecutor();
  const combinedRetry = new DynamoAndRdsUploadIntentStore({ dynamo: retry, database: projection(retryExecutor), evidence: evidence() });
  assert.equal((await combinedRetry.reserve(intent())).outcome, "existing");
  assert.deepEqual(calls, ["dynamo-existing"]);
  assert.deepEqual(retryExecutor.calls.map((call) => call.kind), ["begin", "execute", "execute", "commit"]);

  const failingExecutor = new ProjectionExecutor();
  failingExecutor.malformed = true;
  const reserved: ConditionalUploadIntentStore = {
    async recoverExact() { return undefined; },
    async reserve(value) { calls.push("dynamo-created"); return { outcome: "created", intent: value }; },
  };
  const combined = new DynamoAndRdsUploadIntentStore({
    dynamo: reserved,
    database: projection(failingExecutor),
    evidence: evidence(),
  });
  await assert.rejects(combined.reserve(intent()), /conflicting state/);
  assert.equal(failingExecutor.calls.at(-1)?.kind, "rollback");
});

test("previous-key recovery strongly reads Dynamo and repairs RDS without invoking reservation", async () => {
  const calls: string[] = [];
  const dynamo: ConditionalUploadIntentStore = {
    async recoverExact(value, recovery) {
      calls.push("recover-exact");
      assert.ok(recovery);
      return { outcome: "existing", intent: value };
    },
    async reserve() {
      calls.push("reserve");
      throw new Error("previous-key recovery must never reserve");
    },
  };
  const executor = new ProjectionExecutor();
  const combined = new DynamoAndRdsUploadIntentStore({ dynamo, database: projection(executor), evidence: evidence() });
  const recovered = await combined.recoverExact(intent());
  assert.equal(recovered?.outcome, "existing");
  assert.deepEqual(calls, ["recover-exact"]);
  assert.deepEqual(executor.calls.map((call) => call.kind), ["begin", "execute", "execute", "commit"]);

  calls.length = 0;
  const missingExecutor = new ProjectionExecutor();
  const missing = new DynamoAndRdsUploadIntentStore({
    dynamo: {
      async recoverExact() { calls.push("missing"); return undefined; },
      async reserve(value) { return { outcome: "created", intent: value }; },
    },
    database: projection(missingExecutor),
    evidence: evidence(),
  });
  assert.equal(await missing.recoverExact(intent()), undefined);
  assert.deepEqual(calls, ["missing"]);
  assert.equal(missingExecutor.calls.length, 0);
});

test("an ambiguous RDS commit response is repaired by the same exact Dynamo retry", async () => {
  let existing: ControlledUploadIntent | undefined;
  const dynamo: ConditionalUploadIntentStore = {
    async recoverExact(value) {
      void value;
      return existing ? { outcome: "existing", intent: existing } : undefined;
    },
    async reserve(value) {
      if (existing) return { outcome: "existing", intent: existing };
      existing = value;
      return { outcome: "created", intent: value };
    },
  };
  const executor = new ProjectionExecutor();
  let loseFirstCommitResponse = true;
  const originalCommit = executor.commitTransaction.bind(executor);
  executor.commitTransaction = async (input) => {
    await originalCommit(input);
    if (loseFirstCommitResponse) {
      loseFirstCommitResponse = false;
      throw new Error("response lost after commit");
    }
  };
  const combined = new DynamoAndRdsUploadIntentStore({ dynamo, database: projection(executor), evidence: evidence() });
  await assert.rejects(combined.reserve(intent()), /response lost after commit/);
  const repaired = await combined.reserve(intent());
  assert.equal(repaired.outcome, "existing");
  assert.equal(repaired.intent.id, INTENT);
  assert.equal(executor.calls.filter((call) => call.kind === "begin").length, 2);
  assert.equal(executor.calls.filter((call) => call.kind === "commit").length, 2);
});

test("composition snapshots evidence so caller mutation cannot split Dynamo and RDS facts", async () => {
  const mutable = evidence({ metadata: { catalogVersion: "pci-dss-v4.0.1" } });
  const executor = new ProjectionExecutor();
  let recoveryJson = "";
  const dynamo: ConditionalUploadIntentStore = {
    async recoverExact() { return undefined; },
    async reserve(value, recovery) {
      recoveryJson = recovery?.canonicalEvidenceProjection ?? "";
      (mutable.metadata as { catalogVersion: string }).catalogVersion = "attacker-mutated";
      return { outcome: "created", intent: value };
    },
  };
  const combined = new DynamoAndRdsUploadIntentStore({ dynamo, database: projection(executor), evidence: mutable });
  await combined.reserve(intent());
  assert.equal(JSON.parse(recoveryJson).metadata.catalogVersion, "pci-dss-v4.0.1");
  const parameters = executor.calls[2].input.parameters as Array<{ name: string; value: { stringValue: string } }>;
  assert.equal(JSON.parse(parameters.find((entry) => entry.name === "metadata")!.value.stringValue).catalogVersion, "pci-dss-v4.0.1");
});

test("projection rejects unsafe metadata and retention contradictions before opening RDS", async () => {
  const executor = new ProjectionExecutor();
  await assert.rejects(projection(executor).project(intent(), evidence({ metadata: { access_token: "secret" } })), /forbidden field/);
  await assert.rejects(projection(executor).project(intent(), evidence({ metadata: ["not-an-object"] })), /must be a JSON object/);
  await assert.rejects(projection(executor).project(intent(), evidence({ artifactExpiresAt: "2028-01-01T00:00:00.000Z" })), /retention boundary/);
  await assert.rejects(projection(executor).project(intent(), evidence({ deviceId: `usr_${"c".repeat(32)}` })), /identifier/);
  assert.equal(executor.calls.length, 0);
});
