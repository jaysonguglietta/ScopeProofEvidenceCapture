import assert from "node:assert/strict";
import test from "node:test";

import {
  loadRotatingUploadIdempotencySecrets,
  parseUploadIdempotencySecret,
  type UploadIdempotencySecretStage,
} from "../lib/aws-runtime/evidence/upload-idempotency-secret-loader.ts";

function secret(character: string): string {
  return JSON.stringify({ schemaVersion: 1, hmacKey: character.repeat(64) });
}

function missingPrevious(message = "Secrets Manager can't find the specified secret value for staging label: AWSPREVIOUS") {
  return Object.assign(new Error(message), {
    name: "ResourceNotFoundException",
    $metadata: { httpStatusCode: 400 },
  });
}

test("secret rotation loads AWSCURRENT first and the optional AWSPREVIOUS key", async () => {
  const calls: UploadIdempotencySecretStage[] = [];
  const loaded = await loadRotatingUploadIdempotencySecrets({
    async getSecretValue(stage) {
      calls.push(stage);
      return { SecretString: secret(stage === "AWSCURRENT" ? "A" : "B") };
    },
  });
  assert.deepEqual(calls, ["AWSCURRENT", "AWSPREVIOUS"]);
  assert.equal(new TextDecoder().decode(loaded.current), "A".repeat(64));
  assert.equal(new TextDecoder().decode(loaded.previous[0]), "B".repeat(64));
});

test("only the precise missing-AWSPREVIOUS response is optional", async () => {
  const calls: UploadIdempotencySecretStage[] = [];
  const loaded = await loadRotatingUploadIdempotencySecrets({
    async getSecretValue(stage) {
      calls.push(stage);
      if (stage === "AWSPREVIOUS") throw missingPrevious();
      return { SecretString: secret("A") };
    },
  });
  assert.deepEqual(calls, ["AWSCURRENT", "AWSPREVIOUS"]);
  assert.deepEqual(loaded.previous, []);
});

test("authorization, transport, and ambiguous not-found failures never downgrade rotation checks", async () => {
  const failures = [
    Object.assign(new Error("not authorized"), { name: "AccessDeniedException", $metadata: { httpStatusCode: 400 } }),
    Object.assign(new Error("socket reset"), { name: "TimeoutError" }),
    Object.assign(new Error("Secrets Manager can't find the specified secret"), { name: "ResourceNotFoundException", $metadata: { httpStatusCode: 400 } }),
    missingPrevious("Secrets Manager can't find AWSPREVIOUS"),
    Object.assign(missingPrevious(), { $metadata: { httpStatusCode: 500 } }),
  ];
  for (const failure of failures) {
    await assert.rejects(loadRotatingUploadIdempotencySecrets({
      async getSecretValue(stage) {
        if (stage === "AWSPREVIOUS") throw failure;
        return { SecretString: secret("A") };
      },
    }), (error) => error === failure);
  }
});

test("AWSCURRENT is mandatory and malformed secret payloads fail closed", async () => {
  const missing = missingPrevious();
  await assert.rejects(loadRotatingUploadIdempotencySecrets({
    async getSecretValue() { throw missing; },
  }), (error) => error === missing);
  await assert.rejects(loadRotatingUploadIdempotencySecrets({
    async getSecretValue(stage) {
      return { SecretString: stage === "AWSCURRENT" ? secret("A") : "{\"schemaVersion\":1}" };
    },
  }), /secret is invalid/);
  assert.throws(() => parseUploadIdempotencySecret(JSON.stringify({ schemaVersion: 1, hmacKey: "!".repeat(64) })), /secret is invalid/);
});
