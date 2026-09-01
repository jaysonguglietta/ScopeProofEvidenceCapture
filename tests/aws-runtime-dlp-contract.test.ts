import assert from "node:assert/strict";
import test from "node:test";

import {
  buildExactVersionDlpRequest,
  parseExactVersionDlpResponse,
} from "../infra/aws/cdk/runtime/promote-evidence/dlp-contract.mjs";

const TENANT = `ten_${"a".repeat(32)}`;
const NOW = new Date("2026-09-01T15:00:00.000Z");

function request() {
  return buildExactVersionDlpRequest({
    tenantId: TENANT,
    bucket: "scopeproof-acme-quarantine",
    key: `tenants/${TENANT}/controls/PCI-DSS-10.2.1/quarantine/upl_${"b".repeat(32)}.upload`,
    versionId: "3LgA.example-version-001",
    sha256: "c".repeat(64),
    byteSize: 4096,
    contentType: "image/png",
    policyVersion: "pci-evidence-v4",
  });
}

function response(overrides: Record<string, unknown> = {}) {
  return {
    ...request(),
    decision: "CLEAN",
    findingCount: 0,
    scannedAt: "2026-09-01T14:59:30.000Z",
    scannerRequestId: "scanner-request-0001",
    ...overrides,
  };
}

test("exact-version DLP receipt binds every immutable object attribute", () => {
  const parsed = parseExactVersionDlpResponse(response(), request(), NOW);
  assert.equal(parsed.decision, "CLEAN");
  assert.match(parsed.receiptDigest, /^[a-f0-9]{64}$/);
  assert.deepEqual(JSON.parse(parsed.canonicalReceipt), response());

  for (const [field, changed] of [
    ["tenantId", `ten_${"d".repeat(32)}`],
    ["key", `${request().key}-other`],
    ["versionId", "different-version"],
    ["sha256", "e".repeat(64)],
    ["byteSize", 4097],
    ["contentType", "application/json"],
    ["policyVersion", "pci-evidence-v5"],
  ] as const) {
    assert.throws(
      () => parseExactVersionDlpResponse(response({ [field]: changed }), request(), NOW),
      /exact requested object version/i,
    );
  }
});

test("DLP decisions, response shape, time, and quarantine namespace fail closed", () => {
  assert.throws(
    () => parseExactVersionDlpResponse(response({ decision: "CLEAN", findingCount: 2 }), request(), NOW),
    /finding count/i,
  );
  assert.throws(
    () => parseExactVersionDlpResponse({ ...response(), ignored: true }, request(), NOW),
    /response contract/i,
  );
  assert.throws(
    () => parseExactVersionDlpResponse(response({ scannedAt: "2026-09-01T14:40:00.000Z" }), request(), NOW),
    /timestamp/i,
  );
  assert.throws(
    () => buildExactVersionDlpRequest({ ...request(), key: `tenants/${TENANT}/controls/x/evidence/file.png` }),
    /quarantine prefix/i,
  );
});

test("a canonical persisted receipt may be replayed only for the same exact version", () => {
  const oldResponse = response({ scannedAt: "2026-08-31T15:00:00.000Z" });
  const parsed = parseExactVersionDlpResponse(oldResponse, request(), NOW, { maximumAgeMilliseconds: null });
  assert.equal(parsed.scannedAt, oldResponse.scannedAt);
  assert.throws(
    () => parseExactVersionDlpResponse(oldResponse, { ...request(), versionId: "replacement-version" }, NOW, { maximumAgeMilliseconds: null }),
    /exact requested object version/i,
  );
  assert.throws(
    () => parseExactVersionDlpResponse(response({ scannedAt: "2026-09-01T15:02:00.000Z" }), request(), NOW, { maximumAgeMilliseconds: null }),
    /timestamp/i,
  );
});
