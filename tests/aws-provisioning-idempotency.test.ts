import assert from "node:assert/strict";
import test from "node:test";

import { transactionToken } from "../infra/aws/cdk/runtime/provision-tenant/idempotency.mjs";

const acquisition = Object.freeze({
  action: "acquire",
  apiHostname: "api-acme.evidence.example.com",
  executionId: "arn:aws:states:us-east-1:123456789012:execution:tenant:run-1",
  hostname: "acme.evidence.example.com",
  now: "2026-08-27T12:00:00.000Z",
  tenantId: "ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
});

test("provisioning transaction tokens are canonical and exact", () => {
  const reordered = Object.fromEntries(Object.entries(acquisition).reverse());
  const token = transactionToken(acquisition);
  assert.equal(token, transactionToken(reordered));
  assert.match(token, /^sp-[a-f0-9]{32}$/);
  assert.ok(token.length <= 36);
});

test("a lost-response retry with a new timestamp cannot reuse incompatible Dynamo parameters", () => {
  const first = transactionToken(acquisition);
  const retry = transactionToken({ ...acquisition, now: "2026-08-27T12:00:01.000Z" });
  assert.notEqual(first, retry);
  assert.notEqual(
    transactionToken({ ...acquisition, action: "terminal", status: "ACTIVE" }),
    transactionToken({ ...acquisition, action: "terminal", status: "FAILED" }),
  );
});

test("provisioning transaction tokens reject nested, unbounded, and unsafe facts", () => {
  assert.throws(() => transactionToken([]));
  assert.throws(() => transactionToken({ nested: { unsafe: true } }));
  assert.throws(() => transactionToken({ unsafe: "line\nbreak" }));
  assert.throws(() => transactionToken({ huge: "a".repeat(1_025) }));
});
