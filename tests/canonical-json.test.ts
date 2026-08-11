import assert from "node:assert/strict";
import test from "node:test";
import { stableJson } from "../lib/server/canonical-json.ts";

test("stableJson emits deterministic, valid canonical JSON", () => {
  const left = { z: [3, { b: true, a: "value" }], a: -0, unicode: "😀" };
  const right = { unicode: "😀", a: -0, z: [3, { a: "value", b: true }] };
  const canonical = stableJson(left);

  assert.equal(canonical, stableJson(right));
  assert.deepEqual(JSON.parse(canonical), JSON.parse(JSON.stringify(left)));
  assert.equal(canonical, '{"a":0,"unicode":"😀","z":[3,{"a":"value","b":true}]}');
});

test("stableJson fails closed for values outside the JSON data model", () => {
  const sparse = new Array(1);
  const circular: Record<string, unknown> = {};
  circular.self = circular;

  for (const value of [
    undefined,
    { missing: undefined },
    sparse,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    BigInt(1),
    Symbol("unsupported"),
    () => undefined,
    new Date(),
    circular,
    "\ud800",
    { "\udfff": "invalid key" },
  ]) assert.throws(() => stableJson(value), TypeError);
});

test("stableJson uses UTF-16 code-unit key ordering required by JCS", () => {
  const value = { "\u20ac": "euro", "\r": "cr", "1": "one", "😀": "emoji", "\u0080": "control" };
  assert.equal(stableJson(value), '{"\\r":"cr","1":"one","":"control","€":"euro","😀":"emoji"}');
});
