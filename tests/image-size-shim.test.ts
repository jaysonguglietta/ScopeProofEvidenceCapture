import assert from "node:assert/strict";
import test from "node:test";
import { imageSize } from "../vendor/image-size/index.js";

test("bounded image metadata parser reads supported headers", () => {
  const png = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 16, 0, 0, 0, 32]);
  const gif = Uint8Array.from([...Buffer.from("GIF89a"), 16, 0, 32, 0]);

  assert.deepEqual(imageSize(png), { width: 16, height: 32, type: "png" });
  assert.deepEqual(imageSize(gif), { width: 16, height: 32, type: "gif" });
});

test("bounded image metadata parser rejects unsupported and malformed formats", () => {
  assert.throws(() => imageSize(new Uint8Array(9)), /input size/);
  assert.throws(() => imageSize(Uint8Array.from([...Buffer.from("GIF89a"), 0, 0, 1, 0])), /dimensions/);
  assert.throws(() => imageSize(Uint8Array.from([...Buffer.from("not-an-image"), 0, 0])), /only PNG/);
});
