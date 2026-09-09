import test from "node:test";
import assert from "node:assert/strict";
import { evidenceQuery, mergeRecords, retryDelay, reviewActions } from "../lib/console-state.ts";

test("polling updates existing records without discarding older loaded pages", () => {
  assert.deepEqual(mergeRecords([{ id: "a", status: "queued" }, { id: "old", status: "done" }], [{ id: "new", status: "queued" }, { id: "a", status: "done" }]), [{ id: "new", status: "queued" }, { id: "a", status: "done" }, { id: "old", status: "done" }]);
});
test("whole-library filters and cursors are encoded in the server query", () => {
  const q = evidenceQuery("asm_scope", { search: "control & system", status: "Needs review", type: "Screenshot" }, "opaque&cursor");
  assert.equal(q.get("q"), "control & system"); assert.equal(q.get("status"), "needs_review");
  assert.equal(q.get("type"), "screenshot"); assert.equal(q.get("cursor"), "opaque&cursor");
});
test("retry-after is honored with bounded invalid-input fallback", () => {
  assert.equal(retryDelay("120"), 120_000); assert.equal(retryDelay("invalid"), 5_000);
  assert.equal(retryDelay("-2"), 1_000); assert.equal(retryDelay("999999"), 3_600_000);
});
test("invalid review transitions are never offered as approval", () => {
  assert.deepEqual(reviewActions("Rejected"), ["reopen"]);
  assert.deepEqual(reviewActions("Approved"), ["supersede"]);
  assert.deepEqual(reviewActions("Expired"), []);
});
