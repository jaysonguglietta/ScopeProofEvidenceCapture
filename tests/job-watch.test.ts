import assert from "node:assert/strict";
import test from "node:test";
import { watchedJobIds, rotatingWatchBatch } from "../lib/server/job-watch.ts";
import { nextCollectorRun, normalizeCollectorSchedule } from "../lib/server/workflow-validation.ts";
import { readFile } from "node:fs/promises";
test("loaded work beyond page one is rotated in bounded exact-assessment batches", () => {
  const assessment = "asm_" + "a".repeat(32);
  const ids = Array.from({ length: 121 }, (_, index) => "job_" + index.toString(16).padStart(32, "0"));
  const seen = new Set<string>();
  for (let iteration = 0; iteration < 3; iteration++) {
    const batch = rotatingWatchBatch(ids, iteration); assert.equal(batch.length, 50);
    assert.deepEqual(watchedJobIds(batch.join(","), assessment, "job"), batch);
    batch.forEach((id) => seen.add(id));
  }
  assert.equal(seen.size, ids.length);
  for (const [raw, scope] of [[ids.slice(0, 51).join(","), assessment], [[ids[0], ids[0]].join(","), assessment], [ids[0], ""], ["sbom_" + "b".repeat(32), assessment]]) assert.throws(() => watchedJobIds(raw, scope, "job"));
  assert.deepEqual(rotatingWatchBatch([], 1), []);
});
test("UTC schedule preview is bounded and correct over midnight, weekdays and invalid input", () => {
  const now = new Date("2026-09-08T23:59:30.000Z");
  assert.equal(nextCollectorRun("0 0 * * *", now), "2026-09-09T00:00:00.000Z");
  assert.equal(nextCollectorRun("30 * * * *", now), "2026-09-09T00:30:00.000Z");
  assert.equal(nextCollectorRun("0 7 * * 1", now), "2026-09-14T07:00:00.000Z");
  assert.equal(nextCollectorRun("* * * * *", now), null);
  assert.equal(nextCollectorRun(null, now), null);
});
test("accepted schedules align with the actual deployed 15-minute trigger", async () => {
  const source = await readFile(new URL("../vite.config.ts", import.meta.url), "utf8");
  assert.match(source, /\*\/15 \* \* \* \*/);
  for (let minute = 0; minute < 60; minute++) {
    const cron = `${minute} 10 * * *`;
    if (minute % 15 === 0) assert.equal(normalizeCollectorSchedule(cron), cron);
    else { assert.throws(() => normalizeCollectorSchedule(cron)); assert.equal(nextCollectorRun(cron), null); }
  }
});
