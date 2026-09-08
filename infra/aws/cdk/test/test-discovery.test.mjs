import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("the actual infrastructure test command fails when an mjs regression fails", () => {
  const script = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")).scripts.test;
  const command = script.split("&&").at(-1).trim();
  assert.equal(command, "node --test -r ts-node/register test/*.test.ts test/*.test.mjs");
  const directory = mkdtempSync(join(tmpdir(), "scopeproof-suite-probe-"));
  try {
    mkdirSync(join(directory, "test"));
    writeFileSync(join(directory, "test/pass.test.ts"), 'require("node:test")("ts probe", () => {});\n');
    writeFileSync(join(directory, "test/fail.test.mjs"), 'import test from "node:test"; test("intentional mjs discovery probe", () => { throw new Error("intentional-mjs-regression"); });\n');
    const require = createRequire(import.meta.url);
    const resolved = command.replace("ts-node/register", JSON.stringify(require.resolve("ts-node/register")));
    const childEnvironment = { ...process.env };
    delete childEnvironment.NODE_TEST_CONTEXT;
    const result = spawnSync("/bin/sh", ["-c", resolved], { cwd: directory, env: childEnvironment, encoding: "utf8", timeout: 30000, maxBuffer: 100000 });
    assert.equal(result.status, 1, result.error?.message || result.stderr);
    assert.match(result.stdout + result.stderr, /intentional-mjs-regression/);
    assert.match(result.stdout + result.stderr, /test\/pass\.test\.ts/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
