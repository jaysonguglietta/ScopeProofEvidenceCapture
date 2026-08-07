import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

test("builds the PCI evidence operations console and protected API surface", async () => {
  const [page, consoleSource, worker, routes] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/evidence-console.tsx", import.meta.url), "utf8"),
    readFile(new URL("../dist/server/index.js", import.meta.url), "utf8"),
    Promise.all(["me", "evidence", "collectors", "runs", "audit", "packages"].map((route) => access(new URL(`../app/api/${route}/route.ts`, import.meta.url)))),
  ]);
  assert.match(page, /EvidenceConsole/);
  assert.match(consoleSource, /Scopeproof/);
  assert.match(consoleSource, /PCI DSS 4\.0\.1/);
  assert.match(consoleSource, /Control coverage/);
  assert.match(consoleSource, /Recent evidence/);
  assert.match(consoleSource, /Run collection/);
  assert.match(worker, /content-security-policy/);
  assert.equal(routes.length, 6);
  assert.doesNotMatch(consoleSource, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("keeps evidence models, product UI, and starter cleanup explicit", async () => {
  const [page, consoleSource, data, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/evidence-console.tsx", import.meta.url), "utf8"),
    readFile(new URL("../lib/data.ts", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /EvidenceConsole/);
  assert.match(consoleSource, /fetch\("\/api\/evidence"/);
  assert.doesNotMatch(consoleSource, /localStorage/);
  assert.match(consoleSource, /SHA-256|sha256/);
  assert.match(consoleSource, /Cardholder data scan passed/);
  assert.match(consoleSource, /Approve evidence/);
  assert.match(data, /PCI control|control:/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await assert.rejects(access(new URL("../app/_sites-preview/SkeletonPreview.tsx", import.meta.url)));
});
