import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the PCI evidence operations console", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /Scopeproof/);
  assert.match(html, /PCI DSS 4\.0\.1/);
  assert.match(html, /Control coverage/);
  assert.match(html, /Recent evidence/);
  assert.match(html, /Run collection/);
  assert.match(html, /skip-link/);
  assert.doesNotMatch(html, /codex-preview|Your site is taking shape|react-loading-skeleton/i);
});

test("keeps evidence models, product UI, and starter cleanup explicit", async () => {
  const [page, consoleSource, data, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/evidence-console.tsx", import.meta.url), "utf8"),
    readFile(new URL("../lib/data.ts", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /EvidenceConsole/);
  assert.match(consoleSource, /localStorage/);
  assert.match(consoleSource, /SHA-256|sha256/);
  assert.match(consoleSource, /Cardholder data scan passed/);
  assert.match(consoleSource, /Approve evidence/);
  assert.match(data, /PCI control|control:/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await assert.rejects(access(new URL("../app/_sites-preview/SkeletonPreview.tsx", import.meta.url)));
});
