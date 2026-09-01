import assert from "node:assert/strict";
import test from "node:test";
import { evidenceResponseHeaders, SAFE_MANUAL_EVIDENCE_TYPES } from "../lib/server/evidence-response.ts";
import { hardenedResponseHeaders } from "../lib/server/response-security.ts";
import { readFile } from "node:fs/promises";

test("attacker-controlled active content is not an allowed manual evidence type", () => {
  for (const type of ["text/html", "application/xhtml+xml", "image/svg+xml"]) {
    assert.equal(SAFE_MANUAL_EVIDENCE_TYPES.has(type), false, type);
  }
});

test("only exact PNG evidence can be served inline", () => {
  for (const type of ["text/html", "application/xhtml+xml", "image/svg+xml", "application/xml", "application/json", "text/plain"]) {
    const headers = evidenceResponseHeaders("ev_test", type, true);
    assert.match(headers.get("content-disposition") || "", /^attachment;/);
    assert.equal(headers.get("content-type"), "application/octet-stream");
    assert.equal(headers.get("content-security-policy"), "default-src 'none'; sandbox");
  }
  const png = evidenceResponseHeaders("ev_test", "image/png", true);
  assert.match(png.get("content-disposition") || "", /^inline;/);
  assert.equal(png.get("content-type"), "image/png");
});

test("worker hardening preserves a stricter route CSP", () => {
  const route = new Headers({ "content-security-policy": "default-src 'none'; sandbox" });
  const hardened = hardenedResponseHeaders(route, "https://scopeproof.example/api/evidence/ev_test?view=inline");
  assert.equal(hardened.get("content-security-policy"), "default-src 'none'; sandbox");
  assert.equal(hardened.get("cache-control"), "private, no-store");
  assert.equal(hardened.get("x-content-type-options"), "nosniff");
});

test("every decrypted evidence disclosure requires a durable audit event", async () => {
  const route = await readFile(new URL("../app/api/evidence/[id]/route.ts", import.meta.url), "utf8");
  assert.match(route, /await appendAuditEvent\(user, inline \? "evidence\.previewed" : "evidence\.downloaded"/);
  assert.ok(route.indexOf("await appendAuditEvent") < route.indexOf("return new Response"));
});
