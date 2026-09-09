import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { boundedBytes, validateDownloadIntent, validateLoginTransaction, validatePortalConfiguration } from "../infra/aws/customer-portal/security.mjs";

const configuration = { tenantId: "ten_" + "a".repeat(32), webOrigin: "https://client.example.com", apiOrigin: "https://api-client.example.com", oauthOrigin: "https://auth.example.com", clientId: "abcde12345", scopes: ["openid", "scopeproof/evidence.read"] };

test("AWS portal config is exact, HTTPS and hostname/tenant bound without credential fields", () => {
  assert.equal(validatePortalConfiguration(configuration, configuration.webOrigin).tenantId, configuration.tenantId);
  for (const value of [null, { ...configuration, secret: "do-not-accept" }, { ...configuration, apiOrigin: "http://api-client.example.com" }, { ...configuration, apiOrigin: "https://api-client.example.com/" }, { ...configuration, tenantId: "tenant_" + "a".repeat(32) }, { ...configuration, webOrigin: "https://other.example.com" }, { ...configuration, scopes: ["openid injected"] }]) assert.throws(() => validatePortalConfiguration(value, configuration.webOrigin));
});

test("OAuth transaction cannot move between tenants, clients, states or expire", () => {
  const now = Date.now(); const transaction = { state: "s".repeat(43), verifier: "v".repeat(43), origin: configuration.webOrigin, clientId: configuration.clientId, oauthOrigin: configuration.oauthOrigin, createdAt: now - 1000 };
  assert.equal(validateLoginTransaction(transaction, configuration, transaction.state, now), transaction);
  for (const value of [{ ...transaction, origin: "https://other.example.com" }, { ...transaction, clientId: "foreign" }, { ...transaction, oauthOrigin: "https://foreign.example.com" }, { ...transaction, createdAt: now - 600001 }, { ...transaction, createdAt: now + 1 }, { ...transaction, verifier: null }]) assert.throws(() => validateLoginTransaction(value, configuration, transaction.state, now));
  assert.throws(() => validateLoginTransaction(transaction, configuration, "x".repeat(43), now));
});

test("exact-version downloads reject mismatches, redirects/auth headers and expiry", () => {
  const evidence = { evidenceId: "evd_" + "b".repeat(32), revision: 1, byteSize: 10, contentType: "image/png", checksumSha256: "c".repeat(64) };
  const intent = { evidenceId: evidence.evidenceId, revision: 1, expectedSize: 10, expectedSha256: evidence.checksumSha256, contentType: "image/png", expiresAt: new Date(Date.now() + 60000).toISOString(), download: { method: "GET", url: "https://evidence.s3.us-east-1.amazonaws.com/control/file?versionId=immutable", requiredHeaders: { "x-amz-checksum-mode": "ENABLED" } } };
  assert.equal(validateDownloadIntent(intent, evidence).hostname, "evidence.s3.us-east-1.amazonaws.com");
  for (const value of [{ ...intent, expectedSize: 11 }, { ...intent, contentType: "text/html" }, { ...intent, revision: 2 }, { ...intent, expectedSha256: "d".repeat(64) }, { ...intent, expiresAt: new Date(0).toISOString() }, ...["https://evil.example/file?versionId=x", "https://evidence.s3.us-east-1.amazonaws.com/control/file", "https://evidence.s3.us-east-1.amazonaws.com/control/file?versionId=null", "https://evidence.s3.us-east-1.amazonaws.com/control/file?versionId=a&versionId=b"].map((url) => ({ ...intent, download: { ...intent.download, url } })), { ...intent, download: { ...intent.download, requiredHeaders: { Authorization: "Bearer forbidden" } } }]) assert.throws(() => validateDownloadIntent(value, evidence));
});

test("delivered bytes are bounded even without Content-Length and the stream is cancelled", async () => {
  let cancelled = false;
  const response = new Response(new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(20)); }, cancel() { cancelled = true; } }));
  await assert.rejects(boundedBytes(response, 10), /size limit/); assert.equal(cancelled, true);
  assert.deepEqual(await boundedBytes(new Response(new Uint8Array([1, 2])), 2), new Uint8Array([1, 2]));
  await assert.rejects(boundedBytes(new Response("123", { headers: { "content-length": "100" } }), 3), /size limit/);
});

test("the real static build is fail-closed without host config and packages all executable routes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "scopeproof-portal-build-"));
  try {
    const environment = { ...process.env }; delete environment.SCOPEPROOF_PORTAL_CONFIG_JSON;
    let result = spawnSync(process.execPath, ["infra/aws/customer-portal/build.mjs", directory], { env: environment, encoding: "utf8" });
    assert.notEqual(result.status, 0); assert.match(result.stderr, /public outputs/);
    result = spawnSync(process.execPath, ["infra/aws/customer-portal/build.mjs", directory], { env: { ...environment, SCOPEPROOF_PORTAL_CONFIG_JSON: JSON.stringify({ "client.example.com": configuration }) }, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(await readFile(join(directory, "tenant-config.json"), "utf8")), { "client.example.com": configuration });
    assert.match(await readFile(join(directory, "auth/callback/index.html"), "utf8"), /src="\/portal.mjs"/);
    const script = await readFile(join(directory, "portal.mjs"), "utf8");
    for (const route of ["/v1/customer/invitations/accept", "/v1/customer/evidence/review", "/v1/customer/devices/revoke", "/v1/legal-hold-requests/by-evidence", "/v1/legal-hold-approvals"]) assert.ok(script.includes(route), route);
    assert.doesNotMatch(script, /innerHTML|localStorage|authorization_code.*client_secret/);
    assert.equal((script.match(/sessionStorage\.setItem/g) || []).length, 1);
    assert.match(await readFile(join(directory, "customHttp.yml"), "utf8"), /frame-ancestors 'none'/);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
