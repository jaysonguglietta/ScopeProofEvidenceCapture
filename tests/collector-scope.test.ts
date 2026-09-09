import assert from "node:assert/strict";
import test from "node:test";
import { collectorScopeCompatibility } from "../lib/collector-scope.ts";
test("collector preview uses exact emitted labels and never treats unknown discovered scope as compatible", () => {
  const rows = collectorScopeCompatibility({ githubOrganization: "org", oktaOrigin: "https://tenant.okta.com/path?secret=not-returned", cloudflareZoneIds: "a,b", browserUrls: "https://console.example/settings?token=not-returned" }, ["6.3.2", "1.2.5", "2.2.1"], ["org", "2 zones", "console.example"]);
  assert.equal(rows.find((item) => item.provider === "github")?.compatible, true);
  assert.equal(rows.find((item) => item.provider === "cloudflare")?.compatible, true);
  assert.equal(rows.find((item) => item.provider === "browser")?.compatible, true);
  assert.equal(rows.find((item) => item.provider === "aws")?.compatible, false);
  assert.doesNotMatch(JSON.stringify(rows), /token|secret|settings|path\?/);
  assert.equal(collectorScopeCompatibility({}, ["1.2.5"], ["0 zones"]).find((item) => item.provider === "cloudflare")?.compatible, false);
});
