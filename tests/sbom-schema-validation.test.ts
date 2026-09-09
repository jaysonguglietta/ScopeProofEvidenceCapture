import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import Ajv from "ajv";
import addFormats from "ajv-formats";
import addInternationalFormats from "ajv-formats-draft2019";
import { analyzeDependencyManifests, buildCycloneDx, buildSpdx } from "../lib/server/sbom-inventory.ts";

const pinnedSchemas = [
  ["cyclonedx-spdx.schema.json", "baa9d3bd1ed57b6751b0887edead6b5063ff53ff7429cf85d476c6c94af0166e"],
  ["cyclonedx-jsf-0.82.schema.json", "8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae"],
  ["cyclonedx-1.6.schema.json", "3e92dddbc30cf7f6a02b80f0942b1a4cfd4fb1c26f1dfc4310afa9d613cafb93"],
  ["spdx-2.3.schema.json", "3ec6cd5b8ba0c9a3e821da48536fa1b814567dc7e4376efe98d3e7b2a7a8d230"],
] as const;

function validator() {
  // The published draft-07 schemas use intentional union/extension keywords.
  // Disable Ajv's schema-authoring strictness, not validation or format checks.
  const ajv = new Ajv({ strict: false, allErrors: true });
  addFormats(ajv);
  addInternationalFormats(ajv);
  for (const [file, hash] of pinnedSchemas) {
    const bytes = readFileSync(new URL(`./fixtures/sbom-schemas/${file}`, import.meta.url));
    assert.equal(createHash("sha256").update(bytes).digest("hex"), hash, `${file} must match its pinned official source`);
    ajv.addSchema(JSON.parse(new TextDecoder().decode(bytes)));
  }
  return ajv;
}

const inventory = analyzeDependencyManifests([{ path: "package-lock.json", text: JSON.stringify({ lockfileVersion: 3, packages: {
  "": { dependencies: { "@example/widget": "1.2.3" } },
  "node_modules/@example/widget": { version: "1.2.3" },
  "node_modules/utility": { version: "2.0.0-beta.1+build.9" },
  "node_modules/@example/widget/node_modules/utility": { version: "1.0.0" },
} }) }]);
const parameters: Parameters<typeof buildCycloneDx> = ["example/repository", "a".repeat(40), "2026-09-08T12:00:00.000Z", "b".repeat(64), ["package-lock.json"], inventory.components];

test("actual CycloneDX generator conforms to the pinned official 1.6 schema", () => {
  const validate = validator().getSchema("http://cyclonedx.org/schema/bom-1.6.schema.json")!;
  const document = buildCycloneDx(...parameters);
  assert.equal(validate(document), true, JSON.stringify(validate.errors));
  const invalidSpelling = structuredClone(document) as unknown as { metadata: { component: Record<string, unknown> } };
  invalidSpelling.metadata.component.bom_ref = invalidSpelling.metadata.component["bom-ref"];
  delete invalidSpelling.metadata.component["bom-ref"];
  assert.equal(validate(invalidSpelling), false, "Regression fixture must reject the original bom_ref bug");
  const invalidDate = structuredClone(document);
  invalidDate.metadata.timestamp = "not-a-timestamp";
  assert.equal(validate(invalidDate), false, "Format validation must remain enabled");
});

test("actual SPDX generator conforms to the pinned official 2.3 schema", () => {
  const validate = validator().getSchema("http://spdx.org/rdf/terms/2.3")!;
  const document = buildSpdx(...parameters);
  assert.equal(validate(document), true, JSON.stringify(validate.errors));
  const invalidIdentifier = { ...document, SPDXID: 17 };
  assert.equal(validate(invalidIdentifier), false);
  assert.equal(document.spdxVersion, "SPDX-2.3");
  assert.equal(new Set(document.packages.map((entry) => entry.SPDXID)).size, document.packages.length);
});
