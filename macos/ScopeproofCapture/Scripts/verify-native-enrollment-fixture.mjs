import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import path from "node:path";

// Run with Node's TypeScript stripping support. Executes the real production
// enrollment verifier against a Swift-generated synthetic public proof.
const [repositoryRoot, fixturePath] = process.argv.slice(2);
assert(repositoryRoot && fixturePath, "Usage: node --experimental-strip-types verify-native-enrollment-fixture.mjs REPOSITORY_ROOT FIXTURE.json");
const fixture = JSON.parse(await readFile(fixturePath, "utf8"));
const request = { actor: fixture.actor, identity: fixture.identity };
if (fixture.body.deviceManifest) {
  const { verifyDeviceUploadManifest } = await import(pathToFileURL(path.join(repositoryRoot, "lib/aws-runtime/evidence/device-upload-manifest.ts")));
  const input = { ...request, manifest: fixture.body.deviceManifest, publicKeySpki: fixture.body.devicePublicKeySpki, signature: fixture.body.deviceSignature, request: fixture.body, now: new Date(fixture.now) };
  const result = await verifyDeviceUploadManifest(input);
  assert.equal(result.sequence, fixture.body.deviceManifest.sequence);
  await assert.rejects(verifyDeviceUploadManifest({ ...input, request: { ...fixture.body, expectedSize: fixture.body.expectedSize + 1 } }));
  await assert.rejects(verifyDeviceUploadManifest({ ...input, identity: { ...fixture.identity, jwtId: "another-verified-token" } }));
  console.log("Native Swift upload proof accepted by actual server verifier; changed size and foreign token challenge rejected.");
  process.exit(0);
}
const { verifyDeviceEnrollment } = await import(pathToFileURL(path.join(repositoryRoot, "lib/aws-runtime/http/customer.ts")));
const result = await verifyDeviceEnrollment(request, fixture.body, new Date(fixture.now));
assert.equal(result.deviceId, fixture.body.deviceId);
await assert.rejects(verifyDeviceEnrollment(request, { ...fixture.body, displayName: "Changed proof" }, new Date(fixture.now)));
await assert.rejects(verifyDeviceEnrollment({ ...request, identity: { jwtId: "another-token" } }, fixture.body, new Date(fixture.now)));
console.log("Native Swift enrollment proof accepted by actual server verifier; tampered name and foreign token challenge rejected.");
