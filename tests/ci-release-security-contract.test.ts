import assert from "node:assert/strict";
import { execFile, spawnSync } from "node:child_process";
import { createHash, createPublicKey, generateKeyPairSync, sign } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const codeqlPath = new URL("../.github/workflows/codeql-swift.yml", import.meta.url);
const releaseWorkflowPath = new URL("../.github/workflows/macos-production-release.yml", import.meta.url);
const securityWorkflowPath = new URL("../.github/workflows/security.yml", import.meta.url);
const trivyIgnorePath = new URL("../.trivyignore.yaml", import.meta.url);
const dependabotPath = new URL("../.github/dependabot.yml", import.meta.url);
const buildScriptPath = new URL("../Scripts/build_macos_production_release.sh", import.meta.url);
const localBuildScriptPath = new URL("../Scripts/build_macos_capture.sh", import.meta.url);
const prepareScriptPath = new URL("../Scripts/prepare_macos_release_candidate.sh", import.meta.url);
const publishScriptPath = new URL("../Scripts/publish_release.sh", import.meta.url);
const entitlementValidatorPath = new URL("../Scripts/validate_macos_release_entitlements.mjs", import.meta.url);
const releaseEntitlementsPath = new URL("../macos/ScopeproofCapture/Resources/ScopeproofCapture.entitlements", import.meta.url);
const evidenceScriptPath = new URL("../Scripts/macos_release_evidence.mjs", import.meta.url);
const manifestScriptPath = new URL("../Scripts/sign_update_manifest.mjs", import.meta.url);
const updateKeyValidatorPath = new URL("../Scripts/validate_macos_update_keys.mjs", import.meta.url);
const pnpmSbomScriptPath = new URL("../Scripts/pnpm_lock_to_cyclonedx.mjs", import.meta.url);
const notaryScriptPath = new URL("../Scripts/configure_macos_notary_profile.sh", import.meta.url);
const releaseRunbookPath = new URL("../docs/AWS_RECOVERY_AND_MACOS_RELEASE.md", import.meta.url);
const awsPackagePath = new URL("../infra/aws/cdk/package.json", import.meta.url);
const awsWorkspacePath = new URL("../infra/aws/cdk/pnpm-workspace.yaml", import.meta.url);
const codeownersPath = new URL("../.github/CODEOWNERS", import.meta.url);
const execFileAsync = promisify(execFile);

function assertPinnedActions(workflow: string): void {
  const actions = [...workflow.matchAll(/^\s*uses:\s*([^\s#]+).*$/gm)].map((match) => match[1]);
  assert.ok(actions.length > 0);
  for (const action of actions) assert.match(action, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[a-f0-9]{40}$/);
}

test("Swift CodeQL uses an explicit traced arm64 build and no autobuild", async () => {
  const workflow = await readFile(codeqlPath, "utf8");
  assert.match(workflow, /build-mode: manual/);
  assert.match(workflow, /languages: swift/);
  assert.match(workflow, /swift build --arch arm64/);
  assert.match(workflow, /security-events: write/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /language: \[javascript-typescript, actions\]/);
  assert.match(workflow, /build-mode: none/);
  assert.doesNotMatch(workflow, /autobuild/i);
  assertPinnedActions(workflow);
});

test("production release is manual, main-only, protected, and cleans credentials before artifacts", async () => {
  const workflow = await readFile(releaseWorkflowPath, "utf8");
  assert.match(workflow, /^\s*workflow_dispatch:/m);
  assert.doesNotMatch(workflow, /^\s*(?:push|pull_request):/m);
  assert.match(workflow, /if: github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /environment: production-release/);
  assert.match(workflow, /actions: read/);
  assert.match(workflow, /test "\$EXPECTED_COMMIT" = "\$GITHUB_SHA"/);
  assert.match(workflow, /actions\/workflows\/\$workflow\/runs\?branch=main&event=push&head_sha=\$EXPECTED_COMMIT&status=completed/);
  assert.match(workflow, /security\.yml codeql-swift\.yml/);
  assert.match(workflow, /run\.conclusion === "success"/);
  assert.match(workflow, /persist-credentials: false/);
  assert.match(workflow, /swift test --arch arm64/);
  assert.match(workflow, /security delete-keychain/);
  assert.match(workflow, /prepare-release:/);
  assert.match(workflow, /sign-notarize:\n\s+needs: prepare-release/);
  assert.match(workflow, /attest-release:\n\s+needs: sign-notarize/);
  assert.match(workflow, /actions\/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c/);
  assert.match(workflow, /SCOPEPROOF_RELEASE_PREPARED_ARCHIVE/);
  const signingJob = workflow.slice(workflow.indexOf("  sign-notarize:"), workflow.indexOf("  attest-release:"));
  const attestationJob = workflow.slice(workflow.indexOf("  attest-release:"));
  assert.doesNotMatch(signingJob, /swift (?:build|test)/);
  assert.doesNotMatch(signingJob, /id-token:\s*write|attestations:\s*write/);
  assert.doesNotMatch(attestationJob, /secrets\.|actions\/checkout/);
  assert.match(attestationJob, /id-token: write/);
  assert.match(attestationJob, /attestations: write/);
  assert.match(workflow, /uses: actions\/attest@1e69f48acb82d1966a394da916b4c1698aa569d6/);
  assert.match(workflow, /\.notary-receipt\.json/);
  assert.match(workflow, /\.sbom\.cdx\.json/);
  assert.match(workflow, /\.provenance\.intoto\.json/);
  assert.doesNotMatch(workflow, /actions\/attest-build-provenance@/);
  assert.ok(workflow.indexOf("Destroy temporary release credentials") < workflow.indexOf("Attest the signed release candidate"));
  assert.ok(workflow.indexOf("Destroy temporary release credentials") < workflow.indexOf("Upload the signed candidate for isolated attestation"));
  assert.ok(workflow.indexOf("swift test --arch arm64") < workflow.indexOf("MACOS_DEVELOPER_ID_P12_BASE64"));
  assert.ok(workflow.indexOf("Require successful security workflows") < workflow.indexOf("MACOS_DEVELOPER_ID_P12_BASE64"));
  assertPinnedActions(workflow);
});

test("pull-request security jobs have no OIDC or attestation authority and gate dependency licenses", async () => {
  const [workflow, trivyIgnore] = await Promise.all([
    readFile(securityWorkflowPath, "utf8"),
    readFile(trivyIgnorePath, "utf8"),
  ]);
  assert.doesNotMatch(workflow, /id-token:\s*write/);
  assert.doesNotMatch(workflow, /attestations:\s*write/);
  assert.match(workflow, /actions\/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294/);
  assert.match(workflow, /fail-on-severity: moderate/);
  assert.match(workflow, /license-check: true/);
  assert.match(workflow, /deny-licenses:.*AGPL.*GPL.*SSPL/);
  assert.match(workflow, /scopeproof-worker-sbom\.cdx\.json/);
  assert.match(workflow, /scopeproof-aws-cdk-sbom\.cdx\.json/);
  assert.match(workflow, /npm run test:cloudformation/);
  assert.match(workflow, /pnpm exec cdk synth/);
  assert.match(workflow, /rootDomain=evidence\.example\.com/);
  assert.match(workflow, /deploymentEnvironment=dev/);
  assert.match(workflow, /recovery=\{"mode":"disabled"\}/);
  assert.match(workflow, /aquasecurity\/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25/);
  assert.match(workflow, /scanners: secret,misconfig/);
  assert.match(workflow, /severity: HIGH,CRITICAL/);
  assert.match(workflow, /trivyignores: \.trivyignore\.yaml/);
  assert.match(trivyIgnore, /id: AVD-AWS-0015/);
  assert.match(trivyIgnore, /infra\/aws\/scopeproof-s3-observability\.yaml/);
  assert.match(trivyIgnore, /expired_at: 2026-11-30/);
  assertPinnedActions(workflow);
});

test("Dependabot covers both npm lockfile boundaries and pinned Actions", async () => {
  const source = await readFile(dependabotPath, "utf8");
  assert.match(source, /package-ecosystem: npm\n\s+directory: \/(?:\n|$)/);
  assert.match(source, /package-ecosystem: npm\n\s+directory: \/infra\/aws\/cdk/);
  assert.match(source, /package-ecosystem: github-actions/);
});

test("AWS pnpm lockfile produces a complete deterministic CycloneDX dependency graph", async () => {
  const directory = await mkdtemp(join(tmpdir(), "scopeproof-pnpm-sbom-"));
  try {
    const output = join(directory, "aws.cdx.json");
    const secondOutput = join(directory, "aws-second.cdx.json");
    await execFileAsync(process.execPath, [pnpmSbomScriptPath.pathname, awsPackagePath.pathname, new URL("../infra/aws/cdk/pnpm-lock.yaml", import.meta.url).pathname, output]);
    await execFileAsync(process.execPath, [pnpmSbomScriptPath.pathname, awsPackagePath.pathname, new URL("../infra/aws/cdk/pnpm-lock.yaml", import.meta.url).pathname, secondOutput]);
    const sbom = JSON.parse(await readFile(output, "utf8")) as {
      bomFormat: string;
      specVersion: string;
      metadata: { tools: { components: Array<{ name: string }> }; properties: Array<{ name: string; value: string }> };
      components: Array<{ "bom-ref": string; name: string; scope: string; hashes?: Array<{ alg: string; content: string }>; properties?: Array<{ name: string; value: string }> }>;
      dependencies: Array<{ ref: string; dependsOn: string[] }>;
    };
    assert.equal(sbom.bomFormat, "CycloneDX");
    assert.equal(sbom.specVersion, "1.6");
    assert.ok(sbom.components.length > 50);
    assert.equal(sbom.dependencies[0].dependsOn.length, 19);
    assert.equal(sbom.dependencies.length, sbom.components.length + 1);
    assert.equal(new Set(sbom.components.map((component) => component["bom-ref"])).size, sbom.components.length);
    assert.ok(sbom.components.every((component) => component.hashes?.[0].alg === "SHA-512" && /^[a-f0-9]{128}$/.test(component.hashes[0].content)));
    assert.deepEqual(
      new Set(sbom.dependencies.slice(1).map((dependency) => dependency.ref)),
      new Set(sbom.components.map((component) => component["bom-ref"])),
    );
    const component = (name: string) => sbom.components.find((candidate) => candidate.name === name)!;
    const dependency = (name: string) => sbom.dependencies.find((candidate) => candidate.ref === component(name)["bom-ref"])!;
    assert.equal(component("@aws-sdk/client-s3").scope, "required");
    assert.equal(component("aws-cdk").scope, "excluded");
    assert.ok(dependency("@aws-sdk/client-s3").dependsOn.includes(component("@aws-sdk/checksums")["bom-ref"]));
    assert.ok(dependency("esbuild").dependsOn.length >= 20);
    assert.match(component("@aws-cdk/cloud-assembly-schema").properties?.[0].value ?? "", /jsonschema,semver/);
    assert.equal(sbom.metadata.tools.components[0].name, "scopeproof-pnpm-lock-to-cyclonedx");
    assert.ok(sbom.metadata.properties.some(({ name, value }) => name === "scopeproof:dependencyGraph" && value === "complete-for-pnpm-snapshots"));
    assert.deepEqual(JSON.parse(await readFile(secondOutput, "utf8")), sbom);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("production builder enforces hardened signing, notarization, stapling, and final assessment", async () => {
  const [build, localBuild, prepare, configure] = await Promise.all([
    readFile(buildScriptPath, "utf8"),
    readFile(localBuildScriptPath, "utf8"),
    readFile(prepareScriptPath, "utf8"),
    readFile(notaryScriptPath, "utf8"),
  ]);
  assert.match(build, /--options runtime/);
  assert.match(build, /notarytool submit/);
  assert.match(build, /stapler staple/);
  assert.match(build, /stapler validate/);
  assert.match(build, /spctl --assess --type execute/);
  assert.match(build, /spctl --assess --type open/);
  assert.match(build, /Refusing to overwrite existing release artifact/);
  assert.match(build, /ScopeproofUpdateDownloadOrigin/);
  assert.match(build, /validate_macos_update_keys\.mjs/);
  assert.match(build, /macos_release_evidence\.mjs" create/);
  assert.match(build, /SCOPEPROOF_RELEASE_PREPARED_ARCHIVE/);
  assert.match(build, /Prepared release archive contains missing, duplicate, or unexpected members/);
  assert.match(build, /Prepared Info\.plist differs from the approved signing source/);
  assert.match(build, /Prepared entitlements differ from the approved signing source/);
  assert.match(prepare, /swift build -c release --arch arm64/);
  assert.match(prepare, /SCOPEPROOF_RELEASE_EXPECTED_COMMIT/);
  assert.match(prepare, /Scopeproof-Capture-prepared\.zip\.sha256/);
  assert.equal([...build.matchAll(/validate_macos_release_entitlements\.mjs/g)].length, 2);
  assert.match(configure, /notarytool store-credentials/);
  assert.match(configure, /Refusing to read an App Store Connect private key from the repository/);
  assert.match(configure, /must not have additional hard links/);
  assert.match(configure, /must not have extended ACLs/);
  assert.doesNotMatch(`${build}\n${localBuild}\n${configure}`, /--disable-sandbox/);
});

test("production update keys are canonical P-256 points with a current non-duplicated validity window", async () => {
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicJwk = publicKey.export({ format: "jwk" });
  assert.equal(publicJwk.kty, "EC");
  const key = Buffer.concat([
    Buffer.from([4]),
    Buffer.from(publicJwk.x!, "base64url"),
    Buffer.from(publicJwk.y!, "base64url"),
  ]).toString("base64");
  const now = Date.now();
  const before = new Date(now - 60_000).toISOString();
  const after = new Date(now + 3_600_000).toISOString();
  const runSingle = (...values: string[]) => execFileAsync(
    process.execPath,
    [updateKeyValidatorPath.pathname, "single", ...values],
  );

  await runSingle("release-2026", key, before, after);
  await assert.rejects(runSingle("release-2026", "A".repeat(88), before, after), /canonical base64/);
  const invalidPoint = Buffer.concat([Buffer.from([4]), Buffer.alloc(64)]).toString("base64");
  await assert.rejects(runSingle("release-2026", invalidPoint, before, after), /valid P-256 point/);
  await assert.rejects(
    runSingle("release-2026", key, new Date(now - 7_200_000).toISOString(), new Date(now - 3_600_000).toISOString()),
    /valid now/,
  );
  await assert.rejects(
    runSingle("release-2026", key, new Date(now + 3_600_000).toISOString(), new Date(now + 7_200_000).toISOString()),
    /valid now/,
  );
  await assert.rejects(runSingle("release-2026", key, after, before), /empty or reversed/);

  const entry = { keyId: "release-2026", publicKeyX963Base64: key, notBefore: before, notAfter: after };
  const duplicate = spawnSync(process.execPath, [updateKeyValidatorPath.pathname, "json"], {
    encoding: "utf8",
    input: JSON.stringify([entry, entry]),
  });
  assert.notEqual(duplicate.status, 0);
  assert.match(duplicate.stderr, /Duplicate update key IDs/);

  const deterministic = spawnSync(process.execPath, [
    updateKeyValidatorPath.pathname,
    "json-at",
    "2030-06-01T00:00:00.000Z",
    "release-2026",
    key,
  ], {
    encoding: "utf8",
    input: JSON.stringify([{ ...entry, notBefore: "2030-01-01T00:00:00.000Z", notAfter: "2031-01-01T00:00:00.000Z" }]),
  });
  assert.equal(deterministic.status, 0, deterministic.stderr);
});

test("publication requires the selected compiled key to cover the exact signed envelope window", async () => {
  const directory = await mkdtemp(join(tmpdir(), "scopeproof-update-key-window-"));
  try {
    const keyPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const jwk = keyPair.publicKey.export({ format: "jwk" });
    assert.equal(jwk.kty, "EC");
    const key = Buffer.concat([
      Buffer.from([4]),
      Buffer.from(jwk.x!, "base64url"),
      Buffer.from(jwk.y!, "base64url"),
    ]).toString("base64");
    const otherPair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const otherJwk = otherPair.publicKey.export({ format: "jwk" });
    assert.equal(otherJwk.kty, "EC");
    const otherKey = Buffer.concat([
      Buffer.from([4]),
      Buffer.from(otherJwk.x!, "base64url"),
      Buffer.from(otherJwk.y!, "base64url"),
    ]).toString("base64");
    const envelopePath = join(directory, "release-envelope.json");
    const manifest = {
      schemaVersion: 1,
      version: "99.0.0",
      sequence: 42,
      downloadUrl: "https://downloads.scopeproof.example/macos/99.0.0/Scopeproof-Capture-99.0.0.zip",
      sha256: "a".repeat(64),
      byteSize: 1024,
      publishedAt: "2030-06-01T00:00:00.000Z",
      expiresAt: "2030-07-01T00:00:00.000Z",
      minimumSystemVersion: "14.0",
      teamIdentifier: "ABCDE12345",
      designatedRequirement: 'identifier "com.scopeproof.capture" and anchor apple generic',
      keyId: "selected-2030",
      notes: "Security update",
    };
    const payload = [
      "scopeproof-update-manifest-v1",
      manifest.schemaVersion,
      manifest.version,
      manifest.sequence,
      manifest.downloadUrl,
      manifest.sha256,
      manifest.byteSize,
      manifest.publishedAt,
      manifest.expiresAt,
      manifest.minimumSystemVersion,
      manifest.teamIdentifier,
      manifest.designatedRequirement,
      manifest.keyId,
      Buffer.from(manifest.notes).toString("base64"),
    ].join("\n");
    const signatureDERBase64 = Buffer.from(sign("sha256", Buffer.from(payload), keyPair.privateKey)).toString("base64");
    const publicKeySpkiSha256 = createHash("sha256")
      .update(keyPair.publicKey.export({ type: "spki", format: "der" }))
      .digest("hex");
    const envelope = {
      manifest,
      signatureDERBase64,
      releaseArtifact: "Scopeproof-Capture-99.0.0.zip",
      publicKeySpkiSha256,
      publicKeyX963Base64: key,
    };
    await writeFile(envelopePath, JSON.stringify(envelope));
    const runEnvelope = (entries: unknown[]) => spawnSync(process.execPath, [
      updateKeyValidatorPath.pathname,
      "envelope",
      "selected-2030",
      key,
      envelopePath,
    ], { encoding: "utf8", input: JSON.stringify(entries) });
    const selected = {
      keyId: "selected-2030",
      publicKeyX963Base64: key,
      notBefore: "2030-06-01T00:00:00.000Z",
      notAfter: "2030-07-01T00:00:00.000Z",
    };
    const other = {
      keyId: "other-2030",
      publicKeyX963Base64: otherKey,
      notBefore: "2029-01-01T00:00:00.000Z",
      notAfter: "2032-01-01T00:00:00.000Z",
    };
    const valid = runEnvelope([selected, other]);
    assert.equal(valid.status, 0, valid.stderr);

    await writeFile(envelopePath, JSON.stringify({
      ...envelope,
      manifest: { ...manifest, sha256: "b".repeat(64) },
    }));
    const tamperedManifest = runEnvelope([selected, other]);
    assert.notEqual(tamperedManifest.status, 0);
    assert.match(tamperedManifest.stderr, /signature is invalid/);
    const corruptSignature = `${signatureDERBase64[0] === "A" ? "B" : "A"}${signatureDERBase64.slice(1)}`;
    await writeFile(envelopePath, JSON.stringify({ ...envelope, signatureDERBase64: corruptSignature }));
    const tamperedSignature = runEnvelope([selected, other]);
    assert.notEqual(tamperedSignature.status, 0);
    assert.match(tamperedSignature.stderr, /signature is invalid/);
    await writeFile(envelopePath, JSON.stringify(envelope));

    const startsLate = runEnvelope([{ ...selected, notBefore: "2030-06-01T00:00:00.001Z" }, other]);
    assert.notEqual(startsLate.status, 0);
    assert.match(startsLate.stderr, /complete release validity window/);
    const expiresEarly = runEnvelope([{ ...selected, notAfter: "2030-06-30T23:59:59.999Z" }, other]);
    assert.notEqual(expiresEarly.status, 0);
    assert.match(expiresEarly.stderr, /complete release validity window/);

    await writeFile(envelopePath, JSON.stringify({ ...envelope, publicKeyX963Base64: otherKey }));
    const wrongEnvelopeKey = runEnvelope([selected, other]);
    assert.notEqual(wrongEnvelopeKey.status, 0);
    assert.match(wrongEnvelopeKey.stderr, /does not use the selected update-signing key/);
    await writeFile(envelopePath, JSON.stringify({
      ...envelope,
      manifest: { ...envelope.manifest, keyId: "other-2030" },
    }));
    const wrongEnvelopeKeyId = runEnvelope([selected, other]);
    assert.notEqual(wrongEnvelopeKeyId.status, 0);
    assert.match(wrongEnvelopeKeyId.stderr, /does not use the selected update-signing key/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("production entitlement validation rejects every capability outside the exact reviewed allowlist", async () => {
  const { validateReleaseEntitlements } = await import(entitlementValidatorPath.href);
  const exact = {
    "com.apple.security.cs.allow-jit": false,
    "com.apple.security.cs.allow-unsigned-executable-memory": false,
    "com.apple.security.cs.disable-library-validation": false,
  };
  assert.equal(validateReleaseEntitlements(exact), true);
  const source = await readFile(releaseEntitlementsPath, "utf8");
  const sourceEntries = Object.fromEntries(
    [...source.matchAll(/<key>([^<]+)<\/key>\s*<(true|false)\/>/g)]
      .map(([, key, value]) => [key, value === "true"]),
  );
  assert.deepEqual(sourceEntries, exact);
  assert.equal([...source.matchAll(/<key>/g)].length, Object.keys(exact).length);
  assert.throws(() => validateReleaseEntitlements({ ...exact, "com.apple.security.get-task-allow": true }), /allowlist mismatch/);
  assert.throws(() => validateReleaseEntitlements({ ...exact, "com.apple.security.cs.disable-library-validation": true }), /must be false/);
  const missing = {
    "com.apple.security.cs.allow-unsigned-executable-memory": false,
    "com.apple.security.cs.disable-library-validation": false,
  };
  assert.throws(() => validateReleaseEntitlements(missing), /allowlist mismatch/);
});

test("publication verifies the exact attested candidate and never rebuilds or re-archives it", async () => {
  const publish = await readFile(publishScriptPath, "utf8");
  assert.match(publish, /SCOPEPROOF_RELEASE_CANDIDATE_DIR/);
  assert.match(publish, /SCOPEPROOF_RELEASE_EXPECTED_COMMIT/);
  assert.match(publish, /gh attestation verify/);
  assert.match(publish, /--signer-workflow/);
  assert.match(publish, /--source-digest "\$SCOPEPROOF_RELEASE_EXPECTED_COMMIT"/);
  assert.match(publish, /--source-ref refs\/heads\/main/);
  assert.match(publish, /--deny-self-hosted-runners/);
  assert.match(publish, /macos_release_evidence\.mjs" verify/);
  assert.match(publish, /\/bin\/cp -pP/);
  assert.match(publish, /ScopeproofUpdateDownloadOrigin/);
  assert.match(publish, /SCOPEPROOF_RELEASE_DOWNLOAD_ORIGIN/);
  assert.match(publish, /validate_macos_update_keys\.mjs/);
  assert.match(publish, /validate_macos_update_keys\.mjs" envelope/);
  assert.match(publish, /\/bin\/ln "\$staged_envelope" "\$envelope"/);
  assert.match(publish, /stapler validate/);
  assert.match(publish, /spctl --assess/);
  assert.match(publish, /sign_update_manifest\.mjs" "\$archive"/);
  assert.match(publish, /Refusing to read an update-signing private key from the repository/);
  assert.match(publish, /must have mode 0400 or 0600/);
  assert.match(publish, /must be owned by the publishing user/);
  assert.match(publish, /must not have additional hard links/);
  assert.match(publish, /must not have an extended ACL/);
  assert.match(publish, /must not be group- or world-writable/);
  assert.doesNotMatch(publish, /build_macos_capture|swift build|ditto -c/);
});

test("CODEOWNERS covers cloud infrastructure, AWS runtime, dependency locks, and vendored code", async () => {
  const source = await readFile(codeownersPath, "utf8");
  for (const protectedPath of [
    "/infra/aws/",
    "/lib/aws-runtime/",
    "/package.json",
    "/package-lock.json",
    "/vendor/",
  ]) assert.ok(source.split(/\r?\n/).includes(`${protectedPath} @jaysonguglietta`));
});

test("update manifest signer accepts only the compiled immutable CloudFront release path", async () => {
  const directory = await mkdtemp(join(tmpdir(), "scopeproof-update-manifest-"));
  try {
    const version = "9.8.7";
    const artifact = join(directory, `Scopeproof-Capture-${version}.zip`);
    const privateKeyPath = join(directory, "release-key.pem");
    const output = join(directory, "release-envelope.json");
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const privatePem = privateKey.export({ type: "pkcs8", format: "pem" });
    const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
    assert.equal(publicJwk.kty, "EC");
    const decodeBase64Url = (value: string) => Buffer.from(value.replaceAll("-", "+").replaceAll("_", "/"), "base64");
    const publicX963 = Buffer.concat([Buffer.from([4]), decodeBase64Url(publicJwk.x!), decodeBase64Url(publicJwk.y!)]).toString("base64");
    await Promise.all([writeFile(artifact, "signed release candidate"), writeFile(privateKeyPath, privatePem)]);
    const environment = {
      ...process.env,
      SCOPEPROOF_UPDATE_PRIVATE_KEY: privateKeyPath,
      SCOPEPROOF_UPDATE_PUBLIC_KEY_X963_BASE64: publicX963,
      SCOPEPROOF_UPDATE_KEY_ID: "release-2026",
      SCOPEPROOF_RELEASE_VERSION: version,
      SCOPEPROOF_RELEASE_SEQUENCE: "987",
      SCOPEPROOF_RELEASE_URL: `https://downloads.scopeproof.example/macos/${version}/Scopeproof-Capture-${version}.zip`,
      SCOPEPROOF_RELEASE_DOWNLOAD_ORIGIN: "https://downloads.scopeproof.example",
      SCOPEPROOF_RELEASE_TEAM_ID: "ABCDE12345",
      SCOPEPROOF_RELEASE_REQUIREMENT: 'identifier "com.scopeproof.capture" and anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"',
    };
    await execFileAsync(process.execPath, [manifestScriptPath.pathname, artifact, output], { env: environment });
    const envelope = JSON.parse(await readFile(output, "utf8")) as { manifest: { downloadUrl: string } };
    assert.equal(envelope.manifest.downloadUrl, environment.SCOPEPROOF_RELEASE_URL);
    await assert.rejects(
      execFileAsync(process.execPath, [manifestScriptPath.pathname, artifact, output], { env: environment }),
      /EEXIST/,
    );
    await assert.rejects(
      execFileAsync(process.execPath, [manifestScriptPath.pathname, artifact, join(directory, "bad.json")], {
        env: { ...environment, SCOPEPROOF_RELEASE_URL: `https://github.com/example/releases/download/v${version}/Scopeproof-Capture-${version}.zip` },
      }),
      /immutable download path/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("release evidence is complete, redacted, digest-bound, and tamper evident", async () => {
  const directory = await mkdtemp(join(tmpdir(), "scopeproof-release-evidence-"));
  try {
    const version = "9.8.7";
    const zip = join(directory, `Scopeproof-Capture-${version}.zip`);
    const dmg = join(directory, `Scopeproof-Capture-${version}.dmg`);
    const appReceipt = join(directory, "raw-app.json");
    const dmgReceipt = join(directory, "raw-dmg.json");
    await Promise.all([
      writeFile(zip, "exact zip bytes"),
      writeFile(dmg, "exact dmg bytes"),
      writeFile(appReceipt, JSON.stringify({ id: "11111111-1111-1111-1111-111111111111", status: "Accepted", message: "must be removed", logFileUrl: "https://secret.invalid" })),
      writeFile(dmgReceipt, JSON.stringify({ id: "22222222-2222-2222-2222-222222222222", status: "Accepted", message: "must be removed" })),
    ]);
    const environment = {
      ...process.env,
      SCOPEPROOF_RELEASE_VERSION: version,
      SCOPEPROOF_RELEASE_BUILD_NUMBER: "987",
      SCOPEPROOF_RELEASE_TEAM_ID: "ABCDE12345",
      SCOPEPROOF_RELEASE_REQUIREMENT: 'identifier "com.scopeproof.capture" and anchor apple generic',
      SCOPEPROOF_RELEASE_SOURCE_COMMIT: "a".repeat(40),
    };
    await execFileAsync(process.execPath, [evidenceScriptPath.pathname, "create", zip, dmg, appReceipt, dmgReceipt, directory], { env: environment });
    const { createHash } = await import("node:crypto");
    for (const artifact of [zip, dmg]) {
      const bytes = await readFile(artifact);
      await writeFile(`${artifact}.sha256`, `${createHash("sha256").update(bytes).digest("hex")}  ${artifact.split("/").at(-1)}\n`);
    }
    const receiptPath = join(directory, `Scopeproof-Capture-${version}.notary-receipt.json`);
    const receipt = await readFile(receiptPath, "utf8");
    assert.doesNotMatch(receipt, /message|logFileUrl|secret\.invalid/);
    await execFileAsync(process.execPath, [evidenceScriptPath.pathname, "verify", directory, version, "a".repeat(40)]);
    const duplicateArtifactReceipt = JSON.parse(receipt) as { submissions: Array<{ artifact: string }> };
    duplicateArtifactReceipt.submissions[1].artifact = "application";
    await writeFile(receiptPath, `${JSON.stringify(duplicateArtifactReceipt)}\n`);
    await assert.rejects(
      execFileAsync(process.execPath, [evidenceScriptPath.pathname, "verify", directory, version, "a".repeat(40)]),
      /exactly one accepted application and disk-image/,
    );
    await writeFile(receiptPath, receipt);
    await writeFile(zip, "tampered bytes");
    await assert.rejects(execFileAsync(process.execPath, [evidenceScriptPath.pathname, "verify", directory, version, "a".repeat(40)]), /Checksum mismatch/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("advanced CodeQL documents the managed-setup replacement and preserves complete coverage", async () => {
  const runbook = await readFile(releaseRunbookPath, "utf8");
  assert.match(runbook, /GitHub default setup was disabled on 2026-08-27/);
  assert.match(runbook, /replacement workflow is now present on `main`/);
  assert.match(runbook, /JavaScript, TypeScript, and GitHub Actions\s+coverage/);
  assert.doesNotMatch(runbook, /Keep GitHub's managed\/default CodeQL setup enabled/);
});

test("AWS runtime dependencies are exact-pinned behind a release-age quarantine", async () => {
  const [packageSource, workspace] = await Promise.all([
    readFile(awsPackagePath, "utf8"),
    readFile(awsWorkspacePath, "utf8"),
  ]);
  const packageManifest = JSON.parse(packageSource) as {
    dependencies: Record<string, string>;
    devDependencies: Record<string, string>;
    packageManager: string;
  };
  assert.match(packageManifest.packageManager, /^pnpm@[0-9]+\.[0-9]+\.[0-9]+$/);
  for (const version of [
    ...Object.values(packageManifest.dependencies),
    ...Object.values(packageManifest.devDependencies),
  ]) {
    assert.match(version, /^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$/);
  }
  assert.match(workspace, /^minimumReleaseAge:\s*1440\s*$/m);
  assert.doesNotMatch(workspace, /minimumReleaseAgeExclude/);
  assert.match(workspace, /^\s*esbuild:\s*true\s*$/m);
});
