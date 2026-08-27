#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFile, stat, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

const sha256 = async (path) => createHash("sha256").update(await readFile(path)).digest("hex");
const fail = (message) => { throw new Error(message); };
const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));
const requireMatch = (value, pattern, label) => pattern.test(value || "") || fail(`Invalid ${label}.`);

async function createEvidence(args) {
  const [zipInput, dmgInput, appNotaryInput, dmgNotaryInput, outputInput] = args;
  const zipPath = resolve(zipInput || "");
  const dmgPath = resolve(dmgInput || "");
  const outputDir = resolve(outputInput || "");
  const version = process.env.SCOPEPROOF_RELEASE_VERSION;
  const buildNumber = process.env.SCOPEPROOF_RELEASE_BUILD_NUMBER;
  const team = process.env.SCOPEPROOF_RELEASE_TEAM_ID;
  const requirement = process.env.SCOPEPROOF_RELEASE_REQUIREMENT;
  const commit = process.env.SCOPEPROOF_RELEASE_SOURCE_COMMIT || process.env.GITHUB_SHA;
  requireMatch(version, /^\d+\.\d+\.\d+$/, "release version");
  requireMatch(buildNumber, /^[1-9]\d{0,8}$/, "build number");
  requireMatch(team, /^[A-Z0-9]{10}$/, "team identifier");
  requireMatch(commit, /^[a-f0-9]{40}$/, "source commit");
  if (!requirement) fail("SCOPEPROOF_RELEASE_REQUIREMENT is required.");

  const rawReceipts = await Promise.all([readJson(resolve(appNotaryInput || "")), readJson(resolve(dmgNotaryInput || ""))]);
  const sanitizeReceipt = (receipt, artifact) => {
    requireMatch(receipt.id, /^[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$/, `${artifact} notarization submission ID`);
    if (receipt.status !== "Accepted") fail(`${artifact} notarization was not accepted.`);
    return { artifact, submissionId: receipt.id, status: receipt.status };
  };
  const receipt = {
    schemaVersion: 1,
    provider: "Apple notary service",
    releaseVersion: version,
    submissions: [sanitizeReceipt(rawReceipts[0], "application"), sanitizeReceipt(rawReceipts[1], "disk-image")],
  };
  const stem = `Scopeproof-Capture-${version}`;
  const receiptPath = join(outputDir, `${stem}.notary-receipt.json`);
  await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600, flag: "wx" });

  const artifacts = await Promise.all([zipPath, dmgPath].map(async (path) => ({
    name: basename(path),
    sha256: await sha256(path),
    byteSize: (await stat(path)).size,
  })));
  const sbom = {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    serialNumber: `urn:uuid:${rawReceipts[0].id}`,
    version: 1,
    metadata: {
      component: {
        type: "application",
        "bom-ref": `pkg:generic/scopeproof-capture@${version}?build=${buildNumber}`,
        name: "Scopeproof Capture",
        version,
        properties: [
          { name: "scopeproof:bundleIdentifier", value: "com.scopeproof.capture" },
          { name: "scopeproof:bundleBuild", value: buildNumber },
          { name: "scopeproof:sourceCommit", value: commit },
        ],
      },
    },
    components: [
      {
        type: "library",
        "bom-ref": "pkg:generic/apple-macos-sqlite3",
        name: "SQLite3",
        scope: "required",
        properties: [{ name: "scopeproof:source", value: "macOS system library linked by Package.swift" }],
      },
      ...artifacts.map((artifact) => ({
        type: "file",
        "bom-ref": `urn:scopeproof:artifact:${artifact.name}`,
        name: artifact.name,
        hashes: [{ alg: "SHA-256", content: artifact.sha256 }],
        properties: [{ name: "scopeproof:byteSize", value: String(artifact.byteSize) }],
      })),
    ],
    dependencies: [{ ref: `pkg:generic/scopeproof-capture@${version}?build=${buildNumber}`, dependsOn: ["pkg:generic/apple-macos-sqlite3"] }],
  };
  const sbomPath = join(outputDir, `${stem}.sbom.cdx.json`);
  await writeFile(sbomPath, `${JSON.stringify(sbom, null, 2)}\n`, { mode: 0o600, flag: "wx" });

  const evidence = [
    ...artifacts,
    { name: basename(receiptPath), sha256: await sha256(receiptPath), byteSize: (await stat(receiptPath)).size },
    { name: basename(sbomPath), sha256: await sha256(sbomPath), byteSize: (await stat(sbomPath)).size },
  ];
  const provenance = {
    _type: "https://in-toto.io/Statement/v1",
    subject: evidence.map((item) => ({ name: item.name, digest: { sha256: item.sha256 } })),
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "urn:scopeproof:build-type:macos-developer-id-notarized:v1",
        externalParameters: { version, buildNumber, architecture: "arm64" },
        internalParameters: {},
        resolvedDependencies: [{
          uri: process.env.GITHUB_REPOSITORY ? `https://github.com/${process.env.GITHUB_REPOSITORY}` : "git+local",
          digest: { gitCommit: commit },
        }],
      },
      runDetails: {
        builder: { id: process.env.GITHUB_WORKFLOW_REF || "local:Scripts/build_macos_production_release.sh" },
        metadata: {
          invocationId: process.env.GITHUB_RUN_ID ? `https://github.com/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}` : "local",
        },
      },
      scopeproof: { bundleIdentifier: "com.scopeproof.capture", teamIdentifier: team, designatedRequirement: requirement },
    },
  };
  const provenancePath = join(outputDir, `${stem}.provenance.intoto.json`);
  await writeFile(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  console.log([receiptPath, sbomPath, provenancePath].join("\n"));
}

async function verifyEvidence(args) {
  const [candidateInput, version, expectedCommit] = args;
  requireMatch(version, /^\d+\.\d+\.\d+$/, "release version");
  requireMatch(expectedCommit, /^[a-f0-9]{40}$/, "expected commit");
  const candidateDir = resolve(candidateInput || "");
  const stem = `Scopeproof-Capture-${version}`;
  const zipName = `${stem}.zip`;
  const dmgName = `${stem}.dmg`;
  const expected = new Map();
  for (const name of [zipName, dmgName]) {
    const checksum = (await readFile(join(candidateDir, `${name}.sha256`), "utf8")).trim();
    const match = checksum.match(/^([a-f0-9]{64}) {2}([^/]+)$/);
    if (!match || match[2] !== name) fail(`Invalid checksum sidecar for ${name}.`);
    const actual = await sha256(join(candidateDir, name));
    if (actual !== match[1]) fail(`Checksum mismatch for ${name}.`);
    expected.set(name, actual);
  }
  const receiptName = `${stem}.notary-receipt.json`;
  const sbomName = `${stem}.sbom.cdx.json`;
  const provenance = await readJson(join(candidateDir, `${stem}.provenance.intoto.json`));
  const receipt = await readJson(join(candidateDir, receiptName));
  const sbom = await readJson(join(candidateDir, sbomName));
  if (
    Object.keys(receipt).sort().join(",") !== "provider,releaseVersion,schemaVersion,submissions"
    || receipt.schemaVersion !== 1
    || receipt.provider !== "Apple notary service"
    || receipt.releaseVersion !== version
    || receipt.submissions?.length !== 2
  ) fail("Invalid redacted notarization receipt.");
  const receiptArtifacts = new Set(receipt.submissions.map((item) => item.artifact));
  if (receiptArtifacts.size !== 2 || !receiptArtifacts.has("application") || !receiptArtifacts.has("disk-image")) {
    fail("Notarization receipt must contain exactly one accepted application and disk-image submission.");
  }
  const submissionIds = new Set(receipt.submissions.map((item) => item.submissionId));
  if (submissionIds.size !== 2) fail("Notarization receipt submission IDs must be distinct.");
  for (const item of receipt.submissions) {
    if (!new Set(["application", "disk-image"]).has(item.artifact) || item.status !== "Accepted") fail("Notarization receipt is not accepted for both release forms.");
    requireMatch(item.submissionId, /^[A-Fa-f0-9]{8}(?:-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}$/, "notarization submission ID");
    if (Object.keys(item).sort().join(",") !== "artifact,status,submissionId") fail("Notarization receipt contains unexpected fields.");
  }
  if (sbom.bomFormat !== "CycloneDX" || sbom.specVersion !== "1.6" || sbom.metadata?.component?.version !== version) fail("Invalid release SBOM.");
  const sbomProperties = new Map((sbom.metadata?.component?.properties || []).map((property) => [property.name, property.value]));
  if (sbomProperties.get("scopeproof:sourceCommit") !== expectedCommit) fail("Release SBOM source commit does not match the approved commit.");
  for (const name of [zipName, dmgName]) {
    const component = sbom.components?.find((item) => item.name === name);
    if (component?.hashes?.find((hash) => hash.alg === "SHA-256")?.content !== expected.get(name)) fail(`SBOM digest mismatch for ${name}.`);
  }
  const commit = provenance.predicate?.buildDefinition?.resolvedDependencies?.[0]?.digest?.gitCommit;
  const parameters = provenance.predicate?.buildDefinition?.externalParameters;
  if (
    provenance._type !== "https://in-toto.io/Statement/v1"
    || provenance.predicateType !== "https://slsa.dev/provenance/v1"
    || commit !== expectedCommit
    || parameters?.version !== version
    || parameters?.architecture !== "arm64"
  ) fail("Invalid release provenance or source commit.");
  const rawSubjects = provenance.subject || [];
  const subjects = new Map(rawSubjects.map((subject) => [subject.name, subject.digest?.sha256]));
  if (rawSubjects.length !== 4 || subjects.size !== 4) fail("Release provenance must contain exactly four unique subjects.");
  for (const [name, digest] of expected) if (subjects.get(name) !== digest) fail(`Provenance digest mismatch for ${name}.`);
  for (const name of [receiptName, sbomName]) if (subjects.get(name) !== await sha256(join(candidateDir, name))) fail(`Provenance digest mismatch for ${name}.`);
  console.log(`Verified release evidence for ${stem} from ${expectedCommit}.`);
}

const [command, ...args] = process.argv.slice(2);
if (command === "create") await createEvidence(args);
else if (command === "verify") await verifyEvidence(args);
else fail("Usage: macos_release_evidence.mjs create <zip> <dmg> <app-notary.json> <dmg-notary.json> <output-dir> | verify <candidate-dir> <version> <commit>");
