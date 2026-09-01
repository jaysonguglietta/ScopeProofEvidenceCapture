#!/usr/bin/env node
import { createHash, createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { basename, resolve } from "node:path";

const required = ["SCOPEPROOF_UPDATE_PRIVATE_KEY", "SCOPEPROOF_UPDATE_PUBLIC_KEY_X963_BASE64", "SCOPEPROOF_UPDATE_KEY_ID", "SCOPEPROOF_RELEASE_VERSION", "SCOPEPROOF_RELEASE_SEQUENCE", "SCOPEPROOF_RELEASE_URL", "SCOPEPROOF_RELEASE_DOWNLOAD_ORIGIN", "SCOPEPROOF_RELEASE_TEAM_ID", "SCOPEPROOF_RELEASE_REQUIREMENT"];
for (const name of required) if (!process.env[name]) throw new Error(`${name} is required.`);
const artifactPath = resolve(process.argv[2] || "");
const outputPath = resolve(process.argv[3] || "macos-release-envelope.json");
if (artifactPath === outputPath) throw new Error("Release artifact and manifest output paths must differ.");
const artifact = await readFile(artifactPath);
const now = new Date();
const notes = process.env.SCOPEPROOF_RELEASE_NOTES || `Scopeproof Capture ${process.env.SCOPEPROOF_RELEASE_VERSION}`;
if (Buffer.byteLength(notes, "utf8") > 8 * 1024) throw new Error("Release notes exceed the 8 KiB signed-manifest limit.");
const manifest = {
  schemaVersion: 1,
  version: process.env.SCOPEPROOF_RELEASE_VERSION,
  sequence: Number(process.env.SCOPEPROOF_RELEASE_SEQUENCE),
  downloadUrl: process.env.SCOPEPROOF_RELEASE_URL,
  sha256: createHash("sha256").update(artifact).digest("hex"),
  byteSize: artifact.byteLength,
  publishedAt: now.toISOString(),
  expiresAt: new Date(now.getTime() + 30 * 86_400_000).toISOString(),
  minimumSystemVersion: process.env.SCOPEPROOF_MINIMUM_SYSTEM_VERSION || "14.0",
  teamIdentifier: process.env.SCOPEPROOF_RELEASE_TEAM_ID,
  designatedRequirement: process.env.SCOPEPROOF_RELEASE_REQUIREMENT,
  keyId: process.env.SCOPEPROOF_UPDATE_KEY_ID,
  notes,
};
let downloadOrigin;
let downloadUrl;
try {
  downloadOrigin = new URL(process.env.SCOPEPROOF_RELEASE_DOWNLOAD_ORIGIN);
  downloadUrl = new URL(manifest.downloadUrl);
} catch {
  throw new Error("Release download origin and URL must be valid absolute URLs.");
}
const expectedArtifactName = `Scopeproof-Capture-${manifest.version}.zip`;
const expectedDownloadUrl = `${downloadOrigin.origin}/macos/${manifest.version}/${expectedArtifactName}`;
if (!/^\d+\.\d+\.\d+$/.test(manifest.version) || !Number.isSafeInteger(manifest.sequence) || manifest.sequence < 1
    || downloadOrigin.protocol !== "https:" || downloadOrigin.username || downloadOrigin.password || downloadOrigin.port
    || downloadOrigin.search || downloadOrigin.hash || downloadOrigin.pathname !== "/"
    || process.env.SCOPEPROOF_RELEASE_DOWNLOAD_ORIGIN !== downloadOrigin.origin
    || downloadUrl.href !== expectedDownloadUrl
    || basename(artifactPath) !== expectedArtifactName || !/^[A-Z0-9]{10}$/.test(manifest.teamIdentifier)
    || !/^[A-Za-z0-9._-]{1,64}$/.test(manifest.keyId)
    || !/^\d+\.\d+(?:\.\d+)?$/.test(manifest.minimumSystemVersion)
    || !/^[\x20-\x7e]{20,2048}$/.test(manifest.designatedRequirement)) {
  throw new Error("Release manifest inputs or immutable download path are invalid.");
}
const payload = ["scopeproof-update-manifest-v1", manifest.schemaVersion, manifest.version, manifest.sequence, manifest.downloadUrl, manifest.sha256, manifest.byteSize, manifest.publishedAt, manifest.expiresAt, manifest.minimumSystemVersion, manifest.teamIdentifier, manifest.designatedRequirement, manifest.keyId, Buffer.from(manifest.notes, "utf8").toString("base64")].join("\n");
const privateKey = createPrivateKey(await readFile(resolve(process.env.SCOPEPROOF_UPDATE_PRIVATE_KEY), "utf8"));
if (privateKey.asymmetricKeyType !== "ec" || privateKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
  throw new Error("Update private key must be an EC P-256 key.");
}
const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
const decodeBase64Url = (value) => Buffer.from(value.replaceAll("-", "+").replaceAll("_", "/"), "base64");
const publicKeyX963Base64 = Buffer.concat([Buffer.from([4]), decodeBase64Url(publicJwk.x), decodeBase64Url(publicJwk.y)]).toString("base64");
if (publicKeyX963Base64 !== process.env.SCOPEPROOF_UPDATE_PUBLIC_KEY_X963_BASE64) throw new Error("Update private key does not match the public key compiled into the app.");
const signatureDERBase64 = sign("sha256", Buffer.from(payload), privateKey).toString("base64");
const publicKeySpkiSha256 = createHash("sha256").update(createPublicKey(privateKey).export({ type: "spki", format: "der" })).digest("hex");
await writeFile(outputPath, `${JSON.stringify({ manifest, signatureDERBase64, releaseArtifact: basename(artifactPath), publicKeySpkiSha256, publicKeyX963Base64 }, null, 2)}\n`, { mode: 0o600, flag: "wx" });
console.log(outputPath);
