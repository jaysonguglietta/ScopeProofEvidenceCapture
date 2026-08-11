import type { ScopeproofEnv } from "./env";

export type MacReleaseManifest = {
  schemaVersion: 1;
  version: string;
  sequence: number;
  downloadUrl: string;
  sha256: string;
  byteSize: number;
  publishedAt: string;
  expiresAt: string;
  minimumSystemVersion: string;
  teamIdentifier: string;
  designatedRequirement: string;
  keyId: string;
  notes: string;
};

export function releaseSigningPayload(manifest: MacReleaseManifest): string {
  return ["scopeproof-update-manifest-v1", manifest.schemaVersion, manifest.version, manifest.sequence, manifest.downloadUrl, manifest.sha256, manifest.byteSize, manifest.publishedAt, manifest.expiresAt, manifest.minimumSystemVersion, manifest.teamIdentifier, manifest.designatedRequirement, manifest.keyId, btoa(unescape(encodeURIComponent(manifest.notes)))].join("\n");
}

export function configuredMacRelease(env: ScopeproofEnv, now = new Date()): { manifest: MacReleaseManifest; signatureDERBase64: string } {
  if (!env.MACOS_RELEASE_MANIFEST_JSON || !env.MACOS_RELEASE_SIGNATURE_DER_BASE64) throw new Response(JSON.stringify({ error: "Signed macOS release metadata is not configured." }), { status: 503, headers: { "content-type": "application/json" } });
  let value: unknown;
  try { value = JSON.parse(env.MACOS_RELEASE_MANIFEST_JSON); } catch { throw new Error("MACOS_RELEASE_MANIFEST_JSON is invalid JSON."); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("macOS release manifest must be an object.");
  const manifest = value as Record<string, unknown>;
  const expected = ["schemaVersion", "version", "sequence", "downloadUrl", "sha256", "byteSize", "publishedAt", "expiresAt", "minimumSystemVersion", "teamIdentifier", "designatedRequirement", "keyId", "notes"];
  if (Object.keys(manifest).sort().join(",") !== expected.sort().join(",") || manifest.schemaVersion !== 1 || typeof manifest.version !== "string" || !/^\d+\.\d+\.\d+$/.test(manifest.version) || !Number.isSafeInteger(manifest.sequence) || Number(manifest.sequence) < 1 || typeof manifest.downloadUrl !== "string" || typeof manifest.sha256 !== "string" || !/^[a-f0-9]{64}$/.test(manifest.sha256) || !Number.isSafeInteger(manifest.byteSize) || Number(manifest.byteSize) < 1 || Number(manifest.byteSize) > 500 * 1024 * 1024 || typeof manifest.publishedAt !== "string" || typeof manifest.expiresAt !== "string" || typeof manifest.minimumSystemVersion !== "string" || !/^\d+\.\d+(?:\.\d+)?$/.test(manifest.minimumSystemVersion) || typeof manifest.teamIdentifier !== "string" || !/^[A-Z0-9]{10}$/.test(manifest.teamIdentifier) || typeof manifest.designatedRequirement !== "string" || manifest.designatedRequirement.length < 20 || manifest.designatedRequirement.length > 1_000 || typeof manifest.keyId !== "string" || !/^[A-Za-z0-9._-]{1,64}$/.test(manifest.keyId) || typeof manifest.notes !== "string" || manifest.notes.length > 4_000) throw new Error("macOS release manifest failed strict validation.");
  const url = new URL(manifest.downloadUrl);
  const allowedHosts = new Set(String(env.MACOS_RELEASE_ALLOWED_HOSTS || "").split(",").map((host) => host.trim().toLowerCase()).filter(Boolean));
  if (!allowedHosts.size || allowedHosts.size > 10 || url.protocol !== "https:" || url.username || url.password || url.hash || !allowedHosts.has(url.hostname.toLowerCase())) throw new Error("macOS release download host is not approved.");
  const publishedAt = new Date(manifest.publishedAt);
  const expiresAt = new Date(manifest.expiresAt);
  if (!Number.isFinite(publishedAt.getTime()) || !Number.isFinite(expiresAt.getTime()) || expiresAt <= now || publishedAt > new Date(now.getTime() + 5 * 60_000) || expiresAt.getTime() - publishedAt.getTime() > 45 * 86_400_000) throw new Error("macOS release validity window is invalid.");
  if (!/^[A-Za-z0-9+/]{80,144}={0,2}$/.test(env.MACOS_RELEASE_SIGNATURE_DER_BASE64)) throw new Error("macOS release signature encoding is invalid.");
  return { manifest: manifest as MacReleaseManifest, signatureDERBase64: env.MACOS_RELEASE_SIGNATURE_DER_BASE64 };
}
