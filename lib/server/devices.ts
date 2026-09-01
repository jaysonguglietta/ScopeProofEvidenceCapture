import type { AuthenticatedUser, Role } from "./auth";
import { executeAuditedBatch } from "./audit";
import { bytesToBase64, randomId, sha256 } from "./crypto";
import { getEnv } from "./env";

export type CaptureDevice = {
  id: string;
  displayName: string;
  platform: string;
  ownerId: string;
  status: "active" | "revoked";
  appVersion?: string;
  lastSeenAt?: string;
  tokenExpiresAt?: string;
};

export type DeviceCaptureChainInput = {
  sequence: number;
  previousHash: string;
  eventHash: string;
  evidenceId: string;
  provenanceKeyId: string;
  provenancePublicKey: string;
};

const roleRank: Record<Role, number> = { auditor: 0, reviewer: 1, compliance_lead: 2, admin: 3 };
const DEVICE_TOKEN_LIFETIME_MS = 30 * 24 * 60 * 60_000;

function base64url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function safeEqual(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  return difference === 0;
}

async function deviceUploadSignature(token: string, manifestSha256: string, imageSha256: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(token), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const payload = new TextEncoder().encode(`scopeproof-native-upload-v1\n${manifestSha256}\n${imageSha256}`);
  return Array.from(new Uint8Array(await crypto.subtle.sign("HMAC", key, payload))).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function createCaptureDevice(actor: AuthenticatedUser, displayName: string): Promise<{ device: CaptureDevice; token: string }> {
  const id = randomId("dev");
  const secret = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const token = `spdev_${id}.${secret}`;
  const tokenIssuedAt = new Date().toISOString();
  const tokenExpiresAt = new Date(Date.now() + DEVICE_TOKEN_LIFETIME_MS).toISOString();
  const device: CaptureDevice = { id, displayName, platform: "macOS", ownerId: actor.id, status: "active", tokenExpiresAt };
  await executeAuditedBatch(actor, "capture_device.enrolled", "capture_device", id, { displayName, platform: device.platform, tokenExpiresAt }, [
    getEnv().DB.prepare("INSERT INTO capture_devices (id, display_name, platform, token_hash, owner_id, token_issued_at, token_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .bind(id, displayName, device.platform, await sha256(token), actor.id, tokenIssuedAt, tokenExpiresAt),
  ]);
  return { device, token };
}

export async function listCaptureDevices(actor: AuthenticatedUser): Promise<Array<Record<string, unknown>>> {
  const canSeeAll = roleRank[actor.role] >= roleRank.compliance_lead;
  const query = canSeeAll
    ? "SELECT id, display_name, platform, owner_id, status, app_version, last_seen_at, token_issued_at, token_expires_at, token_last_rotated_at, CASE WHEN unixepoch(token_expires_at) <= unixepoch('now') THEN 1 ELSE 0 END AS token_expired, created_at, revoked_at FROM capture_devices ORDER BY created_at DESC"
    : "SELECT id, display_name, platform, owner_id, status, app_version, last_seen_at, token_issued_at, token_expires_at, token_last_rotated_at, CASE WHEN unixepoch(token_expires_at) <= unixepoch('now') THEN 1 ELSE 0 END AS token_expired, created_at, revoked_at FROM capture_devices WHERE owner_id = ? ORDER BY created_at DESC";
  return canSeeAll ? (await getEnv().DB.prepare(query).all<Record<string, unknown>>()).results : (await getEnv().DB.prepare(query).bind(actor.id).all<Record<string, unknown>>()).results;
}

export async function rotateCaptureDeviceToken(actor: AuthenticatedUser, id: string): Promise<{ token: string; tokenExpiresAt: string }> {
  const device = await getEnv().DB.prepare("SELECT owner_id, display_name, status FROM capture_devices WHERE id = ?").bind(id).first<{ owner_id: string; display_name: string; status: string }>();
  if (!device) throw new Response(JSON.stringify({ error: "Capture device not found." }), { status: 404, headers: { "content-type": "application/json" } });
  if (device.owner_id !== actor.id && roleRank[actor.role] < roleRank.compliance_lead) throw new Response(JSON.stringify({ error: "You cannot rotate this device." }), { status: 403, headers: { "content-type": "application/json" } });
  if (device.status !== "active") throw new Response(JSON.stringify({ error: "Revoked capture devices cannot be rotated." }), { status: 409, headers: { "content-type": "application/json" } });
  const secret = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const token = `spdev_${id}.${secret}`;
  const rotatedAt = new Date().toISOString();
  const tokenExpiresAt = new Date(Date.now() + DEVICE_TOKEN_LIFETIME_MS).toISOString();
  const [result] = await executeAuditedBatch(actor, "capture_device.token_rotated", "capture_device", id, { displayName: device.display_name, tokenExpiresAt }, [
    getEnv().DB.prepare("UPDATE capture_devices SET token_hash = ?, token_issued_at = ?, token_expires_at = ?, token_last_rotated_at = ? WHERE id = ? AND status = 'active'")
      .bind(await sha256(token), rotatedAt, tokenExpiresAt, rotatedAt, id),
  ], { sql: "EXISTS (SELECT 1 FROM capture_devices WHERE id = ? AND token_last_rotated_at = ? AND token_expires_at = ?)", bindings: [id, rotatedAt, tokenExpiresAt] });
  if (!result.meta.changes) throw new Response(JSON.stringify({ error: "Capture device changed concurrently. Reload and try again." }), { status: 409, headers: { "content-type": "application/json" } });
  return { token, tokenExpiresAt };
}

export async function revokeCaptureDevice(actor: AuthenticatedUser, id: string): Promise<boolean> {
  const device = await getEnv().DB.prepare("SELECT owner_id, display_name, status FROM capture_devices WHERE id = ?").bind(id).first<{ owner_id: string; display_name: string; status: string }>();
  if (!device) return false;
  if (device.owner_id !== actor.id && roleRank[actor.role] < roleRank.compliance_lead) throw new Response(JSON.stringify({ error: "You cannot revoke this device." }), { status: 403, headers: { "content-type": "application/json" } });
  if (device.status === "revoked") return false;
  const revokedAt = new Date().toISOString();
  const [result] = await executeAuditedBatch(actor, "capture_device.revoked", "capture_device", id, { displayName: device.display_name }, [
    getEnv().DB.prepare("UPDATE capture_devices SET status = 'revoked', revoked_at = ?, token_hash = 'revoked:' || id || ':' || ?, chain_pending_lease_id = NULL, chain_pending_sequence = NULL, chain_pending_previous_hash = NULL, chain_pending_event_hash = NULL, chain_pending_evidence_id = NULL, chain_pending_expires_at = NULL WHERE id = ? AND status = 'active'").bind(revokedAt, revokedAt, id),
  ], { sql: "EXISTS (SELECT 1 FROM capture_devices WHERE id = ? AND status = 'revoked' AND revoked_at = ?)", bindings: [id, revokedAt] });
  if (!result.meta.changes) return false;
  return true;
}

export async function reserveCaptureDeviceChain(device: CaptureDevice, actor: AuthenticatedUser, input: DeviceCaptureChainInput): Promise<string> {
  const env = getEnv();
  const now = new Date().toISOString();
  const row = await env.DB.prepare(`SELECT provenance_key_id, provenance_public_key, chain_sequence, chain_event_hash,
      chain_pending_lease_id, chain_pending_sequence, chain_pending_previous_hash, chain_pending_event_hash,
      chain_pending_evidence_id, chain_pending_expires_at
    FROM capture_devices WHERE id = ? AND owner_id = ? AND status = 'active'`).bind(device.id, actor.id).first<Record<string, unknown>>();
  if (!row) throw new Response(JSON.stringify({ error: "Capture device is unavailable." }), { status: 401, headers: { "content-type": "application/json" } });
  if ((row.provenance_key_id && row.provenance_key_id !== input.provenanceKeyId) || (row.provenance_public_key && row.provenance_public_key !== input.provenancePublicKey)) {
    throw new Response(JSON.stringify({ error: "The capture signing identity does not match the key pinned to this device." }), { status: 409, headers: { "content-type": "application/json" } });
  }
  const pendingMatches = row.chain_pending_lease_id && row.chain_pending_evidence_id === input.evidenceId
    && Number(row.chain_pending_sequence) === input.sequence && row.chain_pending_previous_hash === input.previousHash
    && row.chain_pending_event_hash === input.eventHash && String(row.chain_pending_expires_at || "") > now;
  if (pendingMatches) return String(row.chain_pending_lease_id);
  if (row.chain_pending_lease_id && String(row.chain_pending_expires_at || "") > now) {
    throw new Response(JSON.stringify({ error: "Another capture is being committed for this device. Retry after it completes." }), { status: 409, headers: { "content-type": "application/json" } });
  }
  const currentSequence = Number(row.chain_sequence || 0);
  const currentHash = String(row.chain_event_hash || "GENESIS");
  if (input.sequence !== currentSequence + 1 || input.previousHash !== currentHash) {
    throw new Response(JSON.stringify({ error: "Capture-chain continuity failed. Refresh or re-enroll this Mac before uploading more evidence." }), { status: 409, headers: { "content-type": "application/json" } });
  }
  const leaseId = randomId("chain_lease");
  const leaseExpiresAt = new Date(Date.now() + 5 * 60_000).toISOString();
  try {
    const [result] = await executeAuditedBatch(actor, "capture_device.chain_reserved", "capture_device", device.id, { evidenceId: input.evidenceId, sequence: input.sequence, previousHash: input.previousHash, eventHash: input.eventHash, provenanceKeyId: input.provenanceKeyId, leaseExpiresAt }, [
      env.DB.prepare(`UPDATE capture_devices SET
          provenance_key_id = COALESCE(provenance_key_id, ?), provenance_public_key = COALESCE(provenance_public_key, ?),
          chain_pending_lease_id = ?, chain_pending_sequence = ?, chain_pending_previous_hash = ?,
          chain_pending_event_hash = ?, chain_pending_evidence_id = ?, chain_pending_expires_at = ?
        WHERE id = ? AND owner_id = ? AND status = 'active'
          AND (provenance_key_id IS NULL OR (provenance_key_id = ? AND provenance_public_key = ?))
          AND chain_sequence = ? AND chain_event_hash = ?
          AND (chain_pending_lease_id IS NULL OR chain_pending_expires_at <= ?)`)
        .bind(input.provenanceKeyId, input.provenancePublicKey, leaseId, input.sequence, input.previousHash, input.eventHash, input.evidenceId, leaseExpiresAt,
          device.id, actor.id, input.provenanceKeyId, input.provenancePublicKey, currentSequence, currentHash, now),
    ], { sql: "EXISTS (SELECT 1 FROM capture_devices WHERE id = ? AND chain_pending_lease_id = ? AND provenance_key_id = ?)", bindings: [device.id, leaseId, input.provenanceKeyId] });
    if (!result.meta.changes) throw new Response(JSON.stringify({ error: "Capture-chain state changed concurrently. Reload and retry." }), { status: 409, headers: { "content-type": "application/json" } });
    return leaseId;
  } catch (error) {
    if (error instanceof Response) throw error;
    if (String(error).includes("idx_capture_devices_provenance_key")) throw new Response(JSON.stringify({ error: "This capture signing identity is already pinned to another device." }), { status: 409, headers: { "content-type": "application/json" } });
    throw error;
  }
}

export async function finalizeCaptureDeviceChain(actor: AuthenticatedUser, device: CaptureDevice, input: DeviceCaptureChainInput & {
  leaseId: string;
  artifactId: string;
  manifestSha256: string;
  imageSha256: string;
  jiraIssueKey: string | null;
}): Promise<void> {
  const env = getEnv();
  const manifestIdentity = `${device.id}:${input.evidenceId}`;
  const exactExisting = async (): Promise<boolean> => Boolean(await env.DB.prepare(`SELECT 1 FROM native_evidence_manifests n JOIN capture_devices d ON d.id = n.device_id
    WHERE n.id = ? AND n.device_id = ? AND n.local_evidence_id = ? AND n.artifact_id = ? AND n.manifest_sha256 = ? AND n.image_sha256 = ?
      AND COALESCE(n.jira_issue_key, '') = COALESCE(?, '') AND n.chain_sequence = ? AND n.chain_event_hash = ?
      AND n.provenance_key_id = ? AND d.chain_sequence >= n.chain_sequence AND d.provenance_key_id = n.provenance_key_id`)
    .bind(manifestIdentity, device.id, input.evidenceId, input.artifactId, input.manifestSha256, input.imageSha256, input.jiraIssueKey,
      input.sequence, input.eventHash, input.provenanceKeyId).first());
  if (await exactExisting()) return;
  try {
    const results = await executeAuditedBatch(actor, "capture_device.uploaded", "evidence", input.artifactId, { deviceId: device.id, evidenceId: input.evidenceId, sequence: input.sequence, imageSha256: input.imageSha256, manifestSha256: input.manifestSha256, provenanceKeyId: input.provenanceKeyId }, [
      env.DB.prepare(`INSERT INTO native_evidence_manifests
        (id, device_id, local_evidence_id, artifact_id, manifest_sha256, image_sha256, jira_issue_key, chain_sequence, chain_event_hash, provenance_key_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(manifestIdentity, device.id, input.evidenceId, input.artifactId, input.manifestSha256, input.imageSha256, input.jiraIssueKey,
          input.sequence, input.eventHash, input.provenanceKeyId),
      env.DB.prepare(`UPDATE capture_devices SET chain_sequence = ?, chain_event_hash = ?,
          chain_pending_lease_id = NULL, chain_pending_sequence = NULL, chain_pending_previous_hash = NULL,
          chain_pending_event_hash = NULL, chain_pending_evidence_id = NULL, chain_pending_expires_at = NULL
        WHERE id = ? AND owner_id = ? AND status = 'active' AND provenance_key_id = ? AND provenance_public_key = ?
          AND chain_sequence = ? AND chain_event_hash = ? AND chain_pending_lease_id = ?
          AND chain_pending_sequence = ? AND chain_pending_previous_hash = ? AND chain_pending_event_hash = ? AND chain_pending_evidence_id = ?`)
        .bind(input.sequence, input.eventHash, device.id, actor.id, input.provenanceKeyId, input.provenancePublicKey,
          input.sequence - 1, input.previousHash, input.leaseId, input.sequence, input.previousHash, input.eventHash, input.evidenceId),
    ], { sql: `EXISTS (SELECT 1 FROM native_evidence_manifests WHERE id = ? AND artifact_id = ? AND manifest_sha256 = ? AND image_sha256 = ?
        AND chain_sequence = ? AND chain_event_hash = ? AND provenance_key_id = ?)
      AND EXISTS (SELECT 1 FROM capture_devices WHERE id = ? AND chain_sequence = ? AND chain_event_hash = ? AND chain_pending_lease_id IS NULL)`, bindings: [manifestIdentity, input.artifactId, input.manifestSha256, input.imageSha256,
        input.sequence, input.eventHash, input.provenanceKeyId, device.id, input.sequence, input.eventHash] });
    if (results.some((result) => !result.meta.changes)) throw new Error("Capture-chain finalization did not commit every required record.");
  } catch (error) {
    if (await exactExisting()) return;
    throw error;
  }
}

export async function requireCaptureDevice(request: Request): Promise<{ device: CaptureDevice; actor: AuthenticatedUser; verifyUploadSignature: (manifestSha256: string, imageSha256: string, signature: string) => Promise<boolean> }> {
  const authorization = request.headers.get("authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
  const separator = token.indexOf(".");
  if (!token.startsWith("spdev_dev_") || separator < 0) throw new Response(JSON.stringify({ error: "Valid capture device authorization is required." }), { status: 401, headers: { "content-type": "application/json" } });
  const id = token.slice("spdev_".length, separator);
  const row = await getEnv().DB.prepare(`SELECT d.id, d.display_name, d.platform, d.token_hash, d.owner_id, d.status, d.app_version, d.last_seen_at, d.token_expires_at,
      u.email, u.display_name AS owner_name, u.role, u.status AS owner_status
    FROM capture_devices d JOIN users u ON u.id = d.owner_id WHERE d.id = ?`).bind(id).first<Record<string, unknown>>();
  if (!row || row.status !== "active" || row.owner_status !== "active" || Date.parse(String(row.token_expires_at)) <= Date.now() || !safeEqual(String(row.token_hash), await sha256(token))) throw new Response(JSON.stringify({ error: "Capture device token is invalid, expired, or revoked." }), { status: 401, headers: { "content-type": "application/json" } });
  const appVersion = request.headers.get("x-scopeproof-version")?.slice(0, 32) || null;
  await getEnv().DB.prepare("UPDATE capture_devices SET last_seen_at = CURRENT_TIMESTAMP, app_version = COALESCE(?, app_version) WHERE id = ?").bind(appVersion, id).run();
  return {
    device: { id: String(row.id), displayName: String(row.display_name), platform: String(row.platform), ownerId: String(row.owner_id), status: "active", appVersion: appVersion || String(row.app_version || ""), lastSeenAt: String(row.last_seen_at || ""), tokenExpiresAt: String(row.token_expires_at) },
    actor: { id: String(row.owner_id), email: String(row.email), displayName: String(row.owner_name), role: String(row.role) as Role },
    verifyUploadSignature: async (manifestSha256, imageSha256, signature) => /^[a-f0-9]{64}$/.test(signature) && safeEqual(await deviceUploadSignature(token, manifestSha256, imageSha256), signature),
  };
}
