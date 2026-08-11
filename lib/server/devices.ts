import type { AuthenticatedUser, Role } from "./auth";
import { appendAuditEvent } from "./audit";
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
};

const roleRank: Record<Role, number> = { auditor: 0, reviewer: 1, compliance_lead: 2, admin: 3 };

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
  const device: CaptureDevice = { id, displayName, platform: "macOS", ownerId: actor.id, status: "active" };
  await getEnv().DB.prepare("INSERT INTO capture_devices (id, display_name, platform, token_hash, owner_id) VALUES (?, ?, ?, ?, ?)")
    .bind(id, displayName, device.platform, await sha256(token), actor.id).run();
  await appendAuditEvent(actor, "capture_device.enrolled", "capture_device", id, { displayName, platform: device.platform });
  return { device, token };
}

export async function listCaptureDevices(actor: AuthenticatedUser): Promise<Array<Record<string, unknown>>> {
  const canSeeAll = roleRank[actor.role] >= roleRank.compliance_lead;
  const query = canSeeAll
    ? "SELECT id, display_name, platform, owner_id, status, app_version, last_seen_at, created_at, revoked_at FROM capture_devices ORDER BY created_at DESC"
    : "SELECT id, display_name, platform, owner_id, status, app_version, last_seen_at, created_at, revoked_at FROM capture_devices WHERE owner_id = ? ORDER BY created_at DESC";
  return canSeeAll ? (await getEnv().DB.prepare(query).all<Record<string, unknown>>()).results : (await getEnv().DB.prepare(query).bind(actor.id).all<Record<string, unknown>>()).results;
}

export async function revokeCaptureDevice(actor: AuthenticatedUser, id: string): Promise<boolean> {
  const device = await getEnv().DB.prepare("SELECT owner_id, display_name, status FROM capture_devices WHERE id = ?").bind(id).first<{ owner_id: string; display_name: string; status: string }>();
  if (!device) return false;
  if (device.owner_id !== actor.id && roleRank[actor.role] < roleRank.compliance_lead) throw new Response(JSON.stringify({ error: "You cannot revoke this device." }), { status: 403, headers: { "content-type": "application/json" } });
  if (device.status === "revoked") return false;
  await getEnv().DB.prepare("UPDATE capture_devices SET status = 'revoked', revoked_at = CURRENT_TIMESTAMP WHERE id = ?").bind(id).run();
  await appendAuditEvent(actor, "capture_device.revoked", "capture_device", id, { displayName: device.display_name });
  return true;
}

export async function requireCaptureDevice(request: Request): Promise<{ device: CaptureDevice; actor: AuthenticatedUser; verifyUploadSignature: (manifestSha256: string, imageSha256: string, signature: string) => Promise<boolean> }> {
  const authorization = request.headers.get("authorization") || "";
  const token = authorization.startsWith("Bearer ") ? authorization.slice(7).trim() : "";
  const separator = token.indexOf(".");
  if (!token.startsWith("spdev_dev_") || separator < 0) throw new Response(JSON.stringify({ error: "Valid capture device authorization is required." }), { status: 401, headers: { "content-type": "application/json" } });
  const id = token.slice("spdev_".length, separator);
  const row = await getEnv().DB.prepare(`SELECT d.id, d.display_name, d.platform, d.token_hash, d.owner_id, d.status, d.app_version, d.last_seen_at,
      u.email, u.display_name AS owner_name, u.role
    FROM capture_devices d JOIN users u ON u.id = d.owner_id WHERE d.id = ?`).bind(id).first<Record<string, unknown>>();
  if (!row || row.status !== "active" || !safeEqual(String(row.token_hash), await sha256(token))) throw new Response(JSON.stringify({ error: "Capture device token is invalid or revoked." }), { status: 401, headers: { "content-type": "application/json" } });
  const appVersion = request.headers.get("x-scopeproof-version")?.slice(0, 32) || null;
  await getEnv().DB.prepare("UPDATE capture_devices SET last_seen_at = CURRENT_TIMESTAMP, app_version = COALESCE(?, app_version) WHERE id = ?").bind(appVersion, id).run();
  return {
    device: { id: String(row.id), displayName: String(row.display_name), platform: String(row.platform), ownerId: String(row.owner_id), status: "active", appVersion: appVersion || String(row.app_version || ""), lastSeenAt: String(row.last_seen_at || "") },
    actor: { id: String(row.owner_id), email: String(row.email), displayName: String(row.owner_name), role: String(row.role) as Role },
    verifyUploadSignature: async (manifestSha256, imageSha256, signature) => /^[a-f0-9]{64}$/.test(signature) && safeEqual(await deviceUploadSignature(token, manifestSha256, imageSha256), signature),
  };
}
