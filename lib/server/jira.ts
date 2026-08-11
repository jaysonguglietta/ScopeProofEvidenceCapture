import type { AuthenticatedUser } from "./auth";
import { appendAuditEvent } from "./audit";
import { bytesToBase64, decryptSecret, encryptSecret, hmac, randomId, sha256, stableJson } from "./crypto";
import { getEnv, requireEnv } from "./env";

const tokenKeyName = "JIRA_OAUTH_TOKEN_ENCRYPTION_KEY";
const oauthScopes = ["offline_access", "read:jira-work", "write:jira-work"];
const requiredJiraScopes = ["read:jira-work", "write:jira-work"];
const issueKeyPattern = /^[A-Z][A-Z0-9_]{1,31}-[1-9][0-9]*$/;
const projectKeyPattern = /^[A-Z][A-Z0-9_]{1,31}$/;

type JiraConnectionRow = {
  id: string;
  user_id: string;
  cloud_id: string;
  site_url: string;
  site_name: string;
  allowed_projects_json: string;
  access_token_ciphertext: string;
  access_token_iv: string;
  refresh_token_ciphertext: string;
  refresh_token_iv: string;
  access_token_expires_at: string;
  scopes: string;
  status: "active" | "reauthorization_required";
  token_version: number;
  refresh_lease_id: string | null;
  refresh_lease_expires_at: string | null;
  last_tested_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
};

type AtlassianTokenResponse = { access_token?: string; refresh_token?: string; expires_in?: number; scope?: string };
type AtlassianResource = { id?: string; name?: string; url?: string; scopes?: string[] };
export type JiraConnectionSummary = {
  connected: boolean;
  configured: boolean;
  id?: string;
  siteUrl?: string;
  siteName?: string;
  allowedProjects?: string[];
  status?: "active" | "reauthorization_required";
  lastTestedAt?: string | null;
  updatedAt?: string;
};
export type JiraIssueSummary = { key: string; summary: string; status: string; projectKey: string; url: string };
export type JiraAttachmentReceipt = { id: string; filename: string; size: number; mimeType: string };
export type JiraUploadReceipt = {
  receiptId: string;
  evidenceId: string;
  issueKey: string;
  siteUrl: string;
  uploadedAt: string;
  attachments: JiraAttachmentReceipt[];
  receiptSha256: string;
  signature: string;
};
type JiraUploadOperation = {
  id: string;
  request_sha256: string;
  status: "reserved" | "uploading" | "succeeded" | "failed" | "unknown";
  lease_id: string | null;
  lease_expires_at: string | null;
  receipt_id: string | null;
};

class OAuthTokenExchangeError extends Error {
  constructor(readonly status: number) { super(`Atlassian OAuth token exchange failed (${status}).`); }
  get retryable(): boolean { return this.status === 408 || this.status === 429 || this.status >= 500; }
}

function changed(result: unknown): boolean {
  return Number((result as { meta?: { changes?: number } })?.meta?.changes || 0) === 1;
}

function base64url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function connectionAad(id: string, userId: string, kind: "access" | "refresh"): string {
  return stableJson({ purpose: "jira-oauth-token", version: 1, connectionId: id, userId, kind });
}

function grantedScopes(value: string | undefined): Set<string> {
  return new Set(String(value || "").split(/\s+/).filter(Boolean));
}

function assertRequiredScopes(value: string | undefined): void {
  const granted = grantedScopes(value);
  if (requiredJiraScopes.some((scope) => !granted.has(scope))) {
    throw new Error("Atlassian did not grant the required Jira read and write scopes.");
  }
}

function oauthConfiguration(): { clientId: string; clientSecret: string; callbackUrl: string; tokenKey: string } {
  const callbackUrl = requireEnv("JIRA_OAUTH_CALLBACK_URL");
  let parsed: URL;
  try { parsed = new URL(callbackUrl); } catch { throw new Error("JIRA_OAUTH_CALLBACK_URL is invalid."); }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash) throw new Error("JIRA_OAUTH_CALLBACK_URL must be a clean HTTPS URL.");
  return {
    clientId: requireEnv("JIRA_OAUTH_CLIENT_ID"),
    clientSecret: requireEnv("JIRA_OAUTH_CLIENT_SECRET"),
    callbackUrl: parsed.toString(),
    tokenKey: requireEnv("JIRA_OAUTH_TOKEN_ENCRYPTION_KEY"),
  };
}

export function normalizeJiraSite(value: string): string | null {
  try {
    const url = new URL(value.trim());
    const host = url.hostname.toLowerCase();
    if (url.protocol !== "https:" || !host.endsWith(".atlassian.net") || host === ".atlassian.net" || url.port || url.username || url.password || url.search || url.hash) return null;
    if (url.pathname !== "/" && url.pathname !== "") return null;
    return `https://${host}`;
  } catch { return null; }
}

export function normalizeJiraProjects(value: unknown): string[] | null {
  const raw = Array.isArray(value) ? value : String(value || "").split(/[\s,]+/);
  const projects = Array.from(new Set(raw.map((item) => String(item).trim().toUpperCase()).filter(Boolean)));
  if (!projects.length || projects.length > 20 || projects.some((project) => !projectKeyPattern.test(project))) return null;
  return projects.sort();
}

export function normalizeJiraIssueKey(value: string): string | null {
  const key = value.trim().toUpperCase();
  return issueKeyPattern.test(key) ? key : null;
}

export function assertJiraOperator(actor: AuthenticatedUser): void {
  if (actor.role === "auditor") throw new Response(JSON.stringify({ error: "Reviewer access is required for Jira Cloud evidence disclosure." }), { status: 403, headers: { "content-type": "application/json" } });
}

async function responseJson<T>(response: Response, maximumBytes = 1_000_000): Promise<T> {
  const text = await response.text();
  if (text.length > maximumBytes) throw new Error("Atlassian returned an oversized response.");
  try { return JSON.parse(text) as T; } catch { throw new Error("Atlassian returned an invalid response."); }
}

async function tokenExchange(body: Record<string, string>): Promise<AtlassianTokenResponse> {
  const response = await fetch("https://auth.atlassian.com/oauth/token", {
    method: "POST",
    headers: { "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new OAuthTokenExchangeError(response.status);
  return responseJson<AtlassianTokenResponse>(response);
}

async function accessibleResources(accessToken: string): Promise<AtlassianResource[]> {
  const response = await fetch("https://api.atlassian.com/oauth/token/accessible-resources", {
    headers: { authorization: `Bearer ${accessToken}`, accept: "application/json" },
    signal: AbortSignal.timeout(20_000),
  });
  if (!response.ok) throw new Error(`Atlassian site access check failed (${response.status}).`);
  const resources = await responseJson<unknown>(response);
  if (!Array.isArray(resources)) throw new Error("Atlassian returned an invalid site list.");
  return resources as AtlassianResource[];
}

async function connectionRow(userId: string): Promise<JiraConnectionRow | null> {
  return getEnv().DB.prepare("SELECT * FROM jira_connections WHERE user_id = ?").bind(userId).first<JiraConnectionRow>();
}

function allowedProjects(row: JiraConnectionRow): string[] {
  try {
    const projects = JSON.parse(row.allowed_projects_json) as unknown;
    return Array.isArray(projects) ? projects.filter((value): value is string => typeof value === "string" && projectKeyPattern.test(value)) : [];
  } catch { return []; }
}

function summary(row: JiraConnectionRow | null): JiraConnectionSummary {
  const env = getEnv();
  if (!row) return { connected: false, configured: Boolean(env.JIRA_OAUTH_CLIENT_ID && env.JIRA_OAUTH_CLIENT_SECRET && env.JIRA_OAUTH_CALLBACK_URL && env.JIRA_OAUTH_TOKEN_ENCRYPTION_KEY) };
  return { connected: row.status === "active", configured: true, id: row.id, siteUrl: row.site_url, siteName: row.site_name, allowedProjects: allowedProjects(row), status: row.status, lastTestedAt: row.last_tested_at, updatedAt: row.updated_at };
}

export async function getJiraConnectionSummary(userId: string): Promise<JiraConnectionSummary> {
  return summary(await connectionRow(userId));
}

export async function startJiraOAuth(actor: AuthenticatedUser, siteValue: string, projectValue: unknown): Promise<string> {
  const config = oauthConfiguration();
  const siteUrl = normalizeJiraSite(siteValue);
  const projects = normalizeJiraProjects(projectValue);
  if (!siteUrl) throw new Response(JSON.stringify({ error: "Enter the root HTTPS URL for a Jira Cloud site ending in .atlassian.net." }), { status: 400, headers: { "content-type": "application/json" } });
  if (!projects) throw new Response(JSON.stringify({ error: "Enter 1–20 valid Jira project keys." }), { status: 400, headers: { "content-type": "application/json" } });
  const state = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const stateHash = await sha256(state);
  const expiresAt = new Date(Date.now() + 10 * 60_000).toISOString();
  await getEnv().DB.batch([
    getEnv().DB.prepare("DELETE FROM jira_oauth_states WHERE user_id = ? OR expires_at < ?").bind(actor.id, new Date().toISOString()),
    getEnv().DB.prepare("INSERT INTO jira_oauth_states (state_hash, user_id, requested_site_url, allowed_projects_json, expires_at) VALUES (?, ?, ?, ?, ?)").bind(stateHash, actor.id, siteUrl, stableJson(projects), expiresAt),
  ]);
  const authorize = new URL("https://auth.atlassian.com/authorize");
  authorize.search = new URLSearchParams({ audience: "api.atlassian.com", client_id: config.clientId, scope: oauthScopes.join(" "), redirect_uri: config.callbackUrl, state, response_type: "code", prompt: "consent" }).toString();
  await appendAuditEvent(actor, "jira.oauth_started", "jira_connection", actor.id, { siteUrl, allowedProjects: projects });
  return authorize.toString();
}

export async function completeJiraOAuth(actor: AuthenticatedUser, state: string, code: string): Promise<JiraConnectionSummary> {
  if (state.length < 32 || state.length > 200 || code.length < 8 || code.length > 2_000) throw new Error("The Jira authorization response is invalid.");
  const stateHash = await sha256(state);
  const pending = await getEnv().DB.prepare("SELECT state_hash, user_id, requested_site_url, allowed_projects_json, expires_at FROM jira_oauth_states WHERE state_hash = ? AND user_id = ?").bind(stateHash, actor.id).first<{ state_hash: string; user_id: string; requested_site_url: string; allowed_projects_json: string; expires_at: string }>();
  if (!pending || Date.parse(pending.expires_at) < Date.now()) throw new Error("The Jira authorization request expired or was already used.");
  await getEnv().DB.prepare("DELETE FROM jira_oauth_states WHERE state_hash = ?").bind(stateHash).run();
  const config = oauthConfiguration();
  const token = await tokenExchange({ grant_type: "authorization_code", client_id: config.clientId, client_secret: config.clientSecret, code, redirect_uri: config.callbackUrl });
  if (!token.access_token || !token.refresh_token || !Number.isFinite(token.expires_in) || Number(token.expires_in) < 60) throw new Error("Atlassian did not return the required OAuth tokens.");
  assertRequiredScopes(token.scope);
  const resources = await accessibleResources(token.access_token);
  const selected = resources.find((resource) => normalizeJiraSite(String(resource.url || "")) === pending.requested_site_url);
  if (!selected?.id || !selected.name || !selected.url) throw new Error("The approved Atlassian account cannot access the requested Jira Cloud site.");
  if (Array.isArray(selected.scopes) && requiredJiraScopes.some((scope) => !selected.scopes?.includes(scope))) throw new Error("The selected Jira Cloud site did not grant the required read and write scopes.");
  const existing = await connectionRow(actor.id);
  const id = existing?.id || randomId("jira");
  const access = await encryptSecret(token.access_token, config.tokenKey, tokenKeyName, connectionAad(id, actor.id, "access"));
  const refresh = await encryptSecret(token.refresh_token, config.tokenKey, tokenKeyName, connectionAad(id, actor.id, "refresh"));
  const expiresAt = new Date(Date.now() + Number(token.expires_in) * 1_000).toISOString();
  await getEnv().DB.prepare(`INSERT INTO jira_connections
    (id, user_id, cloud_id, site_url, site_name, allowed_projects_json, access_token_ciphertext, access_token_iv, refresh_token_ciphertext, refresh_token_iv, access_token_expires_at, scopes, status, last_tested_at, last_error, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', CURRENT_TIMESTAMP, NULL, CURRENT_TIMESTAMP)
    ON CONFLICT(user_id) DO UPDATE SET cloud_id = excluded.cloud_id, site_url = excluded.site_url, site_name = excluded.site_name,
      allowed_projects_json = excluded.allowed_projects_json, access_token_ciphertext = excluded.access_token_ciphertext, access_token_iv = excluded.access_token_iv,
      refresh_token_ciphertext = excluded.refresh_token_ciphertext, refresh_token_iv = excluded.refresh_token_iv, access_token_expires_at = excluded.access_token_expires_at,
      scopes = excluded.scopes, status = 'active', token_version = jira_connections.token_version + 1, refresh_lease_id = NULL,
      refresh_lease_expires_at = NULL, last_tested_at = CURRENT_TIMESTAMP, last_error = NULL, updated_at = CURRENT_TIMESTAMP`)
    .bind(id, actor.id, selected.id, normalizeJiraSite(selected.url), selected.name.slice(0, 160), pending.allowed_projects_json, access.ciphertext, access.iv, refresh.ciphertext, refresh.iv, expiresAt, String(token.scope || oauthScopes.join(" ")).slice(0, 1_000)).run();
  await appendAuditEvent(actor, existing ? "jira.connection_reauthorized" : "jira.connection_created", "jira_connection", id, { siteUrl: pending.requested_site_url, siteName: selected.name.slice(0, 160), allowedProjects: JSON.parse(pending.allowed_projects_json) });
  return summary(await connectionRow(actor.id));
}

async function markReauthorizationRequired(row: JiraConnectionRow, message: string): Promise<void> {
  await getEnv().DB.prepare("UPDATE jira_connections SET status = 'reauthorization_required', refresh_lease_id = NULL, refresh_lease_expires_at = NULL, last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(message.slice(0, 300), row.id).run();
}

async function accessToken(row: JiraConnectionRow): Promise<string> {
  const config = oauthConfiguration();
  const current = await connectionRow(row.user_id);
  if (!current || current.id !== row.id || current.status !== "active") throw new Response(JSON.stringify({ error: "Jira Cloud authorization must be renewed." }), { status: 409, headers: { "content-type": "application/json" } });
  if (Date.parse(current.access_token_expires_at) > Date.now() + 120_000) return decryptSecret(current.access_token_ciphertext, current.access_token_iv, config.tokenKey, tokenKeyName, connectionAad(current.id, current.user_id, "access"));
  const leaseId = randomId("jirarefresh");
  const now = new Date().toISOString();
  const leaseExpiresAt = new Date(Date.now() + 30_000).toISOString();
  const claim = await getEnv().DB.prepare(`UPDATE jira_connections SET refresh_lease_id = ?, refresh_lease_expires_at = ?, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND status = 'active' AND token_version = ? AND (refresh_lease_id IS NULL OR refresh_lease_expires_at < ?)`)
    .bind(leaseId, leaseExpiresAt, current.id, current.token_version, now).run();
  if (!changed(claim)) {
    const refreshed = await connectionRow(current.user_id);
    if (refreshed && refreshed.id === current.id && refreshed.status === "active" && Date.parse(refreshed.access_token_expires_at) > Date.now() + 120_000) {
      return decryptSecret(refreshed.access_token_ciphertext, refreshed.access_token_iv, config.tokenKey, tokenKeyName, connectionAad(refreshed.id, refreshed.user_id, "access"));
    }
    throw new Response(JSON.stringify({ error: "Jira Cloud authorization is being refreshed. Retry shortly." }), { status: 409, headers: { "content-type": "application/json", "retry-after": "2" } });
  }
  try {
    const currentRefresh = await decryptSecret(current.refresh_token_ciphertext, current.refresh_token_iv, config.tokenKey, tokenKeyName, connectionAad(current.id, current.user_id, "refresh"));
    const token = await tokenExchange({ grant_type: "refresh_token", client_id: config.clientId, client_secret: config.clientSecret, refresh_token: currentRefresh });
    if (!token.access_token || !token.refresh_token || !Number.isFinite(token.expires_in)) throw new Error("Atlassian did not rotate the OAuth tokens.");
    assertRequiredScopes(token.scope || current.scopes);
    const nextAccess = await encryptSecret(token.access_token, config.tokenKey, tokenKeyName, connectionAad(current.id, current.user_id, "access"));
    const nextRefresh = await encryptSecret(token.refresh_token, config.tokenKey, tokenKeyName, connectionAad(current.id, current.user_id, "refresh"));
    const expiresAt = new Date(Date.now() + Number(token.expires_in) * 1_000).toISOString();
    const update = await getEnv().DB.prepare(`UPDATE jira_connections SET access_token_ciphertext = ?, access_token_iv = ?, refresh_token_ciphertext = ?, refresh_token_iv = ?, access_token_expires_at = ?, scopes = ?, status = 'active', token_version = token_version + 1, refresh_lease_id = NULL, refresh_lease_expires_at = NULL, last_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND token_version = ? AND refresh_lease_id = ?`)
      .bind(nextAccess.ciphertext, nextAccess.iv, nextRefresh.ciphertext, nextRefresh.iv, expiresAt, String(token.scope || current.scopes).slice(0, 1_000), current.id, current.token_version, leaseId).run();
    if (!changed(update)) throw new Response(JSON.stringify({ error: "The Jira Cloud connection changed during token rotation. Reconnect it before retrying." }), { status: 409, headers: { "content-type": "application/json" } });
    return token.access_token;
  } catch (error) {
    if (error instanceof Response) throw error;
    if ((error instanceof OAuthTokenExchangeError && error.retryable) || error instanceof TypeError || (error instanceof DOMException && ["AbortError", "TimeoutError"].includes(error.name))) {
      await getEnv().DB.prepare("UPDATE jira_connections SET refresh_lease_id = NULL, refresh_lease_expires_at = NULL, last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND token_version = ? AND refresh_lease_id = ?")
        .bind(error.message.slice(0, 300), current.id, current.token_version, leaseId).run();
      throw new Response(JSON.stringify({ error: "Jira Cloud temporarily could not refresh authorization. Retry shortly." }), { status: 502, headers: { "content-type": "application/json", "retry-after": "5" } });
    }
    await getEnv().DB.prepare("UPDATE jira_connections SET status = 'reauthorization_required', refresh_lease_id = NULL, refresh_lease_expires_at = NULL, last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND token_version = ? AND refresh_lease_id = ?")
      .bind(error instanceof Error ? error.message.slice(0, 300) : "OAuth refresh failed", current.id, current.token_version, leaseId).run();
    throw new Response(JSON.stringify({ error: "Jira Cloud authorization expired. Reconnect it from Scopeproof Connections." }), { status: 409, headers: { "content-type": "application/json" } });
  }
}

async function jiraRequest(row: JiraConnectionRow, path: string, init: RequestInit = {}): Promise<Response> {
  const token = await accessToken(row);
  const url = new URL(`/ex/jira/${encodeURIComponent(row.cloud_id)}/rest/api/3/${path.replace(/^\/+/, "")}`, "https://api.atlassian.com");
  const headers = new Headers(init.headers);
  headers.set("authorization", `Bearer ${token}`);
  headers.set("accept", "application/json");
  return fetch(url, { ...init, headers, signal: AbortSignal.timeout(60_000) });
}

function assertAllowedIssue(row: JiraConnectionRow, rawKey: string): string {
  const key = normalizeJiraIssueKey(rawKey);
  if (!key) throw new Response(JSON.stringify({ error: "Enter a valid Jira issue key." }), { status: 400, headers: { "content-type": "application/json" } });
  const project = key.slice(0, key.lastIndexOf("-"));
  if (!allowedProjects(row).includes(project)) throw new Response(JSON.stringify({ error: `Jira project ${project} is not in this connection's allowlist.` }), { status: 403, headers: { "content-type": "application/json" } });
  return key;
}

export async function testJiraConnection(actor: AuthenticatedUser): Promise<JiraConnectionSummary> {
  const row = await connectionRow(actor.id);
  if (!row) throw new Response(JSON.stringify({ error: "Jira Cloud is not connected." }), { status: 404, headers: { "content-type": "application/json" } });
  const token = await accessToken(row);
  const resources = await accessibleResources(token);
  if (!resources.some((resource) => resource.id === row.cloud_id && normalizeJiraSite(String(resource.url || "")) === row.site_url)) {
    await markReauthorizationRequired(row, "The selected Jira site is no longer accessible.");
    throw new Response(JSON.stringify({ error: "The selected Jira Cloud site is no longer accessible. Reconnect Jira." }), { status: 409, headers: { "content-type": "application/json" } });
  }
  await getEnv().DB.prepare("UPDATE jira_connections SET status = 'active', last_tested_at = CURRENT_TIMESTAMP, last_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(row.id).run();
  await appendAuditEvent(actor, "jira.connection_tested", "jira_connection", row.id, { siteUrl: row.site_url });
  return summary(await connectionRow(actor.id));
}

export async function disconnectJira(actor: AuthenticatedUser): Promise<boolean> {
  const row = await connectionRow(actor.id);
  if (!row) return false;
  await getEnv().DB.prepare("DELETE FROM jira_connections WHERE id = ? AND user_id = ?").bind(row.id, actor.id).run();
  await appendAuditEvent(actor, "jira.connection_deleted", "jira_connection", row.id, { siteUrl: row.site_url });
  return true;
}

export async function getJiraIssueForUser(userId: string, issueValue: string): Promise<JiraIssueSummary> {
  const row = await connectionRow(userId);
  if (!row) throw new Response(JSON.stringify({ error: "Connect Jira Cloud from the Scopeproof web console first." }), { status: 409, headers: { "content-type": "application/json" } });
  const key = assertAllowedIssue(row, issueValue);
  const response = await jiraRequest(row, `issue/${encodeURIComponent(key)}?fields=summary,status,project`);
  if (response.status === 401) { await markReauthorizationRequired(row, "Atlassian rejected the access token."); throw new Response(JSON.stringify({ error: "Jira Cloud authorization must be renewed." }), { status: 409, headers: { "content-type": "application/json" } }); }
  if (response.status === 403) throw new Response(JSON.stringify({ error: `The connected Jira user cannot browse ${key}.` }), { status: 403, headers: { "content-type": "application/json" } });
  if (response.status === 404) throw new Response(JSON.stringify({ error: `Jira issue ${key} was not found or is not visible to the connected user.` }), { status: 404, headers: { "content-type": "application/json" } });
  if (!response.ok) throw new Response(JSON.stringify({ error: `Jira issue lookup failed (${response.status}).` }), { status: 502, headers: { "content-type": "application/json" } });
  const data = await responseJson<{ key?: string; fields?: { summary?: string; status?: { name?: string }; project?: { key?: string } } }>(response);
  const returnedKey = normalizeJiraIssueKey(String(data.key || ""));
  if (!returnedKey || returnedKey !== key) throw new Error("Jira returned an unexpected issue.");
  return { key, summary: String(data.fields?.summary || "Untitled issue").slice(0, 500), status: String(data.fields?.status?.name || "Unknown").slice(0, 100), projectKey: String(data.fields?.project?.key || key.split("-")[0]), url: `${row.site_url}/browse/${key}` };
}

export async function uploadJiraEvidence(actor: AuthenticatedUser, deviceId: string, evidenceId: string, issueValue: string, files: File[]): Promise<JiraUploadReceipt> {
  assertJiraOperator(actor);
  const row = await connectionRow(actor.id);
  if (!row) throw new Response(JSON.stringify({ error: "Connect Jira Cloud from the Scopeproof web console first." }), { status: 409, headers: { "content-type": "application/json" } });
  const issueKey = assertAllowedIssue(row, issueValue);
  const prior = await getEnv().DB.prepare("SELECT * FROM jira_upload_receipts WHERE connection_id = ? AND evidence_id = ? AND issue_key = ?").bind(row.id, evidenceId, issueKey).first<Record<string, unknown>>();
  if (prior) return { receiptId: String(prior.id), evidenceId, issueKey, siteUrl: String(prior.site_url), uploadedAt: String(prior.uploaded_at), attachments: JSON.parse(String(prior.attachments_json)) as JiraAttachmentReceipt[], receiptSha256: String(prior.receipt_sha256), signature: String(prior.signature) };
  await getJiraIssueForUser(actor.id, issueKey);
  // Issue lookup may refresh and rotate the OAuth tokens. Use the updated row for
  // the attachment call so a just-rotated refresh token is never reused.
  const uploadRow = await connectionRow(actor.id);
  if (!uploadRow || uploadRow.id !== row.id) throw new Response(JSON.stringify({ error: "The Jira Cloud connection changed during upload. Try again." }), { status: 409, headers: { "content-type": "application/json" } });
  const fileBindings = await Promise.all(files.map(async (file) => ({ name: file.name, type: file.type, size: file.size, sha256: await sha256(new Uint8Array(await file.arrayBuffer())) })));
  const requestSha256 = await sha256(stableJson({ version: 1, connectionId: row.id, evidenceId, issueKey, files: fileBindings }));
  const operationId = `jiraupl_${(await sha256(stableJson({ connectionId: row.id, evidenceId, issueKey }))).slice(0, 40)}`;
  await getEnv().DB.prepare(`INSERT OR IGNORE INTO jira_upload_operations
    (id, connection_id, user_id, device_id, evidence_id, issue_key, request_sha256) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .bind(operationId, row.id, actor.id, deviceId, evidenceId, issueKey, requestSha256).run();
  const operation = await getEnv().DB.prepare("SELECT id, request_sha256, status, lease_id, lease_expires_at, receipt_id FROM jira_upload_operations WHERE id = ?")
    .bind(operationId).first<JiraUploadOperation>();
  if (!operation || operation.request_sha256 !== requestSha256) throw new Response(JSON.stringify({ error: "A different attachment set is already bound to this evidence and Jira issue." }), { status: 409, headers: { "content-type": "application/json" } });
  if (operation.status === "succeeded" && operation.receipt_id) {
    const receipt = await getEnv().DB.prepare("SELECT * FROM jira_upload_receipts WHERE id = ?").bind(operation.receipt_id).first<Record<string, unknown>>();
    if (!receipt) throw new Error("The completed Jira upload is missing its immutable receipt.");
    return { receiptId: String(receipt.id), evidenceId, issueKey, siteUrl: String(receipt.site_url), uploadedAt: String(receipt.uploaded_at), attachments: JSON.parse(String(receipt.attachments_json)) as JiraAttachmentReceipt[], receiptSha256: String(receipt.receipt_sha256), signature: String(receipt.signature) };
  }
  if (operation.status === "unknown") throw new Response(JSON.stringify({ error: "The prior Jira upload outcome is unknown. Reconcile the issue attachments before an operator retries." }), { status: 409, headers: { "content-type": "application/json" } });
  if (operation.status === "uploading" && operation.lease_expires_at && Date.parse(operation.lease_expires_at) <= Date.now()) {
    await getEnv().DB.prepare("UPDATE jira_upload_operations SET status = 'unknown', lease_id = NULL, lease_expires_at = NULL, last_error = 'Upload lease expired before a receipt was committed.', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND status = 'uploading' AND lease_expires_at <= ?")
      .bind(operationId, new Date().toISOString()).run();
    throw new Response(JSON.stringify({ error: "The prior Jira upload outcome is unknown. Reconcile the issue attachments before an operator retries." }), { status: 409, headers: { "content-type": "application/json" } });
  }
  const leaseId = randomId("jirauploadlease");
  const leaseExpiresAt = new Date(Date.now() + 120_000).toISOString();
  const claim = await getEnv().DB.prepare(`UPDATE jira_upload_operations SET status = 'uploading', lease_id = ?, lease_expires_at = ?, attempt = attempt + 1, last_error = NULL, updated_at = CURRENT_TIMESTAMP
    WHERE id = ? AND request_sha256 = ? AND status IN ('reserved', 'failed')`)
    .bind(leaseId, leaseExpiresAt, operationId, requestSha256).run();
  if (!changed(claim)) throw new Response(JSON.stringify({ error: "This Jira upload is already in progress. Retry shortly." }), { status: 409, headers: { "content-type": "application/json", "retry-after": "3" } });
  const form = new FormData();
  for (const file of files) form.append("file", file, file.name);
  let response: Response;
  try {
    response = await jiraRequest(uploadRow, `issue/${encodeURIComponent(issueKey)}/attachments`, { method: "POST", headers: { "X-Atlassian-Token": "no-check" }, body: form });
  } catch (error) {
    const uncertain = !(error instanceof Response);
    await getEnv().DB.prepare("UPDATE jira_upload_operations SET status = ?, lease_id = NULL, lease_expires_at = NULL, last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND lease_id = ?")
      .bind(uncertain ? "unknown" : "failed", uncertain ? "Jira request ended without an authoritative response." : "Jira request was rejected before attachment upload.", operationId, leaseId).run();
    throw error;
  }
  if (response.status === 401) {
    await getEnv().DB.prepare("UPDATE jira_upload_operations SET status = 'failed', lease_id = NULL, lease_expires_at = NULL, last_error = 'Atlassian rejected the access token.', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND lease_id = ?").bind(operationId, leaseId).run();
    await markReauthorizationRequired(uploadRow, "Atlassian rejected the access token during upload.");
    throw new Response(JSON.stringify({ error: "Jira Cloud authorization must be renewed." }), { status: 409, headers: { "content-type": "application/json" } });
  }
  if (!response.ok) {
    const uncertain = response.status === 408 || response.status === 429 || response.status >= 500;
    await getEnv().DB.prepare("UPDATE jira_upload_operations SET status = ?, lease_id = NULL, lease_expires_at = NULL, last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND lease_id = ?")
      .bind(uncertain ? "unknown" : "failed", `Jira attachment endpoint returned HTTP ${response.status}.`, operationId, leaseId).run();
    if (response.status === 403) throw new Response(JSON.stringify({ error: `The connected Jira user cannot add attachments to ${issueKey}.` }), { status: 403, headers: { "content-type": "application/json" } });
    throw new Response(JSON.stringify({ error: uncertain ? "Jira may have accepted the attachment set, but no authoritative receipt was returned. Reconcile before retrying." : `Jira attachment upload failed (${response.status}).` }), { status: uncertain ? 409 : 502, headers: { "content-type": "application/json" } });
  }
  let uploaded: Array<{ id?: string; filename?: string; size?: number; mimeType?: string }>;
  try { uploaded = await responseJson<Array<{ id?: string; filename?: string; size?: number; mimeType?: string }>>(response); }
  catch (error) {
    await getEnv().DB.prepare("UPDATE jira_upload_operations SET status = 'unknown', lease_id = NULL, lease_expires_at = NULL, last_error = 'Jira returned an invalid attachment receipt.', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND lease_id = ?").bind(operationId, leaseId).run();
    throw error;
  }
  const attachments = uploaded.map((item) => ({ id: String(item.id || ""), filename: String(item.filename || "").slice(0, 255), size: Number(item.size || 0), mimeType: String(item.mimeType || "application/octet-stream").slice(0, 100) }));
  if (uploaded.length !== files.length || attachments.some((item) => !item.id || !item.filename || !Number.isFinite(item.size))) {
    await getEnv().DB.prepare("UPDATE jira_upload_operations SET status = 'unknown', lease_id = NULL, lease_expires_at = NULL, last_error = 'Jira returned incomplete attachment metadata.', updated_at = CURRENT_TIMESTAMP WHERE id = ? AND lease_id = ?").bind(operationId, leaseId).run();
    throw new Error("Jira returned an incomplete attachment receipt.");
  }
  const receiptId = randomId("jirarcpt");
  const uploadedAt = new Date().toISOString();
  const unsigned = { version: 1, receiptId, connectionId: row.id, userId: actor.id, deviceId, evidenceId, issueKey, siteUrl: row.site_url, uploadedAt, attachments };
  const receiptSha256 = await sha256(stableJson(unsigned));
  const signature = await hmac(receiptSha256);
  const committed = await getEnv().DB.batch([
    getEnv().DB.prepare("INSERT INTO jira_upload_receipts (id, connection_id, user_id, device_id, evidence_id, issue_key, site_url, uploaded_at, attachments_json, receipt_sha256, signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(receiptId, row.id, actor.id, deviceId, evidenceId, issueKey, row.site_url, uploadedAt, stableJson(attachments), receiptSha256, signature),
    getEnv().DB.prepare("UPDATE jira_upload_operations SET status = 'succeeded', receipt_id = ?, lease_id = NULL, lease_expires_at = NULL, last_error = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND lease_id = ? AND status = 'uploading'")
      .bind(receiptId, operationId, leaseId),
  ]);
  if (committed.length !== 2 || !changed(committed[1])) throw new Error("The Jira upload receipt could not be committed atomically.");
  await appendAuditEvent(actor, "jira.evidence_uploaded", "jira_upload_receipt", receiptId, { connectionId: row.id, deviceId, evidenceId, issueKey, siteUrl: row.site_url, attachmentIds: attachments.map((item) => item.id), receiptSha256 });
  return { receiptId, evidenceId, issueKey, siteUrl: row.site_url, uploadedAt, attachments, receiptSha256, signature };
}
