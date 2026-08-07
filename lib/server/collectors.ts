import type { AuthenticatedUser } from "./auth";
import { sha256 } from "./crypto";
import { getEnv, type ScopeproofEnv } from "./env";
import type { EvidenceInput } from "./evidence";
import { redactText } from "./redaction";

export type CollectorProvider = "aws" | "github" | "okta" | "cloudflare" | "browser";
export class CollectorError extends Error {
  constructor(message: string, public readonly code: string, public readonly retryable: boolean, public readonly status?: number) { super(message); }
}

type Artifact = Omit<EvidenceInput, "createdBy" | "collectorId" | "jobId">;
type CollectorContext = { actor: AuthenticatedUser; config: Record<string, unknown> };

function configured(value: string | undefined, name: string): string {
  if (!value) throw new CollectorError(`${name} is not configured.`, "NOT_CONFIGURED", false);
  return value;
}

async function providerFetch(url: string, init: RequestInit, label: string): Promise<Response> {
  const response = await fetch(url, init);
  if (response.ok) return response;
  const text = (await response.text()).slice(0, 500);
  const retryable = response.status === 429 || response.status >= 500;
  throw new CollectorError(`${label} returned ${response.status}: ${text}`, response.status === 401 || response.status === 403 ? "AUTH_FAILED" : "PROVIDER_ERROR", retryable, response.status);
}

async function githubCollector(env: ScopeproofEnv): Promise<Artifact[]> {
  const token = configured(env.GITHUB_TOKEN, "GITHUB_TOKEN");
  const org = configured(env.GITHUB_ORG, "GITHUB_ORG");
  const headers = { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "Scopeproof-PCI-Evidence" };
  const reposResponse = await providerFetch(`https://api.github.com/orgs/${encodeURIComponent(org)}/repos?per_page=100&type=all&sort=full_name`, { headers }, "GitHub repository inventory");
  const repos = await reposResponse.json() as Array<{ name: string; full_name: string; private: boolean; archived: boolean; default_branch: string; visibility: string; security_and_analysis?: unknown }>;
  const protection = await Promise.all(repos.filter((repo) => !repo.archived).slice(0, 25).map(async (repo) => {
    const response = await fetch(`https://api.github.com/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo.name)}/branches/${encodeURIComponent(repo.default_branch)}/protection`, { headers });
    if (response.status === 404) return { repository: repo.full_name, defaultBranch: repo.default_branch, protected: false };
    if (!response.ok) return { repository: repo.full_name, defaultBranch: repo.default_branch, protected: null, collectionError: response.status };
    const data = await response.json() as Record<string, unknown>;
    return { repository: repo.full_name, defaultBranch: repo.default_branch, protected: true, requiredStatusChecks: data.required_status_checks, requiredReviews: data.required_pull_request_reviews, enforceAdmins: data.enforce_admins };
  }));
  const body = new TextEncoder().encode(JSON.stringify({ organization: org, collectedAt: new Date().toISOString(), repositoryCount: repos.length, repositories: repos.map(({ security_and_analysis, ...repo }) => ({ ...repo, security_and_analysis })), defaultBranchProtection: protection }, null, 2));
  return [{ controlId: "6.3.2", title: `GitHub software inventory and branch protection — ${org}`, description: "Live organization repository inventory and default branch protection configuration.", type: "configuration", source: "GitHub", system: org, contentType: "application/json", bytes: body }];
}

async function oktaCollector(env: ScopeproofEnv): Promise<Artifact[]> {
  const base = configured(env.OKTA_BASE_URL, "OKTA_BASE_URL").replace(/\/$/, "");
  const token = configured(env.OKTA_API_TOKEN, "OKTA_API_TOKEN");
  const headers = { authorization: `SSWS ${token}`, accept: "application/json" };
  const [policiesResponse, groupsResponse] = await Promise.all([
    providerFetch(`${base}/api/v1/policies?type=OKTA_SIGN_ON`, { headers }, "Okta sign-on policies"),
    providerFetch(`${base}/api/v1/groups?limit=200`, { headers }, "Okta groups"),
  ]);
  const [policies, groups] = await Promise.all([policiesResponse.json(), groupsResponse.json()]);
  return [
    { controlId: "8.3.6", title: "Okta global session and MFA policies", description: "Live sign-on policies used to verify authentication factor enforcement.", type: "configuration", source: "Okta", system: new URL(base).hostname, contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify(policies, null, 2)) },
    { controlId: "7.2.5", title: "Okta group inventory for access review", description: "Current identity groups and membership metadata for periodic access review.", type: "report", source: "Okta", system: new URL(base).hostname, contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify(groups, null, 2)) },
  ];
}

async function cloudflareCollector(env: ScopeproofEnv): Promise<Artifact[]> {
  const token = configured(env.CLOUDFLARE_API_TOKEN, "CLOUDFLARE_API_TOKEN");
  const accountId = configured(env.CLOUDFLARE_ACCOUNT_ID, "CLOUDFLARE_ACCOUNT_ID");
  const headers = { authorization: `Bearer ${token}`, accept: "application/json" };
  let zoneIds = (env.CLOUDFLARE_ZONE_IDS || "").split(",").map((item) => item.trim()).filter(Boolean);
  if (!zoneIds.length) {
    const zonesResponse = await providerFetch(`https://api.cloudflare.com/client/v4/zones?account.id=${encodeURIComponent(accountId)}&per_page=50`, { headers }, "Cloudflare zones");
    const zones = await zonesResponse.json() as { result?: Array<{ id: string }> };
    zoneIds = (zones.result || []).map((zone) => zone.id);
  }
  const rulesets = await Promise.all(zoneIds.slice(0, 20).map(async (zoneId) => {
    const response = await providerFetch(`https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zoneId)}/rulesets/phases/http_request_firewall_managed/entrypoint`, { headers }, `Cloudflare managed rules for ${zoneId}`);
    return { zoneId, result: await response.json() };
  }));
  return [{ controlId: "1.2.5", title: "Cloudflare WAF managed rulesets", description: "Live managed firewall ruleset configuration for scoped production zones.", type: "configuration", source: "Cloudflare", system: `${zoneIds.length} zones`, contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify({ accountId, collectedAt: new Date().toISOString(), rulesets }, null, 2)) }];
}

async function hmacBytes(key: Uint8Array, data: string): Promise<Uint8Array> {
  const raw = key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength) as ArrayBuffer;
  const imported = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, new TextEncoder().encode(data)));
}

function hex(bytes: Uint8Array): string { return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join(""); }

async function awsSignedPost(env: ScopeproofEnv, service: string, body: string, headers: Record<string, string>): Promise<Response> {
  const accessKey = configured(env.AWS_ACCESS_KEY_ID, "AWS_ACCESS_KEY_ID");
  const secret = configured(env.AWS_SECRET_ACCESS_KEY, "AWS_SECRET_ACCESS_KEY");
  const region = env.AWS_REGION || "us-east-1";
  const host = `${service}.${region}.amazonaws.com`;
  const date = new Date();
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = await sha256(body);
  const signedHeaderMap: Record<string, string> = { ...headers, host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash };
  if (env.AWS_SESSION_TOKEN) signedHeaderMap["x-amz-security-token"] = env.AWS_SESSION_TOKEN;
  const headerNames = Object.keys(signedHeaderMap).map((key) => key.toLowerCase()).sort();
  const canonicalHeaders = headerNames.map((name) => `${name}:${signedHeaderMap[name].trim()}\n`).join("");
  const signedHeaders = headerNames.join(";");
  const canonicalRequest = `POST\n/\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;
  const scope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${await sha256(canonicalRequest)}`;
  const kDate = await hmacBytes(new TextEncoder().encode(`AWS4${secret}`), dateStamp);
  const kRegion = await hmacBytes(kDate, region);
  const kService = await hmacBytes(kRegion, service);
  const kSigning = await hmacBytes(kService, "aws4_request");
  const signature = hex(await hmacBytes(kSigning, stringToSign));
  const authorization = `AWS4-HMAC-SHA256 Credential=${accessKey}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
  return providerFetch(`https://${host}/`, { method: "POST", headers: { ...signedHeaderMap, authorization }, body }, `AWS ${service}`);
}

async function awsCollector(env: ScopeproofEnv): Promise<Artifact[]> {
  const configHeaders = { "content-type": "application/x-amz-json-1.1", "x-amz-target": "StarlingDoveService.DescribeConfigurationRecorders" };
  const configResponse = await awsSignedPost(env, "config", "{}", configHeaders);
  const configData = await configResponse.json();
  const ec2Body = "Action=DescribeSecurityGroups&Version=2016-11-15";
  const ec2Response = await awsSignedPost(env, "ec2", ec2Body, { "content-type": "application/x-www-form-urlencoded; charset=utf-8" });
  const securityGroupsXml = await ec2Response.text();
  return [
    { controlId: "2.2.1", title: "AWS Config recorder configuration", description: "Live AWS Config recorder settings demonstrating configuration monitoring coverage.", type: "configuration", source: "AWS", system: env.AWS_REGION || "us-east-1", contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify(configData, null, 2)) },
    { controlId: "1.2.5", title: "AWS EC2 security group inventory", description: "Live security group configuration for review of network security controls.", type: "configuration", source: "AWS", system: env.AWS_REGION || "us-east-1", contentType: "application/xml", bytes: new TextEncoder().encode(securityGroupsXml) },
  ];
}

async function browserCollector(env: ScopeproofEnv): Promise<Artifact[]> {
  const token = configured(env.CLOUDFLARE_API_TOKEN, "CLOUDFLARE_API_TOKEN");
  const accountId = configured(env.CLOUDFLARE_ACCOUNT_ID, "CLOUDFLARE_ACCOUNT_ID");
  const urls = configured(env.BROWSER_CAPTURE_URLS, "BROWSER_CAPTURE_URLS").split(",").map((item) => item.trim()).filter(Boolean);
  const artifacts: Artifact[] = [];
  for (const target of urls.slice(0, 10)) {
    const url = new URL(target);
    if (url.protocol !== "https:") throw new CollectorError(`Browser capture only permits HTTPS targets: ${target}`, "UNSAFE_TARGET", false);
    const endpoint = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/browser-rendering`;
    const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };
    const body = JSON.stringify({ url: target, gotoOptions: { waitUntil: "networkidle0", timeout: 30000 } });
    const contentResponse = await providerFetch(`${endpoint}/content`, { method: "POST", headers, body }, `Browser content preflight for ${url.hostname}`);
    const content = await contentResponse.text();
    const scan = redactText(content);
    if (scan.total > 0) throw new CollectorError(`Screenshot blocked: ${scan.total} sensitive value(s) detected in rendered content for ${url.hostname}.`, "SENSITIVE_CONTENT_BLOCKED", false);
    const screenshotResponse = await providerFetch(`${endpoint}/screenshot`, { method: "POST", headers, body: JSON.stringify({ url: target, gotoOptions: { waitUntil: "networkidle0", timeout: 30000 }, screenshotOptions: { type: "png", fullPage: true } }) }, `Browser screenshot for ${url.hostname}`);
    const image = new Uint8Array(await screenshotResponse.arrayBuffer());
    artifacts.push({ controlId: "2.2.1", title: `Authenticated configuration capture — ${url.hostname}`, description: `Browser-rendered evidence captured from ${url.pathname}. DOM content passed PAN and secret preflight scanning before screenshot persistence.`, type: "screenshot", source: "Browser capture", system: url.hostname, contentType: "image/png", bytes: image, preflightFindings: scan.findings });
  }
  return artifacts;
}

export async function runCollector(provider: CollectorProvider, context: CollectorContext): Promise<Artifact[]> {
  void context.config;
  const env = getEnv();
  switch (provider) {
    case "aws": return awsCollector(env);
    case "github": return githubCollector(env);
    case "okta": return oktaCollector(env);
    case "cloudflare": return cloudflareCollector(env);
    case "browser": return browserCollector(env);
  }
}

export function collectorConfiguration(provider: CollectorProvider): { configured: boolean; missing: string[] } {
  const env = getEnv();
  const required: Record<CollectorProvider, Array<keyof ScopeproofEnv>> = {
    aws: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"], github: ["GITHUB_TOKEN", "GITHUB_ORG"], okta: ["OKTA_BASE_URL", "OKTA_API_TOKEN"],
    cloudflare: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"], browser: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "BROWSER_CAPTURE_URLS"],
  };
  const missing = required[provider].filter((key) => !env[key]).map(String);
  return { configured: missing.length === 0, missing };
}
