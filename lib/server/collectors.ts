import type { AuthenticatedUser } from "./auth";
import { sha256 } from "./crypto";
import { getEnv, type ScopeproofEnv } from "./env";
import type { EvidenceInput } from "./evidence";
import { validatePng } from "./native-manifest";
import { redactText } from "./redaction";
import { decodeXmlText } from "./xml";

export type CollectorProvider = "aws" | "github" | "okta" | "cloudflare" | "browser";
export class CollectorError extends Error {
  constructor(message: string, public readonly code: string, public readonly retryable: boolean, public readonly status?: number) { super(message); }
}

type Artifact = Omit<EvidenceInput, "createdBy" | "collectorId" | "jobId">;
type CollectorContext = { actor: AuthenticatedUser; config: Record<string, unknown> };

export type CollectorCoverage = { provider: CollectorProvider; complete: boolean; requestedScope: string; returnedCount: number; providerTotal?: number; pageCount: number; omissions: string[]; apiVersion: string; collectedAt: string };
export type CollectorResult = { artifacts: Artifact[]; coverage: CollectorCoverage };

const MAX_PROVIDER_PAGES = 20;
const MAX_SCOPED_RESOURCES = 250;

function nextLink(response: Response): string | null {
  const link = response.headers.get("link") || "";
  for (const item of link.split(",")) {
    const match = item.match(/<([^>]+)>;\s*rel="next"/);
    if (match) return match[1];
  }
  return null;
}

async function collectLinkedJson<T>(url: string, init: RequestInit, label: string, itemLimit = MAX_SCOPED_RESOURCES): Promise<{ items: T[]; pages: number; complete: boolean; next: string | null }> {
  const items: T[] = [];
  let next: string | null = url;
  let pages = 0;
  while (next && pages < MAX_PROVIDER_PAGES && items.length < itemLimit) {
    const response = await providerFetch(next, init, `${label} page ${pages + 1}`);
    const page = await response.json() as T[];
    if (!Array.isArray(page)) throw new CollectorError(`${label} returned an invalid collection.`, "PROVIDER_INVALID_RESPONSE", false);
    items.push(...page.slice(0, itemLimit - items.length));
    next = nextLink(response);
    pages += 1;
  }
  return { items, pages, complete: !next, next };
}

function coverage(provider: CollectorProvider, requestedScope: string, returnedCount: number, pageCount: number, complete: boolean, omissions: string[] = [], providerTotal?: number, apiVersion = "provider-current"): CollectorCoverage {
  return { provider, complete: complete && omissions.length === 0 && (providerTotal === undefined || returnedCount >= providerTotal), requestedScope, returnedCount, providerTotal, pageCount, omissions, apiVersion, collectedAt: new Date().toISOString() };
}

function configured(value: string | undefined, name: string): string {
  if (!value) throw new CollectorError(`${name} is not configured.`, "NOT_CONFIGURED", false);
  return value;
}

async function providerFetch(url: string, init: RequestInit, label: string, maximumBytes = 5 * 1024 * 1024, allowedStatuses: number[] = []): Promise<Response> {
  const response = await fetch(url, { ...init, redirect: "error", signal: AbortSignal.timeout(60_000) });
  const declaredLength = Number(response.headers.get("content-length") || 0);
  if (declaredLength > maximumBytes) throw new CollectorError(`${label} response exceeds the ${maximumBytes}-byte limit.`, "PROVIDER_RESPONSE_TOO_LARGE", false);
  const reader = response.body?.getReader();
  const chunks: Uint8Array[] = [];
  let received = 0;
  if (reader) {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maximumBytes) {
        await reader.cancel("response size limit exceeded");
        throw new CollectorError(`${label} response exceeds the ${maximumBytes}-byte limit.`, "PROVIDER_RESPONSE_TOO_LARGE", false);
      }
      chunks.push(value);
    }
  }
  const bytes = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const bounded = new Response(bytes, { status: response.status, statusText: response.statusText, headers: response.headers });
  if (bounded.ok || allowedStatuses.includes(bounded.status)) return bounded;
  const text = new TextDecoder().decode(bytes).slice(0, 500);
  const retryable = bounded.status === 429 || bounded.status >= 500;
  throw new CollectorError(`${label} returned ${bounded.status}: ${text}`, bounded.status === 401 || bounded.status === 403 ? "AUTH_FAILED" : "PROVIDER_ERROR", retryable, bounded.status);
}

function approvedOcrEndpoint(env: ScopeproofEnv): URL {
  const endpoint = new URL(configured(env.BROWSER_OCR_ENDPOINT, "BROWSER_OCR_ENDPOINT"));
  const allowedHosts = new Set(configured(env.BROWSER_OCR_ALLOWED_HOSTS, "BROWSER_OCR_ALLOWED_HOSTS").split(",").map((host) => host.trim().toLowerCase()).filter(Boolean));
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.hash || !allowedHosts.has(endpoint.hostname.toLowerCase())) {
    throw new CollectorError("Browser OCR endpoint must be HTTPS and use an explicitly approved host.", "UNSAFE_OCR_ENDPOINT", false);
  }
  return endpoint;
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += 32_768) binary += String.fromCharCode(...bytes.subarray(offset, offset + 32_768));
  return btoa(binary);
}

async function scanExactBrowserPixels(env: ScopeproofEnv, image: Uint8Array): Promise<{ digest: string; policy: string; completedAt: string }> {
  if (image.byteLength > 15 * 1024 * 1024) throw new CollectorError("Browser screenshot exceeds the safety scanner limit.", "SCREENSHOT_TOO_LARGE", false);
  await validatePng(image);
  const digest = await sha256(image);
  const endpoint = approvedOcrEndpoint(env);
  const response = await providerFetch(endpoint.toString(), {
    method: "POST",
    headers: { authorization: `Bearer ${configured(env.BROWSER_OCR_TOKEN, "BROWSER_OCR_TOKEN")}`, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ version: 1, sha256: digest, contentType: "image/png", imageBase64: base64(image) }),
  }, "Browser exact-pixel OCR scan", 2 * 1024 * 1024);
  const declaredLength = Number(response.headers.get("content-length") || 0);
  if (declaredLength > 2 * 1024 * 1024) throw new CollectorError("Browser OCR response exceeds the scanner limit.", "OCR_RESPONSE_TOO_LARGE", false);
  const responseText = await response.text();
  if (responseText.length > 2 * 1024 * 1024) throw new CollectorError("Browser OCR response exceeds the scanner limit.", "OCR_RESPONSE_TOO_LARGE", false);
  let payload: unknown;
  try { payload = JSON.parse(responseText); } catch { throw new CollectorError("Browser OCR service returned invalid JSON.", "OCR_INVALID_RESPONSE", false); }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) throw new CollectorError("Browser OCR service returned an invalid result.", "OCR_INVALID_RESPONSE", false);
  const result = payload as Record<string, unknown>;
  if (Object.keys(result).some((key) => !["sha256", "text", "policyVersion"].includes(key)) || result.sha256 !== digest || typeof result.text !== "string" || result.text.length > 1_500_000 || typeof result.policyVersion !== "string" || !/^[A-Za-z0-9._-]{1,100}$/.test(result.policyVersion)) {
    throw new CollectorError("Browser OCR result is not bound to the captured screenshot.", "OCR_DIGEST_MISMATCH", false);
  }
  const scan = redactText(result.text);
  if (scan.total > 0) throw new CollectorError(`Screenshot blocked: ${scan.total} sensitive value(s) detected in the captured pixels.`, "SENSITIVE_CONTENT_BLOCKED", false);
  return { digest, policy: result.policyVersion, completedAt: new Date().toISOString() };
}

async function githubCollector(env: ScopeproofEnv): Promise<CollectorResult> {
  const token = configured(env.GITHUB_TOKEN, "GITHUB_TOKEN");
  const org = configured(env.GITHUB_ORG, "GITHUB_ORG");
  const headers = { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "Scopeproof-PCI-Evidence" };
  type Repo = { name: string; full_name: string; private: boolean; archived: boolean; default_branch: string; visibility: string; security_and_analysis?: unknown };
  const listing = await collectLinkedJson<Repo>(`https://api.github.com/orgs/${encodeURIComponent(org)}/repos?per_page=100&type=all&sort=full_name`, { headers }, "GitHub repository inventory");
  const repos = listing.items;
  const active = repos.filter((repo) => !repo.archived);
  const omissions: string[] = listing.complete ? [] : [`Repository pagination exceeded ${MAX_PROVIDER_PAGES} pages or ${MAX_SCOPED_RESOURCES} repositories.`];
  const protection: Array<Record<string, unknown>> = [];
  for (let offset = 0; offset < active.length; offset += 10) {
    protection.push(...await Promise.all(active.slice(offset, offset + 10).map(async (repo) => {
      const response = await providerFetch(`https://api.github.com/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo.name)}/branches/${encodeURIComponent(repo.default_branch)}/protection`, { headers }, `GitHub branch protection for ${repo.full_name}`, 2 * 1024 * 1024, [404]);
      if (response.status === 404) return { repository: repo.full_name, defaultBranch: repo.default_branch, protected: false };
      const data = await response.json() as Record<string, unknown>;
      return { repository: repo.full_name, defaultBranch: repo.default_branch, protected: true, requiredStatusChecks: data.required_status_checks, requiredReviews: data.required_pull_request_reviews, enforceAdmins: data.enforce_admins };
    })));
  }
  const resultCoverage = coverage("github", `organization:${org}`, repos.length, listing.pages, listing.complete, omissions, undefined, "2022-11-28");
  const body = new TextEncoder().encode(JSON.stringify({ organization: org, collectedAt: resultCoverage.collectedAt, coverage: resultCoverage, repositoryCount: repos.length, repositories: repos, defaultBranchProtection: protection }, null, 2));
  return { coverage: resultCoverage, artifacts: [{ controlId: "6.3.2", title: `GitHub software inventory and branch protection — ${org}`, description: "Live organization repository inventory and default branch protection configuration.", type: "configuration", source: "GitHub", system: org, contentType: "application/json", bytes: body }] };
}

async function oktaCollector(env: ScopeproofEnv): Promise<CollectorResult> {
  const base = configured(env.OKTA_BASE_URL, "OKTA_BASE_URL").replace(/\/$/, "");
  const token = configured(env.OKTA_API_TOKEN, "OKTA_API_TOKEN");
  const headers = { authorization: `SSWS ${token}`, accept: "application/json" };
  const [policyListing, groupListing] = await Promise.all([
    collectLinkedJson<Record<string, unknown>>(`${base}/api/v1/policies?type=OKTA_SIGN_ON&limit=200`, { headers }, "Okta sign-on policies"),
    collectLinkedJson<Record<string, unknown>>(`${base}/api/v1/groups?limit=200`, { headers }, "Okta groups"),
  ]);
  const policies = policyListing.items;
  const groups = groupListing.items;
  const omissions = [...(!policyListing.complete ? ["Sign-on policy pagination exceeded the safety budget."] : []), ...(!groupListing.complete ? ["Group pagination exceeded the safety budget."] : [])];
  const resultCoverage = coverage("okta", `tenant:${new URL(base).hostname}`, policies.length + groups.length, policyListing.pages + groupListing.pages, policyListing.complete && groupListing.complete, omissions, undefined, "okta-v1");
  return { coverage: resultCoverage, artifacts: [
    { controlId: "8.3.6", title: "Okta global session and MFA policies", description: "Live sign-on policies used to verify authentication factor enforcement.", type: "configuration", source: "Okta", system: new URL(base).hostname, contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify(policies, null, 2)) },
    { controlId: "7.2.5", title: "Okta group inventory for access review", description: "Current identity groups and membership metadata for periodic access review.", type: "report", source: "Okta", system: new URL(base).hostname, contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify(groups, null, 2)) },
  ] };
}

async function cloudflareCollector(env: ScopeproofEnv): Promise<CollectorResult> {
  const token = configured(env.CLOUDFLARE_API_TOKEN, "CLOUDFLARE_API_TOKEN");
  const accountId = configured(env.CLOUDFLARE_ACCOUNT_ID, "CLOUDFLARE_ACCOUNT_ID");
  const headers = { authorization: `Bearer ${token}`, accept: "application/json" };
  const zoneIds = (env.CLOUDFLARE_ZONE_IDS || "").split(",").map((item) => item.trim()).filter(Boolean);
  let pages = 0;
  let providerTotal: number | undefined;
  const omissions: string[] = [];
  if (!zoneIds.length) {
    for (let page = 1; page <= MAX_PROVIDER_PAGES && zoneIds.length < MAX_SCOPED_RESOURCES; page += 1) {
      const zonesResponse = await providerFetch(`https://api.cloudflare.com/client/v4/zones?account.id=${encodeURIComponent(accountId)}&per_page=50&page=${page}`, { headers }, `Cloudflare zones page ${page}`);
      const zones = await zonesResponse.json() as { result?: Array<{ id: string }>; result_info?: { total_count?: number; total_pages?: number } };
      zoneIds.push(...(zones.result || []).map((zone) => zone.id).slice(0, MAX_SCOPED_RESOURCES - zoneIds.length));
      providerTotal = Number(zones.result_info?.total_count || zoneIds.length);
      pages = page;
      if (page >= Number(zones.result_info?.total_pages || 1)) break;
    }
    if ((providerTotal || 0) > zoneIds.length) omissions.push(`Only ${zoneIds.length} of ${providerTotal} zones fit the collection safety budget.`);
  }
  const scopedZoneIds = zoneIds.slice(0, MAX_SCOPED_RESOURCES);
  if (zoneIds.length > scopedZoneIds.length) omissions.push(`Only ${scopedZoneIds.length} explicitly configured zones fit the collection safety budget.`);
  const rulesets: Array<Record<string, unknown>> = [];
  for (let offset = 0; offset < scopedZoneIds.length; offset += 10) {
    rulesets.push(...await Promise.all(scopedZoneIds.slice(offset, offset + 10).map(async (zoneId) => {
      const response = await providerFetch(`https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zoneId)}/rulesets/phases/http_request_firewall_managed/entrypoint`, { headers }, `Cloudflare managed rules for ${zoneId}`);
      return { zoneId, result: await response.json() };
    })));
  }
  const resultCoverage = coverage("cloudflare", `account:${accountId}`, rulesets.length, Math.max(1, pages), omissions.length === 0, omissions, providerTotal || zoneIds.length, "cloudflare-v4");
  return { coverage: resultCoverage, artifacts: [{ controlId: "1.2.5", title: "Cloudflare WAF managed rulesets", description: "Live managed firewall ruleset configuration for scoped production zones.", type: "configuration", source: "Cloudflare", system: `${zoneIds.length} zones`, contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify({ accountId, collectedAt: resultCoverage.collectedAt, coverage: resultCoverage, rulesets }, null, 2)) }] };
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

async function awsCollector(env: ScopeproofEnv): Promise<CollectorResult> {
  const configHeaders = { "content-type": "application/x-amz-json-1.1", "x-amz-target": "StarlingDoveService.DescribeConfigurationRecorders" };
  const configResponse = await awsSignedPost(env, "config", "{}", configHeaders);
  const configData = await configResponse.json();
  const securityGroupPages: string[] = [];
  let token: string | null = null;
  let complete = true;
  do {
    const ec2Body: string = `Action=DescribeSecurityGroups&Version=2016-11-15${token ? `&NextToken=${encodeURIComponent(token)}` : ""}`;
    const ec2Response: Response = await awsSignedPost(env, "ec2", ec2Body, { "content-type": "application/x-www-form-urlencoded; charset=utf-8" });
    const xml: string = await ec2Response.text();
    securityGroupPages.push(xml);
    const match: RegExpMatchArray | null = xml.match(/<nextToken>([^<]+)<\/nextToken>/i);
    token = match ? decodeXmlText(match[1]) : null;
    if (token && securityGroupPages.length >= MAX_PROVIDER_PAGES) { complete = false; break; }
  } while (token);
  const omissions = complete ? [] : [`EC2 security-group pagination exceeded ${MAX_PROVIDER_PAGES} pages.`];
  const resultCoverage = coverage("aws", `account-credential:${env.AWS_REGION || "us-east-1"}`, securityGroupPages.length, securityGroupPages.length + 1, complete, omissions, undefined, "Config 2014-11-12 / EC2 2016-11-15");
  return { coverage: resultCoverage, artifacts: [
    { controlId: "2.2.1", title: "AWS Config recorder configuration", description: "Live AWS Config recorder settings demonstrating configuration monitoring coverage.", type: "configuration", source: "AWS", system: env.AWS_REGION || "us-east-1", contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify(configData, null, 2)) },
    { controlId: "1.2.5", title: "AWS EC2 security group inventory", description: "Live security group configuration for review of network security controls.", type: "configuration", source: "AWS", system: env.AWS_REGION || "us-east-1", contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify({ coverage: resultCoverage, responsePages: securityGroupPages }, null, 2)) },
  ] };
}

async function browserCollector(env: ScopeproofEnv): Promise<CollectorResult> {
  const token = configured(env.CLOUDFLARE_API_TOKEN, "CLOUDFLARE_API_TOKEN");
  const accountId = configured(env.CLOUDFLARE_ACCOUNT_ID, "CLOUDFLARE_ACCOUNT_ID");
  const urls = configured(env.BROWSER_CAPTURE_URLS, "BROWSER_CAPTURE_URLS").split(",").map((item) => item.trim()).filter(Boolean);
  const artifacts: Artifact[] = [];
  const scopedUrls = urls.slice(0, 50);
  for (const target of scopedUrls) {
    const url = new URL(target);
    if (url.protocol !== "https:") throw new CollectorError(`Browser capture only permits HTTPS targets: ${target}`, "UNSAFE_TARGET", false);
    const endpoint = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/browser-rendering`;
    const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };
    const screenshotResponse = await providerFetch(`${endpoint}/screenshot`, { method: "POST", headers, body: JSON.stringify({ url: target, gotoOptions: { waitUntil: "networkidle0", timeout: 30000 }, screenshotOptions: { type: "png", fullPage: true } }) }, `Browser screenshot for ${url.hostname}`, 15 * 1024 * 1024);
    const image = new Uint8Array(await screenshotResponse.arrayBuffer());
    const safetyScan = await scanExactBrowserPixels(env, image);
    artifacts.push({ controlId: "2.2.1", title: `Authenticated configuration capture — ${url.hostname}`, description: `Browser-rendered evidence captured from ${url.pathname}. The immutable PNG pixels passed digest-bound OCR safety policy ${safetyScan.policy} before persistence.`, type: "screenshot", source: "Browser capture", system: url.hostname, contentType: "image/png", bytes: image, safetyScanSha256: safetyScan.digest, safetyScanPolicy: safetyScan.policy, safetyScanCompletedAt: safetyScan.completedAt });
  }
  const omissions = urls.length > scopedUrls.length ? [`Only ${scopedUrls.length} of ${urls.length} browser targets fit the collection safety budget.`] : [];
  const resultCoverage = coverage("browser", "configured HTTPS target list", artifacts.length, artifacts.length, omissions.length === 0, omissions, urls.length, "cloudflare-browser-rendering-v1");
  return { coverage: resultCoverage, artifacts };
}

export async function runCollector(provider: CollectorProvider, context: CollectorContext): Promise<CollectorResult> {
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
    cloudflare: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"], browser: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "BROWSER_CAPTURE_URLS", "BROWSER_OCR_ENDPOINT", "BROWSER_OCR_TOKEN", "BROWSER_OCR_ALLOWED_HOSTS"],
  };
  const missing = required[provider].filter((key) => !env[key]).map(String);
  return { configured: missing.length === 0, missing };
}
