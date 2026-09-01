import type { AuthenticatedUser } from "./auth";
import { sha256 } from "./crypto";
import { getEnv, type ScopeproofEnv } from "./env";
import type { EvidenceInput } from "./evidence";
import { EvidenceSafetyScanError, scanExactEvidencePixels } from "./image-safety";
import { decodeXmlText } from "./xml";

export type CollectorProvider = "aws" | "github" | "okta" | "cloudflare" | "browser";
export class CollectorError extends Error {
  constructor(message: string, public readonly code: string, public readonly retryable: boolean, public readonly status?: number) { super(message); }
}

// The scheduler binds every collector result to the authoritative job assessment
// immediately before persistence. Providers must not be able to choose that scope.
type Artifact = Omit<EvidenceInput, "assessmentId" | "createdBy" | "collectorId" | "jobId">;
type CollectorContext = { actor: AuthenticatedUser; config: Record<string, unknown> };

export type CollectorCoverage = { provider: CollectorProvider; complete: boolean; requestedScope: string; returnedCount: number; providerTotal?: number; pageCount: number; omissions: string[]; apiVersion: string; collectedAt: string; budget: { responseBytes: number; maximumResponseBytes: number; items: number; maximumItems: number; exhausted: boolean } };
export type CollectorResult = { artifacts: Artifact[]; coverage: CollectorCoverage };

const MAX_PROVIDER_PAGES = 20;
const MAX_SCOPED_RESOURCES = 250;
const MAX_COLLECTION_RESPONSE_BYTES = 32 * 1024 * 1024;
const MAX_COLLECTION_ITEMS = 5_000;
const MAX_COLLECTION_ARTIFACT_BYTES = 40 * 1024 * 1024;

class CollectionBudgetExceeded extends CollectorError {
  constructor() { super("The provider response exceeded the aggregate collection safety budget.", "COLLECTION_BUDGET_EXCEEDED", false, 413); }
}

class CollectionBudget {
  responseBytes = 0;
  items = 0;
  exhausted = false;

  consumeBytes(amount: number): void {
    if (!Number.isSafeInteger(amount) || amount < 0 || this.responseBytes + amount > MAX_COLLECTION_RESPONSE_BYTES) {
      this.exhausted = true;
      throw new CollectionBudgetExceeded();
    }
    this.responseBytes += amount;
  }

  availableItems(): number { return Math.max(0, MAX_COLLECTION_ITEMS - this.items); }

  consumeItems(amount: number): void {
    if (!Number.isSafeInteger(amount) || amount < 0 || this.items + amount > MAX_COLLECTION_ITEMS) {
      this.exhausted = true;
      throw new CollectionBudgetExceeded();
    }
    this.items += amount;
  }

  snapshot(): CollectorCoverage["budget"] {
    return { responseBytes: this.responseBytes, maximumResponseBytes: MAX_COLLECTION_RESPONSE_BYTES, items: this.items, maximumItems: MAX_COLLECTION_ITEMS, exhausted: this.exhausted };
  }
}

function providerOrigin(value: string, label: string): URL {
  let url: URL;
  try { url = new URL(value); }
  catch { throw new CollectorError(`${label} must be an absolute HTTPS URL.`, "UNSAFE_PROVIDER_ORIGIN", false); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
    throw new CollectorError(`${label} must be a clean HTTPS origin.`, "UNSAFE_PROVIDER_ORIGIN", false);
  }
  return new URL(url.origin);
}

function nextLink(response: Response, allowedOrigin: string): string | null {
  const link = response.headers.get("link") || "";
  for (const item of link.split(",")) {
    const match = item.match(/<([^>]+)>;\s*rel="next"/);
    if (!match) continue;
    let candidate: URL;
    try { candidate = new URL(match[1], allowedOrigin); }
    catch { throw new CollectorError("Provider pagination returned an invalid URL.", "PROVIDER_INVALID_PAGINATION", false); }
    if (candidate.origin !== allowedOrigin || candidate.protocol !== "https:" || candidate.username || candidate.password || candidate.hash) {
      throw new CollectorError("Provider pagination attempted to leave its approved HTTPS origin.", "UNSAFE_PROVIDER_PAGINATION", false);
    }
    return candidate.toString();
  }
  return null;
}

async function collectLinkedJson<T>(url: string, init: RequestInit, label: string, allowedOrigin: string, budget: CollectionBudget, itemLimit = MAX_SCOPED_RESOURCES): Promise<{ items: T[]; pages: number; complete: boolean; next: string | null }> {
  const items: T[] = [];
  let next: string | null = url;
  let pages = 0;
  let truncatedWithinPage = false;
  while (next && pages < MAX_PROVIDER_PAGES && items.length < itemLimit) {
    const target = new URL(next);
    if (target.origin !== allowedOrigin || target.protocol !== "https:" || target.username || target.password || target.hash) {
      throw new CollectorError(`${label} attempted to leave its approved HTTPS origin.`, "UNSAFE_PROVIDER_PAGINATION", false);
    }
    let response: Response;
    try { response = await providerFetch(next, init, `${label} page ${pages + 1}`, 2 * 1024 * 1024, [], budget); }
    catch (error) {
      if (error instanceof CollectionBudgetExceeded) break;
      throw error;
    }
    const page = await response.json() as T[];
    if (!Array.isArray(page)) throw new CollectorError(`${label} returned an invalid collection.`, "PROVIDER_INVALID_RESPONSE", false);
    const scopeRemaining = itemLimit - items.length;
    const budgetRemaining = budget.availableItems();
    const remaining = Math.min(scopeRemaining, budgetRemaining);
    if (page.length > remaining) {
      truncatedWithinPage = true;
      if (budgetRemaining < page.length && budgetRemaining <= scopeRemaining) budget.exhausted = true;
    }
    const accepted = page.slice(0, remaining);
    budget.consumeItems(accepted.length);
    items.push(...accepted);
    next = nextLink(response, allowedOrigin);
    pages += 1;
  }
  return { items, pages, complete: !next && !truncatedWithinPage, next: next || (truncatedWithinPage ? "item-limit-reached" : null) };
}

function coverage(provider: CollectorProvider, requestedScope: string, returnedCount: number, pageCount: number, complete: boolean, budget: CollectionBudget, omissions: string[] = [], providerTotal?: number, apiVersion = "provider-current"): CollectorCoverage {
  const budgetOmissions = budget.exhausted ? ["Aggregate provider-response or resource budget reached; collection stopped before additional data was retained."] : [];
  const allOmissions = [...omissions, ...budgetOmissions];
  return { provider, complete: complete && allOmissions.length === 0 && (providerTotal === undefined || returnedCount >= providerTotal), requestedScope, returnedCount, providerTotal, pageCount, omissions: allOmissions, apiVersion, collectedAt: new Date().toISOString(), budget: budget.snapshot() };
}

function configured(value: string | undefined, name: string): string {
  if (!value) throw new CollectorError(`${name} is not configured.`, "NOT_CONFIGURED", false);
  return value;
}

async function providerFetch(url: string, init: RequestInit, label: string, maximumBytes = 2 * 1024 * 1024, allowedStatuses: number[] = [], budget?: CollectionBudget): Promise<Response> {
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
      budget?.consumeBytes(value.byteLength);
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
  const retryable = bounded.status === 429 || bounded.status >= 500;
  throw new CollectorError(`${label} returned HTTP ${bounded.status}.`, bounded.status === 401 || bounded.status === 403 ? "AUTH_FAILED" : "PROVIDER_ERROR", retryable, bounded.status);
}

async function scanExactBrowserPixels(env: ScopeproofEnv, image: Uint8Array, budget: CollectionBudget) {
  try {
    const scan = await scanExactEvidencePixels(image, env);
    budget.consumeBytes(scan.responseBytes);
    return scan;
  } catch (error) {
    if (error instanceof EvidenceSafetyScanError) {
      const code = error.code === "SENSITIVE_CONTENT" ? "SENSITIVE_CONTENT_BLOCKED" : error.code === "NOT_CONFIGURED" ? "NOT_CONFIGURED" : error.code === "UNSAFE_ENDPOINT" ? "UNSAFE_OCR_ENDPOINT" : error.code === "UNAVAILABLE" ? "OCR_UNAVAILABLE" : "OCR_INVALID_RESPONSE";
      throw new CollectorError(error.message, code, error.retryable);
    }
    throw error;
  }
}

async function githubCollector(env: ScopeproofEnv, budget: CollectionBudget): Promise<CollectorResult> {
  const token = configured(env.GITHUB_TOKEN, "GITHUB_TOKEN");
  const org = configured(env.GITHUB_ORG, "GITHUB_ORG");
  const headers = { authorization: `Bearer ${token}`, accept: "application/vnd.github+json", "x-github-api-version": "2022-11-28", "user-agent": "Scopeproof-PCI-Evidence" };
  type Repo = { name: string; full_name: string; private: boolean; archived: boolean; default_branch: string; visibility: string; security_and_analysis?: unknown };
  const listing = await collectLinkedJson<Repo>(`https://api.github.com/orgs/${encodeURIComponent(org)}/repos?per_page=100&type=all&sort=full_name`, { headers }, "GitHub repository inventory", "https://api.github.com", budget);
  const repos = listing.items;
  const active = repos.filter((repo) => !repo.archived);
  const omissions: string[] = listing.complete ? [] : [`Repository pagination exceeded ${MAX_PROVIDER_PAGES} pages or ${MAX_SCOPED_RESOURCES} repositories.`];
  const protection: Array<Record<string, unknown>> = [];
  for (let offset = 0; offset < active.length; offset += 5) {
    try { protection.push(...await Promise.all(active.slice(offset, offset + 5).map(async (repo) => {
      const response = await providerFetch(`https://api.github.com/repos/${encodeURIComponent(org)}/${encodeURIComponent(repo.name)}/branches/${encodeURIComponent(repo.default_branch)}/protection`, { headers }, `GitHub branch protection for ${repo.full_name}`, 512 * 1024, [404], budget);
      if (response.status === 404) return { repository: repo.full_name, defaultBranch: repo.default_branch, protected: false };
      const data = await response.json() as Record<string, unknown>;
      budget.consumeItems(1);
      return { repository: repo.full_name, defaultBranch: repo.default_branch, protected: true, requiredStatusChecks: data.required_status_checks, requiredReviews: data.required_pull_request_reviews, enforceAdmins: data.enforce_admins };
    }))); } catch (error) {
      if (!(error instanceof CollectionBudgetExceeded)) throw error;
      break;
    }
  }
  if (protection.length < active.length) omissions.push(`Branch protection was collected for ${protection.length} of ${active.length} active repositories.`);
  const resultCoverage = coverage("github", `organization:${org}`, repos.length, listing.pages, listing.complete && protection.length === active.length, budget, omissions, undefined, "2022-11-28");
  const body = new TextEncoder().encode(JSON.stringify({ organization: org, collectedAt: resultCoverage.collectedAt, coverage: resultCoverage, repositoryCount: repos.length, repositories: repos, defaultBranchProtection: protection }, null, 2));
  return { coverage: resultCoverage, artifacts: [{ controlId: "6.3.2", title: `GitHub software inventory and branch protection — ${org}`, description: "Live organization repository inventory and default branch protection configuration.", type: "configuration", source: "GitHub", system: org, contentType: "application/json", bytes: body }] };
}

async function oktaCollector(env: ScopeproofEnv, budget: CollectionBudget): Promise<CollectorResult> {
  const base = providerOrigin(configured(env.OKTA_BASE_URL, "OKTA_BASE_URL"), "OKTA_BASE_URL").origin;
  const token = configured(env.OKTA_API_TOKEN, "OKTA_API_TOKEN");
  const headers = { authorization: `SSWS ${token}`, accept: "application/json" };
  const policyListing = await collectLinkedJson<Record<string, unknown>>(`${base}/api/v1/policies?type=OKTA_SIGN_ON&limit=200`, { headers }, "Okta sign-on policies", base, budget);
  const groupListing = await collectLinkedJson<Record<string, unknown>>(`${base}/api/v1/groups?limit=200`, { headers }, "Okta groups", base, budget);
  const policies = policyListing.items;
  const groups = groupListing.items;
  const omissions = [...(!policyListing.complete ? ["Sign-on policy pagination exceeded the safety budget."] : []), ...(!groupListing.complete ? ["Group pagination exceeded the safety budget."] : [])];
  const resultCoverage = coverage("okta", `tenant:${new URL(base).hostname}`, policies.length + groups.length, policyListing.pages + groupListing.pages, policyListing.complete && groupListing.complete, budget, omissions, undefined, "okta-v1");
  return { coverage: resultCoverage, artifacts: [
    { controlId: "8.3.6", title: "Okta global session and MFA policies", description: "Live sign-on policies used to verify authentication factor enforcement.", type: "configuration", source: "Okta", system: new URL(base).hostname, contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify(policies, null, 2)) },
    { controlId: "7.2.5", title: "Okta group inventory for access review", description: "Current identity groups and membership metadata for periodic access review.", type: "report", source: "Okta", system: new URL(base).hostname, contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify(groups, null, 2)) },
  ] };
}

async function cloudflareCollector(env: ScopeproofEnv, budget: CollectionBudget): Promise<CollectorResult> {
  const token = configured(env.CLOUDFLARE_API_TOKEN, "CLOUDFLARE_API_TOKEN");
  const accountId = configured(env.CLOUDFLARE_ACCOUNT_ID, "CLOUDFLARE_ACCOUNT_ID");
  const headers = { authorization: `Bearer ${token}`, accept: "application/json" };
  const zoneIds = (env.CLOUDFLARE_ZONE_IDS || "").split(",").map((item) => item.trim()).filter(Boolean);
  let pages = 0;
  let providerTotal: number | undefined;
  const omissions: string[] = [];
  if (!zoneIds.length) {
    for (let page = 1; page <= MAX_PROVIDER_PAGES && zoneIds.length < MAX_SCOPED_RESOURCES; page += 1) {
      let zonesResponse: Response;
      try { zonesResponse = await providerFetch(`https://api.cloudflare.com/client/v4/zones?account.id=${encodeURIComponent(accountId)}&per_page=50&page=${page}`, { headers }, `Cloudflare zones page ${page}`, 1024 * 1024, [], budget); }
      catch (error) { if (error instanceof CollectionBudgetExceeded) break; throw error; }
      const zones = await zonesResponse.json() as { result?: Array<{ id: string }>; result_info?: { total_count?: number; total_pages?: number } };
      const accepted = (zones.result || []).map((zone) => zone.id).slice(0, Math.min(MAX_SCOPED_RESOURCES - zoneIds.length, budget.availableItems()));
      budget.consumeItems(accepted.length);
      zoneIds.push(...accepted);
      providerTotal = Number(zones.result_info?.total_count || zoneIds.length);
      pages = page;
      if (page >= Number(zones.result_info?.total_pages || 1)) break;
    }
    if ((providerTotal || 0) > zoneIds.length) omissions.push(`Only ${zoneIds.length} of ${providerTotal} zones fit the collection safety budget.`);
  }
  const scopedZoneIds = zoneIds.slice(0, Math.min(MAX_SCOPED_RESOURCES, budget.availableItems()));
  if (env.CLOUDFLARE_ZONE_IDS) {
    if (zoneIds.length > scopedZoneIds.length && budget.availableItems() < zoneIds.length) budget.exhausted = true;
    budget.consumeItems(scopedZoneIds.length);
  }
  if (zoneIds.length > scopedZoneIds.length) omissions.push(`Only ${scopedZoneIds.length} explicitly configured zones fit the collection safety budget.`);
  const rulesets: Array<Record<string, unknown>> = [];
  for (let offset = 0; offset < scopedZoneIds.length; offset += 10) {
    try { rulesets.push(...await Promise.all(scopedZoneIds.slice(offset, offset + 5).map(async (zoneId) => {
      const response = await providerFetch(`https://api.cloudflare.com/client/v4/zones/${encodeURIComponent(zoneId)}/rulesets/phases/http_request_firewall_managed/entrypoint`, { headers }, `Cloudflare managed rules for ${zoneId}`, 1024 * 1024, [], budget);
      budget.consumeItems(1);
      return { zoneId, result: await response.json() };
    }))); } catch (error) { if (error instanceof CollectionBudgetExceeded) break; throw error; }
  }
  if (rulesets.length < scopedZoneIds.length) omissions.push(`Managed rules were collected for ${rulesets.length} of ${scopedZoneIds.length} scoped zones.`);
  const resultCoverage = coverage("cloudflare", `account:${accountId}`, rulesets.length, Math.max(1, pages), omissions.length === 0, budget, omissions, providerTotal || zoneIds.length, "cloudflare-v4");
  return { coverage: resultCoverage, artifacts: [{ controlId: "1.2.5", title: "Cloudflare WAF managed rulesets", description: "Live managed firewall ruleset configuration for scoped production zones.", type: "configuration", source: "Cloudflare", system: `${zoneIds.length} zones`, contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify({ accountId, collectedAt: resultCoverage.collectedAt, coverage: resultCoverage, rulesets }, null, 2)) }] };
}

async function hmacBytes(key: Uint8Array, data: string): Promise<Uint8Array> {
  const raw = key.buffer.slice(key.byteOffset, key.byteOffset + key.byteLength) as ArrayBuffer;
  const imported = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", imported, new TextEncoder().encode(data)));
}

function hex(bytes: Uint8Array): string { return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join(""); }

async function awsSignedPost(env: ScopeproofEnv, service: string, body: string, headers: Record<string, string>, budget: CollectionBudget): Promise<Response> {
  const accessKey = configured(env.AWS_ACCESS_KEY_ID, "AWS_ACCESS_KEY_ID");
  const secret = configured(env.AWS_SECRET_ACCESS_KEY, "AWS_SECRET_ACCESS_KEY");
  const sessionToken = configured(env.AWS_SESSION_TOKEN, "AWS_SESSION_TOKEN");
  const region = env.AWS_REGION || "us-east-1";
  const host = `${service}.${region}.amazonaws.com`;
  const date = new Date();
  const amzDate = date.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = await sha256(body);
  const signedHeaderMap: Record<string, string> = { ...headers, host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash };
  signedHeaderMap["x-amz-security-token"] = sessionToken;
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
  return providerFetch(`https://${host}/`, { method: "POST", headers: { ...signedHeaderMap, authorization }, body }, `AWS ${service}`, 2 * 1024 * 1024, [], budget);
}

async function awsCollector(env: ScopeproofEnv, budget: CollectionBudget): Promise<CollectorResult> {
  const configHeaders = { "content-type": "application/x-amz-json-1.1", "x-amz-target": "StarlingDoveService.DescribeConfigurationRecorders" };
  const configResponse = await awsSignedPost(env, "config", "{}", configHeaders, budget);
  const configData = await configResponse.json();
  budget.consumeItems(1);
  const securityGroupPages: string[] = [];
  let token: string | null = null;
  let complete = true;
  do {
    const ec2Body: string = `Action=DescribeSecurityGroups&Version=2016-11-15${token ? `&NextToken=${encodeURIComponent(token)}` : ""}`;
    let ec2Response: Response;
    try { ec2Response = await awsSignedPost(env, "ec2", ec2Body, { "content-type": "application/x-www-form-urlencoded; charset=utf-8" }, budget); }
    catch (error) { if (error instanceof CollectionBudgetExceeded) { complete = false; break; } throw error; }
    const xml: string = await ec2Response.text();
    budget.consumeItems(1);
    securityGroupPages.push(xml);
    const match: RegExpMatchArray | null = xml.match(/<nextToken>([^<]+)<\/nextToken>/i);
    token = match ? decodeXmlText(match[1]) : null;
    if (token && securityGroupPages.length >= MAX_PROVIDER_PAGES) { complete = false; break; }
  } while (token);
  const omissions = complete ? [] : [`EC2 security-group pagination exceeded ${MAX_PROVIDER_PAGES} pages.`];
  const resultCoverage = coverage("aws", `account-credential:${env.AWS_REGION || "us-east-1"}`, securityGroupPages.length, securityGroupPages.length + 1, complete, budget, omissions, undefined, "Config 2014-11-12 / EC2 2016-11-15");
  return { coverage: resultCoverage, artifacts: [
    { controlId: "2.2.1", title: "AWS Config recorder configuration", description: "Live AWS Config recorder settings demonstrating configuration monitoring coverage.", type: "configuration", source: "AWS", system: env.AWS_REGION || "us-east-1", contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify(configData, null, 2)) },
    { controlId: "1.2.5", title: "AWS EC2 security group inventory", description: "Live security group configuration for review of network security controls.", type: "configuration", source: "AWS", system: env.AWS_REGION || "us-east-1", contentType: "application/json", bytes: new TextEncoder().encode(JSON.stringify({ coverage: resultCoverage, responsePages: securityGroupPages }, null, 2)) },
  ] };
}

async function browserCollector(env: ScopeproofEnv, budget: CollectionBudget): Promise<CollectorResult> {
  const token = configured(env.CLOUDFLARE_API_TOKEN, "CLOUDFLARE_API_TOKEN");
  const accountId = configured(env.CLOUDFLARE_ACCOUNT_ID, "CLOUDFLARE_ACCOUNT_ID");
  const urls = configured(env.BROWSER_CAPTURE_URLS, "BROWSER_CAPTURE_URLS").split(",").map((item) => item.trim()).filter(Boolean);
  const artifacts: Artifact[] = [];
  const scopedUrls = urls.slice(0, 50);
  const omissions: string[] = [];
  for (const target of scopedUrls) {
    const url = new URL(target);
    if (url.protocol !== "https:") throw new CollectorError(`Browser capture only permits HTTPS targets: ${target}`, "UNSAFE_TARGET", false);
    const endpoint = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/browser-rendering`;
    const headers = { authorization: `Bearer ${token}`, "content-type": "application/json" };
    let screenshotResponse: Response;
    try { screenshotResponse = await providerFetch(`${endpoint}/screenshot`, { method: "POST", headers, body: JSON.stringify({ url: target, gotoOptions: { waitUntil: "networkidle0", timeout: 30000 }, screenshotOptions: { type: "png", fullPage: true } }) }, `Browser screenshot for ${url.hostname}`, 15 * 1024 * 1024, [], budget); }
    catch (error) { if (error instanceof CollectionBudgetExceeded) break; throw error; }
    const image = new Uint8Array(await screenshotResponse.arrayBuffer());
    let safetyScan: Awaited<ReturnType<typeof scanExactBrowserPixels>>;
    try { safetyScan = await scanExactBrowserPixels(env, image, budget); }
    catch (error) { if (error instanceof CollectionBudgetExceeded) break; throw error; }
    budget.consumeItems(1);
    artifacts.push({ controlId: "2.2.1", title: `Authenticated configuration capture — ${url.hostname}`, description: `Browser-rendered evidence captured from ${url.pathname}. The immutable PNG pixels passed digest-bound OCR safety policy ${safetyScan.policy} before persistence.`, type: "screenshot", source: "Browser capture", system: url.hostname, contentType: "image/png", bytes: image, safetyScanSha256: safetyScan.digest, safetyScanPolicy: safetyScan.policy, safetyScanCompletedAt: safetyScan.completedAt, serverSafetyScan: safetyScan });
  }
  if (urls.length > scopedUrls.length) omissions.push(`Only ${scopedUrls.length} of ${urls.length} browser targets fit the collection safety budget.`);
  if (artifacts.length < scopedUrls.length) omissions.push(`Browser evidence was retained for ${artifacts.length} of ${scopedUrls.length} scoped targets.`);
  const resultCoverage = coverage("browser", "configured HTTPS target list", artifacts.length, artifacts.length, omissions.length === 0, budget, omissions, urls.length, "cloudflare-browser-rendering-v1");
  return { coverage: resultCoverage, artifacts };
}

export async function runCollector(provider: CollectorProvider, context: CollectorContext): Promise<CollectorResult> {
  void context.config;
  const env = getEnv();
  const budget = new CollectionBudget();
  let result: CollectorResult;
  switch (provider) {
    case "aws": result = await awsCollector(env, budget); break;
    case "github": result = await githubCollector(env, budget); break;
    case "okta": result = await oktaCollector(env, budget); break;
    case "cloudflare": result = await cloudflareCollector(env, budget); break;
    case "browser": result = await browserCollector(env, budget); break;
  }
  let artifactBytes = 0;
  const retained: Artifact[] = [];
  for (const artifact of result.artifacts) {
    if (artifactBytes + artifact.bytes.byteLength > MAX_COLLECTION_ARTIFACT_BYTES) break;
    artifactBytes += artifact.bytes.byteLength;
    retained.push(artifact);
  }
  if (retained.length !== result.artifacts.length) {
    result.coverage.complete = false;
    result.coverage.omissions.push(`Only ${retained.length} of ${result.artifacts.length} generated artifacts fit the aggregate persistence budget.`);
    result.artifacts = retained;
  }
  return result;
}

export function collectorConfiguration(provider: CollectorProvider): { configured: boolean; missing: string[] } {
  const env = getEnv();
  const required: Record<CollectorProvider, Array<keyof ScopeproofEnv>> = {
    aws: ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"], github: ["GITHUB_TOKEN", "GITHUB_ORG"], okta: ["OKTA_BASE_URL", "OKTA_API_TOKEN"],
    cloudflare: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"], browser: ["CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID", "BROWSER_CAPTURE_URLS", "BROWSER_OCR_ENDPOINT", "BROWSER_OCR_TOKEN", "BROWSER_OCR_ALLOWED_HOSTS"],
  };
  const missing = required[provider].filter((key) => !env[key]).map(String);
  return { configured: missing.length === 0, missing };
}
