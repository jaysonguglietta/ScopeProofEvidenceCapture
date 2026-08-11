import { env as runtimeEnv } from "cloudflare:workers";

export interface ScopeproofEnv {
  DB: D1Database;
  EVIDENCE_BUCKET: R2Bucket;
  EVIDENCE_ENCRYPTION_KEY?: string;
  AUDIT_HMAC_KEY?: string;
  PACKAGE_SIGNING_PRIVATE_KEY?: string;
  PACKAGE_SIGNING_PUBLIC_KEY?: string;
  BOOTSTRAP_ADMIN_EMAILS?: string;
  TRUSTED_APP_ORIGINS?: string;
  AWS_ACCESS_KEY_ID?: string;
  AWS_SECRET_ACCESS_KEY?: string;
  AWS_SESSION_TOKEN?: string;
  AWS_REGION?: string;
  GITHUB_TOKEN?: string;
  GITHUB_ORG?: string;
  OKTA_BASE_URL?: string;
  OKTA_API_TOKEN?: string;
  CLOUDFLARE_API_TOKEN?: string;
  CLOUDFLARE_ACCOUNT_ID?: string;
  CLOUDFLARE_ZONE_IDS?: string;
  BROWSER_CAPTURE_URLS?: string;
  BROWSER_OCR_ENDPOINT?: string;
  BROWSER_OCR_TOKEN?: string;
  BROWSER_OCR_ALLOWED_HOSTS?: string;
  MACOS_LATEST_VERSION?: string;
  MACOS_RELEASE_URL?: string;
  MACOS_RELEASE_SHA256?: string;
  MACOS_RELEASE_NOTES?: string;
  RFC3161_TSA_URL?: string;
  JIRA_OAUTH_CLIENT_ID?: string;
  JIRA_OAUTH_CLIENT_SECRET?: string;
  JIRA_OAUTH_CALLBACK_URL?: string;
  JIRA_OAUTH_TOKEN_ENCRYPTION_KEY?: string;
}

export function getEnv(): ScopeproofEnv {
  return runtimeEnv as unknown as ScopeproofEnv;
}

export function requireEnv<K extends keyof ScopeproofEnv>(key: K): NonNullable<ScopeproofEnv[K]> {
  const value = getEnv()[key];
  if (!value) throw new Error(`Required runtime binding ${String(key)} is not configured.`);
  return value as NonNullable<ScopeproofEnv[K]>;
}
