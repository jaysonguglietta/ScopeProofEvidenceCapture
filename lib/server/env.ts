import { env as runtimeEnv } from "cloudflare:workers";

export interface ScopeproofEnv {
  DB: D1Database;
  EVIDENCE_BUCKET: R2Bucket;
  EVIDENCE_ENCRYPTION_KEY?: string;
  EVIDENCE_ACTIVE_KEY_ID?: string;
  EVIDENCE_KEYRING_JSON?: string;
  AUDIT_HMAC_KEY?: string;
  AUDIT_ACTIVE_KEY_ID?: string;
  AUDIT_KEYRING_JSON?: string;
  AUDIT_CHECKPOINT_ENDPOINT?: string;
  AUDIT_CHECKPOINT_ALLOWED_HOSTS?: string;
  AUDIT_CHECKPOINT_TOKEN?: string;
  SECURITY_EVENT_ENDPOINT?: string;
  SECURITY_EVENT_ALLOWED_HOSTS?: string;
  SECURITY_EVENT_TOKEN?: string;
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
  MACOS_RELEASE_MANIFEST_JSON?: string;
  MACOS_RELEASE_SIGNATURE_DER_BASE64?: string;
  MACOS_RELEASE_ALLOWED_HOSTS?: string;
  RFC3161_TSA_URL?: string;
  RFC3161_VERIFIER_URL?: string;
  RFC3161_VERIFIER_PUBLIC_KEY?: string;
  RFC3161_VERIFIER_PUBLIC_KEYS?: string;
  RFC3161_VERIFIER_TOKEN?: string;
  RFC3161_VERIFIER_ALLOWED_HOSTS?: string;
  RFC3161_TSA_TRUST_ANCHOR_SHA256?: string;
  JIRA_OAUTH_CLIENT_ID?: string;
  JIRA_OAUTH_CLIENT_SECRET?: string;
  JIRA_OAUTH_CALLBACK_URL?: string;
  JIRA_OAUTH_TOKEN_ENCRYPTION_KEY?: string;
  JIRA_OAUTH_ACTIVE_KEY_ID?: string;
  JIRA_OAUTH_KEYRING_JSON?: string;
}

export function getEnv(): ScopeproofEnv {
  return runtimeEnv as unknown as ScopeproofEnv;
}

export function requireEnv<K extends keyof ScopeproofEnv>(key: K): NonNullable<ScopeproofEnv[K]> {
  const value = getEnv()[key];
  if (!value) throw new Error(`Required runtime binding ${String(key)} is not configured.`);
  return value as NonNullable<ScopeproofEnv[K]>;
}
