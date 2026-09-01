export type ExternalTrustEnvironment = {
  AUDIT_CHECKPOINT_ENDPOINT?: string;
  AUDIT_CHECKPOINT_ALLOWED_HOSTS?: string;
  AUDIT_CHECKPOINT_TOKEN?: string;
  AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY?: string;
  SECURITY_EVENT_ENDPOINT?: string;
  SECURITY_EVENT_ALLOWED_HOSTS?: string;
  SECURITY_EVENT_TOKEN?: string;
  RFC3161_TSA_URL?: string;
  RFC3161_VERIFIER_URL?: string;
  RFC3161_VERIFIER_PUBLIC_KEY?: string;
  RFC3161_VERIFIER_PUBLIC_KEYS?: string;
  RFC3161_VERIFIER_TOKEN?: string;
  RFC3161_VERIFIER_ALLOWED_HOSTS?: string;
  RFC3161_TSA_TRUST_ANCHOR_SHA256?: string;
};

function exactBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function canonicalBase64ToBytes(value: string): Uint8Array {
  if (!value || value.length % 4 !== 0
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("Key material is not canonical base64.");
  }
  let binary: string;
  try { binary = atob(value); } catch { throw new Error("Key material is not valid base64."); }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  let encoded = "";
  for (let offset = 0; offset < bytes.length; offset += 32_768) {
    encoded += String.fromCharCode(...bytes.subarray(offset, offset + 32_768));
  }
  if (btoa(encoded) !== value) throw new Error("Key material is not canonical base64.");
  return bytes;
}

function parseAllowedHosts(value: string | undefined, label: string): Set<string> {
  const hosts = String(value || "").split(",").map((host) => host.trim().toLowerCase()).filter(Boolean);
  const invalid = hosts.length === 0 || hosts.length > 20 || hosts.some((host) => {
    const ipv4Literal = host.split(".").length === 4
      && host.split(".").every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
    return host.length > 253 || host === "localhost" || host.endsWith(".localhost") || ipv4Literal
      || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(host);
  });
  if (invalid) throw new Error(`${label} must contain one to twenty valid DNS hostnames.`);
  return new Set(hosts);
}

function cleanHttpsUrl(value: string | undefined, label: string, allowedHosts?: Set<string>): URL {
  if (!value) throw new Error(`${label} is not configured.`);
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`${label} is invalid.`); }
  if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.port
    || (allowedHosts && !allowedHosts.has(url.hostname.toLowerCase()))) {
    throw new Error(`${label} must use an explicitly allowed HTTPS host without credentials, fragments, or a custom port.`);
  }
  return url;
}

async function importP256Spki(value: string, message: string): Promise<void> {
  try {
    await crypto.subtle.importKey(
      "spki",
      exactBuffer(canonicalBase64ToBytes(value)),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new Error(message);
  }
}

export function auditCheckpointEndpoint(env: ExternalTrustEnvironment): { url: URL; token?: string } | null {
  if (!env.AUDIT_CHECKPOINT_ENDPOINT) return null;
  const hosts = parseAllowedHosts(env.AUDIT_CHECKPOINT_ALLOWED_HOSTS, "AUDIT_CHECKPOINT_ALLOWED_HOSTS");
  const url = cleanHttpsUrl(env.AUDIT_CHECKPOINT_ENDPOINT, "Audit checkpoint delivery", hosts);
  const token = env.AUDIT_CHECKPOINT_TOKEN;
  if (token && (token !== token.trim() || token.length < 16 || token.length > 4_096 || /\p{Cc}/u.test(token))) {
    throw new Error("AUDIT_CHECKPOINT_TOKEN is malformed.");
  }
  if (!env.AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY) {
    throw new Error("AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY is required for independent receipt verification.");
  }
  return { url, ...(token ? { token } : {}) };
}

export async function validateAuditCheckpointConfiguration(env: ExternalTrustEnvironment): Promise<{ origin: string }> {
  const endpoint = auditCheckpointEndpoint(env);
  if (!endpoint || !env.AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY) {
    throw new Error("Independent audit checkpoint delivery is not fully configured.");
  }
  await importP256Spki(
    env.AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY,
    "AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY must be a canonical base64 P-256 SPKI public key.",
  );
  return { origin: endpoint.url.origin };
}

export function securityMonitoringEndpoint(env: ExternalTrustEnvironment): { url: URL; token?: string } | null {
  if (!env.SECURITY_EVENT_ENDPOINT) return null;
  const hosts = parseAllowedHosts(env.SECURITY_EVENT_ALLOWED_HOSTS, "SECURITY_EVENT_ALLOWED_HOSTS");
  const url = cleanHttpsUrl(env.SECURITY_EVENT_ENDPOINT, "Security monitoring delivery", hosts);
  const token = env.SECURITY_EVENT_TOKEN;
  if (!token || token !== token.trim() || token.length < 16 || token.length > 4_096 || /\p{Cc}/u.test(token)) {
    throw new Error("SECURITY_EVENT_TOKEN is missing or malformed.");
  }
  return { url, token };
}

export function validateSecurityMonitoringConfiguration(env: ExternalTrustEnvironment): { origin: string } {
  const endpoint = securityMonitoringEndpoint(env);
  if (!endpoint) throw new Error("Security monitoring delivery is not configured.");
  return { origin: endpoint.url.origin };
}

export function trustedTimestampTsaEndpoint(env: ExternalTrustEnvironment): URL {
  const url = cleanHttpsUrl(env.RFC3161_TSA_URL, "RFC3161_TSA_URL");
  return url;
}

export function trustedTimestampVerifierEndpoint(env: ExternalTrustEnvironment): URL {
  const hosts = parseAllowedHosts(env.RFC3161_VERIFIER_ALLOWED_HOSTS, "RFC3161_VERIFIER_ALLOWED_HOSTS");
  const url = cleanHttpsUrl(env.RFC3161_VERIFIER_URL, "RFC 3161 verifier", hosts);
  return url;
}

export async function validateTrustedTimestampConfiguration(env: ExternalTrustEnvironment): Promise<{
  tsaOrigin: string;
  verifierOrigin: string;
  verifierKeyCount: number;
  trustAnchorCount: number;
}> {
  const tsaUrl = trustedTimestampTsaEndpoint(env);
  const verifierUrl = trustedTimestampVerifierEndpoint(env);
  const token = String(env.RFC3161_VERIFIER_TOKEN || "");
  if (!token || token !== token.trim() || token.length < 16 || token.length > 4_096 || /\p{Cc}/u.test(token)) {
    throw new Error("RFC3161_VERIFIER_TOKEN is missing or invalid.");
  }
  const publicKeys = String(env.RFC3161_VERIFIER_PUBLIC_KEYS || env.RFC3161_VERIFIER_PUBLIC_KEY || "")
    .split(",").map((value) => value.trim()).filter(Boolean);
  if (!publicKeys.length || publicKeys.length > 5) {
    throw new Error("One to five RFC 3161 verifier public keys must be configured.");
  }
  for (const publicKey of publicKeys) {
    await importP256Spki(publicKey, "Every RFC 3161 verifier key must be a canonical base64 P-256 SPKI public key.");
  }
  const anchors = String(env.RFC3161_TSA_TRUST_ANCHOR_SHA256 || "")
    .split(",").map((value) => value.trim().toLowerCase()).filter(Boolean);
  if (!anchors.length || anchors.length > 10 || anchors.some((value) => !/^[a-f0-9]{64}$/.test(value))) {
    throw new Error("One to ten SHA-256 TSA trust-anchor fingerprints must be configured.");
  }
  return {
    tsaOrigin: tsaUrl.origin,
    verifierOrigin: verifierUrl.origin,
    verifierKeyCount: publicKeys.length,
    trustAnchorCount: anchors.length,
  };
}
