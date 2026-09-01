export type EvidenceSafetyEnvironment = {
  BROWSER_OCR_ENDPOINT?: string;
  BROWSER_OCR_TOKEN?: string;
  BROWSER_OCR_ALLOWED_HOSTS?: string;
};

export class EvidenceSafetyScanError extends Error {
  readonly code: "NOT_CONFIGURED" | "UNSAFE_ENDPOINT" | "UNAVAILABLE" | "INVALID_RESPONSE" | "SENSITIVE_CONTENT";
  readonly retryable: boolean;

  constructor(message: string, code: EvidenceSafetyScanError["code"], retryable: boolean) {
    super(message);
    this.code = code;
    this.retryable = retryable;
  }
}

function configured(value: string | undefined, name: string): string {
  if (!value) throw new EvidenceSafetyScanError(`${name} is not configured.`, "NOT_CONFIGURED", false);
  return value;
}

export function evidenceSafetyScannerToken(env: EvidenceSafetyEnvironment): string {
  const token = configured(env.BROWSER_OCR_TOKEN, "BROWSER_OCR_TOKEN");
  if (token !== token.trim() || token.length < 16 || token.length > 4_096 || /\p{Cc}/u.test(token)) {
    throw new EvidenceSafetyScanError("BROWSER_OCR_TOKEN is malformed.", "UNSAFE_ENDPOINT", false);
  }
  return token;
}

export function evidenceSafetyScannerEndpoint(env: EvidenceSafetyEnvironment): URL {
  let endpoint: URL;
  try { endpoint = new URL(configured(env.BROWSER_OCR_ENDPOINT, "BROWSER_OCR_ENDPOINT")); }
  catch (error) {
    if (error instanceof EvidenceSafetyScanError) throw error;
    throw new EvidenceSafetyScanError("The evidence OCR endpoint is invalid.", "UNSAFE_ENDPOINT", false);
  }
  const hosts = configured(env.BROWSER_OCR_ALLOWED_HOSTS, "BROWSER_OCR_ALLOWED_HOSTS")
    .split(",").map((host) => host.trim().toLowerCase()).filter(Boolean);
  const allowedHosts = new Set(hosts);
  const invalidHost = hosts.length === 0 || hosts.length > 20 || hosts.some((host) => {
    const ipv4Literal = host.split(".").length === 4
      && host.split(".").every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
    return host.length > 253 || host === "localhost" || host.endsWith(".localhost") || ipv4Literal
      || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/.test(host);
  });
  if (invalidHost || endpoint.protocol !== "https:" || endpoint.username || endpoint.password
    || endpoint.search || endpoint.hash || endpoint.port || !allowedHosts.has(endpoint.hostname.toLowerCase())) {
    throw new EvidenceSafetyScanError(
      "The evidence OCR endpoint must be a clean HTTPS URL on an explicitly approved host.",
      "UNSAFE_ENDPOINT",
      false,
    );
  }
  return endpoint;
}

export function validateEvidenceSafetyScannerConfiguration(env: EvidenceSafetyEnvironment): { origin: string } {
  const endpoint = evidenceSafetyScannerEndpoint(env);
  evidenceSafetyScannerToken(env);
  return Object.freeze({ origin: endpoint.origin });
}
