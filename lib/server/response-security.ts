export const APPLICATION_CONTENT_SECURITY_POLICY = "default-src 'self'; base-uri 'self'; object-src 'none'; form-action 'self'; frame-ancestors 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'";

/** Add platform-wide headers without weakening a stricter route-specific policy. */
export function hardenedResponseHeaders(source: HeadersInit, requestURL: string): Headers {
  const headers = new Headers(source);
  const url = new URL(requestURL);
  headers.set("x-content-type-options", "nosniff");
  headers.set("referrer-policy", "strict-origin-when-cross-origin");
  headers.set("permissions-policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  if (!headers.has("content-security-policy")) headers.set("content-security-policy", APPLICATION_CONTENT_SECURITY_POLICY);
  if (url.protocol === "https:") headers.set("strict-transport-security", "max-age=31536000; includeSubDomains");
  if (url.pathname.startsWith("/api/")) headers.set("cache-control", "private, no-store");
  return headers;
}
