/** Shared structural validation for the legacy single-tenant identity edge. */
export function validateTrustedApplicationOrigins(
  value: string | undefined,
  options: Readonly<{ allowLoopbackHttp?: boolean }> = {},
): Set<string> {
  const raw = String(value || "");
  const values = raw.split(",").map((entry) => entry.trim()).filter(Boolean);
  if (values.length !== 1) throw new Error("Exactly one trusted application origin is required for the single-tenant runtime.");
  const origins = new Set<string>();
  for (const value of values) {
    let url: URL;
    try { url = new URL(value); } catch { throw new Error("Trusted application origins are not safely configured."); }
    const local = options.allowLoopbackHttp !== false && url.protocol === "http:" && ["localhost", "127.0.0.1", "::1"].includes(url.hostname);
    if ((!local && url.protocol !== "https:") || url.username || url.password || url.search || url.hash || (url.pathname !== "/" && url.pathname !== "")) {
      throw new Error("Trusted application origins are not safely configured.");
    }
    origins.add(url.origin);
  }
  return origins;
}

export function validateBootstrapAdministratorAllowlist(value: string | undefined): Set<string> {
  const raw = String(value || "");
  const values = raw.split(",").map((entry) => entry.trim().toLowerCase()).filter(Boolean);
  if (!values.length || values.length > 20 || values.some((entry) => entry.includes("*") || entry.length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(entry))) {
    throw new Error("Administrator bootstrap allowlist is not safely configured.");
  }
  return new Set(values);
}
