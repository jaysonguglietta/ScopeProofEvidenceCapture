export function validatePortalConfiguration(value, origin) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Portal configuration is unavailable.");
  const keys = ["tenantId", "webOrigin", "apiOrigin", "oauthOrigin", "clientId", "scopes"];
  if (Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) throw new Error("Portal configuration has missing or unsupported fields.");
  for (const field of ["webOrigin", "apiOrigin", "oauthOrigin"]) {
    const url = new URL(value[field]);
    if (url.protocol !== "https:" || url.origin !== value[field] || url.username || url.password || url.port || !/^[a-z0-9.-]+$/u.test(url.hostname)) throw new Error("Portal endpoints must be exact HTTPS origins.");
  }
  if (value.webOrigin !== origin || value.apiOrigin === value.webOrigin || !/^ten_[a-f0-9]{32}$/u.test(value.tenantId)
    || !/^[a-z0-9]{5,128}$/u.test(value.clientId) || !Array.isArray(value.scopes) || !value.scopes.length || value.scopes.length > 16
    || value.scopes.some((scope) => typeof scope !== "string" || !/^[a-zA-Z0-9._:/-]{1,128}$/u.test(scope))) throw new Error("This hostname is not bound to a valid tenant application.");
  return Object.freeze({ ...value, scopes: Object.freeze([...value.scopes]) });
}

export function validateLoginTransaction(transaction, config, state, now = Date.now()) {
  if (!transaction || transaction.origin !== config.webOrigin || transaction.clientId !== config.clientId || transaction.oauthOrigin !== config.oauthOrigin
    || typeof state !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(state) || transaction.state !== state
    || !/^[A-Za-z0-9_-]{43}$/u.test(transaction.verifier) || !Number.isSafeInteger(transaction.createdAt)
    || transaction.createdAt > now || now - transaction.createdAt > 600000) throw new Error("Sign-in request expired or does not match this browser and tenant. Start sign-in again.");
  return transaction;
}

export async function boundedBytes(response, maximumBytes) {
  if (!response.ok || !response.body) throw new Error(`Request failed (${response.status}).`);
  const declared = response.headers.get("content-length");
  if (declared && (!/^\d+$/u.test(declared) || Number(declared) > maximumBytes)) { await response.body.cancel(); throw new Error("Response exceeds the safe size limit."); }
  const reader = response.body.getReader(); const chunks = []; let count = 0;
  try {
    while (true) { const { done, value } = await reader.read(); if (done) break; count += value.byteLength; if (count > maximumBytes) throw new Error("Response exceeds the safe size limit."); chunks.push(value); }
  } catch (error) { await reader.cancel().catch(() => {}); throw error; }
  finally { reader.releaseLock(); }
  const result = new Uint8Array(count); let offset = 0;
  for (const chunk of chunks) { result.set(chunk, offset); offset += chunk.byteLength; }
  return result;
}

export function validateDownloadIntent(intent, evidence) {
  const url = new URL(intent.download?.url);
  if (intent.evidenceId !== evidence.evidenceId || intent.revision !== evidence.revision || intent.expectedSha256 !== evidence.checksumSha256
    || intent.expectedSize !== evidence.byteSize || intent.contentType !== evidence.contentType || !Number.isSafeInteger(intent.expectedSize) || intent.expectedSize < 1 || intent.expectedSize > 25 * 1024 * 1024
    || !/^[a-f0-9]{64}$/u.test(intent.expectedSha256) || intent.download.method !== "GET"
    || !Number.isFinite(Date.parse(intent.expiresAt)) || Date.parse(intent.expiresAt) <= Date.now() || Date.parse(intent.expiresAt) > Date.now() + 900000
    || url.protocol !== "https:" || url.username || url.password || url.port || url.hash
    || !/^[a-z0-9.-]+\.s3(?:-fips)?\.[a-z0-9-]+\.amazonaws\.com(?:\.cn)?$/u.test(url.hostname)
    || url.searchParams.getAll("versionId").length !== 1 || !url.searchParams.get("versionId") || url.searchParams.get("versionId") === "null"
    || Object.entries(intent.download.requiredHeaders || {}).some(([key, value]) => key.toLowerCase() !== "x-amz-checksum-mode" || value !== "ENABLED")) throw new Error("Download intent does not match the exact reviewed artifact/version.");
  return url;
}
