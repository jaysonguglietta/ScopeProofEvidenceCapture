import { TenantSecurityError } from "../contracts.ts";

const encoder = new TextEncoder();
const kidPattern = /^[A-Za-z0-9_.:+/=_~-]{1,128}$/;
const clientIdPattern = /^[A-Za-z0-9_.:+/=_~-]{3,128}$/;
const subjectPattern = /^[^\p{Cc}]{3,200}$/u;

export interface VerifiedCognitoAccessToken {
  readonly signatureVerified: true;
  readonly issuer: string;
  readonly subject: string;
  readonly clientId: string;
  readonly tokenUse: "access";
  readonly issuedAt: string;
  readonly authenticatedAt: string;
  readonly expiresAt: string;
  readonly scopes: readonly string[];
  readonly jwtId?: string;
}

export interface CognitoJwtVerifierOptions {
  readonly issuer: string;
  readonly clientIds: readonly string[];
  readonly maximumAuthenticationAgeSeconds: number;
  readonly maximumTokenLifetimeSeconds?: number;
  readonly clockSkewSeconds?: number;
  readonly maximumTokenBytes?: number;
  readonly jwksCacheTtlMilliseconds?: number;
  readonly minimumJwksRefreshIntervalMilliseconds?: number;
  readonly jwksTimeoutMilliseconds?: number;
  readonly fetch?: typeof fetch;
  readonly now?: () => Date;
}

interface JwtHeader {
  readonly alg: "RS256";
  readonly kid: string;
  readonly typ?: "JWT";
}

interface JsonWebKeySet {
  readonly keys: readonly JsonWebKey[];
}

interface CachedKeySet {
  readonly loadedAt: number;
  readonly expiresAt: number;
  readonly keys: ReadonlyMap<string, CryptoKey>;
}

function authFailure(message = "Authentication token is invalid."): TenantSecurityError {
  return new TenantSecurityError("INVALID_PRINCIPAL", message, 401);
}

function validatedCognitoIssuer(value: string): string {
  const issuer = String(value || "");
  const match = /^https:\/\/cognito-idp\.([a-z0-9-]+)\.(amazonaws\.com(?:\.cn)?)\/([A-Za-z0-9_-]{3,128})$/.exec(issuer);
  if (!match || !match[3].startsWith(`${match[1]}_`)) throw new Error("Cognito issuer must be an exact HTTPS user-pool issuer.");
  if (match[1].startsWith("cn-") !== match[2].endsWith(".cn")) throw new Error("Cognito issuer partition is invalid.");
  return issuer;
}

function assertIntegerClaim(value: unknown, label: string, required = true): number | undefined {
  if (value === undefined && !required) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < 0) throw authFailure(`${label} claim is invalid.`);
  return value as number;
}

function decodeBase64Url(value: string, maximumBytes: number, label: string): Uint8Array {
  if (!value || value.length > Math.ceil(maximumBytes * 4 / 3) + 4 || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw authFailure(`${label} is malformed.`);
  }
  const padding = (4 - (value.length % 4)) % 4;
  let binary: string;
  try {
    binary = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat(padding));
  } catch {
    throw authFailure(`${label} is malformed.`);
  }
  if (binary.length > maximumBytes) throw authFailure(`${label} is too large.`);
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  const canonical = btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
  if (canonical !== value) throw authFailure(`${label} is not canonically encoded.`);
  return bytes;
}

function skipWhitespace(source: string, cursor: { value: number }): void {
  while (/\s/.test(source[cursor.value] || "")) cursor.value += 1;
}

function scanString(source: string, cursor: { value: number }): string {
  if (source[cursor.value] !== "\"") throw authFailure("JWT JSON is malformed.");
  const start = cursor.value;
  cursor.value += 1;
  while (cursor.value < source.length) {
    const character = source[cursor.value];
    if (character === "\"") {
      cursor.value += 1;
      try {
        return JSON.parse(source.slice(start, cursor.value)) as string;
      } catch {
        throw authFailure("JWT JSON is malformed.");
      }
    }
    if (character === "\\") {
      cursor.value += 1;
      if (source[cursor.value] === "u") {
        if (!/^[0-9a-fA-F]{4}$/.test(source.slice(cursor.value + 1, cursor.value + 5))) throw authFailure("JWT JSON is malformed.");
        cursor.value += 5;
      } else {
        if (!/["\\/bfnrt]/.test(source[cursor.value] || "")) throw authFailure("JWT JSON is malformed.");
        cursor.value += 1;
      }
      continue;
    }
    if (character.charCodeAt(0) < 32) throw authFailure("JWT JSON is malformed.");
    cursor.value += 1;
  }
  throw authFailure("JWT JSON is malformed.");
}

function scanValue(source: string, cursor: { value: number }, depth: number): void {
  if (depth > 16) throw authFailure("JWT JSON is too deeply nested.");
  skipWhitespace(source, cursor);
  const character = source[cursor.value];
  if (character === "\"") {
    scanString(source, cursor);
    return;
  }
  if (character === "{") {
    scanObject(source, cursor, depth + 1);
    return;
  }
  if (character === "[") {
    cursor.value += 1;
    skipWhitespace(source, cursor);
    if (source[cursor.value] === "]") {
      cursor.value += 1;
      return;
    }
    let count = 0;
    while (cursor.value < source.length) {
      if (count >= 200) throw authFailure("JWT JSON contains too many values.");
      scanValue(source, cursor, depth + 1);
      count += 1;
      skipWhitespace(source, cursor);
      if (source[cursor.value] === "]") {
        cursor.value += 1;
        return;
      }
      if (source[cursor.value] !== ",") throw authFailure("JWT JSON is malformed.");
      cursor.value += 1;
    }
    throw authFailure("JWT JSON is malformed.");
  }
  const remainder = source.slice(cursor.value);
  const primitive = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(remainder)?.[0];
  if (!primitive) throw authFailure("JWT JSON is malformed.");
  cursor.value += primitive.length;
}

function scanObject(source: string, cursor: { value: number }, depth: number): void {
  if (source[cursor.value] !== "{") throw authFailure("JWT JSON must be an object.");
  cursor.value += 1;
  skipWhitespace(source, cursor);
  if (source[cursor.value] === "}") {
    cursor.value += 1;
    return;
  }
  const keys = new Set<string>();
  let count = 0;
  while (cursor.value < source.length) {
    if (count >= 100) throw authFailure("JWT JSON contains too many fields.");
    skipWhitespace(source, cursor);
    const key = scanString(source, cursor);
    if (keys.has(key)) throw authFailure("JWT JSON contains a duplicate field.");
    keys.add(key);
    count += 1;
    skipWhitespace(source, cursor);
    if (source[cursor.value] !== ":") throw authFailure("JWT JSON is malformed.");
    cursor.value += 1;
    scanValue(source, cursor, depth + 1);
    skipWhitespace(source, cursor);
    if (source[cursor.value] === "}") {
      cursor.value += 1;
      return;
    }
    if (source[cursor.value] !== ",") throw authFailure("JWT JSON is malformed.");
    cursor.value += 1;
  }
  throw authFailure("JWT JSON is malformed.");
}

export function parseStrictJsonObject(bytes: Uint8Array): Record<string, unknown> {
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw authFailure("JWT JSON is not valid UTF-8.");
  }
  const cursor = { value: 0 };
  skipWhitespace(source, cursor);
  scanObject(source, cursor, 0);
  skipWhitespace(source, cursor);
  if (cursor.value !== source.length) throw authFailure("JWT JSON is malformed.");
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch {
    throw authFailure("JWT JSON is malformed.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw authFailure("JWT JSON must be an object.");
  return parsed as Record<string, unknown>;
}

function exactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

async function readBoundedJson(response: Response, maximumBytes: number): Promise<unknown> {
  const declared = response.headers.get("content-length");
  if (declared && (!/^\d+$/.test(declared) || Number(declared) > maximumBytes)) throw authFailure("Identity key response is too large.");
  if (!response.body) throw authFailure("Identity key response is empty.");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel();
        throw authFailure("Identity key response is too large.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return parseStrictJsonObject(bytes);
}

function validateOptions(options: CognitoJwtVerifierOptions): Required<Omit<CognitoJwtVerifierOptions, "fetch" | "now">> & Pick<CognitoJwtVerifierOptions, "fetch" | "now"> {
  const issuer = validatedCognitoIssuer(options.issuer);
  if (!Array.isArray(options.clientIds) || options.clientIds.length < 1 || options.clientIds.length > 20) throw new Error("At least one bounded Cognito client ID is required.");
  const clientIds = [...new Set(options.clientIds)];
  if (clientIds.length !== options.clientIds.length || clientIds.some((value) => !clientIdPattern.test(value))) throw new Error("Cognito client IDs are invalid or duplicated.");
  const maximumAuthenticationAgeSeconds = options.maximumAuthenticationAgeSeconds;
  const maximumTokenLifetimeSeconds = options.maximumTokenLifetimeSeconds ?? 3_600;
  const clockSkewSeconds = options.clockSkewSeconds ?? 30;
  const maximumTokenBytes = options.maximumTokenBytes ?? 16_384;
  const jwksCacheTtlMilliseconds = options.jwksCacheTtlMilliseconds ?? 3_600_000;
  const minimumJwksRefreshIntervalMilliseconds = options.minimumJwksRefreshIntervalMilliseconds ?? 30_000;
  const jwksTimeoutMilliseconds = options.jwksTimeoutMilliseconds ?? 5_000;
  if (!Number.isSafeInteger(maximumAuthenticationAgeSeconds) || maximumAuthenticationAgeSeconds < 60 || maximumAuthenticationAgeSeconds > 86_400) throw new Error("Maximum authentication age is invalid.");
  if (!Number.isSafeInteger(maximumTokenLifetimeSeconds) || maximumTokenLifetimeSeconds < 60 || maximumTokenLifetimeSeconds > 86_400) throw new Error("Maximum token lifetime is invalid.");
  if (!Number.isSafeInteger(clockSkewSeconds) || clockSkewSeconds < 0 || clockSkewSeconds > 300) throw new Error("JWT clock skew is invalid.");
  if (!Number.isSafeInteger(maximumTokenBytes) || maximumTokenBytes < 1_024 || maximumTokenBytes > 65_536) throw new Error("Maximum JWT size is invalid.");
  if (!Number.isSafeInteger(jwksCacheTtlMilliseconds) || jwksCacheTtlMilliseconds < 60_000 || jwksCacheTtlMilliseconds > 86_400_000) throw new Error("JWKS cache TTL is invalid.");
  if (!Number.isSafeInteger(minimumJwksRefreshIntervalMilliseconds) || minimumJwksRefreshIntervalMilliseconds < 1_000 || minimumJwksRefreshIntervalMilliseconds > jwksCacheTtlMilliseconds) throw new Error("JWKS refresh interval is invalid.");
  if (!Number.isSafeInteger(jwksTimeoutMilliseconds) || jwksTimeoutMilliseconds < 250 || jwksTimeoutMilliseconds > 30_000) throw new Error("JWKS timeout is invalid.");
  return { ...options, issuer, clientIds, maximumAuthenticationAgeSeconds, maximumTokenLifetimeSeconds, clockSkewSeconds, maximumTokenBytes, jwksCacheTtlMilliseconds, minimumJwksRefreshIntervalMilliseconds, jwksTimeoutMilliseconds };
}

export interface CognitoAccessTokenVerifier {
  verify(token: string): Promise<VerifiedCognitoAccessToken>;
}

export class CognitoJwtVerifier implements CognitoAccessTokenVerifier {
  readonly #options: ReturnType<typeof validateOptions>;
  readonly #clientIds: ReadonlySet<string>;
  readonly #jwksUri: string;
  #cache: CachedKeySet | null = null;
  #refreshing: Promise<CachedKeySet> | null = null;

  constructor(options: CognitoJwtVerifierOptions) {
    this.#options = validateOptions(options);
    this.#clientIds = new Set(this.#options.clientIds);
    this.#jwksUri = `${this.#options.issuer}/.well-known/jwks.json`;
  }

  async verify(token: string): Promise<VerifiedCognitoAccessToken> {
    if (typeof token !== "string" || token.length < 64 || token.length > this.#options.maximumTokenBytes || /[\s\p{Cc}]/u.test(token)) throw authFailure();
    const segments = token.split(".");
    if (segments.length !== 3) throw authFailure();
    const headerValue = parseStrictJsonObject(decodeBase64Url(segments[0], 2_048, "JWT header"));
    if (headerValue.alg !== "RS256" || typeof headerValue.kid !== "string" || !kidPattern.test(headerValue.kid)) throw authFailure();
    if (headerValue.typ !== undefined && headerValue.typ !== "JWT") throw authFailure();
    if (headerValue.crit !== undefined || headerValue.jku !== undefined || headerValue.jwk !== undefined || headerValue.x5u !== undefined) throw authFailure();
    const header = headerValue as unknown as JwtHeader;
    const payload = parseStrictJsonObject(decodeBase64Url(segments[1], 12_288, "JWT payload"));
    const signature = decodeBase64Url(segments[2], 1_024, "JWT signature");
    const key = await this.#key(header.kid);
    let verified = false;
    try {
      verified = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, exactArrayBuffer(signature), exactArrayBuffer(encoder.encode(`${segments[0]}.${segments[1]}`)));
    } catch {
      throw authFailure();
    }
    if (!verified) throw authFailure();

    const now = Math.floor((this.#options.now?.() ?? new Date()).getTime() / 1_000);
    const skew = this.#options.clockSkewSeconds;
    const exp = assertIntegerClaim(payload.exp, "exp") as number;
    const iat = assertIntegerClaim(payload.iat, "iat") as number;
    const nbf = assertIntegerClaim(payload.nbf, "nbf", false);
    const authTime = assertIntegerClaim(payload.auth_time, "auth_time") as number;
    if (payload.iss !== this.#options.issuer || payload.token_use !== "access" || typeof payload.client_id !== "string" || !this.#clientIds.has(payload.client_id)) throw authFailure();
    if (typeof payload.sub !== "string" || !subjectPattern.test(payload.sub) || payload.sub !== payload.sub.trim()) throw authFailure();
    if (exp <= now - skew || iat > now + skew || authTime > now + skew || (nbf !== undefined && nbf > now + skew)) throw authFailure("Authentication token is expired or not yet valid.");
    if (exp <= iat || exp - iat > this.#options.maximumTokenLifetimeSeconds) throw authFailure("Authentication token lifetime is invalid.");
    if (now - authTime > this.#options.maximumAuthenticationAgeSeconds + skew || authTime > iat + skew) throw authFailure("Authentication session is too old.");
    if (typeof payload.aud !== "undefined") throw authFailure("Access token contains an unexpected audience claim.");
    if (payload.jti !== undefined && (typeof payload.jti !== "string" || payload.jti.length < 8 || payload.jti.length > 200 || /\p{Cc}/u.test(payload.jti))) throw authFailure();
    const scopes = this.#scopes(payload.scope);
    return Object.freeze({
      signatureVerified: true,
      issuer: this.#options.issuer,
      subject: payload.sub,
      clientId: payload.client_id,
      tokenUse: "access",
      issuedAt: new Date(iat * 1_000).toISOString(),
      authenticatedAt: new Date(authTime * 1_000).toISOString(),
      expiresAt: new Date(exp * 1_000).toISOString(),
      scopes,
      ...(typeof payload.jti === "string" ? { jwtId: payload.jti } : {}),
    });
  }

  #scopes(value: unknown): readonly string[] {
    if (value === undefined) return Object.freeze([]);
    if (typeof value !== "string" || value.length > 2_048 || /\p{Cc}/u.test(value)) throw authFailure("scope claim is invalid.");
    const scopes = value.split(" ").filter(Boolean);
    if (scopes.length > 50 || scopes.some((scope) => !/^[A-Za-z0-9:._/-]{1,128}$/.test(scope))) throw authFailure("scope claim is invalid.");
    return Object.freeze([...new Set(scopes)]);
  }

  async #key(kid: string): Promise<CryptoKey> {
    const now = (this.#options.now?.() ?? new Date()).getTime();
    let cache = this.#cache;
    if (!cache || cache.expiresAt <= now) cache = await this.#refresh(now);
    const existing = cache.keys.get(kid);
    if (existing) return existing;
    if (now - cache.loadedAt >= this.#options.minimumJwksRefreshIntervalMilliseconds) {
      cache = await this.#refresh(now);
      const rotated = cache.keys.get(kid);
      if (rotated) return rotated;
    }
    throw authFailure("Authentication signing key is not trusted.");
  }

  async #refresh(now: number): Promise<CachedKeySet> {
    if (this.#refreshing) return this.#refreshing;
    this.#refreshing = this.#fetchKeys(now);
    try {
      const result = await this.#refreshing;
      this.#cache = result;
      return result;
    } finally {
      this.#refreshing = null;
    }
  }

  async #fetchKeys(now: number): Promise<CachedKeySet> {
    const fetcher = this.#options.fetch ?? fetch;
    let response: Response;
    try {
      response = await fetcher(this.#jwksUri, {
        method: "GET",
        headers: { accept: "application/json" },
        redirect: "error",
        cache: "no-store",
        signal: AbortSignal.timeout(this.#options.jwksTimeoutMilliseconds),
      });
    } catch {
      throw authFailure("Identity signing keys are unavailable.");
    }
    if (!response.ok || response.url && response.url !== this.#jwksUri) throw authFailure("Identity signing keys are unavailable.");
    const contentType = response.headers.get("content-type")?.split(";", 1)[0].trim().toLowerCase();
    if (contentType !== "application/json" && contentType !== "application/jwk-set+json") throw authFailure("Identity signing key response is invalid.");
    const document = await readBoundedJson(response, 64 * 1_024) as unknown as JsonWebKeySet;
    if (!Array.isArray(document.keys) || document.keys.length < 1 || document.keys.length > 16) throw authFailure("Identity signing key response is invalid.");
    const keys = new Map<string, CryptoKey>();
    for (const candidate of document.keys) {
      if (!candidate || typeof candidate !== "object" || candidate.kty !== "RSA" || candidate.alg !== "RS256" || candidate.use !== "sig" || typeof candidate.kid !== "string" || !kidPattern.test(candidate.kid) || typeof candidate.n !== "string" || typeof candidate.e !== "string") throw authFailure("Identity signing key response is invalid.");
      if (candidate.key_ops && (candidate.key_ops.length !== 1 || candidate.key_ops[0] !== "verify")) throw authFailure("Identity signing key response is invalid.");
      if (candidate.e !== "AQAB" || decodeBase64Url(candidate.n, 512, "RSA modulus").byteLength < 256 || "d" in candidate || "p" in candidate || "q" in candidate) throw authFailure("Identity signing key response is invalid.");
      if (keys.has(candidate.kid)) throw authFailure("Identity signing key response contains duplicate identifiers.");
      let imported: CryptoKey;
      try {
        imported = await crypto.subtle.importKey("jwk", candidate, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
      } catch {
        throw authFailure("Identity signing key response is invalid.");
      }
      if (imported.algorithm.name !== "RSASSA-PKCS1-v1_5") throw authFailure("Identity signing key response is invalid.");
      keys.set(candidate.kid, imported);
    }
    return Object.freeze({ loadedAt: now, expiresAt: now + this.#options.jwksCacheTtlMilliseconds, keys });
  }
}

export function exactBearerToken(value: string | undefined, maximumBytes = 16_384): string {
  if (typeof value !== "string" || value.length > maximumBytes + 7 || /\p{Cc}/u.test(value)) throw authFailure("Authorization header is invalid.");
  const match = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/.exec(value);
  if (!match || match[1].length > maximumBytes) throw authFailure("Authorization header is invalid.");
  return match[1];
}
