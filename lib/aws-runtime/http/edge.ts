import { TenantSecurityError } from "../contracts.ts";
import { canonicalHostname } from "../tenancy.ts";
import type { ApiGatewayV2Event, TrustedEdgeAuthorityVerifier } from "./api.ts";

const encoder = new TextEncoder();

export interface EdgeReplayNonceStore {
  /** Returns true only for the first atomic insertion of this nonce. */
  consume(nonce: string, expiresAtEpochSeconds: number): Promise<boolean>;
}

export interface HmacTrustedEdgeVerifierOptions {
  readonly secret: Uint8Array;
  readonly replayNonces: EdgeReplayNonceStore;
  readonly maximumAgeSeconds?: number;
  readonly futureClockSkewSeconds?: number;
  readonly now?: () => Date;
}

function failure(): TenantSecurityError {
  return new TenantSecurityError("UNTRUSTED_HOST_SOURCE", "Tenant hostname did not come from the trusted edge.", 421);
}

function edgeHeaders(event: ApiGatewayV2Event): ReadonlyMap<string, string> {
  const headers = new Map<string, string>();
  for (const [rawName, rawValue] of Object.entries(event.headers || {})) {
    const name = rawName.toLowerCase();
    if (headers.has(name) || typeof rawValue !== "string" || rawValue.length > 1_024 || /\p{Cc}/u.test(rawValue)) throw failure();
    headers.set(name, rawValue);
  }
  return headers;
}

function signatureBytes(value: string): Uint8Array {
  const match = /^v1=([A-Za-z0-9_-]{43})$/.exec(value);
  if (!match) throw failure();
  try {
    const binary = atob(match[1].replaceAll("-", "+").replaceAll("_", "/") + "=");
    if (binary.length !== 32) throw failure();
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    const canonical = btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
    if (canonical !== match[1]) throw failure();
    return bytes;
  } catch {
    throw failure();
  }
}

export function edgeProofCanonicalValue(input: Readonly<{
  viewerHost: string;
  requestId: string;
  method: string;
  rawPath: string;
  timestamp: string;
  nonce: string;
}>): string {
  return ["scopeproof-edge-v1", input.viewerHost, input.requestId, input.method, input.rawPath, input.timestamp, input.nonce].join("\n");
}

export class HmacTrustedEdgeAuthorityVerifier implements TrustedEdgeAuthorityVerifier {
  readonly #key: Promise<CryptoKey>;
  readonly #replayNonces: EdgeReplayNonceStore;
  readonly #maximumAgeSeconds: number;
  readonly #futureClockSkewSeconds: number;
  readonly #now: () => Date;

  constructor(options: HmacTrustedEdgeVerifierOptions) {
    if (!(options.secret instanceof Uint8Array) || options.secret.byteLength < 32 || options.secret.byteLength > 256) throw new Error("Trusted-edge HMAC secret must contain 32-256 bytes.");
    const maximumAgeSeconds = options.maximumAgeSeconds ?? 60;
    const futureClockSkewSeconds = options.futureClockSkewSeconds ?? 5;
    if (!Number.isSafeInteger(maximumAgeSeconds) || maximumAgeSeconds < 10 || maximumAgeSeconds > 300) throw new Error("Trusted-edge proof lifetime is invalid.");
    if (!Number.isSafeInteger(futureClockSkewSeconds) || futureClockSkewSeconds < 0 || futureClockSkewSeconds > 30) throw new Error("Trusted-edge clock skew is invalid.");
    const secret = new Uint8Array(options.secret);
    this.#key = crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["verify"])
      .finally(() => secret.fill(0));
    this.#replayNonces = options.replayNonces;
    this.#maximumAgeSeconds = maximumAgeSeconds;
    this.#futureClockSkewSeconds = futureClockSkewSeconds;
    this.#now = options.now ?? (() => new Date());
  }

  async verify(event: ApiGatewayV2Event): Promise<Readonly<{ viewerHost: string }>> {
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/.test(event.requestContext?.requestId || "") || !/^(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(event.requestContext?.http?.method || "") || !/^\/[A-Za-z0-9._~!$&'()*+,;=:@/-]{0,2047}$/.test(event.rawPath || "") || /[\r\n]/.test(event.rawPath || "")) throw failure();
    const headers = edgeHeaders(event);
    let viewerHost: ReturnType<typeof canonicalHostname>;
    try {
      viewerHost = canonicalHostname(headers.get("x-scopeproof-edge-host") || "");
    } catch {
      throw failure();
    }
    const timestamp = headers.get("x-scopeproof-edge-timestamp") || "";
    const nonce = headers.get("x-scopeproof-edge-nonce") || "";
    const signature = signatureBytes(headers.get("x-scopeproof-edge-signature") || "");
    if (!/^\d{10}$/.test(timestamp) || !/^[A-Za-z0-9_-]{16,128}$/.test(nonce)) throw failure();
    const issuedAt = Number(timestamp);
    const now = Math.floor(this.#now().getTime() / 1_000);
    if (!Number.isSafeInteger(issuedAt) || issuedAt < now - this.#maximumAgeSeconds || issuedAt > now + this.#futureClockSkewSeconds) throw failure();
    const canonical = edgeProofCanonicalValue({ viewerHost, requestId: event.requestContext.requestId, method: event.requestContext.http.method, rawPath: event.rawPath, timestamp, nonce });
    let valid = false;
    try {
      valid = await crypto.subtle.verify("HMAC", await this.#key, signature.buffer.slice(signature.byteOffset, signature.byteOffset + signature.byteLength) as ArrayBuffer, encoder.encode(canonical));
    } catch {
      throw failure();
    }
    if (!valid) throw failure();
    const firstUse = await this.#replayNonces.consume(nonce, issuedAt + this.#maximumAgeSeconds + this.#futureClockSkewSeconds);
    if (!firstUse) throw failure();
    return Object.freeze({ viewerHost });
  }
}
