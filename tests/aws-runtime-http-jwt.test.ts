import assert from "node:assert/strict";
import test from "node:test";

import { CognitoJwtVerifier, exactBearerToken } from "../lib/aws-runtime/http/index.ts";
import { TenantSecurityError } from "../lib/aws-runtime/contracts.ts";

const ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_Example";
const CLIENT_ID = "scopeproof-client-123";
const NOW_MILLISECONDS = Date.parse("2026-08-27T16:00:00.000Z");
const NOW_SECONDS = NOW_MILLISECONDS / 1_000;

interface SigningKey {
  readonly kid: string;
  readonly privateKey: CryptoKey;
  readonly jwk: JsonWebKey;
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

async function signingKey(kid: string): Promise<SigningKey> {
  const pair = await crypto.subtle.generateKey({
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2_048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  }, true, ["sign", "verify"]) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    kid,
    privateKey: pair.privateKey,
    jwk: { ...exported, kid, alg: "RS256", use: "sig", key_ops: ["verify"] } as JsonWebKey,
  };
}

function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    iss: ISSUER,
    sub: "248289761001",
    client_id: CLIENT_ID,
    token_use: "access",
    auth_time: NOW_SECONDS - 120,
    iat: NOW_SECONDS - 60,
    nbf: NOW_SECONDS - 60,
    exp: NOW_SECONDS + 600,
    jti: "token-id-12345678",
    scope: "openid evidence:read",
    ...overrides,
  };
}

async function compact(key: SigningKey, payload: Record<string, unknown>, header: Record<string, unknown> = { alg: "RS256", kid: key.kid, typ: "JWT" }): Promise<string> {
  return compactRaw(key, JSON.stringify(header), JSON.stringify(payload));
}

async function compactRaw(key: SigningKey, headerJson: string, payloadJson: string): Promise<string> {
  const header = base64Url(new TextEncoder().encode(headerJson));
  const payload = base64Url(new TextEncoder().encode(payloadJson));
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key.privateKey, new TextEncoder().encode(`${header}.${payload}`));
  return `${header}.${payload}.${base64Url(new Uint8Array(signature))}`;
}

function jwksFetch(keys: readonly SigningKey[], calls?: { value: number }): typeof fetch {
  return (async () => {
    if (calls) calls.value += 1;
    return new Response(JSON.stringify({ keys: keys.map((key) => key.jwk) }), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
}

function verifier(keys: readonly SigningKey[], options: Partial<ConstructorParameters<typeof CognitoJwtVerifier>[0]> = {}): CognitoJwtVerifier {
  return new CognitoJwtVerifier({
    issuer: ISSUER,
    clientIds: [CLIENT_ID],
    maximumAuthenticationAgeSeconds: 3_600,
    now: () => new Date(NOW_MILLISECONDS),
    fetch: jwksFetch(keys),
    ...options,
  });
}

function securityCode(code: string): (error: unknown) => boolean {
  return (error: unknown): boolean => {
    assert.ok(error instanceof TenantSecurityError);
    assert.equal(error.code, code);
    assert.equal(error.safeStatus, 401);
    return true;
  };
}

test("Cognito verifier accepts a correctly signed, client-bound access token", async () => {
  const key = await signingKey("cognito-key-1");
  const verified = await verifier([key]).verify(await compact(key, claims()));
  assert.equal(verified.signatureVerified, true);
  assert.equal(verified.issuer, ISSUER);
  assert.equal(verified.clientId, CLIENT_ID);
  assert.equal(verified.subject, "248289761001");
  assert.deepEqual(verified.scopes, ["openid", "evidence:read"]);
  assert.equal(verified.authenticatedAt, "2026-08-27T15:58:00.000Z");
});

test("Cognito verifier rejects algorithm confusion, embedded key references, and forged signatures", async () => {
  const trusted = await signingKey("trusted-key");
  const attacker = await signingKey("attacker-key");
  const verify = verifier([trusted]);
  await assert.rejects(verify.verify(await compact(trusted, claims(), { alg: "none", kid: trusted.kid })), securityCode("INVALID_PRINCIPAL"));
  await assert.rejects(verify.verify(await compact(trusted, claims(), { alg: "HS256", kid: trusted.kid })), securityCode("INVALID_PRINCIPAL"));
  await assert.rejects(verify.verify(await compact(trusted, claims(), { alg: "RS256", kid: trusted.kid, jku: "https://attacker.invalid/jwks" })), securityCode("INVALID_PRINCIPAL"));
  await assert.rejects(verify.verify(await compact(attacker, claims(), { alg: "RS256", kid: trusted.kid })), securityCode("INVALID_PRINCIPAL"));
});

test("Cognito verifier rejects wrong issuer, client, token use, and unexpected audience", async () => {
  const key = await signingKey("claims-key");
  const verify = verifier([key]);
  for (const override of [
    { iss: "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_Attacker" },
    { client_id: "another-client" },
    { token_use: "id" },
    { aud: CLIENT_ID },
  ]) {
    await assert.rejects(verify.verify(await compact(key, claims(override))), securityCode("INVALID_PRINCIPAL"));
  }
});

test("Cognito verifier enforces exp, nbf, iat, authentication age, and token lifetime", async () => {
  const key = await signingKey("time-key");
  const verify = verifier([key]);
  for (const override of [
    { exp: NOW_SECONDS - 31 },
    { nbf: NOW_SECONDS + 31 },
    { iat: NOW_SECONDS + 31 },
    { auth_time: NOW_SECONDS - 3_631 },
    { auth_time: NOW_SECONDS, iat: NOW_SECONDS - 60 },
    { iat: NOW_SECONDS - 3_601, exp: NOW_SECONDS + 1 },
  ]) {
    await assert.rejects(verify.verify(await compact(key, claims(override))), securityCode("INVALID_PRINCIPAL"));
  }
});

test("Cognito verifier rejects duplicate security claims and malformed compact encodings", async () => {
  const key = await signingKey("strict-json-key");
  const duplicateIssuer = `{"iss":${JSON.stringify(ISSUER)},"iss":"https://attacker.invalid","sub":"248289761001","client_id":${JSON.stringify(CLIENT_ID)},"token_use":"access","auth_time":${NOW_SECONDS - 120},"iat":${NOW_SECONDS - 60},"exp":${NOW_SECONDS + 600}}`;
  await assert.rejects(verifier([key]).verify(await compactRaw(key, JSON.stringify({ alg: "RS256", kid: key.kid }), duplicateIssuer)), securityCode("INVALID_PRINCIPAL"));
  await assert.rejects(verifier([key]).verify("not.a.jwt.with.extra.parts"), securityCode("INVALID_PRINCIPAL"));
  await assert.rejects(verifier([key]).verify("a".repeat(16_385)), securityCode("INVALID_PRINCIPAL"));
});

test("JWKS cache supports bounded key rotation and throttles unknown-kid refreshes", async () => {
  const first = await signingKey("rotation-key-1");
  const second = await signingKey("rotation-key-2");
  const unknown = await signingKey("rotation-key-3");
  let keys: readonly SigningKey[] = [first];
  let clock = NOW_MILLISECONDS;
  const calls = { value: 0 };
  const fetcher = (async () => {
    calls.value += 1;
    return new Response(JSON.stringify({ keys: keys.map((key) => key.jwk) }), { status: 200, headers: { "content-type": "application/jwk-set+json" } });
  }) as typeof fetch;
  const verify = verifier([], {
    fetch: fetcher,
    now: () => new Date(clock),
    minimumJwksRefreshIntervalMilliseconds: 1_000,
    jwksCacheTtlMilliseconds: 60_000,
  });
  await verify.verify(await compact(first, claims()));
  await verify.verify(await compact(first, claims({ jti: "token-id-cache-hit" })));
  assert.equal(calls.value, 1);

  clock += 1_001;
  keys = [second];
  await verify.verify(await compact(second, claims({ iat: NOW_SECONDS, auth_time: NOW_SECONDS, exp: NOW_SECONDS + 600 })));
  assert.equal(calls.value, 2);
  await assert.rejects(verify.verify(await compact(unknown, claims())), securityCode("INVALID_PRINCIPAL"));
  assert.equal(calls.value, 2, "random kids cannot force another refresh inside the cooldown");
});

test("exact Bearer parsing rejects ambiguity and control characters", () => {
  const token = `${"a".repeat(20)}.${"b".repeat(20)}.${"c".repeat(20)}`;
  assert.equal(exactBearerToken(`Bearer ${token}`), token);
  for (const value of [undefined, `bearer ${token}`, `Bearer  ${token}`, `Bearer ${token} trailing`, `Bearer ${token},Bearer ${token}`, `Bearer ${token}\n`]) {
    assert.throws(() => exactBearerToken(value), securityCode("INVALID_PRINCIPAL"));
  }
});

test("JWKS responses fail closed on duplicate kids and non-signing key metadata", async () => {
  const key = await signingKey("duplicate-key");
  await assert.rejects(verifier([key, key]).verify(await compact(key, claims())), securityCode("INVALID_PRINCIPAL"));
  const invalid = { ...key, jwk: { ...key.jwk, use: "enc" } };
  await assert.rejects(verifier([invalid]).verify(await compact(key, claims())), securityCode("INVALID_PRINCIPAL"));
});
