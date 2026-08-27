# Hosted macOS authentication security contract

`HostedOAuth.swift` and `HostedTokenStore.swift` provide the reviewed, non-networking security boundary for the planned hosted Scopeproof sign-in. They are intentionally not wired into `AppDelegate` yet because the token/JWKS, signed discovery, server membership, and device-enrollment boundaries listed below are not complete.

## Intended integration

1. Obtain a reviewed, authenticated tenant configuration containing the immutable tenant ID, Cognito issuer, managed-login authorization/token endpoints, public app-client ID, exact callback URL, and scopes. Do not accept this configuration from an unauthenticated deep link or arbitrary user-entered JSON.
2. Register the exact custom callback scheme in the signed app bundle. Use `ASWebAuthenticationSession` to open the URL returned by `HostedOAuthCoordinator.begin`. The coordinator keeps the state, PKCE verifier, and OIDC nonce in memory for no more than ten minutes; the default is five minutes.
3. Give the returned callback URL to `HostedOAuthCoordinator.consume`. A valid callback is one-shot and returns a `HostedOAuthAuthorizationGrant`.
4. Send `grant.tokenRequest()` with an ephemeral `URLSession`. Reject redirects, bound response size, require the configured token endpoint as the final response origin, and parse only a JSON token response with `Cache-Control: no-store` handling.
5. Cryptographically verify the ID-token signature against the issuer's pinned/discovered JWKS, plus `iss`, `aud`, `exp`, `iat`, token use, and `grant.expectedIDTokenNonce`. Do not derive tenant authorization solely from email domain or an unverified JWT payload. Resolve the user-to-tenant membership at the hosted API.
6. Keep access and ID tokens in memory. Store only a rotating refresh token with `HostedKeychainRefreshTokenStore`, which uses `WhenUnlockedThisDeviceOnly` and does not synchronize through iCloud. Delete it on sign-out, tenant removal, issuer/client changes, or server revocation.
7. Send the access token only to the exact configured Scopeproof API origin. The backend must validate the token and independently enforce tenant isolation for every API, database, cache, job, and S3 operation.

## Security properties already implemented

- Public-client authorization-code flow with S256 PKCE; no client-secret field or request parameter exists.
- 256-bit state and nonce plus a 512-bit verifier from `SecRandomCopyBytes`.
- Canonical public HTTPS issuer and endpoint validation; authorization and token endpoints must share an exact origin.
- Exact callback scheme, host, and percent-encoded path matching; user info, ports, fragments, alternate paths, duplicate parameters, and unknown parameters are rejected.
- Constant-time state comparison, short pending lifetime, replacement on a new sign-in, and one-shot consumption.
- Tenant IDs, display names, email-domain hints, client IDs, and scopes are bounded and validated.
- Refresh credentials are bound to tenant, issuer, and public-client ID in a device-only Keychain item. No AWS key or OAuth client secret can be saved through this abstraction.

## Work deliberately left for integration

- `ASWebAuthenticationSession` UI and app callback registration.
- Token-endpoint network execution and redirect/response controls.
- JWKS retrieval, cache/rotation policy, JWT signature and claims validation, and OIDC nonce checking.
- Refresh-token exchange, rotation/reuse detection, revocation, and logout.
- Device enrollment/attestation and hosted API audience binding.
- An authenticated/signed tenant-configuration delivery channel and configuration rollback protection.
- Server-side membership, authorization, rate limiting, audit logging, and tenant data isolation.

The existing loopback Local Console remains local-only. These primitives are for a separate hosted sync/login workflow and are not a reason to bind that server to a non-loopback interface.
