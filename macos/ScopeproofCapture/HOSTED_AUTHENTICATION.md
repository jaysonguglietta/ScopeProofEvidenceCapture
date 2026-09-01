# Hosted macOS authentication and evidence trust contract

Scopeproof has two deliberately separate native boundaries:

- The shipping local workflow uses the menu-bar app, device-only Keychain identities, local evidence files, and the authenticated loopback Local Console. It does not require hosted sign-in, an independent hosted scanner, an RFC 3161 authority, D1/R2, Cognito, S3, or AWS.
- Optional synchronization to the current hosted service uses an audience-bound capture-device enrollment token. Production acceptance then adds schema-7 device provenance, independent exact-pixel OCR/DLP, a trusted RFC 3161 timestamp, and final server-side device-chain linkage.

`HostedOAuth.swift` and `HostedTokenStore.swift` are still non-networking primitives for a future interactive Cognito user sign-in. They are not the credential path used by the current device-upload workflow and are intentionally not wired into `AppDelegate`. The AWS source defines a public native Cognito client and tenant-aware API contracts, but signed discovery, native token/JWKS/session execution, device-enrollment integration, and production activation remain incomplete. No AWS resources have been deployed by this repository work.

## Current capture-device authentication

1. An administrator enrolls one Mac in **Connections → Mac capture devices** and copies the one-time `spdev_dev_…` token. The service retains only the token verifier/hash.
2. The operator enters the exact HTTPS Scopeproof Server URL and token under **Capture & Jira Settings…**. The origin must already appear in the signed app's `ScopeproofHostedAPIOrigins` allowlist. The checked-in `Info.plist` intentionally has an empty array; a release operator populates one exact pathless HTTPS origin with `SCOPEPROOF_HOSTED_API_ORIGIN` through `Scripts/configure_macos_release_identity.sh`. A normal local release build is therefore local-only and does not default to a developer, personal, or historical service. Development-only debug builds may use loopback HTTP for integration testing. The app binds the credential to that origin and stores it as `WhenUnlockedThisDeviceOnly` in macOS Keychain; changing origins requires a newly issued token and a release approved for the new origin.
3. For each upload, the app sends the token as a bearer credential and derives an HMAC over the exact manifest and image digests. The hosted API independently resolves the active, unrevoked device, token audience, owner, role, permission, and rate limit.
4. The enrollment token is not the evidence-provenance key. New captures use a separate device-only P-256 signing identity. The app signs the canonical schema-7 manifest, whose fields bind the exact PNG digest, manifest metadata, local safety claim, contiguous chain sequence, previous hash, and event hash.

Revoke the capture device when the Mac is lost, reassigned, or compromised. Rotate the 30-day enrollment token before expiry. A token rotation does not rewrite provenance, and a provenance-key change must begin a new explicitly authorized device/chain epoch rather than silently replacing the pinned key.

## Production hosted-ingestion gate

The server must perform the following steps for the exact submitted PNG/manifest pair:

1. Reject every manifest except schema 7; validate bounded canonical fields, PNG structure/dimensions, filenames/content types, image and safety digests, enrollment-token HMAC, P-256 provenance signature/key ID, local event hash, capture-session ownership/scope, and exactly one active assessment.
2. Independently scan the exact PNG through the HTTPS OCR/DLP service configured by `BROWSER_OCR_ENDPOINT`, `BROWSER_OCR_TOKEN`, and `BROWSER_OCR_ALLOWED_HOSTS`. These names are retained for compatibility and cover native screenshots too. The response digest must equal the submitted PNG digest. Recognized text is inspected transiently for sensitive patterns and is never retained in evidence, database rows, audit events, receipts, monitoring, or logs. Only the policy version, exact digest, scanner origin, completion time, and receipt digest are retained.
3. Obtain and verify the required RFC 3161 timestamp using the configured TSA and independent verifier trust material. A Scopeproof server-time signature is useful receipt metadata but is not a substitute for the production timestamp control.
4. Reserve the next contiguous device-chain sequence and matching previous hash, store the encrypted artifact plus digest-bound scan/timestamp metadata, then finalize the immutable device/evidence/manifest/image/event/provenance-key link.

Production readiness must fail when the independent scanner is missing or unsafe, when `REQUIRE_TRUSTED_TIMESTAMP` is false or invalid, or when RFC 3161 issuer/verifier trust material is incomplete. A scanner or required-timestamp failure returns a recoverable error and stores no new artifact. If storage succeeds but final chain linkage does not, the hosted record remains quarantined.

Every server-side read/preview, approval, package/export, and native Jira route must re-evaluate the independent scan binding and final device-chain link. A UI status, client safety claim, local approval, or object presence is not sufficient. An authenticated reviewer cannot approve an unbound item, and Jira cannot disclose it.

## Upgrade, quarantine, and reconciliation

Apply and verify migrations through `0023_independent_image_safety.sql` before enabling production native uploads:

- `0020_native_device_chain.sql` introduces the device signing-key and chain reservation state.
- `0022_native_provenance_quarantine.sql` records immutable schema-7 sequence/event/key finalization and prevents native manifest updates/deletes.
- `0023_independent_image_safety.sql` records the exact digest-bound server safety result.

Unsigned schema-6 captures remain an explicit, visibly unverified local browsing/migration path and cannot be uploaded as trusted evidence. Recapture them with the current Mac application. Existing hosted artifacts without the independent scan or finalized device-chain link remain quarantined and must be re-uploaded/rescanned from the original exact current pair. Never manufacture scan receipts, backfill provenance fields, directly change approval status, or blanket-grandfather old rows.

## Future interactive hosted user sign-in

When interactive native user access is implemented, preserve this contract:

1. Obtain a reviewed, authenticated tenant configuration containing the immutable tenant ID, Cognito issuer, managed-login authorization/token endpoints, public app-client ID, exact callback URL, and scopes. Do not accept configuration from an unauthenticated deep link or arbitrary user-entered JSON.
2. Register the exact callback scheme in the signed app bundle and use `ASWebAuthenticationSession` with authorization code plus S256 PKCE. `HostedOAuthCoordinator` keeps state, verifier, and nonce in memory for no more than ten minutes and consumes a matching callback once.
3. Exchange the code through an ephemeral, redirect-rejecting, size-bounded session whose final response remains on the exact configured token origin.
4. Verify the JWT signature against trusted issuer JWKS plus `iss`, `aud`, `exp`, `iat`, token use, and OIDC nonce. Never infer tenant authorization from email domain or an unverified payload; resolve active membership and role server-side for every request.
5. Keep access and ID tokens in memory. Store only a rotating refresh token with `HostedKeychainRefreshTokenStore` (`WhenUnlockedThisDeviceOnly`) and delete it on sign-out, tenant removal, issuer/client change, or revocation.
6. Send access tokens only to the exact configured API origin. Enforce tenant isolation independently in every API, database query, cache, job, and S3 operation.

The implemented primitives already provide canonical HTTPS issuer/endpoint validation, exact callback matching, strong random state/nonce/verifier values, constant-time state comparison, short one-shot transactions, bounded tenant/client/scope data, S256 PKCE, and device-only refresh-token storage. Remaining launch work includes authenticated signed discovery with rollback protection, `ASWebAuthenticationSession` UI/callback registration, token/JWKS network execution and rotation, refresh-token reuse/revocation handling, complete route-level rate limiting/audit coverage, and live two-tenant isolation validation.

The Local Console must remain loopback-only. Neither capture-device synchronization nor future Hosted OAuth is a reason to expose it on a LAN or internet interface.
