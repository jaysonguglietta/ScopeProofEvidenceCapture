# Scopeproof

Scopeproof is a private PCI DSS evidence-operations application. It collects live configuration evidence from AWS, GitHub, Okta, Cloudflare, and browser-rendered administration pages; scans sensitive content; encrypts artifacts; records an append-only audit chain; and produces independently verifiable assessor packages.

## Security architecture

- Authentication uses the private Sites identity headers. API routes reject anonymous requests.
- RBAC roles are `admin`, `compliance_lead`, `reviewer`, and `auditor`. Authorization is enforced server-side.
- Evidence is redacted before persistence, encrypted with AES-256-GCM, and stored in R2. D1 stores metadata and integrity digests.
- Audit events are hash-chained, HMAC-authenticated, and protected from update/delete by SQLite triggers.
- Assessor ZIPs embed approved artifacts, a PDF index, SHA-256 hashes, and an ECDSA P-256 signed manifest with its public verification key.
- Mutating routes enforce same-origin requests. Worker responses add CSP, HSTS, no-sniff, referrer, and permissions headers.
- Revocable Mac device tokens are stored as SHA-256 hashes server-side. Native uploads must carry a reviewed safety state and matching PNG digest.

## Provider evidence

- AWS: Config recorder settings and EC2 security group inventory using SigV4.
- GitHub: organization repository inventory and default-branch protection.
- Okta: global sign-on/MFA policies and access-review group inventory.
- Cloudflare: WAF managed rulesets for scoped zones.
- Browser capture: Cloudflare Browser Rendering content preflight followed by a full-page screenshot. Captures are blocked if the rendered DOM contains detected PANs or secrets.

Collectors run on demand and from a 15-minute scheduler. Transient failures retry up to three times with bounded exponential backoff; authentication and unsafe-content failures require operator action.

## Native screenshot evidence

The menu-bar app in `macos/ScopeproofCapture` captures a user-selected browser window or display through ScreenCaptureKit. Each capture requires PCI session context, runs local Vision OCR, masks detected PANs and credentials, adds a visible local date/time/timezone and control stamp, and requires preview approval before saving.

The PNG is paired with a JSON manifest containing its SHA-256 digest and local chain-of-custody hashes. Enrolled devices can upload reviewed evidence directly; the server validates the manifest and image, encrypts the artifact, records an immutable audit event, and returns a signed server-time receipt. Configure `RFC3161_TSA_URL` to include an external timestamp-authority token.

The app includes **Help & How to Use…**, recent capture history, offline retry, configurable retention, Launch at Login, Screen Recording recovery, and secure release checks. See `macos/ScopeproofCapture/README.md` for the operator workflow.

## Configuration

Copy `.env.example` to `.env` for local work and configure equivalent hosted secrets in Sites. Never commit credentials.

Required platform secrets:

- `EVIDENCE_ENCRYPTION_KEY`: base64-encoded 32-byte AES key.
- `AUDIT_HMAC_KEY`: high-entropy audit-chain secret.
- `PACKAGE_SIGNING_PRIVATE_KEY`: base64 PKCS#8 ECDSA P-256 private key.
- `PACKAGE_SIGNING_PUBLIC_KEY`: base64 SPKI ECDSA P-256 public key.

Provider-specific values are documented in `.env.example`. Use read-only, least-privilege provider credentials and limit browser targets to dedicated evidence URLs that do not expose cardholder data.

Native release values are `MACOS_LATEST_VERSION`, `MACOS_RELEASE_URL`, `MACOS_RELEASE_SHA256`, and `MACOS_RELEASE_NOTES`. `RFC3161_TSA_URL` is optional. Device enrollment and revocation are managed in **Connections → Mac capture devices**.

## Development

```bash
npm install
npm run dev
```

Validation:

```bash
npm run lint
npx tsc --noEmit
npm test
```

Apply both D1 migrations in order from `drizzle/`. D1 and R2 logical bindings are declared in `.openai/hosting.json` and provisioned by Sites.

Build the local menu-bar app with:

```bash
./Scripts/build_macos_capture.sh
```

## Operational limits

- Arbitrary manual binary uploads remain rejected. The authenticated native route accepts only PNGs produced by a reviewed Scopeproof capture manifest after local OCR/redaction.
- Packages include at most 100 approved artifacts and 25 MB of decrypted evidence, and expire after seven days.
- Provider pagination and collection breadth are intentionally bounded to resist API and memory exhaustion.
- Rotate encryption and signing keys through a documented key-rotation process before replacing them; existing artifacts require their original key version to remain decryptable.
- Developer ID signing, Apple notarization, a hosted release URL, and an external RFC 3161 service require production credentials and are not part of an ad-hoc local build.
