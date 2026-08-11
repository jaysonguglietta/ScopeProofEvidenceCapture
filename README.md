# Scopeproof

Scopeproof is a private, multi-framework compliance evidence-operations application with first-class PCI DSS workflows. It collects live configuration evidence from AWS, GitHub, Okta, Cloudflare, and browser-rendered administration pages; scans sensitive content; encrypts artifacts; records an append-only audit chain; and produces independently verifiable assessor packages.

The repository contains two coordinated products:

- A private web console for collection orchestration, review, encrypted storage, audit history, and signed exports.
- **Scopeproof Capture 1.3.2** for macOS, a menu-bar application for explicitly initiated, timestamped, redacted, control-mapped screenshots and Jira handoff.

## Documentation

| Audience | Guide |
| --- | --- |
| Evidence collectors and reviewers | [Operator guide](docs/OPERATOR_GUIDE.md) |
| Jira/GRC coordinators | [Jira evidence handoff](docs/JIRA_HANDOFF.md) |
| External assessors | [Assessor package and verification guide](docs/ASSESSOR_GUIDE.md) |
| Platform administrators | [Deployment and administration](docs/DEPLOYMENT.md) |
| Security and risk teams | [Security model and operating controls](docs/SECURITY.md) |
| Engineers and maintainers | [Architecture](docs/ARCHITECTURE.md) and [development guide](docs/DEVELOPMENT.md) |
| Release managers | [Changelog](CHANGELOG.md) |

The native-specific build and usage reference remains in [macos/ScopeproofCapture/README.md](macos/ScopeproofCapture/README.md). The macOS application also includes **Help & How to Use…** in its shield menu.

## Run the local Mac app

On macOS 14 or newer, run this from the repository root:

```bash
./Scripts/run_macos_capture.sh
```

The command builds Scopeproof Capture, installs it in your personal `~/Applications` folder, and launches it. It does not require an administrator password. Look for the shield in the menu bar.

The first time you capture, macOS may ask for Screen Recording access. Allow **Scopeproof Capture** under **System Settings → Privacy & Security → Screen & System Audio Recording**, then quit and reopen the app. If the command reports that Swift is missing, run `xcode-select --install`, complete Apple’s installer, and run the command again.

## Security architecture

- Authentication uses private Sites identity headers only on exact canonical origins configured in `TRUSTED_APP_ORIGINS`; API routes reject anonymous, direct-origin, preview-origin, and malformed identities.
- Roles are `admin`, `compliance_lead`, `reviewer`, and `auditor`, with explicit server-side permissions. Reviewers approve but cannot collect or disclose; compliance leads collect and disclose but cannot approve. No identity can approve its own evidence.
- Evidence is redacted before persistence, encrypted with AES-256-GCM, and stored in R2. D1 stores metadata and integrity digests.
- Audit events are hash-chained, HMAC-authenticated, and protected from update/delete by SQLite triggers.
- Assessor ZIPs embed approved artifacts, a PDF index, SHA-256 hashes, and an ECDSA P-256 signed manifest with its public verification key.
- Mutating routes enforce same-origin requests. Worker responses add CSP, HSTS, no-sniff, referrer, and permissions headers.
- Revocable Mac device tokens are stored as SHA-256 hashes server-side. Native uploads use a device-token HMAC over the exact manifest and PNG digests; the server derives metadata from the signed manifest and strictly decodes the PNG before storage.

## Provider evidence

- AWS: Config recorder settings and EC2 security group inventory using SigV4.
- GitHub: organization repository inventory and default-branch protection.
- Okta: global sign-on/MFA policies and access-review group inventory.
- Cloudflare: WAF managed rulesets for scoped zones.
- Browser capture: Cloudflare Browser Rendering produces one immutable full-page PNG, then an approved OCR service scans those exact digest-bound pixels. Captures fail closed if OCR is unavailable, the digest differs, or detected pixels contain PANs or secrets.

Collectors run on demand and from a 15-minute scheduler. Transient failures retry up to three times with bounded exponential backoff; authentication and unsafe-content failures require operator action.

## Native screenshot evidence

The menu-bar app in `macos/ScopeproofCapture` captures a user-selected browser window or display through ScreenCaptureKit. Raw pixels remain in memory. Scopeproof runs local Vision OCR, masks detected PANs and credentials, adds the full evidence header, scans the composited image again, presents those pixels for irreversible manual redaction, then re-scans the exact encoded PNG before atomically writing it. Scan failure prevents saving or upload. Capture presets, evidence owner/tags, expected-evidence guidance, catalog versions, and curated cross-framework mappings reduce classification drift.

The PNG is paired with an immutable JSON manifest containing its SHA-256 digest and local chain-of-custody hashes. Review decisions are stored separately in a hash-chained lifecycle sidecar with Draft, In Review, Approved, Rejected, and Superseded states. An optional Jira issue key is carried into the filename, visible banner, manifest, search, hosted metadata, and package index. Search supports thumbnails plus framework, control, Jira issue, status, date, system, owner, tag, and keyword discovery, and can copy a ticket-ready Jira comment with the approved attachment checklist and integrity hash. Enrolled devices can upload reviewed evidence directly; the client authenticates the exact manifest/image pair, and the server rejects alternate multipart metadata, malformed/polyglot PNGs, dimension mismatches, broken capture-chain hashes, and unknown manifest schemas before preserving metadata or bytes. Configure `RFC3161_TSA_URL` to include an external timestamp-authority token.

The Mac app can build a local approved-only assessor ZIP filtered by framework and assessment period. It revalidates artifact hashes and review chains, organizes content by framework/control, and embeds a Read Me, CSV index, Jira handoff guide, ECDSA-signed manifest, verification instructions, capture manifests, lifecycle records, and server receipts. Hosted packages use the same framework-aware organization and also include a PDF index.

Jira Cloud uses hosted OAuth 2.0 authorization-code flow with rotating refresh tokens. OAuth tokens are encrypted under a Jira-specific key and never enter the Mac app; user-bound state, fixed Atlassian API hosts, site matching, project allowlists, and optimistic refresh leases constrain the connection. Operators connect Jira under **Connections**, approve an artifact locally, upload those exact bytes to Scopeproof, obtain hosted reviewer approval, and explicitly choose **Search Evidence… → Upload to Jira Cloud…**. The server revalidates both approvals, the issue, allowlist, PNG hash, safety state, and lifecycle chain before reserving an idempotent attachment operation and recording a signed immutable receipt. Ambiguous Jira outcomes stop for reconciliation instead of blindly retrying. **Copy Jira Comment** and manual attachment remain available as a fallback; uploads never run automatically.

The app includes **Help & How to Use…**, recent capture history, offline retry, configurable retention, Launch at Login, Screen Recording recovery, and secure release checks.

## Configuration

Copy `.env.example` to `.env` for local work and configure equivalent hosted secrets in Sites. Never commit credentials.

Required platform secrets:

- `EVIDENCE_ENCRYPTION_KEY`: base64-encoded 32-byte AES key.
- `AUDIT_HMAC_KEY`: high-entropy audit-chain secret.
- `PACKAGE_SIGNING_PRIVATE_KEY`: base64 PKCS#8 ECDSA P-256 private key.
- `PACKAGE_SIGNING_PUBLIC_KEY`: base64 SPKI ECDSA P-256 public key.

Provider-specific values are documented in `.env.example`. Browser capture additionally requires `BROWSER_OCR_ENDPOINT`, `BROWSER_OCR_TOKEN`, and an exact `BROWSER_OCR_ALLOWED_HOSTS` allowlist; the OCR service must return the submitted PNG digest, recognized text, and a policy version. Use read-only, least-privilege credentials and limit browser targets to dedicated evidence URLs that do not expose cardholder data.

Native release values are `MACOS_LATEST_VERSION`, `MACOS_RELEASE_URL`, `MACOS_RELEASE_SHA256`, and `MACOS_RELEASE_NOTES`. `RFC3161_TSA_URL` is optional. Device enrollment and revocation are managed in **Connections → Mac capture devices**.

Jira Cloud requires `JIRA_OAUTH_CLIENT_ID`, `JIRA_OAUTH_CLIENT_SECRET`, an exact `JIRA_OAUTH_CALLBACK_URL`, and a distinct base64-encoded 32-byte `JIRA_OAUTH_TOKEN_ENCRYPTION_KEY`. Create one OAuth 2.0 (3LO) integration in the Atlassian developer console with `read:jira-work` and `write:jira-work`; Scopeproof requests `offline_access` for rotating refresh tokens.

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

Apply all D1 migrations in order from `drizzle/`. D1 and R2 logical bindings are declared in `.openai/hosting.json` and provisioned by Sites.

To build the local menu-bar app without installing or launching it, use:

```bash
./Scripts/build_macos_capture.sh
```

See the [development guide](docs/DEVELOPMENT.md) for repository layout, migrations, validation, and release practices.

## Operational limits

- Arbitrary manual binary uploads remain rejected. The authenticated native route accepts only PNGs produced by a reviewed Scopeproof capture manifest after local OCR/redaction.
- Packages include at most 100 approved artifacts and 25 MB of decrypted evidence, and expire after seven days.
- Provider pagination and collection breadth are intentionally bounded to resist API and memory exhaustion.
- Rotate encryption and signing keys through a documented key-rotation process before replacing them; existing artifacts require their original key version to remain decryptable.
- Developer ID signing, Apple notarization, a hosted release URL, and an external RFC 3161 service require production credentials and are not part of an ad-hoc local build.
