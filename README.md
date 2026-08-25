# Scopeproof

Scopeproof is a private, multi-framework compliance evidence-operations application with first-class PCI DSS workflows. It collects live configuration evidence from AWS, GitHub, Okta, Cloudflare, and browser-rendered administration pages; scans sensitive content; encrypts artifacts; records an append-only audit chain; and produces independently verifiable assessor packages.

The repository contains two coordinated products:

- A private web console for collection orchestration, review, encrypted storage, audit history, and signed exports.
- **Scopeproof Capture 1.8.1** for macOS, a local-first menu-bar application with a private evidence console, explicitly initiated timestamped/redacted screenshots, one-time repository SBOM export, KMS/Object-Lock S3 evidence storage, version-aware verified downloads, assessor packaging, optional hosted synchronization, and Jira handoff.

## Documentation

| Audience | Guide |
| --- | --- |
| Mac users and endpoint administrators | [macOS installation and updates](docs/MACOS_INSTALLATION.md) |
| Evidence collectors and reviewers | [Operator guide](docs/OPERATOR_GUIDE.md) |
| Jira/GRC coordinators | [Jira evidence handoff](docs/JIRA_HANDOFF.md) |
| External assessors | [Assessor package and verification guide](docs/ASSESSOR_GUIDE.md) |
| Software inventory operators | [Repository SBOM generation](docs/SBOM_GUIDE.md) |
| AWS storage administrators | [AWS S3 evidence storage](docs/S3_STORAGE.md) |
| Platform administrators | [Deployment and administration](docs/DEPLOYMENT.md) |
| Security and risk teams | [Security model and operating controls](docs/SECURITY.md) |
| Engineers and maintainers | [Architecture](docs/ARCHITECTURE.md) and [development guide](docs/DEVELOPMENT.md) |
| Release managers | [Changelog](CHANGELOG.md) |

The native-specific build and usage reference remains in [macos/ScopeproofCapture/README.md](macos/ScopeproofCapture/README.md). The macOS application also includes **Help & How to Use…** in its shield menu.

## Download the Mac app

[**Download the latest Scopeproof Capture DMG**](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/download/v1.8.1-development-preview.1/Scopeproof-Capture-1.8.1-development-preview.dmg) · [SHA-256 checksum](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/download/v1.8.1-development-preview.1/Scopeproof-Capture-1.8.1-development-preview.dmg.sha256) · [All releases](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases)

The current [Scopeproof Capture 1.8.1 development preview](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/tag/v1.8.1-development-preview.1) includes a drag-to-Applications DMG and a separate SHA-256 checksum. It supports Apple Silicon (`arm64`) Macs running macOS 14 or newer. Download both release assets, verify the checksum as described in the [macOS installation guide](docs/MACOS_INSTALLATION.md), open the DMG, and drag **Scopeproof Capture** into **Applications**.

This preview is ad-hoc signed and is not Apple-notarized. macOS may therefore require an explicit **Open Anyway** decision after verification. It is for evaluation and named testers, not managed production deployment. A public production release still requires Developer ID signing, hardened runtime, notarization, and stapling.

## Build the local Mac app from source

On macOS 14 or newer, run this from the repository root:

```bash
./Scripts/run_macos_capture.sh
```

The command builds Scopeproof Capture, installs it in your personal `~/Applications` folder, and launches it. This source-build path requires Apple's Swift toolchain but does not require an administrator password. The DMG path above installs into `/Applications` and does not require a repository checkout or Swift. In either case, the app starts a loopback-only Local Console and opens it in your browser; no hosted login or device token is required for local capture, search, lifecycle review, or assessor export. Look for the shield in the menu bar to reopen the console or capture evidence.

The first time you capture, macOS may ask for Screen Recording access. Allow **Scopeproof Capture** under **System Settings → Privacy & Security → Screen & System Audio Recording**, then quit and reopen the app. If the command reports that Swift is missing, run `xcode-select --install`, complete Apple’s installer, and run the command again.

## Security architecture

- Authentication uses private Sites identity headers only on exact canonical origins configured in `TRUSTED_APP_ORIGINS`; API routes reject anonymous, direct-origin, preview-origin, and malformed identities.
- Roles are `admin`, `compliance_lead`, `reviewer`, and `auditor`, with explicit server-side permissions. Reviewers approve but cannot collect or disclose; compliance leads collect and disclose but cannot approve. No identity can approve its own evidence.
- Evidence is redacted before persistence, encrypted with AES-256-GCM, and stored in R2. D1 stores metadata and integrity digests.
- Audit events are hash-chained, HMAC-authenticated, and protected from update/delete by SQLite triggers.
- Assessor ZIPs embed approved artifacts, a PDF index, SHA-256 hashes, and an ECDSA P-256 signed manifest with its public verification key.
- Mutating routes enforce same-origin requests. Worker responses add CSP, HSTS, no-sniff, referrer, and permissions headers.
- Revocable Mac device tokens are stored as SHA-256 hashes server-side. Native uploads use a device-token HMAC over the exact manifest and PNG digests; the server derives metadata from the signed manifest and strictly decodes the PNG before storage.
- The native Local Console binds only to `127.0.0.1`, requires an ephemeral HttpOnly SameSite session, rejects cross-origin mutations and path input, verifies artifact hashes, and maintains a disposable SQLite index plus an immutable Keychain-HMAC-authenticated local audit chain.
- Optional native S3 storage offers a production profile requiring expiring STS credentials, a Keychain-bound AWS account/destination, Block Public Access, versioning, BucketOwnerEnforced ownership, customer-managed KMS encryption, Object Lock, TLS/KMS bucket-policy enforcement, SHA-256 response verification, and exact-version downloads. The app supports FIPS endpoints, optional Deep Archive/replication, and a deployable CloudTrail alerting template. A documented Compatible S3 migration exception uses a dedicated no-console IAM identity restricted to one bucket/prefix and an S3-only KMS encryption context; production still requires temporary credentials.

## Provider evidence

- AWS: Config recorder settings and EC2 security group inventory using SigV4.
- GitHub: organization repository inventory, default-branch protection, and non-executing CycloneDX 1.6 or SPDX 2.3 generation at an immutable commit.
- Okta: global sign-on/MFA policies and access-review group inventory.
- Cloudflare: WAF managed rulesets for scoped zones.
- Browser capture: Cloudflare Browser Rendering produces one immutable full-page PNG, then an approved OCR service scans those exact digest-bound pixels. Captures fail closed if OCR is unavailable, the digest differs, or detected pixels contain PANs or secrets.

Collectors run on demand and from a 15-minute scheduler. Transient failures retry up to three times with bounded exponential backoff; authentication and unsafe-content failures require operator action.

## Native screenshot evidence

The menu-bar app in `macos/ScopeproofCapture` captures a user-selected browser window or display through ScreenCaptureKit. **Capture Frontmost Browser Window** can read the active Safari, Chrome, Edge, or Arc tab address after an explicit macOS Automation grant, sanitize it, and prefill it for operator confirmation; unsupported or denied detection falls back to an empty manual field. **Capture Scrolling Evidence…** combines two or more operator-positioned viewports into one artifact with numbered continuation dividers; every intermediate frame remains memory-only. Browser-window workflows also capture the live right-side Mac menu-bar pixels containing the date/time and status context and place that strip across the top of the evidence; full-display mode includes the real menu bar directly. Scopeproof runs local Vision OCR, masks detected PANs and credentials, adds the full evidence header—including a canonical capture timestamp, a local clock/timezone reading, and a wrapping full-page-URL line—scans the composited image again, presents those exact pixels for irreversible manual redaction, then re-scans the encoded PNG before atomically writing it. URL credentials and sensitive query/fragment values are redacted before the URL reaches the image or manifest. Scan failure prevents saving or upload. The classification form displays the selected catalog version, source, and control count and provides **Update Controls…** for a bounded, validated Scopeproof JSON, OSCAL JSON, or CSV import from an approved source. Capture presets, evidence owner/tags, expected-evidence guidance, catalog provenance, and curated cross-framework mappings reduce classification drift.

The PNG is paired with an immutable JSON manifest containing its SHA-256 digest and local chain-of-custody hashes. Review state is derived only from schema-2 lifecycle events that bind the artifact digest, reviewer, time, rationale, and policy; inconsistent or legacy-unbound histories cannot be exported. Package signing requires local user presence. An optional Jira issue key is carried into the filename, visible banner, manifest, search, hosted metadata, and package index. Enrolled devices authenticate the exact manifest/image pair, and the server rejects alternate metadata, malformed/polyglot PNGs, dimension mismatches, broken chains, and unknown schemas. RFC 3161 responses are called trusted only when a pinned, allowlisted verifier validates the nonce, imprint, CMS signature, TSA certificate/EKU/path, configured trust anchor, validity, and revocation policy.

The Mac app can build a local approved-only assessor ZIP filtered by framework and assessment period. It revalidates artifact hashes and review chains, organizes content by framework/control, and embeds a Read Me, CSV index, Jira handoff guide, ECDSA-signed manifest, verification instructions, capture manifests, lifecycle records, and server receipts. Hosted packages use the same framework-aware organization and also include a PDF index.

Jira Cloud uses hosted OAuth 2.0 authorization-code flow with rotating refresh tokens. OAuth tokens are encrypted under a Jira-specific key and never enter the Mac app; user-bound state, fixed Atlassian API hosts, site matching, project allowlists, and optimistic refresh leases constrain the connection. Operators connect Jira under **Connections**, approve an artifact locally, upload those exact bytes to Scopeproof, obtain hosted reviewer approval, and explicitly choose **Search Evidence… → Upload to Jira Cloud…**. The server revalidates both approvals, the issue, allowlist, PNG hash, safety state, and lifecycle chain before reserving an idempotent attachment operation and recording a signed immutable receipt. Ambiguous Jira outcomes stop for reconciliation instead of blindly retrying. **Copy Jira Comment** and manual attachment remain available as a fallback; uploads never run automatically.

The app opens its **Local Console** at launch by default. The console provides overview metrics, preview cards, framework/control/status filters, lifecycle review, evidence reveal, local workspace status, and Help. The original PNG/manifests/lifecycle sidecars remain authoritative; SQLite is only a rebuildable search/audit index. Hosted upload remains optional. The app also includes native search, recent history, offline retry, configurable retention, Launch at Login, Screen Recording recovery, and secure release checks.

## Configuration

Copy `.env.example` to `.env` for local work and configure equivalent hosted secrets in Sites. Never commit credentials.

Required platform secrets:

- `EVIDENCE_ENCRYPTION_KEY`: base64-encoded 32-byte AES key.
- `AUDIT_HMAC_KEY`: high-entropy audit-chain secret.
- `PACKAGE_SIGNING_PRIVATE_KEY`: base64 PKCS#8 ECDSA P-256 private key.
- `PACKAGE_SIGNING_PUBLIC_KEY`: base64 SPKI ECDSA P-256 public key.

Provider-specific values are documented in `.env.example`. Browser capture additionally requires `BROWSER_OCR_ENDPOINT`, `BROWSER_OCR_TOKEN`, and an exact `BROWSER_OCR_ALLOWED_HOSTS` allowlist; the OCR service must return the submitted PNG digest, recognized text, and a policy version. Use read-only, least-privilege credentials and limit browser targets to dedicated evidence URLs that do not expose cardholder data.

Repository SBOM generation is available in two places. The hosted console supports managed organization access or an exact one-time GitHub URL and token, then creates assessment-scoped evidence with review, comparison, approval, and package inclusion. The Mac shield menu also provides **Generate Repository SBOM…** for a direct one-time CycloneDX or SPDX export plus checksum without a hosted account. In both one-time modes the masked token is cleared on submission and never persisted. Use a repository-scoped credential with only **Metadata: read** and **Contents: read**, then revoke it after the run. See the [repository SBOM guide](docs/SBOM_GUIDE.md) for workflow differences, supported lockfiles, safety limits, and auditor interpretation.

Native updates use `MACOS_RELEASE_MANIFEST_JSON`, `MACOS_RELEASE_SIGNATURE_DER_BASE64`, and `MACOS_RELEASE_ALLOWED_HOSTS`. The signed manifest binds the version, monotonic sequence, URL, digest, size, validity window, release key, Developer ID team, and designated requirement. The Mac downloads without credentials or redirects and locally verifies the signature, digest, code identity, Gatekeeper acceptance, and stapled notarization before opening the local ZIP. RFC 3161 requires the TSA and pinned-verifier settings documented in `.env.example`; configuring only a TSA URL does not create trusted time. Device enrollment and revocation are managed in **Connections → Mac capture devices**.

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
- Repository SBOM generation accepts only repositories in the configured GitHub organization, resolves refs to immutable commits, never executes repository code, and enforces archive, decompression, manifest, component, request, and retry limits.
- API mutations and expensive reads have database-backed per-principal and IP quotas; multipart bodies require a bounded `Content-Length`. Provider calls have 60-second and response-byte limits, and collection jobs use expiring atomic leases.
- Evidence is unavailable immediately at expiry. The scheduler deletes expired encrypted objects and packages; an administrator may create a reasoned, owned, time-bounded legal hold before expiry through `PUT /api/evidence/:id/retention` and release it through `DELETE`.
- CSV files are presentation aids with formula-trigger prefixes neutralized. Signed JSON manifests remain authoritative.
- Rotate encryption and signing keys through a documented key-rotation process before replacing them; existing artifacts require their original key version to remain decryptable.
- Developer ID signing, Apple notarization, an offline P-256 update key whose public key is compiled into `Info.plist`, a hosted release URL, and an external RFC 3161 service require production credentials and are not part of an ad-hoc local build.
