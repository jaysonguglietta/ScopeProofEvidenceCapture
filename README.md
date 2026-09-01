# Scopeproof

Scopeproof is a private, multi-framework compliance evidence-operations application with first-class PCI DSS workflows. It collects live configuration evidence from AWS, GitHub, Okta, Cloudflare, and browser-rendered administration pages; scans sensitive content; encrypts artifacts; records an append-only audit chain; and produces independently verifiable assessor packages.

The repository contains two coordinated products:

- A private web console for collection orchestration, review, encrypted storage, audit history, and signed exports.
- The **Unreleased Scopeproof Capture 1.10.0 (build 25) source** for macOS, which postdates the public 1.8.1 preview: a local-first menu-bar application with a private evidence console, explicitly initiated timestamped/redacted screenshots, one-time repository SBOM export, KMS/Object-Lock S3 evidence storage, version-aware verified downloads, assessor packaging, optional hosted synchronization, and Jira handoff.

## Documentation

| Audience | Guide |
| --- | --- |
| New Mac users | [Start here: install and use Scopeproof Capture](docs/GETTING_STARTED.md) |
| Mac users and endpoint administrators | [macOS installation and updates](docs/MACOS_INSTALLATION.md) |
| Evidence collectors and reviewers | [Operator guide](docs/OPERATOR_GUIDE.md) |
| Jira/GRC coordinators | [Jira evidence handoff](docs/JIRA_HANDOFF.md) |
| External assessors | [Assessor package and verification guide](docs/ASSESSOR_GUIDE.md) |
| Software inventory operators | [Repository SBOM generation](docs/SBOM_GUIDE.md) |
| AWS storage administrators | [AWS S3 evidence storage](docs/S3_STORAGE.md) |
| AWS identity administrators | [Secretless S3 authentication CloudFormation templates](infra/aws/cloudformation/README.md) |
| AWS platform and SaaS administrators | [AWS multi-tenant hosting](docs/AWS_MULTI_TENANT_HOSTING.md) |
| AWS deployment operators | [AWS platform runbook](docs/AWS_PLATFORM_RUNBOOK.md) |
| Hosted runtime engineers | [AWS runtime security and evidence lifecycle](docs/AWS_RUNTIME_IMPLEMENTATION.md) |
| Recovery and release operators | [AWS recovery and production macOS release](docs/AWS_RECOVERY_AND_MACOS_RELEASE.md) |
| Platform administrators | [Deployment and administration](docs/DEPLOYMENT.md) |
| Security and risk teams | [2026-09-01 remediation status](docs/SECURITY_REMEDIATION_2026-09-01.md), [security model and operating controls](docs/SECURITY.md), [full adversarial security audit](docs/SECURITY_AUDIT_2026-08-28.md), and [AWS adversarial security review](docs/AWS_SECURITY_REVIEW.md) |
| Engineers and maintainers | [Architecture](docs/ARCHITECTURE.md) and [development guide](docs/DEVELOPMENT.md) |
| Release managers | [Changelog](CHANGELOG.md) |

The native-specific build and usage reference remains in [macos/ScopeproofCapture/README.md](macos/ScopeproofCapture/README.md). The macOS application also includes **Help & How to Use…** in its shield menu. For a clean Mac-to-first-evidence walkthrough, use the [complete getting-started guide](docs/GETTING_STARTED.md).

## AWS multi-tenant hosting direction

The selected production target is an AWS-only hosted runtime with explicit tenant subdomains; names such as `acme.jsontechology.com` are illustrative planning examples only and do not claim ownership or configure that domain. The checked-in CDK context leaves `rootDomain` and `deploymentEnvironment` blank and fails synthesis until an operator supplies both, the complete tenant list, an explicit recovery policy, and exactly one reviewed Route 53 choice: an existing `hostedZoneId` (recommended) or the explicit `-c createHostedZone=true` opt-in. The low-idle-cost bridge architecture shares the AWS application/control plane while giving each customer a separate PostgreSQL identity, S3 evidence boundary, KMS key, and IAM role. Route 53 creates a tenant hostname only after provisioning; the hostname selects a tenant candidate, while Cognito identity plus a server-side active membership authorizes access.

The synthable [AWS CDK foundation](infra/aws/cdk/README.md) creates the shared low-idle platform and explicit per-tenant resource boundaries. The [AWS platform runbook](docs/AWS_PLATFORM_RUNBOOK.md) separates local synthesis, reviewed deployment, database provisioning, and customer activation. Infrastructure or database readiness alone does not migrate or authorize the current application.

The repository now includes a production-shaped, tenant-specific API Gateway/
Lambda source path at `api-<tenant>.<domain>`. API Gateway answers `GET /health`
without invoking Lambda; tenant Lambdas serve authenticated `GET /v1/me`,
`POST /v1/upload-intents`, `POST /v1/evidence/search`, and
`POST /v1/evidence-download-intents`. Those protected routes compose strict
Cognito RS256/JWKS validation, an exact web/native app-client allowlist,
operation-specific OAuth scopes, exact hostname binding, active PostgreSQL
membership/RBAC checks, temporary tenant-role credentials, retry-safe
DynamoDB/Aurora upload-intent reconciliation, opaque tenant-bound pagination,
and 60-second exact-version S3 downloads. The client never chooses a hosted
bucket, object key, KMS key, or S3 version. Production tenant synthesis also
requires a configured exact-version DLP service. Promotion sends that service
the immutable quarantine bucket/key/version/digest/size/content type, accepts
only a strict `CLEAN` response, and durably KMS-signs the DLP facts before the
copy can proceed. Promotion then uses KMS-signed receipts and replay-safe
exact-version verification, and reconciles those same facts across S3,
DynamoDB, and PostgreSQL. The repository
also contains a durable two-person `REQUESTED` → `APPROVED` → `APPLYING`
→ `APPLIED` exact-version legal-hold domain workflow with stale-request
expiry, a DynamoDB global control table,
same-account cross-region S3/Aurora recovery with existing-version Batch
Replication and exact replica verification, a protected macOS Developer ID/
notarization workflow, and manual-build Swift CodeQL.

The repository also includes reviewed, opt-in CloudFormation building blocks
for Cognito authorization-code/PKCE clients, IAM Identity Center permission
sets, Cognito Identity Pools, cross-account hosted ingest, IAM Roles Anywhere,
and S3 Access Grants. These templates are alternatives for different trust
models; they are not intended to be deployed together by default.

These are source- and template-tested components, not a live AWS service. No AWS
stack was deployed, no live PostgreSQL/AWS recovery drill was run, and no Apple
artifact was submitted or notarized by this work. The Amplify customer UI still
has no approved source/release connection; membership administration and most
product routes remain absent. The CDK wires authenticated
`POST /v1/legal-hold-requests` and `POST /v1/legal-hold-approvals` to a separate
least-privilege Lambda and schedules an approved-only exact-version reconciler
with KMS-signed audit receipts and failure/age alarms. No legal-hold UI or live
AWS two-tenant test exists; those remain production gates.

> **Existing AWS deployment stop:** the control-plane resource now synthesizes as
> `AWS::DynamoDB::GlobalTable`. Never apply that template directly over a stack
> that already owns the earlier `AWS::DynamoDB::Table`; CloudFormation does not
> perform this resource-type transition as an in-place data-preserving update.
> Use the reviewed retain/remove/convert/import migration in the
> [AWS platform runbook](docs/AWS_PLATFORM_RUNBOOK.md#existing-control-table-migration-stop).
> Fresh deployments are unaffected.

The legacy Sites/D1/R2 source remains a single-tenant runtime until the staged migration and two-tenant security gates in the [AWS multi-tenant hosting guide](docs/AWS_MULTI_TENANT_HOSTING.md) are complete. If it is deployed, it refuses authenticated traffic unless exactly one canonical origin and the explicit `single-tenant-only` acknowledgement are configured. Do not point a second customer hostname at it or reuse its D1, R2, identity, or key boundary for another customer. This repository does not establish that a Sites deployment or private identity dispatcher currently exists.

## Download the older public Mac preview

[**Download the most recent published Scopeproof Capture DMG (older 1.8.1 preview)**](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/download/v1.8.1-development-preview.1/Scopeproof-Capture-1.8.1-development-preview.dmg) · [SHA-256 checksum](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/download/v1.8.1-development-preview.1/Scopeproof-Capture-1.8.1-development-preview.dmg.sha256) · [All releases](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases)

> **Release-state notice — 2026-09-01:** the public
> [Scopeproof Capture 1.8.1 development preview](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/tag/v1.8.1-development-preview.1)
> was built from tag `v1.8.1-development-preview.1` at commit `8cd2d5c`. It
> predates the current **Unreleased 1.10.0 (build 25)** native security, storage, authentication,
> and local-library work and must not be represented as containing those
> changes. In particular, that tagged build writes new evidence under
> `~/Pictures/Scopeproof Evidence` and accepts manually entered AWS credentials;
> it does not provide the current Documents-root or direct AWS CLI IAM Identity
> Center/AssumeRole workflow. These source changes have not been published as a
> 1.10.0 DMG. To evaluate current-source behavior before a new release is
> published, use an exact reviewed commit that contains this documentation, confirm the
> checkout is clean, and build it with `./Scripts/run_macos_capture.sh`.

The older preview includes a drag-to-Applications DMG and a separate SHA-256 checksum. It supports Apple Silicon (`arm64`) Macs running macOS 14 or newer. Download both release assets, verify the checksum as described in the [macOS installation guide](docs/MACOS_INSTALLATION.md), open the DMG, and drag **Scopeproof Capture** into **Applications**.

This preview is ad-hoc signed and is not Apple-notarized. macOS may therefore require an explicit **Open Anyway** decision after verification. It is for evaluation and named testers, not managed production deployment. A public production release still requires Developer ID signing, hardened runtime, notarization, and stapling.

## Build the local Mac app from source

On macOS 14 or newer, run this from the repository root:

```bash
./Scripts/run_macos_capture.sh
```

The command builds Scopeproof Capture, installs it in your personal `~/Applications` folder, and launches it. This source-build path requires Apple's Swift toolchain but does not require an administrator password. The DMG path above installs into `/Applications` and does not require a repository checkout or Swift. In either case, the app starts a loopback-only Local Console and opens it in your browser; no hosted login or device token is required for local capture, search, lifecycle review, or assessor export. Look for the shield in the menu bar to reopen the console or capture evidence.

The checked-in native `Info.plist` contains no hosted API origin. A normal local source build is therefore local-only for HTTPS hosted synchronization; it does not silently contact a personal or historical Scopeproof host. A reviewed production candidate must set one exact pathless HTTPS origin with `SCOPEPROOF_HOSTED_API_ORIGIN` through `./Scripts/configure_macos_release_identity.sh` before it is built. Development-only loopback HTTP remains available for local integration testing.

The first time you capture, macOS may ask for Screen Recording access. Allow **Scopeproof Capture** under **System Settings → Privacy & Security → Screen & System Audio Recording**, then quit and reopen the app. If the command reports that Swift is missing, run `xcode-select --install`, complete Apple’s installer, and run the command again.

## Security architecture

- The legacy application consumes expected platform identity headers only on the one exact canonical origin configured in `TRUSTED_APP_ORIGINS`; `LEGACY_SINGLE_TENANT_ACKNOWLEDGEMENT=single-tenant-only` is also mandatory. Those headers are not cryptographically authenticated by the application. API routes reject anonymous, misrouted, malformed, uninvited, suspended, and revoked identities, but production approval still requires deployed proof that an identity-aware private dispatcher overwrites every caller-supplied identity-header variant and prevents direct Worker, preview, and origin access.
- Roles are `admin`, `compliance_lead`, `reviewer`, and `auditor`, with explicit server-side permissions. Reviewers approve but cannot collect or disclose; compliance leads collect and disclose but cannot approve. No identity can approve its own evidence. Finding maintenance is distinct from final disposition: reviewers can manage findings, while only compliance leads and administrators can accept or close them.
- Hosted assessments use explicit, non-empty system and control scope from a digest-verified versioned catalog. The built-in PCI DSS 4.0.1 Scopeproof operations catalog is intentionally limited and is not represented as the complete standard. Evidence, collection jobs, and SBOMs fail closed when the active assessment scope does not match.
- Review decisions and findings are persisted as audited event streams. Two-person hosted hold release binds a 24-hour request to the exact hold facts and requires a different administrator. Assessor export performs a fail-closed latest-occurrence preflight and final publication fence for eligibility, coverage, independent screenshot safety, native provenance, package bounds, and concurrent changes.
- Evidence is redacted before persistence, encrypted with AES-256-GCM, and stored in R2. D1 stores metadata and integrity digests.
- Audit events are hash-chained, HMAC-authenticated, and protected from update/delete by SQLite triggers. Verification starts from a signed checkpoint only after the checkpoint uses the configured public key, matches the actual D1 audit anchor/count, and has a cryptographically verified independent receipt. Failed same-head witness deliveries retry with a checkpoint-digest idempotency key and append-only delivery attempts; the immutable checkpoint is never rewritten.
- Hosted assessor ZIPs embed approved artifacts, a PDF index, SHA-256 hashes, and an ECDSA P-256 signed manifest with its public verification key. Local Mac assessor ZIPs use the signed manifest and machine-readable indexes described below but do not claim to contain that hosted PDF index.
- Mutating routes enforce same-origin requests. Worker responses add CSP, HSTS, no-sniff, referrer, and permissions headers.
- Revocable Mac device tokens are stored as SHA-256 hashes server-side, expire after 30 days, and can be rotated with immediate invalidation. Native uploads require a schema-8 manifest whose signed tenant/workspace pair exactly matches the isolated deployment, signed with the device's P-256 provenance key plus a device-token HMAC over the exact manifest and PNG digests. The server derives metadata from that signed manifest, strictly decodes the PNG, and atomically advances one monotonic per-device capture chain.
- Every hosted screenshot—whether supplied by Scopeproof Capture or produced by Cloudflare Browser Rendering—is independently scanned on the server through `lib/server/image-safety.ts` before storage. The scanner is configured with the legacy-named `BROWSER_OCR_*` variables, is restricted to one clean HTTPS endpoint on an exact host allowlist, and must echo the exact PNG SHA-256 plus a valid policy version. Scopeproof retains only digest/policy/time/origin/receipt-hash metadata, not recognized OCR text; an unavailable scanner, sensitive finding, digest mismatch, or malformed policy fails closed.
- Native evidence is readable, approvable, package-eligible, and Jira-eligible only after its signed manifest has been committed to the enrolled device's monotonic chain and the artifact has a matching independent server safety receipt. Older schema, unbound, or incompletely finalized native records remain quarantined rather than inheriting trust from client-side OCR or a prior upload.
- Repeated collections of identical bytes create immutable, auditable occurrence records with their own job/device/session provenance and receive time. Scopeproof reuses the encrypted artifact bytes without presenting an old capture as a new collection.
- The native Local Console binds only to `127.0.0.1`. A one-time nonce in the URL fragment is exchanged once for a short-lived in-memory bearer; fragments are not sent in the initial HTTP request and Scopeproof creates no localhost authentication cookie. Protected requests require that bearer and still reject cross-origin mutations and path input, verify artifact hashes, and use a disposable SQLite index plus an immutable Keychain-HMAC-authenticated local audit chain. Its unified library groups local and S3 inventory by control/period/framework, but labels an artifact `Local + S3` only when a local upload receipt binds the exact S3 keys, versions, ETags, checksums, and manifest digest. S3-only pairs remain visibly provenance-unverified; on-demand previews validate the paired exact-version manifest and PNG digest without treating pair consistency as authorship.
- Native capture, hosted device tokens, S3 settings/credentials and prefixes, capture-chain heads, lifecycle anchors, and local legal-hold anchors are bound to one validated tenant/workspace identity. Trust-bearing review and local hold changes require macOS user authentication, record the authenticated subject, and use separate signing/rollback domains. A Keychain-backed capture journal recovers a complete committed set or removes a partial one after interruption.
- Optional native S3 storage offers a production profile requiring expiring STS credentials, a tenant/workspace- and Keychain-bound AWS account/destination, Block Public Access, versioning, BucketOwnerEnforced ownership, an enabled customer-managed symmetric KMS key verified with `DescribeKey`, an SSE-KMS Bucket Key, COMPLIANCE Object Lock, the exact transport/encryption/deletion-deny bucket policy, SHA-256 response verification, and exact-version downloads. The KMS ARN must match the STS-verified bucket-owner account, partition, and Region. Governance is explicitly non-production because privileged identities can bypass it. The preferred desktop path is a named AWS CLI IAM Identity Center profile, optionally followed by one exact AssumeRole; refreshed STS material stays in memory and is re-bound to the verified account, role, tenant, and workspace. Manual STS entry remains available, while long-lived access keys are accepted only by the Compatible S3 migration profile. Local expiry cleanup never trusts a receipt alone: it performs live exact-version checksum, encryption, KMS, ETag, and COMPLIANCE-retention checks before relying on S3 as a durable copy. The app supports FIPS endpoints, optional Deep Archive/replication, a deployable CloudTrail alerting template, and separately reviewed CloudFormation authentication building blocks.

## Provider evidence

- AWS: Config recorder settings and EC2 security group inventory using SigV4.
- GitHub: organization repository inventory, default-branch protection, and non-executing CycloneDX 1.6 or SPDX 2.3 generation at an immutable commit.
- Okta: global sign-on/MFA policies and access-review group inventory.
- Cloudflare: WAF managed rulesets for scoped zones.
- Browser capture: Cloudflare Browser Rendering produces one immutable full-page PNG, then the same independent server safety boundary used for native uploads scans those exact digest-bound pixels. Captures fail closed before storage if the scanner is unavailable, the digest or policy contract differs, or detected pixels contain PANs or secrets.

Collectors run on demand and from a 15-minute scheduler. Transient failures retry up to three times with bounded exponential backoff, but every retry re-checks the requesting user’s current membership and permission. Authentication and unsafe-content failures require operator action. The legacy AWS collector accepts temporary STS credentials only (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`); use the tenant-role path in the AWS runtime for hosted multi-customer collection.

## Native screenshot evidence

The menu-bar app in `macos/ScopeproofCapture` captures a user-selected browser window or display through ScreenCaptureKit. **Capture Frontmost Browser Window** can read the active Safari, Chrome, Edge, or Arc tab address after an explicit macOS Automation grant and prefill it for operator confirmation; unsupported or denied detection falls back to an empty manual field. **Capture Scrolling Evidence…** combines two or more operator-positioned viewports into one artifact with numbered continuation dividers; every intermediate frame remains memory-only. Browser-window workflows also capture the live right-side Mac menu-bar pixels containing the date/time and status context and place that strip across the top of the evidence; full-display mode includes the real menu bar directly. Scopeproof runs local Vision OCR, masks detected PANs and credentials, adds the full evidence header—including a canonical capture timestamp, a local clock/timezone reading, and the source origin—scans the composited image again, presents those exact pixels for irreversible manual redaction, then re-scans the encoded PNG before atomically writing it. Only the lowercase HTTP(S) origin is allowed into evidence: user information, path, query, and fragment are removed before the value reaches the image, manifest, index, or log. Scan failure prevents saving or upload. The classification form displays the selected catalog version, source, and control count and provides **Update Controls…** for a bounded, validated Scopeproof JSON, OSCAL JSON, or CSV import from an approved source. Capture presets, evidence owner/tags, expected-evidence guidance, catalog provenance, and curated cross-framework mappings reduce classification drift.

The PNG is paired with an immutable current-schema JSON manifest containing its tenant/workspace binding, SHA-256 digest, monotonic chain sequence/hash, and ECDSA P-256/SHA-256 provenance signature. Current lifecycle events bind the artifact digest, authenticated macOS reviewer subject, authentication method/time, rationale, and policy, and advance a separate Keychain rollback anchor; inconsistent, unsigned, or legacy-unbound histories cannot be exported. Package signing requires local user presence. An optional Jira issue key is carried into the filename, visible banner, manifest, search, hosted metadata, and package index. Enrolled devices authenticate the exact manifest/image pair, and the server rejects alternate metadata, malformed/polyglot PNGs, dimension mismatches, broken/out-of-order chains, invalid provenance signatures, and unknown schemas. Before any hosted native screenshot is stored, the server independently scans its exact PNG and obtains a digest-bound safety receipt, then requires a trusted RFC 3161 result whose pinned, allowlisted verifier validates the nonce, imprint, CMS signature, TSA certificate/EKU/path, configured trust anchor, validity, and revocation policy. `REQUIRE_TRUSTED_TIMESTAMP=false` is diagnostic-only: it permits troubleshooting with signed server time, but production readiness remains failed.

New native evidence is stored under `~/Documents/Scopeproof Evidence`. Captures under `~/Pictures/Scopeproof Evidence` remain discoverable without an automatic move, but storage location does not confer trust. Schema-8 adds the signed tenant/workspace required by the current hosted boundary. Schema-7 evidence remains locally verifiable under its earlier signed lifecycle rules but cannot be uploaded to that boundary; unsigned schema-6 and older artifacts remain visibly unverified and browsing-only. Recapture older evidence with the current app when it must enter hosted review, package, Jira, or retention workflows. Confirm that Documents-folder access and any iCloud, enterprise-sync, backup, and DLP behavior are approved for the evidence classification.

The Mac app can build a local approved-only assessor ZIP filtered by framework and assessment period. It revalidates artifact hashes and review chains, organizes content by framework/control, and embeds a Read Me, CSV index, Jira handoff guide, ECDSA-signed manifest, verification instructions, capture manifests, lifecycle records, and server receipts. Hosted packages use the same framework-aware organization and also include a PDF index.

Jira Cloud uses hosted OAuth 2.0 authorization-code flow with rotating refresh tokens. OAuth tokens are encrypted under a Jira-specific key and never enter the Mac app; user-bound state, fixed Atlassian API hosts, site matching, project allowlists, and optimistic refresh leases constrain the connection. Operators connect Jira under **Connections**, approve an artifact locally, upload those exact bytes to Scopeproof, obtain hosted reviewer approval, and explicitly choose **Search Evidence… → Upload to Jira Cloud…**. The server revalidates both approvals, the issue, allowlist, PNG hash, safety state, and lifecycle chain before reserving an idempotent attachment operation and recording a signed immutable receipt. Ambiguous Jira outcomes stop for reconciliation instead of blindly retrying. **Copy Jira Comment** and manual attachment remain available as a fallback; uploads never run automatically.

The app opens its **Local Console** at launch by default. The console provides overview metrics, a unified local/S3 screenshot library, storage/framework/control/period/status filters, control/period/framework grouping, lifecycle review for local artifacts, verified local previews, paired-manifest S3 previews with explicit provenance state, evidence reveal, workspace status, and Help. Without a verified S3 configuration it stays local-only; an S3 failure never hides local evidence. The original PNG/manifests/lifecycle sidecars remain authoritative; SQLite is only a rebuildable search/audit index. Hosted upload remains optional. The app also includes native search, recent history, offline retry, configurable retention, Launch at Login, Screen Recording recovery, and secure release checks.

## Configuration

Copy `.env.example` to `.env` for local work and configure equivalent hosted secrets in Sites. Never commit credentials.

Required platform secrets:

- `EVIDENCE_ENCRYPTION_KEY`: base64-encoded 32-byte AES key.
- `AUDIT_HMAC_KEY`: high-entropy audit-chain secret.
- `PACKAGE_SIGNING_PRIVATE_KEY`: base64 PKCS#8 ECDSA P-256 private key.
- `PACKAGE_SIGNING_PUBLIC_KEY`: base64 SPKI ECDSA P-256 public key.

Those four values are the core cryptographic secrets, not the complete
production configuration. A production-ready legacy Sites deployment also
requires the bootstrap/origin/single-tenant boundary, independently signed
checkpoint delivery, a fail-closed security-monitoring receiver, independent
screenshot scanning, and the full trusted RFC 3161 verifier boundary. Configure `BOOTSTRAP_ADMIN_EMAILS`,
`TRUSTED_APP_ORIGINS`, `LEGACY_SINGLE_TENANT_ACKNOWLEDGEMENT`, exact
`LEGACY_TENANT_ID` and `LEGACY_WORKSPACE_ID` values for schema-8 native ingestion, the
`AUDIT_CHECKPOINT_*` endpoint/host/receipt-key values, the
`SECURITY_EVENT_ENDPOINT`, `SECURITY_EVENT_ALLOWED_HOSTS`, and required
structurally valid `SECURITY_EVENT_TOKEN` values, all three
`BROWSER_OCR_*` values, and the `RFC3161_*` issuer/verifier token, host,
public-key, and trust-anchor values exactly as described in the
[deployment guide](docs/DEPLOYMENT.md). Provider and Jira values remain
optional unless those workflows are enabled.

Provider-specific values are documented in `.env.example`. The independent server screenshot scanner for both native uploads and Browser Rendering uses the legacy-named `BROWSER_OCR_ENDPOINT`, `BROWSER_OCR_TOKEN`, and exact `BROWSER_OCR_ALLOWED_HOSTS` allowlist. It must return only the submitted PNG digest, recognized text, and a policy version; Scopeproof scans the text transiently and persists only receipt metadata. Use read-only, least-privilege credentials and limit browser targets to dedicated evidence URLs that do not expose cardholder data.

Repository SBOM generation is available in two places. The hosted console supports managed organization access or an exact one-time GitHub URL and token, then creates assessment-scoped evidence with review, comparison, approval, and package inclusion. The Mac shield menu also provides **Generate Repository SBOM…** for a direct one-time CycloneDX or SPDX export plus checksum without a hosted account. In both one-time modes the masked token is cleared on submission and never persisted. Use a repository-scoped credential with only **Metadata: read** and **Contents: read**, then revoke it after the run. See the [repository SBOM guide](docs/SBOM_GUIDE.md) for workflow differences, supported lockfiles, safety limits, and auditor interpretation.

Native updates use `MACOS_RELEASE_MANIFEST_JSON`, `MACOS_RELEASE_SIGNATURE_DER_BASE64`, and `MACOS_RELEASE_ALLOWED_HOSTS` at the hosted API boundary. A production app must compile one exact `ScopeproofUpdateDownloadOrigin` such as `https://downloads.<owned-domain>` and one exact `ScopeproofHostedAPIOrigins` entry into `Info.plist`; `./Scripts/configure_macos_release_identity.sh` requires `SCOPEPROOF_RELEASE_DOWNLOAD_ORIGIN` and `SCOPEPROOF_HOSTED_API_ORIGIN` and writes both. The client derives the only allowed immutable ZIP path as `/macos/<version>/Scopeproof-Capture-<version>.zip` and rejects redirects or an alternate signed URL. The signed manifest binds the version, monotonic sequence, digest, size, validity window, release key, Developer ID team, and designated requirement.

Before extraction, the production updater copies the download once into a private, same-volume pending archive and uses that exact staged file for ZIP validation, extraction, and final publication. It validates the staged regular file's identity, single-link state, exact byte size, and SHA-256 before and after extraction and again immediately before persisting the rollback floor and atomically renaming it into place. It also validates both ZIP central-directory and local-file metadata, including strict 32-bit data descriptors used by the production `ditto` packager. It streams every stored or raw-deflate payload itself to verify the actual expanded byte count and CRC-32 instead of trusting declared sizes. It rejects encrypted, split, ZIP64, unsupported-compression, traversal, absolute, ambiguous or colliding paths; symbolic links and other special files; duplicate or overlapping local records; header/descriptor mismatches; and any local record that reaches or overlaps the central directory. The archive is limited to 10,000 entries, a 1,024-byte UTF-8 path per entry, 512 MiB actually expanded per file, 1 GiB actually expanded in total, and a 200:1 per-entry and aggregate compression ratio. Extraction proceeds only when the destination volume reports at least the verified expanded total plus a fixed 256 MiB safety margin; unavailable or insufficient capacity fails closed. A post-extraction walk repeats the count, type, and size checks and rejects symbolic links, hard links, and other special files. Each release subprocess has a 180-second deadline and separate 1 MiB stdout and stderr limits. Cancellation, timeout, or excess output terminates the running command; those conditions and every validation failure reject the update. The client then verifies the embedded bundle identity/version, code identity, Gatekeeper acceptance, and stapled notarization, while a device-only Keychain tuple rejects rollback and same-sequence equivocation. Release publication independently reconstructs and verifies the canonical P-256-signed envelope before accepting its key-validity window. RFC 3161 requires the TSA and pinned-verifier settings documented in `.env.example`; configuring only a TSA URL does not create trusted time. Device enrollment and revocation are managed in **Connections → Mac capture devices**.

Jira Cloud requires `JIRA_OAUTH_CLIENT_ID`, `JIRA_OAUTH_CLIENT_SECRET`, an exact `JIRA_OAUTH_CALLBACK_URL`, and a distinct base64-encoded 32-byte `JIRA_OAUTH_TOKEN_ENCRYPTION_KEY`. Create one OAuth 2.0 (3LO) integration in the Atlassian developer console with `read:jira-work` and `write:jira-work`; Scopeproof requests `offline_access` for rotating refresh tokens.

## Development

```bash
npm ci
npm run dev
```

Validation:

```bash
npm run lint
npm run typecheck
npm test
```

Apply all D1 migrations in journal order through `drizzle/0028_native_reconciliation_cursor.sql`. Before deploying application code, run `npm run db:verify`; it replays the complete migration chain against both fresh and populated databases and checks native provenance, the sparse orphan-reconciliation queue, independent durable reconciliation cursors, independent screenshot safety, explicit scope/review/hold workflows, immutable checkpoint delivery attempts, atomic checkpoint retry leases, and durable key-rotation retry state. D1 and R2 logical bindings are declared in `.openai/hosting.json` for a separately authorized conditional Sites deployment; the repository does not prove that deployment exists.

To build the local menu-bar app without installing or launching it, use:

```bash
./Scripts/build_macos_capture.sh
```

See the [development guide](docs/DEVELOPMENT.md) for repository layout, migrations, validation, and release practices.

## Operational limits

- Arbitrary manual binary uploads remain rejected. The authenticated native route accepts only PNGs bound to a valid schema-8 P-256-signed, deployment-matched tenant/workspace Scopeproof manifest after local OCR/redaction, an independent server scan, trusted RFC 3161 verification, and finalized monotonic device-chain linkage.
- Packages include at most 100 approved artifacts and 25 MB of decrypted evidence, and expire after seven days.
- Provider pagination and collection breadth are intentionally bounded to resist API and memory exhaustion.
- Repository SBOM generation resolves refs to immutable commits, never executes repository code, and enforces archive, decompression, manifest, component, request, and retry limits. Managed mode accepts repositories only from the configured GitHub organization; one-time mode accepts one exact `https://github.com/owner/repository` URL whose repository is within the active assessment's system scope.
- API mutations and expensive reads have database-backed per-principal and IP quotas; multipart bodies require a bounded `Content-Length`. Provider calls have 60-second and response-byte limits, and collection jobs use expiring atomic leases.
- Evidence is unavailable immediately at expiry. The scheduler deletes expired encrypted objects and packages; an administrator may create a reasoned, owned, time-bounded legal hold before expiry through `PUT /api/evidence/:id/retention` and release it through `DELETE`.
- CSV files are presentation aids with formula-trigger prefixes neutralized. Signed JSON manifests remain authoritative.
- Rotate encryption and signing keys through a documented key-rotation process before replacing them; existing artifacts require their original key version to remain decryptable.
- Developer ID signing, Apple notarization, an offline P-256 update key whose public key is compiled into `Info.plist`, a hosted release URL, and an external RFC 3161 service require production credentials and are not part of an ad-hoc local build. No AWS resource was deployed by the repository work described here; this is not an account-wide inventory statement.
