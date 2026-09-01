# Changelog

## Unreleased — 1.9.0 (build 23)

- Removed the hardcoded native hosted-service destination. The checked-in `ScopeproofHostedAPIOrigins` allowlist is empty; production release identity configuration now requires one exact pathless `SCOPEPROOF_HOSTED_API_ORIGIN`, while ordinary source builds remain local-only for remote hosted synchronization.
- Removed the AWS CDK placeholder-domain fallback. `rootDomain` is empty by default, and synthesis now requires an explicit domain plus exactly one Route 53 choice: an existing `hostedZoneId` or the reviewed `createHostedZone=true` opt-in.
- Made the CDK environment and tenant recovery policy explicit: `deploymentEnvironment` is empty by default, and tenant stacks reject missing recovery configuration. Hardened the dormant Amplify build specification to install with `npm ci --ignore-scripts` and a workspace `.npm` cache.
- Hardened local Mac replacement so build and install publish only fresh verified bundles through same-volume rename with rollback. The installer stops a running app even under `--no-launch`, preventing stale executable/resource mixtures.
- Made production readiness require a structurally valid security-monitoring HTTPS endpoint and exact host allowlist, with the optional bearer token rejected unless it is bounded and header-safe.

> **Not published:** these changes postdate
> `v1.8.1-development-preview.1` (`8cd2d5c`) and are not present in that public
> DMG. As of 2026-08-28 this working branch is not merged into the public default
> branch. Version `1.9.0` and build `23` are allocated in source, but no 1.9.0
> artifact exists; an independently verified new release is required before
> these entries can be described as downloadable behavior.

- Upgraded hosted native screenshot ingestion to schema 7 with an ECDSA P-256/SHA-256 signature over the canonical manifest, a per-device provenance-key binding, and an atomically reserved/finalized monotonic capture chain. Native evidence without the finalized manifest link is quarantined from reads, approval, assessor packages, and Jira; older schema-6 behavior remains documented only under its historical release entry below.
- Added one independent server-owned screenshot safety path in `lib/server/image-safety.ts` for both native uploads and Cloudflare Browser Rendering. The legacy-named `BROWSER_OCR_*` configuration now enforces a clean HTTPS endpoint, exact hostname allowlist, exact PNG digest, strict response/policy contract, and fail-closed handling for unavailable scanners, mismatches, malformed results, or sensitive findings. Only digest/policy/time/origin/receipt-hash metadata is stored; recognized OCR text is discarded.
- Made verified RFC 3161 time mandatory for production native ingestion. Missing or failed trusted timestamping rejects the upload before evidence storage; `REQUIRE_TRUSTED_TIMESTAMP=false` is retained only for isolated diagnostics and now fails production readiness.
- Extended the legacy D1 migration chain through `drizzle/0023_independent_image_safety.sql` for rotation, occurrence lifecycle, audited CAS, device-chain, immutable checkpoint/native-provenance, quarantine, and independent screenshot-safety state. The `npm run db:verify` preflight now replays the complete chain against populated legacy fixtures and asserts the resulting invariants.
- Replaced implicit hosted-user creation with invitation-only membership after a single allowlisted bootstrap administrator. Added working team administration, role/status changes, pending-invitation revocation, last-active-administrator enforcement, immediate queued-work reauthorization, and 30-day rotatable Mac device tokens.
- Added auditable evidence occurrences so a repeated collection of identical bytes updates freshness/provenance without duplicating encrypted content. Evidence listings now expose occurrence counts and last-observed time; active assessments and explicit holds prevent physical purge of expired bytes.
- Made unscoped evidence deduplication race-safe despite SQLite's `NULL` uniqueness semantics, normalized device-token expiry checks, and made expired invitations replaceable without losing their history.
- Hardened the legacy Sites boundary to one exact canonical origin plus an explicit `single-tenant-only` acknowledgement. Production readiness now fails on a mismatched package-signing keypair, missing independent checkpoint delivery, untrusted checkpoint key, or checkpoint/audit-anchor mismatch.
- Restricted provider pagination to the original HTTPS origin, removed upstream response bodies from collector errors, and made the legacy AWS collector require all three temporary STS credential values. Revoked users can no longer continue queued collector or SBOM retries.
- Hardened the native evidence boundary with a single validated-artifact loader, bounded regular-file discovery, signed local provenance, rollback-resistant local audit state, exact-version S3 retention revalidation/legal holds, schema migration, bounded Local Console requests, and origin-only source URLs.
- Hardened release/IaC controls with exact entitlement allowlisting, external owner-only update-signing keys, production release dependency gates, a SHA-pinned Trivy secret/IaC gate, explicit CloudFormation tests, transitive deterministic SBOM edges, COMPLIANCE-locked customer-KMS-encrypted CloudTrail storage, and broader CloudTrail/KMS tamper alerts.
- Added native S3 authentication selection for manual credentials, a direct AWS CLI v2 IAM Identity Center profile, or Identity Center followed by one exact AssumeRole. CLI-derived STS credentials stay in memory, refresh automatically, and must preserve the verified account/role binding; unsafe profile sources and arbitrary CLI execution fail closed.
- Hardened native S3 posture verification with exact UUID/MRK KMS-key validation, required SSE-KMS Bucket Keys, and a schema-4 destination binding that stores verified KMS metadata. Production compliance now requires COMPLIANCE Object Lock, visibly labels Governance as non-production, binds the KMS ARN to the STS-verified bucket-owner partition/Region/account, and requires `DescribeKey` to prove an enabled customer-managed `SYMMETRIC_DEFAULT` encryption key that is not pending deletion. Native CloudFormation derives the exact KMS ARN from a key ID and the owner boundary, while its standalone production bucket is fixed to COMPLIANCE retention. The exact retained bucket policy additionally denies bucket deletion, evidence delete markers/version deletion, and Governance-retention bypass.
- Added nine opt-in CloudFormation storage/authentication building blocks for a retained native evidence bucket, native and hosted IAM Identity Center, Cognito/PKCE, Cognito Identity Pools, cross-account hosted ingest, IAM Roles Anywhere, and S3 Access Grants. Direct-reader roles include explicit outside-prefix read/list Denies, and retained buckets retain their enforcement policies. They are locally parsed, synthesized, and invariant-tested; no AWS resource was deployed.
- Added custom Cognito OAuth scopes, separate web/native app clients, exact app-client allowlists, route-level scope enforcement, Aurora-backed evidence metadata listing with tenant-bound HMAC cursors, and a separately privileged exact-version download Lambda. Hosted clients cannot choose S3 bucket, key, KMS key, or version coordinates.
- Bound the upload nonce digest into signed S3 metadata and require the promotion worker to verify all exact metadata before copying; the public upload API no longer returns the raw nonce.
- Hardened tenant database activation so all six application roles are non-inheriting and unprivileged, no managed owner/application role participates in a PostgreSQL membership edge, and the temporary administrator-to-owner migration grant is removed and rechecked before activation. The database now attests the all-eight-file SQL bundle together with an ordered digest of live function/index definitions before activation.
- Completed the production-shaped AWS tenant API adapters: exact API Gateway hostname authority, strict Cognito RS256/JWKS access-token verification, authoritative active PostgreSQL membership/RBAC, isolated runtime identities, bounded request parsing, and authenticated `GET /v1/me`, upload-intent, and two-person legal-hold routes. `GET /health` is an API Gateway mock and does not invoke the authenticated Lambda path.
- Added atomic, rate-limited upload-intent issuance with server-derived retention, stable HMAC idempotency across current/prior secret rotation, exact checksum/header/KMS-bound presigned PUTs, DynamoDB reservation, PostgreSQL reconciliation, assessment/control-state enforcement, and quarantine-only temporary AWS permissions.
- Replaced unfenced evidence copying with a single-winner exact-version stream into S3 using `If-None-Match: *`, durable monotonic promotion attempts, bounded recovery/adoption, Object Lock retention, KMS-signed promotion receipts, and database/DynamoDB reconciliation. Added an exact-version two-administrator legal-hold state machine with a durable `APPLYING` predecessor observation, drift detection, ambiguous-response recovery, KMS-signed audit outbox, and audit-bound recovery publication.
- Added same-account cross-region recovery: a DynamoDB global table, S3 CRR/RTC and existing-version Batch Replication, independently paginated source/change/destination verification, orphan/delete-marker rejection, immutable signed recovery ledgers, Aurora AWS Backup with Vault Lock, freshness/failure alarms, and documented restore/cutover drills. Existing `AWS::DynamoDB::Table` deployments require a reviewed retain/remove/convert/import migration.
- Added a protected production macOS release workflow with ephemeral signing credentials, Developer ID hardened-runtime signing, Apple notarization/stapling/Gatekeeper validation, SBOM/provenance/attestations, immutable candidate snapshot verification, an offline-signed exact-origin update envelope, Keychain rollback/equivocation state, and bundle identity/version verification. Replaced managed Swift autobuild with a complete advanced CodeQL workflow: no-build JavaScript/TypeScript and Actions plus a manual arm64 Swift build.
- Selected and documented an AWS-only multi-tenant hosting target using explicit Route 53 customer subdomains, Cognito, pay-per-use compute, a low-idle relational/control plane, and per-customer S3/KMS/IAM evidence boundaries. Added synthable shared/per-tenant CDK stacks with WAF, budgets, alarms, private release distribution, retained AWS audit storage, a database-provisioning state machine, and an enabled GuardDuty/SQS evidence-promotion path whose live event contract remains a staging gate.
- Added exact-host tenancy, verified-token and authoritative-membership enforcement; role/action authorization; cross-tenant ID guards; checksum- and nonce-bound upload lifecycles; lease-safe jobs and retention; a forced-RLS PostgreSQL tenant schema; least-privilege runtime, ingest, legal-API, evidence-control, evidence-read, and API-audit-signer role migrations; and a validated offline tenant SQL renderer.
- Added native Cognito authorization-code/PKCE security primitives and a tenant/issuer/client-bound Keychain refresh-token abstraction without embedding a client secret or AWS credentials in the Mac application.
- Added a detailed AWS deployment and operations runbook plus an adversarial AWS security review. Both distinguish local validation, infrastructure deployment, database readiness, and customer activation, and record that no AWS environment was deployed or production-authorized by this change.
- Expanded the native Local Console into a unified local/S3 screenshot library with storage badges, search, framework/control/assessment-period/status/storage filters, control/period/framework grouping, S3 version counts, and resilient local-only fallback. Local/S3 joins now require an exact schema-2 upload receipt; S3-only pairs remain visibly provenance-unverified, and on-demand previews validate the paired exact-version manifest plus PNG digest without exposing credentials, object keys, or filesystem paths to browser code.
- Changed the default local evidence root from `~/Pictures/Scopeproof Evidence` to `~/Documents/Scopeproof Evidence`. Existing Pictures-based captures remain discoverable without an automatic file move; only signed schema-7 artifacts remain eligible for trust-bearing review, upload, retention/legal-hold, package, and Jira workflows, while unsigned schema-6 and older artifacts are browsing-only and must be recaptured.

## 1.8.1 — 2026-08-25

### Added

- Added a verified Apple Silicon development-preview DMG with a drag-to-Applications layout, adjacent SHA-256 checksum, CI artifact retention, and explicit ad-hoc-signing/notarization warnings.
- Added a prominent direct DMG, checksum, and release-history shortcut to the repository README and aligned installation, operator, native, architecture, security, development, and deployment documentation with the downloadable workflow.
- Added a live right-side macOS menu-bar pixel strip to browser, selected-window, URL-delayed, and scrolling evidence, with the same OCR, redaction, review, and final-scan pipeline.
- Added **Update Controls…** plus visible catalog version, source, and control count. Imported JSON, OSCAL, and CSV catalogs are limited to 5 MB, normalized, duplicate-checked, and recorded with a SHA-256 provenance digest.
- Added the Mac menu-bar date, time, and timezone as a dedicated line in every screenshot evidence banner.

### Changed

- Made the evidence-review phase explicit in the menu and present its modal workspace above browser windows on the active desktop; closing the review safely discards it.
- Made local-only mode explicit by replacing the misleading hosted update-token error with **Open GitHub Releases…** and disabling hosted-upload retry until a valid server-bound device token exists.

### Fixed

- Replaced the clipped Capture & Jira Settings alert with compact **Capture & Local** and **Jira** tabs so every field and checkbox remains visible on smaller displays.

## Unreleased — production evidence correctness and operations

The entries in this older rollout section describe behavior when each feature was introduced. The current **Unreleased** security contract above supersedes legacy schema-6 upload and optional timestamp/checkpoint behavior without rewriting those historical facts.

- Added active-tab URL detection to **Capture Frontmost Browser Window** for Safari, Chrome, Edge, and Arc. The sanitized address is prefilled for operator confirmation; unsupported browsers or denied macOS Automation access fail safely to an empty manual field instead of reusing a prior capture URL.
- Added operator-guided **Capture Scrolling Evidence…** for browser evidence that spans two or more viewports. Scopeproof keeps every section in memory, inserts numbered continuation dividers, applies one evidence/URL banner, and runs the complete OCR, redaction, review, exact-PNG scan, manifest, indexing, and upload workflow on the combined artifact.
- Added an editable Page URL to capture classification. Security hardening subsequently narrowed persisted evidence provenance to the lowercase HTTP(S) origin; user information, path, query, and fragment are removed before the value reaches the screenshot, manifest, index, or log.
- Added one-time repository SBOM generation from an exact GitHub URL and short-lived read-only token entered in the SBOM menu. The token is masked, cleared on submission, used only for the active request, excluded from persistence/logs/audit details, and never available to automatic retries.
- Added an auditor-facing repository SBOM workspace that generates CycloneDX 1.6 or SPDX 2.3 JSON from supported GitHub lockfiles at an immutable commit without cloning or executing repository code.
- Added assessment-scoped PCI DSS 6.3.2 evidence, independent approval, assessor-package inclusion, prior-inventory comparison, audited downloads, bounded parsing, retryable jobs, and least-privilege GitHub configuration guidance.
- Replaced demo-derived compliance state with fail-closed, assessment-scoped authoritative records.
- Added complete/partial collector coverage provenance and non-truncating assessment exports.
- Added versioned evidence, export, audit, Jira-token, and Jira-receipt key references with bounded audited rotation.
- Added signed audit-chain checkpoints, optional independent delivery, production readiness checks, and HMAC-authenticated monitoring health.
- Added migration replay, native macOS CI, immutable GitHub Action references, SBOM/provenance artifacts, CODEOWNERS, and dependency automation.
- Added key-management, backup/recovery, monitoring, incident-response, launch-authorization, and production macOS release procedures.

All notable Scopeproof changes are recorded here. Dates use the repository’s release timezone.

## 1.8.0 — 2026-08-20

### Added

- Added **Production compliance** S3 configuration with caller-identity verification, same-account expected-owner binding, expiring STS credentials, customer-managed SSE-KMS/DSSE-KMS, Object Lock retention, BucketOwnerEnforced ownership, TLS/KMS bucket policy, optional FIPS endpoints, Deep Archive transition, and replication.
- Added complete bucket-posture verification for existing and newly created destinations. Security-sensitive routing and the verified AWS account/principal/posture are digest-bound in a separate device-only Keychain item; preference or credential changes disable uploads until re-verification.
- Added S3 SHA-256 request/response verification, exact version IDs, KMS/retention metadata, and S3 request IDs to schema-2 upload receipts.
- Replaced current-object browsing with bounded `ListObjectVersions` browsing and exact-version downloads. PNG/JSON downloads now validate version, ETag, size, optional returned checksum, and file structure before atomic save, then receive macOS quarantine metadata.
- Added a deployable CloudFormation template for prefix-scoped CloudTrail data events, immutable audit-log storage, and SNS alerts on evidence deletion, S3 security-control changes, and KMS disable/deletion/policy changes.

### Security

- Production mode rejects long-lived access keys, empty prefixes, SSE-S3, missing KMS keys, expired sessions, incomplete bucket controls, mismatched owners, and unbound destinations.
- Bucket creation displays an explicit irreversible Object Lock confirmation and never overwrites lifecycle or replication settings on a pre-existing bucket.
- Upload-only and optional browser permissions are separated; unknown or executable S3 objects cannot be downloaded through Scopeproof.
- Added least-privilege Compatible S3 IAM-user and KMS key-policy templates constrained to the exact bucket, prefix, account, regional S3 service, and encryption context. Real deployment identifiers are intentionally excluded from repository documentation.

### Fixed

- Replaced the misleading same-region KMS error shown when SSE-S3 was selected with a direct instruction to select SSE-KMS/DSSE-KMS or clear the KMS ARN.

## 1.7.0 — 2026-08-20

### Added

- Added **Browse S3 Evidence…**, a native searchable and sortable workspace for files beneath the configured evidence prefix, with control folder, filename, assessment/evidence path, size, and modified time.
- Added explicit single-file downloads through the macOS save panel and a **Reveal Download** action.
- Added paginated S3 `ListObjectsV2` support capped at 5,000 objects and documented prefix-scoped `s3:GetObject` permissions.

### Security

- S3 downloads are limited to 250 MB, bound to the listed ETag with a signed `If-Match` request, streamed to a mode-`0600` temporary file, checked against the listed size, and moved into place only after completion.
- Listing and download requests stay on the configured AWS bucket and prefix, reuse the redirect-rejecting ephemeral session, reject unsafe XML/object metadata, and never cache credentials or downloaded content in the browser workspace.

## 1.6.1 — 2026-08-19

### Added

- Added **Create & Secure Bucket** to the native S3 configuration flow. It creates the bucket in the selected region, enables all four S3 Block Public Access controls, enables versioning, and verifies access before allowing automatic evidence upload.
- Added fail-closed handling for partially completed bucket setup plus separate one-time creation and long-lived evidence-writer IAM examples.

### Security

- Automatic upload remains disabled until bucket creation, hardening, and connection verification all succeed. Scopeproof never attempts to delete a partially created bucket.
- Bucket-management permissions are documented as temporary setup permissions that should be removed after the bucket is ready.

## 1.6.0 — 2026-08-19

### Added

- Added native AWS S3 evidence storage with bucket, region, prefix, automatic/manual upload, connection testing, retry, disconnect, and Keychain-protected access key, secret key, and optional session token.
- Added control-oriented object paths containing the verified PNG and immutable manifest together, plus a local credential-free S3 receipt after both uploads succeed.
- Added direct AWS Signature Version 4 HTTPS requests, AES-256 S3 server-side encryption, fixed AWS endpoints, redirect rejection, local integrity validation, bounded transfers, native tests, least-privilege IAM guidance, and bucket-hardening documentation.

### Security

- AWS credentials use a `WhenUnlockedThisDeviceOnly` Keychain item and are excluded from preferences, evidence, receipts, logs, documentation examples, and Git. Non-secret bucket routing remains in preferences.
- S3 upload permissions can be restricted to `s3:ListBucket` for connection testing and `s3:PutObject` for one bucket prefix; Scopeproof never lists object content, reads, deletes, changes ACLs, or makes objects public.

## 1.5.1 — 2026-08-17

### Fixed

- Fixed the native repository SBOM dialog collapsing its input controls behind the action buttons by giving the AppKit accessory grid and each control explicit dimensions.
- Added purpose-specific SBOM and warning icons so repository prompts and validation errors are easier to distinguish.

## 1.5.0 — 2026-08-17

### Added

- Added **Generate Repository SBOM…** directly to the macOS shield menu with exact GitHub URL, masked one-time token, branch/tag/commit, and CycloneDX 1.6 or SPDX 2.3 selection.
- Added bounded, read-only GitHub commit/tree/blob collection that downloads only supported lockfiles and never clones, extracts archives, executes source, invokes package managers, or starts subprocesses.
- Added direct JSON export with immutable commit and manifest-set provenance plus an adjacent SHA-256 checksum protected with current-user-only file permissions.

### Security

- Native GitHub access uses an ephemeral session with redirects, cookies, URL caching, and credential storage disabled. The token is cleared at submission, never persisted or logged, and never automatically retried.
- Added strict GitHub host/repository/ref/token validation, response and tree limits, per-manifest and aggregate byte limits, UTF-8/NUL validation, component limits, one-run concurrency, and native parser regression tests.

## 1.4.0 — 2026-08-12

### Added

- Local-first browser console bundled into the macOS menu-bar app and opened automatically at launch.
- Loopback-only evidence overview, previews, framework/control/status search, lifecycle review, folder reveal, capture handoff, workspace status, and Help.
- Rebuildable SQLite evidence index and append-only local audit chain authenticated by a device-only Keychain HMAC key.
- Local-only settings mode that requires no hosted URL, account, or device-enrollment token.
- Dedicated macOS installation, update, verification, and troubleshooting documentation for local and managed deployments.

### Security

- The Local Console binds only to `127.0.0.1`, creates an ephemeral 256-bit HttpOnly SameSite browser session, applies a restrictive CSP, requires exact same-origin proof for mutations, rejects ambiguous HTTP inputs, and never accepts filesystem paths from the browser.
- Evidence previews are resolved by validated evidence ID and served only after PNG signature, size, path-containment, and SHA-256 verification.

## 1.3.2 — 2026-08-11

### Security

- Native capture keeps unreviewed pixels in memory, scans after stamping and review, and atomically saves only the exact verified PNG bytes.
- Native manifest schema 6 binds the saved screenshot digest to the local scanner policy and completion time; older upload manifests now fail closed.
- Hosted browser capture scans the single immutable screenshot through an allowlisted, digest-binding OCR service and fails closed on scanner errors, sensitive pixels, or digest mismatch.
- Source URLs recorded by the Mac client exclude credentials, query parameters, and fragments.
- Local approval state is derived from digest/policy-bound lifecycle events, and package signing now requires local Keychain user presence.
- Security-sensitive database mutations and audit events commit atomically; Jira external effects retain durable intent/result state.
- RFC 3161 responses receive trusted status only after nonce, imprint, CMS, TSA certificate/EKU/path, trust-anchor, validity, and revocation validation by a pinned verifier.

## 1.3.1 — 2026-08-11

### Added

- One-command local macOS build, per-user installation, and launch through `./Scripts/run_macos_capture.sh`.
- Explicit, one-time administrator bootstrap with an immutable database invariant and allowlisted application origins for trusted identity headers.
- Capability-based collection, administration, export, and review permissions with independent evidence approval.
- Digest-bound review attestations that require reviewers to inspect the decrypted artifact rather than relying on collection-time scan claims.
- Jira Cloud OAuth 2.0 connection management, encrypted rotating tokens, site/project restrictions, issue validation, explicit approved-evidence upload, and signed immutable upload receipts.
- Jira handoff settings for HTTPS site, default project, attachment preference, package guide, and organization instructions.
- Optional Jira issue key in capture classification, visible screenshot banners, filenames, manifests, search, hosted metadata, audit details, and assessor indexes.
- **Copy Jira Comment** with evidence scope, lifecycle status, attachment checklist, SHA-256, and safe-handling guidance.
- Jira handoff guides in local and hosted assessor packages.
- Strict Jira key/URL validation and native manifest consistency checks.
- Expanded operator, Jira, assessor, security, architecture, deployment, development, and in-app documentation.

### Changed

- macOS menu item renamed to **Capture & Jira Settings…**.
- Native app version advanced to 1.3.1 (build 8).
- Native upload metadata now comes exclusively from a versioned device-authenticated manifest, with strict PNG decode, dimension, digest, and capture-chain validation.
- Jira attachment uploads now use durable idempotency reservations, explicit unknown-outcome reconciliation, and serialized OAuth refresh-token rotation.
- Hosted responses now deny framing, apply a restrictive content security policy, and require exact same-origin proof for mutations.

## 1.3.0 — 2026-08-11

### Added

- Multi-framework control selection, imported catalogs, capture presets, evidence owners, tags, expected-evidence guidance, and curated control mappings.
- Irreversible manual screenshot redaction and local OCR secret/PAN scanning.
- Hash-chained evidence lifecycle with Draft, In Review, Approved, Rejected, and Superseded states.
- Framework/control/period folder organization, rich local search, and approved-only signed assessor packages.
- External-assessor Help workflow and control-coverage reporting.

## 1.2.0 and earlier

- Initial native ScreenCaptureKit capture, visible timestamp banner, manifest hashing, device enrollment, encrypted hosted upload, provider collectors, RBAC, immutable audit logs, retries, and signed hosted assessor packages.
