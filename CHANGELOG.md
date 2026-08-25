# Changelog

## Unreleased

- Add a verified development-preview DMG with a drag-to-Applications layout, checksum, CI artifact retention, and explicit ad-hoc/notarization warnings.
- Add the Mac menu-bar date, time, and timezone as a dedicated line in every screenshot evidence banner.

## Unreleased — production evidence correctness and operations

- Added active-tab URL detection to **Capture Frontmost Browser Window** for Safari, Chrome, Edge, and Arc. The sanitized address is prefilled for operator confirmation; unsupported browsers or denied macOS Automation access fail safely to an empty manual field instead of reusing a prior capture URL.
- Added operator-guided **Capture Scrolling Evidence…** for browser evidence that spans two or more viewports. Scopeproof keeps every section in memory, inserts numbered continuation dividers, applies one evidence/URL banner, and runs the complete OCR, redaction, review, exact-PNG scan, manifest, indexing, and upload workflow on the combined artifact.
- Added an editable full Page URL to capture classification. The complete sanitized URL is printed on its own line in the screenshot header, recorded in the immutable manifest, and included in local search; embedded credentials and sensitive query/fragment values are redacted before rendering or persistence.
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
