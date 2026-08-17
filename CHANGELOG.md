# Changelog

## Unreleased — production evidence correctness and operations

- Added an auditor-facing repository SBOM workspace that generates CycloneDX 1.6 or SPDX 2.3 JSON from supported GitHub lockfiles at an immutable commit without cloning or executing repository code.
- Added assessment-scoped PCI DSS 6.3.2 evidence, independent approval, assessor-package inclusion, prior-inventory comparison, audited downloads, bounded parsing, retryable jobs, and least-privilege GitHub configuration guidance.
- Replaced demo-derived compliance state with fail-closed, assessment-scoped authoritative records.
- Added complete/partial collector coverage provenance and non-truncating assessment exports.
- Added versioned evidence, export, audit, Jira-token, and Jira-receipt key references with bounded audited rotation.
- Added signed audit-chain checkpoints, optional independent delivery, production readiness checks, and HMAC-authenticated monitoring health.
- Added migration replay, native macOS CI, immutable GitHub Action references, SBOM/provenance artifacts, CODEOWNERS, and dependency automation.
- Added key-management, backup/recovery, monitoring, incident-response, launch-authorization, and production macOS release procedures.

All notable Scopeproof changes are recorded here. Dates use the repository’s release timezone.

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
