# Changelog

All notable Scopeproof changes are recorded here. Dates use the repository’s release timezone.

## 1.3.1 — 2026-08-11

### Added

- One-command local macOS build, per-user installation, and launch through `./Scripts/run_macos_capture.sh`.
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

## 1.3.0 — 2026-08-11

### Added

- Multi-framework control selection, imported catalogs, capture presets, evidence owners, tags, expected-evidence guidance, and curated control mappings.
- Irreversible manual screenshot redaction and local OCR secret/PAN scanning.
- Hash-chained evidence lifecycle with Draft, In Review, Approved, Rejected, and Superseded states.
- Framework/control/period folder organization, rich local search, and approved-only signed assessor packages.
- External-assessor Help workflow and control-coverage reporting.

## 1.2.0 and earlier

- Initial native ScreenCaptureKit capture, visible timestamp banner, manifest hashing, device enrollment, encrypted hosted upload, provider collectors, RBAC, immutable audit logs, retries, and signed hosted assessor packages.
