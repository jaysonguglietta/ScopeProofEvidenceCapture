# Scopeproof Capture for macOS

Scopeproof Capture 1.5.0 is a local-first menu-bar application for producing, finding, reviewing, and packaging timestamped PCI DSS, HIPAA, FedRAMP, SOC 2, ISO 27001, and custom compliance evidence screenshots, plus one-time repository SBOM exports.

Related guides: [installation and updates](../../docs/MACOS_INSTALLATION.md), [operator workflow](../../docs/OPERATOR_GUIDE.md), [Jira handoff](../../docs/JIRA_HANDOFF.md), [repository SBOM generation](../../docs/SBOM_GUIDE.md), [assessor verification](../../docs/ASSESSOR_GUIDE.md), and [security model](../../docs/SECURITY.md).

## Run locally

Requirements: macOS 14 or newer and Apple’s Swift toolchain. From the repository root, run:

```bash
./Scripts/run_macos_capture.sh
```

This single command builds the app, installs it in `~/Applications`, and launches it without requiring an administrator password. Scopeproof opens a private Local Console in the browser automatically. No hosted login or enrollment token is required for local workflows. Look for the shield in the menu bar to capture evidence or reopen the console.

Choose **Generate Repository SBOM…** from the shield menu for a direct one-time CycloneDX 1.6 or SPDX 2.3 export. The native app accepts an exact GitHub URL, a short-lived repository-scoped token, and a branch/tag/commit; reads only recognized lockfile blobs through GitHub's API; saves JSON plus a SHA-256 checksum; and does not persist or retry the credential. Use the hosted workflow instead when the SBOM must be assessment-scoped, independently approved, compared with a prior run, or included automatically in a Scopeproof assessor package.

## Local Console

The embedded console provides local overview metrics, preview cards, framework/control/status filters, lifecycle review, evidence reveal, workspace status, and Help. It binds only to `127.0.0.1`, uses a per-launch authenticated browser session, and stops when Scopeproof quits. Browser requests identify artifacts only by evidence ID; the server resolves and verifies the corresponding local files.

Scopeproof maintains a rebuildable SQLite search index under the current user's Application Support folder. Immutable PNG manifests and `.review.json` lifecycle records remain authoritative. A separate append-only SQLite audit chain is HMAC-authenticated with a device-only Keychain key. Hosted synchronization and Jira Cloud remain optional.

When you make the first capture, allow **Scopeproof Capture** under **System Settings → Privacy & Security → Screen & System Audio Recording**. Quit and reopen the app once after granting access. If Swift is unavailable, run `xcode-select --install`, finish the installation, and retry the command.

## Capture workflow

1. Launch the app and select the shield icon in the macOS menu bar.
2. Choose an exact browser window, capture the frontmost browser, open a URL after a delay, or capture a full display.
3. In the pre-capture dialog, select a compliance framework and corresponding control, customize the filename, and confirm the owner, optional Jira issue, tags, expected evidence, and prefilled context. Use **Capture Presets** for recurring collections or import a Scopeproof JSON, OSCAL JSON, or CSV control catalog.
4. Scopeproof runs local OCR and masks detected PANs and credentials. In the review workspace, drag over any additional sensitive value before saving. The unredacted capture is never retained.
5. Find the stamped PNG, immutable capture manifest, and hash-chained review record under `~/Pictures/Scopeproof Evidence/<Compliance area>/<Control>/<Assessment period>`, or enable upload in **Capture & Jira Settings**.

Every screenshot receives a full-width, high-contrast header above the captured pixels containing local date, time, timezone, compliance framework, control number/title, optional Jira issue, system, source, and a unique evidence ID. The dedicated header never covers the evidence itself. Filenames include the framework, control, optional Jira issue, custom evidence name, capture time, and evidence ID. The adjacent JSON manifest contains UTC time, classification metadata, Jira reference, source metadata, final pixel dimensions, redaction counts, the PNG SHA-256 digest, and the previous/current chain hashes. A successful upload adds a local receipt containing the server-signed time attestation and optional RFC 3161 timestamp token.

Use **Search Evidence…** in the shield menu to filter screenshots by framework, control, review status, age, and system; search their filename, Jira issue, title, owner, tags, notes, or evidence ID; inspect thumbnails; and open or reveal a result. **Review Status…** moves an artifact through Draft, In Review, Approved, Rejected, and Superseded while preserving each decision in a hash-chained `.review.json` sidecar. Approval, rejection, and supersession require a rationale.

Use **Export Assessor Package…** after review. The exporter includes only Approved evidence in the chosen framework/period scope, revalidates every screenshot hash and review chain, and creates a ZIP organized by framework and control. Each package contains a Read Me, control-coverage/gap CSV, evidence index CSV with Jira references, optional Jira handoff guide, signed JSON manifest, verification guide, PNGs, capture manifests, lifecycle records, and available server receipts. A separate SHA-256 checksum file is written beside the ZIP.

## Jira handoff

1. In the Scopeproof web console, open **Connections → Jira Cloud**, enter the Jira Cloud site and allowed project keys, then authorize the site through Atlassian OAuth and test the connection. OAuth tokens remain encrypted on the hosted server and never enter the Mac app.
2. Open **Capture & Jira Settings…** on the Mac and enter the Jira HTTPS site, default project key, preferred attachment set, and any internal handling steps. These are handoff defaults, not credentials.
3. Enter a destination key such as `GRC-123` during capture. It becomes part of the banner, filename, immutable manifest, Search Evidence result, hosted metadata, and package index.
4. Review and approve the artifact locally, upload those exact bytes to Scopeproof, and have an authenticated web reviewer approve the hosted artifact. In **Search Evidence…**, choose **Upload to Jira Cloud…**, inspect the live issue summary, and explicitly confirm the upload. Scopeproof verifies both approvals, the PNG hash, safety state, lifecycle chain, site, project allowlist, and Jira permissions before attaching the evidence set.
5. Keep the signed `.jira.json` receipt beside the evidence. **Copy Jira Comment** and manual attachment remain available as a fallback. Confirm project permissions, external-auditor access, data classification, and retention first.

The app never captures on a timer or in the background without an explicit menu action. OCR runs on the Mac and recognized text is not retained. Device credentials are stored in the macOS Keychain, not preferences or screenshot metadata.

## Optional hosted synchronization

1. In the web app, open **Connections → Mac capture devices → Enroll device**.
2. Copy the one-time token immediately; only its hash is retained by the server.
3. In the menu-bar app, open **Capture & Jira Settings**, enter the HTTPS Scopeproof URL, paste the token, and optionally enable automatic upload.
4. Use **Retry Pending Uploads** after an offline capture. Tokens can be revoked from the web app at any time.

The app signs the exact manifest and PNG digests with its enrolled device credential. The hosted API rejects unsigned, mismatched, ambiguous, malformed, oversized, or polyglot uploads; derives evidence metadata only from the versioned manifest; labels local scanning as a client claim; encrypts accepted evidence with AES-256-GCM in R2; and records device identity plus chain-of-custody metadata in the append-only audit trail. Servers containing this protocol require the matching app release; older clients that send independent multipart metadata are intentionally rejected.

## Help and operations

Choose **Help & How to Use…** from the menu for an in-app quick start, assessor handoff checklist, evidence-file explanation, permission recovery, security model, and troubleshooting guidance. The menu also provides capture presets, catalog import, recent captures, the evidence folder, configurable retention, Launch at Login, permission status, and secure update checks.

## Build only

From the repository root:

```bash
./Scripts/build_macos_capture.sh
```

The signed local app is created at `DerivedData/Scopeproof Capture.app`, but it is not installed or launched. Use `./Scripts/run_macos_capture.sh` for the one-command local workflow.

The local build uses an explicit designated requirement tied to `com.scopeproof.capture`. This keeps the app's Screen Recording permission identity stable across local rebuilds.

For a production release, provision the offline update public key and validity window under `ScopeproofUpdatePublicKeys` in `Info.plist`, then set the Developer ID, notarization, update-key, version, sequence, final URL, team, and designated-requirement variables consumed by `./Scripts/publish_release.sh`. The script produces a notarized ZIP plus a signed release envelope. Configure that envelope through `MACOS_RELEASE_MANIFEST_JSON`, `MACOS_RELEASE_SIGNATURE_DER_BASE64`, and an exact `MACOS_RELEASE_ALLOWED_HOSTS` value. The app rejects redirects, downgrade sequences, wrong keys/digests/teams/requirements, Gatekeeper failures, and releases without a valid stapled notarization ticket.
