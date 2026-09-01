# Scopeproof Capture installation for macOS

This guide installs the local-first Scopeproof Capture menu-bar application for one macOS user. Local capture, evidence search, lifecycle review, and assessor-package export do not require a hosted Scopeproof account, server URL, or device token.

The Mac app can generate a direct, one-time repository SBOM without a hosted account. Choose **Generate Repository SBOM…**, enter an exact GitHub URL and short-lived read-only token, and save CycloneDX or SPDX JSON plus its SHA-256 checksum. The credential is used only for the active request and is not stored. Use the hosted console instead when the SBOM must be assessment-scoped, independently approved, compared with prior evidence, or included automatically in an assessor package. See the [repository SBOM guide](SBOM_GUIDE.md).

## Requirements

- macOS 14 or newer.
- An Apple Silicon (`arm64`) Mac for the older published 1.8.1 development-preview DMG.
- Screen Recording permission for browser-window capture.
- Documents Folder access when macOS requests it for local evidence storage.
- HTTPS access to `api.github.com` when using local repository SBOM generation.
- HTTPS access to the configured region-specific AWS S3 and STS endpoints (or their FIPS variants) when using optional S3 storage.

The downloadable DMG does not require a repository checkout, Xcode, or Swift. Building from source additionally requires a local copy of this repository and Apple's Swift toolchain. Install the toolchain with `xcode-select --install` if `swift --version` is unavailable.

## Install the development-preview DMG

> **Older published build:** `v1.8.1-development-preview.1` was built from
> commit `8cd2d5c`. It does not contain the current **Unreleased 1.9.0 (build 23)** native changes
> described elsewhere in this guide, and the current working branch is not
> merged into the public default branch as of 2026-08-28. Use this DMG only to
> evaluate the tagged build. It writes new captures under
> `~/Pictures/Scopeproof Evidence` and uses manual AWS credential entry rather
> than the current Documents-root and direct AWS CLI IAM Identity
> Center/AssumeRole workflow. Build an exact reviewed current-source checkout for
> current behavior until a new versioned DMG is independently verified and
> published. Current source is version `1.9.0` build `23`; no 1.9.0 artifact
> exists.

Open the [Scopeproof Capture 1.8.1 development-preview release](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/tag/v1.8.1-development-preview.1) and download both:

- `Scopeproof-Capture-1.8.1-development-preview.dmg`
- `Scopeproof-Capture-1.8.1-development-preview.dmg.sha256`

From the folder containing both downloads, verify the disk image before opening it:

```bash
shasum -a 256 -c Scopeproof-Capture-1.8.1-development-preview.dmg.sha256
```

The expected DMG SHA-256 is `2ec6accbf88339b9de1087dd98c87aabfc118e191323866679f1bda365e83227`, which is also recorded in the adjacent `.sha256` release asset. The command must report `OK`. If it does not, delete both downloads and do not open the image.

Open the DMG and drag **Scopeproof Capture** to the **Applications** shortcut. The installed path is `/Applications/Scopeproof Capture.app`. Eject the disk image before launching the installed copy.

This DMG is ad-hoc signed and is not Apple-notarized. It is intended for evaluation and named testers who understand the Gatekeeper warning; it is not a trusted public production release. If macOS blocks it, do not disable Gatekeeper globally. Confirm the checksum and GitHub release source first, then use **System Settings → Privacy & Security → Open Anyway** only when your organization permits development-preview software.

## Build and install from source

From Terminal, change to the repository root and run:

```bash
./Scripts/run_macos_capture.sh
```

The checkout must contain the reviewed **Unreleased** changes you intend to
test. Until they are merged, a plain clone of the public default branch is not
equivalent to this working tree. Record the exact commit and require a clean
`git status --short` before treating a source build as review evidence.

The script builds a release executable into a fresh staging bundle, verifies its signature, bundle identifier, and macOS minimum, and only then publishes `DerivedData/Scopeproof Capture.app`. Installation likewise copies into a fresh staging directory on the destination volume, verifies it, stops the running Scopeproof process, and replaces `~/Applications/Scopeproof Capture.app` by same-volume rename. A failed replacement restores the prior complete app instead of merging new files over stale resources. Administrator access is not required. Do not keep both the DMG-installed and source-installed copies running; consistently open one installed path so macOS permissions remain associated with the intended bundle.

Scopeproof appears as a shield in the menu bar and opens its Local Console in the default browser. The console is served by the running Mac app on a random `127.0.0.1` port and is not published to the LAN or internet. Its Evidence library shows local screenshots and, when the S3 destination is configured and verified, matching S3 screenshots with explicit storage badges and on-demand previews. If the tab is closed, choose **Open Local Console** from the shield menu or press `Command-Shift-L`.

## Grant capture permission

On the first capture:

1. Open **System Settings → Privacy & Security → Screen & System Audio Recording**.
2. Enable **Scopeproof Capture**.
3. Fully quit Scopeproof from its shield menu.
4. Reopen `/Applications/Scopeproof Capture.app` for a DMG installation or `~/Applications/Scopeproof Capture.app` for a source installation.

If Scopeproof is not listed, attempt one capture first so macOS can register the permission request. The permission belongs to the installed application; consistently launch the same `/Applications` or `~/Applications` copy rather than an older build or the copy still mounted inside the DMG.

## Confirm local-only settings

Open **Capture & Jira Settings…** from the shield menu. Leave **Server URL** blank to prevent hosted synchronization. The Local Console, capture, search, review, Jira comment generation, and local assessor-package export continue to work even when no hosted OCR/DLP scanner or trusted timestamp authority exists. New captures still use a signed schema-7 manifest and the device's locally anchored P-256 provenance identity.

New evidence is stored under `~/Documents/Scopeproof Evidence/<framework>/<control>/`. Existing captures under `~/Pictures/Scopeproof Evidence` remain discoverable; Scopeproof does not move or delete them automatically. Storage location does not determine trust. A valid signed schema-7 capture can use the supported legacy root, but unsigned schema-6 and older artifacts are an explicit visibly unverified browsing/migration path and are blocked from approval, upload, legal-hold/retention assertions, package export, and Jira trust workflows. Recapture legacy evidence with the current app rather than editing its manifest or lifecycle record. The Local Console's SQLite search index lives in the current user's Application Support folder and can be rebuilt from the immutable evidence manifests and lifecycle sidecars.

## Optional hosted synchronization requirements

Hosted synchronization is not required for installation or local use. The checked-in `Info.plist` has an empty `ScopeproofHostedAPIOrigins` array, so an ordinary current-source release build rejects every remote HTTPS Server URL and remains local-only. A release operator must first compile one reviewed, exact, pathless HTTPS origin with `SCOPEPROOF_HOSTED_API_ORIGIN` through `Scripts/configure_macos_release_identity.sh`; never add a personal or historical service as a source default. When an administrator enrolls the Mac for that compiled origin, paste the one-time audience-bound device token and the same HTTPS Server URL under **Capture & Jira Settings…**. The token is stored in a device-only Keychain item; the schema-7 provenance signing key is a separate device-only P-256 Keychain identity. Development-only loopback HTTP is accepted only by debug builds for local integration testing.

A production server accepts the current signed schema-7 PNG/manifest pair only. It independently rescans the exact PNG through the OCR/DLP service configured by the legacy-named `BROWSER_OCR_ENDPOINT`, `BROWSER_OCR_TOKEN`, and `BROWSER_OCR_ALLOWED_HOSTS` settings, verifies a trusted RFC 3161 timestamp, and finalizes the exact artifact into the server-side device chain. Recognized OCR text is evaluated transiently and is not retained. Until the scan, timestamp, and final chain linkage succeed, the hosted item is quarantined and cannot be read, previewed, approved, packaged, exported, or sent to Jira.

If scanner or timestamp verification is unavailable, the hosted upload fails closed while the local artifact remains usable. Retry the unchanged current pair after recovery. An unsigned legacy capture must be recaptured; an older hosted item missing the independent scan or final linkage must be re-uploaded/rescanned. Administrators must never grandfather either population with direct database updates. Server operators must apply migrations through `0023_independent_image_safety.sql` and confirm production readiness has no scanner or trusted-timestamp failures before enabling native uploads. No AWS deployment is performed by installing or building the Mac app.

## Update the DMG installation

Download the newer release DMG and checksum, verify them, quit Scopeproof, and replace the existing app in `/Applications`. Evidence under `~/Documents/Scopeproof Evidence` or the legacy `~/Pictures/Scopeproof Evidence` location, Keychain items, and user preferences are not removed. Do not overwrite a production-notarized installation with a development preview unless your organization has approved that downgrade in release trust.

## Update or rebuild from source

Pull or copy the updated repository source, then run the installation command again:

```bash
./Scripts/run_macos_capture.sh
```

The script quits a running Scopeproof process before replacing the application, including when `--no-launch` is supplied. It stages and verifies a fresh bundle, replaces the prior app by same-volume rename, and restores the prior bundle if replacement fails; it never overlays resources into an existing app. Evidence under `~/Documents/Scopeproof Evidence` or the legacy `~/Pictures/Scopeproof Evidence` location, Keychain keys, and user preferences are not removed. Use `./Scripts/run_macos_capture.sh --no-launch` when installation should finish without reopening the app.

## Verify the installation

- `/Applications/Scopeproof Capture.app` exists for a DMG installation, or `~/Applications/Scopeproof Capture.app` exists for a source installation.
- The shield is visible in the menu bar.
- **Open Local Console** opens a browser page while Scopeproof is running.
- **Open Evidence Folder** opens `~/Documents/Scopeproof Evidence`.
- **Generate Repository SBOM…** opens a masked one-time GitHub credential dialog and offers CycloneDX 1.6 or SPDX 2.3 JSON.
- **AWS S3 Storage…** opens the authentication, security-profile, KMS/Object Lock, lifecycle/replication, and FIPS configuration. Identity Center credentials stay in memory; manual credentials use Keychain. Use **Save & Verify** for an existing bucket or **Create & Harden Bucket** after reviewing the irreversible retention warning.
- **Browse S3 Evidence…** searches and sorts immutable versions under the verified prefix and downloads one selected PNG/JSON version to an explicit quarantined local destination.
- The capture form shows the selected catalog version, source, and control count; **Update Controls…** validates and imports an approved JSON, OSCAL JSON, or CSV catalog without changing existing evidence.
- A browser-window test capture shows a real right-side Mac menu-bar pixel strip across the top, followed by the selected framework/control, canonical capture timestamp, local clock/timezone reading, and origin-only source URL in its visible banner.
- The PNG, manifest, and lifecycle sidecar appear together under the expected framework/control folder.

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| `swift` is not found | Run `xcode-select --install`, finish Apple's installer, and retry. |
| Scopeproof is not in `/Applications` | The source installer intentionally uses the current user's `~/Applications` folder; the DMG installs into `/Applications`. |
| Local Console does not open | Choose **Open Local Console**. If the session expired, quit and reopen Scopeproof. |
| Settings fields or checkbox labels are clipped | Install build 20 or newer. **Capture & Jira Settings…** separates the bounded form into **Capture & Local** and **Jira** tabs. |
| Browser reports unauthorized | Do not reuse an old loopback URL; reopen the console from the shield menu to establish a fresh per-launch session. |
| Capture permission repeats | Confirm the enabled entry matches the installed copy you launch, remove obsolete copies, then fully quit and reopen Scopeproof. |
| Evidence cannot be saved under Documents | Open **System Settings → Privacy & Security → Files & Folders**, allow Scopeproof Capture to access Documents, then quit and reopen the same installed copy. Confirm any iCloud Drive or enterprise sync policy is approved for compliance evidence. |
| Menu says `Waiting for evidence review…` | Close the menu and use the review workspace Scopeproof placed above the browser. Save or discard it before starting another operation. |
| Capture cannot find the intended window | Use **Choose Browser Window…** and select the exact browser/window title. |
| Repository SBOM authentication fails | Create a fresh fine-grained token selected only for the repository with Metadata: read and Contents: read, then submit a new run. The app never retains or retries a one-time token. |
| The app says SSE-S3 does not use a KMS key | Select SSE-KMS or DSSE-KMS when the bucket uses your customer-managed key, or clear the KMS ARN for an intentional SSE-S3 bucket. |
| S3 verification or upload fails | Confirm the STS expiration, same-account bucket owner, posture-read permissions, KMS/Object Lock policy, exact prefix, and reported control failure; then re-verify before retrying. |
| Hosted upload reports scanner or timestamp unavailable | Keep using the local artifact, ask the service operator to restore the independent scanner/RFC 3161 boundary, then retry the unchanged schema-7 pair. The server intentionally stores nothing for this failed attempt. |
| Hosted evidence is unverified or quarantined | Do not approve, export, package, download, or disclose it. Retry the original current upload to rescan/finalize it; recapture unsigned legacy evidence. Never manually change the trust fields. |

## Managed distribution

The local development build is ad-hoc signed. Distribution to other Macs without building from source should use a Developer ID Application certificate, hardened runtime, Apple notarization, stapling, an approved release manifest, and independent digest verification. Follow the [deployment guide](DEPLOYMENT.md); do not distribute the ad-hoc build as a trusted production release.

Release managers can build the explicitly labeled development-preview disk image with `./Scripts/build_development_dmg.sh`. The script refuses a non-ad-hoc application, verifies the mounted app, Applications shortcut, disk image, and checksum, and writes the artifacts under `DerivedData/`. Production candidates must be built, signed, and notarized by the protected workflow; `Scripts/publish_release.sh` only verifies and promotes that exact attested candidate and never rebuilds it.
