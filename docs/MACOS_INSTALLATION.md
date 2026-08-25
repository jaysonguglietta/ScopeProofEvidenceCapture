# Scopeproof Capture installation for macOS

This guide installs the local-first Scopeproof Capture menu-bar application for one macOS user. Local capture, evidence search, lifecycle review, and assessor-package export do not require a hosted Scopeproof account, server URL, or device token.

The Mac app can generate a direct, one-time repository SBOM without a hosted account. Choose **Generate Repository SBOM…**, enter an exact GitHub URL and short-lived read-only token, and save CycloneDX or SPDX JSON plus its SHA-256 checksum. The credential is used only for the active request and is not stored. Use the hosted console instead when the SBOM must be assessment-scoped, independently approved, compared with prior evidence, or included automatically in an assessor package. See the [repository SBOM guide](SBOM_GUIDE.md).

## Requirements

- macOS 14 or newer.
- A local copy of this repository.
- Apple's Swift toolchain. Install it with `xcode-select --install` if `swift --version` is unavailable.
- Screen Recording permission for browser-window capture.
- HTTPS access to `api.github.com` when using local repository SBOM generation.
- HTTPS access to the configured region-specific AWS S3 and STS endpoints (or their FIPS variants) when using optional S3 storage.

## Install and launch

From Terminal, change to the repository root and run:

```bash
./Scripts/run_macos_capture.sh
```

The script builds a release executable, creates `DerivedData/Scopeproof Capture.app`, installs it at `~/Applications/Scopeproof Capture.app`, replaces an older per-user installation when present, and launches it. Administrator access is not required.

### Development-preview DMG

GitHub prereleases may include `Scopeproof-Capture-<version>-development-preview.dmg` and its adjacent `.sha256` file. This DMG provides the familiar drag-to-Applications layout, but the application inside is ad-hoc signed and is not Apple-notarized. It is intended only for named testers who understand the Gatekeeper warning; it is not a trusted public production release.

After downloading both files, verify the checksum from Terminal:

```bash
shasum -a 256 -c Scopeproof-Capture-*-development-preview.dmg.sha256
```

Open the DMG and drag **Scopeproof Capture** to **Applications**. If macOS blocks the preview, do not disable Gatekeeper globally. Confirm the checksum and release source first, then use **System Settings → Privacy & Security → Open Anyway** only when your organization permits development-preview software.

Scopeproof appears as a shield in the menu bar and opens its Local Console in the default browser. The console is served by the running Mac app on a random `127.0.0.1` port and is not published to the LAN or internet. If the tab is closed, choose **Open Local Console** from the shield menu or press `Command-Shift-L`.

## Grant capture permission

On the first capture:

1. Open **System Settings → Privacy & Security → Screen & System Audio Recording**.
2. Enable **Scopeproof Capture**.
3. Fully quit Scopeproof from its shield menu.
4. Reopen `~/Applications/Scopeproof Capture.app`.

If Scopeproof is not listed, attempt one capture first so macOS can register the permission request. The permission belongs to the installed application; consistently launch the copy in `~/Applications` rather than an older build elsewhere.

## Confirm local-only settings

Open **Capture & Jira Settings…** from the shield menu. Leave **Server URL** blank to prevent hosted synchronization. The Local Console, capture, search, review, Jira comment generation, and local assessor-package export continue to work.

Evidence is stored under `~/Pictures/Scopeproof Evidence/<framework>/<control>/`. The Local Console's SQLite search index lives in the current user's Application Support folder and can be rebuilt from the immutable evidence manifests and lifecycle sidecars.

## Update or rebuild

Pull or copy the updated repository source, then run the installation command again:

```bash
./Scripts/run_macos_capture.sh
```

The script quits a running Scopeproof process before replacing the application. Evidence under `~/Pictures/Scopeproof Evidence`, Keychain keys, and user preferences are not removed. Use `./Scripts/run_macos_capture.sh --no-launch` when installation should finish without opening the app.

## Verify the installation

- `~/Applications/Scopeproof Capture.app` exists.
- The shield is visible in the menu bar.
- **Open Local Console** opens a browser page while Scopeproof is running.
- **Open Evidence Folder** opens `~/Pictures/Scopeproof Evidence`.
- **Generate Repository SBOM…** opens a masked one-time GitHub credential dialog and offers CycloneDX 1.6 or SPDX 2.3 JSON.
- **AWS S3 Storage…** opens the security-profile, KMS/Object Lock, lifecycle/replication, FIPS, and Keychain credential configuration. Use **Save & Verify** for an existing bucket or **Create & Harden Bucket** after reviewing the irreversible retention warning.
- **Browse S3 Evidence…** searches and sorts immutable versions under the verified prefix and downloads one selected PNG/JSON version to an explicit quarantined local destination.
- A test capture shows the selected framework/control, canonical capture timestamp, and dedicated Mac menu-bar date/time and timezone line in its visible banner.
- The PNG, manifest, and lifecycle sidecar appear together under the expected framework/control folder.

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| `swift` is not found | Run `xcode-select --install`, finish Apple's installer, and retry. |
| Scopeproof is not in `/Applications` | The development installer intentionally uses the current user's `~/Applications` folder. |
| Local Console does not open | Choose **Open Local Console**. If the session expired, quit and reopen Scopeproof. |
| Browser reports unauthorized | Do not reuse an old loopback URL; reopen the console from the shield menu to establish a fresh per-launch session. |
| Capture permission repeats | Confirm the enabled entry is the copy at `~/Applications/Scopeproof Capture.app`, then quit and reopen it. |
| Capture cannot find the intended window | Use **Choose Browser Window…** and select the exact browser/window title. |
| Repository SBOM authentication fails | Create a fresh fine-grained token selected only for the repository with Metadata: read and Contents: read, then submit a new run. The app never retains or retries a one-time token. |
| The app says SSE-S3 does not use a KMS key | Select SSE-KMS or DSSE-KMS when the bucket uses your customer-managed key, or clear the KMS ARN for an intentional SSE-S3 bucket. |
| S3 verification or upload fails | Confirm the STS expiration, same-account bucket owner, posture-read permissions, KMS/Object Lock policy, exact prefix, and reported control failure; then re-verify before retrying. |

## Managed distribution

The local development build is ad-hoc signed. Distribution to other Macs without building from source should use a Developer ID Application certificate, hardened runtime, Apple notarization, stapling, an approved release manifest, and independent digest verification. Follow the [deployment guide](DEPLOYMENT.md); do not distribute the ad-hoc build as a trusted production release.

Release managers can build the explicitly labeled development-preview disk image with `./Scripts/build_development_dmg.sh`. The script refuses a non-ad-hoc application, verifies the mounted app, Applications shortcut, disk image, and checksum, and writes the artifacts under `DerivedData/`. Production release engineering must continue to use the fail-closed Developer ID and notarization workflow in `Scripts/publish_release.sh`.
