# Scopeproof Capture for macOS

Scopeproof Capture is a local menu-bar companion for producing timestamped PCI evidence screenshots.

## Capture workflow

1. Launch the app and select the shield icon in the macOS menu bar.
2. Choose **Start / Edit Capture Session** and enter the PCI control, system, environment, assessment period, and evidence title.
3. Choose an exact browser window, capture the frontmost browser, open a URL after a delay, or capture a full display.
4. Scopeproof runs local OCR, masks detected PANs and credentials, and shows a preview. Save only after reviewing the result.
5. Find the stamped PNG and JSON integrity manifest in `~/Pictures/Scopeproof Evidence`, or enable upload in **Capture Settings**.

Every screenshot includes local date, time, timezone, PCI context, and a unique evidence ID. The adjacent JSON manifest contains UTC time, source metadata, pixel dimensions, redaction counts, the PNG SHA-256 digest, and the previous/current chain hashes. A successful upload adds a local receipt containing the server-signed time attestation and optional RFC 3161 timestamp token.

The app never captures on a timer or in the background without an explicit menu action. OCR runs on the Mac and recognized text is not retained. Device credentials are stored in the macOS Keychain, not preferences or screenshot metadata.

## Connect to Scopeproof

1. In the web app, open **Connections → Mac capture devices → Enroll device**.
2. Copy the one-time token immediately; only its hash is retained by the server.
3. In the menu-bar app, open **Capture Settings**, enter the HTTPS Scopeproof URL, paste the token, and optionally enable automatic upload.
4. Use **Retry Pending Uploads** after an offline capture. Tokens can be revoked from the web app at any time.

The hosted API verifies the PNG digest and manifest safety state before accepting an upload, encrypts accepted evidence with AES-256-GCM in R2, and records device identity plus chain-of-custody metadata in the append-only audit trail.

## Help and operations

Choose **Help & How to Use…** from the menu for an in-app quick start, evidence-file explanation, permission recovery, security model, and troubleshooting guidance. The menu also provides recent captures, the evidence folder, configurable retention, Launch at Login, permission status, and secure update checks.

## Build

From the repository root:

```bash
./Scripts/build_macos_capture.sh
```

The signed local app is created at `DerivedData/Scopeproof Capture.app`.

The local build uses an explicit designated requirement tied to `com.scopeproof.capture`. This keeps the app's Screen Recording permission identity stable across local rebuilds.

For a production release, set `SCOPEPROOF_CODESIGN_IDENTITY` to a trusted Developer ID Application identity. Set `SCOPEPROOF_NOTARY_PROFILE` to an `xcrun notarytool store-credentials` Keychain profile to submit, staple, and validate notarization automatically. The hosted release endpoint supplies release metadata to the app's daily update check; configure `MACOS_LATEST_VERSION`, `MACOS_RELEASE_URL`, `MACOS_RELEASE_SHA256`, and `MACOS_RELEASE_NOTES` in the hosted environment. Production distribution should use HTTPS and an independently verified release digest.
