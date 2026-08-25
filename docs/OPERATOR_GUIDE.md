# Scopeproof operator guide

This guide is for evidence collectors, control owners, and reviewers. It describes the normal evidence lifecycle from a live system to an assessor-ready artifact.

## Install and open the local Mac app

For the simplest test installation on an Apple Silicon Mac, download the [Scopeproof Capture 1.8.0 development preview](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/tag/v1.8.0-development-preview.1), verify its adjacent SHA-256 file, open the DMG, and drag **Scopeproof Capture** to **Applications**. This build is ad-hoc signed and not Apple-notarized; it is not a managed production release.

Developers can instead build from the repository root:

```bash
./Scripts/run_macos_capture.sh
```

The command builds Scopeproof Capture, installs it for the current user in `~/Applications`, and launches it. No administrator password is required. If Swift is missing, run `xcode-select --install`, complete the installation, and try again. The DMG installs into `/Applications`; consistently launch one installed copy so Screen Recording permission remains associated with the intended application. See the [macOS installation guide](MACOS_INSTALLATION.md) for checksum, permission, update, verification, and troubleshooting details.

Look for the Scopeproof shield in the menu bar. On the first capture, allow **Scopeproof Capture** under **System Settings → Privacy & Security → Screen & System Audio Recording**, then quit and reopen the app once.

Scopeproof opens its **Local Console** in your browser at launch. This console runs only while the menu-bar app is running, listens only on the Mac loopback interface, and does not require a hosted account or device token. Use it to search, preview, filter, and review local evidence. Choose **Open Local Console** from the shield menu if you close the browser tab.

## Before collecting evidence

1. Confirm the system, environment, assessment period, framework, and control are in scope.
2. Confirm the source view shows the minimum information needed to prove the control.
3. Remove unrelated customer, employee, authentication, or cardholder data from the view where possible.
4. For Jira-linked work, confirm the destination issue and project are approved for the evidence classification.
5. Confirm **Scopeproof Capture** is enabled under macOS **System Settings → Privacy & Security → Screen & System Audio Recording**.

## Capture a screenshot on macOS

1. Open **Scopeproof Capture** from your Applications folder, then select its shield in the menu bar.
2. Choose **Capture Frontmost Browser Window**, **Choose Browser Window…**, **Capture Scrolling Evidence…**, **Open URL & Capture…**, or **Capture Entire Display**.
3. In the classification dialog, select the compliance area and control. Enter a meaningful evidence filename, title, system/asset, environment, assessment period, and evidence owner.
4. Confirm the **Page URL**. **Capture Frontmost Browser Window** attempts to prefill the active Safari, Chrome, Edge, or Arc tab after macOS grants browser Automation access; **Open URL & Capture** supplies its opened address. Paste the complete HTTP or HTTPS address when detection is unavailable or when using Firefox. Scopeproof never reuses a prior URL when frontmost detection fails. It displays the complete sanitized URL in the header and manifest while removing embedded credentials and redacting sensitive query or fragment values.
5. Optionally enter a Jira issue key such as `GRC-123`, tags, expected-evidence guidance, and a concise explanation of what the artifact proves.
6. Inspect the **Saved as** preview. The final path is organized as `<Compliance area>/<Control>/<Assessment period>`.
7. Inspect the review workspace. Confirm the correct window, full URL, scope, timestamp context, and automatic redactions. Drag over any additional sensitive value to apply an irreversible manual mask.
8. Save the reviewed capture. Scopeproof never saves the temporary unredacted capture.

Each saved item can contain:

- `.png`: stamped, redacted screenshot.
- `.json`: immutable capture manifest, metadata, SHA-256, and capture-chain hashes.
- `.review.json`: hash-chained lifecycle decisions and review notes.
- `.receipt.json`: server evidence identity and signed timestamp receipt, when uploaded.

Files are stored under `~/Pictures/Scopeproof Evidence` and are private to the current macOS account.

### Capture a page that needs multiple screenshots

1. Position the browser at the first evidence section and choose **Capture Scrolling Evidence…**.
2. Complete the ordinary classification dialog, including the full Page URL, then select the exact browser window.
3. After Scopeproof captures the first viewport, switch to the browser, scroll down with a small visible overlap, and return to Scopeproof. Do not resize the window or change browser zoom.
4. Choose **Capture Next Section**. Repeat as needed; after at least two sections, choose **Finish & Review**.
5. Inspect the single combined image. Numbered **CONTINUED** dividers distinguish the captured viewports, while the ordinary evidence banner appears once above the full artifact.
6. Complete redaction review and save normally.

Scopeproof bounds section count and final image size. If the maximum is reached, finish the current composite or cancel it. All intermediate viewports are memory-only and every section is discarded if you cancel, the browser window changes size, safety scanning fails, or review is not completed.

## Review and approve

1. Use **Evidence library** in the Local Console or choose **Search Evidence…** for the native review window.
2. Filter by framework, control, system, date, lifecycle status, or keyword. Jira issue keys are searchable.
3. Open the screenshot and confirm the control mapping, source, period, system, redactions, and visible timestamp banner.
4. Choose **Review Status…** and assign the owner/reviewer, useful tags, a decision, and a rationale.
5. Use **Approved** only when the artifact is current, complete, correctly scoped, and safe to disclose. Use **Superseded** for replaced evidence and **Rejected** for unsuitable evidence.

Approval, rejection, and supersession require a note. Lifecycle changes are written to the sidecar record; the original capture manifest is not rewritten.

## Upload and retry

Local operation requires no enrollment. To add optional hosted synchronization, enroll the Mac from **Connections → Mac capture devices**, then paste the one-time device token into **Capture & Jira Settings…**. The token is stored in the macOS Keychain. Leave Server URL blank for local-only mode.

If an upload fails, local evidence remains available. Correct the network, server URL, or revoked-token issue and choose **Retry Pending Uploads**. Never send a device token in email, Jira, chat, or an evidence package.

### Store evidence in AWS S3

Choose **AWS S3 Storage…** separately from hosted synchronization. For production, enter a same-account bucket, nonempty prefix, customer-managed KMS key, Object Lock mode/retention, and an expiring IAM Identity Center or AssumeRole credential set. Use **Save & Verify** for an existing bucket or **Create & Harden Bucket** after reviewing the irreversible Object Lock warning. The app binds the verified account, principal, destination, and posture in Keychain; any routing change disables uploads until verification. Remove all setup permissions afterward.

The encryption selection must match the bucket: select **SSE-KMS** or **DSSE-KMS** when entering a KMS ARN; **SSE-S3** does not use that ARN. When temporary credentials are not yet available, Compatible S3 can use a dedicated no-console IAM user restricted to the exact bucket, prefix, regional S3 service, and KMS encryption context. Do not use a personal or administrator key, and migrate to the production temporary-credential workflow as soon as possible. The complete identity and key-policy templates are in [AWS S3 evidence storage](S3_STORAGE.md).

Enable browsing only for operators who need it. **Browse S3 Evidence…** loads up to 5,000 object versions under the configured prefix. Select a PNG/JSON version and choose **Download Selected…**. Scopeproof signs the exact version ID and ETag, validates size/checksum/content, applies private permissions and macOS quarantine, and never auto-opens it. Add `s3:ListBucketVersions`, `s3:GetObjectVersion`, and KMS decrypt only to this browser role.

Enable automatic S3 upload to copy each newly saved, safety-scanned PNG and immutable manifest, or leave it off and choose **Upload Pending Evidence to S3** manually. A successful pair creates a local `.s3.json` receipt with exact versions, S3 checksums/request IDs, caller identity, encryption, and retention. Deploy and test the documented CloudTrail alerting template before production use.

## Send approved evidence to Jira Cloud

First connect your Jira account under **Scopeproof web → Connections → Jira Cloud**, select the intended site, and restrict the connection to approved project keys. Use **Test connection** before the first transfer.

On the Mac, assign a Jira issue during capture, complete lifecycle review, and mark the artifact **Approved** with a rationale. Upload that exact evidence set to Scopeproof and have an authenticated reviewer approve the hosted artifact. Then open **Search Evidence…**, select the artifact, and choose **Upload to Jira Cloud…**. Confirm the live issue summary and status before uploading. Scopeproof validates both approval records and the evidence hashes, then records a signed `.jira.json` receipt. Use **Copy Jira Comment** and manual attachment when OAuth is unavailable or policy requires manual transfer.

## Generate a repository SBOM

Choose the workflow that matches the evidence requirement:

- Use the **Mac shield menu** for a direct one-time auditor export. It requires no hosted account and produces JSON plus a checksum, but it is not automatically attached to an assessment, reviewed, compared, or included in a Scopeproof package.
- Use the **hosted console** when the SBOM must become assessment-scoped PCI DSS 6.3.2 evidence with RBAC, encrypted retention, prior-run comparison, independent approval, audited download, and package inclusion.

### Direct one-time export on the Mac

1. Choose **Generate Repository SBOM…** from the Scopeproof shield menu.
2. Enter exactly `https://github.com/owner/repository`, a fresh token selected only for that repository with **Metadata: read** and **Contents: read**, and a branch, tag, or commit.
3. Choose CycloneDX 1.6 JSON or SPDX 2.3 JSON and select **Generate**. The masked token is cleared immediately.
4. Choose a save location. Scopeproof writes the JSON and an adjacent `.sha256.txt` checksum with current-user-only file permissions.
5. Record the immutable commit and verify the checksum before transfer. Revoke the GitHub token after success or failure.

The Mac reads only recognized lockfile blobs through GitHub's commit/tree/blob APIs. It does not clone, check out, build, install, execute, or unpack repository content. It uses an ephemeral URL session without cookies, URL cache, credential storage, redirects, persistence, or automatic retry. A direct export remains outside the Local Console screenshot lifecycle and must be reviewed and transferred under your organization's evidence-handling process.

### Hosted assessment evidence

Use either a platform-managed GitHub organization or a one-time exact GitHub URL and short-lived read-only token. The active assessment must include PCI DSS control **6.3.2** and, when system scope is populated, the selected `owner/repository`, owner/organization, or `GitHub`.

1. Open **SBOMs** in the hosted Scopeproof console and choose **Generate SBOM**.
2. Choose **Managed organization** and select a repository, or choose **One-time repository** and enter `https://github.com/owner/repository` plus a repository-scoped token with Metadata and Contents read access.
3. Enter the branch, tag, or commit to inventory and choose CycloneDX 1.6 JSON or SPDX 2.3 JSON.
4. Generate the SBOM. Scopeproof resolves the ref to an immutable commit before reading supported lockfiles.
5. Review the repository, resolved commit, source-archive digest, parsed manifests, component totals, generator version, and change summary.
6. Open the linked evidence and inspect the actual JSON. A reviewer or administrator other than the generator must approve it before package inclusion.
7. Export the assessment package. The approved SBOM appears under PCI DSS 6.3.2.

The **JSON** action downloads the generated evidence before approval for authorized review; every download is authenticated and audited. A prior-run comparison is a review aid, not the authoritative inventory. See the [repository SBOM guide](SBOM_GUIDE.md) for supported inputs, safety limits, and interpretation.

For one-time hosted access, Scopeproof masks the token and clears the field at submission. It uses the token only during that request and does not write it to application storage, audit details, settings, logs, browser storage, or Keychain. Because the token is unavailable afterward, transient failures do not retry automatically; re-enter a fresh token for a new run. Prefer a short expiry and revoke the token after success or failure.

## Export for an assessor

1. Complete lifecycle review first; only **Approved** evidence is eligible.
2. Choose **Export Assessor Package…** and select the framework and assessment period.
3. Name the package and identify the preparer.
4. Transfer the resulting ZIP and its separate `.sha256.txt` file through an approved secure channel.
5. Send the signing-key fingerprint to the assessor through a separate trusted channel.

Detailed validation steps are in the [assessor guide](ASSESSOR_GUIDE.md). Jira-specific transfer steps are in the [Jira handoff guide](JIRA_HANDOFF.md).

## Retention and disposal

**Apply Local Retention…** moves expired local evidence to Trash; it does not delete hosted evidence. Confirm legal hold, assessment status, regulatory retention, contractual obligations, and organizational policy before disposing of evidence. Empty the Trash only when the deletion is authorized.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Screen capture permission error | Enable Scopeproof Capture in Screen & System Audio Recording, fully quit the app, and reopen it. |
| Local Console does not open | Choose **Open Local Console** from the shield menu. If the session expired, fully quit and reopen Scopeproof Capture. |
| Wrong browser window | Use **Choose Browser Window…** and select the exact titled window. |
| Frontmost Page URL is blank | Paste the URL manually. For Safari, Chrome, Edge, or Arc, optionally enable the browser under **System Settings → Privacy & Security → Automation → Scopeproof Capture**. Firefox requires manual URL entry. |
| Scrolling sections do not align | Start again, keep the selected window size and zoom unchanged, and leave a small visible overlap when scrolling. Scopeproof separates viewports instead of guessing or deleting overlapping pixels. |
| Capture context dialog repeats | Complete every field marked `*`; if a Jira key is present it must look like `GRC-123`. |
| No Jira key in filename/banner | Edit capture defaults, enter the issue key, then recapture; existing immutable evidence is not renamed. |
| Upload remains pending | Verify the HTTPS server URL and active device token, then retry pending uploads. |
| Generate SBOM is disabled | Confirm your role can generate SBOMs and the assessment is active with PCI DSS 6.3.2 in scope. Managed secrets are optional when using one-time repository access. |
| Native SBOM menu says generation is already running | Wait for the current one-time request to finish; the Mac intentionally allows only one repository scan at a time. |
| Repository is missing | Confirm it belongs to the configured organization, is within the token's repository selection, and is among the bounded inventory results. |
| SBOM reports no supported components | Commit a supported lockfile with pinned versions, or request a reviewed parser addition for that ecosystem. |
| Package export is unavailable | Approve at least one artifact in the selected framework/period and resolve any integrity failure. |
| Evidence cannot be found | Search all frameworks and periods, or use **Open Evidence Folder**. |
