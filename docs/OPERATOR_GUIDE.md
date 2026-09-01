# Scopeproof operator guide

This guide is for evidence collectors, control owners, and reviewers. It describes the normal evidence lifecycle from a live system to an assessor-ready artifact.

## Install and open the local Mac app

For a tagged-build evaluation on an Apple Silicon Mac, download the older [Scopeproof Capture 1.8.1 development preview](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/tag/v1.8.1-development-preview.1), verify its adjacent SHA-256 file, open the DMG, and drag **Scopeproof Capture** to **Applications**. It was built from `8cd2d5c`, predates the current **Unreleased 1.10.0 (build 25)** native changes, is ad-hoc signed, and is not Apple-notarized. No 1.10.0 DMG exists. Use an exact reviewed source checkout to test current behavior until a new DMG is published; the public release remains 1.8.1 until a separate release workflow succeeds.

Developers can instead build from the repository root:

```bash
./Scripts/run_macos_capture.sh
```

The command builds Scopeproof Capture, installs it for the current user in `~/Applications`, and launches it. No administrator password is required. If Swift is missing, run `xcode-select --install`, complete the installation, and try again. The DMG installs into `/Applications`; consistently launch one installed copy so Screen Recording permission remains associated with the intended application. See the [macOS installation guide](MACOS_INSTALLATION.md) for checksum, permission, update, verification, and troubleshooting details.

Look for the Scopeproof shield in the menu bar. On the first capture, allow **Scopeproof Capture** under **System Settings → Privacy & Security → Screen & System Audio Recording**, then quit and reopen the app once.

Scopeproof opens its **Local Console** in your browser at launch. This console runs only while the menu-bar app is running, listens only on the Mac loopback interface, and does not require a hosted account or device token. The launch address carries a one-time nonce after `#token=`; the page exchanges it for a separate short-lived in-memory bearer and clears the fragment. Scopeproof creates no localhost authentication cookie. Do not copy or share the launch address. Its **Evidence library** automatically shows only the active tenant/workspace's local screenshots and, when configured and verified, screenshot versions beneath the matching S3 prefix. Use storage/framework/control/period/status filters and group by control, assessment period, or framework. `Local`, `S3`, and `Local + S3` badges make the authoritative locations explicit. Choose **Open Local Console** from the shield menu if you close the browser tab.

The Local Console is optional. To prevent it from starting automatically, open **Capture & Jira Settings…**, use the **Capture & Local** tab, clear **Open Local Console when Scopeproof launches**, save, then quit and reopen Scopeproof. The current random loopback port closes when the app quits; screenshot capture and the native evidence tools continue to work.

In local-only mode, the menu shows **Open GitHub Releases…** for development-preview DMGs and checksums and disables **Hosted Uploads: Not connected**. Automatic signed update checks and hosted evidence/Jira transfer require a server-specific device token and a release with that exact HTTPS origin compiled into its allowlist, but local capture, review, search, S3 storage, and package export do not. The checked-in current-source allowlist is empty, so a normal local release build cannot be redirected to an arbitrary hosted server.

### Local evidence versus hosted-trusted evidence

The local app does not depend on the hosted OCR/DLP scanner or timestamp authority. You can continue to capture, redact, review, search, retain, and export locally when no hosted service is configured. New captures use a current signed manifest bound to the selected tenant/workspace and its local capture-chain head. Lifecycle and local legal-hold changes use separate signing/rollback domains and require macOS local-user authentication.

Uploading introduces independent server controls. The server verifies the schema-8 device signature, exact configured tenant/workspace, and exact PNG/manifest digests, performs its own OCR/DLP scan of the exact PNG bytes, verifies a trusted RFC 3161 timestamp, and finalizes the artifact into the device's hosted chain. Local OCR is useful endpoint protection, but it is not a substitute for this independent hosted scan. The server evaluates recognized OCR text only in memory and retains no recognized text; it stores only digest-bound scanner policy, origin, completion time, and receipt metadata.

Until every hosted step succeeds, the item is unverified/quarantined and cannot be read, previewed, approved, packaged, exported, or sent to Jira. An older or unsigned capture cannot be converted into current hosted evidence by changing a status or database field. Recapture it with the current app. If an otherwise current upload is missing its server scan or final chain link, retry the original exact schema-8 PNG/manifest pair so the server can rescan and reconcile it.

## Before collecting evidence

1. Confirm the customer/tenant, workspace, system, environment, assessment period, framework, and control are in scope. For a non-default identity, set the lowercase tenant and workspace in **Capture & Jira Settings…** before enrollment, S3 verification, or capture. Switching identity stops the previous Local Console, rejects suspended requests, cancels and closes S3 activity, removes Scopeproof's S3 Keychain binding, and resets S3 configuration; enroll and verify credentials for the new identity.
2. Confirm the source view shows the minimum information needed to prove the control.
3. Remove unrelated customer, employee, authentication, or cardholder data from the view where possible.
4. For Jira-linked work, confirm the destination issue and project are approved for the evidence classification.
5. Confirm **Scopeproof Capture** is enabled under macOS **System Settings → Privacy & Security → Screen & System Audio Recording**.

## Capture a screenshot on macOS

1. Open **Scopeproof Capture** from your Applications folder, then select its shield in the menu bar.
2. Choose **Capture Frontmost Browser Window**, **Choose Browser Window…**, **Capture Scrolling Evidence…**, **Open URL & Capture…**, or **Capture Entire Display**.
3. In the classification dialog, select the compliance area and control. Enter a meaningful evidence filename, title, system/asset, environment, assessment period, and evidence owner.
   - The **Catalog** row shows the selected framework version, control count, and source. Choose **Update Controls…** to import a current Scopeproof JSON, OSCAL catalog JSON, or CSV from the framework publisher or your organization's approved GRC source. Confirm publisher version and provenance before importing; Scopeproof records the supplied version/source plus the file's SHA-256 digest but cannot grant authenticity to an arbitrary operator-selected file.
4. Confirm the **Page URL**. **Capture Frontmost Browser Window** attempts to prefill the active Safari, Chrome, Edge, or Arc tab after macOS grants browser Automation access; **Open URL & Capture** supplies its opened address. Paste the HTTP or HTTPS address when detection is unavailable or when using Firefox. Scopeproof never reuses a prior URL when frontmost detection fails. The header and manifest retain only its lowercase origin; user information, path, query, and fragment are removed before persistence.
5. Optionally enter a Jira issue key such as `GRC-123`, tags, expected-evidence guidance, and a concise explanation of what the artifact proves.
6. Inspect the **Saved as** preview. The final path is organized as `<Compliance area>/<Control>/<Assessment period>`.
7. Inspect the review workspace. Confirm the live Mac menu-bar strip across the top shows the expected date/time context, then confirm the correct window, source origin, scope, evidence header, and automatic redactions. Status icons and menu-bar text are evidence pixels too; drag over anything that should not be disclosed to the assessor.
8. Save the reviewed capture. Scopeproof never saves the temporary unredacted capture.

When scanning finishes, the menu status changes to **Waiting for evidence review…** and Scopeproof brings the modal review workspace above the browser on the active desktop. Choose **Save Evidence**, **Discard**, press Escape, or close the review window; closing is treated as a discard and cannot leave the app trapped in a hidden modal state.

Each saved item can contain:

- `.png`: stamped, redacted screenshot.
- `.json`: immutable capture manifest, metadata, SHA-256, and capture-chain hashes.
- `.review.json`: hash-chained lifecycle decisions and review notes.
- `.receipt.json`: server evidence identity and signed timestamp receipt, when uploaded.

New files are stored under `~/Documents/Scopeproof Evidence` and use current-account-only permissions. The default local identity writes directly under that root; another identity writes under `tenants/<tenant>/workspaces/<workspace>/`. Evidence under `~/Pictures/Scopeproof Evidence` remains discoverable and is not moved automatically. A valid schema-8 or signed schema-7 artifact may remain locally trust-bearing under the lifecycle rules for its schema, regardless of which supported root contains it; schema 7 cannot cross the current hosted tenant/workspace boundary. Unsigned schema-6 and older evidence is visibly unverified and browsing-only; it cannot enter review, pending-upload, retention/legal-hold, assessor-package, or Jira workflows and must be recaptured. A Keychain-backed commit journal makes an interrupted save recover as either a complete validated image/manifest/lifecycle set or a removed partial set. Before collection, confirm that iCloud Drive, enterprise file synchronization, backup, and DLP settings for Documents are approved for the evidence classification.

The visible menu-bar clock is useful corroborating context, but it is controlled by the endpoint and does not independently prove time. For scrolling evidence, Scopeproof captures the menu-bar strip when you choose **Finish & review**, rather than when the first viewport was taken. A local artifact may rely on that corroborating context. Production hosted evidence additionally requires the verified RFC 3161 timestamp attestation included with its signed server receipt.

### Capture a page that needs multiple screenshots

1. Position the browser at the first evidence section and choose **Capture Scrolling Evidence…**.
2. Complete the ordinary classification dialog, including the Page URL when relevant, then select the exact browser window. Only its origin will enter the saved evidence.
3. After Scopeproof captures the first viewport, switch to the browser, scroll down with a small visible overlap, and return to Scopeproof. Do not resize the window or change browser zoom.
4. Choose **Capture Next Section**. Repeat as needed; after at least two sections, choose **Finish & Review**.
5. Inspect the single combined image. Numbered **CONTINUED** dividers distinguish the captured viewports, while the ordinary evidence banner appears once above the full artifact.
6. Complete redaction review and save normally.

Scopeproof bounds section count and final image size. If the maximum is reached, finish the current composite or cancel it. All intermediate viewports are memory-only and every section is discarded if you cancel, the browser window changes size, safety scanning fails, or review is not completed.

## Review and approve

1. Use **Evidence library** in the Local Console or choose **Search Evidence…** for the native review window.
2. Filter by framework, control, system, date, lifecycle status, or keyword. Jira issue keys are searchable.
3. Open the screenshot and confirm the control mapping, source, period, system, redactions, and visible timestamp banner.
4. Choose **Review Status…**, assign the owner, useful tags, a decision, and a rationale. Scopeproof displays the reviewer as the authenticated macOS user; it does not trust a typed reviewer name. Complete the local-user authentication prompt to save a trust-bearing decision.
5. Use **Approved** only when the artifact is current, complete, correctly scoped, and safe to disclose. Use **Superseded** for replaced evidence and **Rejected** for unsuitable evidence.

Approval, rejection, and supersession require a note. Lifecycle changes are written to a signed sidecar and advance a tenant/workspace/file-scoped Keychain rollback head; the original capture manifest is not rewritten. Placing or releasing a local legal hold requires the same macOS authentication but uses a separate signing key and an immutable tenant/workspace/evidence/digest rollback scope. Deleting or moving its sidecar cannot silently release the hold: missing or inconsistent marker/head state blocks retention. A local hold does not change an S3 Object Lock legal hold.

## Upload and retry

Local operation requires no enrollment. To add optional hosted synchronization, use a reviewed app release whose exact pathless HTTPS server origin was compiled into `ScopeproofHostedAPIOrigins`, enroll the Mac from **Connections → Mac capture devices**, then paste that exact Server URL and the one-time device token into **Capture & Jira Settings…**. The checked-in source allowlist is empty; a release operator populates it with `SCOPEPROOF_HOSTED_API_ORIGIN` through `Scripts/configure_macos_release_identity.sh`. The token is stored in the macOS Keychain, expires after 30 days, and is shown only when created or rotated. Rotate it before expiry, immediately replace the Mac’s Keychain value, and revoke the device when it is lost, reassigned, or retired. Leave Server URL blank for local-only mode.

If an upload fails, local evidence remains available. Correct the network, server URL, revoked-token, independent-scanner, or RFC 3161 issue and choose **Retry Pending Uploads**. A scanner or required-timestamp failure stores no new hosted artifact. A later cross-store finalization failure can leave a hosted record quarantined; retrying the same exact pair lets the server reconcile and finalize it. Never send a device token in email, Jira, chat, or an evidence package, and never bypass quarantine with a manual status update.

### Manage hosted team access

The legacy Sites/D1/R2 source is for one organization only. If an authorized private instance is deployed and its identity-aware ingress has been proven, an administrator opens **Settings → Team & access**, creates an invitation for an exact email/role, and communicates only the normal sign-in URL; there is no invitation secret to copy. The identity must sign in before the 1–30 day invitation expires. Administrators can suspend, reactivate, revoke, or change roles, while the database prevents removal of the final active administrator. Suspension or revocation immediately blocks new web requests, devices owned by that member, and queued collector/SBOM retries. Keep at least two named administrators and use separate collector and reviewer identities.

The **Settings → Audit log** view shows the newest 250 material actions and the current bounded integrity result. Treat a failed or pending chain/checkpoint result as a production stop: compare the D1 head with the independently retained checkpoint and trusted signing-key fingerprint before resuming collection or export.

### Create scoped assessments and findings

In the hosted console, create or edit an assessment before collecting:

1. Select a reviewed versioned control catalog. The bundled **PCI DSS 4.0.1 · Scopeproof operations catalog** is intentionally a limited operations catalog, not the complete PCI DSS standard.
2. Enter at least one explicit system and select at least one control from that exact catalog before changing the assessment to **Active**. Drafts may remain incomplete; active assessments may not.
3. Confirm the period and owner. A scope reduction is a separately audited action. Collection, native upload, and SBOM generation fail if their framework, catalog version, system, or control falls outside the active scope.
4. Use **Load more** where offered. Evidence, runs, SBOMs, findings, assessments, and package history are cursor-paged; totals and control counts are server aggregates across the full filtered set, not the number of visible cards.

Use **Findings** for durable issues, not a local note on an evidence card. Bind each finding to the assessment and, when applicable, an in-scope control, evidence item, collection run, owner, severity, and due date. Reviewers can create and maintain ordinary finding work. Only a compliance lead or administrator can **Accept** risk or **Close** a finding, and that disposition requires a rationale. Closed is terminal; create a new finding for later recurrence.

### Store evidence in AWS S3

Choose **AWS S3 Storage…** separately from hosted synchronization. First verify the active tenant/workspace in **Capture & Jira Settings…**. For production, select a direct named **IAM Identity Center profile** or **Identity Center + assumed role**. Scopeproof can start AWS CLI v2 SSO login, keeps derived STS credentials only in memory, refreshes them before expiry, and rejects a refreshed account, role, tenant, or workspace that no longer matches the verified binding. Manual STS entry remains available when SSO cannot be used. Enter a same-account bucket, nonempty base prefix, customer-managed KMS key, and Object Lock mode/retention; SSE-KMS requires an enabled S3 Bucket Key. The app automatically adds `/tenants/<tenant>/workspaces/<workspace>` to that base prefix. Use **Save & Verify** for an existing bucket. For a new production bucket, prefer the reviewed `native-capture-evidence-bucket.yaml` CloudFormation stack; use **Create & Harden Bucket** only with a separately reviewed short-lived setup role. The app stores the verified account, principal/role scope, destination, tenant/workspace, and posture in Keychain; any identity, authentication, or routing change disables uploads until verification. The native verifier requires the template's exact transport/encryption/deletion-deny bucket policy. None of the supplied daily access templates grants setup permissions.

The encryption selection must match the bucket: select **SSE-KMS** or **DSSE-KMS** when entering a KMS ARN; **SSE-S3** does not use that ARN. Production rejects long-lived credentials. Compatible S3 can use a dedicated no-console IAM user restricted to the exact bucket, prefix, regional S3 service, and KMS encryption context only as a migration exception. Do not use a personal or administrator key. The complete identity/KMS guidance and optional secretless-authentication CloudFormation templates are linked from [AWS S3 evidence storage](S3_STORAGE.md).

Enable browsing only for operators who need it. **Browse S3 Evidence…** loads up to 5,000 object versions under the configured prefix. Select a PNG/JSON version and choose **Download Selected…**. Scopeproof signs the exact version ID and ETag, validates size/checksum/content, applies private permissions and macOS quarantine, and never auto-opens it. Add `s3:ListBucketVersions`, `s3:GetObjectVersion`, and KMS decrypt only to this browser role.

The Local Console uses the same verified prefix and role. Prefix-scoped `s3:ListBucketVersions` lets it list paired screenshot/manifest metadata and collapse immutable versions into one card. It labels a local artifact `Local + S3` only when the local upload receipt binds the exact S3 keys, versions, ETags, and checksums; an S3-only card remains visibly provenance-unverified and cannot be reviewed or treated as lifecycle-valid. For S3-only cards, **Load secure preview** first validates the paired exact-version manifest and then its PNG digest; this proves pair consistency, not trusted authorship. Previews are limited to 40 MiB, served only to the authenticated loopback page, and removed from temporary storage. If validated downloads are disabled but the list permission remains, metadata stays visible while preview/download controls are disabled. S3 failures leave the complete local library available with a recovery message.

Enable automatic S3 upload to copy each newly saved, safety-scanned PNG and immutable manifest, or leave it off and choose **Upload Pending Evidence to S3** manually. A successful pair creates a local `.s3.json` receipt with exact versions, S3 checksums/request IDs, caller identity, tenant/workspace, encryption, and retention. That receipt is evidence of the completed upload but is not sufficient by itself for later deletion. If local expiry cleanup would rely on S3, Scopeproof uses the current matching temporary session to perform live exact-version `HEAD` and Object Lock retention checks for every receipt object; any version, ETag, checksum, KMS, account, prefix, or future COMPLIANCE-retention mismatch blocks cleanup. Deploy and test the documented CloudTrail alerting template before production use.

## Send approved evidence to Jira Cloud

First connect your Jira account under **Scopeproof web → Connections → Jira Cloud**, select the intended site, and restrict the connection to approved project keys. Use **Test connection** before the first transfer.

On the Mac, assign a Jira issue during capture, complete lifecycle review, and mark the artifact **Approved** with a rationale. Upload that exact schema-8 tenant/workspace-bound evidence set to Scopeproof. The independent server scan, trusted timestamp, and final device-chain linkage must complete before an authenticated reviewer can read and approve the hosted artifact. Then open **Search Evidence…**, select the artifact, and choose **Upload to Jira Cloud…**. Confirm the live issue summary and status before uploading. Scopeproof revalidates both approval records, exact PNG and manifest hashes, server safety record, signed attestation, and final provenance link before disclosure, then records a signed `.jira.json` receipt. Use **Copy Jira Comment** and manual attachment only as an explicitly governed fallback; they do not turn unverified evidence into hosted-trusted evidence.

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

1. Complete lifecycle review first; only **Approved** evidence is eligible. In the hosted console, review the package preflight and resolve every blocker: zero eligible evidence, partial coverage, pending independent screenshot safety, pending native provenance, or more than 100 eligible artifacts prevents export.
2. Choose **Export Assessor Package…** and select the framework and assessment period.
3. Name the package and identify the preparer.
4. Transfer the resulting ZIP and its separate `.sha256.txt` file through an approved secure channel.
5. Send the signing-key fingerprint to the assessor through a separate trusted channel.

Detailed validation steps are in the [assessor guide](ASSESSOR_GUIDE.md). Jira-specific transfer steps are in the [Jira handoff guide](JIRA_HANDOFF.md).

## Retention and disposal

**Apply Local Retention…** moves expired local evidence to Trash; it does not delete hosted or S3 evidence. Active or invalid local hold state blocks cleanup. When the policy permits cleanup only after a durable S3 copy, Scopeproof must successfully revalidate every exact remote version and its unexpired COMPLIANCE Object Lock retention live; a receipt or object name alone is never enough. Confirm legal hold, assessment status, regulatory retention, contractual obligations, and organizational policy before disposing of evidence. Empty the Trash only when the deletion is authorized.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Screen capture permission error | Enable Scopeproof Capture in Screen & System Audio Recording, fully quit the app, and reopen it. |
| Local Console does not open | Choose **Open Local Console** from the shield menu. If the session expired, fully quit and reopen Scopeproof Capture. |
| Wrong browser window | Use **Choose Browser Window…** and select the exact titled window. |
| Frontmost Page URL is blank | Paste the URL manually. For Safari, Chrome, Edge, or Arc, optionally enable the browser under **System Settings → Privacy & Security → Automation → Scopeproof Capture**. Firefox requires manual URL entry. |
| Scrolling sections do not align | Start again, keep the selected window size and zoom unchanged, and leave a small visible overlap when scrolling. Scopeproof separates viewports instead of guessing or deleting overlapping pixels. |
| Capture context dialog repeats | Complete every field marked `*`; if a Jira key is present it must look like `GRC-123`. |
| Required control is missing or catalog is old | Click **Update Controls…** in the classification form, import a current approved JSON/OSCAL/CSV catalog, and confirm the displayed version/source/control count before capturing. Existing evidence is unchanged. |
| No Jira key in filename/banner | Edit capture defaults, enter the issue key, then recapture; existing immutable evidence is not renamed. |
| Upload remains pending | Verify that the HTTPS server origin is compiled into this release, the Mac customer/workspace matches the server's `LEGACY_TENANT_ID`/`LEGACY_WORKSPACE_ID`, and the active device token is current. If the service reports scanner or RFC 3161 unavailability, preserve the local artifact and retry the unchanged schema-8 pair after recovery. |
| Hosted evidence is unverified or quarantined | Do not read, approve, package, export, or disclose it. Retry a current exact upload so the server rescans and finalizes it; recapture unsigned legacy evidence. Never manually grandfather the record. |
| Generate SBOM is disabled | Confirm your role can generate SBOMs and the assessment is active with PCI DSS 6.3.2 in scope. Managed secrets are optional when using one-time repository access. |
| Native SBOM menu says generation is already running | Wait for the current one-time request to finish; the Mac intentionally allows only one repository scan at a time. |
| Repository is missing from managed selection | Confirm it belongs to the configured organization, is within the managed token's repository selection, and is among the first 250 bounded inventory results. For a separately scoped repository, use one-time mode with an exact GitHub URL and an assessment system scope that includes the repository, owner, or `GitHub`. |
| SBOM reports no supported components | Commit a supported lockfile with pinned versions, or request a reviewed parser addition for that ecosystem. |
| Package export is unavailable | Read the hosted preflight blockers. Approve at least one eligible artifact, recollect partial coverage, complete independent screenshot safety/native provenance, or split an explicit scope above 100 artifacts; then retry. |
| Local expiry reports that no durable S3 copy is available | Refresh the matching tenant/workspace AWS session and verify the exact receipt versions, checksums, KMS key, and COMPLIANCE retention. Scopeproof intentionally preserves the local files when any live check is unavailable or mismatched. |
| Evidence cannot be found | Search all frameworks and periods, or use **Open Evidence Folder**. |
