# Install and use Scopeproof Capture on a Mac

This guide is the shortest complete path from a new Mac to a reviewed evidence package. It also explains the optional S3, GitHub SBOM, Jira, and hosted-service paths so an operator can tell which credentials are needed and where data goes.

## Choose how you want to run it

| Goal | Recommended path | Account or cloud required? |
| --- | --- | --- |
| Capture, review, search, and export evidence on one Mac | Install the DMG and use the Local Console | No |
| Evaluate or modify the source | Clone the repository and run the local build script | No hosted account; Apple Swift toolchain required |
| Copy local evidence into an organization-owned S3 bucket | Configure **AWS S3 Storage…** after local setup | AWS credentials scoped to that bucket; S3 remains optional |
| Generate an SBOM for one GitHub repository | Choose **Generate Repository SBOM…** | A short-lived, repository-scoped GitHub token for private repositories |
| Team review or Jira Cloud attachment | Connect the Mac to an approved hosted Scopeproof deployment | Hosted account and device enrollment |
| Operate the future multi-customer AWS service | Follow the AWS platform runbook | AWS administrator access; this is a platform-engineering workflow |

The Mac app is fully useful in local-only mode. Leaving the hosted Server URL blank and leaving S3 disconnected does not disable capture, local review, search, or assessor-package export.

## Requirements

- An Apple Silicon Mac running macOS 14 or newer.
- A user account allowed to install or run applications.
- Screen Recording permission for Scopeproof Capture.
- Enough approved local storage for the evidence you expect to collect.
- FileVault and an organization-approved backup/synchronization policy when evidence is sensitive.

Source builds additionally require Xcode or the Apple Command Line Tools. AWS, GitHub, Jira, and a hosted Scopeproof account are optional unless you choose those workflows.

## Option A: install the downloadable DMG

1. Download the current development-preview assets:

   - [Scopeproof Capture 1.8.1 DMG](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/download/v1.8.1-development-preview.1/Scopeproof-Capture-1.8.1-development-preview.dmg)
   - [SHA-256 checksum file](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/download/v1.8.1-development-preview.1/Scopeproof-Capture-1.8.1-development-preview.dmg.sha256)

2. Open Terminal and verify the file before opening it:

   ```bash
   cd ~/Downloads
   shasum -a 256 -c Scopeproof-Capture-1.8.1-development-preview.dmg.sha256
   ```

   Continue only when the command prints `OK`. If it reports a mismatch, delete both downloads and obtain them again from the GitHub release page.

3. Double-click the DMG, then drag **Scopeproof Capture** into **Applications**.
4. Eject the Scopeproof disk image.
5. Open **Applications → Scopeproof Capture**.

The preview is ad-hoc signed and is not Apple-notarized. After verifying the checksum, macOS may require **System Settings → Privacy & Security → Open Anyway**. This exception is appropriate only for an approved evaluation build. A managed production rollout requires a Developer ID-signed, hardened, notarized, and stapled release.

## Option B: clone, build, install, and run from source

1. Install the Apple Command Line Tools if needed:

   ```bash
   xcode-select --install
   ```

2. Clone the public repository:

   ```bash
   cd ~/Documents
   git clone https://github.com/jaysonguglietta/ScopeProofEvidenceCapture.git
   cd ScopeProofEvidenceCapture
   ```

3. Build, install into your personal Applications folder, and launch:

   ```bash
   ./Scripts/run_macos_capture.sh
   ```

   This installs the source-built app under `~/Applications`; it does not require an administrator password.

4. To build without installing or launching, use:

   ```bash
   ./Scripts/build_macos_capture.sh
   ```

5. To run the native test suite before installing:

   ```bash
   swift test --package-path macos/ScopeproofCapture
   ```

Do not paste AWS, Jira, GitHub, encryption, or signing credentials into the repository or build command. Local secrets belong in the relevant one-time form, macOS Keychain, or the hosted secret manager described by the specific workflow.

## First launch

1. Look for the Scopeproof shield in the macOS menu bar. Scopeproof is a menu-bar app and does not open a normal Dock window.
2. When prompted, allow notifications if your operating policy permits them.
3. Choose a capture action. macOS will request Screen Recording access.
4. Open **System Settings → Privacy & Security → Screen & System Audio Recording**, enable **Scopeproof Capture**, quit the app, and launch the same installed copy again.
5. Scopeproof opens its private Local Console in the default browser. The console listens only on `127.0.0.1`, uses a new authenticated session each launch, and is not a LAN or internet service.

If Documents access is denied, allow Scopeproof under **System Settings → Privacy & Security → Files & Folders**. New evidence is saved under:

```text
~/Documents/Scopeproof Evidence/
```

Captures created by older versions under `~/Pictures/Scopeproof Evidence/` remain visible and are not moved automatically.

## Configure capture defaults

1. Select the shield, then **Configure Capture Defaults…**.
2. Choose the compliance framework and control.
3. Enter a specific evidence title, system, environment, assessment period, owner, and expected-evidence note.
4. Add useful tags such as `identity`, `production`, or `quarterly`.
5. Enter a Jira issue key only when the capture is intended for an approved Jira workflow.
6. Confirm the full source URL. Scopeproof removes embedded URL credentials and known-sensitive query or fragment values before the URL reaches the screenshot or manifest.
7. Save the configuration. Reusable contexts can be saved under **Capture Presets**.

Avoid generic titles such as “Screenshot” or “Settings.” An assessor should be able to understand what control, system, environment, period, and expected state the image supports without guessing.

## Capture evidence

Use the narrowest appropriate menu action:

- **Capture Frontmost Browser Window** captures the supported browser currently in front.
- **Choose Browser Window…** lets you select a specific browser window.
- **Capture Scrolling Evidence…** combines multiple operator-positioned viewports with continuation markers.
- **Open URL & Capture…** opens an exact HTTP(S) address and starts a capture workflow.
- **Capture Entire Display** includes the complete display and menu bar; use it only when the broader context is required.

For every capture:

1. Verify the selected window and classification.
2. Wait for the configured countdown.
3. Review Scopeproof's OCR safety scan and automatic masks.
4. Apply any additional irreversible manual redactions in the pixel preview.
5. Confirm that no PAN, password, cookie, bearer token, private key, recovery code, or unrelated customer information remains visible.
6. Save the exact reviewed pixels.

Scopeproof scans before persistence, encodes the reviewed PNG in memory, scans the final bytes again, writes a private PNG plus immutable manifest, and records a local chain-of-custody event. A failed safety scan prevents saving.

## Browse and review evidence

Choose **Open Local Console** from the shield menu.

The Evidence library supports:

- text search;
- local, S3, and local-plus-S3 storage filters;
- framework, control, assessment period, and review-status filters;
- grouping by control, period, or framework;
- digest-verified local previews;
- on-demand exact-version S3 previews when a verified S3 destination is connected.

An S3 failure never hides local evidence. The browser receives normalized evidence identifiers and display metadata, not local filesystem paths, S3 object keys, AWS credentials, or Keychain values. Temporary S3 preview files are private and removed after the authenticated loopback response.

Use **Search Evidence…** when you need native lifecycle actions. Review the exact image, validate its digest and capture chain, record a rationale, and mark it Approved only after the evidence is complete, correctly scoped, current, and safely redacted. The app prevents inconsistent or legacy-unbound lifecycle records from being treated as approved.

## Export an assessor package

1. Approve at least one eligible artifact.
2. Choose **Export Assessor Package…**.
3. Select the framework and assessment period.
4. Choose an approved destination folder.
5. Authenticate with macOS user presence when asked to use the package-signing identity.

The ZIP contains the approved evidence, capture and review records, an index, assessor instructions, SHA-256 values, and a signed manifest. Verify the package's embedded signing-key fingerprint through an independent trusted channel before treating signer continuity as established.

## Optional: configure AWS S3 storage

S3 is an additional copy, not a prerequisite for the local app.

1. Create or identify a dedicated evidence bucket and customer-managed KMS key.
2. Obtain narrowly scoped temporary credentials through IAM Identity Center or `AssumeRole`. Production mode rejects permanent access keys.
3. Choose **AWS S3 Storage…**.
4. Select **Production** for compliance use.
5. Enter the bucket name, region, nonempty object prefix, encryption mode, exact KMS key ARN, Object Lock mode, and retention days. Enable **Allow prefix-scoped browsing and validated downloads** only if this operator should preview or save S3 objects.
6. Paste the temporary access key ID, secret access key, session token, and expiration.
7. Choose **Save & Verify**, or **Create & Harden Bucket** when the temporary setup role has the documented bucket-creation permissions.
8. Read every posture result. Automatic upload remains disabled when ownership, Block Public Access, versioning, encryption, KMS, Object Lock, policy, or destination binding cannot be verified.
9. Enable automatic copy only after verification, or use **Upload Pending Evidence to S3** for an explicit batch.
10. To show S3 inventory in the Local Console, grant prefix-scoped `s3:ListBucketVersions`. When the validated-download option is enabled, also grant exact-version read and KMS decrypt, then use **Browse S3 Evidence…** to save an exact immutable version.

Temporary AWS credentials and the verified destination binding are stored in separate `WhenUnlockedThisDeviceOnly` Keychain items. They are not stored in preferences, evidence, receipts, logs, the browser, or Git. The hosted multi-customer design does not distribute AWS credentials to Macs at all; it will use short-lived exact-key upload authorization issued by the hosted API.

The complete IAM, KMS, bucket-policy, Object Lock, lifecycle, and CloudTrail guidance is in [S3 storage](S3_STORAGE.md).

## Optional: generate a one-time repository SBOM

1. Create a short-lived GitHub fine-grained token selected only for the target repository. Grant **Metadata: read** and **Contents: read**; do not grant write or administration permissions.
2. Choose **Generate Repository SBOM…**.
3. Enter an exact URL in the form `https://github.com/owner/repository`.
4. Paste the token, enter a branch, tag, or commit, and choose CycloneDX 1.6 or SPDX 2.3.
5. Generate and save the JSON plus adjacent checksum file.
6. Revoke the token after the operation.

The native workflow resolves an immutable commit and reads only recognized lockfile blobs through GitHub's API. It does not clone, build, install, execute, or unpack repository code. The token is one-use process input: it is cleared at submission and excluded from preferences, Keychain, caches, cookies, logs, evidence, audit records, and retry state.

The direct local SBOM is operator-managed output. Use the hosted SBOM workflow when you need assessment scoping, comparison, team review, approval, retention, or package inclusion. See [SBOM guide](SBOM_GUIDE.md).

## Optional: connect Jira Cloud

The Mac never stores an Atlassian client secret or Jira OAuth token. A platform administrator first configures the hosted Jira OAuth integration. A compliance lead then connects an allowed Jira Cloud site and projects under the hosted console's **Connections → Jira Cloud** view.

After the Mac is enrolled with that hosted deployment:

1. Enter a destination issue key during capture classification.
2. Approve the artifact locally.
3. Upload the exact artifact to Scopeproof and obtain independent hosted approval.
4. Choose **Search Evidence… → Upload to Jira Cloud…**.
5. Confirm the live issue summary, site, project, and attachment set.

The service revalidates the device, issue, project allowlist, digest, safety state, local and hosted approvals, and lifecycle before attachment. Ambiguous provider outcomes stop for reconciliation instead of blindly retrying. Manual attachment and **Copy Jira Comment** remain fallback paths.

## Optional hosted synchronization

The current public code still contains the legacy single-tenant hosted runtime. Do not serve unrelated customers from that runtime or add customer subdomains to it. The AWS foundation, tenant contracts, PostgreSQL schema, secure ingest state model, and Cognito PKCE primitives are migration components; the production AWS browser/API runtime and signed Mac discovery/enrollment flow must pass the gates in [AWS multi-tenant hosting](AWS_MULTI_TENANT_HOSTING.md) before they are enabled.

For the existing approved single-tenant service, an administrator can enroll a capture device and provide its one-time `spdev_dev_…` token. Enter the exact HTTPS Server URL and one-time token under **Capture & Jira Settings…**. The token is audience-bound and stored in Keychain. Leave the Server URL blank for local-only operation.

## Routine operator checklist

Before each evidence session:

- Confirm the correct framework, control, customer/system, environment, and assessment period.
- Confirm the Mac clock/time zone and Screen Recording permission.
- Verify that capture targets do not expose cardholder or unrelated customer data.
- Refresh expired temporary S3 credentials if S3 copy is required.

After the session:

- Review and approve only complete, safely redacted artifacts.
- Resolve failed uploads without deleting the authoritative local files.
- Export and independently verify the assessor package.
- Revoke one-time GitHub tokens.
- Review S3 receipts, CloudTrail alerts, hosted audit events, and Jira receipts when those workflows were used.

## Troubleshooting

- **No menu icon:** launch Scopeproof Capture from the Applications folder and check macOS Login Items if it should start automatically.
- **Capture is blank or denied:** grant Screen Recording permission, quit, and reopen the same installed app copy.
- **Documents cannot be written:** grant Files & Folders access and confirm DLP/synchronization policy.
- **Wrong browser window:** use **Choose Browser Window…**.
- **Frontmost URL is blank:** paste it manually or grant Automation permission for the supported browser.
- **Local Console does not open:** quit and reopen Scopeproof; its loopback port and session are created at launch.
- **SBOM URL is rejected:** use exactly `https://github.com/owner/repository`, without extra path components, query, fragment, or embedded credential.
- **SBOM authentication fails:** create a fresh repository-scoped token with Metadata and Contents read access and start a new run.
- **S3 credentials expired:** obtain a new temporary session including its token and expiration, then choose **Save & Verify**.
- **KMS ARN is rejected:** select SSE-KMS or DSSE-KMS and use the full customer-managed key ARN from the same AWS partition, account, and region as the bucket.
- **S3 cannot browse:** add prefix-scoped `s3:ListBucketVersions`; exact downloads require `s3:GetObjectVersion` and `kms:Decrypt`.
- **Checksum mismatch:** do not overwrite the local evidence. Preserve the receipt and investigate CloudTrail/request IDs as an integrity event.
- **Hosted upload is unavailable:** verify the exact server URL and replace a revoked or expired device token.
- **Export is disabled:** at least one selected artifact must have a valid bound Approved lifecycle state.

For deeper topics, use the [documentation index](README.md), [macOS installation guide](MACOS_INSTALLATION.md), [operator guide](OPERATOR_GUIDE.md), [security model](SECURITY.md), and [production operations runbook](PRODUCTION_OPERATIONS.md).
