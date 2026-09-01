# Install and use Scopeproof Capture on a Mac

This guide is the shortest complete path from a new Mac to a reviewed evidence package. It also explains the optional S3, GitHub SBOM, Jira, and hosted-service paths so an operator can tell which credentials are needed and where data goes.

## Choose how you want to run it

| Goal | Recommended path | Account or cloud required? |
| --- | --- | --- |
| Capture, review, search, and export evidence on one Mac | Install the DMG and use the Local Console | No |
| Evaluate or modify the source | Clone the repository and run the local build script | No hosted account; Apple Swift toolchain required |
| Copy local evidence into an organization-owned S3 bucket | Configure **AWS S3 Storage…** after local setup | Prefer an IAM Identity Center profile; S3 remains optional |
| Generate an SBOM for one GitHub repository | Choose **Generate Repository SBOM…** | A short-lived, repository-scoped GitHub token for private repositories |
| Team review or Jira Cloud attachment | Connect the Mac to an approved hosted Scopeproof deployment | Hosted account and device enrollment |
| Operate the future multi-customer AWS service | Follow the AWS platform runbook | AWS administrator access; this is a platform-engineering workflow |

The Mac app is fully useful in local-only mode. Leaving the hosted Server URL blank and leaving S3 disconnected does not disable capture, local review, search, or assessor-package export.

The checked-in current-source app contains no approved HTTPS hosted API origin. A normal source build is therefore intentionally local-only for hosted synchronization even if a user types a remote Server URL. A release operator must compile one reviewed, exact, pathless HTTPS origin with `SCOPEPROOF_HOSTED_API_ORIGIN` through `Scripts/configure_macos_release_identity.sh`; development-only loopback HTTP remains available for local integration testing. This prevents a checkout from silently contacting a developer, personal, or historical service.

### Understand the local and hosted trust boundary

Local capture is intentionally independent from hosted services. The Mac performs its own OCR-assisted review, irreversible pixel redaction, final-PNG scan, tenant/workspace-bound signed manifest creation, and local chain anchoring. Trust-bearing lifecycle and local legal-hold changes require macOS local-user authentication and use signing/rollback domains separate from capture provenance. Those local workflows remain usable when the hosted independent scanner or trusted timestamp authority is not configured or is temporarily unavailable.

Hosted use adds a second, stricter trust boundary. A production hosted upload is not eligible to be read, previewed, approved, packaged, exported, or disclosed to Jira until all of the following are true:

1. The current Mac app submitted the exact PNG and a schema-7 manifest signed by its device-only P-256 provenance key.
2. The server independently scanned those exact PNG bytes through the configured OCR/DLP service and bound the result to the PNG SHA-256. The historical variable names `BROWSER_OCR_ENDPOINT`, `BROWSER_OCR_TOKEN`, and `BROWSER_OCR_ALLOWED_HOSTS` configure this scanner for every hosted screenshot, including native uploads; they do not mean that native evidence may skip the server scan.
3. The server obtained and verified the required RFC 3161 timestamp.
4. The server finalized the manifest's contiguous device-chain sequence, prior hash, event hash, signing-key ID, artifact ID, and image/manifest digests in the hosted database.

Recognized OCR text is evaluated transiently for sensitive patterns and is not retained in evidence, database records, receipts, audit events, or logs. Only the digest-bound scanner policy, origin, completion time, and receipt digest are retained. Unsigned legacy captures and hosted records missing the server scan or final device-chain link remain visibly unverified/quarantined. Preserve them for investigation or local legacy browsing, but recapture or re-upload the exact current artifact so it can be independently rescanned and finalized; never make them trusted with a manual database update or blanket grandfathering rule.

## Requirements

- An Apple Silicon Mac running macOS 14 or newer.
- A user account allowed to install or run applications.
- Screen Recording permission for Scopeproof Capture.
- Enough approved local storage for the evidence you expect to collect.
- FileVault and an organization-approved backup/synchronization policy when evidence is sensitive.

Source builds additionally require Xcode or the Apple Command Line Tools. AWS, GitHub, Jira, and a hosted Scopeproof account are optional unless you choose those workflows.

## Option A: install the downloadable DMG

The downloadable `1.8.1` DMG is the older public development preview built from
commit `8cd2d5c`. It predates the **Unreleased** native changes described in this
guide, including the current storage/authentication and trust-boundary behavior.
That tagged build writes new captures under `~/Pictures/Scopeproof Evidence` and
uses manual AWS credential entry; it does not provide the current Documents-root
or direct AWS CLI IAM Identity Center/AssumeRole workflow. Use it only to evaluate that tagged release. For current behavior, use Option B
with an exact reviewed checkout that contains this documentation until a new
DMG is built, verified, and published.

1. Download the older published development-preview assets:

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

   As of 2026-09-01, a plain clone checks out an older public default branch and
   does not contain the current **Unreleased** hardening work. Before building,
   check out the exact reviewed commit or branch supplied by the maintainer and
   confirm `git status --short` is clean. Do not infer release status from the
   `1.10.0` bundle version: build `24` is currently source-only and no 1.10.0 DMG
   has been published.

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
5. Scopeproof opens its private Local Console in the default browser. The console listens only on `127.0.0.1`, uses a one-time URL-fragment nonce to establish a short-lived in-memory bearer, creates no localhost authentication cookie, and is not a LAN or internet service. Do not copy or share the launch URL.

If Documents access is denied, allow Scopeproof under **System Settings → Privacy & Security → Files & Folders**. New evidence is saved under:

```text
~/Documents/Scopeproof Evidence/
```

Captures created by older versions under `~/Pictures/Scopeproof Evidence/` remain visible and are not moved automatically.

The default identity is `local/default`. If you collect for a named customer or workspace, open **Capture & Jira Settings…** first and enter the normalized tenant and workspace. New evidence then uses:

```text
~/Documents/Scopeproof Evidence/tenants/<tenant>/workspaces/<workspace>/
```

The same identity binds the device token, S3 configuration/credentials/prefix, capture-chain head, lifecycle rollback head, and local legal-hold head. Switching it invalidates the prior console session and requires credentials verified for the new boundary.

## Configure capture defaults

1. Select the shield, then **Configure Capture Defaults…**.
2. Choose the compliance framework and control.
3. Enter a specific evidence title, system, environment, assessment period, owner, and expected-evidence note.
4. Add useful tags such as `identity`, `production`, or `quarterly`.
5. Enter a Jira issue key only when the capture is intended for an approved Jira workflow.
6. Confirm the source URL. Scopeproof reduces it to the lowercase HTTP(S) origin and removes user information, path, query, and fragment before the value reaches the screenshot or manifest.
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

Use **Search Evidence…** when you need native lifecycle actions. Review the exact image, validate its digest and capture chain, record a rationale, and mark it Approved only after the evidence is complete, correctly scoped, current, and safely redacted. Authenticate with macOS when prompted; Scopeproof records the authenticated user rather than trusting an editable reviewer name. The app prevents inconsistent or legacy-unbound lifecycle records from being treated as approved.

## Export an assessor package

1. Approve at least one eligible artifact.
2. Choose **Export Assessor Package…**.
3. Select the framework and assessment period.
4. Choose an approved destination folder.
5. Authenticate with macOS user presence when asked to use the package-signing identity.

The ZIP contains the approved evidence, capture and review records, an index, assessor instructions, SHA-256 values, and a signed manifest. Verify the package's embedded signing-key fingerprint through an independent trusted channel before treating signer continuity as established.

## Optional: configure AWS S3 storage

S3 is an additional copy, not a prerequisite for the local app.

1. Confirm the active tenant/workspace, then create or identify a dedicated evidence bucket and customer-managed KMS key.
2. Install AWS CLI v2 and configure a direct named SSO profile with `aws configure sso`. The profile must not contain static keys, `credential_process`, a source profile, or role chaining.
3. Choose **AWS S3 Storage…**, then select **IAM Identity Center profile**. Select **Identity Center + assumed role** when access must flow through one exact evidence role.
4. Enter the profile name and, when applicable, the role ARN and external ID. Select the browser sign-in option if the SSO session is not active.
5. Select **Production compliance** and enter the bucket name, region, nonempty base object prefix, encryption mode, exact KMS key ARN, and retention days. Scopeproof appends `tenants/<tenant>/workspaces/<workspace>` to the base prefix and binds that identity into the verified destination. This profile fixes Object Lock to **Compliance**; Governance is explicitly non-production because privileged identities can bypass it. SSE-KMS additionally requires the bucket's S3 Bucket Key to be enabled. Enable **Allow prefix-scoped browsing and validated downloads** only if this operator should preview or save S3 objects.
6. Choose **Save & Verify**. For a new production bucket, first deploy the reviewed `infra/aws/cloudformation/native-capture-evidence-bucket.yaml` stack through your normal infrastructure change process. Supply its `KmsKeyId` parameter with only the UUID or `mrk-…` ID; use that same ID with the native Identity Center template, and paste the derived owner/Region-bound `KmsKeyArn` output into the app. Use **Create & Harden Bucket** only with a separately reviewed, short-lived setup role; none of the supplied daily access templates grants bucket-administration permissions.
7. Read every posture result. Automatic upload remains disabled unless `kms:DescribeKey` proves the exact ARN belongs to the verified bucket-owner account and Region and is an enabled customer-managed symmetric encryption key. Identity, ownership, Block Public Access, versioning, encryption/Bucket Key, COMPLIANCE Object Lock, the exact transport/encryption/deletion-deny policy, and destination binding must also verify.
8. Confirm the daily role has no setup permissions, then enable automatic copy or use **Upload Pending Evidence to S3** for an explicit batch.
9. To show S3 inventory in the Local Console, grant prefix-scoped `s3:ListBucketVersions`. When the validated-download option is enabled, also grant exact-version read and KMS decrypt, then use **Browse S3 Evidence…** to save an exact immutable version.

Identity Center and AssumeRole credentials stay in app memory only and refresh as expiring sessions; the non-secret profile/role configuration remains in preferences. A manually pasted STS session is the fallback and uses a `WhenUnlockedThisDeviceOnly` Keychain item. The verified account/role/destination/tenant/workspace binding is stored separately in device-only Keychain. No AWS credential enters preferences, evidence, receipts, logs, the browser, or Git. A local receipt is not sufficient proof of a durable copy for expiry cleanup: Scopeproof rechecks every exact S3 version, ETag, checksum, KMS setting, and future COMPLIANCE retention live, and preserves the local artifact on any mismatch or unavailable check. See [AWS S3 evidence storage](S3_STORAGE.md) and the [CloudFormation authentication templates](../infra/aws/cloudformation/README.md).

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
3. Upload the exact schema-7 artifact to Scopeproof. The server must independently scan its pixels, verify the trusted RFC 3161 timestamp, and finalize its signed device-chain link before an authenticated reviewer can read or approve it.
4. Choose **Search Evidence… → Upload to Jira Cloud…**.
5. Confirm the live issue summary, site, project, and attachment set.

The service revalidates the device, issue, project allowlist, digest, safety state, local and hosted approvals, and lifecycle before attachment. Ambiguous provider outcomes stop for reconciliation instead of blindly retrying. Manual attachment and **Copy Jira Comment** remain fallback paths.

## Optional hosted synchronization

The current public code still contains the legacy single-tenant hosted runtime. It accepts exactly one configured origin and will not start its authenticated APIs without `LEGACY_SINGLE_TENANT_ACKNOWLEDGEMENT=single-tenant-only`; that safety gate does not make it multi-tenant. Do not serve unrelated customers from it, add customer subdomains, or share its D1/R2/key boundary. The AWS foundation now includes tenant contracts, PostgreSQL isolation, secure ingest and exact-version evidence read APIs, Cognito web/native clients, and tested infrastructure templates, but it has not been deployed or live-integrated. The hosted browser UI and signed Mac discovery/enrollment flow must pass the gates in [AWS multi-tenant hosting](AWS_MULTI_TENANT_HOSTING.md) before they are enabled.

For an existing approved single-tenant service, the bootstrap administrator first uses **Settings → Team & access** to create expiring invitations and assign roles. An administrator or compliance lead can then enroll a capture device and provide its one-time `spdev_dev_…` token. The release must already contain that exact HTTPS origin in `ScopeproofHostedAPIOrigins`; the checked-in source array is empty. Enter the same origin and token under **Capture & Jira Settings…**. The token is audience-bound, stored in Keychain, expires after 30 days, and is shown again only when an administrator rotates it. Rotation invalidates the old token immediately. Leave the Server URL blank for local-only operation.

Before enabling native hosted uploads, the service operator must apply database migrations through `0027_lonely_guardian.sql`, run `npm run db:verify`, configure the independent scanner through the legacy-named `BROWSER_OCR_*` settings, configure the RFC 3161 issuer/verifier trust boundary, and confirm the administrator readiness endpoint has no failures. Hosted assessments must use an explicit digest-verified catalog/system/control scope; package export runs one shared fail-closed eligibility policy at preflight and publication; durable findings separate reviewer maintenance from compliance-lead/administrator disposition. Immutable external-checkpoint delivery attempts, atomic checkpoint retry leases, and durable per-record key-rotation retries must be healthy before launch. Production readiness fails when the scanner is missing or unsafe, when trusted timestamp enforcement is disabled, or when the timestamp service/trust material is incomplete. No AWS environment has been deployed by this repository work; the AWS files are reviewed templates and implementation source only.

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
- **Local Console does not open:** quit and reopen Scopeproof; its loopback port, one-time fragment nonce, and in-memory bearer are recreated at launch. Do not reuse an old URL after switching tenant/workspace.
- **SBOM URL is rejected:** use exactly `https://github.com/owner/repository`, without extra path components, query, fragment, or embedded credential.
- **SBOM authentication fails:** create a fresh repository-scoped token with Metadata and Contents read access and start a new run.
- **S3 credentials expired:** obtain a new temporary session including its token and expiration, then choose **Save & Verify**.
- **KMS ARN is rejected:** select SSE-KMS or DSSE-KMS and use the full customer-managed key ARN from the same AWS partition, account, and region as the bucket.
- **S3 cannot browse:** add prefix-scoped `s3:ListBucketVersions`; exact downloads require `s3:GetObjectVersion` and `kms:Decrypt`.
- **Checksum mismatch:** do not overwrite the local evidence. Preserve the receipt and investigate CloudTrail/request IDs as an integrity event.
- **Local expiry says the S3 copy is not durable:** refresh the temporary session for the same tenant/workspace and correct the exact version, ETag, checksum, KMS, or COMPLIANCE-retention issue. Scopeproof intentionally leaves local evidence in place when live verification cannot complete.
- **Hosted upload is unavailable:** verify the exact server URL and replace a revoked or expired device token. A server-side scanner or RFC 3161 outage intentionally rejects the upload without storing it; retry the unchanged schema-7 pair after the service recovers.
- **Hosted evidence says unverified or pending:** do not approve, download, package, export, or send it to Jira. Retry the original exact upload so the server can rescan and finalize the device-chain link. Recapture unsigned legacy evidence with the current Mac app; do not ask an administrator to grandfather it in the database.
- **Export is disabled:** at least one selected artifact must have a valid bound Approved lifecycle state.

For deeper topics, use the [documentation index](README.md), [macOS installation guide](MACOS_INSTALLATION.md), [operator guide](OPERATOR_GUIDE.md), [security model](SECURITY.md), and [production operations runbook](PRODUCTION_OPERATIONS.md).
