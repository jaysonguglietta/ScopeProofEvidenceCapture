# Deployment and administration

> This guide currently describes the single-tenant Sites deployment. The selected replacement is the [AWS-only multi-tenant hosting architecture](AWS_MULTI_TENANT_HOSTING.md). Use the separate [AWS platform runbook](AWS_PLATFORM_RUNBOOK.md) for that target and review its [adversarial security findings](AWS_SECURITY_REVIEW.md). The legacy runtime deliberately accepts exactly one canonical origin and requires an explicit `single-tenant-only` acknowledgement. Do not provision a second customer hostname or share its D1/R2/key boundary. No AWS resource has been deployed from the source or templates in this repository.

## Prerequisites

- Node.js 22.13 or newer and npm.
- A Sites project with D1 bound as `DB` and R2 bound as `EVIDENCE_BUCKET`.
- Xcode with the Swift 6 toolchain for the macOS application.
- Production cryptographic keys and least-privilege provider credentials.

The logical hosted bindings are declared in `.openai/hosting.json`. Do not place physical resource identifiers or secret values in that file.

Save Sites releases from the validated `dist/` archive produced by the official Sites packaging helper. This preserves the reviewed vendored dependency graph; source-only rebuilds intentionally reject local `file:` dependencies.

## Required hosted secrets

| Variable | Requirement |
| --- | --- |
| `EVIDENCE_ENCRYPTION_KEY` | Base64-encoded 32-byte AES key. |
| `AUDIT_HMAC_KEY` | Independent high-entropy secret for audit-chain authentication. |
| `PACKAGE_SIGNING_PRIVATE_KEY` | Base64 PKCS#8 ECDSA P-256 private key. |
| `PACKAGE_SIGNING_PUBLIC_KEY` | Matching base64 SPKI public key. |
| `BOOTSTRAP_ADMIN_EMAILS` | Lowercase email allowlist for the one available bootstrap-administrator claim. After that claim, allowlisted addresses still require an invitation. |
| `TRUSTED_APP_ORIGINS` | Exactly one canonical HTTPS Sites origin allowed to carry platform identity headers; no comma-separated alternates, paths, or wildcards. |
| `LEGACY_SINGLE_TENANT_ACKNOWLEDGEMENT` | Must equal `single-tenant-only`. Missing or different values disable authenticated APIs. |
| `REQUIRE_TRUSTED_TIMESTAMP` | Must be `true` or omitted in production. `false` is a diagnostic-only bypass and makes production readiness fail. |

Use versioned keyrings for production rotation. See the [key-management guide](KEY_MANAGEMENT.md). Configure `AUDIT_CHECKPOINT_ENDPOINT`, `AUDIT_CHECKPOINT_ALLOWED_HOSTS`, and `AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY` for an organization-controlled append-only service in a different administrative boundary; set `AUDIT_CHECKPOINT_TOKEN` when that receiver requires bearer authentication. Readiness and audit verification fail until a signed receipt for a checkpoint is delivered and verified. Configure the required `SECURITY_EVENT_ENDPOINT`, `SECURITY_EVENT_ALLOWED_HOSTS`, and `SECURITY_EVENT_TOKEN` for the authenticated monitoring ingress described in the [production-operations runbook](PRODUCTION_OPERATIONS.md).

Never reuse one value for multiple purposes. Record key ownership, creation date, rotation version, recovery escrow, and destruction approval outside the repository.

`GET /api/admin/readiness` validates configuration structure, not just variable presence. It parses the one-origin trust boundary, rejects an empty, wildcard, malformed, oversized, or invalid bootstrap-administrator allowlist, and validates that the independent scanner uses a clean HTTPS endpoint on its exact hostname allowlist with a trimmed 16–4096-character bearer token containing no control characters. It also requires the security-monitoring endpoint, exact host allowlist, and a trimmed, control-free 16–4096-character `SECURITY_EVENT_TOKEN`. The checkpoint, key, signing-keypair, and RFC 3161 checks likewise validate their underlying material. Treat any failed check as a release blocker; do not replace these validators with Boolean presence checks.

## Provider and evidence-service configuration

| Collector | Variables | Recommended scope |
| --- | --- | --- |
| AWS | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION` | Read-only Config recorder and EC2 security-group inventory using a complete temporary STS session. Long-lived two-part access keys are rejected. Rotate all three credential values together before expiry. |
| GitHub | `GITHUB_TOKEN`, `GITHUB_ORG` | Limit the token to intended repositories with Metadata: read and Contents: read. This supports inventory, branch-protection collection, immutable commit resolution, and bounded SBOM archive download; no write scopes are required. |
| Okta | `OKTA_BASE_URL`, `OKTA_API_TOKEN` | Read-only policy and group inventory. |
| Cloudflare | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, optional `CLOUDFLARE_ZONE_IDS` | Zone and managed-ruleset read access. |
| Browser Rendering and all hosted screenshots | Cloudflare variables, `BROWSER_CAPTURE_URLS`, `BROWSER_OCR_ENDPOINT`, `BROWSER_OCR_TOKEN`, `BROWSER_OCR_ALLOWED_HOSTS` | Dedicated HTTPS evidence URLs plus the independently operated screenshot scanner shared by Browser Rendering and native uploads. Despite their legacy names, all three `BROWSER_OCR_*` values are required for hosted screenshot storage. The scanner endpoint must be a clean HTTPS URL on the exact host allowlist and return only the exact PNG SHA-256, recognized text, and a valid policy version. Scopeproof persists receipt metadata, never OCR text. |
| RFC 3161 timestamping | `RFC3161_TSA_URL`, `RFC3161_VERIFIER_URL`, `RFC3161_VERIFIER_TOKEN`, `RFC3161_VERIFIER_PUBLIC_KEYS`, `RFC3161_VERIFIER_ALLOWED_HOSTS`, `RFC3161_TSA_TRUST_ANCHOR_SHA256` | Approved TSA plus a separately deployed standards-compliant verifier. Pin one to five comma-separated P-256 SPKI keys and the allowed TSA root fingerprints. This complete path is mandatory for production native ingestion. |

Missing ordinary provider variables leave the corresponding collector in **Not configured**. The screenshot-scanner and trusted-timestamp boundaries are stricter: missing scanner configuration prevents every hosted screenshot from being stored, and a missing or failed RFC 3161 path prevents native hosted storage when trusted timestamps are required. Authentication and unsafe-content failures require operator action; transient rate-limit/server failures can retry up to three times.

### GitHub and repository SBOM setup

1. Create a GitHub App installation token or fine-grained personal access token selected only for repositories in this Scopeproof tenant. Grant repository **Metadata: read** and **Contents: read**; grant no write, administration, workflow, issue, pull-request, environment, or secret permissions.
2. Set `GITHUB_ORG` to the exact GitHub organization login and store `GITHUB_TOKEN` only as a hosted Sites secret. Scopeproof does not mint or refresh GitHub App installation tokens, so the external secret-rotation process must replace expiring installation tokens before use.
3. Apply migration `drizzle/0012_opposite_rachel_grey.sql`, which creates `sbom_jobs` and its scheduler/query indexes, before deploying code that exposes `/api/sboms`.
4. Create or select an active PCI DSS assessment containing control 6.3.2. If its system scope is not empty, include the exact `organization/repository`, the organization, or `GitHub`.
5. Sign in as a compliance lead or administrator, open **SBOMs**, confirm only intended repositories are listed, and generate a non-production baseline from a known commit. Verify its commit SHA, archive digest, manifests, component count, encrypted evidence record, audit events, independent approval, and assessor-package inclusion.
6. Confirm an auditor/reviewer cannot generate an SBOM, the generator cannot approve its own evidence, an out-of-organization repository/ref is rejected, and removing either hosted variable returns the feature to **Not configured**.

The GitHub API permissions are described in GitHub's [repository administration endpoints](https://docs.github.com/en/rest/repos/repos) and [repository contents endpoints](https://docs.github.com/en/rest/repos/contents). Review the [repository SBOM guide](SBOM_GUIDE.md) before enabling the feature for auditors.

Managed GitHub configuration is optional for one-time repository access. When managed variables are absent, authorized operators may submit an exact GitHub URL and short-lived token in **SBOMs → Generate SBOM → One-time repository**. No additional hosted secret or migration is required. Confirm reverse proxies, request tracing, browser monitoring, and support tooling do not capture authorization request bodies; Scopeproof itself never logs or persists the submitted token.

## Database migrations

Drizzle schema changes live in `db/schema.ts`. Generate a migration with:

```bash
npm run db:generate
```

Inspect generated SQL for destructive operations, unintended nullability changes, missing indexes, and table rebuilds. Apply migrations in journal order. Never edit a migration already applied to production; add a new forward migration.

The current application requires every migration through `drizzle/0023_independent_image_safety.sql`. Migrations 0016–0019 add rotation leases, occurrence-owned lifecycle state, active-record de-duplication, and audited compare-and-swap guards. Migrations 0020–0022 add per-device P-256 provenance keys, monotonic chain leases/heads, immutable checkpoint receipts, immutable native-manifest links, and quarantine fields for older/unbound native evidence. Migration 0023 adds the independent server screenshot-safety receipt fields.

Before applying migrations to a hosted environment or deploying application code, run the populated upgrade-path preflight:

```bash
npm run db:verify
```

The preflight replays the complete journal through 0023 against a database containing legacy devices and duplicate evidence, runs `PRAGMA integrity_check`, and asserts the native-chain, immutable-checkpoint, quarantine, and independent-image-safety columns/triggers. Do not deploy if it fails. Back up D1 first, apply the same ordered files once, and verify the recorded migration journal before enabling traffic.

## Roles

| Role | Typical capabilities |
| --- | --- |
| `auditor` | Read evidence/package/SBOM metadata and audit-chain status; download authorized evidence and packages. Cannot generate or approve SBOM evidence. |
| `reviewer` | Auditor access plus independent evidence inspection/approval and package generation. Cannot collect, enroll devices, or operate Jira. |
| `compliance_lead` | Evidence collection, repository SBOM generation, collector schedules, device enrollment, Jira operations, and package generation. Cannot approve evidence. |
| `admin` | All operational permissions, including SBOM generation, plus invitation, membership status, and role administration; still cannot approve evidence the same identity created or uploaded. |

Review role assignments regularly. Use separate named accounts; do not share administrator sessions. Keep at least two active administrators. Suspending or revoking a member immediately blocks web access, native device uploads owned by that member, and queued collector/SBOM retries. Invitations expire after 1–30 days and should be revoked when no longer expected.

Production fails closed when bootstrap/origin/single-tenant acknowledgement, retained keys, the matched signing keypair, independent checkpoint delivery, security-monitoring delivery, independent screenshot scanning, or trusted native timestamping is missing or unsafe. The production-readiness result remains failed whenever `REQUIRE_TRUSTED_TIMESTAMP=false`; that setting is limited to isolated diagnostics. Managed repository selection requires both GitHub variables; one-time repository generation does not.

## macOS device deployment

For a single-user local installation built from source, follow the [macOS installation guide](MACOS_INSTALLATION.md). It installs into `~/Applications`, opens the loopback Local Console, and requires no hosted enrollment.

The GitHub Releases page may also contain an explicitly labeled development-preview DMG for named testers. That image installs into `/Applications` but is ad-hoc signed and not notarized. Verify its adjacent checksum, architecture, target commit, and release notes before use. Do not deploy it through MDM, present it as a production-trusted build, or use it to replace the Developer ID/notarization workflow below.

For managed distribution:

1. Create the production candidate with the protected `.github/workflows/macos-production-release.yml` workflow for the approved full commit.
2. Download its exact seven-file artifact set; do not rebuild or re-archive the ZIP during publication.
3. Verify the candidate on macOS with `./Scripts/publish_release.sh`, including `SCOPEPROOF_RELEASE_CANDIDATE_DIR`, `SCOPEPROOF_RELEASE_ATTESTATION_REPOSITORY`, and `SCOPEPROOF_RELEASE_EXPECTED_COMMIT`.
4. Generate an offline P-256 release key, compile its X9.63 public key and validity window into `ScopeproofUpdatePublicKeys` in `Info.plist`, and keep the private key outside the repository. `./Scripts/configure_macos_release_identity.sh` validates and writes the public release identity from `SCOPEPROOF_UPDATE_*` and `SCOPEPROOF_RELEASE_*` variables. It also requires `SCOPEPROOF_HOSTED_API_ORIGIN` and writes that one exact pathless HTTPS origin into `ScopeproofHostedAPIOrigins`; the checked-in array is empty so an unconfigured source build cannot contact a remote hosted service. Review and commit only that public metadata, never a personal or preview host.
5. Compile the exact HTTPS `ScopeproofUpdateDownloadOrigin` into `Info.plist` through `SCOPEPROOF_RELEASE_DOWNLOAD_ORIGIN`, then set the remaining `SCOPEPROOF_UPDATE_*` and `SCOPEPROOF_RELEASE_*` variables required by `./Scripts/publish_release.sh`. The final URL must be `<compiled-origin>/macos/<version>/Scopeproof-Capture-<version>.zip`. The script privately snapshots all seven candidate files before verification, refuses unattested, checksum/provenance-mismatched, unsigned, non-notarized, identity-mismatched, or key-mismatched candidates, and emits an envelope under `DerivedData/Publication/` over the exact snapshot ZIP.
6. Publish the exact ZIP to that immutable versioned HTTPS path. Store only the envelope's `manifest` as `MACOS_RELEASE_MANIFEST_JSON`, its `signatureDERBase64` as `MACOS_RELEASE_SIGNATURE_DER_BASE64`, and configure the exact hostname in `MACOS_RELEASE_ALLOWED_HOSTS`. The client derives the URL from its compiled origin, rejects redirects, verifies the embedded bundle identifier/version, and stores a device-only Keychain `(sequence, version, SHA-256)` tuple to prevent rollback and same-sequence equivocation.
7. If hosted synchronization is enabled, enroll each Mac separately from **Connections**. The current client generates a schema-7 ECDSA P-256-signed manifest and monotonically chained event for every upload. Tokens expire after 30 days; rotate before expiry and replace the Keychain value on the Mac. Rotation invalidates the previous token immediately. Revoke devices when reassigned, lost, or retired. Leave the native Server URL blank when policy requires local-only operation.
8. Approve Documents Folder access and verify that `~/Documents/Scopeproof Evidence` is covered by the intended FileVault, backup, DLP, retention, and recovery policies. Disable or explicitly approve iCloud Drive and enterprise synchronization for that evidence classification. Inventory the legacy `~/Pictures/Scopeproof Evidence` root until its retained evidence expires or is dispositioned.

The development build and development-preview DMG are ad-hoc signed with a stable designated requirement for `com.scopeproof.capture`; neither is a notarized production release. A checksum detects changed bytes but does not establish an Apple-trusted publisher identity. The Local Console is embedded in the native process, binds to a random loopback-only port, and stops when the app quits. It does not require or deploy the hosted Sites application. Local-only capture also does not require the hosted independent scanner or RFC 3161 path; those controls become mandatory when the screenshot crosses the hosted evidence boundary.

When native S3 evidence storage is enabled, complete the production profile in **AWS S3 Storage…**, use expiring IAM Identity Center/AssumeRole credentials, require an S3 Bucket Key for SSE-KMS, and apply the exact native transport/encryption/deletion-deny bucket policy before verification. Deploy the monitoring template in `infra/aws/scopeproof-s3-observability.yaml`. The setup role, daily verifier/upload role, and optional browser role must be separate and prefix-scoped as documented in [AWS S3 evidence storage](S3_STORAGE.md). CloudTrail log-bucket names, KMS keys, replication roles/destinations, retention approval, and SNS subscriptions are environment-specific and are not deployed automatically with the Mac app.

Long-lived IAM user keys are a Compatible S3 migration exception, not a production credential. If the exception is required, provision a dedicated no-console identity with no unrelated policies, use the exact bucket/prefix identity and KMS key-policy templates, and record an owner and removal date before distributing the Mac configuration.

## RFC 3161 verifier contract

Scopeproof does not parse CMS itself. The configured verifier must use a maintained RFC 3161/CMS/X.509 implementation and reject non-granted status, wrong SHA-256 imprint or nonce, invalid CMS signatures, missing `id-kp-timeStamping` EKU, untrusted/expired chains, and failed revocation policy. Its response is a bounded JSON attestation signed over RFC 8785 JCS bytes with the pinned ECDSA P-256 verifier key; `signatureBase64` uses the 64-byte IEEE P1363 `r || s` form expected by WebCrypto. The attestation includes the token digest, request digest/nonce, TSA origin, generation/verification times, signer and trust-anchor fingerprints, chain fingerprints/expiry, revocation status, policy OID, and serial number.

Maintain at least two verifier public keys during a controlled rotation window by deploying application support before switching the verifier signer. Update TSA trust-anchor fingerprints only after out-of-band validation, document the change, and retain prior verification metadata with existing evidence. In the production/default policy, if any verifier setting is absent or validation fails, native upload fails before R2 storage. `REQUIRE_TRUSTED_TIMESTAMP=false` permits a signed-server-time diagnostic receipt only in an isolated troubleshooting environment and deliberately leaves production readiness failed.

Alert on repeated `scopeproof_audited_batch_failure` events and any sustained Jira operation in `unknown`, collector `action_needed`, or package `failed` state. Database state and its required audit event are committed in one D1 batch; external Jira/R2 work uses durable intent/state records so uncertain outcomes can be reconciled instead of replayed blindly.

The 15-minute scheduler also retries expired collection leases, purges expired evidence/export objects, and removes expired rate-limit buckets. Alert on `evidence.purge_failed`, investigate R2 deletion errors, and do not treat a legal hold as indefinite: every hold records an owner, reason, and expiry of at most one year.

## Jira Cloud OAuth deployment

1. In the [Atlassian developer console](https://developer.atlassian.com/console/myapps/), create one OAuth 2.0 (3LO) integration for this Scopeproof deployment.
2. Add the Jira Cloud API and grant `read:jira-work` and `write:jira-work`. Scopeproof requests `offline_access` so it can use rotating refresh tokens.
3. Set the callback exactly to `https://<scopeproof-host>/api/jira/oauth/callback` in Atlassian and in `JIRA_OAUTH_CALLBACK_URL`.
4. Store `JIRA_OAUTH_CLIENT_ID` and `JIRA_OAUTH_CLIENT_SECRET` only in the hosted secret manager.
5. Generate a distinct 32-byte key with `openssl rand -base64 32` and store the output as `JIRA_OAUTH_TOKEN_ENCRYPTION_KEY`. Do not reuse the evidence-encryption or audit key.
6. Apply `drizzle/0004_cheerful_tombstone.sql`, `drizzle/0005_nappy_alice.sql`, and `drizzle/0006_first_madelyne_pryor.sql` in order, deploy, then connect and test Jira under **Connections**.

Do not embed the OAuth client secret in the Mac app or distribute personal Jira API tokens. Restrict each user connection to the minimum approved project keys, review Atlassian consent and connected-app access regularly, and reconnect after a revoked or expired grant.

Migration `0006` adds OAuth refresh leases and durable Jira upload reservations. Deploy it before a server build that contains the concurrency-safe Jira code. Existing connections start at token version 1; existing immutable receipts remain valid. If an upload operation reaches `unknown`, inspect the destination issue and reconcile its attachments before any operator-authorized retry.

## Production validation

Before releasing:

```bash
npm run db:verify
npm run lint
npx tsc --noEmit
npm test
```

Run the native tests with the Xcode Swift toolchain, build the `.app`, confirm its bundle version/signature, and smoke-test the menu, one-time repository SBOM dialog/export/checksum, S3 posture verification/upload/version browser/quarantined download, settings, capture classification, redaction review, search, Jira comment, and package export on non-production sources. At the hosted boundary, verify a valid schema-7 upload advances the device chain once, while schema 6, invalid P-256 signatures, duplicate/out-of-order chain links, missing/mismatched safety receipts, sensitive scanner findings, and unavailable/invalid RFC 3161 verification all fail before disclosure or storage as applicable. Confirm older/unbound native rows cannot be read, approved, packaged, or sent to Jira. Never use production AWS credentials in an automated test.

## Backup, retention, and recovery

- Back up D1, R2 ciphertext, cryptographic key versions, and release artifacts according to the evidence-retention policy.
- Test restoration into an isolated environment and verify sample artifact hashes and audit-chain continuity.
- Hosted packages expire after seven days; preserve the original evidence rather than depending on package objects as the system of record.
- Local retention moves files to Trash and does not remove hosted evidence.
- Place evidence under legal hold before applying deletion when an assessment, investigation, dispute, or regulatory requirement is active.

The full backup manifest, monitoring, quarterly restore-drill, incident-response, and launch-authorization procedures are in [Production operations](PRODUCTION_OPERATIONS.md). A production deployment is not approved until named owners have executed and recorded those controls.
