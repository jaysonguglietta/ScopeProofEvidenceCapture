# Deployment and administration

## Prerequisites

- Node.js 22.13 or newer and npm.
- A Sites project with D1 bound as `DB` and R2 bound as `EVIDENCE_BUCKET`.
- Xcode with the Swift 6 toolchain for the macOS application.
- Production cryptographic keys and least-privilege provider credentials.

The logical hosted bindings are declared in `.openai/hosting.json`. Do not place physical resource identifiers or secret values in that file.

## Required hosted secrets

| Variable | Requirement |
| --- | --- |
| `EVIDENCE_ENCRYPTION_KEY` | Base64-encoded 32-byte AES key. |
| `AUDIT_HMAC_KEY` | Independent high-entropy secret for audit-chain authentication. |
| `PACKAGE_SIGNING_PRIVATE_KEY` | Base64 PKCS#8 ECDSA P-256 private key. |
| `PACKAGE_SIGNING_PUBLIC_KEY` | Matching base64 SPKI public key. |
| `BOOTSTRAP_ADMIN_EMAILS` | Comma-separated lowercase administrator emails configured before first sign-in. |
| `TRUSTED_APP_ORIGINS` | Comma-separated exact HTTPS Sites origins allowed to carry platform identity headers; no paths or wildcards. |

Use versioned keyrings for production rotation. See the [key-management guide](KEY_MANAGEMENT.md). Configure `AUDIT_CHECKPOINT_ENDPOINT` to an organization-controlled append-only service in a different administrative boundary, and `SECURITY_EVENT_ENDPOINT` to the monitoring ingress described in the [production-operations runbook](PRODUCTION_OPERATIONS.md).

Never reuse one value for multiple purposes. Record key ownership, creation date, rotation version, recovery escrow, and destruction approval outside the repository.

## Optional provider configuration

| Collector | Variables | Recommended scope |
| --- | --- | --- |
| AWS | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`, `AWS_REGION` | Read-only Config recorder and EC2 security-group inventory. Prefer temporary credentials. |
| GitHub | `GITHUB_TOKEN`, `GITHUB_ORG` | Organization repository metadata and default-branch protection read access. |
| Okta | `OKTA_BASE_URL`, `OKTA_API_TOKEN` | Read-only policy and group inventory. |
| Cloudflare | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, optional `CLOUDFLARE_ZONE_IDS` | Zone and managed-ruleset read access. |
| Browser Rendering | Cloudflare variables, `BROWSER_CAPTURE_URLS`, `BROWSER_OCR_ENDPOINT`, `BROWSER_OCR_TOKEN`, `BROWSER_OCR_ALLOWED_HOSTS` | Dedicated HTTPS evidence URLs and a contractually approved OCR processor. The OCR response must echo the exact PNG SHA-256 and a policy version. |
| RFC 3161 timestamping | `RFC3161_TSA_URL`, `RFC3161_VERIFIER_URL`, `RFC3161_VERIFIER_TOKEN`, `RFC3161_VERIFIER_PUBLIC_KEYS`, `RFC3161_VERIFIER_ALLOWED_HOSTS`, `RFC3161_TSA_TRUST_ANCHOR_SHA256` | Approved TSA plus a separately deployed standards-compliant verifier. Pin one to five comma-separated P-256 SPKI keys and the allowed TSA root fingerprints. |

Missing variables leave the corresponding collector in **Not configured**. Authentication and unsafe-content failures require operator action; transient rate-limit/server failures can retry up to three times.

## Database migrations

Drizzle schema changes live in `db/schema.ts`. Generate a migration with:

```bash
npm run db:generate
```

Inspect generated SQL for destructive operations, unintended nullability changes, missing indexes, and table rebuilds. Apply migrations in journal order. Never edit a migration already applied to production; add a new forward migration.

## Roles

| Role | Typical capabilities |
| --- | --- |
| `auditor` | Read evidence/package metadata and audit-chain status; download authorized packages. |
| `reviewer` | Auditor access plus independent evidence inspection/approval and package generation. Cannot collect, enroll devices, or operate Jira. |
| `compliance_lead` | Evidence collection, collector schedules, device enrollment, Jira operations, and package generation. Cannot approve evidence. |
| `admin` | All operational permissions plus role administration; still cannot approve evidence the same identity created or uploaded. |

Review role assignments regularly. Use separate named accounts; do not share administrator sessions.

Apply migrations through `drizzle/0011_easy_vision.sql`. Migration 0010 adds authoritative assessment scope and collector coverage; migration 0011 adds versioned encryption/HMAC key references and signed audit checkpoints. Production fails closed when `BOOTSTRAP_ADMIN_EMAILS` or `TRUSTED_APP_ORIGINS` is unsafe. Browser collection remains unavailable until its OCR endpoint, token, and exact host allowlist are all configured.

## macOS device deployment

For a single-user local installation built from source, follow the [macOS installation guide](MACOS_INSTALLATION.md). It installs into `~/Applications`, opens the loopback Local Console, and requires no hosted enrollment.

For managed distribution:

1. Build with `./Scripts/build_macos_capture.sh`.
2. For managed production distribution, set `SCOPEPROOF_CODESIGN_IDENTITY` to a trusted Developer ID Application identity.
3. Set `SCOPEPROOF_NOTARY_PROFILE` to a Keychain profile created for `xcrun notarytool` when notarization is required.
4. Generate an offline P-256 release key, compile its X9.63 public key and validity window into `ScopeproofUpdatePublicKeys` in `Info.plist`, and keep the private key outside the repository.
   `./Scripts/configure_macos_release_identity.sh` validates and writes the public release identity from `SCOPEPROOF_UPDATE_*` and `SCOPEPROOF_RELEASE_*` variables. Review and commit only that public metadata.
5. Set the `SCOPEPROOF_UPDATE_*` and `SCOPEPROOF_RELEASE_*` variables required by `./Scripts/publish_release.sh`. The script refuses unsigned, non-notarized, identity-mismatched, or key-mismatched releases and emits `DerivedData/macos-release-envelope.json`.
6. Publish the exact ZIP to its final HTTPS origin. Store only the envelope's `manifest` as `MACOS_RELEASE_MANIFEST_JSON`, its `signatureDERBase64` as `MACOS_RELEASE_SIGNATURE_DER_BASE64`, and configure the exact hostname in `MACOS_RELEASE_ALLOWED_HOSTS`.
7. If hosted synchronization is enabled, enroll each Mac separately from **Connections**. Revoke devices when reassigned, lost, or retired. Leave the native Server URL blank when policy requires local-only operation.

The development build is ad-hoc signed with a stable designated requirement for `com.scopeproof.capture`; it is not a notarized production release. The Local Console is embedded in the native process, binds to a random loopback-only port, and stops when the app quits. It does not require or deploy the hosted Sites application.

## RFC 3161 verifier contract

Scopeproof does not parse CMS itself. The configured verifier must use a maintained RFC 3161/CMS/X.509 implementation and reject non-granted status, wrong SHA-256 imprint or nonce, invalid CMS signatures, missing `id-kp-timeStamping` EKU, untrusted/expired chains, and failed revocation policy. Its response is a bounded JSON attestation signed over RFC 8785 JCS bytes with the pinned ECDSA P-256 verifier key; `signatureBase64` uses the 64-byte IEEE P1363 `r || s` form expected by WebCrypto. The attestation includes the token digest, request digest/nonce, TSA origin, generation/verification times, signer and trust-anchor fingerprints, chain fingerprints/expiry, revocation status, policy OID, and serial number.

Maintain at least two verifier public keys during a controlled rotation window by deploying application support before switching the verifier signer. Update TSA trust-anchor fingerprints only after out-of-band validation, document the change, and retain prior verification metadata with existing evidence. If any verifier setting is absent or validation fails, Scopeproof records signed server time but never labels the RFC 3161 response trusted.

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
npm run lint
npx tsc --noEmit
npm test
```

Run the native tests with the Xcode Swift toolchain, build the `.app`, confirm its bundle version/signature, and smoke-test the menu, settings, capture classification, redaction review, search, Jira comment, and package export on a non-production evidence page.

## Backup, retention, and recovery

- Back up D1, R2 ciphertext, cryptographic key versions, and release artifacts according to the evidence-retention policy.
- Test restoration into an isolated environment and verify sample artifact hashes and audit-chain continuity.
- Hosted packages expire after seven days; preserve the original evidence rather than depending on package objects as the system of record.
- Local retention moves files to Trash and does not remove hosted evidence.
- Place evidence under legal hold before applying deletion when an assessment, investigation, dispute, or regulatory requirement is active.

The full backup manifest, monitoring, quarterly restore-drill, incident-response, and launch-authorization procedures are in [Production operations](PRODUCTION_OPERATIONS.md). A production deployment is not approved until named owners have executed and recorded those controls.
