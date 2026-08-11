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

Never reuse one value for multiple purposes. Record key ownership, creation date, rotation version, recovery escrow, and destruction approval outside the repository.

## Optional provider configuration

| Collector | Variables | Recommended scope |
| --- | --- | --- |
| AWS | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, optional `AWS_SESSION_TOKEN`, `AWS_REGION` | Read-only Config recorder and EC2 security-group inventory. Prefer temporary credentials. |
| GitHub | `GITHUB_TOKEN`, `GITHUB_ORG` | Organization repository metadata and default-branch protection read access. |
| Okta | `OKTA_BASE_URL`, `OKTA_API_TOKEN` | Read-only policy and group inventory. |
| Cloudflare | `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`, optional `CLOUDFLARE_ZONE_IDS` | Zone and managed-ruleset read access. |
| Browser Rendering | Cloudflare variables plus `BROWSER_CAPTURE_URLS` | Dedicated HTTPS evidence URLs only. |

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
| `reviewer` | Auditor access plus manual evidence submission, approval, and own-device enrollment/revocation. |
| `compliance_lead` | Reviewer access plus collector operation, package generation, user/device oversight, and schedules. |
| `admin` | Compliance-lead access plus role administration. |

Review role assignments regularly. Use separate named accounts; do not share administrator sessions.

## macOS device deployment

1. Build with `./Scripts/build_macos_capture.sh`.
2. For managed production distribution, set `SCOPEPROOF_CODESIGN_IDENTITY` to a trusted Developer ID Application identity.
3. Set `SCOPEPROOF_NOTARY_PROFILE` to a Keychain profile created for `xcrun notarytool` when notarization is required.
4. Publish only through HTTPS with an independently recorded release SHA-256.
5. Configure `MACOS_LATEST_VERSION=1.3.1`, `MACOS_RELEASE_URL`, `MACOS_RELEASE_SHA256`, and operator-facing `MACOS_RELEASE_NOTES` in the hosted environment.
6. Enroll each Mac separately from **Connections**. Revoke devices when reassigned, lost, or retired.

The development build is ad-hoc signed with a stable designated requirement for `com.scopeproof.capture`; it is not a notarized production release.

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
