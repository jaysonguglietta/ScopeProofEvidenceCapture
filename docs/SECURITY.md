# Scopeproof security model

Scopeproof handles security and compliance evidence that may expose sensitive configuration, identities, infrastructure, and control gaps. Deploy it as a high-sensitivity internal system and assume browsers, endpoints, provider responses, uploaded metadata, and assessors’ workstations may be compromised.

## Protected assets

- Evidence plaintext and decrypted assessor packages.
- Provider credentials and macOS device tokens.
- Evidence encryption, audit HMAC, and package-signing keys.
- User identity, roles, review decisions, Jira associations, and audit history.
- The integrity and availability of captures, manifests, receipts, and packages.
- Repository source provenance, generated SBOM contents, SBOM job history, and the GitHub read token used to access private source archives.

## Implemented controls

### Identity and authorization

- Private Sites identity headers authenticate web users only on exact HTTPS origins in `TRUSTED_APP_ORIGINS`. Direct Worker, preview, alternate-domain, and misrouted requests fail before identity headers are consumed; the private Sites dispatcher must strip client-supplied identity headers and inject authenticated values.
- Server-side permissions separate review from collection: reviewers inspect/approve, compliance leads collect/enroll/disclose, and administrators manage roles. An identity can never approve evidence it created or uploaded.
- Initial administration requires a non-empty explicit email allowlist. A D1 invariant and atomic batch permit one bootstrap claim, bind its audit event, and preserve the final administrator at the database layer.
- Mutation endpoints require an exact same-origin `Origin` and reject conflicting Fetch Metadata.
- Reviewers receive the actual decrypted, digest-verified artifact rather than a generated placeholder. Approval requires a matching full digest, a review rationale, and explicit scope/freshness/redaction confirmation.
- macOS devices use revocable random bearer tokens; only SHA-256 token hashes are stored server-side and the Mac stores its token in Keychain.
- Local mode requires no web identity or device token. The embedded console binds only to `127.0.0.1`, uses a per-launch 256-bit HttpOnly SameSite session, rejects cross-origin mutations and transfer-encoded/ambiguous requests, and never accepts browser-supplied filesystem paths.
- Jira Cloud uses OAuth 2.0 authorization-code flow. Rotating access and refresh tokens are AES-256-GCM encrypted with a dedicated hosted key and bound to a Scopeproof user and connection identity.

### Data protection and integrity

- Textual evidence is scanned for Luhn-valid PAN and supported secret/token families before persistence.
- Native screenshots never write the unreviewed source pixels to disk. Local OCR/redaction runs before and after stamping, the reviewed PNG is encoded in memory and scanned again, and the manifest binds the exact saved digest, scanner policy, and completion time. The client HMAC-authenticates the exact manifest/PNG digest pair; the server requires schema 6, validates the scan binding and capture chain, and fully parses/decompresses bounded PNG data before storage. Local scan results remain explicitly labeled as client claims.
- Evidence and generated packages are encrypted with AES-256-GCM in R2.
- D1 contains metadata, object references, IVs, and integrity digests rather than evidence plaintext.
- Audit events are canonicalized, hash-chained, HMAC-authenticated, and protected from update/delete by D1 triggers. Security-sensitive D1 mutations and their audit event execute in one transactional batch; a stale audit head rolls the entire batch back and retries. Repeated failures emit `scopeproof_audited_batch_failure` for alerting without event details.
- The local SQLite index is non-authoritative and rebuildable from manifests. Its audit table is hash-chained, authenticated with a device-only Keychain key, verified before every append, and protected from update/delete by SQLite triggers. Local evidence files use macOS complete file protection and account-only permissions; managed endpoints should also enforce FileVault.
- Assessor manifests are ECDSA P-256/SHA-256 signed and include independent artifact hashes.
- Jira URLs require HTTPS, issue keys are format-restricted, and native Jira metadata must match the immutable manifest.
- Jira API calls use fixed Atlassian hosts and server-selected cloud IDs. OAuth state is random, user-bound, stored only as a hash, single-use, and expires after ten minutes. Requested sites must end in `.atlassian.net`, match Atlassian’s accessible resources, and use configured project allowlists.
- Jira uploads require explicit confirmation and revalidate the device, issue, project, PNG digest, redaction safety state, Approved lifecycle chain, and attachment limits. A durable idempotency reservation prevents concurrent duplicate attachment sets; ambiguous network/provider outcomes require reconciliation instead of automatic replay. OAuth refresh-token rotation is serialized with an expiring lease and optimistic token version. Signed upload receipts and audit events exclude token material.
- Repository SBOM creation is restricted to compliance leads and administrators, while evidence approval remains independent. Managed mode constructs the repository owner from fixed `GITHUB_ORG`; one-time mode accepts only an exact HTTPS `github.com/owner/repository` URL. Both validate repository/ref syntax, require an active assessment with PCI DSS 6.3.2 and matching system scope, and resolve the requested ref to an immutable commit before inventory generation.
- GitHub access is read-only and destination-restricted to `api.github.com` and the exact `codeload.github.com` archive redirect. Managed credentials remain server-side. A one-time token is masked, cleared from the form at submission, held only for the request, and excluded from D1, R2, jobs, evidence, audit details, logs, settings, browser storage, and Keychain. One-time jobs have one attempt and fail closed rather than retrying without a credential. Generated JSON uses the same evidence encryption, digest, lifecycle, download-audit, retention, and package controls as other hosted evidence.

### Abuse resistance

- Provider requests, pagination, browser targets, retries, due work, upload sizes, package counts, and decrypted package bytes are bounded.
- Browser collection permits HTTPS targets only. It scans the single captured PNG through an HTTPS OCR endpoint on an exact host allowlist, verifies the OCR response names the same digest, and fails closed on scan errors or sensitive recognized pixels.
- Repository archives are untrusted. Scopeproof validates the central directory before extraction, rejects malformed/oversized/over-compressed archives and non-UTF-8 or NUL-containing manifests, extracts only recognized lockfiles, caps parsed components, and never invokes source files, package managers, install hooks, build tools, containers, or subprocesses.
- SBOM generation permits ten requests per authenticated user per hour, uses leased jobs with bounded retries only for transient provider failures, and caps scheduler work to prevent one repository from monopolizing execution.
- Error responses use request IDs and avoid returning server exception details to clients.

## Secure operating requirements

1. Use a private Sites access policy and grant the minimum role required.
2. Configure `BOOTSTRAP_ADMIN_EMAILS` and the exact canonical `TRUSTED_APP_ORIGINS` before any sign-in. Missing or unsafe values make authenticated APIs unavailable by design.
3. Use distinct, high-entropy encryption, audit, and signing keys. Store them only in the hosted secret manager.
4. Use least-privilege, read-only provider credentials and dedicated accounts where supported.
5. Restrict browser capture URLs to an explicit approved list and avoid pages containing cardholder or customer data.
6. Require managed, encrypted macOS endpoints with screen lock, malware protection, and current OS updates.
7. Verify Jira project permissions, automation rules, marketplace apps, backups, and retention before attachment.
8. Review audit-chain health, device inventory, collector errors, failed jobs, expiring evidence, and package downloads routinely.
9. Rotate or revoke a device/provider credential immediately after suspected exposure.
10. Preserve old encryption-key material under controlled key-version procedures until all dependent evidence is expired or re-encrypted.
11. Restrict `GITHUB_TOKEN` to the intended repositories with Metadata and Contents read access only. Rotate it, monitor GitHub access, remove repositories no longer in scope, and leave SBOM generation unconfigured rather than granting broad organization access.
12. For one-time SBOM access, use a dedicated short-expiry repository-scoped token, prevent password-manager saving, revoke it after use, and treat the operator browser/endpoint as part of the credential trust boundary.

## Residual risks and limitations

- OCR and pattern matching cannot guarantee detection of every sensitive value. Native operator preview remains mandatory, and browser OCR services require independent security/privacy review because captured pixels are disclosed to that processor.
- A compromised endpoint can display falsified source content or capture manipulated pixels.
- Local timestamps depend on the Mac clock. Hosted receipts add signed server time. A third-party timestamp is labeled verified only after a pinned verifier attests the RFC 3161 success status, SHA-256 message imprint, request nonce, CMS signature, TSA `timeStamping` EKU, certificate path, configured trust anchor, validity window, and revocation status; otherwise the receipt retains only Scopeproof server time and a bounded diagnostic.
- Local lifecycle schema 2 derives all projected state from the final verified event. Every event binds reviewer identity, time, artifact digest, review policy, scanner policy, owner, rationale, tags, and supersession state. Obsolete/unbound or inconsistent sidecars are draft/ineligible and require recapture. The package-signing identity rotates to a user-presence-protected Keychain item.
- The package’s embedded public key must be fingerprint-verified out of band to establish signer continuity.
- Jira permissions, issue security, marketplace apps, notifications, backups, exports, retention, and downstream sharing remain outside Scopeproof’s control. Timeout failures can leave an ambiguous attachment outcome that must be inspected before retry.
- Spreadsheet CSV indexes are presentation-only and prefix formula-like cells (including after leading ASCII whitespace/control characters) with an apostrophe. Use the signed JSON manifest for machine verification.
- Update trust depends on protecting the offline release private key and accurately provisioning its matching public key and validity window in the signed app bundle. An empty key list fails closed and intentionally disables updates.
- Provider coverage is intentionally bounded and may require additional collection for large environments.
- Repository SBOM coverage is limited to supported pinned lockfiles and the first 250 repositories returned for the configured organization. Static parsing cannot prove the deployed artifact, dynamically loaded dependencies, vendored code, generated lockfiles absent from the commit, transitive resolution performed outside a supported lockfile, vulnerability status, or license obligations.
- A compromised GitHub organization administrator or source repository can supply deceptive lockfiles. Commit immutability and archive hashing establish what Scopeproof parsed, not that the source is trustworthy; require protected branches, change review, release provenance, and vulnerability analysis as separate controls.
- One-time input avoids long-term application storage but cannot protect a token from a compromised browser, extension, endpoint, organization-managed TLS inspection, or GitHub access logging. Use managed endpoints and narrowly scoped, short-lived credentials; do not use a personal broad-scope token.
- Key rotation is not automatic; replacing an encryption key without a migration can make prior evidence undecryptable.
- An ad-hoc local macOS build is not notarized and does not provide a Developer ID trust chain.

## Incident response

If evidence, a token, or a signing/encryption key may be compromised:

1. Stop affected collectors or Jira transfers and preserve relevant logs and hashes.
2. Revoke affected macOS device tokens and provider credentials.
3. Restrict site and Jira access; identify downloads, exports, and downstream recipients.
4. Rotate exposed keys using a documented migration and recovery plan. Do not destroy keys still required to decrypt retained evidence.
5. Verify the hosted audit chain and compare affected artifact/package hashes.
6. Recapture or rebuild evidence when provenance or confidentiality cannot be established.
7. Record containment, impact, decisions, notifications, and recovery evidence in the incident system.

Report vulnerabilities privately through the GitHub repository’s Security Advisory feature. Do not include real credentials, PAN, customer data, or production evidence in a public issue.
