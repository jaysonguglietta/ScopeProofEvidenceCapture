# Scopeproof security model

Scopeproof handles security and compliance evidence that may expose sensitive configuration, identities, infrastructure, and control gaps. Deploy it as a high-sensitivity internal system and assume browsers, endpoints, provider responses, uploaded metadata, and assessors’ workstations may be compromised.

## Protected assets

- Evidence plaintext and decrypted assessor packages.
- Provider credentials and macOS device tokens.
- Evidence encryption, audit HMAC, and package-signing keys.
- User identity, roles, review decisions, Jira associations, and audit history.
- The integrity and availability of captures, manifests, receipts, and packages.

## Implemented controls

### Identity and authorization

- Private Sites identity headers authenticate web users.
- Server-side roles are ordered `auditor`, `reviewer`, `compliance_lead`, and `admin`.
- Reviewers can submit/approve evidence and enroll their capture devices; compliance leads can operate collectors, build packages, and view broader administration; admins can change roles.
- The last administrator cannot be demoted.
- Mutation endpoints enforce same-origin requests.
- macOS devices use revocable random bearer tokens; only SHA-256 token hashes are stored server-side and the Mac stores its token in Keychain.

### Data protection and integrity

- Textual evidence is scanned for Luhn-valid PAN and supported secret/token families before persistence.
- Native screenshots run local OCR/redaction and must have a reviewed safety state and matching manifest digest.
- Evidence and generated packages are encrypted with AES-256-GCM in R2.
- D1 contains metadata, object references, IVs, and integrity digests rather than evidence plaintext.
- Audit events are canonicalized, hash-chained, HMAC-authenticated, and protected from update/delete by D1 triggers.
- Assessor manifests are ECDSA P-256/SHA-256 signed and include independent artifact hashes.
- Jira URLs require HTTPS, issue keys are format-restricted, and native Jira metadata must match the immutable manifest.

### Abuse resistance

- Provider requests, pagination, browser targets, retries, due work, upload sizes, package counts, and decrypted package bytes are bounded.
- Browser collection permits HTTPS targets only and blocks persistence when rendered text contains detected sensitive values.
- Error responses use request IDs and avoid returning server exception details to clients.

## Secure operating requirements

1. Use a private Sites access policy and grant the minimum role required.
2. Configure `BOOTSTRAP_ADMIN_EMAILS` before the first sign-in. Without it, the first user becomes administrator.
3. Use distinct, high-entropy encryption, audit, and signing keys. Store them only in the hosted secret manager.
4. Use least-privilege, read-only provider credentials and dedicated accounts where supported.
5. Restrict browser capture URLs to an explicit approved list and avoid pages containing cardholder or customer data.
6. Require managed, encrypted macOS endpoints with screen lock, malware protection, and current OS updates.
7. Verify Jira project permissions, automation rules, marketplace apps, backups, and retention before attachment.
8. Review audit-chain health, device inventory, collector errors, failed jobs, expiring evidence, and package downloads routinely.
9. Rotate or revoke a device/provider credential immediately after suspected exposure.
10. Preserve old encryption-key material under controlled key-version procedures until all dependent evidence is expired or re-encrypted.

## Residual risks and limitations

- OCR and pattern matching cannot guarantee detection of every sensitive value. Operator preview remains mandatory.
- A compromised endpoint can display falsified source content or capture manipulated pixels.
- Local timestamps depend on the Mac clock. Hosted receipts add signed server time; RFC 3161 requires an independently configured authority.
- The package’s embedded public key must be fingerprint-verified out of band to establish signer continuity.
- Jira handoff is manual. Scopeproof cannot enforce Jira authorization, retention, or downstream sharing.
- Provider coverage is intentionally bounded and may require additional collection for large environments.
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
