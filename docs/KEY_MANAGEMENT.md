# Key Management and Audit Checkpoints

Scopeproof uses separate key domains for evidence encryption, audit integrity, Jira OAuth token encryption, and package/checkpoint signing. Production operators must keep these keys in the hosting secret manager or an organization-controlled secrets platform. Never place live key material in source control, support tickets, Jira, or exported assessor packages.

## Key domains

| Purpose | Active-key setting | Retained keyring | Legacy compatibility |
| --- | --- | --- | --- |
| Evidence and export AES-256-GCM | `EVIDENCE_ACTIVE_KEY_ID` | `EVIDENCE_KEYRING_JSON` | `EVIDENCE_ENCRYPTION_KEY` is loaded as `legacy-v1` |
| Audit and Jira-receipt HMAC | `AUDIT_ACTIVE_KEY_ID` | `AUDIT_KEYRING_JSON` | `AUDIT_HMAC_KEY` is loaded as `legacy-v1` |
| Jira OAuth token AES-256-GCM | `JIRA_OAUTH_ACTIVE_KEY_ID` | `JIRA_OAUTH_KEYRING_JSON` | `JIRA_OAUTH_TOKEN_ENCRYPTION_KEY` is loaded as `legacy-v1` |
| Package and checkpoint ECDSA P-256 | n/a | externally versioned signing process | `PACKAGE_SIGNING_PRIVATE_KEY` and `PACKAGE_SIGNING_PUBLIC_KEY` |

Key IDs are durable record metadata. Do not reuse an ID for different key material.

## Rotation procedure

1. Generate a new 32-byte random AES key for an encryption domain or a high-entropy secret for the audit domain. Use an organization-approved cryptographic random generator.
2. Add the new key to the corresponding JSON keyring while retaining every existing entry. Set the active-key ID to the new entry and deploy the secret update.
3. Confirm `GET /api/admin/readiness` reports that every referenced key is retained.
4. For evidence/Jira encryption, invoke `POST /api/admin/keys/rotate` as an administrator with `{"limit":25}` until `remaining` is zero. The scheduled worker also rotates five records per run. Each successful record rotation is audit logged.
5. Download representative evidence and an assessor package, test the Jira connection, verify the audit chain, and verify the latest audit checkpoint.
6. Keep old evidence/Jira encryption keys until readiness reports no references. Keep old audit HMAC keys for at least the entire audit-log retention period: historical events and Jira upload receipts are intentionally never re-signed during rotation.
7. Remove an old encryption key only after a database inventory, object recovery test, and an approved change record all confirm zero references. Removal is a destructive operation because missing retained keys make historical data unverifiable or undecryptable.

If rotation is interrupted, records already switched to the new object remain valid and unprocessed records continue to use their recorded old key. A new encrypted object is committed in the database before the old object is deleted, avoiding an in-place ciphertext/key mismatch.

## Audit checkpoints

Every scheduled worker run signs the current audit-chain head with the package ECDSA key and writes an immutable checkpoint-shaped object under `audit-checkpoints/YYYY-MM/` in the evidence bucket. Configure `AUDIT_CHECKPOINT_ENDPOINT` and `AUDIT_CHECKPOINT_ALLOWED_HOSTS` to send the same signed envelope to an independent, append-only system outside the Scopeproof database account. The endpoint must use HTTPS, cannot redirect, and must be on the explicit hostname allowlist.

Alert on:

- `scopeproof_audit_checkpoint_delivery_failure`
- a `failed` independent-checkpoint status
- no checkpoint for more than 30 minutes while audit events exist
- any audit-chain verification failure
- any retained-key readiness failure

Use `node Scripts/verify_audit_checkpoint.mjs checkpoint.json` to verify an exported checkpoint independently. A valid local signature proves that the checkpoint was signed by the included public key. The public-key fingerprint must also be compared with the fingerprint held in an independent organizational trust record.

## Compromise response

If an evidence/Jira encryption key may be exposed, preserve the affected key in a restricted incident vault, activate a new key, rotate all records, revoke affected OAuth grants when applicable, and investigate object/database access logs. If an audit HMAC or package signing key may be exposed, treat historical integrity assertions after the earliest suspected compromise time as untrusted, rotate the key, publish the new public-key fingerprint through an independent channel, and preserve the incident timeline and previously externalized checkpoints.
