# Key Management and Audit Checkpoints

Scopeproof uses separate key domains for evidence encryption, audit integrity, Jira OAuth token encryption, package/checkpoint signing, native device provenance, independent scanner authentication, and trusted timestamp verification. Production operators must keep hosted secrets in the hosting secret manager or an organization-controlled secrets platform. Native private keys and device credentials belong only in device-bound macOS Keychain items. Never place live key material in source control, support tickets, Jira, logs, or exported assessor packages.

## Key domains

| Purpose | Active-key setting | Retained keyring | Legacy compatibility |
| --- | --- | --- | --- |
| Evidence and export AES-256-GCM | `EVIDENCE_ACTIVE_KEY_ID` | `EVIDENCE_KEYRING_JSON` | `EVIDENCE_ENCRYPTION_KEY` is loaded as `legacy-v1` |
| Audit and Jira-receipt HMAC | `AUDIT_ACTIVE_KEY_ID` | `AUDIT_KEYRING_JSON` | `AUDIT_HMAC_KEY` is loaded as `legacy-v1` |
| Jira OAuth token AES-256-GCM | `JIRA_OAUTH_ACTIVE_KEY_ID` | `JIRA_OAUTH_KEYRING_JSON` | `JIRA_OAUTH_TOKEN_ENCRYPTION_KEY` is loaded as `legacy-v1` |
| Package and checkpoint ECDSA P-256 | n/a | externally versioned signing process | `PACKAGE_SIGNING_PRIVATE_KEY` and `PACKAGE_SIGNING_PUBLIC_KEY` |

Key IDs are durable record metadata. Do not reuse an ID for different key material.

## Native provenance, scanner, and timestamp trust

Each current Mac creates a P-256 signing identity in a `WhenUnlockedThisDeviceOnly` Keychain item. New schema-8 manifests are signed with that key, include the exact tenant/workspace, its public key and SHA-256 key ID, and advance a separately stored local chain anchor. The hosted service first requires that signed binding to equal its isolated deployment configuration, then pins the first authorized device provenance key and requires the same key, contiguous sequence, previous hash, event hash, image digest, and manifest digest when finalizing later uploads. The provenance private key is distinct from the audience-bound `spdev_dev_…` enrollment token used for API authentication and HMAC upload binding; compromise or rotation of either one requires its own response.

Do not export a native provenance private key, copy it to another Mac, or silently regenerate it after Keychain loss. Revoke the affected device, preserve the last trusted hosted/local chain heads, enroll the replacement as a new authorized device/epoch, and recapture evidence that must enter the hosted trust boundary. Never rewrite an older manifest, add a tenant/workspace, or backfill a replacement key ID. Schema-7 evidence predates the current hosted binding and schema-6 or older artifacts remain visibly unverified legacy material; recapture any of them that must enter the current hosted trust boundary.

The independent screenshot scanner bearer secret is `BROWSER_OCR_TOKEN`; the legacy-named `BROWSER_OCR_ENDPOINT` and `BROWSER_OCR_ALLOWED_HOSTS` bind where it may be sent. This credential authorizes a transient exact-PNG OCR/DLP request but does not sign evidence and must never appear in a scan receipt. Recognized OCR text is used in memory for policy evaluation and is not retained. Rotate the scanner token at both ends, run a digest-bound canary, and confirm production readiness before retiring the previous secret.

The RFC 3161 boundary uses the configured TSA endpoint plus an independent verifier endpoint/token, verifier public-key set, allowed-host list, and pinned TSA trust-anchor SHA-256. Treat verifier public keys and the TSA anchor as versioned trust records even when they are not secret. A Scopeproof application signing key or server clock must not substitute for a required trusted timestamp. Production readiness must fail when timestamp enforcement is disabled, the issuer/verifier is missing, or trust material is incomplete.

## Rotation procedure

1. Generate a new 32-byte random AES key for an encryption domain or a high-entropy secret for the audit domain. Use an organization-approved cryptographic random generator.
2. Add the new key to the corresponding JSON keyring while retaining every existing entry. Set the active-key ID to the new entry and deploy the secret update.
3. Confirm `GET /api/admin/readiness` reports that every referenced key is retained.
4. For evidence/Jira encryption, invoke `POST /api/admin/keys/rotate` as an administrator with `{"limit":25}` until `remaining` is zero. The scheduled worker also rotates five records per run. Each record is isolated: a failure creates or advances durable `key_rotation_attempts` state, uses bounded exponential backoff, and cannot prevent later records from rotating. Failure increments carry unique attempt IDs and use compare-and-swap transitions so concurrent workers cannot overwrite or undercount one another. The fifth consecutive failure moves the record to `action_required`, emits an audit event, and makes production readiness fail; `retrying` state is a readiness warning. Repair the underlying key/object/token condition and rerun rotation. Recovery is audit logged and ambiguous copy-switch-delete results are reconciled from the authoritative database state before any candidate ciphertext is deleted. Do not delete the retry row or edit its state by hand.
5. Download representative evidence and an assessor package, test the Jira connection, verify the audit chain, and verify the latest audit checkpoint.
6. Keep old evidence/Jira encryption keys until readiness reports no references. Keep old audit HMAC keys for at least the entire audit-log retention period: historical events and Jira upload receipts are intentionally never re-signed during rotation.
7. Remove an old encryption key only after a database inventory, object recovery test, and an approved change record all confirm zero references. Removal is a destructive operation because missing retained keys make historical data unverifiable or undecryptable.

If rotation is interrupted, records already switched to the new object remain valid and unprocessed records continue to use their recorded old key. A new encrypted object is committed in the database before the old object is deleted, avoiding an in-place ciphertext/key mismatch.

Native provenance and RFC 3161 trust are append-only provenance concerns, not re-encryption jobs. Rotation starts a new explicitly authorized signing/trust epoch and preserves the prior public keys, anchors, receipts, and chain heads for as long as the corresponding evidence is retained. Do not re-sign historical manifests, timestamps, lifecycle events, or Jira receipts.

## Audit checkpoints

The scheduled worker creates one immutable, ECDSA-signed checkpoint when it observes a new audit-chain head and stores the envelope under `audit-checkpoints/YYYY-MM/` in the evidence bucket. Later runs reuse that exact checkpoint while the same head remains current; they do not mint duplicate checkpoints. Configure `AUDIT_CHECKPOINT_ENDPOINT` and `AUDIT_CHECKPOINT_ALLOWED_HOSTS` to send the same signed envelope to an independent, append-only system outside the Scopeproof database account. The endpoint must use HTTPS, cannot redirect, and must be on the explicit hostname allowlist.

Before an outbound witness call, a worker atomically claims the due retry state with a two-minute lease. This prevents concurrent schedulers from bypassing the retry window or consuming multiple attempts. Each delivery uses the checkpoint SHA-256 as its `Idempotency-Key`; failed and successful outcomes are appended to an immutable ledger and are bound to the active claim. Failures use bounded exponential backoff from one minute to six hours. A stale claim is safely recovered, and the tenth unsuccessful claim moves the checkpoint to terminal `action_required` state. Only one delivered attempt may win, and its signed receipt is bound to a unique immutable R2 object. Repair the endpoint or trust configuration, then append an audited operational event so a new audit head can create a new checkpoint; do not delete or edit retry state. Production readiness and tail verification fail until delivery succeeds. Verification rejects a checkpoint unless its embedded public key exactly matches `PACKAGE_SIGNING_PUBLIC_KEY`, its sequence, event hash, HMAC key ID, and cumulative event count match the actual D1 anchor, and its successful delivery-attempt receipt/digest still verifies.

Alert on:

- `scopeproof_audit_checkpoint_delivery_failure`
- `scopeproof_audit_checkpoint_delivery_action_required`
- `scopeproof_maintenance_stage_failure` for `audit_checkpoint`
- `scopeproof_key_rotation_retry_scheduled` and `scopeproof_key_rotation_action_required`
- a `failed` independent-checkpoint status
- no checkpoint for more than 30 minutes while audit events exist
- any audit-chain verification failure
- any retained-key readiness failure

Use `node Scripts/verify_audit_checkpoint.mjs checkpoint.json` to verify an exported checkpoint independently. A valid signature proves only that the included public key signed the bytes. Compare that key and fingerprint with the organization-controlled trust record, then compare the envelope’s sequence/hash/count with both the independently retained checkpoint and the exported audit log. The application performs the corresponding configured-key and live-D1 checks before using a checkpoint as its bounded verification anchor.

## Compromise response

If an evidence/Jira encryption key may be exposed, preserve the affected key in a restricted incident vault, activate a new key, rotate all records, revoke affected OAuth grants when applicable, and investigate object/database access logs. If an audit HMAC or package signing key may be exposed, treat historical integrity assertions after the earliest suspected compromise time as untrusted, rotate the key, publish the new public-key fingerprint through an independent channel, and preserve the incident timeline and previously externalized checkpoints.
