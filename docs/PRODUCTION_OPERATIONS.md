# Production operations, recovery, and incident response

This runbook is the minimum operational control set for using Scopeproof as a compliance-evidence system of record. Assign named owners and store completed records in an organization-controlled change/incident system. The application remains single-tenant: deploy a separate Sites project, D1 database, R2 bucket, identity policy, and key set for every legal entity or isolation boundary.

## Service objectives

Approve organization-specific objectives before launch. The recommended starting targets are a 24-hour recovery point objective for D1 metadata and R2 ciphertext, a 4-hour recovery time objective for read-only evidence access, and an 8-hour objective for resumed collection. Reduce the RPO when an active assessment cannot tolerate recreating one business day of evidence.

## Backup control

At least daily, capture or verify:

1. A restorable D1 snapshot/export that includes its capture time and platform restore identifier.
2. An inventory of every R2 object key, size, ETag/digest metadata, and capture time. Replicate ciphertext to an organization-controlled account or storage service with retention/immutability enabled when policy requires account-level disaster recovery.
3. Every retained encryption/HMAC key version, the package-signing recovery key, public-key fingerprints, Jira client configuration, Sites configuration, and release public metadata. Key escrow must be encrypted under a separately controlled recovery key with dual-person access.
4. The deployed Git commit, Sites version identifier, migrations applied, macOS release envelope, notarization log, and SBOM.
5. A JSON backup manifest listing each exported file as `{ "path": "relative/path", "sha256": "..." }`. Verify it with `node Scripts/verify_backup_manifest.mjs backup-manifest.json` before marking the backup successful.

Never place plaintext evidence or production secrets in an ordinary workstation backup. Keep backup access separate from application-administrator access and alert on backup deletion, retention changes, restore activity, and failed daily verification.

## Quarterly recovery drill

1. Create an isolated recovery Sites project and new restricted operator identities.
2. Restore D1 and R2 ciphertext from a selected recovery point without connecting collectors or Jira.
3. Restore all referenced keys. Run the administrator readiness endpoint; missing-key references are a failed drill.
4. Verify the full audit chain and the latest signed checkpoint against the independently retained public-key fingerprint and external checkpoint copy.
5. Download a stratified sample covering each retained encryption key, evidence type, assessment, and month. Verify plaintext SHA-256 values.
6. Generate and independently verify an assessor package. Do not send it to production Jira.
7. Record actual RPO/RTO, sample IDs/digests, deviations, owners, corrective issues, and destruction of the isolated recovery environment.

## Monitoring and alerting

Configure `SECURITY_EVENT_ENDPOINT`, its exact hostname allowlist, and a bearer token for the organization monitoring ingress. Every scheduler run sends an HMAC-authenticated, metadata-only health record containing 24-hour failure counts and checkpoint health. Configure the receiver with the retained audit HMAC keys and alert on signature failure, missing health records for 30 minutes, collector action-needed state, failed jobs/packages/purges, unresolved Jira uploads, or stale/failed audit checkpoints.

Also alert from platform logs on `scopeproof_api_error`, `scopeproof_audited_batch_failure`, `scopeproof_audit_checkpoint_delivery_failure`, `scopeproof_operational_health_delivery_failure`, `scopeproof_rekey_old_object_delete_failure`, and sustained rate limiting. Do not send evidence contents, OAuth tokens, user tokens, OCR text, or secrets to monitoring.

## Incident response

Severity 1 includes suspected key compromise, audit-chain/checkpoint failure, unauthorized evidence access, cross-boundary exposure, malicious release/update, or loss of both primary and recovery data. Immediately stop collection/export/Jira transfer, preserve logs and external checkpoints, revoke affected device/OAuth/provider credentials, restrict administrator access, and open the security incident process. Do not rotate away or destroy a suspected key before preserving a controlled recovery copy needed to analyze historical records.

For integrity incidents, compare the database head with independent checkpoints, restore into isolation, identify the earliest divergence, and treat later assertions as untrusted until re-established. For confidentiality incidents, identify affected assessment/evidence IDs from metadata, determine whether ciphertext and keys were both exposed, follow contractual/regulatory notification procedures, and reissue provider/Jira credentials. For release compromise, remove hosted release metadata, revoke/notarization credentials where supported, publish an independently communicated block notice, and ship a higher monotonic sequence signed by a new trusted update key.

Close an incident only after root cause, evidence preservation, containment, eradication, recovery validation, notification decisions, key/credential rotation, control improvements, and an owner/due date for every follow-up are recorded.

## Launch authorization checklist

- Named application, security, backup, Jira, and assessment owners are assigned.
- DPA/privacy review, data classification, retention schedule, legal-hold process, and data-residency decision are approved.
- Production secrets are organization-owned; readiness has no failures; external audit checkpoint and monitoring delivery are tested.
- At least two named administrators and separate collector/reviewer identities exist; roles and break-glass access are reviewed.
- Jira OAuth uses an organization-owned Atlassian app and least-privilege projects; a test attachment and reconciliation exercise succeeded.
- Every required collector has complete pagination coverage and an approved least-privilege service identity.
- Backup verification and an isolated recovery drill met approved RPO/RTO.
- GitHub protected-branch checks, code-owner review, dependency updates, secret scanning, and release approvals are enabled.
- The production Mac build is Developer ID signed, hardened, notarized, stapled, update-signed, hosted on an approved HTTPS origin, and verified on a clean Mac.
- A representative assessment completed capture → independent review → scoped export → independent verification without manual database repair.

If any item is not applicable, record the owner, rationale, compensating control, expiration date, and approval. An unchecked or undocumented item is not a production exception.
