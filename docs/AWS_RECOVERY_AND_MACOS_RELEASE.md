# AWS recovery and production macOS release

This runbook covers the cross-region recovery resources and the production
Developer ID/notarization workflow. Both are fail-closed. Neither is deployed or
submitted to Apple by committing this repository.

## Cross-region recovery architecture

The implemented recovery target is deliberately same-account and cross-region:
it covers regional loss but is not an AWS account-compromise boundary.
Production uses three complementary mechanisms:

- the DynamoDB control plane is synthesized as an on-demand
  `AWS::DynamoDB::GlobalTable` with PITR and deletion protection in the primary
  region and, when recovery is enabled, in the configured recovery region;
- S3 replication copies every immutable object version under
  `tenants/<tenant>/controls/` into a tenant-specific, versioned, KMS-encrypted,
  Object-Locked bucket in a different AWS region. Delete-marker replication is
  disabled. S3 Replication Time Control is mandatory in production. A
  tenant-local recovery reconciler also creates a deterministic S3 Batch
  Replication job for pre-cutoff `NONE`/`FAILED` versions, persists its progress,
  and compares each source/destination `VersionId`, byte count, provider-returned
  full-object SHA-256 checksum, SHA-256 metadata, original upload time, tenant
  metadata, KMS key, retention, and legal-hold state. The first generation and
  explicit repair generations scan S3 versions; later generations consume a
  strongly consistent, time-ordered DynamoDB recovery ledger rather than
  rescanning all historical evidence;
- AWS Backup creates daily Aurora recovery points in a locked primary vault and
  copies them into a customer-managed-KMS vault in the recovery region. Backup,
  copy, and restore failures publish to encrypted operations topics.

Recovery resources are retained if a stack is removed. Production requires
Compliance Vault Lock, at least a seven-day changeable cooling-off window, at
least 365 days for cross-region Aurora copies, and one exact destination bucket
and KMS key for every configured tenant.

### Existing control-table migration stop

> **Do not directly deploy this revision over an existing stack whose control
> plane is `AWS::DynamoDB::Table`.** The source now uses
> `AWS::DynamoDB::GlobalTable`; changing the CloudFormation resource type is not
> an in-place data-preserving update. A direct update can fail, attempt a
> replacement, or leave ownership drift. Fresh deployments are safe to create
> from the current template.

For an existing deployment, open a dedicated recovery-tested change and:

1. stop tenant provisioning and evidence mutations; record the table ARN/name,
   item count, latest restorable time, TTL/GSI/PITR/deletion-protection settings,
   tags, alarms, and a checksum/count reconciliation against Aurora;
2. take and verify an export or on-demand backup in addition to PITR;
3. apply a reviewed retain policy, remove the old logical resource from
   CloudFormation management without deleting the physical table, and verify the
   application still points to the retained table;
4. use the approved DynamoDB global-table conversion/replica procedure, then
   import the retained physical resource under the new
   `AWS::DynamoDB::GlobalTable` logical resource with the exact primary and
   recovery replicas; and
5. run drift detection, item/index/TTL/PITR reconciliation, cross-region writes
   and failover-read tests, and all tenant denial canaries before unfreezing.

Rehearse the exact retain/remove/convert/import sequence in a disposable account
with production-shaped data first. Never rename, replace, empty, or dual-write
the control table as an improvised migration.

## Two-phase recovery deployment

Vault and destination key ARNs do not exist until AWS creates them, so use an
explicit bootstrap followed by enablement. Do this first in an isolated stage
account.

### 1. Bootstrap the destination region

Set an explicit AWS account and primary region, then synthesize the recovery-only
stack with `recovery.mode=bootstrap`. Example context:

```json
{
  "deploymentEnvironment": "stage",
  "recovery": {
    "mode": "bootstrap",
    "region": "us-west-2",
    "vaultLockMode": "GOVERNANCE",
    "auroraLocalRetentionDays": 35,
    "auroraCopyRetentionDays": 365,
    "s3ReplicationTimeControl": false
  }
}
```

Review `cdk diff`, deploy only `ScopeproofRecovery`, and record these outputs:

- `RecoveryBackupVaultArn`
- `RecoveryBackupVaultKeyArn`
- each `EvidenceReplicaBucket-*`
- each `EvidenceReplicaKeyArn-*`

Do not infer or hand-edit an ARN. Account, partition, region, tenant ID, bucket
name, and KMS key ID are validated exactly.

### 2. Enable the complete topology

Change `recovery.mode` to `enabled`, provide `backupVaultKeyArn`, and add exactly
one destination per configured tenant:

```json
{
  "deploymentEnvironment": "prod",
  "recovery": {
    "mode": "enabled",
    "region": "us-west-2",
    "vaultLockMode": "COMPLIANCE",
    "vaultLockChangeableDays": 7,
    "auroraLocalRetentionDays": 35,
    "auroraCopyRetentionDays": 365,
    "s3ReplicationTimeControl": true,
    "backupVaultKeyArn": "arn:aws:kms:us-west-2:111111111111:key/EXACT-KEY-ID",
    "evidenceDestinations": [
      {
        "tenantId": "ten_0123456789abcdef0123456789abcdef",
        "bucketName": "sp-r-111111111111-uswest2-0123456789abcdef0123456789abcdef",
        "kmsKeyArn": "arn:aws:kms:us-west-2:111111111111:key/EXACT-TENANT-KEY-ID"
      }
    ]
  }
}
```

Synthesize, inspect the exact replication IAM resources, KMS conditions, global
table replicas, S3 Batch role/report bucket/reconciler, and alarms. Deploy the
destination stack first, then the shared and tenant stacks. Do not enter
Compliance Vault Lock until retention, billing, legal, and recovery owners
approve its effectively irreversible behavior. If this is not a fresh
environment, complete the control-table migration stop above before deploying
the shared stack.

After the enabled tenant stack is stable, the 15-minute reconciler reserves one
durable recovery generation under the mutable
`RECOVERY_STATE#TENANT#<tenant-id>` control-table partition, uses an immutable cutoff and
deterministic client token to create an S3-generated-manifest Batch Replication
job, and waits for a terminal job with zero failed tasks. It then validates at
most 250 exact versions per invocation and persists continuation cursors. Every
generation has a final, separately paginated destination-inventory phase. It
cannot advance `verifiedThrough` or report `VERIFIED` until every destination
version at or before the immutable cutoff resolves to the same exact source
`VersionId`; any destination delete marker or orphan version fails closed.
Destination entries newer than the cutoff are left for the next generation so
normal in-flight replication cannot contaminate the immutable snapshot. The
recovery bucket also explicitly denies `s3:DeleteObject` and
`s3:DeleteObjectVersion` for the tenant evidence prefix to all principals; S3
delete-marker replication remains disabled. A live
S3 replication-failure notification records a repair request and emits a
redacted operational alert; a previously verified generation is rotated only
after that durable repair request. Do not edit reconciler rows, submit a second
manual job, or treat a completed Batch job as proof that exact versions match.

Promotion completion atomically writes two records outside the ordinary tenant
API partition: a KMS-signed authoritative promotion receipt at
`RECOVERY#TENANT#<tenant-id>/PROMOTION#<receipt-hash>` and an append-only
`CHANGE#<published-at>#PROMOTION#<receipt-hash>` ledger entry. The verifier has
read/query access—but no write access—to this authoritative partition and calls
KMS `Verify` over the exact domain-separated database receipt before trusting
the S3 metadata or checksum. Ordinary tenant API roles can address only
`TENANT#<tenant-id>` and cannot read or forge recovery state or receipts.

An applied legal-hold operation remains in the database's durable `APPLIED`
recovery-publication outbox until the worker has created or reused and read back
its KMS-signed audit receipt, published the audit-bound recovery state, and
separately acknowledged that exact DynamoDB publication time in Aurora. The recovery
record binds the receipt's canonical payload, event hash, payload digest,
signing key, algorithm, and signature; the recovery verifier calls KMS `Verify`
before accepting that legal-hold state. After the audit proof is durable, the
publisher atomically creates a deterministic operation record, a time-ordered
legal-hold change, and a canonical exact-version current-status projection. A
lost DynamoDB response is recovered with strongly consistent reads and exact
record comparison; a retry reuses and KMS-verifies the authoritative committed
audit event/receipt even if the audit head has advanced, and conflicting retries
fail closed. Each actual write attempt
receives a fresh publication timestamp. The
periodic verifier deliberately stops at `now - 900 seconds`, which is longer
than the five-minute publisher/promoter Lambda timeout, so a late successful
retry cannot appear behind an already-advanced verification watermark. Do not
reduce `LEDGER_SETTLE_SECONDS` below 900 without increasing it beyond every
authorized publisher's maximum end-to-end timeout and re-running concurrency
and lost-response tests.

Legal-hold verification is status-bound, not merely an equality check between
two replicas. Recovery revalidates the current projection's canonical operation
and request digest, then requires both exact S3 versions to equal the requested
`ON` or `OFF` status. If a valid later ON/OFF transition is newer than the
current generation cutoff, the older change is deferred rather than compared
against historical mutable state; the later immutable change remains above the
watermark for the next generation.

## Recovery validation and drill

For each tenant, first require the backfill reconciler's durable state to reach
`VERIFIED`, retain the S3 Batch completion report, and reconcile its total/
success/failure counters. Then create a non-sensitive canary through the real
upload path and record the primary bucket/key/`VersionId`, SHA-256, KMS key,
retention, and legal hold. In the recovery region verify:

1. The corresponding destination version exists under the same tenant/control
   prefix.
2. Its SHA-256, metadata, tags, retention, and legal-hold state match.
3. Its encryption key is the configured destination tenant KMS key.
4. No other tenant role can list, read, modify, or hold that version.
5. A full destination inventory through the recorded cutoff contains no delete
   markers and no key/`VersionId` pair absent from the source namespace.
6. Replication failure and latency alarms reach the confirmed operations target.

Also inspect the exact authoritative promotion item and its matching ordered
change item, independently verify the RSA-PSS/SHA-256 signature with the audit
KMS public key, and confirm the signed `uploadedAt`, bucket, key, `VersionId`,
checksum, retention, and source-version facts match both exact S3 heads. Apply
and remove a legal hold through the approved two-person workflow. Confirm the
KMS-signed audit receipt commits and verifies before its audit-bound recovery
change appears, then confirm the Aurora publication acknowledgement clears the
outbox. Inject a failure after audit commit and another after DynamoDB commit;
both retries must reuse the exact signed event and converge without a second
ledger change. Wait through the safety-lag
window for the periodic generation to advance `verifiedThrough`. Negative tests
must prove the tenant API role cannot read or write either recovery partition,
the reconciler cannot write the authoritative partition, and the legal-hold
worker cannot write the ordinary tenant partition.

Also write a non-sensitive control-plane canary in the primary region, read it
strongly from the recovery replica, and prove TTL/PITR/GSI configuration and
tenant-leading-key IAM constraints in both regions. Do not use the global table
as automatic application failover: API, Aurora, secrets, KMS grants, routing,
and restored-resource wiring still require an approved cutover procedure.

Run an Aurora restore drill at least quarterly. Restore into isolated subnets
with no customer routing, use a new secret, and deny application roles until
validation finishes. Check schema migrations, tenant identity, forced RLS,
role ownership, memberships, upload/evidence revisions, ingest and audit
receipts, hash-chain continuity, retention holds, and cross-tenant negative
queries. Record recovery-point ARN, timestamps, RTO/RPO, approvers, evidence
checksums, and secure teardown. Never test a destructive failover against the
only production copy.

## Production macOS release prerequisites

The production workflow produces arm64 artifacts for macOS 14 or later. Before
it can succeed, commit reviewed values to
`macos/ScopeproofCapture/Resources/Info.plist`:

- the real `ScopeproofUpdateTeamIdentifier`;
- a designated requirement binding Apple trust, bundle ID
  `com.scopeproof.capture`, and that team;
- at least one offline update-signing public key and stable key ID;
- one exact HTTPS `ScopeproofUpdateDownloadOrigin`, normally
  `https://downloads.<owned-domain>`, with no path, port, query, or fragment;
- the intended `CFBundleShortVersionString`; and
- a monotonically increasing `CFBundleVersion`.

Keep the update private key offline. It is not the Developer ID certificate and
must not be stored in GitHub Actions.

Create a protected GitHub environment named `production-release` with required
reviewers, protected `main` access, and no self-approval. Configure:

The repository environment created on 2026-09-01 is an interim fail-closed
release gate: it allows protected branches only, requires an explicit owner
approval, and disables administrator bypass. The repository currently has no
second collaborator, so self-approval cannot yet be disabled without making the
only release approver ineligible. This interim gate is **not** two-person
production authorization. Add a second trusted release reviewer, then set
`prevent_self_review` to true before the first production release.

| Name | Type | Purpose |
| --- | --- | --- |
| `MACOS_DEVELOPER_ID_P12_BASE64` | environment secret | Base64 Developer ID Application certificate and private key |
| `MACOS_DEVELOPER_ID_P12_PASSWORD` | environment secret | P12 password |
| `MACOS_NOTARY_API_KEY_P8_BASE64` | environment secret | Base64 App Store Connect API private key |
| `MACOS_NOTARY_KEY_ID` | environment secret | Exact ten-character API key ID |
| `MACOS_NOTARY_ISSUER_ID` | environment secret | App Store Connect issuer UUID |
| `MACOS_RELEASE_TEAM_ID` | environment secret | Exact ten-character Apple team ID |

Use a narrowly scoped App Store Connect key that can notarize this application.
Rotate any credential exposed in logs or copied outside the protected secret
store.

## Run a protected production release

1. Merge the reviewed version, build number, public update key, and designated
   requirement to `main`.
2. Record the full 40-character commit SHA after required checks pass.
3. Open **Actions → macOS production release candidate → Run workflow**.
4. Enter the exact version, build number, and approved commit SHA.
5. Approve the protected environment deployment with the required second person.

The workflow refuses non-`main` refs, mismatched commits, dirty source, malformed
versions, missing trust metadata, multiple Developer ID identities, or missing
credentials. It uses a fresh Swift scratch directory and ephemeral Keychain,
builds arm64 without disabling the Swift sandbox, explicitly signs the app with
hardened runtime and a trusted timestamp, and validates team, identifier,
designated requirement, architecture, entitlements, and version.

The script submits the app archive to Apple, requires exact JSON status
`Accepted` within 30 minutes, staples and validates the app, and requires
Gatekeeper acceptance. It then creates and signs the DMG, repeats notarization,
stapling, Gatekeeper, `hdiutil verify`, mount, inner-app signature, designated
requirement, and ticket checks. It refuses to overwrite artifacts and emits
SHA-256 files for both ZIP and DMG, a CycloneDX SBOM for the dependency-free
Swift package plus its macOS SQLite system-library dependency, an in-toto/SLSA
provenance statement binding the exact commit and candidate digests, and a
redacted Apple receipt containing only artifact kind, submission ID, and
`Accepted` status.

Signing and notarization credentials are destroyed before provenance or artifact
actions run. The workflow attests and uploads only the seven expected release
outputs for 30 days: ZIP, DMG, their checksum sidecars, SBOM, provenance, and
redacted receipt. It does not upload the raw notarization JSON, P12, P8,
Keychain, logs, temp directory, or broad `DerivedData` tree. Publishing remains
a separate, explicitly approved promotion.

Download the named artifact from the approved workflow run without flattening or
renaming it. Set `SCOPEPROOF_RELEASE_CANDIDATE_DIR`,
`SCOPEPROOF_RELEASE_ATTESTATION_REPOSITORY`, and the approved full commit in
`SCOPEPROOF_RELEASE_EXPECTED_COMMIT`, then provide the offline update-signing and
release-manifest variables and run `./Scripts/publish_release.sh` on macOS. The
publication script never invokes a build or creates a replacement ZIP. Before
the first trust decision it snapshots all seven regular, non-symlink inputs into
a private mode-`0700` temporary directory; every subsequent attestation, digest,
notarization, bundle, and signing check reads only that snapshot. It checks
GitHub attestations for all seven files, checksum/SBOM/provenance agreement,
both accepted Apple submissions, archive paths, Developer ID identity,
hardened runtime, trusted timestamp, stapled tickets, Gatekeeper, and the mounted
DMG before signing an update envelope over the exact downloaded ZIP. The final
URL must equal the origin compiled into that candidate plus
`/macos/<version>/Scopeproof-Capture-<version>.zip`; redirecting or mutable
GitHub release URLs are rejected. Publish only that verified ZIP and its
matching envelope. A locally rebuilt or re-archived ZIP is a different
candidate and must be rejected.

The Mac never trusts the manifest URL as a free-form redirect target. It derives
the immutable versioned path from the compiled origin, verifies the downloaded
app's bundle identifier and version against the signed manifest, and stores the
last accepted `(sequence, version, SHA-256)` tuple in a device-only Keychain
item. A lower sequence, or the same sequence with a different version or digest,
fails closed. Existing sequence-only Keychain state is treated as a rollback
floor during migration and cannot authorize a different release at that same
sequence.

For a controlled local signing workstation, first create a dedicated Keychain,
place the App Store Connect P8 outside the repository with mode `0600`, and run:

```bash
SCOPEPROOF_NOTARY_PROFILE=scopeproof-production \
SCOPEPROOF_NOTARY_KEYCHAIN=/absolute/path/scopeproof-release.keychain-db \
SCOPEPROOF_NOTARY_API_KEY_PATH=/absolute/path/AuthKey_EXAMPLE.p8 \
SCOPEPROOF_NOTARY_KEY_ID=ABCDEFGHIJ \
SCOPEPROOF_NOTARY_ISSUER_ID=00000000-0000-0000-0000-000000000000 \
./Scripts/configure_macos_notary_profile.sh
```

Then export the required release variables and run
`./Scripts/build_macos_production_release.sh` from a clean committed worktree.
The script never accepts ad-hoc signing as a production fallback.

## Manual Swift CodeQL

`.github/workflows/codeql-swift.yml` is the repository's complete advanced
CodeQL workflow. It preserves JavaScript, TypeScript, and GitHub Actions
coverage with no-build analysis on Linux, and initializes Swift with
`build-mode: manual` before running the real arm64 Swift build on `macos-15`.
Every language uses the `security-extended` query suite. GitHub actions are
pinned to immutable commit SHAs and checkout credentials are not persisted.

GitHub default setup was disabled on 2026-08-27 after the advanced workflow was
opened in the pull request, because default setup rejects custom CodeQL result
uploads. The replacement workflow is now present on `main`, and its Swift,
JavaScript/TypeScript, and Actions jobs are required branch checks alongside
`verify`, `macos`, and `dependency-review`. Confirm the CodeQL tool-status page
shows current coverage for each language after any workflow or branch-
protection change. Existing alerts were preserved by GitHub during the setup
transition.

## Known external dependencies

This repository cannot supply or validate the Apple team, Developer ID identity,
App Store Connect key, protected-environment reviewers, offline update-signing
key, AWS account, destination region, DNS domain, alert subscription, or deployed
restore result. No workflow in this work submitted an artifact to Apple, and no
AWS backfill, replica verification, Aurora restore, control-table migration, or
regional cutover was executed. Those are deliberate operator-controlled gates,
not values to replace with placeholders in production.
