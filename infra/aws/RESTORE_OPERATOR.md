# Isolated cross-region restore operator

The source provides a real AWS SDK/AWS CLI orchestration path. No AWS call,
restore, IAM change or DNS cutover was performed during its development.

`cdk/runtime/restore-operator/index.mjs` runs locally with Node 22+, the pinned
CDK dependencies and AWS CLI v2. It is deliberately not a customer Lambda.
It has five explicit modes:

```text
node infra/aws/cdk/runtime/restore-operator/index.mjs plan config.json inventory.json
node infra/aws/cdk/runtime/restore-operator/index.mjs verify plan.json inventory-signature.json
node infra/aws/cdk/runtime/restore-operator/index.mjs start plan.json inventory-signature.json approval.json ACCEPTED_PLAN_DIGEST
node infra/aws/cdk/runtime/restore-operator/index.mjs attach plan.json inventory-signature.json RESTORE_JOB_ID writer-approval.json ACCEPTED_PLAN_DIGEST
node infra/aws/cdk/runtime/restore-operator/index.mjs receipt plan.json inventory-signature.json RESTORE_JOB_ID
```

`plan` is offline and creates no SDK clients. Output goes to stdout; the operator
reviews and saves each JSON artifact. `verify` is read-only against AWS. `start`
has exactly one write: AWS Backup StartRestoreJob. `attach` separately approves
the exact private writer instance. `receipt` is read-only and never authorizes
cutover. No Route 53, deletion, overwrite or public-network operation exists.

## Reviewed configuration and prerequisite authority

The exact versioned schema is enforced in `contract.mjs`: account, primary and
recovery regions, source cluster, copied recovery point, vault/key, restore
service role, operator role, distinct inventory-signing and approval keys,
isolated target cluster/subnet group/VPC/security groups, approved writer class,
tenant IDs, exact destination bucket/prefix/key mappings and recovery age.
There are no inferred infrastructure identifiers or production defaults. Target
names must start `scopeproof-restore-`; security groups must have no ingress or
egress, and subnet membership must match the exact reviewed private VPC in two
AZs. The primary region is currently us-east-1; supported drill destinations are
other US commercial east/west regions.

Before execution a platform security operator must separately provision and
review the configured roles/network/keys. This tool does not grant itself
permissions. The operator role needs read-only recovery-point/job inspection,
exact-version S3 reads/hold/retention inspection, bucket-location reads, exact
KMS Verify on the two signing keys, RDS/EC2 network/target inspection, bounded
StartRestoreJob, PassRole only to the exact Backup restore service role with
`iam:PassedToService=backup.amazonaws.com`, and CreateDBInstance only for the
reviewed target writer. It needs no Secrets Manager, customer SQL, KMS Sign,
Route 53, bucket mutation or delete permissions. The Backup service role must
be separately scoped to restoring the exact recovery point into the isolated
target and using only its approved encryption key. Do not reuse tenant roles
or the central database bootstrap administrator.

Only independent approvers receive KMS Sign for the approval ECC_NIST_P256 key;
the inventory publisher signs with a different key. The operator has Verify
only. These IAM/key-policy prerequisite boundaries are not yet provisioned by
this local CLI and require release review; config-file edit authority is trusted
platform authority, not a customer input.

## Signed inventory and approvals

The inventory binds exact tenant IDs, source cluster and copied recovery point,
a recent inventory timestamp, and every reviewed artifact's bucket, key,
version, SHA-256, size, COMPLIANCE retention and legal-hold state. It must include
CloudTrail logs/digests plus immutable completeness and CloudTrail-validation
receipts and their hashes. The inventoried set must be produced from an
independently reconciled control/evidence ledger. Listing a few files is not
proof of completeness. Zero-evidence tenants remain in the signed tenant set.

The operator re-downloads every exact version and verifies bytes, size, bucket
region, expected owner, KMS key, retention and legal hold. This implementation
verifies the signed inventory and receipt bytes; it does **not** implement the
CloudTrail RSA digest-chain algorithm or itself prove inventory completeness.
The trusted inventory publisher must verify the source CloudTrail chain with
AWS's validation tooling and reconcile the complete evidence/control ledger
before signing. These are explicit prerequisites, not fabricated successful
checks. Receipt objects require an approved immutable publication path.

Sign SHA-256 of UTF-8 `scopeproof-recovery-inventory-v1\n` plus canonical inventory
JSON, using KMS ECDSA_SHA_256 and MessageType DIGEST. Supply base64 signature in
`{"signature":"..."}`. Canonicalization is exported from `contract.mjs`.
Inventory freshness is one hour; longer drills require reviewed renewed
inventory/plan and a new phase approval before proceeding.

An approval has exactly schemaVersion 1, decision APPROVED, phase START_CLUSTER
or ATTACH_WRITER, planDigest, operatorRoleArn, approvedAt, expiresAt and base64
signature. Sign SHA-256 of `scopeproof-recovery-approval-v1\n` plus canonical JSON
of all fields except signature with the separate approval key, ECDSA_SHA_256 /
DIGEST. Approval lasts at most fifteen minutes. The operator must also type the
accepted plan digest. A writer approval cannot start a cluster and vice versa.

## Progress, recovery and limits

The plan digest is the Backup idempotency token. After an uncertain submission,
reconcile the original job/token; do not invent a new plan to bypass an existing
target. Start refuses existing clusters. Each subsequent phase rechecks exact
artifacts/network and the completed job's source, service role and target ARN.
Writer attachment refuses a cluster that already has members. If attachment
times out, inspect the exact named writer and use receipt verification; never
blindly create another instance. Nothing is automatically deleted on failure.

The final digest-bound receipt says ISOLATED_INFRASTRUCTURE_RESTORED and
cutoverAuthorized false. It is not cryptographically signed, not customer-ready,
and not a substitute for database schema/tenant/session reconciliation,
evidence/audit application reconciliation and independent acceptance. Enabling
network/Data API access and any cutover require separate reviewed source work
and explicit authority. Current tests cover contracts and mutation ordering
using fake AWS adapters, not AWS permissions, a real recovery job or RTO/RPO.

AWS Backup restores the Aurora cluster but does not attach its writer; hence
the distinct writer phase. API metadata follows the official
[Aurora restore guide](https://docs.aws.amazon.com/aws-backup/latest/devguide/restoring-aur.html).
