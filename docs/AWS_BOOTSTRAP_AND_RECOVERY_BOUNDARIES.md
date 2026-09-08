# Database bootstrap and recovery boundaries

This describes development source. No AWS deployment, restore, DNS change or
customer activation was performed. These implementation-state notes supersede
the historical review's state, not its release gates.

## Separate privileged bootstrap

Tenant workers no longer receive the shared cluster administrator secret.
Their mapped tenant-specific login is NOCREATEDB, NOCREATEROLE, NOINHERIT,
NOSUPERUSER and NOBYPASSRLS, with non-delegable SET membership in its own NOLOGIN
owner only. Grant migrations contain no cluster-level ALTER ROLE. Tenant workers
cannot start the central workflow or choose databases/secrets/roles from input.

The central workflow has distinct operator/approver identities, immutable
deployment mappings, execution-bound expiring approval, exact identity/grant
checks and a durable PREPARED receipt. Only this separately operated workflow
retrieves the shared administrator secret; it has no public API. See
[Database bootstrap](../infra/aws/DATABASE_BOOTSTRAP.md) for the offline planner,
approval, interrupted-run and role-nomination rules.

Local real PostgreSQL tests execute the actual restricted-login installation
and grants. Application logins are execute-only; tests deny protected reads
and privileged functions. Synthetic A/B roles cannot assume or delegate the
other's ownership. This does not prove Aurora cross-database CONNECT, Data API,
deployed IAM or Secrets Manager isolation. Qualify two disposable tenants there.

## Immutable SQL lineage

Forward 010/011 introduce session/repair and customer workflows. The installer
uses schema/owner version 5 and bundle v7, accepting only exact reviewed earlier
fingerprints and attested catalogs. Historical 001 remains unchanged. A helper
checks its exact SHA-256 and defers checking its known-invalid function bodies
only inside the baseline transaction. Forward 011 corrects them; every function
is recompiled with checking enabled before grants. Both production installer and
offline renderer share this sequence. Never disable validation globally, rewrite
history, edit an attestation marker or grandfather an unknown catalog.

## Cross-region audit durability

Recovery templates configure KMS-encrypted, versioned, COMPLIANCE-locked
destinations and live replication for CloudTrail logs/digest files. The original
source bucket name is preserved; replication/KMS authority uses reviewed exact
boundaries. Synthesis does not prove historical backfill or digest-chain validity.

Independently reconcile existing-version backfill, retain its zero-failure
report, verify bytes/version/checksum/KMS/hold/retention and validate the entire
CloudTrail recovery window. Same-account replication does not isolate a
compromised account administrator.

## Restore and separately approved cutover

[Restore operator](../infra/aws/RESTORE_OPERATOR.md) implements offline planning,
signed inventory verification, independently approved cluster restore, a
separate private-writer approval and an isolated-infrastructure receipt. It
verifies every inventoried exact-version object's bytes and retention and denies
public/permissive recovery networks. Inventory completeness and CloudTrail
chain validity remain independently verified publisher prerequisites, not
algorithms implemented by this CLI. The tool does not enable customer traffic.

[Cutover operator](../infra/aws/CUTOVER_OPERATOR.md) separately requires signed
application acceptance, primary-write-fence evidence and independent short-lived
DNS approval. It submits one exact-preimage DELETE/CREATE transaction and checks
INSYNC/target state. No blind UPSERT, automatic uncertain-mutation retry or rollback.

Fake-adapter tests cover ordering, tamper, drift and approval expiry. These tools
do not deploy recovery API/auth/frontend, reconcile restored application/control
state, fence primary writers, provision prerequisite operator IAM or measure
RPO/RTO. Those remain engineering/operational prerequisites. Do not sign
acceptance based solely on source tests.
