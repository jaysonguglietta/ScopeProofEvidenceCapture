# Operator-approved database bootstrap

This is source implementation, not a deployed or live-Aurora-validated service.

## Authority split

The tenant stack holds a new tenant-specific provisioning secret. That login is
NOCREATEDB, NOCREATEROLE, NOINHERIT, NOSUPERUSER and NOBYPASSRLS. It has CONNECT
only to its own database and non-delegable SET membership in its own NOLOGIN
database-owner role (`ADMIN FALSE, INHERIT FALSE, SET TRUE`). The tenant worker
cannot read the shared administrator secret or invoke the central workflow.
Grant migrations no longer contain cluster-level ALTER ROLE operations.

`DatabaseBootstrapStack` alone holds shared administrator-secret access. It has
no customer API, Lambda URL or schedule. A platform operator role can start its
Standard workflow but cannot approve. A distinct approver role can publish a
short-lived approval but cannot start the workflow. The deployment publishes
immutable tenant/revision mappings; an existing revision cannot be changed.
An approval binds the exact mapping digest and full execution ARN. It is valid
for at most fifteen minutes. Unknown fields, account/region drift, reused
identities, foreign CONNECT privileges or unexpected role memberships fail
closed. Administrator membership in the tenant owner is temporary and revoked
in a finally block. A durable exact-mapping PREPARED receipt is required by the
tenant worker before migration, verification or activation.

## Operator workflow

1. Review the compiled tenant identity, database, seven role/secret mappings and
   mapping revision. Synthesis with tenants now requires explicit, distinct
   `databaseBootstrapOperatorPrincipalArn` and
   `databaseBootstrapApproverPrincipalArn` context values. These must name
   reviewed platform operator identities, never customer/runtime roles.
2. Deploy only through the separately approved platform release process. This
   change does not authorize deployment. Read the exact `mappingJson` from the
   stack's mapping-table output using the operator role; save it locally.
3. Run the read-only planner:
   `node Scripts/plan_aws_database_bootstrap.mjs mapping.json unique-execution-name <BootstrapApproverRoleArn>`.
   Independently review the digest, all mapped resources and execution name.
4. Using the separate approver role, conditionally PutItem the emitted
   `approvalItem` in the approval-table output (`attribute_not_exists(PK)`).
   Using the operator role, StartExecution with the emitted request before
   expiry. Neither role receives secret access or Data API privileges.
5. After PREPARED, use the existing tenant provisioning workflow. This worker
   verifies actual role flags, exact membership and foreign CONNECT denial.
   An old database with unexpected grants is blocked for platform review.

No planner command contacts AWS. The central execution uses the mapped secret's
current credential version; approval does not pin a Secrets Manager version.
Role/password changes are central operator actions. An interrupted run can
leave its own newly-created roles/database and fail-closed tenant state; review
and reapprove an exact-mapping retry. There is no automatic delete or cleanup.

## Immutable SQL lineage

Historical `001_tenant_schema.sql` is preserved byte-for-byte. PostgreSQL
compilation exposed invalid historical PL/pgSQL function bodies. The shared
`database/bootstrap-baseline.mjs` helper accepts only SHA-256
`be0798f20decabb911f0187c8ee499b5277b313500658d4bce99a935724785df`
and defers function body checking only in that baseline transaction. Production
provisioning must install the correcting forward migration and recompile every
installed Scopeproof function with checking enabled before granting application
access. The correcting `011_customer_runtime.sql` migration is now included in
both the production installer and SQL renderer. A real embedded PostgreSQL test
executes the rendered bundle, recompiles every function and checks installed
function/trigger inventories and execute-only grants. This is not an Aurora
Data API integration test. Do not disable checking globally or rewrite
historical SQL in tests.

Customer schema/grant changes create bundle v7 and owner version5. Upgrades accept only exact reviewed v4/v5/v6
fingerprints and first compare the live catalog to its stored attestation.
Unknown prior hashes are never accepted by prefix alone.

The manual `Scripts/render_aws_tenant_sql.mjs` bootstrap renderer now requires
`--api-audit-role` as well as its prior role arguments, includes the audit-signer
grants and uses the same exact historical transform/011/revalidation order.
Create the restricted mapped logins with the approved central workflow first;
the renderer contains no role or database creation authority. Never run it
against an existing database as an unreviewed migration replacement.

## Verification and release gates

The PGlite test exercises real PostgreSQL non-delegable role membership and
cross-schema denial with two synthetic tenants. The CDK tests synthesize IAM,
immutable mapping publication and operator/approver separation. These do not
prove Aurora Data API behavior, cross-database CONNECT, secret/KMS permissions,
or an interruption drill. Before production, validate those boundaries against
two disposable Aurora databases, explicitly deny tenant access to the other
tenant and administrator secrets, and exercise approval expiry/replay, worker
failure and non-production migration/activation. No such AWS validation or
deployment was performed for this patch.
