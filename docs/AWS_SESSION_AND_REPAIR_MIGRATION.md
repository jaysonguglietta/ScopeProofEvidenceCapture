# AWS session and projection repair migration

This source change is not a deployment or a passed customer-readiness gate. Apply and validate in an isolated non-customer environment first.

## Forward migration

`010_session_and_repair_security.sql` introduces schema version 4;
`011_customer_runtime.sql` advances to schema/owner version 5 and bundle v7.
Provisioning and the SQL renderer install the same exact forward sequence,
recompile functions, reapply operation-specific grants and verify the catalog.
Upgrades accept only exact reviewed v4/v5/v6 bundle fingerprints and matching
live catalog attestations. Modified or unattested databases fail closed.
Interrupted older installations require reviewed recovery, never a forced
marker rewrite. See [Database bootstrap](../infra/aws/DATABASE_BOOTSTRAP.md).

## Resource-server revocation

Authenticated clients POST an exact empty JSON object to `/v1/sessions/revoke` with `scopeproof/evidence.read`, or `/v1/collector/sessions/revoke` with `scopeproof/evidence.collect`. These routes bind the verified Cognito subject and `auth_time`; no actor, timestamp, epoch, or tenant body fields are accepted. The transaction advances the principal's durable session epoch and revocation cutoff, and appends `session.all_revoked` to the immutable audit outbox atomically. The response returns the committed epoch/cutoff. Clear client credentials even after an ambiguous response; the old token is rejected on the next membership lookup.

Every AWS resource-server membership lookup now requires `auth_time` strictly later than the principal cutoff. A refreshed token with an older original authentication time stays revoked. Cutoffs use whole seconds because Cognito authentication claims are second-granularity; reauthentication in the same second is conservatively rejected. Already-authorized concurrent requests and previously issued S3 capabilities are not recalled. Revocation is per tenant; this does not automatically mirror Cognito console global sign-out or identity-provider revocation into every tenant. Identity incident tooling must call the owner-only compare-and-swap `advance_session_epoch(principal_id, expected_epoch, reason)` in the appropriate tenant transaction and retain the operator change record. Cognito refresh-token revocation should accompany application sign-out. User-interface sign-out wiring is separate from these endpoints.

## Delayed repair boundary

Public issuance retains its fresh device-proof check. An exact already-committed SQL replay is compared before proof freshness. The scheduled worker uses `repair_upload_intent` through the ingest identity, never the public upload identity. It strongly reads the immutable Dynamo lifecycle facts, verifies the canonical evidence projection digest, and binds repair freshness to the original reservation timestamp. Repair is limited to 14 days and never extends an upload URL or emits a new capability. The original actor/device/scope, equality, retention, and sequence checks remain; revoked membership/device, closed scope, out-of-order sequence conflicts, or an expired repair horizon require explicit operator reconciliation, not a bypass.

One poison row no longer prevents later rows or the durable cursor from progressing. Failed rows receive exponential backoff and become `ACTION_REQUIRED` after eight attempts; the invocation signals failure only after saving its cursor. Inspect the exact tenant/upload IDs and failure state through approved operational tooling. Requeue only after resolving the cause, by clearing the repair backoff/status on that exact row under a conditional write; never modify immutable lifecycle or projection facts. No repair administration UI is included. A late public HTTP retry can still fail its device-manifest freshness check; recovery is the separate worker, not an HTTP freshness exemption.

## Validation

Run `npm test` and the CDK tests (both now include `.mjs`). Embedded PostgreSQL
tests execute the real rendered bundle/functions, restricted grants, invitation,
device-proof, immutable scope, independent review, revocation and isolation
behavior without AWS credentials. The opt-in external PostgreSQL harness uses
`SCOPEPROOF_TEST_PG_URL` only for a permitted disposable local `scopeproof_test_*`
database. Never point it at shared/customer data; absence is a reported skip.
PGlite is real PostgreSQL execution, not Aurora/Data API, live Cognito, deployed
IAM or Dynamo/S3 integration. Qualify those separately before release.
