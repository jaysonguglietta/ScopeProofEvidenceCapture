# Scopeproof AWS CDK platform

This directory contains a synthable AWS foundation for a hosted Scopeproof
evidence portal. It includes a small production-shaped per-tenant API Gateway/
Lambda, strict tenant/JWT/membership adapters, an idempotent upload-intent route
with DynamoDB/Aurora reconciliation, a durable public-API audit outbox and
bounded KMS signer, KMS-signed audit/promotion receipts,
CDK-wired two-person exact-version legal-hold routes/worker, a cross-region recovery topology
with existing-version backfill, and a protected macOS release workflow. It still
does **not** contain the complete customer web product, membership-administration
UI or complete membership/administration workflows. Nothing in this work was deployed to
AWS or submitted to Apple; a successful synthesis or future CDK deployment is
not a production-ready hosted service until the release gates below are closed.

## Product brief

- **Users:** compliance teams, customer reviewers, auditors, and Scopeproof operators.
- **Problem:** isolate each customer's portal and evidence without host discovery, cross-tenant access, unscanned promotion, or retention bypass.
- **Primary workflows:** provision a tenant, authenticate on its exact host, issue a one-time upload, quarantine/scan/promote evidence, browse authorized versions, and process jobs.
- **Views still to migrate:** sign-in, evidence browser, capture/upload, job status, membership administration, and operator tenant lifecycle management.
- **Core models:** opaque tenant, exact domain, membership, upload lifecycle, immutable evidence version/receipt, job, audit event/head, and retention policy.
- **Edge cases:** replay/duplicate/expired uploads, slow scans, unknown hosts, partial schemas, failed DNS, poison messages, KMS denial, and Object Lock conflicts.
- **Assumptions:** `us-east-1`, an owned Route 53 domain, Amplify Hosting compute, and authoritative host-plus-membership authorization on every request.
- **Done here:** shared/tenant/audit stacks, fail-closed provisioning, DNS-last activation, a tenant-specific API/custom domain with API Gateway mock health plus authenticated identity/upload-intent routes, immutable S3 boundaries, an active exact-intent GuardDuty promotion path, upload reconciliation, durable KMS-signed API auditing, two-person legal-hold persistence procedures, split API/runtime/ingest/evidence-control roles, WAF, CloudTrail data events, encrypted alerting/logs, budgets, release distribution, SES identity, and an explicit two-phase cross-region recovery foundation with a global control table and existing-version backfill/verifier.

## Implemented architecture

| Boundary | AWS resources | Design choice |
| --- | --- | --- |
| Web/API edge | Route 53, Amplify, regional API Gateway/WAF | Exact UI mappings plus one `api-<tenant>` Alias and authenticated Lambda per tenant; unauthenticated health is an API Gateway mock; default execute-api endpoint disabled; tenant CNAME only after database verification. |
| Releases | private versioned S3, CloudFront OAC/WAF, ACM | `downloads.<domain>`, TLS 1.2+, security headers and access logs. |
| Identity | Cognito, one public client per tenant | Required TOTP, authorization code, exact redirects, no self-registration. |
| Control | DynamoDB on-demand global table | Direct tenant/domain keys, PITR/deletion protection, upload lifecycle/receipts, and an enabled recovery-region replica. |
| Metadata | Aurora PostgreSQL 16 Serverless v2, Data API | Isolated/no-NAT network, auto-pause, database-per-tenant, FORCE RLS. |
| Provisioning | Step Functions, Lambda, Secrets Manager, Route 53 | Lease/initialize/verify/activate/fail states; schema and DNS precede `ACTIVE`. |
| Evidence | quarantine/evidence S3, KMS, GuardDuty, SQS/DLQ, Lambda | 25 MiB intent contract; only promoter writes Object-Locked evidence. |
| Audit/ops | Aurora outbox/hash chain, asymmetric KMS, Lambda/EventBridge/DLQ, CloudTrail, Object-Locked S3, CloudWatch, SNS | Exact application-action receipts plus tenant S3 data events, bounded retries, persistent poison-row alarms, denial/root metrics, and DLQ/job/database alarms. |
| Recovery | S3 CRR/RTC/Batch Operations, exact verifier, destination KMS/Object Lock, AWS Backup/Vault Lock | Live and pre-existing exact tenant versions plus daily Aurora recovery points; destination resources are bootstrapped before source replication is enabled. |
| Cost/email | Budgets, Cost Anomaly Detection, SES/DKIM | USD 100 default budget; optional email notifications; identity only. |

The design avoids always-on containers, load balancers, NAT gateways, and provisioned DynamoDB. Route 53, WAF, CloudFront, KMS, Secrets Manager, GuardDuty, logs, S3, Amplify, Cognito, Aurora, CloudTrail, and backups remain billable.

The dormant Amplify build specification uses `npm ci --ignore-scripts --cache .npm --prefer-offline`, keeps npm data under the workspace `.npm` cache, and then runs `npm run build`. This reduces lifecycle-script and home-cache exposure, but it does not make the current UI deployable: the Amplify app has no repository/source connection, its branch has automatic builds disabled, and no AWS web release has run.

## Layout and validation

```text
bin/scopeproof.ts                  context validation and stack assembly
lib/shared-platform-stack.ts       identity, DB, Amplify/WAF, releases, alerts/cost
lib/tenant-stack.ts                tenant data, GuardDuty, queues, provisioning/promotion
lib/observability-stack.ts         immutable CloudTrail and security alarms
lib/recovery-config.ts             fail-closed recovery context validation/names
lib/recovery-stack.ts              destination-region vault, keys, locked replicas
lib/recovery-support.ts            source backup, live replication, Batch backfill/verifier
runtime/provision-tenant/index.mjs fail-closed database and DNS worker
runtime/promote-evidence/index.mjs intent-bound immutable evidence promoter
runtime/reconcile-recovery/*       durable Batch backfill and exact-version verifier
runtime/tenant-api/index.ts        authenticated JWT/membership/upload-intent Lambda
runtime/tenant-evidence-read-api/* isolated evidence search/exact-version-download Lambda
runtime/tenant-legal-hold-api/*    separate authenticated request/approval Lambda
runtime/reconcile-legal-holds/*    scheduled approved-only S3/KMS audit worker
runtime/sign-api-audit-outbox/*   bounded retry-safe public-API KMS signer
test/foundation.test.ts            template and runtime-contract guardrails
../database/001_tenant_schema.sql  authoritative schema/RLS migration
../database/002_runtime_role.sql   authoritative least-privilege runtime grants
../database/003_ingest_role.sql    execute-only promotion-reconciliation grants
../database/004_evidence_control_role.sql execute-only audit/legal-hold grants
../database/005_legal_hold_api_role.sql execute-only request/approval grants
../database/006_evidence_access_api.sql tenant-authorized list/exact-read procedures
../database/007_evidence_read_role.sql execute-only evidence-read grants
../database/008_api_audit_signer_role.sql execute-only audit-outbox signer grants
../../../lib/aws-runtime/http      exact-host, JWT, membership, and API adapters
../../../lib/aws-runtime/evidence  upload, receipt, reconciliation, and hold adapters
```

Use Node.js 22+ and pnpm. Install and test first; the final command performs a local synthesis only and does not deploy. The checked-in context intentionally has no domain, so even local synthesis must receive an explicit owned/example domain and exactly one Route 53 mode:

```bash
cd infra/aws/cdk
pnpm install --frozen-lockfile
pnpm run build
pnpm test
pnpm run synth \
  -c deploymentEnvironment=dev \
  -c rootDomain=evidence.example.com \
  -c hostedZoneId=Z0123456789EXAMPLE \
  -c 'recovery={"mode":"disabled"}' \
  -c 'tenants=[]'
```

Production-shaped baseline synthesis requires an explicit account and region. Production intentionally refuses `recovery.mode=disabled`; use the two-phase recovery procedure below.

> **Existing deployment stop:** `ControlPlaneTable` now synthesizes as
> `AWS::DynamoDB::GlobalTable`. Never deploy that resource-type change directly
> over an older stack that owns it as `AWS::DynamoDB::Table`. Freeze writes,
> verify PITR plus an independent backup/export, retain and remove the physical
> table from the old template, convert/add the replica using an approved DynamoDB
> procedure, import the exact table under the new global-table logical resource,
> then reconcile all items/indexes/TTL/PITR/IAM and test recovery. Rehearse the
> change in a disposable account. Fresh deployments are unaffected. Follow the
> [platform runbook](../../../docs/AWS_PLATFORM_RUNBOOK.md#existing-control-table-migration-stop),
> not an improvised replacement or dual-write.

## Cross-region recovery

The recovery architecture is intentionally same-account, cross-region. It protects against a regional loss and accidental primary-resource deletion, but it is **not** an account-compromise boundary. Organizations that require that boundary should move the destination stack into a separately controlled recovery account after adding and testing exact cross-account key, vault, bucket, and role policies.

Recovery is configured in two phases so CDK never guesses KMS key ARNs and never grants wildcard destination access:

1. Set `mode=bootstrap` and synthesize/diff/deploy only `ScopeproofRecovery` in the destination region. This creates a customer-managed backup-vault key, a Vault-Locked backup vault, and one KMS-encrypted, versioned, Object-Locked replica bucket per tenant. Record the exact output ARNs and bucket names; confirm the SNS email subscription before relying on notifications.
2. Change the same reviewed context to `mode=enabled`, copying the exact destination vault-key ARN and each exact tenant bucket/key output into the context. Synth/diff all stacks. Deploy the recovery stack first, the shared stack second, tenant stacks third, and observability last. The source then receives the recovery-region DynamoDB replica, daily Aurora backup/copy plan, exact-prefix live S3 replication, S3 Batch existing-version role/report bucket, and a 15-minute reconciliation Lambda.

Example bootstrap context (placeholders only; never put credentials in CDK context):

```bash
export CDK_DEFAULT_ACCOUNT=123456789012
export CDK_DEFAULT_REGION=us-east-1
pnpm exec cdk synth ScopeproofRecovery \
  -c deploymentEnvironment=prod \
  -c rootDomain=evidence.example.com \
  -c hostedZoneId=Z0123456789EXAMPLE \
  -c alertEmail=security@example.com \
  -c 'tenants=[{"id":"ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","slug":"acme","displayName":"Acme Corporation","retentionDays":365,"retentionMode":"COMPLIANCE"}]' \
  -c 'recovery={"mode":"bootstrap","region":"us-west-2","vaultLockMode":"COMPLIANCE","vaultLockChangeableDays":7,"auroraLocalRetentionDays":35,"auroraCopyRetentionDays":365,"s3ReplicationTimeControl":true}'
```

After the reviewed bootstrap deployment returns the exact keys, enable the primary resources with output values in place of these examples:

```bash
pnpm exec cdk synth --all \
  -c deploymentEnvironment=prod \
  -c rootDomain=evidence.example.com \
  -c hostedZoneId=Z0123456789EXAMPLE \
  -c alertEmail=security@example.com \
  -c 'tenants=[{"id":"ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","slug":"acme","displayName":"Acme Corporation","retentionDays":365,"retentionMode":"COMPLIANCE"}]' \
  -c 'recovery={"mode":"enabled","region":"us-west-2","vaultLockMode":"COMPLIANCE","vaultLockChangeableDays":7,"auroraLocalRetentionDays":35,"auroraCopyRetentionDays":365,"s3ReplicationTimeControl":true,"backupVaultKeyArn":"arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111","evidenceDestinations":[{"tenantId":"ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bucketName":"sp-r-123456789012-uswest2-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","kmsKeyArn":"arn:aws:kms:us-west-2:123456789012:key/22222222-2222-4222-8222-222222222222"}]}'
```

Run `cdk diff` with the identical context and obtain approval before any deploy. Production validation requires a distinct region, COMPLIANCE Vault Lock with a 7–30 day cooling-off period, at least 365 days of Aurora-copy retention, S3 Replication Time Control, an exact destination for every tenant, and exact same-account destination key ARNs. The COMPLIANCE lock becomes immutable after its cooling-off period. Never bootstrap it casually.

Primary evidence bucket names are deterministic from account, region, and opaque tenant ID so enabling recovery does not replace a generated-name bucket. Live replication includes only `tenants/<tenant-id>/controls/` in the tenant's evidence bucket, does not replicate delete markers, requires SSE-KMS source selection, and uses a distinct least-privilege role per tenant. Destination bucket policy rejects direct object/retention writes by any principal other than that exact replication role; its direct-PUT encryption-header denials also exempt only that role so AWS replication is not caught by a missing request header. Aurora recovery uses a customer-managed local locked vault, an exact custom Backup role, daily recovery points, and a copy into the destination locked vault.

For versions that existed before the live rule or reached `NONE`/`FAILED`, the
tenant recovery reconciler reserves a durable generation in the global control
table, fixes an immutable UTC cutoff, and creates a deterministic S3 Batch
Replication job from an S3-generated eligible-version manifest. It accepts only
a terminal job with internally consistent counters and zero failures. It then
walks source versions in bounded pages and requires the destination to expose
the same `VersionId`, bytes, provider-returned full-object SHA-256 checksum,
tenant/SHA-256 metadata, Object Lock mode/date,
legal-hold state, configured destination KMS key, and replication state. Cursors
survive Lambda retries. An S3 failed-replication notification records a repair
request and alerts; a verified generation rotates only for that durable request.
The Batch report bucket is private, retained, versioned, and expires reports
after 365 days.

After deployment, require each durable backfill state to reach `VERIFIED`, retain
and reconcile its zero-failure Batch report, exercise a repair request, verify a
new live source object version/checksum/KMS/retention/hold in the destination,
test a control-plane canary through the global-table replica, then perform an
isolated Aurora restore and tenant ownership/RLS verification. CloudFormation
synthesis proves configuration shape, not recovery. No restore/cutover
automation, recovery-account isolation, or audit-bucket replication is
implemented in this slice.

## Baseline context example

```bash
pnpm exec cdk synth \
  -c deploymentEnvironment=dev \
  -c rootDomain=evidence.example.com \
  -c hostedZoneId=Z0123456789EXAMPLE \
  -c alertEmail=security@example.com \
  -c monthlyBudgetUsd=100 \
  -c 'tenants=[{"id":"ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","slug":"acme","displayName":"Acme Corporation","retentionDays":365,"retentionMode":"GOVERNANCE"}]' \
  -c 'recovery={"mode":"disabled"}'
```

There is no default domain or deployment environment: `cdk.json` leaves `rootDomain` and `deploymentEnvironment` blank, and synthesis fails until both are supplied. Supply the complete tenant list and explicit recovery object too; tenant stacks never infer a recovery policy. Supply exactly one of an existing `hostedZoneId` (recommended) or `-c createHostedZone=true`; specifying neither or both fails. The latter is a deliberate, billable public-zone creation choice and is not implied by a domain name. `jsontechology.com` appears only in planning examples. Tenant IDs must be `ten_` plus 32 lowercase hex characters. Slugs are 1–48 character lowercase DNS labels and cannot use reserved platform names. More than 49 tenants is rejected because the root mapping consumes one of Amplify's 50 fixed domain settings.

## Fail-closed activation

CloudFormation creates the Cognito client, tenant data plane, exact Amplify mapping, and `TENANT#<id>`/`DOMAIN#<host>` registry rows in `PROVISIONING`; it publishes no tenant CNAME. Start `TenantProvisioningStateMachineArn` with a unique Standard Workflow execution name. It:

1. atomically leases both registry rows;
2. creates a separate NOLOGIN/NOSUPERUSER/NOBYPASSRLS owner and six distinct NOINHERIT logins—upload runtime, ingest reconciliation, evidence control, legal-hold API, evidence read, and API-audit signer—supplying PostgreSQL-native SCRAM verifiers rather than placing reusable generated passwords in SQL;
3. temporarily grants the administrator `SET ROLE` membership, applies authoritative migrations `001` and `006` as the owner, applies grants migrations `002`, `003`, `004`, `005`, `007`, and `008`, records an all-eight-file bundle digest plus live function/index catalog digest, and always revokes membership;
4. verifies that exact database attestation, tables/domains/functions and their owners, FORCE RLS policies, tenant FKs, triggers, singleton tenant/domain rows, all six role boundaries, zero PostgreSQL membership edges involving any managed owner/application role, and a real wrong-context denial;
5. re-verifies, UPSERTs only the approved CNAME under conditioned IAM, waits for Route 53 `INSYNC`, then marks the database and both registry rows `ACTIVE`; and
6. restores the database to `PROVISIONING` and marks registry rows `FAILED` on terminal failure. A `FAILED` tenant can be retried with a new execution.

Active registry rows record schema version 2 and the SHA-256 of all eight packaged SQL files. The database migration table comment independently binds that package digest to an ordered SHA-256 of the live `scopeproof` function and index definitions. Any mismatch fails before activation and requires a separately reviewed forward migration; changing the recorded hash is not an upgrade mechanism. A CNAME may remain after a late failure, but the tenant API must return a generic non-disclosing failure for non-active registry state; DNS is never authorization.

The shared Aurora administrator secret, cluster, database KMS key, tenant database secrets, upload-idempotency HMAC secret, and tenant secret KMS keys are retained. The administrator secret uses the customer-managed database key; each provisioner receives only exact secret-read, Secrets Manager-scoped KMS decrypt, and Data API permissions. Stack deletion must never be used as credential rotation or offboarding.

Any subsequent tenant-stack update moves both registry rows back to `PROVISIONING` and is rejected while a provisioning execution lease is active. Re-run the state machine and all change-specific canaries before restoring infrastructure readiness. This deliberately favors a visible, recoverable outage over serving with a changed bucket, role, key, client, or database mapping that has not been re-verified.

## Tenant API source boundary

Each tenant stack creates a regional custom domain
`api-<tenant-slug>.<root-domain>`, exact Route 53 Alias, WAF association, request
model/validator, bounded throttling, encrypted retained logs, and an ARM64 Node.js
Lambda for authenticated routes. The API Gateway default execute endpoint is
disabled. API Gateway itself answers unauthenticated health checks without
invoking Lambda. The Lambda entry role can strongly read only
`DOMAIN#<that-api-hostname>` and assume only the same tenant's data role for a
15-minute session.

- `GET /health` is an unauthenticated API Gateway mock. It returns only
  `{"status":"ok"}` and cannot cold-start or assume the authenticated upload
  boundary.
- `GET /v1/me` requires `evidence:read` after strict Cognito RS256/JWKS,
  `token_use=access`, exact client, token-time, tenant-domain, active-membership,
  and RBAC validation.
- `POST /v1/upload-intents` requires `evidence:collect`, an exact bounded JSON
  shape, and the tenant's server-only Secrets Manager HMAC. The client supplies
  `capturedAt` but cannot supply `artifactExpiresAt` or
  `requiredRetentionUntil`; both retention boundaries are derived as
  `capturedAt + tenant retentionDays`, and PostgreSQL independently requires that
  exact policy result. It reconciles the DynamoDB reservation and PostgreSQL
  projection before returning a fresh exact-key/checksum/KMS/header-bound
  presigned PUT.
- `POST /v1/legal-hold-requests` and `POST /v1/legal-hold-approvals` require
  `retention:manage` and use a separate entry role/Lambda. Requester/approver
  identifiers cannot come from the body; the database requires distinct active
  administrators and binds approval to the exact request digest.

Safe problem responses do not serialize exceptions, SQL, ARNs, tokens, secrets,
credentials, or presigned URLs. These routes are source/template tested but have
not been deployed. Upload-intent requests are atomically limited to 60 per member
and 300 per tenant per UTC minute. New reservations are separately limited to 500
per member and 5,000 per tenant per UTC day, with both daily counters committed in
the same DynamoDB transaction as the lifecycle/nonce/request reservation. Exact
retries remain recoverable and do not consume a second daily creation slot. The
Amplify UI/auth callback, membership administration, remaining APIs, live quota
tests, and a live HMAC rotation drill remain production gates. The handler already
loads `AWSCURRENT` plus at most one optional `AWSPREVIOUS`; the prior key is
recovery-only and cannot create a new lifecycle.

## Durable public-API audit signing

Successful upload-intent, evidence-search, exact-version download-intent, and
legal-hold request/approval operations write immutable facts to
`scopeproof.api_audit_outbox` in the same tenant database boundary. Mutable
delivery state lives separately in `scopeproof.api_audit_outbox_work`; API roles
cannot read or change either table directly. A one-minute EventBridge schedule
invokes the tenant's single-concurrency signer and processes at most ten rows per
invocation using 120-second database leases.

The signer reconstructs one canonical user event from the leased tenant, user,
membership, action, resource, request, outcome, occurrence time, details, and
full outbox digest. It signs only the canonical receipt digest with the tenant's
RSA-3072 KMS audit key. The specialized database append procedure independently
recomputes the immutable outbox digest and exact field bindings, serializes the
hash-chain head, appends the event, and marks delivery complete in the same
transaction. The signer login has execute permission only for claim, head read,
specialized append, failure transition, and health procedures. Its Lambda role
has only its exact database secret/cluster, audit-key `kms:Sign`/`kms:Verify`,
and pre-created log group; it has no S3, DynamoDB, STS, legal-hold, evidence, or
generic audit-append capability.

Retries use exponential backoff from 30 seconds to six hours and become a
persistent dead letter after eight failed attempts. A committed append remains
idempotent even if the Data API commit response is lost: the failure transition
detects `already_completed` and does not create a second event. A row that fails
runtime parsing keeps a minimal committed lease so it can follow the same retry
and dead-letter path rather than block later rows. CloudWatch alarms cover row
failures, persistent database dead letters, oldest unsigned age of five minutes,
Lambda errors/throttles, missing health telemetry, and exhaustion of the
EventBridge invocation DLQ.

Do not repair a poison row by editing either outbox table or by granting the
signer generic append/table access. Diagnose the safe `last_error_code`, correct
the producing code or schema with a reviewed forward change, then use the
owner-only `scopeproof.requeue_dead_lettered_api_audit_event(...)` procedure in
an approved break-glass database session. Confirm the row reaches `completed_at`,
verify the returned KMS receipt and tenant chain, and retain the incident and
CloudTrail evidence.

## Storage and promotion

- The tenant data role can presign only an exact SSE-KMS `PutObject` into its
  quarantine prefix. It cannot list or read quarantine or immutable evidence;
  the promoter's ingest identity and the evidence-control identity are separate.
- Only the promoter can `PutObject`/set retention in the evidence prefix. The
  bucket denies `DeleteObject`, `DeleteObjectVersion`, and evidence writes that
  omit `s3:if-none-match`, preventing delete-marker reopening and unconditioned
  additional versions.
- Exact keys are `tenants/<ten_id>/controls/<control>/quarantine/upl_<32hex>.upload` and `tenants/<ten_id>/controls/<control>/evidence/evd_<32hex>.<approved-extension>`.
- A strongly consistent `UploadLifecycle` item authorizes tenant/user/evidence IDs, source/destination, MIME, size, SHA-256, nonce, expiry, server-derived retention, status, and revision. Expiry gates only unconsumed `issued` uploads.
- The source library requires a canonical 256-bit client idempotency key and a server-only 32-64 byte HMAC loaded from the tenant Secrets Manager secret. DynamoDB atomically reserves the lifecycle/nonce/request rows together with the tenant/member daily creation counters and stores the bounded recovery projection; every exact retry re-runs the equality-checking PostgreSQL procedure before a fresh presign is returned, including after an ambiguous Data API commit response.
- A durable monotonic copy fence plus a no-retry `If-None-Match: *` destination
  `PutObject` prevents concurrent duplicate versions even if an older worker
  resumes after takeover. The losing/newer attempt adopts the sole tracked
  version and preserves both copy-fence and reconciliation-fence provenance.
  Completion verifies S3 SHA-256/version/KMS/retention, signs the canonical
  receipt digest with the tenant asymmetric KMS key, and atomically records the
  receipt; replay revalidates that exact receipt and S3 version.
- `CleanMalwareScanResult` is enabled in the synthesized tenant stack and accepts only matching clean scan events. This is safe only after the composed upload route has been deployed and proved to write the exact lifecycle contract; because no AWS route or stack has been deployed, the production activation gate remains open.
- Exact-version legal holds use separately committed `REQUESTED`, `APPROVED`,
  `APPLYING`, and `APPLIED` PostgreSQL phases, plus terminal `EXPIRED` requests.
  Requester and approver identities come from two distinct authenticated active
  tenant administrators and the approval is bound to the exact request digest.
  Before S3 mutation, the worker reads the predecessor state and durably records
  its deterministic application attempt; pre-existing drift fails closed.
  Ambiguous S3 responses are recovered only by an exact idempotent retry and
  readback. The KMS-signed audit receipt commits and verifies before audit-bound
  recovery publication. Aurora acknowledges the exact DynamoDB publication
  time before clearing the durable outbox; retries reuse and KMS-verify the
  committed audit receipt even after the audit head advances. Failure, age, expiry, and Lambda
  alarms publish to the operations topic. Only the evidence-control IAM/database
  identity can append audit receipts or set/get holds; the promoter has a
  separate narrowly scoped signing path. Neither path can delete objects or
  bypass governance retention.

## WAF, audit, alerting, release, and email

- Amplify uses a **REGIONAL** WAF ACL; CloudFront releases use a separate **CLOUDFRONT** ACL. Both enforce exact hosts, managed reputation/input rules, and rate limits. The app ACL also rejects bodies over 64 KiB; direct evidence uploads use S3 controls.
- WAF keeps blocked-request logs and redacts Authorization/Cookie. Lambda, Step Functions, WAF, and CloudTrail logs are encrypted and retained one year.
- The multi-region trail captures global/management events, API/error insights, validation, and exact quarantine/evidence S3 data events into KMS-encrypted, versioned, compliance-locked storage.
- SNS alarms cover shared/per-tenant DLQs, public-API audit signing/backlog/dead letters, job age, Aurora capacity, denied API calls, and root use. Email subscriptions require recipient confirmation.
- Releases use a private S3 origin behind CloudFront OAC. The protected production macOS candidate workflow performs Developer ID signing, hardened-runtime verification, Apple notarization/stapling, and provenance-safe artifact upload, but publishing to the AWS release bucket remains a separate approved step.
- SES creates domain identity, Easy DKIM, and rejecting custom MAIL FROM. Sending access, bounce/suppression handling, and an app sender are not included.

## Production prerequisites and blockers

Before launch:

1. use an owned/delegated domain, existing zone ID, real alert recipient, and reviewed budget;
2. use OIDC CI, pinned revisions, `cdk diff`, approvals, and change control;
3. deploy and live-test the API Gateway `/health` mock plus the implemented tenant
   `/v1/me` and `/v1/upload-intents` routes, including the 60/300 per-minute
   request limits and atomic 500/5,000 daily new-reservation limits; extend the
   same exact-host/JWT/membership/RBAC and safe-error boundary to every migrated
   API, and connect the approved UI/auth callback;
4. retain `AWSPREVIOUS` through intent expiry plus the seven-day reconciliation
   grace, exercise rotation against outstanding exact retries, and remove the
   prior stage only after the durable retry inventory is empty;
5. implement invitation/membership administration, the legal-hold UI/operating
   process, onboarding/offboarding, AWS release publishing, SES delivery,
   and incident workflows;
6. live-test API-audit ordering, KMS verification, ambiguous Data API commit
   recovery, lease takeover, eight-attempt dead-lettering, owner-only requeue,
   alarm delivery, and a backlog that contains both a poison row and later valid
   rows;
7. integration-test Amplify WAF/domain behavior, DNS-last activation, Data API ownership/RLS, GuardDuty events/tags, KMS contexts, S3 checksums/Object Lock, replay, and cross-tenant denial in an isolated AWS account; and
8. run restore/DR exercises and decide whether higher-assurance customers require separate accounts/regions.

Evidence, keys, registry/audit data, and databases are retained/deletion-protected. Stack deletion leaves billable resources and registry history. Automated offboarding/deletion is not implemented.

## Known limitations

1. The small tenant API is composed in source, but no AWS route is deployed and
   the Amplify customer UI has no source/release connection. Most product routes
   remain on the legacy runtime.
2. No invitation/membership administration, legal-hold UI/deployed operating
   workflow, or offboarding workflow. The two-person legal-hold routes, domain/
   persistence, worker, and alarms are source infrastructure only.
3. Security-sensitive AWS integrations are source/template-tested, not account integration-tested, and nothing has been deployed.
4. Primary compute, identity, control, and database infrastructure remains shared; account-per-tenant has a smaller blast radius. Recovery is same-account/cross-region and does not protect against full account compromise.
5. The global control table, live S3 replication, S3 Batch existing-version
   backfill/exact verifier, and Aurora copies are source infrastructure only:
   existing-table migration, restore/cutover orchestration, audit-bucket
   replication, and demonstrated RPO/RTO remain outstanding.
6. SES sending and dashboards remain outside this slice. KMS application audit adapters exist, but general product-route audit receipt composition remains outstanding.
7. Production release-candidate signing/notarization and advanced CodeQL are automated in source; Swift uses a manual arm64 build while JavaScript/TypeScript and Actions retain no-build coverage. Merge the workflow before switching the repository from default to advanced setup, then require every language check. Protected repository settings, Apple credentials, and explicit release publication are still required.
