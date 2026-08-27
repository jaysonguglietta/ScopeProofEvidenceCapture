# AWS multi-tenant hosting

## Decision

Scopeproof's production hosted service will use AWS-managed resources. The local macOS Local Console remains a loopback-only, offline-capable component and is never exposed as the hosted service.

The initial architecture is a **shared control plane with an isolated evidence plane per tenant**. This keeps idle cost low while placing customer evidence behind separate AWS authorization and encryption boundaries.

`jsontechology.com` is the exact placeholder domain for infrastructure configuration. It is not a claim of domain ownership and must remain configurable. Example customer hostnames are:

- `acme.jsontechology.com`
- `northwind.jsontechology.com`
- `contoso.jsontechology.com`

Route 53 creates an explicit record only after the tenant database boundary passes verification. An unprovisioned hostname must not become usable. The current Amplify implementation deliberately publishes one exact CNAME per tenant because the provisioner and its scoped IAM policy support only that record type. A future migration to an AWS target with a stable Route 53 Alias target may use reviewed A/AAAA Alias records, but the provisioner, IAM conditions, verification tests, and this runbook must change together.

## Product brief

1. **Target users:** customer administrators, compliance leads, evidence collectors, reviewers, external auditors, and enrolled Mac users.
2. **Problem:** collect, review, retain, browse, and export compliance evidence without exposing one customer to another.
3. **Primary workflow:** open the assigned customer hostname, authenticate, operate only within an active tenant membership, collect or upload evidence, review it, and export an assessor package.
4. **Main views:** sign-in, evidence library, assessments, integrations, devices, tenant users and roles, audit history, retention, and platform onboarding.
5. **Core models:** Tenant, TenantDomain, User, Membership, Device, Assessment, Evidence, StorageLocation, Connector, Job, RetentionHold, AuditEvent, and ExportPackage.
6. **Important edge cases:** users in multiple tenants, unknown or disabled hostnames, a suspended tenant, device reassignment, job replay, customer-owned S3, legal holds, regional storage, and offboarding.
7. **Assumptions:** early traffic is modest, `us-east-1` is the initial application region, and external providers such as Jira and GitHub remain integrations rather than hosting dependencies.
8. **Done:** Client A cannot discover, read, change, export, decrypt, or infer Client B data through any API, database query, object operation, queue, cache, log, backup, or support workflow.

## Selected AWS services

| Concern | AWS service | Cost and isolation rationale |
| --- | --- | --- |
| DNS | Route 53 | Explicit tenant records; the domain is configurable. |
| Web UI hosting | Amplify Hosting compute | Intended managed UI/SSR host; the current Amplify app has no source/release connection. |
| Tenant API | Regional API Gateway + per-tenant Lambda/custom domain | A dedicated `api-<tenant>.<domain>` boundary, disabled default execute endpoint, exact-domain registry key, tenant-specific assume role, request validation, throttling, and no always-running server. |
| Edge security | Amplify/CloudFront/API Gateway, AWS WAF, Shield Standard | TLS termination, caching only for public/static assets, baseline managed rules, and rate controls. |
| Authentication | Cognito User Pools | MFA, OIDC/SAML federation, authorization-code flow, and PKCE for public/native clients. |
| Tenant registry/control plane | DynamoDB on-demand global table | Strongly consistent primary-region domain/tenant lookup plus a recovery-region replica when recovery is enabled; PITR and deletion protection on every replica. |
| Evidence metadata | Aurora Serverless v2 PostgreSQL with Data API | Preserves relational workflows and can scale to zero when the supported engine/platform configuration is selected. |
| Evidence bytes | S3 | One Object-Locked evidence bucket and optional quarantine bucket per tenant. |
| Encryption and signing | KMS | A customer-managed key per tenant; separate platform signing/HMAC keys by purpose. |
| Secrets | Secrets Manager | Tenant-specific connector and OAuth secret references; no plaintext secrets in records or queues. |
| Background work | EventBridge Scheduler, SQS, Lambda, DLQ | Pay-per-use collection, SBOM, package, validation, retention, and retry processing. |
| Monitoring | CloudWatch, CloudTrail, SNS | Tenant-aware service metrics plus AWS control-plane and S3 data-event auditing. |
| Release distribution | S3 and CloudFront | AWS-hosted DMGs, update manifests, checksums, and signed release metadata. |

This design intentionally avoids a NAT Gateway, load balancer, RDS Proxy, and continuously running ECS/App Runner task in the initial low-traffic deployment. If cold-start latency becomes unacceptable, Aurora minimum capacity or compute concurrency can be raised without changing the tenant model.

## Logical architecture

```text
customer.jsontechology.com
        |
Route 53 explicit tenant record
        |
Amplify Hosting / CloudFront + WAF
        |
Future AWS UI ---- Cognito
        |
api-customer.jsontechology.com
        |
Route 53 Alias -> regional API Gateway + WAF
        |
        +---- API Gateway mock integration (/health; no Lambda/STS)
        |
        +---- per-tenant data and legal-control Lambdas
              (/v1/me, /v1/upload-intents, /v1/legal-hold-*)
                    |
              tenant resolver + membership authorization
                    |
                    +---- DynamoDB tenant registry
                    +---- tenant PostgreSQL execute-only role through RDS Data API
                    +---- tenant-scoped upload or legal-control IAM role
                    +---- SQS -> Lambda workers -> tenant-bound integrations
```

The hostname selects a candidate tenant. It is never authorization by itself.

## Tenant and authentication model

Required records:

- `tenants`: immutable opaque ID, DNS-safe slug, display name, status, region, and retention profile.
- `tenant_domains`: exact normalized hostname, tenant ID, canonical/alias state, and verification status.
- `users`: immutable Cognito `sub` plus display/contact attributes. Email is not an authorization key.
- `tenant_memberships`: tenant ID, user ID, tenant role, status, invitation, and activation metadata.
- `tenant_storage`: database, role, bucket, region, KMS, Object Lock, and access-point configuration.
- `tenant_integrations`: provider, non-secret metadata, and Secrets Manager references.
- `platform_operators` and `support_access_grants`: separate from customer administrator memberships.

For a browser request:

1. Normalize and resolve the exact API Gateway custom-domain hostname through
   the strongly consistent DynamoDB domain record.
2. Reject unknown, disabled, noncanonical, direct execute-api, direct Amplify/
   CloudFront, malformed, or reserved hosts.
3. Validate the Cognito token issuer, signature, audience/app client, `token_use`, expiry, and session state.
4. Load an active membership for the Cognito subject and resolved tenant.
5. Derive role and tenant from that membership. Never trust a tenant header, body field, route value, email domain, or editable token attribute.
6. Authorize the action and the exact resource tenant.
7. Use an exact-host, Secure, HttpOnly, `__Host-` session cookie. Do not share a parent-domain cookie between tenants.

Use a central authentication return endpoint such as `auth.jsontechology.com` or create one Cognito app client per tenant with exact callback URLs. Cognito callback URLs must never use an attacker-controlled return target.

The Mac uses authorization-code flow with PKCE through the system browser. Its device enrollment is bound to one tenant, exact server origin, user membership, device identifier, scopes, and revocation state. The Mac never receives the hosted service's AWS access key.

## Database isolation

The AWS schema must not copy the current global authorization model. Every customer-owned row receives a non-null `tenant_id`, and every relationship uses a tenant-aware foreign key. Roles move from `users.role` to `tenant_memberships.role`.

For a separate-schema or pooled database, enable and force PostgreSQL row-level security on every tenant table. The application role must not own tenant tables, be a superuser, or have `BYPASSRLS`. Set tenant context with `SET LOCAL` inside a transaction so a reused connection cannot retain another tenant's context. Explicit tenant predicates remain required in application queries as an additional barrier.

Examples of tenant-aware uniqueness include:

```text
UNIQUE (tenant_id, sha256, source, control_id, assessment_id)
UNIQUE (tenant_id, provider)
UNIQUE (tenant_id, user_id, jira_cloud_id)
UNIQUE (tenant_id, device_id, local_evidence_id)
```

The lowest-risk initial bridge model provisions a separate PostgreSQL database and non-administrator role per tenant in one Aurora cluster. Higher-volume tiers can move to forced-RLS pooling later without weakening the application-level tenant contract.

## S3 and KMS isolation

Each tenant receives:

- a short-lived ingest/quarantine bucket when direct uploads are enabled;
- a private, versioned evidence bucket with Object Lock;
- a customer-managed KMS key;
- narrowly separated IAM roles. The upload role can write only the exact
  control-scoped quarantine key and generate an S3-bound data key; it cannot
  list a bucket, read quarantine, read evidence, decrypt evidence, or operate
  legal holds.

Canonical object names use opaque IDs rather than customer display names:

```text
tenants/<tenant-id>/controls/<control-id>/quarantine/<upload-id>.upload
tenants/<tenant-id>/controls/<control-id>/evidence/<evidence-id>.<approved-extension>
tenants/<tenant-id>/exports/<package-id>
tenants/<tenant-id>/audit-checkpoints/<yyyy-mm>/<checkpoint-id>
```

Tenant ID, resource type, resource ID, object version, and cryptographic purpose must be included in application authenticated data, signed receipts, and KMS encryption context. S3 metadata must record the exact `VersionId`, checksum, KMS key ARN, Object Lock mode, and retain-until time.

The web and Mac clients receive only exact-key, short-expiry, checksum-bound presigned operations after authorization. They cannot list the service bucket or choose an arbitrary key. The service derives retention from the tenant's server-managed policy; a client cannot choose or shorten `required_retention_until`. An accepted upload is validated before it moves from quarantine into locked evidence storage.

For customer-owned S3, Scopeproof assumes a narrowly scoped cross-account role using a unique provider-generated External ID. Long-lived customer access/secret keys are not accepted by the hosted service.

## Jobs, integrations, audit, and support

- Every SQS message, job row, lease, retry, idempotency key, DLQ record, and metric includes immutable tenant identity.
- Workers re-fetch the job under the tenant's database and IAM context instead of trusting queue fields alone.
- AWS collectors assume tenant-specific customer roles. GitHub, Jira, Okta, and other integrations use tenant-specific secret references.
- Jira OAuth state includes the tenant and exact return hostname; a flow started on one tenant cannot complete on another.
- Audit events use a per-tenant sequence/head/checkpoint. Platform operations have a separate chain.
- Support access has no standing evidence permission. It requires MFA, a reason/ticket, approval, a short expiry, and a customer-visible immutable audit event.
- Upload issuance enforces atomic principal and tenant quotas: 60 and 300
  requests per minute respectively, plus 500 and 5,000 new reservations per UTC
  day. Exact idempotent retries return the canonical reservation without
  consuming another daily reservation. WAF's separate source-IP control remains
  defense in depth, and future routes need route-appropriate quotas.

## Domain provisioning

The tenant slug must be 1–48 lowercase ASCII characters and match `^(?=.{1,48}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`. Reserve at least `admin`, `api`, `app`, `auth`, `downloads`, `status`, `support`, and `www`.

Infrastructure provisioning is fail-closed at the workflow level:

1. Reserve a unique opaque tenant ID and slug and create exact tenant/domain registry rows in `PROVISIONING`.
2. Provision the Cognito client, database identity, buckets, KMS key, IAM role, secret references, queues, and exact Amplify mapping without publishing tenant DNS.
3. Run the tenant state machine to create the database boundary, apply owner-scoped migrations and runtime grants, and verify exact schema ownership, forced RLS, tenant identity/domain state, and a real wrong-context denial.
4. Re-run verification, publish only the exact Route 53 tenant CNAME, and wait for Route 53 `INSYNC`.
5. Mark database and registry state `ACTIVE`, recording the schema version and packaged migration digest. This currently means infrastructure/database readiness only.
6. Keep customer activation separately blocked until hosted authentication, membership, storage and application canaries, recovery, and two-tenant adversarial tests pass.

Amplify Hosting has a fixed quota of 50 subdomains per domain. The initial stack reserves one mapping for the root, so it fails synthesis above 49 tenant hostnames. Split larger deployments across controlled domains/accounts rather than replacing explicit DNS with an authorization-ambiguous wildcard.

Offboarding reverses public reachability first, suspends membership and device access, blocks new jobs, completes retention/legal-hold disposition, exports the customer record when authorized, and destroys keys or retained data only after approved evidence of completion.

> **Existing-deployment migration stop:** the current control-plane template is
> `AWS::DynamoDB::GlobalTable`. Do not update an existing stack that still owns
> the previous `AWS::DynamoDB::Table` resource directly. Freeze mutations, verify
> PITR plus an independent backup/export, retain and remove the physical table
> from old stack ownership, convert/add the recovery replica through a reviewed
> DynamoDB procedure, import it under the new logical resource, and reconcile all
> items/indexes/TTL/settings before resuming. Rehearse this in a disposable
> account. Fresh deployments can create the global table normally; see the
> [operator runbook](AWS_PLATFORM_RUNBOOK.md#existing-control-table-migration-stop).

## Implementation status and production boundary

The repository now contains production-shaped AWS security adapters,
infrastructure, and a deliberately small composed tenant API. That API slice is
composed in source; the complete customer-facing AWS product is not yet composed
or deployed. Source-level and
synthesized-template tests are not evidence that the design works in a real AWS
account.

| Area | Implemented in this repository | Still required before customer use |
| --- | --- | --- |
| AWS infrastructure | Synthable shared and per-tenant CDK stacks, DynamoDB global control table, explicit tenant resources, Cognito clients, WAF, budgets, alarms, release distribution, provisioning workflow, quarantine scanning resources, and retained audit storage. | Controlled account deployment, safe migration of any existing single-region control table, verified domain and certificates, real alert recipients, UI source/release connection, integration tests, restore drills, and penetration testing. |
| Tenant request boundary | Strongly consistent exact-host resolution, strict Cognito RS256/JWKS access-token verification, exact app-client binding, RDS Data active-membership/RBAC lookup, safe API errors, an API Gateway mock `GET /health`, and authenticated Lambda routes for `GET /v1/me` and `POST /v1/upload-intents`. Upload issuance atomically limits each member/tenant to 60/300 requests per minute and 500/5,000 new reservations per UTC day. | Deploy it, connect the approved customer UI/auth callback, validate quota and replay behavior under real concurrency, migrate the remaining product routes, and prove the boundary against two tenants. |
| Relational data | PostgreSQL baseline, tenant-aware keys, forced RLS, four separate runtime/ingest/evidence-control-worker/legal-hold-API logins, execute-only procedure allowlists with no direct application table grants, an offline renderer, and an AWS provisioning implementation. | Port remaining D1 repositories/queries, run the provisioner in an isolated AWS account, verify all role boundaries and RLS with two tenants, test backup/restore, and reconcile imported production data. |
| Evidence storage | Per-tenant KMS, quarantine and Object-Locked buckets, server-managed tenant retention, a write-only/no-list upload IAM boundary, composed upload-intent route, Dynamo/Aurora ambiguous-commit reconciliation, replay-safe KMS-signed promotion receipts, and CDK-wired two-person `REQUESTED` → `APPROVED` → `APPLYING` → `APPLIED` exact-version S3 legal-hold routes plus terminal `REQUESTED` → `EXPIRED`, durable signed audit/recovery-publication outboxes, bounded retry/backoff, and age/failure/expiry alarms. The public legal-hold API can only request/approve in SQL; only the separate worker role can expire/reconcile and use S3/KMS/audit state. | Deploy/test the upload and active clean paths, add the legal-hold UI/operating process, prove independent authorization and KMS audit emission in AWS, and complete replay/chaos/operational canaries before accepting evidence. |
| Recovery and native release | DynamoDB global control table, same-account cross-region S3 Object-Lock live replication, deterministic S3 Batch backfill, recurring 24-hour exact-version checksum/metadata/KMS/Object-Lock verification with 36-hour freshness alarms, Aurora AWS Backup/Vault Lock plus regional recovery-freshness alarms, a protected Developer ID/notarization workflow, and advanced CodeQL with a manual Swift build plus JavaScript/TypeScript/Actions coverage. | Safely migrate any existing control table, deploy bootstrap/enabled recovery phases, perform backfill/restore/RPO/RTO/cutover drills, configure protected environments and Apple credentials, merge the advanced workflow before switching the repository away from default setup, require all language checks, and explicitly publish an approved release. |
| Native authentication | Cognito authorization-code/PKCE transaction validation, exact callback/issuer/audience constraints, tenant binding, and refresh-token Keychain abstraction. | Discovery/enrollment protocol, production UI wiring, JWT verification/server exchange integration, device-key lifecycle, suspension/revocation tests, and signed update/release validation against the deployed service. |
| Legacy hosted application | The existing Cloudflare/Sites application remains functional for its approved single-tenant use. | Convert the vinext/Worker runtime and D1/R2 adapters to the AWS tenant-aware implementation, migrate and reconcile one legacy tenant, then pass Client A/Client B isolation gates before adding another customer. |

Legal-hold request and approval are distinct authenticated HTTP calls. Actor
identity comes only from the strict Cognito and active-membership context; actor
fields in JSON are rejected, and the same administrator cannot approve their
own request. Canonical `changedAt`/`approvedAt` values are client-stable for
durable retry, but PostgreSQL permits a new transition only within ±5 minutes
of its clock and requires approval within 24 hours. An exact committed replay is
accepted after that skew window; changed or newly backdated facts fail. The
bounded scheduled worker applies only `APPROVED` operations—`REQUESTED` is never
auto-approved—and atomically expires requests that remain unapproved for 24
hours. Expiry never changes S3 and remains in a durable outbox until a signed
audit event is appended. Failed approved/applying operations retain their
durable state and receive database-enforced exponential backoff so poison work
cannot starve later rows. An applied operation remains eligible until the worker
reuses or creates and KMS-verifies the exact committed audit receipt,
idempotently publishes the exact bucket, key, and `VersionId` in the recovery
ledger, and separately records the DynamoDB publication timestamp in Aurora.
The signed event also binds provider request IDs, receipt digest, and revisions.
All worker actions use the separate evidence-control IAM/database
identity, except the recovery-ledger transaction, which is held directly by the
narrow worker execution role and restricted to that tenant's recovery partition.

The current paths `vite.config.ts`, `worker/index.ts`, `.openai/hosting.json`, `lib/server/env.ts`, `db/schema.ts`, `db/index.ts`, and `drizzle/*` are still the legacy Cloudflare/Sites, D1, and R2 implementation. Its roles, queries, and storage paths are not safe to share across unrelated customers. Do not create a second customer hostname pointing at it.

Follow the [AWS platform runbook](AWS_PLATFORM_RUNBOOK.md) for the exact sequence and the [AWS adversarial security review](AWS_SECURITY_REVIEW.md) for release-blocking findings and residual risks.

## Migration sequence

1. Build and synthesize the AWS infrastructure without serving customer traffic.
2. If an earlier AWS stack exists, perform the runbook's retain/remove/convert/
   import migration from `AWS::DynamoDB::Table` to the global control table;
   never deploy that resource-type change directly. Fresh stacks skip this step.
3. Convert vinext to an Amplify-supported Next.js runtime, connect it to the
   implemented per-tenant API, and replace Worker cron with EventBridge/SQS/Lambda.
4. Extend the strict Cognito/exact-host/membership boundary from `/v1/me` and
   `/v1/upload-intents` to every migrated API; add membership administration and
   tenant-bound Mac enrollment.
5. Port D1/SQLite to PostgreSQL, add tenant constraints and forced RLS, and remove direct database access from route handlers.
6. Replace R2 with the implemented tenant S3/KMS upload, reconciliation,
   receipt, and exact-version legal-hold adapters; require a canonical 256-bit
   client idempotency key and rotate the 32-64 byte tenant HMAC with overlap.
7. Add the customer/admin UI and operating procedure for the CDK-wired,
   separately authenticated legal-hold request/approval routes and scheduled
   reconciler; source infrastructure alone is not an available service.
8. Create a legacy tenant and import every current row under explicit ownership. No row may have a null or ambiguous tenant.
9. Decrypt, verify, and copy every R2 object to its tenant S3 location; re-encrypt values whose authenticated data gains a tenant ID.
10. Anchor the final legacy audit head into the new tenant audit genesis event.
11. Run the legacy tenant on AWS at one hostname and reconcile counts, hashes, packages, checkpoints, recovery backfill, and restore.
12. Run full Client A/Client B adversarial tests.
13. Only then provision the first additional customer hostname.

Avoid cross-provider dual writes. Use a controlled cutover and retain the old service as read-only until reconciliation succeeds.

## Cost controls

- Aurora Serverless v2 minimum capacity is `0` only on engine/platform versions supporting auto-pause; retain a small maximum during pilot operation.
- Use DynamoDB on-demand, Lambda reserved concurrency, SQS batch limits, and per-tenant quotas.
- Do not add a NAT Gateway or always-on compute to the pilot architecture.
- Use S3 lifecycle rules only when they are compatible with evidence retention and legal holds.
- KMS keys are the principal per-tenant fixed resource cost in the bridge model; do not trade them away silently.
- Add AWS Budgets and anomaly alerts before onboarding external customers.

## Security acceptance tests

Before adding a second customer, seed Tenants A and B with equivalent users, evidence, assessments, devices, jobs, Jira records, SBOMs, packages, and audit events, then verify:

- Every A request containing a valid B identifier returns the same non-disclosing failure and causes no B S3/KMS request.
- Raw SQL under A's transaction cannot select, insert, update, or delete B rows.
- Cross-tenant foreign keys and uniqueness operations fail.
- Reused database sessions cannot retain a prior tenant context.
- A's IAM role cannot list, read, write, delete, or decrypt B's resources.
- Tampered queue tenant/job pairs are rejected and audited.
- Jira OAuth, SBOM comparisons, packages, retention, and audit checkpoints never cross tenants.
- Unknown, inactive, trailing-dot, port-bearing, punycode-confusing, suffix-confusing, direct AWS, and spoofed-forwarded hosts fail closed.
- Dynamic and API responses containing tenant data are not cached across users or hostnames.
- Backup, restore, suspension, legal hold, key rotation, and offboarding operate on exactly one tenant.

Commission an independent BOLA/IDOR-focused penetration test before production authorization.

## References

- [AWS SaaS tenant isolation](https://docs.aws.amazon.com/whitepapers/latest/saas-architecture-fundamentals/tenant-isolation.html)
- [Amplify Next.js SSR support](https://docs.aws.amazon.com/amplify/latest/userguide/ssr-amplify-support.html)
- [Amplify custom and wildcard domains](https://docs.aws.amazon.com/amplify/latest/userguide/wildcard-subdomain-support.html)
- [Amplify Hosting service quotas](https://docs.aws.amazon.com/amplify/latest/userguide/quotas-chapter.html)
- [Cognito application-client and authorization-code guidance](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html)
- [Aurora Serverless v2 scale-to-zero](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-serverless-v2-auto-pause.html)
- [Aurora RDS Data API](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api.html)
- [PostgreSQL row-level tenant isolation](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-managed-postgresql/rls.html)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [Third-party cross-account roles and External IDs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html)
