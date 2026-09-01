# AWS multi-tenant foundation adversarial security review

**Review date:** 2026-08-28

**Review basis:** the working-tree implementation under `infra/aws/cdk`, `infra/aws/database`, `lib/aws-runtime`, and the hosted-authentication primitives in `macos/ScopeproofCapture`. The existing web runtime was inspected only where necessary to determine whether it can safely serve the new tenant hostnames.

**Deployment status:** **no AWS deployment was performed.** The resources and findings below describe code and synthesized design, not controls verified in a live AWS account.
**Important boundary:** the current web application remains a single-workspace Cloudflare/D1/R2 application. It is not the AWS multi-tenant runtime described by the new contracts and infrastructure.

## 1. Executive Summary

### Remediation status addendum — 2026-09-01

The current source adds route-specific API Gateway Cognito scopes while
retaining Lambda JWT/tenant/membership/RBAC enforcement; makes exact-version
DLP configuration mandatory for production tenants; KMS-signs and verifies the
canonical DLP receipt; binds those facts into promotion, S3 metadata, DynamoDB,
and PostgreSQL reconciliation; persists immutable rejected-ingest receipts;
ships forward-only PostgreSQL migration `009_runtime_hardening.sql`; and blocks
DNS activation without a current `CUSTOMER_ENABLED` approval bound to the exact
provisioning execution.

These controls materially narrow AWS-02, AWS-05, and AWS-06 and repair the
source-enforceable rejection/upgrade/activation gaps found during integration
review. They do not establish closure through live operation: scanner privacy,
efficacy, region, retention, availability, KMS/IAM behavior, two-tenant denial,
failure convergence, recovery, alarm delivery, and release notarization still
require deployed staging evidence. No AWS resource was deployed by this work.
Use [Security and product remediation status — 2026-09-01](SECURITY_REMEDIATION_2026-09-01.md)
for the detailed source-control matrix and validation plan. The audit's Open
Questions section is intentionally unchanged because those decisions were
deferred by the owner.

Final source review also corrected a rejection-availability edge: an exact
DynamoDB-first rejection receipt now replays before the age gate, while a
missing Aurora receipt can recover only within the configured 14-day ingest DLQ
horizon. Canonical receipt digest, stored `rejectedAt`, tenant, intent, evidence,
version, and optimistic-revision checks remain mandatory. The regression suite
covers a 25-hour partial-commit replay; live Aurora outage and DLQ-redrive proof
is still a production gate.

The new foundation materially improves the security design. It establishes exact tenant hostnames, private per-tenant S3 quarantine and evidence buckets, customer-managed KMS encryption, S3 Object Lock, versioning, GuardDuty malware scanning, separate tenant PostgreSQL databases, forced row-level security, non-owner runtime roles, Cognito MFA, WAF controls, bounded jobs, immutable CloudTrail storage, and fail-closed TypeScript state-transition contracts. The evidence promoter is notably skeptical: it requires a strongly consistent upload intent, an exact opaque key and object version, a full-object SHA-256 checksum, an exact MIME type and size, a clean GuardDuty result and tag, the configured KMS key and encryption context, and an Object Lock retention receipt.

At the original review baseline, those controls were foundations rather than a
completed hosted product: the hosted API/JWT/membership/upload/KMS/legal-hold
adapters did not yet exist, the Amplify application had no repository/runtime
connection, and the GuardDuty clean-event rule was disabled. The dated
remediation addendum below records subsequent branch changes without rewriting
the historical finding evidence. The legacy Cloudflare/Sites application still
must never be attached to multiple customer hostnames.

No confirmed remotely exploitable RCE, command injection, path traversal, SQL injection, SSRF, or cryptographic primitive failure was found in the dormant AWS foundation. That original statement was intentionally narrow: there was no exposed AWS runtime to test. A small source-defined AWS API now exists, but it has still not been deployed or tested against live AWS/PostgreSQL services. The original review found one conditional Critical deployment hazard, six High production blockers or integrity risks, three Medium defense-in-depth/operations gaps, and one Low supply-chain/diagnostic gap.

| ID | Finding | Severity | Confidence | Classification |
|---|---|---:|---:|---|
| AWS-01 | The legacy web runtime is single-tenant and must not serve AWS tenant hostnames | Critical | High | Confirmed deployment hazard; not currently deployed |
| AWS-02 | Cryptographic JWT verification and the hosted OAuth network flow are absent | High | High | Production blocker |
| AWS-03 | Shared AWS roles and per-tenant provisioners retain broad cross-tenant blast radius | High | High | Confirmed architectural defense gap |
| AWS-04 | Privileged tenant actions rely on future application authorization while the database role can write security state directly | High | High | Production blocker / defense gap |
| AWS-05 | The secure upload issuer is absent and clean-object promotion is disabled | High | High | Production blocker; safe fail-closed default |
| AWS-06 | Business audit and receipt signatures are placeholders rather than KMS-verifiable attestations | High | High | Confirmed integrity gap |
| AWS-07 | Database legal holds are not enforced with S3 Object Lock legal holds | High | High | Production blocker for legal-hold claims |
| AWS-08 | Security alert delivery is optional and can silently have no recipient | Medium | High | Confirmed secure-default gap |
| AWS-09 | Immutable CloudTrail omits DynamoDB control-plane data events | Medium | High | Confirmed monitoring gap |
| AWS-10 | Governance retention, short metadata backup retention, and no cross-region recovery leave administrator/region risks | Medium | High | Design/continuity gap |
| AWS-11 | Lambda dependency provenance and failure diagnostics need hardening | Low | Medium | Defense in depth |

### Remediation status addendum — 2026-08-28

This table describes the current branch after the original review. It does not
claim deployment effectiveness or erase the original evidence and attack
scenarios below. **No AWS resource was deployed, no live Aurora/Cognito/STS/S3/
KMS/GuardDuty integration test or recovery drill was run, and no Apple artifact
was signed, submitted, or notarized by this work.**

| ID | Current branch status | Evidence added | Truthful residual risk / required validation |
|---|---|---|---|
| AWS-01 | Partially addressed | A tenant-specific regional API Gateway custom domain and purpose-separated Lambdas now compose `GET /health`, authenticated `GET /v1/me`, `POST /v1/upload-intents`, `POST /v1/evidence/search`, `POST /v1/evidence-download-intents`, and two-person legal-hold request/approval; the default execute-api endpoint is disabled. | The legacy Cloudflare/Sites app remains single tenant; Amplify has no approved source/UI release; most customer routes are not migrated. Do not attach tenant UI hostnames or onboard customers. |
| AWS-02 | Server-side portion substantially addressed | `CognitoJwtVerifier` performs strict RS256/JWKS, issuer, exact allowlisted web/native client, `token_use=access`, lifetime, duplicate-JSON, key-quality, redirect/size, refresh-throttling, and rotation checks. The CDK defines a public authorization-code/PKCE native client plus custom read/collect/retention scopes, and every composed route requires its exact OAuth scope before active RDS membership/RBAC. | No live Cognito test, signed tenant discovery, hosted callback/session flow, membership administration, Mac token exchange/JWKS/revocation flow, or account-recovery exercise. The native client exists in infrastructure source but is not connected to the Mac UI. |
| AWS-03 | Partially addressed | Upload, evidence-read, and API-audit signing paths have separate entry/data roles, Secrets Manager credentials, and narrowly scoped keys. The provisioner creates and catalog-verifies six execute-only PostgreSQL application logins, including a fifth evidence-read login and sixth API-audit signer; neither can create upload intents or access tables directly. Each Lambda resolves only its exact tenant boundary, and evidence read is constrained to canonical exact tenant versions and immutable-evidence KMS context. | Exercise IAM, Secrets Manager, RDS, KMS, and S3 denial with two live tenants and retain account-per-tenant as the higher-assurance option. Provisioning still has necessarily powerful tenant-creation access and needs live containment tests. |
| AWS-04 | Partially addressed | Upload writes use a bounded procedure; hosted listing and exact download use the dedicated read login and tenant-context `SECURITY DEFINER` procedures that independently recheck active `evidence:read` membership; promotion uses an ingest-only execute role; signed audit/legal-hold operations use a separate control role. Legal holds require separately committed requester-derived `REQUESTED`, distinct-admin digest-bound `APPROVED`, durable worker-only `APPLYING`, and exact-readback `APPLIED` states. | Membership, support, review/approval, and other legacy writes are not fully migrated to narrow actor-bound procedures. Legal-hold UI, deployed operations, and live authorization tests remain absent. |
| AWS-05 | Addressed in source; deployment gate remains | The upload-intent route derives retention from the tenant policy and canonical capture time, and PostgreSQL independently enforces the same boundary. Principal- and tenant-scoped budgets and atomic reservations prevent replay and quota bypass. The public API no longer returns the upload nonce; its digest is signed into exact S3 metadata and verified before promotion. The assumed upload role has quarantine-only write/KMS permissions and no evidence read, while a separate service lists Aurora metadata and signs 60-second exact-version reads without accepting client storage coordinates. The clean promotion rule and exact promoter are enabled in synthesized IaC. | No live DynamoDB contention/TTL/cost test, PostgreSQL close-versus-upload locking test, delayed-worker S3 conditional-write test, GuardDuty/S3/Data API integration test, exact-download integration test, or outstanding-retry HMAC rotation test; deep content validation and operational canaries remain. |
| AWS-06 | Substantially addressed in source | Tenant RSA-3072 KMS signing, domain-separated canonical audit receipts, immutable append procedures, promotion receipt persistence, and replay-safe reuse of the first randomized RSA-PSS signature are implemented. Promotion receipts are KMS-verified before database commit and again on retry/read. Promotion completion atomically projects the exact signed database receipt into a tenant-API-inaccessible recovery partition; recovery re-canonicalizes it and calls KMS `Verify` before accepting an exact-version replica. Promotion retry verifies the authoritative database row and recovery projection before accepting prior completion. Applied legal-hold audit receipts are also KMS-verified before the worker commits them to Aurora; only then does it publish the audit-bound recovery projection, and the durable outbox remains eligible until Aurora separately acknowledges that publication. | General product routes do not yet emit these receipts; no live key-policy/CloudTrail/export verification or independent checkpoint drill exists. Exercise the post-audit/pre-recovery-publication retry and acknowledgement window against live Aurora/DynamoDB. KMS signing proves key use, not an uncompromised caller. |
| AWS-07 | Addressed in source; deployment gate remains | Exact non-empty S3 `VersionId` is bound to the two-person `REQUESTED` → `APPROVED` → `APPLYING` → `APPLIED` state machine, a durable application-attempt identity and observed prior S3 status, S3 legal-hold write/readback, approval digest, expected-revision CAS, and exact receipt; no delete or governance-bypass permission is granted. An S3 or database partial failure remains durably `APPLYING` for an identical retry. Stale unapproved requests transition only to `EXPIRED`, with a durable KMS-signed expiry-audit outbox. For applied work, the KMS-signed append-only audit receipt commits before the audit-bound recovery ledger is published, and a separate Aurora acknowledgement is the only event that clears the recovery-publication outbox. Bounded database backoff prevents a poison `APPROVED` or `APPLYING` row from starving later work, and CDK alarms on failures, ages, and expiries. | No legal-hold UI/operating drill, alert-delivery proof, live Object Lock/recovery-ledger test, or deployed reconciliation evidence exists. Keep the feature unavailable until those gates pass. |
| AWS-08 | Open | Existing encrypted SNS/CloudWatch paths remain. | Alert email/subscription can still be omitted or unconfirmed; require and canary-test an owned on-call destination. |
| AWS-09 | Open | The control plane is now a recovery-capable DynamoDB global table with PITR/deletion protection. | Application-level immutable audit/alerts for registry/lifecycle mutation and the original DynamoDB data-event visibility gap still require a reviewed solution. |
| AWS-10 | Substantially addressed in source; drills open | Recovery now includes a recovery-region global-table replica, exact-prefix S3 CRR/RTC with Object Lock/KMS, deterministic S3 Batch backfill for existing `NONE`/`FAILED` versions, bounded exact source/replica verification, failure-triggered repair, and Aurora AWS Backup/Vault Lock copies. Initial and repair scans remain bounded S3 version walks; every generation verifies immutable checksum, receipt, KMS, retention, and metadata facts even when a post-cutoff legal-hold projection makes only the mutable hold assertion deferrable. Each generation finishes with a bounded destination inventory and cannot report `VERIFIED` while any pre-cutoff destination delete marker or exact version absent from the source exists. The destination evidence prefix explicitly denies both object and exact-version deletion. Verified periodic generations use a strongly consistent immutable promotion/legal-hold change ledger, an explicit 900-second writer safety lag, exact KMS-verified promotion receipts, separate mutable recovery-state and authoritative recovery partitions, and stale/missing freshness alarms. The reconciler's narrowly scoped source and destination KMS permissions include the data-key operation required for checksum-mode HEAD of SSE-KMS objects. | Same-account design does not survive account compromise; no deployment, backfill, existing-table migration, restore/cutover, audit-bucket replication, or demonstrated RPO/RTO. Existing `AWS::DynamoDB::Table` stacks require retain/remove/convert/import—not a direct update. |
| AWS-11 | Substantially addressed in source | GitHub actions are SHA-pinned, advanced CodeQL uses an explicit manual arm64 Swift build plus separate JavaScript/TypeScript and Actions jobs, and the production release workflow requires a clean approved commit, ephemeral Keychain, hardened Developer ID signing, Apple acceptance, stapling/Gatekeeper checks, bounded artifacts, and attestations. Release identity configuration and production build both validate canonical base64 for a 65-byte uncompressed P-256 point, a unique key ID, canonical ordered timestamps, and a key validity window that includes the build time. Direct CDK and AWS SDK dependencies are exact-version pinned in `infra/aws/cdk/package.json` and `pnpm-lock.yaml`; the reviewed TypeScript runtime Lambdas use `NodejsFunction` with `externalModules: []`, producing self-contained bundles rather than relying on the Lambda runtime's SDK. | Switch the repository from default to advanced CodeQL, require all three analysis checks, and successfully run the protected production-release workflow; configure protected Apple/repository settings; verify Lambda SBOM/provenance and deployed hashes; exercise failure diagnostics in AWS. No Apple submission, production release, or live Lambda deployment has run. |

The original severity reflects risk at discovery. “Addressed in source” means a
reviewed code path now exists; it does not mean the finding is closed for
production. Closure requires the validation named in this table and the launch
test plan.

### Current-branch upload-control findings and remediation — 2026-08-27

The following issues were confirmed during the post-baseline review and fixed
in the current source branch. They are listed separately so that the historical
AWS-05 evidence remains intact. Every item is **source-remediated but not
production-closed**: no live AWS resource, PostgreSQL database, or concurrency
test was used to validate these controls.

#### AWS-U01 — Client-controlled evidence retention could weaken the tenant policy

- **Severity:** High
- **Confidence:** High
- **Classification:** Confirmed business-logic vulnerability at review; remediated in current source; live validation open
- **Affected files/functions:** `infra/aws/cdk/runtime/tenant-api/index.ts` (`POST /v1/upload-intents`), `lib/aws-runtime/evidence/upload-retention-policy.ts` (`deriveServerManagedUploadRetention`), and `infra/aws/database/001_tenant_schema.sql` (`scopeproof.create_upload_intent`)
- **Description and code evidence:** The pre-remediation upload contract allowed an untrusted client to influence the retention boundary used for evidence. The route now canonicalizes `capturedAt`, rejects a capture time more than five minutes in the future, loads `RETENTION_DAYS` from trusted tenant configuration, derives both `requiredRetentionUntil` and `artifactExpiresAt`, and overwrites the caller's evidence projection before issuance. PostgreSQL independently reads `tenant_identity.retention_days` and rejects any `p_required_retention_until` or `p_artifact_expires_at` that differs from `p_captured_at + configured_retention_days`.
- **Exploitation scenario:** A compromised Mac client or malicious member requests a short or already-expired retention date. Without server and database enforcement, the resulting evidence metadata could permit deletion before the tenant's compliance period ends or create a receipt that falsely implies policy-compliant retention.
- **Potential impact:** Premature evidence loss, invalid audit evidence, broken retention representations, and repudiation of compliance claims.
- **Recommended fix / patch guidance:** Keep retention policy out of the public request contract. Derive it only from an authoritative tenant setting and a canonical server-validated capture timestamp, then enforce the same equality rule inside the security-definer database procedure. Treat disagreement as a non-retryable policy violation; do not silently clamp a caller-supplied value.
- **Tests and validation:** `tests/aws-runtime-upload-retention-policy.test.ts` covers exact derivation, future-clock skew, and invalid retention limits. `tests/aws-postgres.test.ts` asserts the SQL policy equality and assessment lock. Add a live Data API/PostgreSQL test that sends shortened, extended, mismatched, and future-dated values and verifies atomic rejection with no intent/evidence row. Test tenant-policy boundary changes under an explicit migration policy before production.
- **CWE / OWASP:** CWE-602 (Client-Side Enforcement of Server-Side Security), CWE-840 (Business Logic Errors), OWASP API6:2023 (Unrestricted Access to Sensitive Business Flows)
- **Residual validation status:** No live tenant configuration, Data API, transaction rollback, clock-boundary, or retention-policy migration test has run. This finding must remain open as a deployment gate until those tests pass.

#### AWS-U02 — Missing atomic quotas enabled upload-request cost and availability abuse

- **Severity:** High
- **Confidence:** High
- **Classification:** Confirmed resource-consumption vulnerability at review; remediated in current source; live validation open
- **Affected files/functions:** `infra/aws/cdk/runtime/tenant-api/index.ts` (upload-intent request ordering), `lib/aws-runtime/evidence/aws.ts` (`DynamoUploadRequestRateLimiter.consume` and `DynamoConditionalUploadIntentStore.reserve`), and `infra/aws/cdk/lib/tenant-stack.ts` (quota configuration and scoped DynamoDB access)
- **Description and code evidence:** The pre-remediation issuer had no atomic principal/tenant budgets, allowing authenticated callers to drive repeated DynamoDB, Secrets Manager, STS, RDS Data API, KMS/S3 signing, and logging work. The route now atomically consumes both tenant and principal UTC-minute counters before expensive dependencies. New intent creation atomically commits tenant and principal UTC-day counters in the same DynamoDB transaction as the lifecycle, nonce, and idempotency reservation. Conditional counter updates fail closed at their configured limit. An exact logical retry first strongly reads and returns the committed lifecycle row, so it does not consume another daily creation reservation; per-request minute limits intentionally continue to count retry work.
- **Exploitation scenario:** One valid low-privilege account, a stolen access token, or many enrolled clients repeatedly request upload intents without uploading evidence. In the prior path, the attacker could exhaust downstream quotas, increase per-request cloud spend, and degrade uploads for every user in the tenant.
- **Potential impact:** Tenant-level denial of service, unexpected AWS charges, DynamoDB hot-partition pressure, and exhaustion or throttling of shared STS/Secrets Manager/RDS/S3 capacity.
- **Recommended fix / patch guidance:** Retain both dimensions and windows: principal plus tenant minute request budgets before external calls, and principal plus tenant daily *new-intent* budgets in the same transaction as the authoritative reservation. Keep counter keys tenant-prefixed, conditions atomic, limits deployment-configurable but bounded, and 429 responses free of internal quota details. Never implement the check as read-then-write. Preserve exact-retry recovery ahead of the daily creation transaction.
- **Tests and validation:** `tests/aws-runtime-evidence-aws.test.ts` asserts the two-item minute transaction, both counter dimensions, daily quota cancellation handling, fail-closed behavior, and the 429 mapping; `tests/aws-runtime-http-api.test.ts` verifies quota details are not disclosed. Add live parallel DynamoDB tests at `limit - 1`, `limit`, and `limit + 1`, exact-retry tests across ambiguous transaction responses, TTL/window rollover tests, hot-key load tests, and cost/latency alarms under controlled abuse.
- **CWE / OWASP:** CWE-770 (Allocation of Resources Without Limits or Throttling), CWE-400 (Uncontrolled Resource Consumption), OWASP API4:2023 (Unrestricted Resource Consumption)
- **Residual validation status:** No live DynamoDB contention, cancellation-reason, TTL-expiry, regional throttling, WAF interaction, or cost-alarm exercise has run. Limits require production traffic sizing and a tested emergency-adjustment runbook.

#### AWS-U03 — Upload IAM and database identities had unnecessary evidence/data privileges

- **Severity:** High
- **Confidence:** High
- **Classification:** Confirmed least-privilege vulnerability at review; remediated in current source; live validation open
- **Affected files/functions:** `infra/aws/cdk/lib/tenant-stack.ts` (`TenantDataRole` and tenant API grants), `infra/aws/database/002_runtime_role.sql` (runtime-role reset and grants), `infra/aws/database/007_evidence_read_role.sql`, and `infra/aws/cdk/runtime/provision-tenant/index.mjs` (database privilege verification)
- **Description and code evidence:** The pre-remediation upload execution path held privileges beyond issuance needs, increasing the impact of a compromised handler or assumed role. The current tenant data role can strongly read only its tenant-prefixed control records, call the bounded RDS Data API transaction operations against the exact tenant cluster/secret, generate a data key only for the quarantine encryption context, and `s3:PutObject` only to the exact tenant quarantine prefix with required encryption headers. It has no `s3:ListBucket`, evidence `s3:GetObject*`, delete, Object Lock mutation, KMS decrypt/sign, or evidence-bucket write permission. `002_runtime_role.sql` revokes table, sequence, and function access before granting execute only on `current_tenant_id`, `resolve_active_membership`, and `create_upload_intent`.
- **Exploitation scenario:** An attacker who gains code execution in the API Lambda, steals temporary tenant credentials, or exploits an authorization bug attempts to enumerate/download immutable evidence, bypass the upload procedure with direct SQL, alter retention state, or delete artifacts. The previous privilege set expanded those post-compromise options.
- **Potential impact:** Evidence confidentiality loss, unauthorized database mutation, retention or audit-integrity damage, and a materially larger post-compromise blast radius.
- **Recommended fix / patch guidance:** Keep separate entry, upload-data, evidence-read, ingest, legal-hold, and evidence-control roles. Upload issuance needs quarantine-only write plus KMS data-key generation, not evidence read/list/delete or KMS decrypt. Revoke database privileges as an allow-list reset on every deployment and expose only audited security-definer procedures. Continue testing both allowed and explicitly denied actions; do not add broad managed policies to fix deployment failures.
- **Tests and validation:** `infra/aws/cdk/test/foundation.test.ts` asserts the absence of S3 read/list/delete/retention/legal-hold, KMS sign/decrypt, wildcard, and direct broad Data API grants while requiring the exact quarantine write/context. `tests/aws-postgres.test.ts` and the provisioner's catalog verification assert the execute-only function allow-list. Add IAM Policy Simulator/Access Analyzer checks against the synthesized role, live STS negative tests for every evidence action, and PostgreSQL catalog plus direct-table denial tests using the deployed role.
- **CWE / OWASP:** CWE-250 (Execution with Unnecessary Privileges), CWE-284 (Improper Access Control), OWASP A01:2021 (Broken Access Control)
- **Residual validation status:** No live IAM evaluation, permission-boundary/SCP interaction, temporary-credential exfiltration test, PostgreSQL catalog audit, or direct-table denial test has run. Effective permissions in the target account remain unproven.

#### AWS-U04 — Closed or out-of-scope assessments could receive new evidence

- **Severity:** High
- **Confidence:** High
- **Classification:** Confirmed authorization/business-state vulnerability at review; remediated in current source; live validation open
- **Affected files/functions:** `infra/aws/database/001_tenant_schema.sql` (`scopeproof.create_upload_intent`), `infra/aws/cdk/runtime/tenant-api/index.ts` (membership-authorized upload issuance), and `lib/aws-runtime/evidence/upload-intent-database.ts` (procedure adapter)
- **Description and code evidence:** The pre-remediation write path did not make assessment lifecycle and configured control scope part of the authoritative upload transaction. `create_upload_intent` now selects the exact tenant assessment `FOR SHARE`, accepts only `DRAFT` or `ACTIVE`, rejects a closed assessment, rejects an empty control scope, and requires `p_control_id` to be explicitly present. These checks occur before an existing idempotent intent can be returned, so a replay cannot bypass the current assessment state or control mapping.
- **Exploitation scenario:** A malicious or stale client submits evidence to an already closed assessment, or chooses a valid tenant control that is not included in the target assessment. Without the in-transaction lock and scope check, it could alter the apparent evidence set after sign-off or pollute an auditor-facing package with unrelated artifacts.
- **Potential impact:** Unauthorized post-close changes, misleading audit packages, broken reviewer sign-off, and loss of assessment/control integrity.
- **Recommended fix / patch guidance:** Resolve the target assessment inside the same tenant-scoped database procedure that creates the intent. Lock it against concurrent lifecycle changes, fail closed unless its status permits collection, and validate the control against the assessment's explicit scope before idempotent recovery or insertion. Keep the assessment ID and control ID bound into the signed/presigned upload contract and subsequent promotion receipt.
- **Tests and validation:** `tests/aws-postgres.test.ts` asserts the status rejection, `assessment_controls ? p_control_id`, and `FOR SHARE` lock in the procedure. Add live two-session PostgreSQL tests for close-versus-upload races in both lock orders, empty-scope policy tests, DRAFT/ACTIVE acceptance tests, out-of-scope rejection, and verification that rejected calls leave no intent/evidence rows.
- **CWE / OWASP:** CWE-862 (Missing Authorization), CWE-840 (Business Logic Errors), OWASP API5:2023 (Broken Function Level Authorization)
- **Residual validation status:** The repository test is a structural SQL assertion, not a live isolation/locking proof. No deployed Aurora concurrency, deadlock/retry, close-state transition, or auditor-package reconciliation test has run.

### Current dependency-packaging clarification — 2026-08-27

The original AWS-11 and dependency-risk text below records the baseline, when
Lambda assets depended on runtime-supplied SDK availability. In the current
branch, direct AWS SDK/CDK/esbuild/TypeScript dependencies are exact-version
pinned in `infra/aws/cdk/package.json` and resolved by `pnpm-lock.yaml`. The
workspace enforces pnpm's 24-hour minimum release age without package-specific
exceptions, so newly published dependency versions cannot silently bypass the
repository's quarantine window. The tenant API, legal-hold API/worker, tenant
provisioner, evidence promoter, Aurora
recovery-freshness monitor, and evidence recovery reconciler are CDK
`NodejsFunction` assets with `externalModules: []`. That materially reduces
runtime drift, but it is not a complete supply-chain closure: production still
requires lockfile-frozen installation, vulnerability/license review, SBOM and
provenance generation, artifact signing/attestation verification, and a
deployed-bundle hash comparison.

### Review-time defects corrected before this report was finalized

- Native production S3 now rejects long-lived manual credentials and supports
  only temporary IAM Identity Center profile or one-hop SSO `AssumeRole`
  credentials. Manual static keys remain an explicitly non-production,
  Keychain-backed compatible-S3 fallback.
- AWS CLI execution uses only reviewed absolute executable roots, fixed argument
  arrays without a shell, a minimal allowlisted environment, bounded output,
  command/login deadlines, cancellation, and terminate/kill cleanup. It rejects
  `credential_process`, static/source/web-identity profiles, and role chaining.
- Production bucket verification always reads policy, lifecycle, and replication.
  It accepts the exact generated deny-only policy, requires lifecycle/replication
  to be absent when disabled, and otherwise requires the exact configured XML;
  extra cross-account Allows, expiration rules, or replication rules fail closed.
- The native bucket is now provisioned by a retained, fixed CloudFormation
  resource rather than a temporary operator permission that could rewrite bucket
  policy/lifecycle/replication. Its enforcement policy is retained with the
  bucket, and DSSE-KMS omits the unsupported Bucket Key setting. The daily
  Identity Center permission set has no bucket-administration actions.
- Direct-S3 CloudFormation uses a tenant-dedicated admin-only TOTP Cognito pool,
  app-bound S3 Access Grants directory identities with isolated `sts:SetContext`,
  explicit outside-prefix object-read and bucket-list Denies, and no unsupported
  S3 encryption-context condition key. No template creates an IAM user or access
  key.
- Hosted evidence listing/download now uses a dedicated execute-only PostgreSQL login
  and a dedicated rotating cursor HMAC. It reconstructs the canonical object key
  from tenant/control/evidence/MIME facts before signing one exact immutable S3
  version, preventing identifier-collision and MIME/extension drift.
- Tenant activation now verifies `NOINHERIT` on all six application logins and
  requires zero `pg_auth_members` edges involving any managed owner/application
  role before and after the temporary administrator-to-owner migration grant.
- Tenant activation now binds the digest of all eight packaged SQL files to an
  ordered digest of the live `scopeproof` function and index definitions in the
  database itself, then recomputes and checks that marker before activation.
  Application-role verification also covers migration metadata tables, not only
  tenant data tables.
- PostgreSQL owner/runtime names now include the full opaque tenant-ID suffix, eliminating collisions between long slugs with the same prefix.
- Tenant stack updates move registry rows back to `PROVISIONING`, reject updates during an active provisioning lease, and require the verification workflow to run again.
- The retained Aurora cluster now uses an explicitly retained, customer-managed-KMS-encrypted administrator secret; its narrowly conditioned provisioner grants avoid a cross-stack policy cycle.
- The provisioner supplies PostgreSQL a SCRAM-SHA-256 verifier rather than placing the reusable runtime password in SQL that could be copied into error logs.
- The Mac Local Console no longer treats an S3 key/evidence-ID match as provenance. `Local + S3` requires an exact local upload receipt; S3-only inventory is lifecycle-invalid and visibly unverified, and preview requires a paired exact-version manifest plus matching PNG digest and bounded dimensions.

### Confirmed controls already implemented

These are code-confirmed controls, not claims of deployed effectiveness:

- Tenant IDs and resource IDs are opaque, bounded, and reject ambiguous legacy identifiers in `infra/aws/cdk/lib/config.ts`, `lib/aws-runtime/contracts.ts`, and `infra/aws/database/001_tenant_schema.sql`.
- `TenantDirectory.resolve`, `authorizeTenantActor`, `tenantQueryGuard`, and `assertTenantOwned` fail closed on unknown/inactive domains, inactive tenants, missing membership, wrong-tenant rows, and insufficient roles.
- Every tenant database is separate; tenant-bearing tables use composite tenant foreign keys, `ENABLE ROW LEVEL SECURITY`, `FORCE ROW LEVEL SECURITY`, and a database-identity trigger. The provisioner verifies six purpose-specific non-owner/NOBYPASSRLS/NOINHERIT application roles, zero managed-role membership edges, their exact function allowlists, and a wrong-tenant write denial before activation.
- Deploy-time SQL identifiers are narrowly allowlisted. Ordinary values use RDS Data API parameters. The generated runtime password is validated in memory and converted to a PostgreSQL-native SCRAM-SHA-256 verifier before it enters CREATE/ALTER ROLE SQL, preventing the reusable plaintext from appearing in PostgreSQL failure logs. The migration parser processes trusted bundled migrations, not user-supplied SQL.
- S3 buckets block public access, enforce TLS, use bucket-owner-enforced ownership, are versioned, and use a per-tenant KMS key. The immutable bucket has Object Lock; the quarantine bucket expires objects and incomplete multipart uploads. Every retained CDK data bucket retains its enforcement bucket policy so stack deletion cannot silently remove the TLS/immutability perimeter while preserving data.
- The tenant application role can write only the exact quarantine prefix with the expected KMS headers/context and cannot write, delete, or shorten retention in the evidence bucket.
- `runtime/promote-evidence/index.mjs` binds a clean scan to account, region, malware plan, bucket, tenant, opaque key, object version, ETag, SHA-256 checksum, byte size, MIME type, upload intent, KMS context, and retention date. A durable attempt ledger plus monotonic DynamoDB/PostgreSQL fences blocks stale reconciliation; an exact-version `GetObject` followed by single-attempt `PutObject` with `If-None-Match: *` makes destination creation single-winner even if an older worker resumes after takeover. Signed facts preserve the actual copy attempt/fence separately from the current reconciliation attempt/fence.
- WAF rejects unknown hosts and oversized request bodies, applies AWS managed rules and per-IP rate limits, and redacts authorization/cookie headers in retained blocked-request logs.
- Cognito disables self-sign-up, requires MFA, uses 14-character complex passwords, enables token revocation, hides user-existence errors, and creates separate public web/native clients without client secrets.
- The Mac primitives use authorization code plus S256 PKCE, high-entropy state/nonce/verifier values, exact callback matching, canonical public HTTPS endpoints, one-shot state, and a `WhenUnlockedThisDeviceOnly` Keychain item for the refresh token. Access and ID tokens are designed to remain in memory.
- CloudTrail is multi-region, includes global service events and file validation, sends logs to a KMS-encrypted Object-Locked bucket, and records exact S3 data events for tenant ingest/evidence buckets.

## 2. System Overview and Trust Boundaries

Sections 2–6 preserve the original review-time architecture, findings, and
attack chains as historical evidence. Where those sections say an adapter,
route, legal hold, signature, or recovery control was absent, that statement is
the dated baseline—not the current branch. Sections 7–11 and the remediation
addendum describe the current source state. Production closure still requires
the addendum's live validation.

### Intended architecture

1. Route 53 assigns one explicit hostname per tenant, such as `acme.<owned-domain>`; wildcard tenant DNS is not created.
2. AWS WAF filters hostnames, large bodies, common attacks, bad IP reputation, and per-IP request rate before Amplify SSR.
3. Cognito authenticates humans through a shared user pool and a tenant-specific public app client. The intended server adapter validates the access token and resolves a tenant membership.
4. DynamoDB is the shared control plane for exact hostname-to-tenant routing, tenant provisioning state, and upload/promotion coordination.
5. The shared Amplify SSR role and worker role assume a per-tenant IAM data role after authorization.
6. Aurora PostgreSQL stores each tenant in a separate database. A separate NOLOGIN owner owns the database boundary; the application role is LOGIN, non-owner, NOSUPERUSER, NOCREATEROLE, NOCREATEDB, NOREPLICATION, and NOBYPASSRLS. Forced RLS and a one-row database identity provide a second tenant check.
7. Uploads enter a tenant quarantine bucket through a future exact presigned PUT. GuardDuty scans the exact version. A Lambda validates the authoritative intent and scan receipt before copying to an Object-Locked evidence bucket.
8. CloudTrail, CloudWatch, SQS DLQs, SNS, budgets, and cost-anomaly detection provide infrastructure observability.
9. The Mac application will use Cognito OAuth/PKCE and a hosted API. The current local capture and loopback console remain independent and local-only.

### Principal trust boundaries

- **Internet to WAF/Amplify:** Host, path, query, headers, cookies, authorization values, body, request size, source IP, and timing are attacker controlled.
- **Browser to Cognito and callback:** OAuth state, code/error response, callback delivery, user-entered email, and browser session are untrusted until cryptographic verification and state/nonce validation complete.
- **Mac to hosted API:** The Mac and bearer token can be compromised. The server must never trust a client-supplied tenant ID, role, upload key, S3 receipt, checksum, or `signatureVerified` marker.
- **Shared control plane to tenant data plane:** Host resolution, membership, assumed-role selection, database name/secret, S3 bucket/key, and KMS ARN must all resolve from the same authoritative tenant record.
- **Presigned upload to quarantine:** File bytes, MIME declaration, length, checksum claim, upload timing, multipart behavior, metadata, tags, and replay attempts are untrusted.
- **EventBridge/SQS to promotion Lambda:** Queue bodies are data, not authority. Only a validated AWS-origin event plus an authoritative intent and live S3 facts may cause promotion.
- **Application to PostgreSQL:** Application bugs and SQL injection are assumed possible. RLS limits tenant crossing, but the current runtime role still has substantial within-tenant mutation authority.
- **AWS operators and CI/CD:** Administrators, deployment roles, compromised dependencies, and malicious build inputs can change infrastructure, Lambda assets, release artifacts, or retention configuration.

### High-value assets

- Customer evidence bytes, screenshots, SBOMs, exports, checksums, metadata, review/approval state, and retention/hold state.
- Cognito identities, tenant memberships, refresh tokens, device identities, integration credentials, RDS secrets, and KMS keys.
- Tenant/domain registry, upload intents, promotion receipts, database identity, and IAM role mappings.
- Audit events, audit heads, CloudTrail files, log groups, alarms, release artifacts, and signing keys/attestations.

## 3. Threat Model

### Attacker personas

- An unauthenticated Internet attacker probing tenant domains, Cognito, WAF bypasses, large requests, SSRF, callback manipulation, and cost exhaustion.
- A legitimate low-privilege tenant collector or auditor attempting IDOR, role escalation, approval forgery, destructive retention actions, or access to another customer.
- A compromised Mac or stolen refresh token attempting replay, tenant switching, arbitrary S3 writes, or forged evidence receipts.
- A malicious file supplier attempting parser exploitation, malware delivery, content-type confusion, checksum mismatch, decompression abuse, or scan/promotion races.
- A compromised shared SSR process, job worker, Lambda execution role, or CI dependency attempting to pivot across every tenant.
- A malicious or compromised AWS administrator attempting to bypass governance retention, alter logs, replace release artifacts, or exfiltrate database/evidence data.
- An operator making a plausible configuration mistake: using the placeholder domain, enabling the clean rule early, omitting alert recipients, assigning the wrong tenant role, or deploying the legacy runtime.

### Likely attack paths

1. **Cross-tenant web access:** reach tenant B through tenant A's session or host header, then exploit global legacy tables/bucket keys or a missing tenant predicate.
2. **Identity forgery:** submit a decoded but unsigned JWT, wrong Cognito client token, stale token, or a client-supplied `signatureVerified: true` object to an incomplete adapter.
3. **Shared-role pivot:** obtain shared SSR/worker credentials and call `sts:AssumeRole` for every `sp-*-data` tenant role.
4. **Evidence substitution:** upload different bytes/version after intent creation, spoof a queue event, reuse a clean event, alter content type/size, or redirect the final S3 key.
5. **Audit forgery:** use the general runtime database credential to insert arbitrary audit/receipt rows containing syntactically plausible but unverified signature strings.
6. **Separation-of-duties bypass:** directly mutate membership, approval, retention, or support-grant rows through a vulnerable route or SQL injection.
7. **Persistence/destruction:** compromise an AWS administrator or deployment role, bypass GOVERNANCE retention, change KMS/bucket policy, or deploy a malicious Lambda/release.
8. **Operational evasion:** exploit missing alert subscribers or unlogged DynamoDB writes so tenant mappings or upload intents change without timely detection.

## 4. Attack Surface Inventory

The inventory below is the original review snapshot. The new per-tenant API,
upload-intent route, KMS receipt path, two-person hold states, global control
table, and recovery backfill are summarized in the addendum; they have not been
deployed.

| Surface | Entry points | Attacker-controlled inputs | Present controls | Material gaps |
|---|---|---|---|---|
| Tenant web edge | root and explicit tenant hostnames through WAF/Amplify | Host, URL, headers, body, cookies, IP | exact-host WAF, managed rules, 64 KiB body bound, IP rate rule | no hosted API implementation; no authenticated user/tenant rate limit |
| Cognito | `auth.<domain>`, tenant app clients, `/auth/callback` | credentials, MFA attempts, OAuth request/callback | required MFA, no self-signup, public-client code flow, revocation | server JWT/JWKS verifier and Mac token exchange are absent; Cognito domain is not associated with this WAF |
| Mac OAuth callback | custom URL callback | callback URL/query, code/error/state | exact callback, PKCE, random state/nonce, one-shot transaction | custom scheme UI registration and token/JWKS validation absent; signed discovery absent |
| Tenant registry | DynamoDB `TENANT#...` and `DOMAIN#...` | deployment context and future onboarding API | strict ID/slug/domain validation; transactional registration/provision status | no onboarding API authorization; DynamoDB data events omitted from trail |
| PostgreSQL | RDS Data API, tenant database secret | SQL parameters, session tenant setting, business mutations | separate DBs, forced RLS, identity trigger, non-owner runtime, timeouts | broad within-tenant mutation grants; business actor is not DB-bound |
| Quarantine upload | future presigned S3 PUT | bytes, type, size, checksum, key, timing | exact prefix/IAM KMS context, versioning, lifecycle, GuardDuty | issuer/presigner not implemented; clean rule disabled |
| Malware promotion | EventBridge -> SQS -> Lambda | event envelope and referenced S3 object | AWS identity fields, exact plan/bucket/key/version, live tag/head/checksum, CAS | event schema not validated against a live account; limited diagnostic logging |
| Evidence storage | S3 GET/HEAD and future delete/hold flows | key/version requests | private bucket, exact prefix, KMS, Object Lock, versions | S3 legal hold adapter absent; governance default; no replication |
| Jobs | shared and tenant SQS/DLQ | future job envelope and retries | bounded pure transitions, leases, idempotency, DLQs, alarms | worker adapter and persisted CAS not implemented |
| Audit/monitoring | DB audit chain, CloudTrail, WAF/Step Functions/Lambda logs | event details, AWS API activity | canonical hashing, forced append order, Object-Locked trail | KMS business signature adapter absent; runtime may insert; DDB data events missing; subscribers optional |
| Release channel | private S3 origin + public CloudFront hostname | release object paths and deployment artifacts | OAC, TLS 1.2+, versioning, access logs, response headers, WAF | artifact signature/provenance enforcement is outside this stack |

## 5. Prioritized Findings

### AWS-01 — The legacy web runtime is single-tenant and must not serve AWS tenant hostnames

- **Severity:** Critical
- **Confidence:** High
- **Classification:** Confirmed deployment hazard; not an active deployed vulnerability
- **Affected files/functions:** `lib/server/env.ts` (`ScopeproofEnv`, `getEnv`); `lib/server/auth.ts` (`AuthenticatedUser`, `requireApiUser`); existing `app/api/**` handlers; `infra/aws/cdk/lib/shared-platform-stack.ts` (`CfnApp`, `CfnBranch`)
- **Description:** The existing server binds one global D1 database and R2 bucket. `AuthenticatedUser` contains no tenant ID or membership ID, and `requireApiUser` loads a global `users` row by user ID. The existing API handlers use that global model. The new AWS tenant contracts are not imported by `app` or `lib/server`. Meanwhile, the Amplify app has no repository connected, no AWS runtime adapter, and automatic builds are disabled. The legacy application cannot safely be placed behind multiple customer hostnames.
- **Evidence from code:** `ScopeproofEnv` exposes `DB: D1Database` and `EVIDENCE_BUCKET: R2Bucket` with no tenant binding. `AuthenticatedUser` is `{ id, email, displayName, role }`. `requireApiUser` queries `users WHERE id = ?` without a tenant key. A repository search finds the new `lib/aws-runtime` exports only in their own module/tests, not in hosted routes. `SharedPlatformStack` creates an empty Amplify `CfnApp`/`CfnBranch` and sets `enableAutoBuild: false`.
- **Exploitation scenario:** An operator connects the current repository to Amplify and enables `client-a.example` and `client-b.example`. A user authenticated on client A calls evidence, users, Jira, or package APIs. Because the application resolves global users and global data rather than an authoritative hostname/membership tenant, it can return or mutate the shared workspace, including client B's records.
- **Potential impact:** Cross-tenant evidence disclosure and alteration, integration-token misuse, auditor package contamination, privacy breach, and loss of all customer isolation claims.
- **Recommended fix:** Treat the legacy application and AWS hosted application as separate deployment targets. Do not point tenant DNS at any build until every API uses a single server-side boundary: trusted exact host -> active tenant record -> cryptographically verified Cognito access token -> active tenant membership -> permission -> exact tenant role/database/bucket. Tenant IDs must never be selected from request bodies or query strings. Every row, cache key, job, audit event, and S3 operation must be tenant bound.
- **Example secure patch guidance:** Add an AWS request-context factory that accepts the raw request and bearer token, performs host lookup and JWT verification internally, loads `membership(tenant_id, cognito_sub)`, and returns an opaque `TenantActor`. Make data repositories require that context rather than an optional tenant parameter. Use separate AWS route implementations; do not add fallback to D1/R2 when AWS resolution fails.
- **Validation:** Run a two-tenant adversarial matrix against every endpoint. Reuse tenant A IDs, cookies, access tokens, presigned URLs, job IDs, S3 keys, and host headers against tenant B. Each response must be an indistinguishable 404/403 and must produce no cross-tenant AWS API call. Verify the direct Amplify hostname and spoofed `X-Forwarded-Host` are blocked.
- **CWE/OWASP:** CWE-639 (Authorization Bypass Through User-Controlled Key), CWE-862 (Missing Authorization), OWASP ASVS V4, OWASP API1:2023 Broken Object Level Authorization.

### AWS-02 — Cryptographic JWT verification and the hosted OAuth network flow are absent

- **Severity:** High
- **Confidence:** High
- **Classification:** Production blocker
- **Affected files/functions:** `lib/aws-runtime/tenancy.ts` (`AuthenticatedPrincipal`, `validatePrincipal`, `authorizeTenantActor`); `macos/ScopeproofCapture/Sources/ScopeproofCapture/HostedOAuth.swift` (`HostedOAuthCoordinator`, `HostedOAuthAuthorizationGrant.tokenRequest`); `HostedTokenStore.swift`; `HOSTED_AUTHENTICATION.md`; `infra/aws/cdk/lib/tenant-stack.ts` (`TenantWebClient`)
- **Description:** The TypeScript boundary accepts an object containing `signatureVerified: true`; it does not verify a JWT. The comment correctly assigns verification to a future adapter, but TypeScript types do not exist at runtime and a boolean from decoded client JSON would satisfy this check. The Mac creates safe OAuth/PKCE requests but intentionally does not execute the token exchange, validate redirects/response bounds, retrieve JWKS, verify JWT signatures/claims or nonce, refresh/revoke tokens, or enroll a device. There is no server endpoint implementing those duties.
- **Evidence from code:** `validatePrincipal` checks the supplied boolean, issuer, audience, token use, auth time, and expiry, but performs no signature operation and imports no JOSE/JWT library. `HostedOAuthAuthorizationGrant.tokenRequest()` only constructs a request. `HOSTED_AUTHENTICATION.md` explicitly lists token execution, JWKS/JWT validation, refresh/revocation, signed discovery, and server membership as unfinished.
- **Exploitation scenario:** During integration, a route deserializes a caller-provided principal object or decodes JWT claims without verifying the signature, then sets or preserves `signatureVerified: true`. An attacker creates an arbitrary user ID and audience, selects a privileged membership or exploits a weak membership lookup, and obtains tenant access. On the Mac, an unverified token response or malicious discovery configuration could redirect tokens to an attacker-controlled public HTTPS origin.
- **Potential impact:** Authentication bypass, account takeover, privilege escalation, stolen refresh tokens, and cross-tenant access.
- **Recommended fix:** Implement one server-owned Cognito JWT verifier that accepts only the raw bearer string. Pin the configured user-pool issuer and exact per-tenant client ID; verify `alg`, signature, `kid` through bounded/rotating JWKS cache, `iss`, `client_id`/audience, `token_use=access`, `exp`, `iat`, and authentication age. Construct the verified principal inside a non-exported factory and never deserialize it. On macOS, use `ASWebAuthenticationSession`, reject token-endpoint redirects, limit response bytes/content type, verify the ID-token nonce and all JWT claims, rotate/revoke refresh tokens, and obtain tenant configuration through an authenticated signed channel.
- **Example secure patch guidance:** Expose `authenticateBearer(request, resolvedTenant)` rather than `validatePrincipal(inputObject)`. Its output should carry a module-private symbol that cannot arrive over JSON. Cache Cognito JWKS by fixed issuer, reject unknown algorithms and duplicate JSON keys, and force one refresh on an unknown `kid` before failing. Bind membership by `(tenant_id, cognito_sub)`; email domain is routing metadata only.
- **Validation:** Negative-test unsigned/`none` tokens, algorithm confusion, wrong issuer, wrong app client, ID token used as access token, expired/future/stale tokens, reused nonce, duplicate JWT fields, unknown/rotated `kid`, oversized JWKS/token responses, redirects, malicious discovery origins, and revoked/suspended memberships. Verify access/ID tokens never persist to disk, logs, crash reports, defaults, or Keychain.
- **CWE/OWASP:** CWE-287 (Improper Authentication), CWE-345 (Insufficient Verification of Data Authenticity), CWE-613 (Insufficient Session Expiration), OWASP ASVS V2, OWASP API2:2023 Broken Authentication.

### AWS-03 — Shared AWS roles and per-tenant provisioners retain broad cross-tenant blast radius

- **Severity:** High
- **Confidence:** High
- **Classification:** Confirmed architectural defense gap
- **Affected files/functions:** `infra/aws/cdk/lib/shared-platform-stack.ts` (`amplifyComputeRole`, `jobWorkerRole`, `tenantDataRolePattern`); `infra/aws/cdk/lib/tenant-stack.ts` (`tenantDataRole`, `TenantProvisioner`, `databaseAdminSecret` grants)
- **Description:** Both shared runtime roles may assume every role matching `role/scopeproof/tenants/sp-*-data`. Each tenant role trusts those same shared principals without a tenant-bound session-tag or broker proof. Separately, every tenant provisioning Lambda can read the shared Aurora cluster administrator secret and execute Data API operations across the cluster. Per-tenant S3/DB role permissions protect ordinary requests, but compromise of a shared role or any provisioner has a much larger blast radius.
- **Evidence from code:** `tenantDataRolePattern` contains `sp-*-data`; both shared roles receive `sts:AssumeRole` on it. Each `TenantDataRole` uses a `CompositePrincipal` containing the shared roles. Each per-tenant `TenantProvisioner` receives explicit RDS Data API permissions, narrowly scoped Secrets Manager/KMS decrypt permissions for the retained administrator secret, and that secret ARN in its environment. Those grants still permit cluster-administrator operations by design.
- **Exploitation scenario:** A dependency or SSR bug yields credentials for `AmplifyComputeRole`; the attacker enumerates tenant metadata from the shared table and assumes every tenant data role. Alternatively, code execution in one provisioner retrieves the cluster admin secret and reads or changes all tenant databases despite per-database runtime restrictions.
- **Potential impact:** Full cross-tenant evidence/metadata exfiltration, tenant registry manipulation, database takeover, persistent compromise, and destruction of the isolation model.
- **Recommended fix:** For the highest assurance, place tenants in separate AWS accounts or isolate tenant API/worker execution roles so a compromised shared process cannot freely select a tenant. At minimum, introduce a narrowly scoped authorization broker that is the only principal allowed to assume tenant roles, issues a session policy for one exact tenant resource set, records every issuance, and cannot access data itself. Use IAM role tags and enforced session tags as an additional check, but do not treat caller-selectable tags as protection from a fully compromised shared role. Move database bootstrap to one central provisioner with a narrow stored procedure or dedicated bootstrap credential; remove/disable tenant provisioner admin access after activation and rotate credentials.
- **Example secure patch guidance:** Remove wildcard `sts:AssumeRole` from the Amplify role. Route authorized work to a tenant-specific Lambda/role ARN resolved from a signed server-side registry, or use a broker whose policy is generated for one exact ARN and whose caller cannot choose `TenantId`. Replace general cluster-admin Data API access with a bootstrap stored procedure that accepts validated tenant metadata and cannot query existing tenant schemas/data.
- **Validation:** With credentials for the shared SSR role, job worker, one tenant data role, and one provisioner in turn, attempt to assume/read/write every other tenant role, database, secret, KMS key, quarantine bucket, and evidence bucket. IAM simulation and live canaries must deny all unintended paths. Verify active tenants remain available after the provisioning function is disabled.
- **CWE/OWASP:** CWE-250 (Execution with Unnecessary Privileges), CWE-269 (Improper Privilege Management), CWE-284 (Improper Access Control), OWASP ASVS V1/V4.

### AWS-04 — Privileged tenant actions rely on future application authorization while the database role can write security state directly

- **Severity:** High
- **Confidence:** High
- **Classification:** Production blocker / defense-in-depth gap
- **Affected files/functions:** `infra/aws/database/002_runtime_role.sql`; `infra/aws/database/001_tenant_schema.sql` (`memberships`, `evidence_artifacts`, `retention_holds`, `support_access_grants`); `lib/aws-runtime/tenancy.ts` (`assertActorPermission`)
- **Description:** RLS correctly prevents crossing the database tenant boundary, but the single runtime role receives direct `SELECT, INSERT, UPDATE` on membership, device, assessment, integration, job, upload, evidence, retention, export, and support-grant tables. Database constraints require distinct principal IDs for some approval actions, but they do not establish which authenticated actor executed the statement or prove that the second person approved it. `memberships` can be updated directly and is not covered by an immutable-state trigger. The intended RBAC exists only as pure TypeScript functions that no API currently invokes.
- **Evidence from code:** `002_runtime_role.sql` grants broad writes to all listed security-state tables. `retention_holds` checks `created_by <> approved_by`; evidence approval checks `approved_by <> created_by`; neither binds a database session actor. `support_access_grants` similarly accepts an `approved_by` row reference. `assertActorPermission` is not imported by the existing hosted routes.
- **Exploitation scenario:** A SQL injection or missing route-level permission in one future endpoint runs under the tenant runtime credential. The attacker upgrades their membership to admin, creates a support grant naming another user as approver, or approves their own evidence by supplying a different existing principal ID. Forced RLS keeps the attack within one tenant but does not preserve role or separation-of-duties guarantees.
- **Potential impact:** Within-tenant privilege escalation, fraudulent evidence approval, forged dual control, unauthorized integrations/exports, and compliance-report integrity loss.
- **Recommended fix:** Revoke direct runtime writes to memberships, approvals, support grants, and retention decisions. Expose narrowly scoped `SECURITY DEFINER` procedures owned by a NOLOGIN security owner, with a fixed `search_path`, explicit actor/membership parameters sourced from verified server context, current-state/revision checks, and append-only audit writes in the same transaction. Prefer separate database roles for ordinary reads/collection, review/approval, and background promotion where practical.
- **Example secure patch guidance:** Set a transaction-local `scopeproof.actor_user_id` only from the authenticated adapter, then have `approve_evidence(evidence_id, rationale)` verify the active reviewer/admin membership, reject creator=actor, write approval plus a KMS-signing outbox entry, and expose no direct `UPDATE` on `evidence_artifacts`. Apply the same model to `change_membership_role`, `grant_support_access`, and `release_hold`.
- **Validation:** Connect as the runtime role and prove direct `UPDATE memberships`, direct evidence approval, direct support-grant insertion, and direct hold release are denied. Then test each stored procedure with collector/auditor/reviewer/admin roles, suspended memberships, creator-as-reviewer, stale revisions, forged actor settings, and concurrent requests.
- **CWE/OWASP:** CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-285 (Improper Authorization), OWASP API5:2023 Broken Function Level Authorization.

### AWS-05 — The secure upload issuer is absent and clean-object promotion is disabled

- **Severity:** High
- **Confidence:** High
- **Classification:** Production blocker; current disabled state is fail closed
- **Affected files/functions:** `infra/aws/cdk/lib/tenant-stack.ts` (`CleanMalwareScanResult`, `EvidencePromoter`); `runtime/promote-evidence/index.mjs` (`parseIntent`, `claimIssuedIntent`, `validateHeadAgainstIntent`, `completePromotion`); `lib/aws-runtime/upload.ts` (`issueUploadIntent`, `UploadStateRepository`)
- **Description:** The promotion worker is strongly validated, but no authenticated API creates its exact DynamoDB `UploadLifecycle` item, persists it with atomic semantics, produces an exact presigned PUT, or reconciles durable PostgreSQL evidence rows. The pure `UploadStateRepository` is only an interface. The clean GuardDuty event rule is intentionally `DISABLED`, so legitimate evidence cannot currently advance. Manually enabling the rule or implementing a permissive presigner would bypass the intended launch gate.
- **Evidence from code:** The stack sets `enabled: false` on `CleanMalwareScanResult`. `parseIntent` requires a precise camel-case DynamoDB item and revision/status contract, but there is no issuer Lambda/API or role with the corresponding conditional write. No production adapter implements `UploadStateRepository` or imports `issueUploadIntent`. The promoter does not create the authoritative PostgreSQL `evidence_artifacts`/`ingest_receipts` records.
- **Exploitation scenario:** Under release pressure, an operator enables clean promotion and adds a generic presigned `PutObject` route without binding tenant, actor, exact key, checksum, size, MIME, KMS context, TTL, and retention. A malicious client uploads substituted bytes, reuses a URL, writes an unexpected key/version, or causes clean bytes to be associated with another evidence record. A less dangerous current outcome is that every valid upload fails or accumulates in the DLQ.
- **Potential impact:** Evidence substitution, malicious-file promotion, cross-record contamination, replay, unbounded storage/cost, or total ingestion outage.
- **Recommended fix:** Implement the issuer as an authenticated tenant operation with `evidence:collect`. Generate opaque IDs and a high-entropy nonce server-side; calculate exact quarantine/final keys; require one supported MIME, 1–25 MiB length, lowercase SHA-256, <=10 minute expiry, and required retention. Write the DynamoDB lifecycle item with `attribute_not_exists` and an idempotency key before generating an exact single-object presign. Require signed checksum, content type, KMS key/context, and length constraints. After promotion, atomically reconcile PostgreSQL evidence/receipt/audit state. Enable the clean rule only after capturing the actual GuardDuty event schema in a staging account and passing end-to-end tests.
- **Example secure patch guidance:** The API should return `{intentId, uploadUrl, requiredHeaders, expiresAt}` only. It must not accept an S3 key/bucket/KMS ARN from the client. Use an IAM principal that can write only `TENANT#<resolved tenant>/UPLOAD#...`, and a DynamoDB condition on absent PK/SK and nonce digest. Keep the promoter as the only principal able to write immutable evidence objects.
- **Validation:** Test wrong tenant/resource IDs, path traversal/encoding, unsupported MIME, multipart and oversize uploads, missing/wrong checksum, KMS/header substitution, expired/replayed URLs, alternate object versions, spoofed EventBridge/SQS bodies, changed ETag, absent GuardDuty tag, threat/unsupported/denied scans, duplicate delivery, concurrency, copy-success/database-failure retry, and DLQ redrive. Use the standard harmless EICAR test file only in an isolated non-production tenant.
- **CWE/OWASP:** CWE-434 (Unrestricted Upload of File with Dangerous Type), CWE-367 (TOCTOU Race Condition), CWE-345 (Insufficient Verification of Data Authenticity), OWASP ASVS V12, OWASP API6:2023 Unrestricted Access to Sensitive Business Flows.

### AWS-06 — Business audit and receipt signatures are placeholders rather than KMS-verifiable attestations

- **Severity:** High
- **Confidence:** High
- **Classification:** Confirmed integrity gap
- **Affected files/functions:** `lib/aws-runtime/audit.ts` (`createTenantAuditEvent`, `assertAuditContinuation`); `infra/aws/database/001_tenant_schema.sql` (`audit_events`, `advance_audit_head`, `ingest_receipts`); `infra/aws/database/002_runtime_role.sql`
- **Description:** The TypeScript audit contract computes a canonical SHA-256 chain but produces no digital signature. SQL requires `kms_signature` and receipt `signature` fields, yet validates only string length. The general tenant runtime role can insert both audit events and ingest receipts. No KMS asymmetric signing key, `kms:Sign` permission, signing service, or signature-verification path exists in the reviewed AWS code. The append trigger prevents reordering/removal through that role, but a compromised runtime can append arbitrary signed-looking events and receipts.
- **Evidence from code:** `createTenantAuditEvent` returns `eventHash` only. A search of the reviewed foundation finds no `kms:Sign`, `SignCommand`, or signature verifier. The SQL checks only `char_length(kms_signature) BETWEEN 40 AND 4096` and equivalent receipt length. `002_runtime_role.sql` grants `INSERT` on `audit_events` and `ingest_receipts`.
- **Exploitation scenario:** An attacker obtains tenant runtime SQL execution through an application flaw. They read the current audit head, compute the next hash for a fabricated `evidence.approved` or support event, supply 40 arbitrary characters as the signature, and insert it. The database accepts the record and advances the head. The attacker can likewise insert a fabricated ingest receipt referring to existing rows.
- **Potential impact:** False audit history, forged evidence provenance/approval, misleading assessor packages, repudiation disputes, and loss of compliance evidence credibility. Earlier events remain difficult to erase through the runtime role, but authenticity of new events is not established.
- **Recommended fix:** Create a dedicated asymmetric KMS signing key and a small audit-signing service/outbox worker. Only that service may call `kms:Sign` and insert finalized audit/receipt rows. Revoke direct runtime inserts. Sign a domain-separated canonical envelope containing tenant ID, sequence, event hash, key ARN/version, and schema version. Store the algorithm/key ARN/signature, verify it on read/export, and periodically checkpoint the head to the Object-Locked audit bucket or an independent trust domain.
- **Example secure patch guidance:** Business transactions should insert a bounded audit outbox record in the same DB transaction. A signer leases the row, locks `audit_heads`, computes the canonical event, calls `KMS Sign` using `ECDSA_SHA_256` or an approved RSA-PSS algorithm, verifies the returned signature locally, inserts the immutable event, and marks the outbox complete using compare-and-swap. Exports must fail closed if chain or signature verification fails.
- **Validation:** Attempt arbitrary/empty/wrong-key signatures, modified details, sequence gaps, duplicate sequence/hash, concurrent append, signer replay, KMS disabled/revoked key, key rotation, outbox retry, and compromised runtime direct insert. Independently verify every event and receipt from genesis with the public KMS key and compare checkpoints to CloudTrail/Object-Locked copies.
- **CWE/OWASP:** CWE-345 (Insufficient Verification of Data Authenticity), CWE-117 (Improper Output Neutralization for Logs), CWE-778 (Insufficient Logging), OWASP ASVS V7.

### AWS-07 — Database legal holds are not enforced with S3 Object Lock legal holds

- **Severity:** High
- **Confidence:** High
- **Classification:** Production blocker for legal-hold claims
- **Affected files/functions:** `lib/aws-runtime/retention.ts` (`placeLegalHold`, `releaseLegalHold`, deletion transitions); `infra/aws/database/001_tenant_schema.sql` (`retention_holds`); `infra/aws/cdk/lib/tenant-stack.ts` (evidence bucket and IAM permissions)
- **Description:** Legal hold is modeled in TypeScript and PostgreSQL, but no adapter invokes S3 `PutObjectLegalHold` for the exact evidence version and no reviewed role has `s3:PutObjectLegalHold`/`GetObjectLegalHold`. Default time-based Object Lock protects only until `retainUntil`. After that date, an AWS principal with delete/bypass capability can remove an object even while the database says an active legal hold exists.
- **Evidence from code:** `placeLegalHold` updates an in-memory record only. `retention_holds` stores logical state only. The evidence bucket has default Object Lock retention, but IAM policies contain no object-legal-hold actions and there is no AWS retention adapter.
- **Exploitation scenario:** Evidence is placed on legal hold near the end of its scheduled retention. The database shows the hold, but S3 retention expires. A compromised administrator, cleanup job, or future deletion worker deletes the exact version because S3 has no legal-hold bit. The database record and audit package falsely imply preservation.
- **Potential impact:** Destruction of litigation/audit evidence, regulatory noncompliance, spoliation risk, and inaccurate evidence-retention attestations.
- **Recommended fix:** Implement a dedicated legal-hold worker with least privilege to call `PutObjectLegalHold(ON/OFF)` on one exact tenant key/version. Placement is complete only after `GetObjectLegalHold` verifies `ON` and a signed receipt is persisted. Release must use dual authorization, verify the exact version, call `OFF`, verify the result, and audit it. A periodic reconciler must compare every active database hold with S3 and alarm/fail closed on drift.
- **Example secure patch guidance:** Add hold states `PENDING_ON`, `ACTIVE`, `PENDING_OFF`, `RELEASED`, revisions, provider request IDs, and failure fields. The worker IAM resource must be `evidenceBucket/tenants/<tenant>/evidence/*`; it must not have `DeleteObjectVersion` or `s3:BypassGovernanceRetention`.
- **Validation:** Test exact-version binding, duplicate/replayed hold commands, stale revisions, creator attempting self-release, S3 timeout after DB commit, DB timeout after S3 success, reconciliation drift, expired time retention with active legal hold, and compromised deletion worker. Confirm S3 itself denies deletion while hold is ON.
- **CWE/OWASP:** CWE-284 (Improper Access Control), CWE-672 (Operation on a Resource After Expiration or Release), OWASP ASVS V8.

### AWS-08 — Security alert delivery is optional and can silently have no recipient

- **Severity:** Medium
- **Confidence:** High
- **Classification:** Confirmed secure-default gap
- **Affected files/functions:** `infra/aws/cdk/lib/config.ts` (`validateAlertEmail`); `infra/aws/cdk/lib/shared-platform-stack.ts` (`operationsTopic`, alarms, budget/anomaly configuration); `infra/aws/cdk/lib/tenant-stack.ts` (malware/DLQ alerts); `infra/aws/cdk/lib/observability-stack.ts` (security alarms)
- **Description:** An absent `alertEmail` is accepted. In that case the encrypted SNS topic has no subscription, budget notifications have no subscribers, and no cost anomaly subscription exists. CloudWatch alarms can transition correctly while nobody is notified. Even with an email, SNS subscription confirmation is an external manual step that the stack does not verify.
- **Evidence from code:** `validateAlertEmail` returns `undefined` for empty input. The SNS subscription, budget subscribers, and anomaly subscription are all conditional on `props.alertEmail`.
- **Exploitation scenario:** The stack is deployed without an email or the confirmation is ignored. An attacker generates authorization failures, puts jobs in DLQs, triggers malware detections, or uses the root account. Events exist in AWS, but response is delayed because no operator receives them.
- **Potential impact:** Longer attacker dwell time, missed malware/ingestion failures, unbounded cost, and incomplete incident evidence.
- **Recommended fix:** Add an explicit production mode that refuses synthesis/deployment without at least one verified alert destination. Prefer an organization-managed SNS/PagerDuty/Security Hub destination over a single mailbox. Add a deployment canary and recurring alarm-delivery test; document SNS confirmation as a blocking step.
- **Example secure patch guidance:** Make `alertDestinationArn` or `alertEmail` required when `environment=production`. Output a deployment-blocking custom-resource check or post-deploy script that confirms at least one SNS subscription is `Confirmed`, then publish a test message and require acknowledgment in the runbook.
- **Validation:** Synthesis must fail for production with no destination. Test invalid/unconfirmed/disabled subscriptions, alarm actions, KMS access, malware alerts, DLQ alarms, root-use alarm, budget forecast/actual thresholds, and an end-to-end canary page.
- **CWE/OWASP:** CWE-778 (Insufficient Logging), CWE-223 (Omission of Security-Relevant Information), OWASP ASVS V7.

### AWS-09 — Immutable CloudTrail omits DynamoDB control-plane data events

- **Severity:** Medium
- **Confidence:** High
- **Classification:** Confirmed monitoring gap
- **Affected files/functions:** `infra/aws/cdk/lib/observability-stack.ts` (`Trail`, `addS3EventSelector`); `shared-platform-stack.ts` (`controlTable`); `runtime/provision-tenant/index.mjs`; `runtime/promote-evidence/index.mjs`
- **Description:** CloudTrail captures all management events and exact S3 object data events, but it does not select DynamoDB data events for the tenant/domain registry and upload/promotion records. `PutItem`, `UpdateItem`, and `TransactWriteItems` are DynamoDB data-plane activity and therefore need an explicit data-event selector for immutable CloudTrail coverage.
- **Evidence from code:** `ObservabilityStack` calls only `trail.addS3EventSelector` for ingest and evidence buckets. The control table is central to hostname routing, provisioning status, upload intent authority, and promotion receipts; both runtime Lambdas use DynamoDB transaction calls.
- **Exploitation scenario:** Compromised AWS credentials alter a domain mapping, tenant role ARN, provisioning status, upload intent, or promotion receipt. Application alarms may miss it, and the immutable CloudTrail bucket contains no item-level DynamoDB data event for forensic attribution.
- **Potential impact:** Harder detection and investigation of tenant-routing changes, forged upload authority, evidence-promotion tampering, and privileged control-plane abuse.
- **Recommended fix:** Add a CloudTrail advanced event selector for write-only DynamoDB data events on the exact control-table ARN; consider reads if the privacy/cost tradeoff is acceptable. Add Lambda invoke data events for security-critical workers if required by the audit policy. Create metrics/alarms for control-table writes by unexpected principals and periodic registry integrity snapshots.
- **Example secure patch guidance:** Add an exact DynamoDB data resource selector rather than `arn:aws:dynamodb:*:*:table/*`. Filter to write events and preserve them in the existing Object-Locked trail. Record approved deploy/provisioner/promoter principal ARNs and alert when `eventSource=dynamodb.amazonaws.com` plus the table ARN is used by anything else.
- **Validation:** Perform one expected and one deliberately unauthorized registry/intent write in staging. Confirm both appear in CloudTrail with principal, request ID, table ARN, key metadata permitted by AWS, log-file digest validation, and delivery to the immutable bucket. Confirm the unexpected-principal alarm fires.
- **CWE/OWASP:** CWE-778 (Insufficient Logging), CWE-223 (Omission of Security-Relevant Information), OWASP ASVS V7.

### AWS-10 — Governance retention, short metadata backup retention, and no cross-region recovery leave administrator/region risks

- **Severity:** Medium
- **Confidence:** High
- **Classification:** Design/continuity gap
- **Affected files/functions:** `infra/aws/cdk/lib/config.ts` (`validateTenant` default retention mode); `tenant-stack.ts` (`ObjectLockRetention`, evidence bucket); `shared-platform-stack.ts` (`Database` backup); `observability-stack.ts` (single-region audit resources)
- **Description:** Tenant retention defaults to `GOVERNANCE`, which authorized AWS identities with bypass permission can override. The reviewed runtime roles do not receive bypass permission, which is good, but account administrators remain in scope for a hostile high-risk environment. Aurora backup retention is seven days. Evidence, database snapshots, KMS keys, and the immutable trail have no cross-region or cross-account recovery design in this foundation.
- **Evidence from code:** `validateTenant` defaults `retentionMode` to `GOVERNANCE`; the tenant bucket uses that mode. Aurora specifies `backup.retention: 7 days`. No replication rule, backup vault, cross-account trail destination, or secondary-region key/bucket is created.
- **Exploitation scenario:** A compromised administrator bypasses GOVERNANCE retention, or a region/account incident makes the evidence bucket, KMS key, database metadata, and audit trail unavailable together. A customer discovers that evidence bytes may survive while approvals/index metadata outside the seven-day recovery point do not, or vice versa.
- **Potential impact:** Evidence loss/unavailability, inability to prove chain of custody, prolonged outage, and failure of customer retention/BCP commitments.
- **Recommended fix:** Make COMPLIANCE mode the documented default for regulated tenants after confirming its irreversible operational implications. Use SCPs and break-glass controls to deny bypass/deletion. Extend Aurora PITR to the approved period, add AWS Backup with Vault Lock, and design cross-account/cross-region replication for evidence and audit records with destination KMS keys. Test key-loss and restore procedures before claiming recovery objectives.
- **Example secure patch guidance:** Introduce explicit `environment` and `assuranceTier` configuration. For production high assurance, require `COMPLIANCE`, 35-day Aurora PITR, cross-account audit archive, and a tested backup plan; reject synth if destinations/keys are absent. Keep immutable primary and replica retention settings consistent.
- **Validation:** Attempt governance bypass with every runtime/operations role, then test compliance-mode immutability. Restore a tenant database to a point in time, recover an exact evidence version and audit checkpoint in a secondary account/region, validate hashes/signatures, and measure RPO/RTO.
- **CWE/OWASP:** CWE-284 (Improper Access Control), CWE-693 (Protection Mechanism Failure), OWASP ASVS V8/V14.

### AWS-11 — Lambda dependency provenance and failure diagnostics need hardening

- **Severity:** Low
- **Confidence:** Medium
- **Classification:** Defense in depth; the AWS-managed runtime dependency behavior requires live verification
- **Affected files/functions:** `infra/aws/cdk/package.json`, `pnpm-lock.yaml`; `tenant-stack.ts` (`Lambda.Code.fromAsset`); `runtime/promote-evidence/index.mjs` (`handler`); `runtime/provision-tenant/index.mjs` (`handler`); Amplify `buildSpec`
- **Description:** CDK dependencies are exactly pinned and a lockfile exists, but Lambda assets are copied rather than bundled and import AWS SDK v3 modules that are not application dependencies. This relies on the SDK version supplied by the Node.js 22 Lambda runtime, which AWS may update. The promotion handler catches record errors without logging a safe error code/request context; the provisioner converts internal failures to a generic error without an explicit structured diagnostic. DLQ alarms reveal failure but can leave weak forensic detail. The stack also does not enforce artifact provenance, signing, or an SBOM at deployment time.
- **Evidence from code:** At the time of the original finding, `package.json` did not declare `@aws-sdk/client-dynamodb`, `client-s3`, `client-rds-data`, or `client-secrets-manager`; assets excluded `node_modules`, and the promoter's `catch` only appended `messageId` to batch failures. Current source exact-pins the required SDK clients and bundles reviewed TypeScript Lambdas; the dormant Amplify build specification now uses `npm ci --ignore-scripts --cache .npm --prefer-offline`, but still defines no provenance/signature gate and has never run as an approved AWS release.
- **Exploitation scenario:** An AWS runtime SDK update changes checksum/event handling or introduces a regression, producing nondeterministic promotion/provisioning behavior. An attacker or dependency compromise modifies a deploy artifact without a signed attestation; or repeated malformed events reach the DLQ with insufficient reason codes for rapid triage.
- **Potential impact:** Availability failures, delayed incident response, hard-to-reproduce security behavior, and weaker supply-chain assurance. No current exploitable dependency CVE was established by this review.
- **Recommended fix:** Bundle and pin the required AWS SDK clients with a reproducible esbuild configuration; generate an SBOM and signed provenance for Lambda/web/release artifacts; verify the digest before deployment. Emit bounded structured error codes, tenant ID, message/event/request IDs, stage, and retryability—never tokens, object content, secrets, full callback URLs, or raw AWS responses. Add log metric filters for each terminal reason.
- **Example secure patch guidance:** Build Lambda zip files in CI from the lockfile, hash/sign them, and pass immutable asset paths to CDK. Replace catch-all silence with `console.error("evidence_promotion_failed", { tenantId, messageId, eventId, code })` where `code` comes from an internal allowlist.
- **Validation:** Compare deployed Lambda asset hashes to signed CI attestations and SBOMs; run dependency audit/license checks; pin a staging runtime; inject each validation failure and confirm sanitized logs, metrics, DLQ content, alarms, and runbook diagnostics without secret leakage.
- **CWE/OWASP:** CWE-1104 (Use of Unmaintained Third-Party Components), CWE-778 (Insufficient Logging), OWASP A06:2021 Vulnerable and Outdated Components.

## 6. Exploitation Chains or Combined-Risk Scenarios

> **Historical baseline:** the chains in this section explain why the original
> findings were serious. Chains C and D are no longer accurate descriptions of
> the current source controls: strict JWT/membership adapters, split database
> roles, KMS receipts, and the exact-version legal-hold worker now exist. They
> remain useful regression scenarios and are not evidence of a deployed fix.

### Chain A — Premature AWS launch to cross-tenant compromise

1. Operator connects the current repository to the new Amplify app and maps multiple tenant hostnames.
2. Legacy APIs authenticate a global user and query global D1/R2 state without tenant membership.
3. Tenant A requests tenant B identifiers or simply receives the shared workspace.
4. Existing integration and export operations act on the same global records.

**Result:** AWS-01 converts a deployment shortcut into a Critical cross-tenant breach. WAF exact-host checks do not help because both hostnames are valid.

### Chain B — Shared SSR compromise to every tenant

1. A future SSR parser/dependency vulnerability yields the `AmplifyComputeRole` credentials.
2. The role reads the shared tenant registry and assumes every wildcard-matched tenant role.
3. It reads exact tenant evidence versions and uses each tenant database credential through the Data API.
4. Missing DynamoDB data-event logging and optional alert delivery reduce timely detection.

**Result:** AWS-03 + AWS-08 + AWS-09 turn one shared runtime compromise into broad multi-customer exfiltration with weaker forensic evidence.

### Chain C — Route authorization error to fraudulent compliance evidence

1. A future endpoint forgets `assertActorPermission`, trusts unverified token claims, or contains SQL injection.
2. The runtime role updates membership/approval/support/retention state directly.
3. It appends a syntactically valid audit event with a fabricated signature.
4. An assessor export treats the database chain as authentic.

**Result:** AWS-02 + AWS-04 + AWS-06 allow privilege escalation and false provenance within a tenant even though RLS remains intact.

### Chain D — Logical legal hold without physical protection

1. An operator records a legal hold in PostgreSQL.
2. Time-based S3 retention expires; the S3 legal-hold bit was never enabled.
3. A compromised admin or future cleanup worker deletes the exact version.
4. Optional/missing alerts and incomplete control-plane data events delay discovery.

**Result:** AWS-07 + AWS-08/AWS-09 create evidence spoliation while the database continues to claim a hold.

## 7. Dependency and Configuration Risks

- **Pinned and bundled, but not deployment-attested:** Direct CDK, AWS SDK,
  esbuild, and TypeScript dependencies are exact-version pinned and locked.
  Reviewed runtime Lambdas use `NodejsFunction` with `externalModules: []`, so
  they are self-contained rather than dependent on the managed runtime's SDK.
  Production still needs a frozen install, dependency/license review, Lambda
  SBOM/provenance, and comparison of deployed bundle hashes to approved output.
- **Release controls exist only in source:** The protected workflow can build an
  arm64 Developer-ID/hardened-runtime candidate, require Apple acceptance,
  staple and assess it, and attest seven bounded artifacts. The release scripts
  require public update keys to be canonical, currently valid, unique P-256
  points. No workflow run, Apple submission, artifact publication, or updater
  discovery test has occurred.
- **Advanced CodeQL is repository-activated but not yet on `main`:** The
  SHA-pinned workflow uses a manual arm64 Swift build and separate
  JavaScript/TypeScript and Actions jobs. GitHub default setup was disabled on
  2026-08-27 so advanced-analysis uploads are accepted. Until this pull request
  is merged, `main` does not contain that workflow; merge promptly, require all
  three checks, and confirm current coverage for every language.
- **Domain and hosted-zone choice fail closed in current source:** `cdk.json` leaves `rootDomain` blank, and synthesis rejects an invalid/empty domain. The app also requires exactly one of an existing `hostedZoneId` or the explicit `createHostedZone=true` opt-in. This removes the prior implicit placeholder/zone-creation behavior; production still requires proof of ownership, delegation, and an approved certificate/DNS change procedure.
- **No source-connected Amplify build:** `CfnApp` has no repository configuration and the branch disables automatic builds. This is good evidence that nothing was deployed, but it is also a production blocker requiring a controlled, signed build pipeline.
- **Manual alert confirmation:** Email SNS subscriptions require confirmation. Infrastructure creation does not mean notification delivery works.
- **Retention mode is consequential:** COMPLIANCE Object Lock is intentionally difficult or impossible to shorten. Tenant onboarding must require an approved retention policy and explicit acknowledgment, not silently accept a generic default.
- **Cognito is a shared identity boundary:** Per-tenant public clients do not themselves restrict a user-pool identity to that tenant. Membership authorization must remain server-side and exact for every request.
- **Infrastructure tests are synth-oriented:** Template assertions are valuable but do not validate PostgreSQL behavior, IAM evaluation, GuardDuty event schema, KMS encryption context, Cognito tokens, or S3 Object Lock in a live account.

## 8. Secure Design Gaps

- The AWS API surface is intentionally small: `/health`, `/v1/me`,
  `/v1/upload-intents`, `/v1/evidence/search`,
  `/v1/evidence-download-intents`, and legal-hold request/approval are composed
  in source. The customer UI and most assessment, integration, device, admin,
  export, support, retention, and offboarding routes still use the legacy
  single-tenant runtime or have no AWS route.
- No authenticated tenant onboarding or membership-administration plane exists;
  CDK context remains the tenant source and there is no safe production user
  bootstrap workflow.
- Strict server JWT/JWKS, exact-host, and active-membership adapters plus a
  dedicated native Cognito client exist, but the Mac has no integrated hosted
  callback/token exchange, refresh/revocation, signed discovery, or
  device-enrollment flow.
- The upload-intent issuer/presigner, DynamoDB reservation, PostgreSQL
  projection, monotonic promotion fencing, conditional immutable S3 creation,
  and signed promotion reconciliation exist in source but have not been tested
  against live Cognito, STS, DynamoDB, Aurora, GuardDuty, S3 Object Lock, or KMS.
- No persisted job repository/compare-and-swap worker adapter exists.
- KMS signing/verifying and append-only receipts exist for promotion and legal
  holds. General product mutations, independent audit checkpoints, and
  fail-closed export verification remain incomplete.
- Exact-version S3 legal-hold request, approval, durable `APPLYING`, provider
  readback, KMS audit, and recovery projection exist. No UI, release workflow,
  exact-version deletion worker, deployed drift drill, or proof of recovery from
  every audit/recovery partial-failure window exists.
- No tenant suspension/offboarding data workflow, key retirement workflow, data export, or destruction certificate is implemented.
- Upload issuance has atomic member/tenant minute and daily-new-intent quotas;
  broader tenant-aware cache, request propagation, route quotas, and abuse
  controls remain incomplete.
- No cross-account break-glass process, SCP/permission-boundary package, Access Analyzer policy validation, AWS Config conformance pack, Security Hub integration, or general account GuardDuty configuration is included.
- Same-account cross-region global-table, S3 replication/backfill/verification,
  and Aurora Backup/Vault Lock resources exist in source. They are not deployed,
  restored, cut over, or isolated from account compromise; the audit bucket is
  not cross-region replicated.
- The production release/notarization and manual Swift CodeQL workflows exist
  but have not run with protected repository/Apple settings.
- The existing local console must remain loopback-only; hosted auth is not authorization to expose it on a LAN or public interface.

## 9. Recommended Remediation Roadmap

### P0 — Before any tenant hostname or customer data

1. Keep the legacy D1/R2 runtime off every tenant hostname; connect and release
   only a separately reviewed AWS customer application.
2. Deploy the existing exact-host/JWT/membership, upload, promotion, KMS receipt,
   and legal-hold paths first in a disposable two-tenant environment. Run the
   full negative authorization, delayed-worker, partial-failure, and live AWS
   service matrix before accepting evidence.
3. Implement the audited membership invitation/administration flow and migrate
   every customer route to repositories that require the opaque tenant actor.
4. Prove the enabled clean-scan rule against captured GuardDuty events and exact
   tags; prove single-winner S3 conditional creation, fence takeover, signed
   database recovery, and DLQ redrive without duplicate immutable versions.
5. Prove the legal-hold `REQUESTED` → `APPROVED` → `APPLYING` → `APPLIED`
   lifecycle, signed-audit-before-recovery ordering, expiry, retry, alarm, and
   exact-version S3 behavior in live integration tests before exposing it.
6. Connect at least one confirmed on-call destination and add immutable audit for
   security-critical control-table mutations.

### P1 — Before production pilot

1. Reduce shared-role and provisioner blast radius; demonstrate denial across two tenant stacks with captured AWS evidence.
2. Complete Mac `ASWebAuthenticationSession`, token/JWKS/nonce validation, rotation/revocation, signed discovery, and device enrollment.
3. Extend authenticated quotas, bounded pagination, request size/time limits, cache isolation, and abuse alarms to every migrated route.
4. Run PostgreSQL 16 migration/role/RLS tests and full two-tenant AWS integration tests in a disposable staging account.
5. Enable advanced CodeQL, require all three language checks, and run the protected production release through Apple notarization without publishing customer-facing assets.

### P2 — Before general availability

1. Move recovery to a separately controlled account where required, add audit-bucket replication and key-loss procedures, automate restored-resource rewiring, and demonstrate approved RPO/RTO.
2. Enforce CI artifact/signature/provenance/SBOM verification for Lambda, web, and Mac deployment; retain the existing exact bundling, attestation, and notarization controls.
3. Add account-level SCPs, IAM Access Analyzer, AWS Config, Security Hub, general GuardDuty, Inspector where applicable, and break-glass audit controls.
4. Complete suspension/offboarding, retention-policy approval, customer export/destruction certificate, privacy retention, and incident response workflows.

## 10. Security Test Plan

### Authentication and session tests

- Exercise the negative JWT matrix from AWS-02, MFA recovery, token revocation, membership suspension, app-client confusion, refresh rotation/reuse, sign-out, clock skew, and JWKS rotation/outage.
- Verify Mac callback hijacking resistance, state/nonce one-time use, ASWebAuthenticationSession cancellation, custom-scheme registration, signed discovery rollback protection, redirect rejection, and secret-free logs/crash reports.

### Authorization and tenant-isolation tests

- Maintain two real tenant stacks with distinct IDs, roles, DBs, buckets, KMS keys, app clients, and users.
- Generate an endpoint/resource matrix covering create/read/update/delete/search/filter/sort/export/admin/job/retention actions for every role.
- Swap hosts, tenant IDs, object IDs, S3 keys/versions, membership IDs, Cognito clients, job envelopes, and assumed roles across tenants. Assert both response and AWS API trace are isolated.
- Compromise-test each AWS execution role with IAM simulation and controlled staging credentials.

### Input, injection, and parsing tests

- Fuzz hostnames, forwarded headers, IDs, slugs, Unicode/control characters, JSON depth/width, duplicate JSON fields, timestamps, SQL parameters, migration identifiers, S3 keys, versions, MIME values, and queue event envelopes.
- Run SAST plus targeted review for SQL/command/template/path/SSRF/deserialization sinks. The current validators should remain fail closed.
- Confirm no endpoint accepts bucket names, role ARNs, database names, KMS ARNs, or final object keys from a client.

### Evidence upload and storage tests

- Execute every test listed in AWS-05, including duplicate/out-of-order events and injected failures at each CAS/copy/DB transition.
- Confirm malware, unsupported, denied, and failed scans never reach immutable storage.
- Confirm exact checksum, KMS encryption context, Object Lock mode/date, bucket, key, version, and tenant receipts after success.
- Test browsing/download authorization with exact version IDs, range requests, content disposition, active retention, and access logging.

### Database tests

- Apply migrations to real PostgreSQL 16/Aurora-compatible instances; do not rely only on text assertions.
- Verify owners, PUBLIC revocations, role flags including `NOINHERIT`, zero direct or indirect membership paths involving managed roles, schema/table privileges, forced RLS, transaction-local tenant context, wrong/missing tenant, composite foreign keys, state transitions, immutable fields, audit concurrency, timeouts, and restore behavior.
- Add tests proving general runtime roles cannot perform privileged security transitions after remediation.

### Audit, monitoring, and incident tests

- Cryptographically verify business events/receipts from genesis, KMS key rotation, external checkpoints, and assessor exports.
- Validate CloudTrail log digests and Object Lock, DynamoDB/S3 data selectors, root/denied API metrics, WAF redaction, malware alerts, DLQs, budget alerts, and subscriber delivery.
- Ensure logs never contain bearer/refresh tokens, OAuth codes, cookies, authorization headers, AWS secrets, evidence content, presigned URLs, or unredacted sensitive fields.

### Availability, abuse, and recovery tests

- Load-test WAF/IP and authenticated tenant quotas, Cognito throttling, presign issuance, SQS backlog, Aurora cold starts/capacity, large tenant counts, and deliberate poison messages.
- Test KMS/Secrets Manager/S3/RDS/DynamoDB partial outages, retry storms, lease expiry, idempotency, DLQ redrive, and budget/cost alarms.
- Restore a tenant and exact evidence package from backup/replica and independently validate bytes, metadata, audit signatures, and chain of custody.

### CI/CD and supply-chain tests

- Run lockfile-enforced builds, dependency audit, license policy, secret scan, SAST, IaC scanning (`cdk-nag`, IAM Access Analyzer/CloudFormation Guard), tests, SBOM creation, signed provenance, notarization/signature verification, and deployment diff approval.
- Rebuild artifacts reproducibly where possible and compare hashes. Reject unsigned or mismatched Lambda/web/DMG artifacts.

## 11. Open Questions and Assumptions

1. What AWS organization/account structure will be used? A single account was assumed by the CDK; high-risk customers may require account-per-tenant isolation.
2. Which owned production domain and delegated Route 53 hosted zone will be supplied to the deliberately empty CDK context? No ownership or DNS delegation was verified.
3. What exact regulatory and contractual retention periods apply per customer, and must COMPLIANCE mode be mandatory?
4. Who can approve and release legal holds, retention changes, support access, user roles, and tenant offboarding? The required dual-control workflow needs policy ownership.
5. What are the target RPO/RTO, regions, cross-account archive, residency, and customer-managed-key requirements?
6. Will Cognito remain a shared pool, or do customers require dedicated pools/federation/SAML domains? How will subject collisions and lifecycle deprovisioning be handled?
7. What signed channel supplies the Mac with tenant ID, issuer, app-client ID, API origin, callback, and key/configuration version?
8. What device proof is required: user approval only, device public key, Secure Enclave key, MDM attestation, or another managed-device signal?
9. What exact GuardDuty malware event shape and tag behavior occurs in the target account/region? The clean rule is enabled in synthesized source, so deployment and customer evidence must remain blocked until the exact event/tag contract is captured and tested in staging.
10. DynamoDB is the authoritative upload/promotion coordination plane and PostgreSQL is the durable evidence catalog in the current source. Does that remain the approved authority model, and what operator procedure resolves a signed PostgreSQL commit that has not yet reached DynamoDB completion?
11. Promotion and legal-hold receipts use the tenant RSA-3072 KMS key. Which additional product events and export manifests require that signer, and where will public verification material and independent audit-head checkpoints be published?
12. Which principals may read evidence, issue downloads, bypass governance retention, administer KMS, modify bucket policies, or invoke provisioners? Break-glass paths need explicit review.
13. Are WAF's 64 KiB body limit and 1,000 requests/5 minutes/IP suitable for all APIs, and what tenant/user quotas are required behind NAT/proxy environments?
14. What evidence classifications, privacy restrictions, data residency, deletion certificates, and customer audit-log access are contractually required?
15. The review assumes the bundled SQL and Lambda assets are trusted build inputs and that no AWS resources exist yet. A live-account review must verify synthesized IAM, key/bucket policies, CloudTrail selectors, Cognito behavior, DNS/TLS, GuardDuty events, and service quotas before production approval.

### Release decision

**Do not deploy customer tenant hostnames or customer evidence yet.** The dated AWS-01 through AWS-07 findings remain launch-gate records, although the current source substantially remediates the server JWT/membership, upload/promotion, KMS receipt, and exact-version legal-hold portions. A safe next milestone is a disposable two-tenant staging deployment with synthetic data, the remaining customer application and membership flows kept disabled, followed by the current P0 integration/adversarial test plan above. Source remediation is not production closure.
