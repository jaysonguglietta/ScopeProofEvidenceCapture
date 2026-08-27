# Scopeproof AWS CDK platform

This directory contains a synthable, no-deployment AWS foundation for a hosted Scopeproof evidence portal. It provisions the security-critical data plane and tenant database workflow, but it does **not** contain the hosted web application, upload-intent issuer, membership administration UI, or release pipeline. A successful CDK deployment is not a production-ready hosted service until the release blockers below are closed.

## Product brief

- **Users:** compliance teams, customer reviewers, auditors, and Scopeproof operators.
- **Problem:** isolate each customer's portal and evidence without host discovery, cross-tenant access, unscanned promotion, or retention bypass.
- **Primary workflows:** provision a tenant, authenticate on its exact host, issue a one-time upload, quarantine/scan/promote evidence, browse authorized versions, and process jobs.
- **Views still to migrate:** sign-in, evidence browser, capture/upload, job status, membership administration, and operator tenant lifecycle management.
- **Core models:** opaque tenant, exact domain, membership, upload lifecycle, immutable evidence version/receipt, job, audit event/head, and retention policy.
- **Edge cases:** replay/duplicate/expired uploads, slow scans, unknown hosts, partial schemas, failed DNS, poison messages, KMS denial, and Object Lock conflicts.
- **Assumptions:** `us-east-1`, an owned Route 53 domain, Amplify Hosting compute, and authoritative host-plus-membership authorization on every request.
- **Done here:** shared/tenant/audit stacks, fail-closed provisioning, DNS-last activation, immutable S3 boundaries, GuardDuty plumbing, dormant intent-bound promotion, WAF, CloudTrail data events, encrypted alerting/logs, budgets, release distribution, and SES identity.

## Implemented architecture

| Boundary | AWS resources | Design choice |
| --- | --- | --- |
| Web edge | Route 53, Amplify, regional WAF | Exact mappings, no wildcard DNS; tenant CNAME only after database verification. |
| Releases | private versioned S3, CloudFront OAC/WAF, ACM | `downloads.<domain>`, TLS 1.2+, security headers and access logs. |
| Identity | Cognito, one public client per tenant | Required TOTP, authorization code, exact redirects, no self-registration. |
| Control | DynamoDB on demand | Direct tenant/domain keys, PITR/deletion protection, upload lifecycle/receipts. |
| Metadata | Aurora PostgreSQL 16 Serverless v2, Data API | Isolated/no-NAT network, auto-pause, database-per-tenant, FORCE RLS. |
| Provisioning | Step Functions, Lambda, Secrets Manager, Route 53 | Lease/initialize/verify/activate/fail states; schema and DNS precede `ACTIVE`. |
| Evidence | quarantine/evidence S3, KMS, GuardDuty, SQS/DLQ, Lambda | 25 MiB intent contract; only promoter writes Object-Locked evidence. |
| Audit/ops | CloudTrail, Object-Locked S3, CloudWatch, SNS | Exact tenant data events, denial/root metrics, DLQ/job/database alarms. |
| Cost/email | Budgets, Cost Anomaly Detection, SES/DKIM | USD 100 default budget; optional email notifications; identity only. |

The design avoids always-on containers, load balancers, NAT gateways, and provisioned DynamoDB. Route 53, WAF, CloudFront, KMS, Secrets Manager, GuardDuty, logs, S3, Amplify, Cognito, Aurora, CloudTrail, and backups remain billable.

## Layout and validation

```text
bin/scopeproof.ts                  context validation and stack assembly
lib/shared-platform-stack.ts       identity, DB, Amplify/WAF, releases, alerts/cost
lib/tenant-stack.ts                tenant data, GuardDuty, queues, provisioning/promotion
lib/observability-stack.ts         immutable CloudTrail and security alarms
runtime/provision-tenant/index.mjs fail-closed database and DNS worker
runtime/promote-evidence/index.mjs intent-bound immutable evidence promoter
test/foundation.test.ts            template and runtime-contract guardrails
../database/001_tenant_schema.sql  authoritative schema/RLS migration
../database/002_runtime_role.sql   authoritative least-privilege runtime grants
```

Use Node.js 22+ and pnpm. These commands do not deploy:

```bash
cd infra/aws/cdk
pnpm install --frozen-lockfile
pnpm run build
pnpm test
pnpm run synth
```

Production-shaped synthesis:

```bash
pnpm exec cdk synth \
  -c rootDomain=evidence.example.com \
  -c hostedZoneId=Z0123456789EXAMPLE \
  -c alertEmail=security@example.com \
  -c monthlyBudgetUsd=100 \
  -c 'tenants=[{"id":"ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","slug":"acme","displayName":"Acme Corporation","retentionDays":365,"retentionMode":"GOVERNANCE"}]'
```

The default `jsontechology.com` is a placeholder. Tenant IDs must be `ten_` plus 32 lowercase hex characters. Slugs are 1–48 character lowercase DNS labels and cannot use reserved platform names. More than 49 tenants is rejected because the root mapping consumes one of Amplify's 50 fixed domain settings.

## Fail-closed activation

CloudFormation creates the Cognito client, tenant data plane, exact Amplify mapping, and `TENANT#<id>`/`DOMAIN#<host>` registry rows in `PROVISIONING`; it publishes no tenant CNAME. Start `TenantProvisioningStateMachineArn` with a unique Standard Workflow execution name. It:

1. atomically leases both registry rows;
2. creates a separate NOLOGIN/NOSUPERUSER/NOBYPASSRLS owner and non-owner runtime login, supplying a PostgreSQL-native SCRAM verifier rather than placing the reusable generated password in SQL;
3. temporarily grants the administrator `SET ROLE` membership, applies authoritative migration `001` as the owner, applies `002`, and always revokes membership;
4. verifies the exact migration, tables/domains/functions and their owners, FORCE RLS policies, tenant FKs, triggers, singleton tenant/domain rows, runtime privileges, and a real wrong-context denial;
5. re-verifies, UPSERTs only the approved CNAME under conditioned IAM, waits for Route 53 `INSYNC`, then marks the database and both registry rows `ACTIVE`; and
6. restores the database to `PROVISIONING` and marks registry rows `FAILED` on terminal failure. A `FAILED` tenant can be retried with a new execution.

Active registry rows record schema version 1 and the packaged `001` SHA-256. A CNAME may remain after a late failure, but the non-active registry must make the future web runtime return generic `404`; DNS is never authorization.

The shared Aurora administrator secret, cluster, database KMS key, tenant database secrets, and tenant secret KMS keys are retained. The administrator secret uses the customer-managed database key; each provisioner receives only exact secret-read, Secrets Manager-scoped KMS decrypt, and Data API permissions. Stack deletion must never be used as credential rotation or offboarding.

Any subsequent tenant-stack update moves both registry rows back to `PROVISIONING` and is rejected while a provisioning execution lease is active. Re-run the state machine and all change-specific canaries before restoring infrastructure readiness. This deliberately favors a visible, recoverable outage over serving with a changed bucket, role, key, client, or database mapping that has not been re-verified.

## Storage and promotion

- Tenant roles write only their quarantine prefix with the exact KMS key/context; immutable evidence is read-only to them.
- Only the promoter can `PutObject`/set retention in the evidence prefix.
- Exact keys are `tenants/<ten_id>/quarantine/upl_<32hex>.upload` and `tenants/<ten_id>/evidence/evd_<32hex>.<approved-extension>`.
- A strongly consistent `UploadLifecycle` item authorizes tenant/user/evidence IDs, source/destination, MIME, size, SHA-256, nonce, expiry, retention, status, and revision. Expiry gates only unconsumed `issued` uploads.
- A strict lease prevents concurrent duplicate copies. Completion verifies S3 SHA-256/version/KMS/retention and atomically records the receipt; replay revalidates that exact receipt and S3 version.
- GuardDuty protection/tagging is enabled, but `CleanMalwareScanResult` is deliberately **disabled**. Do not enable it until an authenticated issuer persists this contract before issuing a checksum-bound, short-lived presigned PUT. Outputs expose `HostedPromotionRuleName` and `HostedPromotionActivationState=DISABLED_PENDING_UPLOAD_INTENT_ISSUER`.

## WAF, audit, alerting, release, and email

- Amplify uses a **REGIONAL** WAF ACL; CloudFront releases use a separate **CLOUDFRONT** ACL. Both enforce exact hosts, managed reputation/input rules, and rate limits. The app ACL also rejects bodies over 64 KiB; direct evidence uploads use S3 controls.
- WAF keeps blocked-request logs and redacts Authorization/Cookie. Lambda, Step Functions, WAF, and CloudTrail logs are encrypted and retained one year.
- The multi-region trail captures global/management events, API/error insights, validation, and exact quarantine/evidence S3 data events into KMS-encrypted, versioned, compliance-locked storage.
- SNS alarms cover shared/per-tenant DLQs, job age, Aurora capacity, denied API calls, and root use. Email subscriptions require recipient confirmation.
- Releases use a private S3 origin behind CloudFront OAC. A signed CI publishing workflow is still required.
- SES creates domain identity, Easy DKIM, and rejecting custom MAIL FROM. Sending access, bounce/suppression handling, and an app sender are not included.

## Production prerequisites and blockers

Before launch:

1. use an owned/delegated domain, existing zone ID, real alert recipient, and reviewed budget;
2. use OIDC CI, pinned revisions, `cdk diff`, approvals, and change control;
3. implement exact normalized-Host lookup, strongly consistent `ACTIVE` resolution, membership/role authorization, tenant-scoped repositories, CSRF controls, and generic unknown-host responses;
4. implement/adversarially test the authenticated upload-intent issuer before enabling clean promotion;
5. implement invitation/membership, onboarding/offboarding, release publishing, SES delivery, application audit writes, and incident workflows;
6. integration-test Amplify WAF/domain behavior, DNS-last activation, Data API ownership/RLS, GuardDuty events/tags, KMS contexts, S3 checksums/Object Lock, replay, and cross-tenant denial in an isolated AWS account; and
7. run restore/DR exercises and decide whether higher-assurance customers require separate accounts/regions.

Evidence, keys, registry/audit data, and databases are retained/deletion-protected. Stack deletion leaves billable resources and registry history. Automated offboarding/deletion is not implemented.

## Known limitations

1. No hosted web runtime or Amplify source/release connection.
2. No authenticated upload-intent issuer; clean promotion must stay disabled.
3. No invitation/membership administration or offboarding workflow.
4. Security-sensitive AWS integrations are template-tested, not account integration-tested.
5. The single-region design shares compute/identity/control/database infrastructure; account-per-tenant has a smaller blast radius.
6. SES sending, release signing, application audit production, dashboards, and automated recovery remain outside this slice.
