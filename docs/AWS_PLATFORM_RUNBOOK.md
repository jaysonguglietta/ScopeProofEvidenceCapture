# Scopeproof AWS platform operator runbook

> **Pre-deployment status — 2026-08-27:** this repository contains an AWS CDK foundation and security-domain code, but no AWS resources have been deployed or validated by this project work. The current browser/API application is still the legacy Cloudflare/Sites, D1, and R2 single-tenant runtime. It is not the AWS multi-tenant service described here. Do not direct a second customer hostname to the legacy runtime.
>
> **Production stop:** do not onboard a customer or serve traffic from the AWS hostname. The repository now implements the database boundary; a composed per-tenant API for `/health`, `/v1/me`, `/v1/upload-intents`, and two-person legal-hold request/approval; strict JWT/membership authorization; retry-safe upload reconciliation; KMS receipts; a scheduled exact-version legal-hold reconciliation/expiry worker; global-table/S3/Aurora recovery; a protected signing/notarization workflow; and advanced CodeQL with a manual Swift build. None is deployed or validated in a live AWS/PostgreSQL/Apple environment, and no artifact has been submitted to Apple. The Amplify customer UI still has no source connection or application release, no legal-hold UI/operational drill exists, and most product routes are not migrated. A successful infrastructure deployment or database execution is not customer-service activation.

This is the start-to-finish operator procedure for the selected [AWS CDK foundation](../infra/aws/cdk), its [PostgreSQL contract](../infra/aws/database), the tested [runtime security contracts](../lib/aws-runtime), the macOS [hosted-authentication design](../macos/ScopeproofCapture/HOSTED_AUTHENTICATION.md), the migration design in [AWS multi-tenant hosting](AWS_MULTI_TENANT_HOSTING.md), and the current [adversarial AWS security review](AWS_SECURITY_REVIEW.md). Commands are examples for an authorized operator. Replace every `<PLACEHOLDER>`, use temporary IAM Identity Center credentials, record changes in the organization change system, and never paste passwords, tokens, access keys, private signing keys, or secret values into shell history, CDK context, tickets, or this repository.

Keep these lifecycle stages distinct:

| Stage | What it proves | What it does not prove |
| --- | --- | --- |
| Local tests and `cdk synth` | Source contracts compile and CloudFormation can be generated | No AWS resource exists; no IAM, service, network, or engine behavior was exercised |
| `cdk diff` and approved stack deployment | Reviewed infrastructure resources exist in the target account | The tenant database is not provisioned and no customer application is running |
| Tenant state-machine execution | Migrations `001`-`005`, identity seed, four split execute-only application grants, ownership/RLS invariants, a wrong-tenant write denial, and DNS-last publication passed for that tenant | `ACTIVE` is infrastructure/database readiness only; it does not release an application, create users/memberships, expose uploads/legal holds, or authorize customer service |
| Runtime integration and activation record | Hosted authentication, membership, adapters, upload issuer/promotion, monitoring, restore, and isolation tests passed | Nothing beyond the signed scope/environment of that activation record |

## 1. Product and operating brief

1. **Target users:** customer administrators, compliance leads, evidence collectors, reviewers, external auditors, enrolled Mac users, and a small, separately authorized platform-operations team.
2. **Problem:** collect and retain compliance evidence for multiple customers without allowing one customer to discover, read, modify, export, decrypt, or infer another customer's data.
3. **Primary workflows:** operator provisions a tenant; an invited user authenticates with MFA; an enrolled Mac or browser requests an exact upload intent; the artifact enters quarantine; GuardDuty scans the exact object version; a worker validates and promotes clean bytes into Object-Locked evidence storage; an authorized reviewer browses or exports it; operators monitor and recover the service.
4. **Main views:** tenant sign-in, evidence library, assessments, integrations, devices, users and roles, audit history, retention/legal hold, plus a separate platform-operator onboarding view.
5. **Key models:** tenant, exact tenant domain, Cognito principal, tenant membership, device enrollment, assessment, upload intent, evidence artifact/version, job, audit event, retention hold, and export receipt.
6. **Important edge cases:** unknown or disabled hostnames, users with multiple memberships, revoked devices, cross-tenant identifiers, replayed uploads/jobs, unsupported or failed malware scans, checksum/KMS/Object Lock mismatch, legal holds, poison messages, backup inconsistency, and attempted deletion of retained resources.
7. **Assumptions:** the first AWS region is `us-east-1`; each environment has its own AWS account and authoritative Route 53 zone; customer evidence remains in the service account for this bridge design; and the service initially remains below Amplify's 50-subdomain-per-domain quota.
8. **Done means:** application and Mac runtimes are migrated and integrated, all activation gates in this runbook pass in dev and stage, Client A/Client B adversarial tests pass in an isolated AWS account, backup restoration is demonstrated, an independent BOLA/IDOR-focused test is closed, and named Security and Operations approvers authorize production. Synthesized infrastructure alone is not done.

### Implemented infrastructure versus usable service

| Area | Present in the repository | Production status |
| --- | --- | --- |
| Shared AWS foundation | Route 53, Amplify resources, WAF, Cognito, DynamoDB, Aurora/Data API, SQS, SES, budgets, release S3/CloudFront | Synthesizable only; no deployment was performed |
| Tenant data plane | Per-tenant Cognito client and regional API custom domain; an API Gateway mock `/health`; separated data-API, legal-hold-API, upload, ingest, and evidence-control-worker identities; evidence/secret/signing KMS keys; quarantine/evidence buckets; GuardDuty; promotion Lambda; and database provisioning | Source/template-tested only; the mock `/health`, `/v1/me`, `/v1/upload-intents`, and legal-hold request/approval routes are composed in source, but no route or stack is deployed |
| Audit and recovery infrastructure | Multi-region CloudTrail, exact tenant S3 data events, locked audit bucket, KMS receipt adapters, DynamoDB global table, same-account cross-region S3 live replication plus Batch backfill/exact verification, Aurora AWS Backup/Vault Lock, and selected alarms | Not deployed; no live backfill execution, replica validation, restore, cutover, or RPO/RTO evidence exists, and application routes do not append general audit receipts yet |
| AWS runtime code | Strict Cognito/JWKS, exact-host/Dynamo, active-membership/RBAC, RDS Data, a composed API Gateway/Lambda upload route, Dynamo/Aurora reconciliation, KMS receipts, authenticated two-person legal-hold routes, and a scheduled exact-version worker | Production-shaped code with adversarial tests; remaining product/UI routes are not composed and no live AWS integration test has run |
| Browser/API runtime | Legacy Cloudflare/Sites application | Single tenant; must not serve multiple customers |
| macOS hosted auth | PKCE and Keychain primitives under `HostedOAuth.swift` and `HostedTokenStore.swift` | Not integrated with app UI, callback handling, token exchange, or device enrollment |

The operator-facing source contracts are the [tenant schema](../infra/aws/database/001_tenant_schema.sql), [runtime](../infra/aws/database/002_runtime_role.sql), [ingest](../infra/aws/database/003_ingest_role.sql), [evidence-control worker](../infra/aws/database/004_evidence_control_role.sql), and [legal-hold API](../infra/aws/database/005_legal_hold_api_role.sql) grants, [tenant provisioner](../infra/aws/cdk/runtime/provision-tenant/index.mjs), [evidence promoter](../infra/aws/cdk/runtime/promote-evidence/index.mjs), [HTTP/auth adapters](../lib/aws-runtime/http), [evidence adapters](../lib/aws-runtime/evidence), [tenancy boundary](../lib/aws-runtime/tenancy.ts), [OAuth/PKCE primitives](../macos/ScopeproofCapture/Sources/ScopeproofCapture/HostedOAuth.swift), and [Keychain token abstraction](../macos/ScopeproofCapture/Sources/ScopeproofCapture/HostedTokenStore.swift). Treat their tests as source-level evidence, not deployed-service assurance.

## 2. Account, ownership, and access model

Use AWS Organizations and IAM Identity Center. Do not deploy workloads into the Organizations management account, and do not use IAM users or long-lived access keys for operators or CI.

| Account | Purpose | Data allowed | Recommended access |
| --- | --- | --- | --- |
| Organization management | Billing and organization administration only | No application or customer evidence | Break-glass administration; tightly monitored |
| Security/log archive | Organization CloudTrail, Security Hub/GuardDuty aggregation, immutable backup copies when implemented | Central security telemetry, not application traffic | Security team; write-only delivery roles where possible |
| Scopeproof dev | Disposable integration testing with synthetic data | No production/customer data | Developer deployment role; short sessions |
| Scopeproof stage | Production-shaped validation and restore drills | Synthetic or contractually approved test data only | Release and security-validation roles |
| Scopeproof prod | Customer service | Approved production evidence | Just-in-time production deploy, incident, and read-only operations roles |

Use separate dev, stage, and prod accounts. The current CDK uses fixed names and aliases such as `scopeproof`, `scopeproof-production`, `alias/scopeproof/platform-database`, and `scopeproof-monthly-cost`; deploying multiple environments into one account/region would create collisions and increase blast radius. The CDK currently rejects every region except `us-east-1`.

Before any environment deployment:

- Enable root-user MFA, remove root access keys, and configure alternate security contacts.
- Enable organization-level CloudTrail and centralized GuardDuty/Security Hub outside this stack if those services are part of the approved security baseline. Do not assume the application CloudTrail replaces organization audit logging.
- Create least-privilege IAM Identity Center permission sets for `ScopeproofDeploy`, `ScopeproofSecurityReadOnly`, `ScopeproofOperations`, and a separately controlled emergency role.
- Require two-person approval for production changes, retention-mode selection, legal-hold release, governance bypass grants, key deletion, and data retirement.
- Apply service-control policies that deny disabling CloudTrail, public S3 access, unapproved regions, and unauthorized KMS/S3 deletion. Test SCPs in dev before production.
- Record service quotas for Amplify subdomains, Cognito, GuardDuty Malware Protection for S3, KMS, CloudFront, Lambda concurrency, SQS, and Aurora. The CDK rejects more than 49 tenant slugs because the root mapping consumes one Amplify subdomain setting.

## 3. Domain and Route 53 prerequisites

Use an owned domain or an owned, explicitly delegated subdomain for each environment. A safe pattern is:

| Environment | Example pattern |
| --- | --- |
| Dev | `dev.<OWNED_DOMAIN>` |
| Stage | `stage.<OWNED_DOMAIN>` |
| Prod | `<PRODUCTION_DOMAIN>` |

The examples are patterns, not configured values. `jsontechology.com` in `cdk.json` is a placeholder. The code warns but does not fail if it is used, so the operator must enforce this stop condition.

1. Create the environment's public hosted zone before deploying Scopeproof.
2. If it is a delegated subdomain, add its four Route 53 NS values to the authoritative parent zone and verify delegation from two independent resolvers.
3. Confirm the deployment account owns the hosted zone and that the change role can read and modify only the approved zone.
4. Record the exact zone name and hosted-zone ID. Always pass `hostedZoneId`; omitting it causes the stack to create another public hosted zone, which can leave an undelegated or dangling zone.
5. Confirm there are no conflicting `auth`, `downloads`, root, or tenant records.
6. Do not create wildcard tenant DNS. The shared stack creates exact Amplify mappings, while each tenant state machine creates only its exact CNAME after database verification.

Route 53 becomes authoritative only after the registrar or parent zone delegates to the hosted zone's assigned name servers. Follow AWS's [domain routing guidance](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-new-domain.html) and avoid [dangling delegation records](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html).

## 4. Operator workstation prerequisites

Install and verify:

- Git.
- Node.js `22.13.0` or later.
- Corepack and pnpm `11.19.0` for `infra/aws/cdk`.
- npm matching the locked root project dependencies.
- AWS CLI v2.
- An IAM Identity Center profile for the target account; use the [AWS CLI SSO setup](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html), not static keys.
- A ticket/change record containing the reviewed commit, target account, domain, tenant metadata, retention decision, rollback owner, and approvers.

Configure and authenticate the profile interactively:

```bash
aws configure sso --profile <SCOPEPROOF_ENV_PROFILE>
aws sso login --profile <SCOPEPROOF_ENV_PROFILE>
aws sts get-caller-identity --profile <SCOPEPROOF_ENV_PROFILE>
```

The returned account must exactly equal the approved environment account. Stop on any mismatch.

Clone and install from a reviewed immutable revision:

```bash
git clone <REPOSITORY_HTTPS_URL> <CHECKOUT_DIRECTORY>
cd <CHECKOUT_DIRECTORY>
git fetch --tags --prune
git checkout --detach <REVIEWED_COMMIT_SHA>
git status --short
npm ci

cd infra/aws/cdk
corepack enable
corepack prepare pnpm@11.19.0 --activate
pnpm install --frozen-lockfile
node --version
pnpm --version
aws --version
```

`git status --short` must be empty on the release checkout. Do not deploy from a developer's dirty working tree.

## 5. Prepare explicit CDK context

CDK context contains identifiers and customer metadata, never credentials or secrets. Keep the exact reviewed context with the change record. Do not put tokens, passwords, private keys, AWS access keys, Git credentials, database passwords, or OAuth secrets in `cdk.json`, `cdk.context.json`, `-c` arguments, Amplify environment variables, or tenant display names.

Generate a new opaque tenant ID with Node's cryptographic random source:

```bash
node -e 'console.log("ten_" + require("node:crypto").randomBytes(16).toString("hex"))'
```

Copy the output once into the authoritative onboarding record. It must match `^ten_[a-f0-9]{32}$`. Never reuse a tenant ID across customers, and generate a distinct ID in each environment so a copied resource cannot silently bind to another environment.

Set non-secret, task-specific shell values for one approved environment:

```bash
export SP_AWS_PROFILE='<SCOPEPROOF_ENV_PROFILE>'
export SP_AWS_ACCOUNT='<12_DIGIT_ACCOUNT_ID>'
export SP_ROOT_DOMAIN='<OWNED_ROUTE53_ZONE_NAME>'
export SP_HOSTED_ZONE_ID='<ROUTE53_HOSTED_ZONE_ID>'
export SP_BRANCH_NAME='main'
export SP_ALERT_EMAIL='<CONTROLLED_OPERATIONS_EMAIL>'
export SP_MONTHLY_BUDGET_USD='<APPROVED_BUDGET>'
export SP_TENANT_ID='ten_<32_LOWERCASE_HEX_CHARACTERS>'
export SP_TENANT_SLUG='<LOWERCASE_DNS_LABEL>'
export SP_TENANT_DISPLAY_NAME='<CUSTOMER_DISPLAY_NAME>'
export SP_RETENTION_DAYS='<1_TO_3650>'
export SP_RETENTION_MODE='<GOVERNANCE_OR_COMPLIANCE>'
```

Verify the account and region before every synth, diff, or deploy:

```bash
test "$(aws sts get-caller-identity --profile "$SP_AWS_PROFILE" --query Account --output text)" = "$SP_AWS_ACCOUNT"
test "$(aws configure get region --profile "$SP_AWS_PROFILE")" = 'us-east-1'
```

Build the tenant JSON with a JSON tool rather than hand-concatenating untrusted values. For a change-controlled command, the final value has this shape:

```json
[
  {
    "id": "ten_<32_LOWERCASE_HEX_CHARACTERS>",
    "slug": "<TENANT_SLUG>",
    "displayName": "<CUSTOMER_DISPLAY_NAME>",
    "retentionDays": 365,
    "retentionMode": "GOVERNANCE"
  }
]
```

Validation enforced by `lib/config.ts`:

- Root domain is lowercase ASCII, has a real suffix, and is at most 64 characters.
- Branch name is a lowercase DNS label of 1–63 characters.
- Tenant slug is a lowercase DNS label of 1–48 characters and cannot be `admin`, `api`, `app`, `auth`, `downloads`, `status`, `support`, or `www`.
- Display name is 2–120 characters.
- Retention is 1–3650 days and mode is exactly `GOVERNANCE` or `COMPLIANCE`.
- Tenant IDs and slugs are unique in the supplied tenant list.

Select `GOVERNANCE` for controlled pilots unless Legal and Compliance have approved an irreversible `COMPLIANCE` period. In S3 compliance mode, even the account root user cannot shorten retention or delete the protected version. Review [S3 Object Lock behavior](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) before approval.

For every CDK command below, supply the complete tenant list, not only the tenant being changed:

```text
-c rootDomain=<OWNED_ROUTE53_ZONE_NAME>
-c hostedZoneId=<ROUTE53_HOSTED_ZONE_ID>
-c branchName=<DNS_SAFE_BRANCH>
-c alertEmail=<CONTROLLED_OPERATIONS_EMAIL>
-c monthlyBudgetUsd=<APPROVED_BUDGET>
-c tenants=<REVIEWED_JSON_ARRAY>
```

Use identical context for synth, diff, and deploy. A missing tenant changes the shared WAF host allow-list and Amplify domain settings, and omits the tenant stack that owns the DNS-last provisioning workflow.

## 6. Validate without changing AWS

From the repository root:

```bash
npm run lint
npm test
```

From `infra/aws/cdk`:

```bash
pnpm run build
pnpm test
pnpm exec cdk list \
  --profile "$SP_AWS_PROFILE" \
  -c rootDomain="$SP_ROOT_DOMAIN" \
  -c hostedZoneId="$SP_HOSTED_ZONE_ID" \
  -c branchName="$SP_BRANCH_NAME" \
  -c alertEmail="$SP_ALERT_EMAIL" \
  -c monthlyBudgetUsd="$SP_MONTHLY_BUDGET_USD" \
  -c 'tenants=<REVIEWED_JSON_ARRAY>'

pnpm exec cdk synth --quiet \
  --profile "$SP_AWS_PROFILE" \
  -c rootDomain="$SP_ROOT_DOMAIN" \
  -c hostedZoneId="$SP_HOSTED_ZONE_ID" \
  -c branchName="$SP_BRANCH_NAME" \
  -c alertEmail="$SP_ALERT_EMAIL" \
  -c monthlyBudgetUsd="$SP_MONTHLY_BUDGET_USD" \
  -c 'tenants=<REVIEWED_JSON_ARRAY>'
```

Expected stack names with at least one tenant are:

```text
ScopeproofSharedPlatform
ScopeproofTenant-<TENANT_SLUG>
ScopeproofObservability
```

Inspect synthesized templates for the approved account, region, exact domain/hosts, retention mode/days, KMS encryption, public-access blocks, Object Lock, deletion protection, IAM grants, and absence of secrets. Archive the templates and their SHA-256 hashes in the change record. A successful synth proves only template generation; it is not runtime validation.

Run and review a diff immediately before deployment:

```bash
pnpm exec cdk diff --profile "$SP_AWS_PROFILE" \
  -c rootDomain="$SP_ROOT_DOMAIN" \
  -c hostedZoneId="$SP_HOSTED_ZONE_ID" \
  -c branchName="$SP_BRANCH_NAME" \
  -c alertEmail="$SP_ALERT_EMAIL" \
  -c monthlyBudgetUsd="$SP_MONTHLY_BUDGET_USD" \
  -c 'tenants=<REVIEWED_JSON_ARRAY>'
```

Require Security approval for every IAM, KMS, bucket policy, Cognito, WAF, DNS, Object Lock, logging, deletion-policy, or trust-policy change. AWS explains that `cdk diff` compares the local app with deployed stacks in the [CDK CLI guide](https://docs.aws.amazon.com/cdk/v2/guide/cli.html).

### Existing control-table migration stop

> **STOP for any existing AWS deployment.** The current CDK synthesizes the
> control plane as `AWS::DynamoDB::GlobalTable`; older revisions synthesized the
> same logical resource as `AWS::DynamoDB::Table`. Do **not** approve or deploy a
> direct CloudFormation resource-type change. It is not an in-place,
> data-preserving update and may fail, propose replacement, or strand stack
> ownership. Fresh deployments have no migration and may continue normally.

Treat an existing table as a data migration with its own rollback plan:

1. Freeze provisioning, upload-intent issuance, promotion, and other control
   writes. Record the exact physical table name/ARN, stack logical ID, item count,
   latest restorable time, TTL attribute, GSI schema, billing mode, stream state,
   PITR/deletion protection, tags, alarms, IAM references, and DynamoDB/Aurora
   reconciliation counts.
2. Verify PITR and create a separate export or on-demand backup. Restore that
   copy in isolation and compare representative lifecycle, registry, receipt,
   nonce, idempotency, and recovery records before changing ownership.
3. Deploy a reviewed intermediate template that retains the physical table, then
   remove only its CloudFormation resource definition so the retained table is
   no longer managed. Confirm the stack update did not delete or rename it and
   that every application reference still resolves to the same physical table.
4. Convert the retained table/add the recovery-region replica using the approved
   DynamoDB global-table procedure, with writes still frozen. Then use
   CloudFormation resource import to adopt that exact physical table under the
   new `AWS::DynamoDB::GlobalTable` logical resource and exact replica settings.
   Generate and review the import change set; do not hand-create a replacement
   table or copy only a subset of item types.
5. Run drift detection and reconcile item counts, sampled hashes, GSI/TTL/PITR/
   deletion-protection settings, replica status, CloudTrail, alarms, IAM leading
   keys, and DynamoDB/Aurora state. Test primary writes/recovery-region reads,
   regional-loss procedures, and Client A/Client B denial canaries before
   unfreezing.

Rehearse the complete retain/remove/convert/import sequence in a disposable
account with production-shaped synthetic data. If any step, import support, or
rollback behavior differs in the target AWS account, stop and update the change
plan; do not improvise a dual-write or destructive replacement.

## 7. Bootstrap and deploy in dependency order

> **Current project status:** the following commands have not been run by this project work. They are an operator procedure for a future approved environment, not a statement that resources exist.

Bootstrap each account/region once, with termination protection:

```bash
pnpm exec cdk bootstrap "$SP_AWS_ACCOUNT/us-east-1" \
  --profile "$SP_AWS_PROFILE" \
  --termination-protection
```

Every account/region is an independent CDK environment and must be bootstrapped before deployment. See [AWS CDK bootstrapping](https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html). Protect and periodically update the `CDKToolkit` stack; do not delete and recreate it casually.

Deploy in this order under an approved change window:

1. **Recovery destination, when enabled.** Bootstrap/deploy
   `ScopeproofRecovery` in the destination region first and record its exact
   vault, bucket, and key outputs. Follow the two-phase recovery guide; never
   guess an ARN.
2. **Shared platform.** This creates shared identity/database/edge/release
   resources and the global control table. For an existing deployment, first
   complete the retain/remove/convert/import migration stop above. It does not
   publish a tenant CNAME.
3. **One tenant stack at a time.** Confirm each stack creates only the expected
   tenant's evidence/secret/signing keys, buckets, Cognito client, API Gateway
   custom domain and data/legal-control Lambdas, scoped IAM roles, scheduled
   legal-hold worker/alarms, secrets, GuardDuty plan, recovery
   backfill/reconciler resources, queues, promoter, and state machine.
4. **Observability.** This depends on the shared and every tenant stack so
   CloudTrail can enumerate exact S3 data-event resources.

```bash
pnpm exec cdk deploy ScopeproofSharedPlatform \
  --profile "$SP_AWS_PROFILE" \
  --require-approval broadening \
  -c rootDomain="$SP_ROOT_DOMAIN" \
  -c hostedZoneId="$SP_HOSTED_ZONE_ID" \
  -c branchName="$SP_BRANCH_NAME" \
  -c alertEmail="$SP_ALERT_EMAIL" \
  -c monthlyBudgetUsd="$SP_MONTHLY_BUDGET_USD" \
  -c 'tenants=<REVIEWED_JSON_ARRAY>'

pnpm exec cdk deploy "ScopeproofTenant-$SP_TENANT_SLUG" \
  --profile "$SP_AWS_PROFILE" \
  --require-approval broadening \
  -c rootDomain="$SP_ROOT_DOMAIN" \
  -c hostedZoneId="$SP_HOSTED_ZONE_ID" \
  -c branchName="$SP_BRANCH_NAME" \
  -c alertEmail="$SP_ALERT_EMAIL" \
  -c monthlyBudgetUsd="$SP_MONTHLY_BUDGET_USD" \
  -c 'tenants=<REVIEWED_JSON_ARRAY>'

pnpm exec cdk deploy ScopeproofObservability \
  --profile "$SP_AWS_PROFILE" \
  --require-approval broadening \
  -c rootDomain="$SP_ROOT_DOMAIN" \
  -c hostedZoneId="$SP_HOSTED_ZONE_ID" \
  -c branchName="$SP_BRANCH_NAME" \
  -c alertEmail="$SP_ALERT_EMAIL" \
  -c monthlyBudgetUsd="$SP_MONTHLY_BUDGET_USD" \
  -c 'tenants=<REVIEWED_JSON_ARRAY>'
```

Do not use `--require-approval never` from an operator workstation. A production pipeline may use it only after the exact synthesized change has received out-of-band approval and the pipeline role is restricted to that environment.

A tenant-stack update intentionally returns both tenant/domain registry rows to `PROVISIONING`; it fails if a provisioning execution currently owns the lease. Plan the change window accordingly. After CloudFormation succeeds, re-run the tenant state machine and all affected canaries before treating the tenant as infrastructure-ready. Do not bypass this fail-closed re-verification by editing DynamoDB status directly.

Record CloudFormation events and stack outputs. Relevant shared outputs are `RootDomain`, `HostedZoneId`, `AmplifyAppId`, `AmplifyDefaultDomain`, `CognitoUserPoolId`, `CognitoLoginDomain`, `ControlPlaneTableName`, `DatabaseClusterArn`, `JobsQueueUrl`, `OperationsTopicArn`, `ReleaseBucketName`, and `ReleaseDownloadOrigin`. Relevant tenant outputs include hostname/API hostname/API origin/ID, Cognito client ID, upload data-role ARN, legal-hold workflow-role ARN, bucket names, KMS ARN, database name, all four application database usernames/secret ARNs (including `TenantLegalHoldApiDatabaseUsername`), provisioning state-machine ARN, ingest DLQ URL, Malware Protection plan ID, and—when recovery is enabled—the backfill role/report bucket/reconciler outputs.

### DNS-last activation boundary

The shared stack may create the exact Amplify subdomain mapping needed for certificate/domain preparation, but it does not publish the tenant Route 53 CNAME. The tenant provisioner re-runs database verification, UPSERTs only the stack-controlled exact CNAME through hosted-zone- and record-scoped IAM, waits for Route 53 `INSYNC`, then marks database and registry state `ACTIVE`. If a later activation write fails, the CNAME can remain, but both registry rows remain non-active and the database is restored to `PROVISIONING`. The tenant API must therefore return the same generic non-disclosing failure for unknown, `PROVISIONING`, `FAILED`, suspended, or unauthorized tenants before any customer data access. DNS remains routing, never authorization.

## 8. Post-deployment shared-platform checks

Perform these checks after each stack and before proceeding to the next gate.

### 8.1 Operations email and cost alerts

The shared stack creates an encrypted SNS operations topic. If `alertEmail` is supplied, AWS sends a subscription-confirmation email. An authorized owner must open the AWS-generated message and confirm it; alarms do not deliver to a `PendingConfirmation` subscription. Verify it without exposing message contents:

```bash
aws sns list-subscriptions-by-topic \
  --profile "$SP_AWS_PROFILE" \
  --topic-arn '<OPERATIONS_TOPIC_ARN>' \
  --query 'Subscriptions[].{Protocol:Protocol,Endpoint:Endpoint,SubscriptionArn:SubscriptionArn}'
```

Do not proceed if `SubscriptionArn` is `PendingConfirmation`. Send a controlled test notification containing no customer data, verify receipt/on-call escalation, and attach evidence to the change. AWS documents the confirmation behavior in [Confirm an SNS subscription](https://docs.aws.amazon.com/sns/latest/dg/SendMessageToHttp.confirm.html).

Verify that the monthly budget uses the approved amount, forecast alerts at 80%, actual alerts at 100%, and the daily Cost Anomaly Detection subscription reaches the controlled address. `alertEmail` is optional in code; omission silently leaves several cost and operational notifications without an email recipient and is a production stop.

### 8.2 DNS and certificates

Verify independently:

- `auth.<ROOT_DOMAIN>` resolves to the Cognito custom domain.
- `downloads.<ROOT_DOMAIN>` resolves to CloudFront.
- The root and each approved tenant hostname resolve only to the intended Amplify app/branch.
- Each `api-<TENANT>.<ROOT_DOMAIN>` resolves only to its regional API Gateway
  custom domain, and the default execute-api endpoint is disabled.
- An unknown and a reserved hostname returns NXDOMAIN.
- Certificates cover only expected names, are issued, and use modern TLS.
- Direct Amplify/CloudFront origins do not become an authorization bypass.

Do not weaken the exact-host rule to work around certificate or DNS delays.

### 8.3 WAF

The CloudFront-scope Web ACL is named `scopeproof-production` in every environment account and contains:

- exact allowed hosts: root, downloads, and approved tenant hostnames;
- body blocking above 65,536 bytes, including WAF inspection oversize;
- AWS managed IP reputation, common, and known-bad-input rule groups;
- 1,000 requests per five minutes per source IP;
- blocked-request logging only, with `Authorization` and `Cookie` fields redacted and one-year log retention.

Verify the ACL association to Amplify and the release CloudFront distribution. Exercise allowed host, unknown host, oversized request, managed-rule, and rate-limit canaries from authorized test sources. Inspect false positives before tuning; use scoped exclusions, never disable a whole managed group without a reviewed compensating control. The WAF rate limit is per source IP. The upload-intent route separately enforces atomic principal/tenant quotas of 60/300 requests per minute and 500/5,000 new reservations per UTC day; validate those controls under real concurrency, and add route-appropriate authenticated quotas to each future API.

### 8.4 SES

The stack creates a domain identity, Easy DKIM records, and `mail.<ROOT_DOMAIN>` MAIL FROM with reject-on-MX-failure. Verify identity/DKIM/MX status and account sending state:

```bash
aws sesv2 get-email-identity \
  --profile "$SP_AWS_PROFILE" \
  --region us-east-1 \
  --email-identity "$SP_ROOT_DOMAIN"

aws sesv2 get-account \
  --profile "$SP_AWS_PROFILE" \
  --region us-east-1
```

New SES accounts are commonly sandboxed. Request production access only after identity verification, bounce/complaint handling, recipient consent, and sending-use-case review. AWS describes the process in [Moving out of the SES sandbox](https://docs.aws.amazon.com/ses/latest/dg/request-production-access.html). The current application has no AWS email-sending implementation; SES verification alone does not enable invitations or notifications in the hosted runtime.

### 8.5 Tenant API — source-defined, deployment validation required

Each tenant stack creates `api-<TENANT>.<ROOT_DOMAIN>` as a regional API Gateway
custom domain, associates WAF, disables the default execute-api endpoint, and
routes authenticated data operations and legal-hold operations to separate
tenant-specific Lambdas. API Gateway answers the exact `/health` route directly
with a mock integration, so a health probe cannot invoke Lambda or trigger STS
role assumption. Before any evidence upload:

1. require the API Gateway mock `GET /health` to return only `{"status":"ok"}`
   with `no-store` and security headers on the exact custom domain, and verify it
   causes no Lambda invocation or tenant-role assumption;
2. require anonymous, ID-token, wrong-client, expired, stale-authentication,
   revoked-membership, suspended-tenant, malformed-host, direct execute-api, and
   cross-tenant requests to fail without disclosing tenant/resource existence;
3. require authenticated `GET /v1/me` to return only the exact authorized
   tenant/membership/role facts;
4. require `POST /v1/upload-intents` to reject duplicate/unknown JSON fields,
   oversized or mismatched bodies, noncanonical identifiers/idempotency keys,
   unsupported MIME/size, client-supplied retention fields, and foreign
   assessment/device data; verify the server derives retention from the tenant
   database policy and atomically enforces 60/300 requests per member/tenant per
   minute plus 500/5,000 new reservations per member/tenant per UTC day;
5. require `POST /v1/legal-hold-requests` and
   `POST /v1/legal-hold-approvals` to derive two distinct active administrators
   from separate tokens/calls, bind the approval to the exact digest, reject
   actor fields, reject new transition timestamps outside ±5 minutes of the
   database clock, accept an old exact canonical replay without creating a new
   transition, enforce the 24-hour request-to-approval window, and make no S3
   call before `APPROVED`;
6. verify CloudTrail shows the data entry role assuming only its exact tenant
   upload role and the legal-hold entry role assuming only its exact workflow
   role for 15 minutes. Prove the upload role cannot list either bucket, read
   quarantine/evidence objects, decrypt evidence, or use legal holds; prove the
   public legal-hold role cannot use S3/KMS or worker reconciliation procedures;
   and prove both are denied every other tenant's secret, database, DynamoDB
   partition, bucket, and KMS key; and
7. exercise lost Data API responses, exact retries, conflicting retries, STS/
   Secrets Manager/DynamoDB/Aurora/S3 failures, and presigned-header tampering.

Do not log or attach the bearer token, tenant secret, STS credentials, or
presigned URL to test evidence. Preserve redacted request IDs, provider request
IDs, exact object versions, and database/DynamoDB reconciliation results.

### 8.6 Amplify application release — currently blocked

The CDK creates a `WEB_COMPUTE` Amplify app and branch, but deliberately creates no repository/source connection and has auto-build disabled. The repository's web app still targets Cloudflare/Sites and is not a deployable AWS Next.js migration. AWS also states that manual Amplify deployments do not support SSR apps. Therefore:

- do not connect the legacy repository in the console;
- do not manually patch the Amplify app, role, environment, or branch and create untracked drift;
- implement and review the AWS runtime migration, Amplify-compatible build output, OIDC-based CI/CD/source connection, immutable commit pinning, deployment tests, and rollback before any web release;
- keep tenant traffic disabled until exact-host resolution, Cognito validation, active membership authorization, tenant role assumption, cache controls, and persistence adapters pass adversarial tests.

See AWS's [Amplify SSR deployment specification](https://docs.aws.amazon.com/amplify/latest/userguide/ssr-deployment-specification.html) and its warning that [manual deploys do not support SSR](https://docs.aws.amazon.com/amplify/latest/userguide/manual-deploys.html).

### 8.7 CloudFront and Mac release assets

The shared stack creates a private, versioned release bucket behind CloudFront at `downloads.<ROOT_DOMAIN>`, with origin access control, TLS 1.2 (2021 policy), HTTP/2 and HTTP/3, security headers, WAF, and access logs. It does not publish an application artifact or configure the Mac updater.

For a future production release:

1. Commit the real update Team ID, designated requirement, offline update-signing public key, canonical UTC validity window, version, and monotonically increasing build number; build only from an immutable, clean `main` commit. `Scripts/configure_macos_release_identity.sh` and the production builder both require a unique key ID, canonical base64 for a valid 65-byte uncompressed P-256 X9.63 point, ordered canonical timestamps, and a key window that is valid at execution time.
2. Configure the protected `production-release` GitHub environment and the six Apple secrets documented in [AWS recovery and production macOS release](AWS_RECOVERY_AND_MACOS_RELEASE.md). Keep the offline update-signing private key outside GitHub Actions.
3. Run `.github/workflows/macos-production-release.yml` for the exact 40-character approved commit. Its manual-build script imports credentials into an ephemeral Keychain, requires Developer ID/hardened-runtime identity, submits the app and DMG to Apple, requires `Accepted`, staples and validates both, checks Gatekeeper, and attests the exact ZIP, DMG, checksum sidecars, CycloneDX SBOM, in-toto/SLSA provenance, and redacted notary receipt. No Apple submission has been made by committing this workflow.
4. Download that exact seven-file candidate set and run `Scripts/publish_release.sh` on a clean Mac with the approved commit and attestation repository. The script verifies attestations, digests, provenance, redacted receipt, code identity, staples, Gatekeeper, and the mounted DMG without rebuilding or re-archiving, then produces the public signed update envelope with the separately controlled offline P-256 key and final versioned HTTPS URL. Never place that private key or notarization credentials in the release bucket, CDK context, Amplify variables, logs, or workflow artifacts.
5. Upload the verified exact ZIP/DMG, public envelope/manifest, checksum sidecars, SBOM, provenance, and redacted receipt to immutable versioned keys such as `macos/<VERSION>/...` only after a separate release-promotion approval.
6. Retrieve each resulting S3 `VersionId`, independently download through CloudFront, and compare size, SHA-256, signature, staple, and Gatekeeper result.
7. Publish or update a stable `latest` pointer only after immutable assets verify. Prefer versioned filenames; AWS recommends versioned names over invalidations for reliable rollback and cache behavior. If an existing stable key must change, invalidate only the exact affected path.
8. Record artifact hashes, object versions, signing identity, Apple notarization result, CloudFront URL, release commit, workflow run, and approvers.

Example publication shape, after all signing checks pass:

```bash
aws s3 cp '<SIGNED_RELEASE_ZIP>' \
  "s3://<RELEASE_BUCKET>/macos/<VERSION>/<RELEASE_FILENAME>.zip" \
  --profile "$SP_AWS_PROFILE" \
  --only-show-errors

aws s3 cp '<PUBLIC_SIGNED_RELEASE_ENVELOPE>' \
  "s3://<RELEASE_BUCKET>/macos/<VERSION>/macos-release-envelope.json" \
  --profile "$SP_AWS_PROFILE" \
  --content-type application/json \
  --only-show-errors
```

Do not run these examples with a preview or ad-hoc-signed build. The current Mac updater calls the configured hosted API and is not wired to discover an AWS static manifest, so AWS-hosted automatic updates remain blocked even if direct downloads work. See [CloudFront file versioning](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/UpdatingExistingObjects.html).

Swift security scanning is defined in `.github/workflows/codeql-swift.yml` with
CodeQL `build-mode: manual`; it executes the real arm64 Swift build on
`macos-15`. The same advanced workflow preserves JavaScript/TypeScript and
GitHub Actions analysis as separate no-build jobs. After this workflow exists
on `main`, switch CodeQL from default to advanced setup, require all three
checks, and confirm each language is current on the tool-status page; default
setup blocks uploads from a custom advanced workflow while it remains enabled.

## 9. Tenant database schema and provisioning

### 9.1 Authoritative files and roles

- [Migration 001](../infra/aws/database/001_tenant_schema.sql) creates the tenant schema, tenant-aware keys, forced row-level security, boundary triggers, upload/evidence/job/audit/retention records, and migration version `1`.
- [Migration 002](../infra/aws/database/002_runtime_role.sql) is an allow-list reset for the non-privileged runtime role: it revokes table, sequence, and function grants, then grants only tenant context, active-membership resolution, and upload-intent creation procedures.
- [Migration 003](../infra/aws/database/003_ingest_role.sql) grants the non-privileged ingest role only tenant context, monotonic promotion-fence claim, authoritative promotion-receipt read, and exact promotion reconciliation.
- [Migration 004](../infra/aws/database/004_evidence_control_role.sql) grants the non-privileged worker role only tenant context, pending/audit/recovery-outbox work reads, durable exact-version legal-hold application start, exact-version confirmation, bounded expiry/retry metadata, recovery-publication acknowledgement, audit-head read, and signed-audit append. It cannot request or approve a hold.
- [Migration 005](../infra/aws/database/005_legal_hold_api_role.sql) grants the separate non-privileged public legal-hold API role only tenant context, active-membership resolution, request reservation, and distinct-administrator approval. It has no direct table, reconciliation, audit-append, S3, or KMS access.
- The [tenant provisioner](../infra/aws/cdk/runtime/provision-tenant/index.mjs) is the apply/verify implementation packaged for Lambda. The asset contains all five authoritative SQL files; it has not been deployed by this work.
- The [offline SQL renderer](../Scripts/render_aws_tenant_sql.mjs) is review/recovery tooling. It is not the payload used by the state machine.

The CDK derives one owner and four separate application database identities from the validated tenant slug and opaque tenant ID:

- database: `scopeproof_<NORMALIZED_SLUG>`;
- NOLOGIN database owner: `scopeproof_<FIRST_11_NORMALIZED_SLUG_CHARACTERS>_<FULL_32_HEX_TENANT_SUFFIX>_owner`;
- LOGIN runtime role: `tenant_<FIRST_11_NORMALIZED_SLUG_CHARACTERS>_<FULL_32_HEX_TENANT_SUFFIX>_app_runtime`;
- LOGIN ingest role: `tenant_<FIRST_11_NORMALIZED_SLUG_CHARACTERS>_<FULL_32_HEX_TENANT_SUFFIX>_ingest`;
- LOGIN evidence-control worker role: `tenant_<FIRST_11_NORMALIZED_SLUG_CHARACTERS>_<FULL_32_HEX_TENANT_SUFFIX>_control`; and
- LOGIN legal-hold API role: `tenant_<FIRST_11_NORMALIZED_SLUG_CHARACTERS>_<FULL_32_HEX_TENANT_SUFFIX>_legal_api`.

Normalization replaces hyphens with underscores. The full tenant-ID suffix prevents collisions between long slugs with the same prefix while keeping every PostgreSQL identifier at or below 63 characters. Treat the `TenantDatabaseName`, `TenantDatabaseUsername`, `TenantIngestDatabaseUsername`, `TenantEvidenceControlDatabaseUsername`, and `TenantLegalHoldApiDatabaseUsername` outputs as authoritative; do not reconstruct recovery usernames by hand. Each login has a distinct generated Secrets Manager password encrypted under the per-tenant secret KMS key. The provisioner requires all four credentials and usernames to be different and converts each password to a PostgreSQL SCRAM verifier before constructing role SQL so reusable plaintext cannot enter PostgreSQL failure logs. Operators must never retrieve or print a password or verifier.

### 9.2 Optional offline SQL rendering

Render after tenant stack outputs exist when Security wants a human-reviewable expected bundle or when a separately approved recovery procedure requires it. From the repository root:

```bash
umask 077
mkdir -p '<APPROVED_TEMPORARY_DIRECTORY>'

node Scripts/render_aws_tenant_sql.mjs \
  --tenant-id 'ten_<32_LOWERCASE_HEX_CHARACTERS>' \
  --slug '<TENANT_SLUG>' \
  --display-name '<CUSTOMER_DISPLAY_NAME>' \
  --hostname '<TENANT_SLUG>.<ROOT_DOMAIN>' \
  --retention-days '<1_TO_3650>' \
  --retention-mode '<GOVERNANCE_OR_COMPLIANCE>' \
  --runtime-role '<TENANT_DATABASE_USERNAME_OUTPUT>' \
  --ingest-role '<TENANT_INGEST_DATABASE_USERNAME_OUTPUT>' \
  --control-role '<TENANT_EVIDENCE_CONTROL_DATABASE_USERNAME_OUTPUT>' \
  --legal-api-role '<TENANT_LEGAL_HOLD_API_DATABASE_USERNAME_OUTPUT>' \
  --aws-account-id '<12_DIGIT_ACCOUNT_ID>' \
  --aws-region 'us-east-1' \
  --quarantine-bucket '<INGEST_BUCKET_OUTPUT>' \
  --evidence-bucket '<EVIDENCE_BUCKET_OUTPUT>' \
  --kms-key-arn '<EVIDENCE_KEY_ARN_OUTPUT>' \
  --signing-key-arn '<AUDIT_SIGNING_KEY_ARN_OUTPUT>' \
  --output '<APPROVED_TEMPORARY_DIRECTORY>/tenant-bootstrap.sql'

shasum -a 256 '<APPROVED_TEMPORARY_DIRECTORY>/tenant-bootstrap.sql'
```

The renderer validates/quotes every supplied value, writes mode `0600`, and refuses overwrite. Its output contains customer metadata and resource identifiers but no password. Never commit it. It includes a review-oriented seed with a pending database domain; do not manually apply it over a database managed by the state machine or treat its hash as the deployed Lambda asset hash.

### 9.3 What the state machine applies and verifies

The state machine runs `AcquireProvisioningLease → InitializeTenantDatabase → VerifyTenantDatabase → ActivateTenant`; failures run `MarkTenantFailed`. Execution data is excluded from its encrypted one-year logs.

The provisioner currently:

1. Atomically leases both exact DynamoDB tenant and domain rows when their status is `PROVISIONING` or `FAILED`.
2. Reads the generated runtime, ingest, evidence-control-worker, and legal-hold-API secrets without logging them; validates exact usernames/password shapes and requires four distinct credentials.
3. Creates or hardens a NOLOGIN, non-privileged owner role and four distinct LOGIN, NOINHERIT, non-privileged application roles. It grants the database administrator temporary membership in the owner role only for the migration transaction and revokes that membership in a `finally` path.
4. Creates the tenant database owned by the owner role; revokes `PUBLIC` connection and grants only the four application roles connection.
5. Refuses an unversioned partial `scopeproof` schema. When migration `1` is absent, it changes to the dedicated owner role, parses the packaged SQL, and executes each statement through RDS Data API inside one explicit transaction. This makes the owner—not the cluster administrator—the schema/table/function owner and handles the Data API rule that one `ExecuteStatement` call cannot contain multiple statements; see [Troubleshooting RDS Data API](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api.troubleshooting.html).
6. In a transaction with the exact tenant context, seeds the immutable tenant identity and a verified canonical database-domain row from stack-controlled account, region, bucket, KMS, hostname, retention, and display metadata.
7. Safely substitutes each validated role token and applies execute-only allow-list resets for runtime, ingest, evidence-control worker, and legal-hold API. None receives direct table access.
8. Connects using all four application secrets and verifies exact identities, schema `USAGE` but no `CREATE`, non-privileged role flags, exact procedure allowlists, absence of direct table grants, the named schema migration and packaged SHA marker, the exact table/domain/function set and owner, every expected forced-RLS policy, tenant foreign key, boundary/immutability/audit trigger, singleton tenant identity, and single verified canonical database-domain row. It also verifies the owner is NOLOGIN/unprivileged and is no longer granted to the administrator.
9. Starts a separate runtime transaction with a different syntactically valid tenant context and requires a fully valid attempted write for the configured tenant to fail specifically under RLS or the tenant-boundary trigger.
10. Re-runs database verification, publishes only the exact approved tenant CNAME, and waits for Route 53 `INSYNC`. It then marks the database identity and both DynamoDB registry rows `ACTIVE`, recording schema version `1` and the packaged migration SHA-256. A terminal failure restores database state to `PROVISIONING` and leaves registry rows `FAILED` with a sanitized error name.

This is materially stronger than an operator-applied bundle, but it has not been run against an AWS environment in this project. Its local tests and synthesized permissions are not evidence that Aurora engine behavior, Data API statement parsing, transaction duration, IAM, or retry behavior works in the deployed account.

### 9.4 Execute and observe provisioning

Run only after the shared, tenant, and observability stacks are stable; the exact outputs and registry records match the onboarding record; alarm delivery works; and the change explicitly authorizes database creation. First execution belongs in dev with synthetic data, followed by stage. Production requires the prior environments' execution evidence and all non-application platform gates.

Before starting, retrieve both registry rows with strongly consistent reads and require `PROVISIONING` (or a reviewed retry from `FAILED`). Do not proceed from `ACTIVE`, `SUSPENDED`, or an unknown status.

Start with an approved, non-sensitive execution name and empty input:

```bash
aws stepfunctions start-execution \
  --profile "$SP_AWS_PROFILE" \
  --region us-east-1 \
  --state-machine-arn '<TENANT_PROVISIONING_STATE_MACHINE_ARN>' \
  --name '<CHANGE_ID_AND_UNIQUE_SEQUENCE>' \
  --input '{}'
```

Record the returned execution ARN, then wait for a terminal status without printing execution payloads:

```bash
aws stepfunctions describe-execution \
  --profile "$SP_AWS_PROFILE" \
  --region us-east-1 \
  --execution-arn '<EXECUTION_ARN>' \
  --query '{status:status,startDate:startDate,stopDate:stopDate,error:error}'
```

On `FAILED`, do not manually repair roles, schema, migrations, identity rows, or registry status. Preserve Step Functions/Lambda/CloudTrail metadata, identify the exact failing invariant in an incident/change, fix code in dev, and use a new execution after approval. The lease permits a reviewed retry from `FAILED`; do not force it with direct DynamoDB writes.

On `SUCCEEDED`, use consistent reads to verify both registry rows are `ACTIVE`, refer to the same tenant ID/hostname, and report schema version `1`. Independently run the positive/negative database canary in the isolated test account. At minimum it must verify migration version, exact identity, database owner/runtime/ingest/evidence-control-worker/legal-hold-API separation, each execute-only procedure allowlist, absence of direct application table grants, every RLS/`FORCE RLS` flag, trigger/grant/timeouts, and denial of wrong-tenant reads, writes, joins, and foreign keys.

`ACTIVE` currently means that the database boundary passed the provisioner's checks. It does **not** mean the customer service is launched: the source-defined tenant API is not deployed, the Amplify UI is not released, and no membership-administration flow, Mac enrollment, live issuer test, restore drill, or penetration test follows from this state. Keep customer access disabled until the remaining activation gates pass. Before a live multi-tenant product exists, introduce a separate externally controlled launch gate or a registry state that distinguishes database readiness from customer activation.

## 10. Cognito bootstrap, MFA, and membership

The shared user pool requires TOTP MFA, disables self-registration, uses email sign-in, requires a 14-character mixed password, sets temporary passwords to three days, and is retained/deletion-protected. Each tenant stack creates a public client with no client secret, authorization-code flow, exact tenant web callback/logout URLs, one-hour access/ID tokens, seven-day refresh tokens, and revocation enabled.

After the source-defined tenant API is deployed, a reviewed hosted login/session
flow and membership-administration write path exist, and all tenant
infrastructure gates pass, create an initial user without placing a temporary
password in the CLI or ticket:

```bash
aws cognito-idp admin-create-user \
  --profile "$SP_AWS_PROFILE" \
  --region us-east-1 \
  --user-pool-id '<COGNITO_USER_POOL_ID>' \
  --username '<VERIFIED_USER_EMAIL>' \
  --user-attributes Name=email,Value='<VERIFIED_USER_EMAIL>' \
  --desired-delivery-mediums EMAIL
```

Do not set `email_verified=true` unless an approved process independently verified the address. Never use a shared bootstrap account. The invitee must set a new password and enroll TOTP at first managed-login sign-in; verify MFA registration and conduct a recovery test. Cognito's behavior is documented in [Administrator-created users](https://docs.aws.amazon.com/cognito/latest/developerguide/how-to-create-user-accounts.html) and [TOTP MFA](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa-totp.html).

A Cognito user or app client is not a tenant authorization grant. The application must create an explicit active tenant membership bound to immutable Cognito `sub`, tenant ID, role, inviter, and audit event. `RdsDataMembershipRepository` implements fail-closed active-membership reads under tenant RLS, but no operator API/UI implements the audited membership-creation/invitation workflow, so production user activation is blocked. Do not use email domain, Cognito groups, hostname alone, or editable token attributes as a substitute.

Bootstrap two tenant administrators only after a two-person approval and recovery-account review. Customer roles should be least privilege: tenant admin, compliance lead, reviewer, auditor, and collector as defined by the eventual server policy. Platform operators must remain separate from customer memberships.

## 11. Tenant activation gates

The current state machine changes the tenant and domain registry rows to `ACTIVE` after database and DNS verification. In this foundation, `ACTIVE` means **infrastructure-ready only**; it is not a customer-launch authorization. Keep the external/customer launch gate closed until every item below has attached evidence and named approval. Do not let an `ACTIVE` registry value bypass that separate gate.

- [ ] Account, region, domain, hosted-zone ID, tenant ID/slug, retention, and customer contract match the approved onboarding record.
- [ ] Shared, tenant, and observability CloudFormation stacks are stable and drift checks are clean.
- [ ] SNS subscription and budget/anomaly notifications are confirmed and tested.
- [ ] Exact DNS/certificates and WAF allow/deny tests pass; unknown hosts fail closed.
- [ ] An immutable, reviewed AWS web release is deployed through an approved OIDC pipeline. Direct Amplify origins cannot bypass tenant resolution.
- [ ] Cognito issuer, signature, client audience, `token_use`, time, session, exact callback, and logout behaviors pass; required TOTP is demonstrated.
- [ ] Tenant membership exists and revoked/missing/wrong-tenant users receive a non-disclosing failure.
- [ ] The tenant state machine applies migrations `001`-`005`, records schema `1`, preserves owner/runtime/ingest/evidence-control-worker/legal-hold-API separation, and passes positive and negative RLS/procedure-grant tests in the deployed environment.
- [ ] The upload role can write only its exact tenant/control quarantine prefix,
  cannot list or read either bucket or decrypt evidence, and is denied every
  other tenant's S3, KMS, secret, and database boundary. The separate legal-hold
  API and worker roles pass their request/approve versus reconcile/audit
  procedure and IAM denial tests.
- [ ] GuardDuty plan is `ACTIVE`, tagging works, threat/unsupported/access-denied/failed canaries alert correctly, and tag-failure events are monitored. The synthesized clean-scan rule is enabled; before deploying it, the composed authenticated issuer must durably create the exact lifecycle contract, and the clean canary must reach database-reconciled promotion.
- [ ] Exact upload intent, quarantine, checksum/size/MIME validation, promotion, Object Lock, receipt, audit, replay, and expiration tests pass.
- [ ] Server-managed retention cannot be overridden by the client; atomic
  60/300 per-minute and 500/5,000 per-UTC-day member/tenant upload quotas hold
  under concurrent requests, ambiguous provider responses, and exact retries.
- [ ] Browser and Mac device enrollment, revocation, origin binding, PKCE, and token rotation pass if enabled.
- [ ] CloudTrail S3 data events, WAF logs, application audit chain, Lambda/Step Functions logs, alarms, DLQs, and on-call routing are verified.
- [ ] Backup and one-tenant restore drill reconcile DynamoDB, Aurora, S3 versions/checksums/locks, Secrets Manager, KMS, and audit chain.
- [ ] Client A/Client B adversarial suite and an independent BOLA/IDOR-focused penetration test pass.
- [ ] Security, Operations, Product, Legal/Compliance, and customer owner sign the activation record.

**Current result: NO-GO.** The security adapters, per-tenant API, database migrations, promotion worker, CDK-wired two-person legal-hold routes/scheduled worker, recovery topology/backfill, and release workflow exist in source but have not been AWS/PostgreSQL/Apple integration-tested. The Amplify UI/auth callback, remaining product APIs, membership administration, legal-hold UI/operational drill, Mac enrollment, restore and regional-cutover drills, and controlled production deployment remain incomplete.

## 12. Mac enrollment status

The local Mac application remains usable without the hosted service. Its loopback Local Console and optional customer-managed S3 configuration are separate from AWS SaaS enrollment.

The repository contains secure building blocks for a future Cognito authorization-code + PKCE public client and a Keychain refresh-token store. They validate HTTPS endpoints, exact callback target, cryptographic state/verifier/challenge, transaction expiry, and tenant binding, and deliberately have no client-secret or AWS-key storage API. They are not integrated into `AppDelegate`, `ASWebAuthenticationSession`, URL-scheme registration, token exchange, discovery/JWKS validation, refresh/revocation, device attestation/enrollment, or upload APIs. The CDK also creates only tenant web clients with HTTPS callbacks, not a native-client callback.

The currently running Mac path still accepts a legacy `spdev_dev_...` device token for an exact configured server origin and defaults to the legacy hosted URL. That is not Cognito enrollment and must not be pointed at the AWS tenant host.

Before enabling hosted Mac sync:

1. Add a dedicated Cognito public native app client with exact approved callback(s), no secret, PKCE, short token lifetimes, and revocation.
2. Integrate system-browser authentication and one-shot callback consumption.
3. Validate issuer/JWKS signature, audience/client, token use, nonce/state, expiry, and tenant membership server-side.
4. Create an explicit device enrollment bound to tenant, user membership, device public key, server origin, scopes, expiry, and revocation.
5. Store only refresh credentials and device private material in Keychain; never AWS credentials or a client secret.
6. Add lost/reassigned-device revocation, token replay protection, refresh rotation, offline behavior, and audit events.
7. Test cross-tenant callback, malicious issuer, stale state, stolen refresh token, revoked device, changed origin, and tenant suspension.

## 13. Evidence ingest, quarantine, scanning, and promotion

### Intended production flow

1. An authenticated user/device with an active tenant membership requests an upload intent.
2. The client creates one canonical unpadded base64url 256-bit idempotency key for the logical operation. The server combines it with the tenant ID and server-only 32-64 byte HMAC to derive a stable opaque `upl_...` intent, nonce, and idempotency digest. The server—not the client—loads the tenant retention policy and derives the required retention/expiry dates from the accepted capture time; it binds those dates with the `evd_...` evidence ID, control-scoped quarantine/final keys, expected SHA-256, size, MIME, and maximum ten-minute upload expiry. PostgreSQL independently reloads tenant retention and rejects a projection that does not exactly match the server-derived dates.
3. The server returns a short-lived, checksum- and exact-key-bound presigned `PUT`; the client never receives AWS credentials or bucket listing/read access. The assumed upload role can write only the exact control-scoped quarantine prefix and generate an S3-bound data key. It cannot list, read quarantine/evidence objects, decrypt evidence, or use legal holds.
4. S3 writes a new version in the tenant quarantine bucket. The service records the exact version and verifies checksum, bytes, content type, nonce, tenant, intent state, and expiry.
5. GuardDuty scans the object and tags it. Only `COMPLETED` plus `NO_THREATS_FOUND`, with the matching managed tag on the same exact version, may enter promotion.
6. The promoter claims a monotonic attempt/fence in DynamoDB and PostgreSQL, atomically renews that lease while creating a durable `COPY_PERMITTED` attempt record, reads the exact quarantine `VersionId` with its ETag/checksum/size bound, and streams at most 25 MiB into one single-SDK-attempt `PutObject` with `If-None-Match: *`. S3 is the final creation fence: whether an older paused worker or its replacement reaches S3 first, only one current destination object can be created and the loser adopts the winner after a 409/412. The worker verifies the exact KMS/Object-Locked version, signs facts that distinguish the actual copy attempt/fence from the current reconciliation attempt/fence, verifies the KMS receipt before committing PostgreSQL, atomically projects the committed receipt/recovery change into DynamoDB, and then deletes only the exact quarantine version. The evidence-bucket policy denies `DeleteObject`, `DeleteObjectVersion`, and evidence creation without the conditional header, preventing both delete-marker creation and exact-version deletion on that prefix.
7. Threats, unsupported types, access denial, failures, tag failures, timeouts, and mismatches fail closed, alert, and never become evidence.

AWS documents the GuardDuty scan statuses and managed tag in [Monitoring Malware Protection for S3 scans](https://docs.aws.amazon.com/guardduty/latest/ug/monitoring-malware-protection-s3-scans-gdu.html) and its EventBridge schema in [Monitoring with EventBridge](https://docs.aws.amazon.com/guardduty/latest/ug/monitor-with-eventbridge-s3-malware-protection.html).

### Implemented source boundary and remaining deployment gaps

- `authorizeApiGatewayRequest` composes exact-host resolution, strict Cognito
  access-token verification, exact app-client binding, active tenant
  membership/RBAC, and non-disclosing failures. The per-tenant regional API
  Gateway/Lambda uses it for authenticated `GET /v1/me` and
  `POST /v1/upload-intents`; API Gateway's mock `GET /health` exposes no tenant
  data and invokes no Lambda. API Gateway's default endpoint is disabled, the exact origin is enforced, and the Lambda
  entry role can resolve only its API-domain record and assume only that
  tenant's data role. None of this is deployed, and it is not connected to the
  legacy Cloudflare/Sites routes or unreleased Amplify UI.
- `UploadIntentIssuer`, `DynamoConditionalUploadIntentStore`, and
  `RdsDataUploadIntentProjection` implement the checksum/key/expiry/KMS-bound
  presign and dual-store reservation. The composed upload route retrieves the
  tenant's current idempotency secret through temporary assumed credentials.
  DynamoDB atomically reserves lifecycle, nonce-digest, and idempotency rows and
  stores a bounded secret-screened recovery projection. The exact first request
  and every retry re-run the equality-checking database procedure, which closes
  Dynamo-success/RDS-failure and ambiguous RDS-commit response windows before
  returning a fresh presign.
- Upload issuance atomically increments both member and tenant minute counters
  before expensive work (60 and 300 requests per minute). New lifecycle,
  nonce/idempotency, member-day, and tenant-day reservations commit in one
  DynamoDB transaction (500 and 5,000 new reservations per UTC day). A strongly
  consistent exact-idempotency read happens first, so an exact retry returns the
  canonical reservation without consuming a second daily reservation. These
  source contracts still require deployed concurrency and throttling canaries.
- The HTTP body cannot supply retention dates. The route derives retention from
  the tenant policy, and the SQL upload-intent boundary independently verifies
  the same server-managed result. A client capture time more than five minutes
  in the future is rejected.
- The SQL, domain, IAM, S3-key, MIME, size, and promoter contracts agree on `tenants/<tenant-id>/controls/<control>/quarantine/<upload-id>.upload`, `tenants/<tenant-id>/controls/<control>/evidence/<evidence-id>.<extension>`, the six allowed evidence MIME types, and a 25 MiB maximum. That agreement is source-level only; no deployed end-to-end test has proved it.
- The per-tenant Secrets Manager secret contains server-only HMAC material. Clients send a canonical 256-bit base64url idempotency key and reuse it for the same logical request; neither the raw client key nor raw nonce is persisted. The route loads `AWSCURRENT` plus at most one optional `AWSPREVIOUS`; the prior key is tried only for strongly read, exact recovery and can never create a lifecycle. Keep the prior version selectable for at least intent expiry plus the seven-day reconciliation grace, and complete a live rotation/retry drill before production.
- `CleanMalwareScanResult` is enabled in the synthesized CDK. The worker validates the account, region, GuardDuty plan/event, exact bucket/key/`VersionId`, scan tag, ETag, checksum, metadata, size, MIME, issuance window, revision, tenant, KMS context, and Object Lock result. DynamoDB and PostgreSQL carry the same monotonic reconciliation fence, while a durable copy-attempt ledger and object metadata preserve the possibly older attempt that actually won S3. Exact-version `GetObject` plus single-attempt conditional `PutObject` lets a takeover adopt but never append a second version after a prior winner. The signed receipt binds both provenance identities; KMS verification occurs before the database commit and on authoritative retry/recovery reads. The worker deletes only the exact quarantine version after both stores commit. Primary bucket policy denies `DeleteObject`, `DeleteObjectVersion`, and evidence creation without `s3:if-none-match`.
- The quarantine lifecycle retains current and noncurrent versions for seven days to permit scan and database reconciliation. Threat/failed-scan forensic retention still requires an approved policy and operational runbook.
- Browser CORS permits exact tenant origins, but CORS is not authorization.

Do not upload customer evidence until the composed AWS handler and canonical
contract are deployed and proven end to end in dev and stage. Inspect `cdk diff`,
deploy only with approval, verify the enabled clean rule target/dead-letter
behavior, and run wrong-host/client/membership/tenant, clean, threat, unsupported,
access-denied, duplicate, expired, secret-rotation, ambiguous-commit,
mismatched-version, and tampered-intent canaries. Test malware handling only
under the approved GuardDuty procedure in the isolated test account.

## 14. Monitoring, incident routing, and DLQs

### Implemented alarms and logs

The shared stack defines alarms for shared-job DLQ depth, oldest shared-job age above 15 minutes, and sustained Aurora capacity above 3 ACUs. Each tenant defines an ingest/promotion DLQ alarm. The observability stack adds a multi-region CloudTrail with log-file validation, exact tenant ingest/evidence S3 data events, one-year CloudWatch logs, a compliance-locked audit bucket, and alarms for repeated denied AWS API calls and root-account use. WAF retains blocked-request logs for one year with sensitive headers redacted.

Confirm all alarms are `OK`, their SNS actions are enabled, and a controlled test changes and restores each expected alarm state. Attach screenshots/JSON evidence to the change record. Do not include customer payloads or credentials.

### Required monitoring not yet implemented

Add before production:

- Lambda errors, throttles, duration, concurrency, iterator/queue age, and log-delivery failures;
- Step Functions failed, timed-out, aborted, and long-running executions;
- GuardDuty plan health, scan latency, tag failures, skipped/unsupported/access-denied results, and scan-volume cost;
- Cognito sign-in failures, account takeover signals, MFA/recovery events, and token-revocation anomalies;
- tenant-aware application latency/error/denial metrics with no sensitive dimensions;
- CloudFront/Amplify 4xx/5xx, origin errors, certificate health, and WAF block/rate spikes;
- SES bounce/complaint/reputation alarms if email is enabled;
- KMS key disable/deletion scheduling and policy changes;
- backup age, restore-test age, CloudTrail delivery, audit-chain/checkpoint health, and storage growth;
- on-call escalation, acknowledgement SLAs, and ticket integration.

### DLQ response

For any DLQ alarm:

1. Acknowledge the alert, create an incident, record queue URL/ARN, time window, tenant identifier, approximate count/age, deploy version, and correlated request IDs. Never copy full customer evidence into the ticket.
2. Stop automated redrive. Do not purge the DLQ.
3. Inspect Lambda, GuardDuty, S3, KMS, and CloudTrail metadata to classify transient dependency failure, permission drift, contract mismatch, malicious input, or software defect.
4. For the evidence DLQ, verify the exact source bucket/key/version, tenant metadata, checksum, GuardDuty event and tag, destination state, monotonic lease/fence, durable copy-attempt ledger, and authoritative DynamoDB/PostgreSQL promotion receipts before any retry. If a conditional loser exists, confirm it adopted the sole destination `VersionId`; never issue an unconditional copy or manually delete a marker/version. Do not download or open an untrusted object on an operator workstation.
5. For the shared jobs DLQ, do not redrive: the repository has no job-worker implementation and the maintenance rule is disabled.
6. Fix and deploy the cause in dev/stage, test idempotency and duplicate delivery, then obtain incident-owner approval.
7. Redrive evidence messages at a bounded rate while watching errors, KMS/S3 activity, receipt state, and the destination version. AWS documents controlled DLQ redrive in [SQS dead-letter queue redrive](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-dead-letter-queue-redrive.html).
8. Reconcile every message and exact S3 version, close the alert, preserve evidence, and add a regression test.

## 15. Backup and restore

### Current protection

- DynamoDB control table: on-demand global table with PITR and deletion
  protection in the primary region and, when recovery is enabled, the recovery
  region; retained on stack removal. Existing single-region tables require the
  migration stop in section 6 and must not be directly updated.
- Aurora: seven-day automated backup retention, encryption, deletion protection, and a source-region customer-managed locked AWS Backup vault/plan that creates daily recovery points and copies them into a customer-managed-KMS Vault-Locked destination when `recovery.mode=enabled`.
- Tenant S3: versioning and Object Lock on promoted versions; exact-prefix
  same-account cross-region live replication; deterministic S3 Batch Replication
  for pre-cutoff existing `NONE`/`FAILED` versions; and bounded source/destination
  exact-version verification of canonical SHA-256 checksums, receipt/source/
  replica metadata, content length, destination KMS key, retention, and legal
  holds. A decoded S3 checksum must be exactly 32 bytes and match the hexadecimal
  promotion-receipt digest and both object metadata values. A legal-hold change
  newer than the immutable verification cutoff may defer only the mutable hold
  comparison; the worker still verifies every immutable source/replica fact in
  that generation. Checksum-mode HEAD of either SSE-KMS copy is backed by
  narrowly scoped `kms:Decrypt` plus `kms:GenerateDataKey`. Delete-marker
  replication is disabled, both primary and recovery evidence prefixes deny
  `DeleteObject` and `DeleteObjectVersion`, and production requires S3
  Replication Time Control. The recovery bucket's direct-PUT encryption-header
  denials exempt only the exact deterministic replication role ARN; the live
  recovery gate must prove that AWS supplies that `aws:PrincipalArn` context and
  can create an SSE-KMS replica while every other unqualified PUT is denied.
- CloudTrail audit bucket: versioning, KMS, compliance Object Lock for 365 days, retained.
- Secrets Manager and KMS resources: retained.

The recovery topology is implemented as a fail-closed two-phase CDK
configuration, not deployed or tested recovery evidence. The recovery reconciler
reserves a durable generation, uses an immutable cutoff/deterministic Batch client
token, waits for a terminal job with zero failed tasks, and persists bounded
verification cursors. `VERIFIED` is a point-in-time result rather than a terminal
state: the scheduled 15-minute reconciler starts another bounded verification
generation when `verifiedThrough` becomes 24 hours old. CloudWatch treats
missing data as breaching and alarms when S3 verification freshness exceeds 36
hours. A per-region Aurora monitor runs hourly and alarms after two consecutive
samples beyond the same 36-hour recovery-point freshness threshold. Live S3
replication failures request a new repair generation and publish a redacted
alert. The design is intentionally
same-account/cross-region and therefore does not protect against full account
compromise. There is no automated restore/cutover, audit-bucket replication,
demonstrated RTO/RPO, or restored-resource rewiring.

### Required backup policy

Before production, approve RPO/RTO and complete:

- bootstrap the destination stack, record exact output bucket/key/vault ARNs, enable the source configuration with those exact values, and validate daily Aurora recovery points/copies;
- verify global-table replication, PITR and restore semantics in both regions,
  plus periodic on-demand/cross-account recovery copies if required;
- a separately controlled recovery account if the threat model requires an account-compromise boundary;
- require every tenant backfill generation to reach durable `VERIFIED`, retain
  its S3 Batch report, reconcile zero failed tasks, exercise a repair request,
  and sample the exact version/checksum/Object-Lock comparisons; validate the
  recurring 24-hour verification and both 36-hour freshness alarms, including
  missing-data behavior;
- backed-up configuration, deployment manifests, public signing material, key metadata, secret references, tenant/resource maps, and audit heads;
- documented recovery of KMS/secrets without exporting secret plaintext;
- quarterly restore drills and evidence of reconciliation.

### Restore drill

1. Open a restore change/incident, select an exact UTC recovery point, freeze affected mutations, and record expected tenant/object/audit counts and hashes.
2. Restore into new isolated names and security boundaries. Never overwrite the source as the first action.
3. DynamoDB PITR always creates a new table. Reapply TTL, PITR, deletion protection, tags, alarms, and IAM wiring that are not restored automatically. See [DynamoDB PITR restore](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/pointintimerecovery_restores.html).
4. Aurora PITR creates a new cluster. With CLI restore, create a writer instance explicitly and apply the intended VPC, subnet/security group, parameter group, KMS, Data API, log exports, deletion protection, and backup settings. See [Aurora point-in-time restore](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-pitr.html).
5. Keep restored resources inaccessible to customers. Validate database/schema versions, role ownership/RLS, tenant/domain status, memberships, jobs, upload intents, evidence rows, S3 object versions/checksums/retention/holds, receipts, and the audit chain.
6. Reconcile DynamoDB and Aurora to a consistent time. S3 Object Lock/version history is independent; never assume a database timestamp alone identifies the correct object version.
7. Run Client A/Client B denial tests and a read-only application smoke test through a temporary non-public origin.
8. Cut over only with Security/Operations approval and a documented reverse plan. Rotate affected credentials and invalidate stale sessions.
9. Retain source and restored evidence according to incident/legal policy, then retire only through the approved offboarding process.

The current CDK creates the cross-region backup topology but cannot import or rewire restored DynamoDB/Aurora resources automatically. Until both recovery phases are deployed and a restore/cutover drill is reconciled, the production restore gate is not satisfied. Follow [AWS recovery and production macOS release](AWS_RECOVERY_AND_MACOS_RELEASE.md) for the exact two-phase configuration.

## 16. Retention, legal hold, and tenant offboarding

S3 Object Lock protects exact versions. A legal hold has no expiry and is independent of retention. In general S3, a simple delete can create a delete marker even while protected versions remain; Scopeproof's primary and recovery evidence-prefix policies explicitly deny both `DeleteObject` and `DeleteObjectVersion`, so runtime and administrators cannot create that marker or delete an exact version through those APIs. Always address and verify the exact non-empty `VersionId`, and treat any listed source or destination delete marker as a recovery-integrity failure. Review [Object Lock considerations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html).

The repository implements a durable two-person exact-version legal-hold domain
workflow and S3 client. One authenticated administrator commits immutable
requester-derived facts as `REQUESTED`; a separate authenticated administrator
commits an approval bound to the exact request digest as `APPROVED`; only then
may a worker commit `APPLYING` with a deterministic application-attempt ID,
the exact observed prior S3 hold status/request ID, and revision 2. The worker
then calls `PutObjectLegalHold` for one non-empty `VersionId`, reads that same
version back, and changes the operation to `APPLIED` with an expected-revision
CAS, approval digest, and provider request receipt. The worker can read existing
work but cannot create or approve it. S3 or database partial failure remains
durably `APPLYING`, so an identical retry can distinguish the intended change
from provider drift. Exact idempotent retries converge; changed facts,
same-actor approval, missing approval, and drift fail.
For durable HTTP idempotency, `changedAt` and `approvedAt` are canonical,
client-stable facts. PostgreSQL accepts a new `REQUESTED` or `APPROVED`
transition only when that timestamp is within five minutes of its server clock,
and approval must occur no later than 24 hours after the request. The database
checks an exact already-committed request/approval replay before applying the
new-transition clock-skew check, so the same canonical retry remains valid after
five minutes while a changed or newly backdated transition fails.
An unapproved `REQUESTED` operation becomes terminal `EXPIRED` after its
immutable 24-hour approval window. The bounded database sweep uses row locking
with `SKIP LOCKED`, never converts a request into an approval, never calls S3
for expiry, and leaves the expiry in a durable outbox until a KMS-signed
`evidence.legal_hold_request_expired` event is appended. An exact expired
operation cannot later be approved or reconciled.
Releasing one logical hold leaves S3 `ON` while any other active hold covers the
same version.

The general tenant upload role cannot use legal holds. The public legal-hold API
assumes a dedicated per-tenant workflow role and uses a dedicated database login
that can resolve membership and request/approve only; it has no S3, KMS,
reconciliation, list-work, or audit-append permission. Only the separate
evidence-control worker IAM role receives exact `s3:GetObjectLegalHold`,
`s3:PutObjectLegalHold`, and KMS signing/verification, and its separate
execute-only database identity can read/confirm pending work and append signed
audit events, expire stale requests, and record bounded retry metadata, but
cannot request or approve. Neither role receives `DeleteObject`
or `s3:BypassGovernanceRetention`, and the shared Amplify role may assume
neither tenant workflow role.

The remaining customer-facing process is:

1. Legal creates an authorized matter/ticket and identifies exact tenant, evidence ID, bucket, key, and version.
2. One authenticated active tenant administrator submits the request; a second
   authenticated active tenant administrator separately approves the exact
   request digest. API Gateway routes those exact operations to a separate
   low-concurrency legal-control Lambda. No UI exists, so customer exposure still
   requires an audited workflow and live authorization tests.
3. A dedicated least-privilege reconciler reads the committed approval, commits
   the durable `APPLYING` attempt, enables the S3 legal hold on the exact version,
   reads it back, and commits the provider receipt. It then KMS-signs and commits
   the append-only audit receipt in Aurora **before** publishing the audit-bound
   exact operation and `VersionId` to the idempotent recovery ledger, then
   records the exact publication timestamp in Aurora. The durable outbox remains
   eligible until that acknowledgement commits, so a publication or
   acknowledgement failure reuses the authoritative audit receipt and retries
   idempotently. Recovery never accepts a legal-hold projection without verifying
   that committed audit signature. The applied event binds the S3 write/readback
   request IDs, receipt digest, operation and hold revisions, application time,
   and exact version; the later recovery projection binds those facts to the
   committed audit hash, canonical receipt payload, KMS key, algorithm, and
   signature. EventBridge invokes the single-concurrency worker every five
   minutes; it never promotes or
   auto-approves `REQUESTED` work. Failed work remains in its durable `APPROVED`
   or `APPLYING` state and receives a database-enforced 30-second-to-six-hour
   exponential backoff so one poison row cannot permanently occupy the bounded
   queue head. Only a safe error code, attempt count, and failure/next-attempt
   timestamps are retained. Do not infer recovery publication merely from the
   presence of the audit event; require the exact `recovery_published_at`
   acknowledgement.
   CloudWatch alarms on worker/reconciliation failures, `APPROVED` age above 15
   minutes, `REQUESTED` age above 24 hours, and any newly expired request.
4. Export/download/delete operations consult both authoritative metadata and S3 before acting.
5. Release requires a second two-person decision, exact-version readback, immutable audit event, and continued retention enforcement.

Tenant offboarding is also not implemented. The registry custom resource intentionally has no delete action, while tables, databases, buckets, logs, secrets, and KMS keys are retained. Do not run `cdk destroy` or manually delete a tenant stack as an offboarding method.

Required future offboarding order:

1. Obtain customer, Legal, Security, and Operations authorization; inventory active holds/retention and define disposition.
2. Atomically set tenant and exact domain to `SUSPENDED`/`OFFBOARDING`; reject new sessions, presigns, uploads, jobs, exports, and integration calls.
3. Revoke memberships, devices, OAuth/integration credentials, refresh tokens, support grants, and queued work; preserve audit events.
4. Remove exact DNS/Amplify mapping only after application denial and session expiry are verified.
5. Produce and customer-approve a signed export/reconciliation manifest if contractually required.
6. Maintain evidence, backups, audit, KMS, and secrets until every Object Lock period and legal hold is satisfied.
7. Delete only exact eligible versions under dual control; verify absence and record provider request IDs.
8. Retire database/secret/bucket/key only after evidence, backups, and contractual windows close. KMS deletion requires a separate waiting period and recovery check.
9. Retain minimal non-sensitive tombstone/audit records required to prevent identifier reuse and prove completion.

## 17. Cost controls

The design avoids NAT Gateway, load balancer, always-on containers, and provisioned DynamoDB, but it does not idle to zero cost. Track at least:

- two KMS keys (evidence and secret), one Secrets Manager secret, two buckets, GuardDuty scans, queues, Lambdas, and logs per tenant;
- shared WAF rules, CloudFront, Amplify, Route 53, Cognito, SES, DynamoDB, Aurora storage/I/O/backup, CloudTrail data events, audit storage, and KMS keys;
- one-year retained logs and retained resources after failed deployments or stack removal;
- Object-Locked evidence and audit data that cannot be deleted early;
- GuardDuty charges for every uploaded/scanned object and CloudTrail data-event volume.

Operational controls:

- Always supply a real `alertEmail` and approved `monthlyBudgetUsd`; the code default is USD 100 but is not an approved production budget.
- Set environment-specific budget thresholds outside the fixed current CDK if the organization requires more than 80% forecast/100% actual.
- Tag every cost-bearing resource with environment, owner, tenant ID, data class, and cost center; the current global tags include only application/manager and tenant stacks add tenant ID/slug.
- Use synthetic, short-retention governance-mode data in dev; never copy production evidence into lower environments.
- Keep Lambda concurrency and Aurora maximum bounded, and alert on capacity/scan/log anomalies.
- Review S3 lifecycle against Object Lock and legal holds. The current evidence bucket has no archive/expiration lifecycle, and the audit bucket transitions but does not expire.
- Review retained CloudFormation resources after failed/rolled-back tests; retention protects data but also preserves cost.
- Split domains/accounts before 49 tenants rather than introducing wildcard routing or silently raising isolation blast radius.

## 18. Troubleshooting

| Symptom | Likely cause | Safe response |
| --- | --- | --- |
| Synthesis says region must be `us-east-1` | Profile/CLI resolved another region | Stop; correct the approved profile region. Do not edit out the region guard. |
| Placeholder-domain warning | `rootDomain` was omitted or is `jsontechology.com` | Stop. Supply the owned zone and existing hosted-zone ID. |
| Invalid tenant context | ID/slug/display/retention/JSON violates `config.ts` | Regenerate an opaque ID or correct the onboarding record; do not weaken validation. |
| CDK bootstrap parameter missing | Account/region was not bootstrapped | Reconfirm account, then bootstrap that exact environment with termination protection. |
| Certificate remains pending | DNS zone/delegation/record conflict | Verify authoritative NS and exact validation records. Do not bypass TLS or create wildcard shortcuts. |
| Tenant host resolves but has no app | The verified tenant state machine published DNS, but Amplify still has no approved source/release | Expected current blocker. Keep customer activation disabled; do not connect the legacy app. |
| WAF returns 403 | Host not exact, request over 64 KiB, managed rule, reputation, or rate limit | Correlate redacted WAF log/request ID; fix caller or narrowly tune after review. Never globally allow. |
| SNS alarm email absent | Subscription is pending or `alertEmail` omitted | Confirm the AWS email, inspect subscription state, and send a metadata-only test. |
| SES cannot send to customer | Account sandbox, identity/DKIM/MX incomplete, or reputation issue | Verify SES account/identity and approved production access; do not switch to an unreviewed sender. |
| Provisioning reports `ACTIVE`, but the service is unavailable | `ACTIVE` currently denotes database-boundary readiness, not customer activation | Confirm both registry rows and the state-machine evidence, then continue the remaining activation gates. Do not expose traffic or manually change status. |
| Provisioner reports a Data API parse/transaction failure | The packaged statement-aware migrator encountered unsupported SQL, timeout, engine drift, or a partial pre-existing schema | Preserve the failed execution and Lambda metadata. Fix and test the parser/migration in source; do not split or apply statements manually and do not force the registry to `ACTIVE`. |
| GuardDuty does not tag/scan | Plan not active, role/KMS/S3 notification drift, unsupported object, or upload preceded tagging | Keep object quarantined; inspect plan status/EventBridge/CloudTrail and alert. Never promote without exact clean event and tag. |
| Evidence promotion enters DLQ | Event/tag/version/checksum/metadata/MIME/size/path mismatch or S3/KMS failure | Follow the DLQ procedure; do not purge or blindly redrive. |
| CloudFront release returns 403 | Key missing, case/path mismatch, OAC/bucket policy propagation, or WAF host failure | Verify exact immutable key/version and distribution association; do not make the bucket public. |
| `UPDATE_ROLLBACK_FAILED` | CloudFormation could not restore a changed resource | Fix the underlying resource/permission and use `continue-update-rollback` sparingly. Skipped resources create drift and require reconciliation. |
| Aurora will not scale to zero | Engine/platform capability or pending connections/work | Verify the deployed engine/version and open sessions; never reduce resilience based only on cost. |
| `cdk destroy` cannot delete resources | Expected retention, deletion protection, Object Lock, or nonempty buckets | Stop. Use the approved retirement procedure; never disable protections to make destroy succeed. |

For a failed CloudFormation update, preserve events and diagnose before action. AWS documents recovery from `UPDATE_ROLLBACK_FAILED` in [ContinueUpdateRollback](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ContinueUpdateRollback.html).

## 19. Rollback and failed-change handling

### Before every change

- Record the deployed commit, exact context, synthesized template hashes, stack outputs, current CloudFormation status/drift, alarm state, DynamoDB latest-restorable time, Aurora earliest/latest restorable times, and relevant S3 object versions.
- Create an approved Aurora recovery point/snapshot for high-risk database changes and verify it becomes available.
- Preserve the prior immutable web/Mac release and signed metadata.
- Identify which changes are irreversible: Object Lock enablement/compliance retention, evidence writes, key deletion scheduling, DNS delegation, database migrations, and customer-visible audit events.

### Infrastructure rollback

1. If an update is still `UPDATE_IN_PROGRESS` and cancellation is safer, use CloudFormation's cancel operation through the approved change role and monitor until rollback completes.
2. If CloudFormation rolls back automatically, validate every retained resource, policy, DNS record, alarm, and data path; rollback completion is not data reconciliation.
3. If it enters `UPDATE_ROLLBACK_FAILED`, repair the exact cause and continue rollback. Skip the minimum resource only when Security approves and immediately reconcile template versus live state.
4. To roll forward to a prior infrastructure definition, check out the prior reviewed commit, use the exact approved context, run tests/synth/diff, obtain approval, and deploy. Do not use `git reset --hard`, edit live resources, or run `cdk destroy` as recovery.
5. Run drift detection and all tenant denial canaries after stability returns.

### Application/release rollback

There is no AWS web release pipeline yet. Its future rollback must redeploy an immutable prior bundle without changing tenant/DNS/auth boundaries. For static Mac assets, point the signed `latest` metadata back only if monotonic update policy permits it; normally publish a new higher sequence that references the approved artifact. Do not overwrite a versioned artifact key or reuse a release sequence.

### Database rollback

Migration `001` is forward-only; no down migration exists. Never improvise DDL rollback in production. Correct with a reviewed forward migration or restore a new cluster to the approved point, reconcile DynamoDB/S3/audit state, and perform a controlled cutover. Object-Locked S3 versions are not rolled back with Aurora.

## 20. Security validation and launch record

Before a production authorization, run in dev and stage:

- repository lint, unit, integration, Swift, and CDK synth tests from a clean locked install;
- CDK template security assertions and secrets scan;
- exact DNS/host/certificate/WAF behavior, including direct-origin and forwarded-host attacks;
- Cognito code-flow/PKCE, callback, MFA, logout, revocation, token issuer/audience/use/time, fixation, and recovery tests;
- exhaustive Client A/Client B API, SQL, S3, KMS, queue, cache, log, backup, support, export, Jira, SBOM, and Mac-device isolation tests;
- SSR/API cache-key and no-store tests for customer data;
- upload replay, checksum, size, MIME/polyglot, path, scan-status, tag, exact-version, Object Lock, and duplicate-event tests;
- queue poison/retry/DLQ/redrive and partial-failure tests;
- tenant suspend, user/device revoke, integration revoke, legal hold, retention expiry, and offboarding tests;
- restore and release rollback drills;
- independent application penetration test focused on BOLA/IDOR, authentication/session, SSRF, presigned URLs, S3/KMS, business logic, and support/operator paths.

The launch record must include tested commit/artifact hashes, environment/account/domain, full approved tenant context, infrastructure diffs, all gate evidence, known-risk acceptance, incident contacts, RPO/RTO, retention/legal opinion, penetration-test closure, and explicit signatures from Security, Operations, Product, and Legal/Compliance.

## 21. Exact current limitations

As of this runbook's snapshot:

1. No AWS account, domain, DNS, stack, database, bucket, Cognito user, or release was created or deployed by this work.
2. The live browser/API code is still the legacy Cloudflare/Sites, D1, and R2 single-tenant application. Its routes and queries are not AWS adapters or multi-tenant persistence.
3. `lib/aws-runtime` now has concrete exact-host/Dynamo, Cognito JWT/JWKS, active-membership/RDS Data, upload, reconciliation, S3 legal-hold, and KMS receipt adapters. Per-tenant API Gateway composes a mock `/health`, data Lambda routes for `/v1/me` and `/v1/upload-intents`, and separate legal-hold request/approval Lambda routes. They are source/template-tested, not deployed or live-integration-tested, and most product routes remain unmigrated.
4. Amplify has no source connection, CI/CD pipeline, build artifact, or deployed runtime. Manual Amplify deployment does not solve SSR hosting.
5. Exact tenant DNS is now created by the tenant provisioner only after database verification and Route 53 is awaited to `INSYNC`; however, the resulting `ACTIVE` status still means infrastructure/database readiness, not an application launch authorization.
6. Cognito has a shared user pool and tenant web clients, and strict access-token plus membership-read adapters exist, but no hosted callback/session composition, invitation/membership write workflow, federation, or account-recovery operations exist.
7. A per-tenant Cognito client is not isolation. The data API and legal-hold API have separate entry/workflow roles scoped to their exact tenant; the shared Amplify role cannot assume tenant upload or evidence-control roles, and there is no shared wildcard `sts:AssumeRole` grant. Future shared runtimes must preserve this boundary; higher-assurance customers may still require account-per-tenant isolation.
8. The database provisioner packages migration `001` and grant migrations `002`-`005`, separates owner plus runtime/ingest/evidence-control-worker/legal-hold-API logins, resets each application login to an execute-only procedure allowlist with no direct table grants, verifies ownership/RLS/identity/grants, and tests a wrong-tenant write denial, but none has been exercised against deployed Aurora/Data API.
9. `ACTIVE` currently means database readiness and is written before API/UI deployment, membership administration, live upload/release, restore, and penetration-test gates. A separate externally controlled customer-activation state/gate is not implemented. The offline renderer remains review/recovery tooling only, and there is no down migration.
10. No active tenant membership can be safely created through an implemented operator API/UI.
11. The Mac hosted OAuth/Keychain primitives are not integrated, and CDK has no native Cognito client. The Mac still uses the legacy exact-origin device-token flow.
12. The upload issuer and composed `/v1/upload-intents` route implement canonical 256-bit client idempotency, server-managed retention derived from tenant policy, atomic member/tenant quotas (60/300 requests per minute and 500/5,000 new reservations per UTC day), tenant HMAC derivation, atomic Dynamo reservation, RDS projection, exact retry, ambiguous-commit recovery, and recovery-only lookup with one optional `AWSPREVIOUS` key. It has not been deployed; concurrency/quota canaries, an outstanding-retry rotation drill, and a verified prior-stage retirement procedure remain required before production use.
13. `CleanMalwareScanResult` is enabled in synthesized IaC. The promoter uses a durable attempt ledger, monotonic DynamoDB/PostgreSQL fences, exact-version streaming, and single-attempt `If-None-Match: *` S3 creation so a delayed superseded worker can adopt but cannot append a second immutable destination version. Its KMS-signed receipt distinguishes copy provenance from reconciliation provenance and is verified before database commit and during authoritative recovery. None of this has been deployed or exercised against real GuardDuty events, S3 conditional-write races/Object Lock, KMS, or Data API.
14. The shared jobs queue has no worker, and its maintenance schedule is disabled.
15. Browser evidence browsing/download/export, tenant admin, Jira, GitHub/SBOM, integrations, devices, audit, retention, support, and offboarding are not migrated to the AWS runtime.
16. Durable exact-version S3 legal-hold code and PostgreSQL implement requester-derived `REQUESTED`, distinct-admin digest-bound `APPROVED`, worker-only durable `APPLYING`, and exact-readback `APPLIED` phases with separate public-API and reconciliation IAM/database roles. New request/approval timestamps must be within ±5 minutes of the database clock, approval must be within 24 hours of the request, and an exact old replay remains valid while a changed replay fails. The worker commits the KMS-signed audit receipt before publishing the audit-bound recovery projection; Aurora clears the durable publication outbox only after separately acknowledging the exact DynamoDB publication time. Source tests cover retry after the audit head advances and after publication ambiguity. CDK wires the two authenticated routes, five-minute bounded reconciliation/expiry/audit sweep, and failure/requested-age/approved-age alarms. No UI, deployed alert delivery, live Object Lock drill, or live proof of those audit/recovery partial-failure recoveries exists; do not expose the operation.
17. SES infrastructure is not connected to application mail. Sandbox exit, bounce/complaint handling, and reputation monitoring are operational gaps.
18. The protected macOS production workflow can Developer-ID sign, require Apple notarization acceptance, staple/assess, attest, and validate candidates with SBOM/provenance/redacted-receipt evidence; exact-candidate publication verification is scripted without rebuilding. Release configuration/build now reject non-canonical or invalid P-256 update keys, duplicate IDs, and expired/future/reversed validity windows. Advanced CodeQL preserves JavaScript/TypeScript/Actions analysis while using a manual arm64 Swift build. The repository setting must still be switched from default to advanced after merge and all three checks required. Apple credentials/protected settings are not configured here, no workflow has submitted an artifact, the release bucket remains empty, and AWS publication/updater discovery are separate gaps.
19. Monitoring covers selected AWS signals only; application, authentication, GuardDuty health, Lambda/Step Functions, CloudFront/SES, backup, key, and audit-chain coverage is incomplete.
20. A DynamoDB global control table, same-account cross-region S3 live replication, S3 Batch existing-version backfill, recurring 24-hour exact-version cryptographic/metadata verification with a 36-hour freshness alarm, Aurora AWS Backup/Vault Lock, and regional 36-hour recovery-point freshness alarms are implemented, but are not deployed. Every generation still verifies immutable checksum/receipt/KMS/retention/metadata facts when a later legal-hold projection defers only the mutable hold comparison; a bounded destination inventory rejects delete markers and orphan versions before advancing the watermark. Existing `AWS::DynamoDB::Table` deployments require a retain/remove/convert/import migration. There is no recovery-account isolation, audit-bucket cross-region copy, automated restore/cutover, or demonstrated RPO/RTO.
21. Tenant suspension, customer-facing legal-hold UI/operational release workflow, exact-version deletion, and offboarding are not implemented end to end; stack destruction is unsupported because data resources are retained/deletion-protected/Object-Locked.
22. WAF rate limiting is only per source IP and the host/body settings require real traffic validation. The upload-intent route has atomic per-member/per-tenant quotas, but those controls have not been load-tested in AWS and route-specific quotas are still required as additional APIs are migrated.
23. Current tests are local unit/domain/template assertions, not deployed AWS integration, restore, isolation, chaos, or penetration-test evidence.
24. Primary serving remains single-region and uses one shared Aurora cluster/global control table/user pool. A recovery-region DynamoDB replica and data copies exist in source design, but there is no automatic regional application/Aurora failover or restored-resource rewiring.
25. The default placeholder domain warns rather than hard-fails, and several fixed resource names make account-per-environment isolation operationally necessary.

None of these limitations may be reclassified as “accepted” merely because CloudFormation reports success.

## 22. AWS references

- [AWS SaaS tenant isolation](https://docs.aws.amazon.com/whitepapers/latest/saas-architecture-fundamentals/tenant-isolation.html)
- [AWS CDK bootstrapping](https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping.html)
- [AWS CDK deployment](https://docs.aws.amazon.com/cdk/v2/guide/deploy.html)
- [IAM Identity Center authentication for AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
- [Amplify SSR support](https://docs.aws.amazon.com/amplify/latest/userguide/ssr-amplify-support.html)
- [Cognito application clients](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html)
- [Aurora RDS Data API](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api.html)
- [PostgreSQL row-level tenant isolation](https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-managed-postgresql/rls.html)
- [GuardDuty Malware Protection for S3](https://docs.aws.amazon.com/guardduty/latest/ug/how-malware-protection-for-s3-gdu-works.html)
- [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- [DynamoDB point-in-time restore](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/pointintimerecovery_restores.html)
- [Aurora point-in-time restore](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/aurora-pitr.html)
- [SQS DLQ redrive](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-dead-letter-queue-redrive.html)
