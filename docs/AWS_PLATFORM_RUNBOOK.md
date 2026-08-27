# Scopeproof AWS platform operator runbook

> **Pre-deployment status — 2026-08-27:** this repository contains an AWS CDK foundation and security-domain code, but no AWS resources have been deployed or validated by this project work. The current browser/API application is still the legacy Cloudflare/Sites, D1, and R2 single-tenant runtime. It is not the AWS multi-tenant service described here. Do not direct a second customer hostname to the legacy runtime.
>
> **Production stop:** do not onboard a customer or serve traffic from the AWS hostname. The database state machine now packages, applies, and tests the PostgreSQL baseline, but it has not been exercised in an AWS integration environment. More importantly, the Amplify app has no source connection or application release, no hosted issuer writes authoritative upload intents, and the clean-scan promotion rule is deliberately disabled. A successful infrastructure deployment or database execution is not customer-service activation.

This is the start-to-finish operator procedure for the selected [AWS CDK foundation](../infra/aws/cdk), its [PostgreSQL contract](../infra/aws/database), the tested [runtime security contracts](../lib/aws-runtime), the macOS [hosted-authentication design](../macos/ScopeproofCapture/HOSTED_AUTHENTICATION.md), the migration design in [AWS multi-tenant hosting](AWS_MULTI_TENANT_HOSTING.md), and the current [adversarial AWS security review](AWS_SECURITY_REVIEW.md). Commands are examples for an authorized operator. Replace every `<PLACEHOLDER>`, use temporary IAM Identity Center credentials, record changes in the organization change system, and never paste passwords, tokens, access keys, private signing keys, or secret values into shell history, CDK context, tickets, or this repository.

Keep these lifecycle stages distinct:

| Stage | What it proves | What it does not prove |
| --- | --- | --- |
| Local tests and `cdk synth` | Source contracts compile and CloudFormation can be generated | No AWS resource exists; no IAM, service, network, or engine behavior was exercised |
| `cdk diff` and approved stack deployment | Reviewed infrastructure resources exist in the target account | The tenant database is not provisioned and no customer application is running |
| Tenant state-machine execution | Migrations `001` and `002`, identity seed, grants, ownership/RLS invariants, a wrong-tenant write denial, and DNS-last publication passed for that tenant | `ACTIVE` is infrastructure/database readiness only; it does not release an application, create users/memberships, enable uploads, or authorize customer service |
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
| Tenant data plane | Per-tenant Cognito client, IAM role, evidence and secret KMS keys, quarantine/evidence buckets, GuardDuty, promotion queue/Lambda, database provisioning workflow | Not end-to-end usable; database flow still needs AWS validation and promotion is deliberately disabled |
| Audit infrastructure | Multi-region CloudTrail, exact tenant S3 data events, locked audit bucket, selected alarms | Not deployed; application audit persistence is absent |
| AWS runtime code | In-memory tenancy, upload, job, audit, and retention contracts under `lib/aws-runtime` | Domain code and tests only; no HTTP, Cognito, DynamoDB, Aurora, S3, or queue adapters |
| Browser/API runtime | Legacy Cloudflare/Sites application | Single tenant; must not serve multiple customers |
| macOS hosted auth | PKCE and Keychain primitives under `HostedOAuth.swift` and `HostedTokenStore.swift` | Not integrated with app UI, callback handling, token exchange, or device enrollment |

The operator-facing source contracts are the [tenant schema](../infra/aws/database/001_tenant_schema.sql), [runtime-role grant migration](../infra/aws/database/002_runtime_role.sql), [tenant provisioner](../infra/aws/cdk/runtime/provision-tenant/index.mjs), [evidence promoter](../infra/aws/cdk/runtime/promote-evidence/index.mjs), [tenancy boundary](../lib/aws-runtime/tenancy.ts), [upload lifecycle](../lib/aws-runtime/upload.ts), [audit contract](../lib/aws-runtime/audit.ts), [OAuth/PKCE primitives](../macos/ScopeproofCapture/Sources/ScopeproofCapture/HostedOAuth.swift), and [Keychain token abstraction](../macos/ScopeproofCapture/Sources/ScopeproofCapture/HostedTokenStore.swift). Treat their tests as source-level evidence, not deployed-service assurance.

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

1. **Shared platform.** This creates shared identity/control/database/edge/release resources and exact Amplify domain mappings for the complete tenant list. It does not publish a tenant CNAME.
2. **One tenant stack at a time.** Confirm each stack creates only the expected tenant's evidence KMS key, secret KMS key, buckets, Cognito client, IAM role, secret, GuardDuty plan, queues, Lambda functions, and state machine.
3. **Observability.** This depends on the shared and every tenant stack so CloudTrail can enumerate exact S3 data-event resources.

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

Record CloudFormation events and stack outputs. Relevant shared outputs are `RootDomain`, `HostedZoneId`, `AmplifyAppId`, `AmplifyDefaultDomain`, `CognitoUserPoolId`, `CognitoLoginDomain`, `ControlPlaneTableName`, `DatabaseClusterArn`, `JobsQueueUrl`, `OperationsTopicArn`, `ReleaseBucketName`, and `ReleaseDownloadOrigin`. Relevant tenant outputs include hostname/ID, Cognito client ID, data-role ARN, bucket names, KMS ARN, database name/runtime username/secret ARN, provisioning state-machine ARN, ingest DLQ URL, and Malware Protection plan ID.

### DNS-last activation boundary

The shared stack may create the exact Amplify subdomain mapping needed for certificate/domain preparation, but it does not publish the tenant Route 53 CNAME. The tenant provisioner re-runs database verification, UPSERTs only the stack-controlled exact CNAME through hosted-zone- and record-scoped IAM, waits for Route 53 `INSYNC`, then marks database and registry state `ACTIVE`. If a later activation write fails, the CNAME can remain, but both registry rows remain non-active and the database is restored to `PROVISIONING`. The future runtime must therefore return the same generic `404` for unknown, `PROVISIONING`, `FAILED`, suspended, or unauthorized tenants before any customer data access. DNS remains routing, never authorization.

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

Verify the ACL association to Amplify and the release CloudFront distribution. Exercise allowed host, unknown host, oversized request, managed-rule, and rate-limit canaries from authorized test sources. Inspect false positives before tuning; use scoped exclusions, never disable a whole managed group without a reviewed compensating control. The current rate limit is per IP, not per tenant or authenticated principal, so application-layer quotas are still required.

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

### 8.5 Amplify application release — currently blocked

The CDK creates a `WEB_COMPUTE` Amplify app and branch, but deliberately creates no repository/source connection and has auto-build disabled. The repository's web app still targets Cloudflare/Sites and is not a deployable AWS Next.js migration. AWS also states that manual Amplify deployments do not support SSR apps. Therefore:

- do not connect the legacy repository in the console;
- do not manually patch the Amplify app, role, environment, or branch and create untracked drift;
- implement and review the AWS runtime migration, Amplify-compatible build output, OIDC-based CI/CD/source connection, immutable commit pinning, deployment tests, and rollback before any web release;
- keep tenant traffic disabled until exact-host resolution, Cognito validation, active membership authorization, tenant role assumption, cache controls, and persistence adapters pass adversarial tests.

See AWS's [Amplify SSR deployment specification](https://docs.aws.amazon.com/amplify/latest/userguide/ssr-deployment-specification.html) and its warning that [manual deploys do not support SSR](https://docs.aws.amazon.com/amplify/latest/userguide/manual-deploys.html).

### 8.6 CloudFront and Mac release assets

The shared stack creates a private, versioned release bucket behind CloudFront at `downloads.<ROOT_DOMAIN>`, with origin access control, TLS 1.2 (2021 policy), HTTP/2 and HTTP/3, security headers, WAF, and access logs. It does not publish an application artifact or configure the Mac updater.

For a future production release:

1. Build only from an immutable, clean release commit.
2. Run `Scripts/publish_release.sh` with an offline P-256 update key, Developer ID identity, notarization profile, team ID, designated requirement, monotonically increasing sequence, and the final versioned HTTPS URL. Never place the private key or notarization credentials in the release bucket, CDK context, Amplify variables, or logs.
3. Verify Developer ID signature, hardened runtime, notarization, staple, Gatekeeper acceptance, archive digest, signed envelope, and clean-Mac installation.
4. Upload the exact ZIP, public signed envelope/manifest, and SHA-256 file to immutable versioned keys such as `macos/<VERSION>/...`. The production update script emits a ZIP, not the development-preview DMG.
5. Retrieve each resulting S3 `VersionId`, independently download through CloudFront, and compare size and SHA-256.
6. Publish or update a stable `latest` pointer only after immutable assets verify. Prefer versioned filenames; AWS recommends versioned names over invalidations for reliable rollback and cache behavior. If an existing stable key must change, invalidate only the exact affected path.
7. Record artifact hashes, object versions, signing identity, notarization result, CloudFront URL, release commit, and approvers.

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

## 9. Tenant database schema and provisioning

### 9.1 Authoritative files and roles

- [Migration 001](../infra/aws/database/001_tenant_schema.sql) creates the tenant schema, tenant-aware keys, forced row-level security, boundary triggers, upload/evidence/job/audit/retention records, and migration version `1`.
- [Migration 002](../infra/aws/database/002_runtime_role.sql) validates a non-privileged, non-owner runtime role and grants bounded, non-destructive access.
- The [tenant provisioner](../infra/aws/cdk/runtime/provision-tenant/index.mjs) is the deployed apply/verify implementation. The tenant Lambda asset packages both authoritative SQL files.
- The [offline SQL renderer](../Scripts/render_aws_tenant_sql.mjs) is review/recovery tooling. It is not the payload used by the state machine.

The CDK derives three separate database identities from the validated tenant slug and opaque tenant ID:

- database: `scopeproof_<NORMALIZED_SLUG>`;
- NOLOGIN database owner: `scopeproof_<FIRST_11_NORMALIZED_SLUG_CHARACTERS>_<FULL_32_HEX_TENANT_SUFFIX>_owner`;
- LOGIN runtime role: `tenant_<FIRST_11_NORMALIZED_SLUG_CHARACTERS>_<FULL_32_HEX_TENANT_SUFFIX>_app_runtime`.

Normalization replaces hyphens with underscores. The full tenant-ID suffix prevents collisions between long slugs with the same prefix while keeping every PostgreSQL identifier at or below 63 characters. Treat the `TenantDatabaseName` and `TenantDatabaseUsername` CloudFormation outputs as authoritative; do not reconstruct a recovery username by hand. The generated Secrets Manager secret contains only the runtime username/database and a generated 40-character password, encrypted under a separate per-tenant secret KMS key. The provisioner converts that secret to a PostgreSQL SCRAM verifier before constructing role SQL so the reusable plaintext cannot enter PostgreSQL failure logs. Operators must never retrieve or print the password or verifier.

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
  --aws-account-id '<12_DIGIT_ACCOUNT_ID>' \
  --aws-region 'us-east-1' \
  --quarantine-bucket '<INGEST_BUCKET_OUTPUT>' \
  --evidence-bucket '<EVIDENCE_BUCKET_OUTPUT>' \
  --kms-key-arn '<EVIDENCE_KEY_ARN_OUTPUT>' \
  --output '<APPROVED_TEMPORARY_DIRECTORY>/tenant-bootstrap.sql'

shasum -a 256 '<APPROVED_TEMPORARY_DIRECTORY>/tenant-bootstrap.sql'
```

The renderer validates/quotes every supplied value, writes mode `0600`, and refuses overwrite. Its output contains customer metadata and resource identifiers but no password. Never commit it. It includes a review-oriented seed with a pending database domain; do not manually apply it over a database managed by the state machine or treat its hash as the deployed Lambda asset hash.

### 9.3 What the state machine applies and verifies

The state machine runs `AcquireProvisioningLease → InitializeTenantDatabase → VerifyTenantDatabase → ActivateTenant`; failures run `MarkTenantFailed`. Execution data is excluded from its encrypted one-year logs.

The provisioner currently:

1. Atomically leases both exact DynamoDB tenant and domain rows when their status is `PROVISIONING` or `FAILED`.
2. Reads the generated runtime secret without logging it; validates exact username and password shape.
3. Creates or hardens a NOLOGIN, non-privileged owner role and a distinct LOGIN, non-privileged runtime role. It grants the database administrator temporary membership in the owner role only for the migration transaction and revokes that membership in a `finally` path.
4. Creates the tenant database owned by the owner role; revokes `PUBLIC` connection and grants only the runtime role connection.
5. Refuses an unversioned partial `scopeproof` schema. When migration `1` is absent, it changes to the dedicated owner role, parses the packaged SQL, and executes each statement through RDS Data API inside one explicit transaction. This makes the owner—not the cluster administrator—the schema/table/function owner and handles the Data API rule that one `ExecuteStatement` call cannot contain multiple statements; see [Troubleshooting RDS Data API](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api.troubleshooting.html).
6. In a transaction with the exact tenant context, seeds the immutable tenant identity and a verified canonical database-domain row from stack-controlled account, region, bucket, KMS, hostname, retention, and display metadata.
7. Safely substitutes the validated runtime-role token and applies the bounded grants migration.
8. Connects using the runtime secret and verifies the exact user/database, schema `USAGE` but no `CREATE`, non-privileged role flags, the single named migration and packaged SHA marker, the exact table/domain/function set and owner, every expected forced-RLS policy, tenant foreign key, boundary/immutability/audit trigger, singleton tenant identity, and single verified canonical database-domain row. It also verifies the owner is NOLOGIN/unprivileged and is no longer granted to the administrator.
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

On `SUCCEEDED`, use consistent reads to verify both registry rows are `ACTIVE`, refer to the same tenant ID/hostname, and report schema version `1`. Independently run the positive/negative database canary in the isolated test account. At minimum it must verify migration version, exact identity, database owner/runtime separation, every RLS/`FORCE RLS` flag, trigger/grant/timeouts, and denial of wrong-tenant reads, writes, joins, and foreign keys.

`ACTIVE` currently means that the database boundary passed the provisioner's checks. It does **not** mean the customer service is launched: no web runtime, membership, Mac enrollment, upload issuer, enabled promotion rule, restore drill, or penetration test follows from this state. Keep the Amplify app unreleased and do not create customer access until the remaining activation gates pass. Before a live multi-tenant runtime exists, introduce a separate externally controlled launch gate or a registry state that distinguishes database readiness from customer activation.

## 10. Cognito bootstrap, MFA, and membership

The shared user pool requires TOTP MFA, disables self-registration, uses email sign-in, requires a 14-character mixed password, sets temporary passwords to three days, and is retained/deletion-protected. Each tenant stack creates a public client with no client secret, authorization-code flow, exact tenant web callback/logout URLs, one-hour access/ID tokens, seven-day refresh tokens, and revocation enabled.

After the hosted login/session runtime and membership adapter exist and all tenant infrastructure gates pass, create an initial user without placing a temporary password in the CLI or ticket:

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

A Cognito user or app client is not a tenant authorization grant. The application must create an explicit active tenant membership bound to immutable Cognito `sub`, tenant ID, role, inviter, and audit event. No operator API/UI or persistence adapter currently exists for this step, so production user activation is blocked. Do not use email domain, Cognito groups, hostname alone, or editable token attributes as a substitute.

Bootstrap two tenant administrators only after a two-person approval and recovery-account review. Customer roles should be least privilege: tenant admin, compliance lead, reviewer, auditor, and collector as defined by the eventual server policy. Platform operators must remain separate from customer memberships.

## 11. Tenant activation gates

The current state machine changes the tenant and domain registry rows to `ACTIVE` after database and DNS verification. In this foundation, `ACTIVE` means **infrastructure-ready only**; it is not a customer-launch authorization. Keep the external/customer launch gate closed until every item below has attached evidence and named approval. Do not let an `ACTIVE` registry value bypass that separate gate.

- [ ] Account, region, domain, hosted-zone ID, tenant ID/slug, retention, and customer contract match the approved onboarding record.
- [ ] Shared, tenant, and observability CloudFormation stacks are stable and drift checks are clean.
- [ ] SNS subscription and budget/anomaly notifications are confirmed and tested.
- [ ] Exact DNS/certificates and WAF allow/deny tests pass; unknown hosts fail closed.
- [ ] An immutable, reviewed AWS web release is deployed through the future pipeline. Direct Amplify origins cannot bypass tenant resolution.
- [ ] Cognito issuer, signature, client audience, `token_use`, time, session, exact callback, and logout behaviors pass; required TOTP is demonstrated.
- [ ] Tenant membership exists and revoked/missing/wrong-tenant users receive a non-disclosing failure.
- [ ] The tenant state machine applies migrations `001` and `002`, records schema `1`, preserves owner/runtime separation, and passes positive and negative RLS tests in the deployed environment.
- [ ] Tenant role can access only its bucket/key/database secret and is denied another tenant's S3, KMS, secret, and database boundary.
- [ ] GuardDuty plan is `ACTIVE`, tagging works, threat/unsupported/access-denied/failed canaries alert correctly, and tag-failure events are monitored. After the upload issuer exists and its contract tests pass, the clean-scan rule is enabled through reviewed CDK and the clean canary reaches promotion.
- [ ] Exact upload intent, quarantine, checksum/size/MIME validation, promotion, Object Lock, receipt, audit, replay, and expiration tests pass.
- [ ] Browser and Mac device enrollment, revocation, origin binding, PKCE, and token rotation pass if enabled.
- [ ] CloudTrail S3 data events, WAF logs, application audit chain, Lambda/Step Functions logs, alarms, DLQs, and on-call routing are verified.
- [ ] Backup and one-tenant restore drill reconcile DynamoDB, Aurora, S3 versions/checksums/locks, Secrets Manager, KMS, and audit chain.
- [ ] Client A/Client B adversarial suite and an independent BOLA/IDOR-focused penetration test pass.
- [ ] Security, Operations, Product, Legal/Compliance, and customer owner sign the activation record.

**Current result: NO-GO.** The database migrator exists but has not been AWS-tested. The web runtime, membership adapter, upload-intent API, guarded activation of clean promotion, Mac enrollment, and production release path are incomplete.

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
2. The server creates an opaque `upl_...` intent and `evd_...` evidence ID, exact tenant-bound quarantine and final keys, expected SHA-256, size, MIME, nonce digest, maximum ten-minute expiry, and required retention-until time.
3. The server returns a short-lived, checksum- and exact-key-bound presigned `PUT`; the client never receives AWS credentials or bucket listing access.
4. S3 writes a new version in the tenant quarantine bucket. The service records the exact version and verifies checksum, bytes, content type, nonce, tenant, intent state, and expiry.
5. GuardDuty scans the object and tags it. Only `COMPLETED` plus `NO_THREATS_FOUND`, with the matching managed tag on the same exact version, may enter promotion.
6. The complete production design requires the promoter to copy the verified exact version into the tenant KMS/Object-Locked evidence bucket, verify returned version/retention, write a KMS-verifiable immutable receipt/audit event, atomically advance both durable metadata stores, and then delete only the exact quarantine version. The current worker implements the S3/DynamoDB portion only, as called out below.
7. Threats, unsupported types, access denial, failures, tag failures, timeouts, and mismatches fail closed, alert, and never become evidence.

AWS documents the GuardDuty scan statuses and managed tag in [Monitoring Malware Protection for S3 scans](https://docs.aws.amazon.com/guardduty/latest/ug/monitoring-malware-protection-s3-scans-gdu.html) and its EventBridge schema in [Monitoring with EventBridge](https://docs.aws.amazon.com/guardduty/latest/ug/monitor-with-eventbridge-s3-malware-protection.html).

### Current implementation gaps

- No hosted API authenticates a membership, persists an upload intent, or issues a presigned upload.
- The SQL, domain, IAM, S3-key, MIME, size, and promoter contracts now agree on `tenants/<tenant-id>/quarantine/<upload-id>.upload`, `tenants/<tenant-id>/evidence/<evidence-id>.<extension>`, the six allowed evidence MIME types, and a 25 MiB maximum. That alignment is source-level only; no deployed end-to-end test has proved it.
- The clean-result EventBridge rule `CleanMalwareScanResult` is deliberately **disabled** in CDK. The GuardDuty plan and rejected/failed-result alert rule may be deployed, but clean events cannot enter the queue until an authoritative hosted issuer writes the exact `UploadLifecycle` DynamoDB item required by the promoter.
- The promoter validates the AWS account, region, GuardDuty plan ARN/event, exact bucket/key/version, managed tag, ETag, checksum, metadata, size, MIME, intent expiry/revision, tenant and Object Lock/KMS result; uses conditional DynamoDB transitions and a promotion receipt; and deletes only the exact quarantine version after success. It still does not update the PostgreSQL upload/evidence/ingest records, create the SQL-defined signed receipt, or append the application audit chain.
- The quarantine lifecycle expires current and noncurrent versions after one day. Threat/failed-scan forensic retention and legal requirements have not been integrated.
- Browser CORS permits exact tenant origins, but CORS is not authorization.

Do not upload customer evidence to this hosted pipeline until the missing API/persistence/audit adapters exist and the canonical source contract is proven end to end. Do not enable the clean rule manually in the EventBridge console. Add an explicit, reviewed CDK activation control only after the issuer atomically writes the exact `UploadLifecycle` item and returns a checksum-, key-, expiry-, nonce-, tenant-, and content-bound presign. Validate it in dev and stage, inspect `cdk diff`, deploy the change, verify the rule target/dead-letter behavior, and run clean, threat, unsupported, access-denied, duplicate, expired, mismatched-version, and tampered-intent canaries. Test malware handling only under the approved GuardDuty test procedure in the isolated test account.

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
4. For the evidence DLQ, verify the exact source bucket/key/version, tenant metadata, checksum, GuardDuty event and tag, destination state, and DynamoDB promotion receipt before any retry. Do not download or open an untrusted object on an operator workstation.
5. For the shared jobs DLQ, do not redrive: the repository has no job-worker implementation and the maintenance rule is disabled.
6. Fix and deploy the cause in dev/stage, test idempotency and duplicate delivery, then obtain incident-owner approval.
7. Redrive evidence messages at a bounded rate while watching errors, KMS/S3 activity, receipt state, and the destination version. AWS documents controlled DLQ redrive in [SQS dead-letter queue redrive](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-configure-dead-letter-queue-redrive.html).
8. Reconcile every message and exact S3 version, close the alert, preserve evidence, and add a regression test.

## 15. Backup and restore

### Current protection

- DynamoDB control table: point-in-time recovery and deletion protection, retained on stack removal.
- Aurora: seven-day automated backup retention, encryption, deletion protection, retained on stack removal.
- Tenant S3: versioning; evidence versions use Object Lock on promotion; both buckets and keys are retained.
- CloudTrail audit bucket: versioning, KMS, compliance Object Lock for 365 days, retained.
- Secrets Manager and KMS resources: retained.

These are protective settings, not a tested disaster-recovery program. There is no AWS Backup plan, cross-account vault, cross-region replication, automated restore, RTO/RPO validation, or restored-resource rewiring in the repository.

### Required backup policy

Before production, approve RPO/RTO and implement:

- scheduled Aurora recovery points/snapshots retained beyond the current seven-day window as required;
- DynamoDB PITR plus periodic on-demand/cross-account recovery copies if required;
- cross-account, logically isolated backup vault controls and deletion protection;
- S3 Inventory/checksum reconciliation and approved replication where residency/Object Lock allow it;
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

The current CDK cannot import or rewire restored DynamoDB/Aurora resources automatically. Until a tested recovery stack/configuration exists, the production restore gate is not satisfied.

## 16. Retention, legal hold, and tenant offboarding

S3 Object Lock protects exact versions. A legal hold has no expiry and is independent of retention; a simple delete can create a delete marker even while protected versions remain. Always address the exact `VersionId`. Review [Object Lock considerations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html).

The repository has retention/legal-hold domain logic and a PostgreSQL `retention_holds` model with dual-person release, but no persistence adapter, operator API/UI, or S3 `PutObjectLegalHold` workflow. The tenant data role does not have legal-hold permissions. A database hold record alone does not place an S3 legal hold. Therefore hosted legal holds are not currently operable.

The required future legal-hold process is:

1. Legal creates an authorized matter/ticket and identifies exact tenant, evidence ID, bucket, key, and version.
2. Two distinct authorized people approve the hold.
3. The service atomically records the hold/audit event and enables the S3 legal hold on the exact version, then reads it back and records the provider request/version.
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
3. `lib/aws-runtime` is tested domain logic only; it is not connected to HTTP requests, token verification, DynamoDB, Aurora, S3, SQS, KMS, Secrets Manager, or CloudTrail/application audit storage.
4. Amplify has no source connection, CI/CD pipeline, build artifact, or deployed runtime. Manual Amplify deployment does not solve SSR hosting.
5. Exact tenant DNS is now created by the tenant provisioner only after database verification and Route 53 is awaited to `INSYNC`; however, the resulting `ACTIVE` status still means infrastructure/database readiness, not an application launch authorization.
6. Cognito has a shared user pool and tenant web clients, but no hosted login callback/session middleware, JWKS/token adapter, invitation/membership operator workflow, federation, recovery operations, or application authorization integration.
7. A per-tenant Cognito client is not isolation. The intended shared compute role can assume every tenant data role; a shared-runtime compromise can cross tenants. Higher-assurance customers still require account/per-tenant compute isolation.
8. The database provisioner packages and transactionally applies migrations `001` and `002`, separates database owner/runtime roles, verifies ownership/RLS/identity/grants, and tests a wrong-tenant write denial, but none of this has been exercised against a deployed Aurora/Data API environment.
9. `ACTIVE` currently means database readiness and is written before the absent application, membership, upload, release, restore, and penetration-test gates. A separate externally controlled customer-activation state/gate is not implemented. The offline renderer remains review/recovery tooling only, and there is no down migration.
10. No active tenant membership can be safely created through an implemented operator API/UI.
11. The Mac hosted OAuth/Keychain primitives are not integrated, and CDK has no native Cognito client. The Mac still uses the legacy exact-origin device-token flow.
12. No hosted API issues upload intents or presigned requests or persists the exact DynamoDB `UploadLifecycle` item. Source-level SQL/domain/promoter key, size, and MIME contracts are aligned, but no deployed end-to-end adapter proves them.
13. GuardDuty/promotion infrastructure is intentionally inert for clean files: the plan is enabled but `CleanMalwareScanResult` is disabled until the issuer contract exists. The promoter's conditional DynamoDB lifecycle and S3 copy path do not update PostgreSQL lifecycle records, create SQL-defined signed receipts, or append the application audit chain.
14. The shared jobs queue has no worker, and its maintenance schedule is disabled.
15. Browser evidence browsing/download/export, tenant admin, Jira, GitHub/SBOM, integrations, devices, audit, retention, support, and offboarding are not migrated to the AWS runtime.
16. Legal-hold domain/schema concepts do not operate S3 legal holds; the application role lacks legal-hold permissions.
17. SES infrastructure is not connected to application mail. Sandbox exit, bounce/complaint handling, and reputation monitoring are operational gaps.
18. The release bucket/distribution contains no artifact and has no publication pipeline. The Mac updater is not wired to an AWS static manifest.
19. Monitoring covers selected AWS signals only; application, authentication, GuardDuty health, Lambda/Step Functions, CloudFront/SES, backup, key, and audit-chain coverage is incomplete.
20. Backups are provider defaults/protections only. There is no AWS Backup plan, cross-account/cross-region recovery, automated restore/cutover, or demonstrated RPO/RTO.
21. Tenant suspension, legal hold, exact-version deletion, and offboarding are not implemented end to end; stack destruction is unsupported because data resources are retained/deletion-protected/Object-Locked.
22. WAF rate limiting is only per source IP and the host/body settings require real traffic validation. Tenant/principal quotas are absent.
23. Current tests are local unit/domain/template assertions, not deployed AWS integration, restore, isolation, chaos, or penetration-test evidence.
24. The foundation is single-region, uses one shared Aurora cluster/control table/user pool, and has no regional failover.
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
