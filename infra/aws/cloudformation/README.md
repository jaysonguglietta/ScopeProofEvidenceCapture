# Scopeproof AWS storage and temporary-access templates

This directory contains opt-in CloudFormation templates for two distinct storage
models: the native macOS Capture application's customer-owned bucket/prefix and
the hosted tenant service's quarantine/immutable-evidence buckets. The preferred
hosted production path is Cognito authentication followed by a backend-authorized,
short-lived presigned S3 request. Direct-S3 access is reserved for the native app,
administrators, and enterprise environments with a specific reason to trust the
client with temporary AWS credentials.

The templates deliberately create **no IAM users, access keys, KMS keys, public
data/storage resources, APIs, or custom domains**. The one native bucket template
creates only the named private bucket and its fixed bucket policy; all access
templates leave storage unchanged. The Cognito
managed-login endpoint is internet-reachable by design; it exposes authentication,
not evidence data. The templates also do not change an existing bucket policy or
KMS key policy. Those resource policies must be reviewed and updated separately so
that only the intended role ARNs can use the exact bucket, prefix, and key.

## Selection guide

| Template | Use case | Credentials available to the client | Safe default |
| --- | --- | --- | --- |
| `native-capture-evidence-bucket.yaml` | Provision one new private, KMS-encrypted, versioned, Object-Locked native Capture bucket | None | Retained bucket, one-year COMPLIANCE retention, no access identity |
| `native-capture-identity-center-s3.yaml` | Native Scopeproof Capture upload/posture verification for one customer-owned bucket and prefix | One-hour Identity Center role session | Daily upload/verifier only; no assignment, browsing, download, or setup permission |
| `cognito-presigned-auth.yaml` | Normal desktop/web user authentication for backend-issued presigned operations | No AWS credentials | Admin-created users, TOTP MFA required, authorization-code flow only, no client secret |
| `identity-center-direct-s3.yaml` | Hosted tenant immutable-evidence access from an AWS CLI/profile | One-hour Identity Center role session | Read-only; account assignment and quarantine upload are both off |
| `cognito-identity-pool-direct-s3.yaml` | Secondary direct-S3 mode with a user directory dedicated to one tenant | Temporary Cognito identity credentials | Stack-owned tenant pool, admin-created users, TOTP MFA, authorization-code-only client, no classic flow, read-only |
| `cross-account-hosted-ingest-role.yaml` | A Scopeproof-hosted AWS account writes into a customer's quarantine prefix | Temporary `AssumeRole` session | Exact source role plus unique external ID; write-only |
| `roles-anywhere-direct-s3.yaml` | Enterprise device/workload with managed X.509 PKI | Fifteen-minute Roles Anywhere session | Read-only; profile disabled until PKI validation |
| `s3-access-grants-instance.yaml` | Create the one regional S3 Access Grants singleton if one does not already exist | None | Retained; Identity Center association off |
| `s3-access-grants-read-grant.yaml` | Scalable temporary read access for one IAM role or application-bound directory group | Credentials vended by S3 Access Grants | Exact location prefix and `READ` grant only; directory access is bound to one trusted application |

Do not deploy every option. Select the smallest option that satisfies the use
case. A hosted tenant should normally use `cognito-presigned-auth.yaml` and none
of the hosted direct-S3 rows. A Mac that writes directly to a customer bucket
uses `native-capture-identity-center-s3.yaml`, plus
`native-capture-evidence-bucket.yaml` only when a new bucket is required. The hosted templates
use a different key layout and KMS context and are not interchangeable with it.

## Required existing controls

Before deployment, confirm all of the following:

1. The immutable-evidence bucket (unless the native bucket template creates it),
   optional ingest bucket, and enabled customer-managed symmetric
   `ENCRYPT_DECRYPT` KMS key exist in the same AWS Region as the stack and are not
   pending deletion. The current hosted stack
   uses one tenant KMS key for both buckets. Hosted templates accept an immutable
   KMS **key ARN**, never an alias ARN. The two native templates instead accept
   the immutable key ID and derive the ARN from the reviewed owner boundary.
2. Both buckets are private, have all four Block Public Access settings enabled,
   Object Ownership set to bucket-owner-enforced, versioning enabled, and bucket
   policies that deny insecure transport and unexpected principals.
3. Evidence retention and legal hold are enforced by the bucket/Object Lock
   configuration and the promotion service. Access templates cannot create Object
   Lock on an existing bucket; the native bucket template enables it only during
   initial bucket creation.
4. The KMS key policy permits only the generated role or permission-set role,
   through regional S3, with the required encryption context. An IAM allow cannot
   override a missing KMS key-policy allow.
5. For the **hosted tenant templates only**, existing and new evidence objects contain the non-secret custom KMS context
   `scopeproofTenantId=<tenant>` and `scopeproofPurpose=immutable-evidence`. Direct reads of
   objects encrypted without that context intentionally fail.
6. For the **hosted tenant templates only**, uploaders send `x-amz-server-side-encryption: aws:kms`, the exact KMS key ARN,
   and the base64-encoded JSON context emitted by the stack. Upload context uses
   `scopeproofPurpose=quarantine`. S3 IAM has no condition key for the optional
   encryption-context header, so the role policy binds the algorithm and KMS key;
   KMS permissions enforce the tenant/purpose context and promotion re-verifies it.
7. CloudTrail management events, S3 data events, KMS events, alerting, AWS Config,
   IAM Access Analyzer, and CloudFormation drift detection cover these resources.

Every hosted direct-reader role also contains explicit Denies for object reads
outside its derived tenant/control evidence ARN and for bucket listings with a
missing or nonmatching `s3:prefix`. These are a permissions ceiling against a
later same-account bucket-policy Allow; do not remove them when customizing a
permission set, Cognito role, Roles Anywhere role, or Access Grants location role.

The custom encryption context is authenticated metadata, but it is not encrypted;
never put secrets or personal data in it.

## Native macOS Capture direct S3

Use `native-capture-identity-center-s3.yaml` for the **AWS S3 Storage…** workflow
in the local menu-bar app. It deliberately matches the native object layout:

```text
<EvidencePrefix>/<control>/<assessment-period>/<evidence-id>/<file>.png
<EvidencePrefix>/<control>/<assessment-period>/<evidence-id>/<file>.json
```

The template creates no S3 bucket or KMS key. It always creates one daily,
one-hour IAM Identity Center permission set with only:

- read-only verification of Block Public Access, versioning, ownership,
  encryption, Object Lock, bucket policy, lifecycle, and replication posture;
- `ListBucket` restricted to the exact nonempty `EvidencePrefix`;
- single-part `PutObject` beneath only that prefix with the selected SSE-KMS or
  DSSE-KMS algorithm and exact key ARN; and
- direct metadata-only `kms:DescribeKey` on the one exact key so Capture can
  require a customer-managed, symmetric, enabled encryption key in the verified
  bucket-owner account; and
- S3-mediated `kms:GenerateDataKey` restricted to the bucket-owner account,
  regional S3 service, exact key, and the encryption context emitted by native
  Capture. SSE-KMS uses the bucket ARN because Capture requires an S3 Bucket Key;
  DSSE-KMS uses the exact object-prefix ARN.

`EnableVersionInventory` separately adds prefix-scoped `ListBucketVersions`.
`EnableValidatedDownloads` requires inventory and adds only
`GetObjectVersion` plus S3-mediated KMS decrypt. Keep both off for an upload-only
workstation. The template never grants current-object `GetObject`, delete,
retention, legal-hold, ACL, restore, or governance-bypass operations.

Account assignment is off by default. If CloudFormation should create it, set
`CreateDailyAccountAssignment=true` and provide the Identity Store ID of a
dedicated operator group. The assignment target is always
`BucketOwnerAccountId`, matching the account Scopeproof sends in
`x-amz-expected-bucket-owner`. Both native templates accept an immutable
`KmsKeyId` and derive the ARN from the stack partition and Region plus the exact
bucket-owner account; use the emitted `KmsKeyArn` output in the app. After
assignment provisioning finishes, create a
direct named AWS CLI v2 IAM Identity Center profile for that permission set with
`aws configure sso`; enter that profile name, the exact bucket, Region, prefix,
encryption selection, and KMS ARN in the app, then use **Save & Verify**.

### Native bucket creation

Use `native-capture-evidence-bucket.yaml` when a new bucket is required. The
template expresses the bucket configuration directly instead of granting an
operator mutable `PutBucketPolicy`, lifecycle, or replication authority. It
creates a retained bucket with all four Block Public Access settings, bucket-owner
enforced ownership, versioning, SSE-KMS or DSSE-KMS default encryption, fixed
COMPLIANCE Object Lock default retention, no lifecycle or replication
configuration, and the exact fixed policy Scopeproof verifies for insecure transport, bucket/evidence deletion,
Governance bypass, and unexpected encryption.
It creates no access identity and no KMS key.

Review a CloudFormation change set, create the bucket stack once, then pass its
bucket/prefix/encryption values and the same `KmsKeyId` to
`native-capture-identity-center-s3.yaml`; its derived ARN output must exactly
match the bucket stack's `KmsKeyArn` output.
Leave the app's **Archive after days** value at its secure default of `0`; this
template intentionally creates no lifecycle. A nonzero value requires a separate
reviewed lifecycle change and the app will fail verification until the live XML
exactly matches it.
Object Lock and Compliance retention are irreversible security decisions: use a
non-production account first and set the final retention period before uploading
evidence. Governance retention is intentionally unsupported by this production
template because privileged identities can bypass or shorten it; use only a
separately labeled non-production Compatible S3 destination when Governance is
required for evaluation. Future lifecycle or replication changes belong in reviewed
infrastructure, not a routine Capture operator session.

The generated same-account Identity Center role is authorized to S3 by its
permission-set identity policy. Keep the native bucket policy at the exact five
deny statements emitted by the bucket template; adding any statement, including a role `Allow`, makes
Scopeproof's exact posture verification fail and is unnecessary for same-account
access. The KMS key policy must separately authorize metadata-only
`kms:DescribeKey` plus the constrained cryptographic operations for the role,
because an IAM allow cannot override a missing KMS key-policy allow. This native template uses
standard S3 KMS context (`aws:s3:arn`), not the hosted tenant template's
`scopeproofTenantId`/`scopeproofPurpose` context.

## Preferred Cognito + backend-presigning path

Deploy `cognito-presigned-auth.yaml`, then configure the client and backend from
the outputs. The app client is public (`GenerateSecret: false`) and supports only
the OAuth authorization-code flow.

CloudFormation and Cognito cannot require PKCE on the app client. The native app
must enforce all of these at runtime:

- Open the Cognito managed-login authorization endpoint in the system browser.
- Generate a high-entropy, single-use verifier and send an S256 challenge. Never
  use `plain` and never reuse a verifier.
- Generate and verify single-use `state` and `nonce` values.
- Use an exact allowlisted HTTPS callback or native loopback callback. Bind a
  loopback listener only to `127.0.0.1`/`::1`, on an ephemeral port where the
  registered callback strategy supports it, and stop it immediately after use.
- Exchange the code once, without a client secret, and verify the callback before
  processing it. Do not log codes, tokens, or verifier values.
- Store refresh tokens only in an OS-protected credential store, replace them
  atomically on each rotation, and revoke them on sign-out or device
  deprovisioning. The app client disables API authentication flows and enables
  refresh-token rotation; use the OAuth token endpoint's `refresh_token` grant.

The backend must validate JWT signature and current JWKS, exact issuer, exact
client audience/client ID, `token_use`, expiry, not-before time, and nonce where
applicable. It must load tenant membership and authorization from server-side
records; a tenant ID, bucket, prefix, control, or object key supplied by the client
is never an authorization decision.

Send only the Cognito **access token** to the API. The backend must reject ID
tokens as API credentials even when their signature and audience are otherwise
valid.

The template creates only the desktop API scopes `scopeproof/evidence.read` and
`scopeproof/evidence.collect`; it deliberately omits retention/legal-hold
administration. Require the exact scope for each backend route in addition to
tenant membership and RBAC.

Presigned operations should expire in five minutes or less and bind an
unpredictable server-generated object key, maximum content length, allowed MIME
type, checksum, exact SSE-KMS key, and exact encryption context. Issue quarantine
writes only; a trusted promotion service performs validation, evidence promotion,
retention/legal hold, audit receipt generation, and reconciliation.

For production-volume verification and recovery email, set
`EmailSendingAccount=DEVELOPER` and provide a verified SES identity. Cognito's
default sender is useful for initial testing but has delivery quotas.

## IAM Identity Center direct S3

`identity-center-direct-s3.yaml` creates a one-hour permission set. It does not
create or modify IAM Identity Center itself. By default, it creates no account
assignment. To create one, set `CreateAccountAssignment=true` and provide an AWS
account ID plus an Identity Store user or group ID. Prefer groups and enforce MFA
and device/session policy in the external identity provider and IAM Identity
Center.

Read access is derived, not supplied by an operator: only
`tenants/<tenant>/controls/*/evidence/*` in `EvidenceBucketName`. Optional upload
permits only single-part `PutObject` to
`tenants/<tenant>/controls/*/quarantine/*` in the separately named ingest bucket;
it intentionally grants no list, read, delete, ACL, retention, or legal-hold
permission there. For multipart upload or additional operations, use the
backend-presigned path rather than widening this permission set casually.

IAM cannot cap `PutObject` content length, object count, or request rate. Any
direct-upload or cross-account write role can therefore be abused for storage/KMS
cost denial of service if its temporary credentials are compromised. Keep the
ingest bucket's short quarantine lifecycle, add budgets/anomaly alarms and service
quotas where applicable, and use backend-issued presigned intents for untrusted
users so application rate, size, checksum, and intent controls are enforced.

## Cognito identity pool direct S3

`cognito-identity-pool-direct-s3.yaml` is a standalone, per-tenant stack. It
creates its own deletion-protected and retained user pool, an administrator-only
user enrollment policy, required TOTP MFA, and a secretless public OAuth client
that permits only the authorization-code flow. Supply exact callback/logout URL
allowlists and a globally unique Cognito domain prefix. The identity pool is
bound directly to that stack-owned pool and client, has
`AllowUnauthenticatedIdentities=false` and `AllowClassicFlow=false`, and attaches
only an authenticated role. `UserPoolId`, `UserPoolClientId`, and an operator
acknowledgement are intentionally not parameters: an assertion cannot make a
shared user directory tenant-isolated.

This option gives a compromised client temporary AWS credentials, so it has a
larger blast radius than a single presigned request. Use one independently scoped
role/stack and user directory per tenant, keep upload disabled unless required,
and test cross-tenant denials before release. Never import users for another
tenant into this pool. Cognito identity pools cannot apply the backend's
membership lookup before vending credentials, so the separately deployed
`cognito-presigned-auth.yaml` pool is for the preferred backend-presigned path and
must not be reused here. Cognito authentication does not replace application
business-authorization checks for workflows outside this exact direct-S3 role.

The dedicated user pool is retained and has deletion protection so stack deletion
cannot silently destroy tenant identities or authentication records. The direct
credential plane (identity pool, public app client, domain, and IAM role) is not
retained; reviewed tenant offboarding should remove that access plane, preserve
required records, and later disable deletion protection and delete or import the
retained pool through a separate approved change.

## Cross-account hosted ingest

Deploy `cross-account-hosted-ingest-role.yaml` in the bucket owner's account. The
trusted hosted principal must be an IAM **role**, not a user. Generate a unique
external ID for each customer with at least 128 bits of randomness and never reuse
it. External IDs prevent confused-deputy errors but are authorization identifiers,
not passwords; protect them from casual disclosure without treating them as the
only control.

The trust policy uses the source account root only as a delegation boundary and
then requires `aws:PrincipalArn` to equal the exact source role. Recreating or
renaming the hosted source role requires a stack update. The role can write only
to the exact quarantine prefix and cannot list, read, delete, change retention,
or bypass legal hold. The hosted service should request a 15-minute session even
though IAM's role-level maximum is one hour.

## IAM Roles Anywhere

`roles-anywhere-direct-s3.yaml` takes an **existing** trust-anchor ARN. It binds
the role trust to that exact anchor, this account, and one exact X.509 subject CN.
The profile contains one role, a duplicate read-only session-policy ceiling, and
15-minute credential lifetime. It is disabled by default.

Before enabling it, validate CA path constraints, issuance authorization, hardware
or Keychain-backed private-key custody, short certificate lifetime, CRL operations,
certificate renewal, emergency revocation, and CloudTrail alerting. Deploy one
role/profile per narrowly defined workload identity rather than sharing a common
CN across customers or devices.

## S3 Access Grants

CloudFormation officially supports `AWS::S3::AccessGrantsInstance`,
`AWS::S3::AccessGrantsLocation`, and `AWS::S3::AccessGrant`, so this suite does not
use custom resources.

Only one S3 Access Grants instance can exist per AWS account and Region. Deploy
`s3-access-grants-instance.yaml` only after confirming the singleton is absent. If
it already exists, do not deploy that template; deploy only
`s3-access-grants-read-grant.yaml`. A directory-group grant requires the regional
instance to be associated with IAM Identity Center. The read-grant template also
accepts an existing IAM **role** ARN; it deliberately rejects IAM user ARNs.
Directory-group mode additionally requires the exact IAM Identity Center
`ApplicationArn` for the calling application's trusted identity propagation. The
grant then rejects access through every other Identity Center application. Do not
use the Identity Center instance ARN or treat the application ARN as a secret.

Each read-grant stack is also bound to one exact `ControlId`; deploy a separate
grant only for each control a role or directory group must access. The location
role trusts only the current account's regional Access Grants instance and permits
reads only when S3 supplies the matching `s3:AccessGrantsInstanceArn`. The caller
still needs narrowly scoped permission to
call `s3:GetDataAccess` (and optionally `s3:ListCallerAccessGrants`) for the grant;
attach that permission to the existing caller or its application integration.
This template does not modify an existing grantee.

For `DIRECTORY_GROUP`, the location-role trust adds `sts:SetContext` in its own
statement, restricts `sts:RequestContextProviders` to the IAM Identity Center
context provider, rejects a missing provider, and retains the same exact regional
Access Grants source account/ARN boundary. `sts:AssumeRole` and
`sts:SetSourceIdentity` remain in a separate statement. In `IAM_ROLE` mode the
`sts:SetContext` statement and access-grant `ApplicationArn` are omitted entirely.
Before creating a directory grant, verify that the named application belongs to
the same Identity Center instance associated with S3 Access Grants, has only the
required trusted token issuer/authentication methods and application grants, and
maps the intended immutable directory identity attribute.

## Deployment order and change control

1. Review parameters and resource-policy changes in a non-production account.
2. Run the local tests and `cfn-lint` with current resource specifications.
3. Run `aws cloudformation validate-template --template-body file://<template>`
   in the intended partition/Region. Validation is read-only; deployment is not.
4. Create and review a CloudFormation change set. IAM-bearing templates require
   `CAPABILITY_IAM`. Role names are intentionally generated by CloudFormation to
   avoid collisions and unnecessary named-IAM capability.
5. Apply the matching bucket/KMS policy changes through their own reviewed stack.
6. Exercise positive access and every denial in the security test list below.
7. Enable the client feature only after CloudTrail evidence and reconciliation
   prove the expected principal, tenant, prefix, KMS key, and context.

Never paste access keys into parameters. None of these templates has a legitimate
access-key parameter.

`cognito-presigned-auth.yaml` retains its user pool and enables Cognito deletion
protection. Deleting that stack does not delete the pool. A separately approved
offboarding change must first preserve required authentication/audit records,
disable deletion protection, and deliberately remove or import the retained pool;
do not treat stack deletion as user or tenant offboarding.

`cognito-identity-pool-direct-s3.yaml` applies the same retention and deletion
protection to its dedicated tenant user pool, while deliberately allowing deletion
of the direct AWS credential plane during reviewed offboarding.

## Local validation

Use Node.js 22 or newer. From the repository root:

```bash
node --test infra/aws/cloudformation/tests/templates.test.mjs
```

If available, also run:

```bash
cfn-lint infra/aws/cloudformation/*.yaml
```

The local tests parse every template and assert security invariants, but they do
not replace CloudFormation service-side validation, IAM policy simulation, or an
isolated integration deployment.

## Security tests before production

- The native daily role can verify only the named bucket, list/write only the
  exact native prefix, and cannot read content unless both inventory and download
  options were enabled. Wrong algorithm, KMS key, prefix, account, Region, and
  KMS context are denied.
- No native permission set can create a bucket or mutate bucket policy,
  encryption, lifecycle, replication, Object Lock, ownership, or public-access
  settings. Those changes require a reviewed infrastructure change set.
- Correct user/role can list and read only its evidence prefix.
- A principal from tenant A receives `AccessDenied` for tenant B bucket prefixes
  and KMS contexts, including guessed object version IDs.
- HTTP S3 requests, arbitrary KMS calls, wrong KMS key, missing/wrong tenant or
  purpose context, and evidence writes are denied.
- Upload-enabled paths accept only the exact quarantine prefix and reject reads,
  listings, deletes, ACLs, retention changes, legal holds, and writes elsewhere.
- Cross-account assumptions fail for a wrong source role, source account, missing
  external ID, another customer's external ID, and sessions over policy limits.
- Cognito identity-pool credential exchange fails for unauthenticated identities,
  the preferred/shared backend user pool or any other audience, an expired/revoked
  token, and classic-flow attempts. Self-sign-up, password-only sign-in, implicit
  OAuth, and direct username/password app-client flows also fail.
- Roles Anywhere fails for another trust anchor, subject CN, expired/revoked
  certificate, and disabled profile.
- Access Grants temporary credentials fail outside the registered grant scope and
  when obtained outside the expected Access Grants instance. Directory-group
  access fails when the Identity Center context provider is missing or different
  or when a different trusted-identity-propagation application is used; IAM-role
  mode has no `sts:SetContext` trust action or application binding.
- Cognito OAuth rejects an unregistered redirect URI; the client rejects state,
  nonce, issuer, audience, and PKCE mismatches.

## Important limitations

- Template parameters cannot prove that a bucket, key, trust anchor, Identity
  Center instance, or trusted-identity-propagation application belongs to the same
  account/Region and intended identity graph. Deployment
  preflight and service-side validation must enforce that relationship.
- CloudFormation configures an authorization-code-only public Cognito client but
  cannot require the PKCE `S256` method. That requirement is in client and backend
  code and must be tested.
- IAM policy conditions do not replace a restrictive bucket policy and KMS key
  policy. Organization SCPs and permissions boundaries may further restrict these
  roles and are intentionally supported.
- These templates do not provision a PKI, CRL, device attestation, Identity Center
  organization instance, SES identity, audit trail, WAF, rate limiting, presigner,
  evidence promotion/reconciliation service, backup, or disaster recovery.
- S3 Access Grants and Cognito managed-login CloudFormation resources must be
  available in the chosen Region. Check the current regional service/resource
  support before creating a change set.
- The native Capture access template cannot verify at template-evaluation time
  that the supplied bucket, owner account, KMS key, and stack Region all agree.
  Confirm those exact relationships before a change set. The native bucket
  template accepts an existing key ARN, so its key policy must separately allow
  the eventual Identity Center permission-set role through regional S3.

## Official references

- [Cognito user-pool client CloudFormation reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html)
- [Cognito authorization endpoint and PKCE parameters](https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html)
- [Cognito identity-pool CloudFormation reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypool.html)
- [IAM Identity Center permission-set CloudFormation reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-sso-permissionset.html)
- [Configure IAM Identity Center authentication with AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
- [IAM Roles Anywhere trust model](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/trust-model.html)
- [S3 Access Grants CloudFormation resources](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/AWS_S3.html)
- [Application-bound `AWS::S3::AccessGrant`](https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-s3-accessgrant.html#cfn-s3-accessgrant-applicationarn)
- [Registering and securing S3 Access Grants locations](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-grants-location-register.html)
- [S3 Access Grants with IAM Identity Center trusted identity propagation](https://docs.aws.amazon.com/singlesignon/latest/userguide/tip-tutorial-s3.html)
- [IAM and STS request-context condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html#condition-keys-requestcontextproviders)
- [SSE-KMS encryption context](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)
