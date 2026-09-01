# AWS S3 evidence storage

Scopeproof Capture can copy each locally verified screenshot and immutable JSON manifest to a private, versioned S3 evidence prefix. Production compliance mode adds temporary-credential enforcement, a verified customer-managed KMS encryption key, mandatory COMPLIANCE Object Lock retention, ownership controls, bucket-posture verification, exact version receipts, optional Deep Archive and replication, and auditable downloads.

## Recommended production workflow

1. Install AWS CLI v2 from AWS and configure a named IAM Identity Center profile with `aws configure sso`. Do not place access keys in that profile.
2. Choose **Scopeproof shield → AWS S3 Storage…**, select **IAM Identity Center profile**, and enter the exact profile name. Select **Identity Center + assumed role** instead when the daily S3 policy belongs to a separate least-privilege role; enter its exact ARN and optional external ID.
3. Select **Sign in with IAM Identity Center before verification** when the cached SSO session is absent or expired. Scopeproof opens the AWS browser flow through the reviewed AWS CLI v2 executable, then obtains an expiring credential set without displaying or persisting it.
4. Select **Production compliance** and enter a same-account bucket, region, nonempty evidence prefix, customer-managed KMS key ARN, and retention. The app fixes Object Lock to **Compliance** in this profile. Governance appears only as an explicitly non-production Compatible S3 setting, does not satisfy the production verifier, and can be bypassed or shortened by a sufficiently privileged identity. Leave **Archive after days** at `0` for the supplied native bucket template; a nonzero value requires an independently reviewed exact lifecycle configuration. Select FIPS endpoints when policy requires them.
5. Leave downloads disabled for an upload-only role. Enable them only for operators who need the version-aware S3 browser.
6. For an existing bucket, choose **Save & Verify**. Scopeproof verifies the caller identity and expected bucket owner, then calls `kms:DescribeKey` on the exact ARN and requires the same partition, Region, and owner account plus `KeyManager=CUSTOMER`, `KeyUsage=ENCRYPT_DECRYPT`, `KeySpec=SYMMETRIC_DEFAULT`, `Enabled=true`, and `KeyState=Enabled`. It also verifies prefix access, Block Public Access, versioning, BucketOwnerEnforced ownership, bucket encryption, an enabled S3 Bucket Key for SSE-KMS, COMPLIANCE Object Lock/retention, the exact deletion-deny policy, and any requested lifecycle or replication configuration.
7. For a new production bucket, deploy the reviewed `infra/aws/cloudformation/native-capture-evidence-bucket.yaml` stack through an approved infrastructure change. Give both native templates only the KMS UUID or `mrk-…` key ID; they derive the ARN from the stack partition/Region and exact owner account. Paste the resulting `KmsKeyArn` output into the app. Use **Create & Harden Bucket** only with a separately reviewed, short-lived setup role; none of the supplied daily access templates grants bucket administration. Read the irreversible Object Lock warning before either path.
8. Confirm the daily role has no bucket-management permissions. Keep only the applicable upload-only or browser role.
9. Deploy the CloudTrail monitoring template in `infra/aws/scopeproof-s3-observability.yaml` through an approved infrastructure change and confirm its SNS subscription.

## Authentication choices

| App selection | Credential source | Persistence | Recommended use |
| --- | --- | --- | --- |
| **IAM Identity Center profile** | A direct AWS CLI v2 SSO profile | Profile name is saved; refreshed STS credentials stay only in process memory | Preferred same-account production path |
| **Identity Center + assumed role** | A direct SSO profile followed by `sts:AssumeRole` to one exact role ARN | Profile/role configuration is saved; source and assumed-role credentials stay only in memory | Preferred cross-account or separately administered evidence role |
| **Manual credentials** with token and expiration | One pasted STS session | Credential set is stored in device-only Keychain until near expiry | Break-glass or environments where AWS CLI SSO cannot be used |
| **Manual credentials** without token/expiration | Dedicated static access key | Device-only Keychain | Compatible S3 migration exception only; never Production compliance |

Scopeproof accepts only direct IAM Identity Center profiles. It deliberately rejects profile-based static keys, `credential_process`, `credential_source`, web-identity files, `source_profile`, and role chaining. The CLI executable must be AWS CLI v2 at a reviewed standard installation path; the app never invokes a shell or searches `PATH`. Every refreshed session is checked against the verified AWS account and expected principal or assumed role before it can sign an S3 request.

The [CloudFormation authentication templates](../infra/aws/cloudformation/README.md) provide separately deployable least-privilege building blocks for IAM Identity Center, Cognito Identity Pools, hosted cross-account ingest, IAM Roles Anywhere, and S3 Access Grants. Choose one trust model based on the workflow and review its parameters and IAM scope; do not deploy all templates as a bundle. This repository does not deploy them automatically.

The **Compatible S3** profile supports existing SSE-S3 buckets and long-lived credentials during migration. It still requires Block Public Access, versioning, matching default encryption, fixed AWS endpoints, destination binding, checksummed uploads, and version IDs. It is not the recommended profile for high-risk production evidence.

When using a customer-managed key, select **SSE-KMS** or **DSSE-KMS** in the app. **SSE-S3 (AES-256)** uses an S3-managed key and must not have a KMS ARN. The app's encryption selection, KMS ARN, bucket default encryption, bucket policy, IAM policy, and KMS key policy must agree.

Production credentials must include an STS session token and expiration. Identity Center/AssumeRole sessions refresh in memory when needed; a manually entered Keychain session is automatically deleted when expired or within five minutes of expiration. Never use AWS root credentials.

## What bucket creation changes

For a new production bucket, Scopeproof configures:

- all four S3 Block Public Access controls;
- versioning;
- Object Ownership `BucketOwnerEnforced`;
- SSE-KMS or DSSE-KMS default encryption with the selected key;
- COMPLIANCE Object Lock with the selected retention period;
- an optional prefix-scoped Deep Archive transition; and
- optional replication when a destination bucket, replication role, and destination KMS key are supplied.

Object Lock cannot be disabled after it is enabled. Compliance retention cannot be shortened, bypassed, or removed during its active period. Confirm retention with records, legal, privacy, and compliance owners before creation.

If the bucket already belongs to the caller, **Create & Harden Bucket** hardens its access, ownership, encryption, versioning, and Object Lock posture. It does not overwrite an existing bucket policy, lifecycle, or replication configuration. Configure those through reviewed infrastructure-as-code and use **Save & Verify** to confirm the result. The production verifier requires the complete five-statement policy below and rejects every additional or changed statement. This exact-match rule prevents a resource-policy `Allow` or an apparently stricter but incompatible control from silently changing the verified access boundary. If organization policy requires additional bucket-policy statements, treat that as an unsupported production posture until the policy and verifier are changed and reviewed together; do not weaken or bypass verification.

Setup is fail-closed. A partially created bucket is retained with automatic uploads disabled; Scopeproof never attempts to delete it.

## Credential and configuration storage

For **Manual credentials**, the access key, secret key, session token, and optional expiration are encoded together in a macOS generic-password Keychain item:

```text
service: com.scopeproof.capture
account: aws-s3-evidence-credentials-v1
protection: WhenUnlockedThisDeviceOnly
```

For either IAM Identity Center option, AWS CLI v2 obtains temporary credentials. Scopeproof parses them through bounded formats, copies them into an in-memory refresh cache, and never writes them to Keychain, preferences, evidence, receipts, logs, or browser storage. The AWS CLI maintains its own SSO token cache outside Scopeproof under the signed-in macOS account; protect that account with FileVault, screen lock, and endpoint controls, and use your IdP session policy to bound lifetime and revoke access.

After verification, the AWS account, principal ARN or assumed-role scope, exact destination/settings digest, verification time, verified bucket posture, and verified KMS key metadata are stored in a separate `WhenUnlockedThisDeviceOnly` Keychain item. Changing the authentication method, profile, role, external ID, destination, or other security-sensitive setting invalidates that binding and disables uploads until re-verification. A refreshed session must match the saved account and role scope. Bindings created by earlier app schemas do not satisfy the current verifier and must be refreshed.

Bucket, region, prefix, KMS ARN, retention, FIPS, lifecycle, replication, download, automatic-upload, authentication method, profile name, and role ARN are configuration and remain in macOS preferences. An external ID is an authorization binding rather than a password, but treat the saved value as restricted configuration. Credentials are never written to preferences, manifests, receipts, logs, environment files, Git, or the CloudTrail template. **Disconnect** deletes Scopeproof's S3 Keychain items, in-memory credentials, and preferences; it does not delete evidence, sign out of IAM Identity Center, or delete the AWS CLI's independently managed SSO cache. Run `aws sso logout` separately when workstation AWS access must end; that command signs out cached IAM Identity Center sessions used by the AWS CLI account.

## Unified Local Console library

The Local Console automatically selects its inventory source from the running app configuration:

- without an S3 destination, it scans the current `~/Documents/Scopeproof Evidence` root plus the bounded legacy Pictures root;
- with configured but unverified S3 settings, it continues to show local evidence and reports that verification is required; and
- with current credentials, `s3:ListBucketVersions`, and a matching verified destination, it adds paired current PNG/manifest objects beneath that exact prefix. A local artifact is labeled `Local + S3` only when its local upload receipt binds the exact S3 keys, versions, ETags, and checksums; inventory-only objects are labeled `S3` with unverified provenance.

The inventory accepts only the generated `<control>/<assessment-period>/<evidence-id>/<file>.png` plus same-basename `.json` manifest layout, and it never resurrects an older version when the current object is deleted. It groups immutable S3 versions by object key and displays one current screenshot card plus the version count. A matching evidence ID or filename is not proof of identity: joining to a local artifact additionally requires the exact schema-2 local `.s3.json` receipt, destination account/settings, key, version, ETag, S3 checksum, and local manifest digest to agree. If two different object keys claim the same evidence ID, the console omits that ambiguous ID instead of guessing. The browser API receives normalized display metadata, not an S3 object key, version ID, ETag, filesystem path, access key, secret, or session token. S3-only records remain explicitly lifecycle-invalid and provenance-unverified until a trusted receipt exists.

S3 listing is limited to 5,000 object versions and cached in memory for 60 seconds. **Refresh** forces a new list. A list failure is fail-open only for local availability: local evidence remains visible and the console reports the S3 recovery steps, but it never invents S3 state.

When validated downloads are enabled, **Load secure preview** retrieves only the selected card. The server first downloads the paired exact-version manifest and validates its schema, evidence ID, filename, version, and receipt digest when available. It then downloads the exact PNG version/ETag, applies the expected bucket owner and prefix, enforces 40 MiB, validates the S3 checksum, PNG signature, and manifest SHA-256, and rechecks any local receipt binding. Files pass through a private random temporary directory and are removed immediately after the authenticated loopback response. Automatic bulk preview fetching is intentionally avoided. Self-consistent S3-only pairs remain marked unverified because an S3 writer could replace both without a trusted receipt. Use **S3 files…** or **Browse S3 Evidence…** for explicit save. With only prefix-scoped `s3:ListBucketVersions`, metadata remains visible while preview/download controls are disabled.

## Object layout and receipts

Objects use sanitized control-oriented keys:

```text
<prefix>/
  <control-id>-<control-title>/
    <assessment-period>/
      <evidence-id>/
        <timestamped-evidence>.png
        <timestamped-evidence>.json
```

User input cannot supply traversal segments, backslashes, a host, or an absolute object path. Production mode requires a nonempty prefix so IAM and CloudTrail can be narrowly scoped.

Every PUT includes a base64 SHA-256 checksum and the selected encryption headers. Scopeproof requires S3 to return the same checksum, the expected encryption/KMS key, and a non-null version ID. Only after both objects succeed does it write a mode-`0600` schema-2 `.s3.json` receipt containing:

- AWS account and verified principal ARN;
- bucket, region, security profile, encryption, KMS key, retention mode, and retention days;
- exact object keys, version IDs, ETags, S3 SHA-256 checksums, and S3 request IDs; and
- local screenshot and manifest SHA-256 digests.

The receipt contains no AWS credential. A retry creates a new protected version at the deterministic key and records that exact version.

## Required production bucket policy

Replace the bucket, prefix, and KMS ARN. The document must be the complete bucket policy: do not merge additional statements into it. Scopeproof compares the normalized JSON document with the generated policy so changed actions, resources, conditions, or resource-policy grants fail verification. Authorize same-account daily access in the role/permission-set identity policy and authorize KMS use in the KMS key policy.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ScopeproofDenyInsecureTransport",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::company-compliance-evidence",
        "arn:aws:s3:::company-compliance-evidence/*"
      ],
      "Condition": {"Bool": {"aws:SecureTransport": "false"}}
    },
    {
      "Sid": "ScopeproofDenyBucketDeletion",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:DeleteBucket",
      "Resource": "arn:aws:s3:::company-compliance-evidence"
    },
    {
      "Sid": "ScopeproofDenyEvidenceDeletion",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:BypassGovernanceRetention"
      ],
      "Resource": "arn:aws:s3:::company-compliance-evidence/scopeproof-evidence/*"
    },
    {
      "Sid": "ScopeproofDenyWrongEncryption",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::company-compliance-evidence/scopeproof-evidence/*",
      "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption": "aws:kms"}}
    },
    {
      "Sid": "ScopeproofDenyWrongKMSKey",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::company-compliance-evidence/scopeproof-evidence/*",
      "Condition": {"StringNotEquals": {"s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/REPLACE"}}
    }
  ]
}
```

Use `aws:kms:dsse` instead of `aws:kms` when DSSE-KMS is selected. The supplied native bucket CloudFormation template emits this policy and retains both the bucket and policy. A bucket newly created by the app receives it automatically; the app never replaces an existing policy.

## IAM separation

Use separate roles or permission sets. The setup/verifier permissions should not remain on the daily application identity.

### Temporary setup and posture verification

Replace the bucket ARN. Production verification always needs both lifecycle and replication **Get** actions so it can prove those configurations are absent when disabled. Add the corresponding **Put** action only when the feature is selected. Replication changes also require a tightly scoped `iam:PassRole` permission for the one replication role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateHardenAndVerifyScopeproofBucket",
      "Effect": "Allow",
      "Action": [
        "s3:CreateBucket",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketVersioning",
        "s3:PutBucketOwnershipControls",
        "s3:PutEncryptionConfiguration",
        "s3:PutBucketObjectLockConfiguration",
        "s3:PutBucketPolicy",
        "s3:ListBucket",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetBucketOwnershipControls",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketPolicy",
        "s3:GetLifecycleConfiguration",
        "s3:GetReplicationConfiguration"
      ],
      "Resource": "arn:aws:s3:::company-compliance-evidence"
    },
    {
      "Sid": "DescribeExactScopeproofKey",
      "Effect": "Allow",
      "Action": "kms:DescribeKey",
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/REPLACE"
    }
  ]
}
```

The `s3:GetLifecycleConfiguration`, `s3:GetReplicationConfiguration`, and exact-resource `kms:DescribeKey` actions above are mandatory for production posture verification. Add `s3:PutLifecycleConfiguration` only when Scopeproof is authorized to configure archiving, and add `s3:PutReplicationConfiguration` plus `iam:PassRole` on the exact replication role only when it is authorized to configure replication. The destination bucket, Object Lock posture, KMS policy, and cross-account trust must be prepared separately.

### Verifier and upload-only daily role

The app re-verifies posture whenever credentials or security-sensitive settings change, so the daily role needs read-only posture permissions in addition to prefix-scoped listing and writes. It does not need bucket mutation or deletion permissions.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadScopeproofBucketPosture",
      "Effect": "Allow",
      "Action": [
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketVersioning",
        "s3:GetBucketOwnershipControls",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetBucketPolicy",
        "s3:GetLifecycleConfiguration",
        "s3:GetReplicationConfiguration"
      ],
      "Resource": "arn:aws:s3:::company-compliance-evidence"
    },
    {
      "Sid": "VerifyScopeproofPrefix",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::company-compliance-evidence",
      "Condition": {"StringLike": {"s3:prefix": ["scopeproof-evidence/", "scopeproof-evidence/*"]}}
    },
    {
      "Sid": "WriteScopeproofEvidence",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::company-compliance-evidence/scopeproof-evidence/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-server-side-encryption": "aws:kms",
          "s3:x-amz-server-side-encryption-aws-kms-key-id": "arn:aws:kms:us-east-1:123456789012:key/REPLACE"
        }
      }
    },
    {
      "Sid": "DescribeExactScopeproofKey",
      "Effect": "Allow",
      "Action": "kms:DescribeKey",
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/REPLACE"
    },
    {
      "Sid": "EncryptScopeproofEvidence",
      "Effect": "Allow",
      "Action": "kms:GenerateDataKey",
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/REPLACE",
      "Condition": {
        "StringEquals": {
          "kms:CallerAccount": "123456789012",
          "kms:ViaService": "s3.us-east-1.amazonaws.com",
          "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::company-compliance-evidence"
        }
      }
    }
  ]
}
```

This example assumes SSE-KMS with S3 Bucket Keys enabled, which Scopeproof requires in Production compliance. In that mode, AWS uses the bucket ARN as the KMS encryption context. For DSSE-KMS, use `ArnLike` with `arn:aws:s3:::company-compliance-evidence/scopeproof-evidence/*` instead, as the supplied Identity Center template does. An SSE-KMS bucket without Bucket Keys is supported only by the Compatible S3 profile and needs the same object-ARN context adjustment.

### Dedicated IAM user for Compatible S3

Use a long-lived IAM user only when a migration or workstation constraint prevents temporary STS credentials. Select **Compatible S3** because Production compliance rejects long-lived access keys. Create a dedicated no-console user such as `scopeproof-s3-evidence`; do not reuse an administrator or personal identity, add it to broad groups, or attach any other policy. Attach the exact daily policy above plus the optional browser additions only when downloads are required. Where organization policy permits, use the same maximum-permission document as a permissions boundary. Rotate the key, disable it when the workstation is not in use, and delete it when the temporary-credential workflow is available.

Add both statements below for that user to the existing customer-managed KMS key policy. The direct `DescribeKey` grant exposes only key metadata needed for fail-closed verification; encryption/decryption remains limited to regional S3 and the exact encryption context. Do not replace the current key policy or remove its account-root delegation and administrator recovery statements. The IAM user must exist before saving a policy that names it.

```json
[
  {
    "Sid": "AllowScopeproofCompatibleUserToDescribeExactKey",
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:user/scopeproof-s3-evidence"
    },
    "Action": "kms:DescribeKey",
    "Resource": "*"
  },
  {
    "Sid": "AllowScopeproofCompatibleUserThroughS3Only",
    "Effect": "Allow",
    "Principal": {
      "AWS": "arn:aws:iam::123456789012:user/scopeproof-s3-evidence"
    },
    "Action": [
      "kms:GenerateDataKey",
      "kms:Decrypt"
    ],
    "Resource": "*",
    "Condition": {
      "StringEquals": {
        "kms:CallerAccount": "123456789012",
        "kms:ViaService": "s3.us-east-1.amazonaws.com",
        "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::company-compliance-evidence"
      }
    }
  }
]
```

This key-policy example also assumes SSE-KMS with S3 Bucket Keys enabled. Apart from direct metadata-only `DescribeKey`, it allows the named identity to generate data keys and decrypt only when KMS is called through S3 in the expected account for that bucket. It does not grant key administration, grants, deletion, rotation, or cryptographic use with another bucket. If browsing is disabled, omit `kms:Decrypt` from both the key policy and IAM identity policy. Review any existing key-administrator statements separately: an administrator who can edit the key policy remains capable of changing these restrictions.

### Local Console inventory permission

The unified Local Console requires the following read-only list permission to show S3 metadata, even when previews and downloads remain disabled:

```json
{
  "Sid": "ListScopeproofVersions",
  "Effect": "Allow",
  "Action": "s3:ListBucketVersions",
  "Resource": "arn:aws:s3:::company-compliance-evidence",
  "Condition": {"StringLike": {"s3:prefix": ["scopeproof-evidence/", "scopeproof-evidence/*"]}}
}
```

Omit this statement when the Mac should remain local-only. Listing does not grant object-content access or KMS decrypt.

### Optional preview and download additions

Add these only when **Allow prefix-scoped browsing and validated downloads** is enabled:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadExactScopeproofVersion",
      "Effect": "Allow",
      "Action": "s3:GetObjectVersion",
      "Resource": "arn:aws:s3:::company-compliance-evidence/scopeproof-evidence/*"
    },
    {
      "Sid": "DecryptScopeproofEvidence",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/REPLACE",
      "Condition": {
        "StringEquals": {
          "kms:CallerAccount": "123456789012",
          "kms:ViaService": "s3.us-east-1.amazonaws.com",
          "kms:EncryptionContext:aws:s3:arn": "arn:aws:s3:::company-compliance-evidence"
        }
      }
    }
  ]
}
```

Use KMS encryption-context conditions and the exact verified bucket policy to restrict the key and writes to the bucket/prefix. Block public access at the bucket/account layer; the exact policy denies non-TLS requests, bucket/evidence deletion, Governance bypass, incorrect encryption algorithms, and any KMS key other than the configured key.

## Browser and download security

The browser calls `ListObjectVersions`, shows current and historical versions, stops after 5,000 versions, and never requests outside the configured prefix. Downloads:

- require the explicit browser permission mode and a selected PNG or JSON version;
- sign the exact `versionId`, expected bucket owner, and listed ETag;
- reject redirects, changes, oversized responses, checksum mismatches, malformed PNG signatures, and invalid/oversized JSON;
- stream through a mode-`0600` temporary file and move it only after validation; and
- apply macOS quarantine metadata before allowing **Reveal Download**.

Unknown and executable object types are visible for inventory purposes but cannot be downloaded by Scopeproof.

## Network and endpoint controls

- Requests use AWS Signature Version 4 and TLS 1.2 or newer.
- Standard mode permits only generated regional `*.amazonaws.com` S3 and STS endpoints.
- FIPS mode uses regional `s3-fips` and `sts-fips` endpoints and path-style bucket addressing.
- Dotted bucket names use path-style addressing to preserve TLS hostname validation.
- The URL session is ephemeral, has no cookies/cache/credential storage, and rejects every redirect.
- AWS China and unsupported partitions fail validation instead of redirecting credentials.
- The verified STS caller account is sent as `x-amz-expected-bucket-owner`; direct storage is intentionally same-account. Use S3 replication for a separately controlled destination account.

## Audit monitoring and recovery

Deploy `infra/aws/scopeproof-s3-observability.yaml` with the evidence bucket/prefix, exact evidence KMS key ARN, and a separate globally unique CloudTrail log bucket. It creates a separate retained rotating customer-managed KMS key for the trail, enables log-file validation, S3 data events, COMPLIANCE-locked immutable versioned audit-log storage, and SNS alerts for evidence deletions, bucket-policy/public-access/versioning/Object Lock/encryption/lifecycle/replication changes, account-level S3 Public Access Block changes, and changes to the evidence KMS key. CloudTrail data events and the additional KMS key are billable, and the email subscription must be confirmed.

Test at least annually:

1. restore a receipt-referenced object version by its version ID;
2. verify its S3 checksum and local SHA-256;
3. exercise KMS-key recovery and rotation procedures;
4. confirm Object Lock prevents prohibited deletion;
5. confirm CloudTrail and SNS detect a controlled policy-change test; and
6. restore from the replication destination when replication is enabled.

Deep Archive affects retrieval time and cost. A lifecycle transition does not change Object Lock retention. Configure deletion/expiration separately through reviewed records-management infrastructure; Scopeproof intentionally does not create an automatic deletion policy.

## Troubleshooting

| Message | Resolution |
| --- | --- |
| Temporary credentials required or expired | Export a fresh IAM Identity Center/AssumeRole session, include its expiration, and re-verify. |
| Bucket posture failed | Grant the read-only posture actions temporarily and correct every reported control. |
| Expected bucket owner rejected | Use a bucket owned by the STS caller account or assume a role in the owner account. |
| KMS ARN entered while SSE-S3 is selected | Select SSE-KMS or DSSE-KMS to use the key, or clear the KMS ARN when the bucket intentionally uses SSE-S3. |
| KMS key does not match verified destination | Use the exact key ARN in the STS-verified bucket-owner account, AWS partition, and bucket Region; aliases and cross-account ARNs are rejected. |
| KMS rejected `DescribeKey` | Grant `kms:DescribeKey` on the exact ARN in the IAM policy and key policy, then confirm the key is customer-managed, symmetric, enabled, `ENCRYPT_DECRYPT`, and not pending deletion. |
| Governance selected with Production compliance | Use COMPLIANCE Object Lock. Governance is only a visibly non-production Compatible S3 setting, does not satisfy production verification, and can be bypassed by privileged identities. |
| KMS mismatch | Select the exact same-region customer-managed key and correct its IAM/key policies. |
| KMS access denied | Confirm the identity policy and key policy both name the exact key, account, S3 regional service, and Bucket Key encryption context; then verify the bucket default encryption matches the app. |
| Object Lock mismatch | Confirm mode and minimum retention. Enabling Object Lock is irreversible. |
| Bucket policy, lifecycle, or replication mismatch | Apply the complete exact five-statement policy from the native bucket template; do not merge extra bucket-policy statements. Configure lifecycle/replication through reviewed IaC. Scopeproof verifies but does not overwrite these controls on an existing bucket. |
| Browser cannot list versions | Add prefix-scoped `s3:ListBucketVersions`. |
| Exact version download rejected | Add `s3:GetObjectVersion` and `kms:Decrypt`, then refresh the version list. |
| Checksum mismatch | Treat as an integrity incident; retain local evidence and investigate the S3/request audit trail. |
| More than 5,000 versions | Narrow the prefix or use S3 Inventory for the larger evidence set. |

Never paste AWS credentials into Jira, evidence notes, repositories, screenshots, assessor packages, or support tickets.

## AWS references

- [S3 Bucket Keys and KMS encryption context](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html)
- [S3 server-side encryption with AWS KMS](https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html)
- [AWS KMS key policies](https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html)
- [Default KMS key policy and account delegation](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html)
- [Using IAM policies with AWS KMS](https://docs.aws.amazon.com/kms/latest/developerguide/iam-policies.html)
