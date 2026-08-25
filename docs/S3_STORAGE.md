# AWS S3 evidence storage

Scopeproof Capture can copy each locally verified screenshot and immutable JSON manifest to a private, versioned S3 evidence prefix. Production compliance mode adds temporary-credential enforcement, customer-managed KMS encryption, Object Lock retention, ownership controls, bucket-posture verification, exact version receipts, optional Deep Archive and replication, and auditable downloads.

## Recommended production workflow

1. Obtain temporary AWS credentials from IAM Identity Center or an approved `AssumeRole` workflow. Export the access key ID, secret access key, session token, and exact expiration time. Scopeproof does not perform the browser-based Identity Center login itself.
2. Choose **Scopeproof shield → AWS S3 Storage…** and select **Production compliance**.
3. Enter a same-account bucket, region, nonempty evidence prefix, customer-managed KMS key ARN, Object Lock mode and retention, and the temporary credential set. Select FIPS endpoints when policy requires them.
4. Leave downloads disabled for an upload-only endpoint. Enable them only for operators who need the version-aware S3 browser.
5. For an existing bucket, choose **Save & Verify**. Scopeproof verifies the caller identity, expected bucket owner, prefix access, Block Public Access, versioning, BucketOwnerEnforced ownership, KMS configuration, Object Lock mode/retention, and any requested lifecycle or replication configuration.
6. For a new bucket, choose **Create & Harden Bucket**, read the irreversible Object Lock warning, and confirm. Scopeproof applies and re-reads the selected posture before enabling uploads.
7. Remove bucket-management permissions immediately. Keep only the applicable upload-only or browser policy.
8. Deploy the CloudTrail monitoring template in `infra/aws/scopeproof-s3-observability.yaml` and confirm its SNS subscription.

The **Compatible S3** profile supports existing SSE-S3 buckets and long-lived credentials during migration. It still requires Block Public Access, versioning, matching default encryption, fixed AWS endpoints, destination binding, checksummed uploads, and version IDs. It is not the recommended profile for high-risk production evidence.

When using a customer-managed key, select **SSE-KMS** or **DSSE-KMS** in the app. **SSE-S3 (AES-256)** uses an S3-managed key and must not have a KMS ARN. The app's encryption selection, KMS ARN, bucket default encryption, bucket policy, IAM policy, and KMS key policy must agree.

Production credentials must include an STS session token and expiration. The Keychain item is automatically deleted when the session is expired or within five minutes of expiration. Obtain a new session and run **Save & Verify** again. Never use AWS root credentials.

## What bucket creation changes

For a new production bucket, Scopeproof configures:

- all four S3 Block Public Access controls;
- versioning;
- Object Ownership `BucketOwnerEnforced`;
- SSE-KMS or DSSE-KMS default encryption with the selected key;
- Object Lock with the selected Governance or Compliance default retention;
- an optional prefix-scoped Deep Archive transition; and
- optional replication when a destination bucket, replication role, and destination KMS key are supplied.

Object Lock cannot be disabled after it is enabled. Compliance retention cannot be shortened, bypassed, or removed during its active period. Confirm retention with records, legal, privacy, and compliance owners before creation.

If the bucket already belongs to the caller, **Create & Harden Bucket** hardens its access, ownership, encryption, versioning, and Object Lock posture. It does not overwrite an existing bucket policy, lifecycle, or replication configuration. Configure those through reviewed infrastructure-as-code and use **Save & Verify** to confirm the result. The production verifier requires the three exact `ScopeproofDeny*` policy statements below; they may coexist with stricter organization statements.

Setup is fail-closed. A partially created bucket is retained with automatic uploads disabled; Scopeproof never attempts to delete it.

## Credential and configuration storage

The access key, secret key, session token, and optional expiration are encoded together in a macOS generic-password Keychain item:

```text
service: com.scopeproof.capture
account: aws-s3-evidence-credentials-v1
protection: WhenUnlockedThisDeviceOnly
```

After verification, the AWS account, principal ARN, exact destination/settings digest, verification time, and verified bucket posture are stored in a separate `WhenUnlockedThisDeviceOnly` Keychain item. Changing credentials or any security-sensitive routing setting invalidates that binding and disables uploads until re-verification.

Bucket, region, prefix, KMS ARN, retention, FIPS, lifecycle, replication, download, and automatic-upload selections are non-secret and remain in macOS preferences. Credentials are never written to preferences, manifests, receipts, logs, environment files, Git, or the CloudTrail template. **Disconnect** deletes both S3 Keychain items and preferences; it does not delete evidence.

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

Replace the bucket, prefix, and KMS ARN. Merge these statements into an existing policy without removing organization controls. Scopeproof checks the statement IDs, deny effect, wildcard principal, actions, resources, and conditions so a same-named but weakened statement does not pass verification.

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

Use `aws:kms:dsse` instead of `aws:kms` when DSSE-KMS is selected. A new production bucket receives this policy automatically. Existing policies are never replaced by the app.

## IAM separation

Use separate roles or permission sets. The setup/verifier permissions should not remain on the daily application identity.

### Temporary setup and posture verification

Replace the bucket ARN. Add lifecycle or replication actions only when those features are selected. Replication also requires a tightly scoped `iam:PassRole` permission for the one replication role.

```json
{
  "Version": "2012-10-17",
  "Statement": [{
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
      "s3:GetBucketPolicy"
    ],
    "Resource": "arn:aws:s3:::company-compliance-evidence"
  }]
}
```

Optional lifecycle actions are `s3:PutLifecycleConfiguration` and `s3:GetLifecycleConfiguration`. Optional replication actions are `s3:PutReplicationConfiguration` and `s3:GetReplicationConfiguration`; grant `iam:PassRole` only on the exact replication role. The destination bucket, Object Lock posture, KMS policy, and cross-account trust must be prepared separately.

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
        "s3:GetBucketPolicy"
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

This example assumes SSE-KMS with S3 Bucket Keys enabled, which Scopeproof requests for SSE-KMS uploads. In that mode, AWS uses the bucket ARN as the KMS encryption context. For DSSE-KMS or an SSE-KMS bucket without Bucket Keys, restrict the encryption context with `ArnLike` to `arn:aws:s3:::company-compliance-evidence/scopeproof-evidence/*` instead.

### Dedicated IAM user for Compatible S3

Use a long-lived IAM user only when a migration or workstation constraint prevents temporary STS credentials. Select **Compatible S3** because Production compliance rejects long-lived access keys. Create a dedicated no-console user such as `scopeproof-s3-evidence`; do not reuse an administrator or personal identity, add it to broad groups, or attach any other policy. Attach the exact daily policy above plus the optional browser additions only when downloads are required. Where organization policy permits, use the same maximum-permission document as a permissions boundary. Rotate the key, disable it when the workstation is not in use, and delete it when the temporary-credential workflow is available.

Add an explicit statement for that user to the existing customer-managed KMS key policy. Do not replace the current key policy or remove its account-root delegation and administrator recovery statements. The IAM user must exist before saving a policy that names it.

```json
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
```

This key-policy example also assumes SSE-KMS with S3 Bucket Keys enabled. It allows the named identity to generate data keys and decrypt only when KMS is called through S3 in the expected account for that bucket. It does not grant direct KMS API use, key administration, grants, deletion, rotation, or use with another bucket. If browsing is disabled, omit `kms:Decrypt` from both the key policy and IAM identity policy. Review any existing key-administrator statements separately: an administrator who can edit the key policy remains capable of changing these restrictions.

### Optional browser additions

Add these only when **Allow prefix-scoped browsing and validated downloads** is enabled:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListScopeproofVersions",
      "Effect": "Allow",
      "Action": "s3:ListBucketVersions",
      "Resource": "arn:aws:s3:::company-compliance-evidence",
      "Condition": {"StringLike": {"s3:prefix": ["scopeproof-evidence/", "scopeproof-evidence/*"]}}
    },
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

Use KMS encryption-context conditions and a bucket policy to restrict the key and writes to the exact bucket/prefix. Deny non-TLS requests, public ACLs, incorrect encryption algorithms, and any KMS key other than the configured key.

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

Deploy `infra/aws/scopeproof-s3-observability.yaml` with the evidence bucket/prefix, exact evidence KMS key ARN, and a separate globally unique CloudTrail log bucket. It enables log-file validation, S3 data events, immutable versioned audit-log storage, and SNS alerts for evidence deletions, bucket-policy/public-access/versioning/Object Lock/encryption/lifecycle/replication changes, account-level S3 Public Access Block changes, and changes to that KMS key. CloudTrail data events are billable and the email subscription must be confirmed.

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
| KMS mismatch | Select the exact same-region customer-managed key and correct its IAM/key policies. |
| KMS access denied | Confirm the identity policy and key policy both name the exact key, account, S3 regional service, and Bucket Key encryption context; then verify the bucket default encryption matches the app. |
| Object Lock mismatch | Confirm mode and minimum retention. Enabling Object Lock is irreversible. |
| Bucket policy, lifecycle, or replication mismatch | Merge the documented `ScopeproofDeny*` policy statements or configure lifecycle/replication through reviewed IaC; Scopeproof verifies but does not overwrite these controls on an existing bucket. |
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
