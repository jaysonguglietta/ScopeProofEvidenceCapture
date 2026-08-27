import assert from "node:assert/strict";
import test from "node:test";

import { PutObjectCommand, S3Client } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";

test("pinned AWS SDK signs every exact upload header, including content-type", async () => {
  const tenantId = `ten_${"a".repeat(32)}`;
  const intentId = `upl_${"b".repeat(32)}`;
  const evidenceId = `evd_${"c".repeat(32)}`;
  const kmsKeyArn = "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const headers = Object.freeze({
    "content-length": "1024",
    "content-type": "image/png",
    "x-amz-checksum-sha256": Buffer.from("d".repeat(64), "hex").toString("base64"),
    "x-amz-meta-control-id": "PCI-DSS-10.2.1",
    "x-amz-meta-evidence-id": evidenceId,
    "x-amz-meta-expected-sha256": "d".repeat(64),
    "x-amz-meta-tenant-id": tenantId,
    "x-amz-meta-upload-intent-id": intentId,
    "x-amz-server-side-encryption": "aws:kms",
    "x-amz-server-side-encryption-aws-kms-key-id": kmsKeyArn,
    "x-amz-server-side-encryption-context": Buffer.from(JSON.stringify({
      scopeproofPurpose: "quarantine",
      scopeproofTenantId: tenantId,
    })).toString("base64"),
  });
  const client = new S3Client({
    region: "us-east-1",
    credentials: {
      accessKeyId: "ASIAABCDEFGHIJKLMNOP",
      secretAccessKey: "s".repeat(40),
      sessionToken: "offline-presign-test-session-token",
    },
  });
  const command = new PutObjectCommand({
    Bucket: "scopeproof-quarantine",
    Key: `tenants/${tenantId}/controls/PCI-DSS-10.2.1/quarantine/${intentId}.upload`,
    ContentLength: Number(headers["content-length"]),
    ContentType: headers["content-type"],
    ChecksumSHA256: headers["x-amz-checksum-sha256"],
    Metadata: {
      "control-id": headers["x-amz-meta-control-id"],
      "evidence-id": headers["x-amz-meta-evidence-id"],
      "expected-sha256": headers["x-amz-meta-expected-sha256"],
      "tenant-id": headers["x-amz-meta-tenant-id"],
      "upload-intent-id": headers["x-amz-meta-upload-intent-id"],
    },
    ServerSideEncryption: "aws:kms",
    SSEKMSKeyId: kmsKeyArn,
    SSEKMSEncryptionContext: headers["x-amz-server-side-encryption-context"],
  });
  const signedHeaderNames = new Set(Object.keys(headers));
  const url = await getSignedUrl(client, command, {
    expiresIn: 300,
    signingDate: new Date("2026-08-27T16:00:00.000Z"),
    signableHeaders: new Set(signedHeaderNames),
    unhoistableHeaders: new Set(signedHeaderNames),
  });

  const signedHeaders = new Set(
    (new URL(url).searchParams.get("X-Amz-SignedHeaders") ?? "").split(";"),
  );
  assert.ok(signedHeaders.has("host"));
  for (const header of Object.keys(headers)) {
    assert.ok(signedHeaders.has(header), `missing signed header: ${header}`);
  }
});
