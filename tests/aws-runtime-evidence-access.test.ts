import assert from "node:assert/strict";
import test from "node:test";

import { TenantSecurityError, type TenantId, type UserId } from "../lib/aws-runtime/contracts.ts";
import {
  HostedEvidenceAccessService,
  RdsDataEvidenceAccessRepository,
  decodeEvidenceCursor,
  type EvidenceAccessRepository,
  type EvidenceArtifactAccessRecord,
  type ExactGetObjectPresignInput,
  type ExactGetObjectPresigner,
  type ExactPresignedGetObject,
} from "../lib/aws-runtime/evidence/index.ts";
import type { RdsDataApiExecutor } from "../lib/aws-runtime/http/index.ts";
import type { TenantActor } from "../lib/aws-runtime/tenancy.ts";

const TENANT = `ten_${"a".repeat(32)}` as TenantId;
const OTHER_TENANT = `ten_${"b".repeat(32)}` as TenantId;
const USER = `usr_${"c".repeat(32)}` as UserId;
const EVIDENCE_1 = `evd_${"d".repeat(32)}`;
const EVIDENCE_2 = `evd_${"e".repeat(32)}`;
const EVIDENCE_3 = `evd_${"f".repeat(32)}`;
const NOW = new Date("2026-08-28T16:00:00.000Z");
const BUCKET = "scopeproof-acme-evidence";
const ENDPOINT = `${BUCKET}.s3.us-east-1.amazonaws.com`;
const CURSOR_SECRET = new Uint8Array(32).fill(23);

const actor: TenantActor = Object.freeze({
  tenantId: TENANT,
  tenantHostname: "api-acme.evidence.example.com" as TenantActor["tenantHostname"],
  userId: USER,
  membershipId: `mem_${"1".repeat(32)}` as TenantActor["membershipId"],
  subject: "cognito-subject-acme",
  role: "auditor",
});

function evidence(evidenceId = EVIDENCE_1, overrides: Partial<EvidenceArtifactAccessRecord> = {}): EvidenceArtifactAccessRecord {
  return {
    tenantId: TENANT,
    evidenceId,
    controlId: "PCI-DSS-10.2.1",
    title: "Quarterly privileged-access review",
    description: "Redacted audit evidence",
    evidenceType: "SCREENSHOT",
    source: "Scopeproof Capture",
    systemName: "Production identity provider",
    status: "APPROVED",
    revision: 4,
    contentType: "image/png",
    byteSize: 4_096,
    checksumSha256: "2".repeat(64) as EvidenceArtifactAccessRecord["checksumSha256"],
    evidenceBucket: BUCKET,
    objectKey: `tenants/${TENANT}/controls/PCI-DSS-10.2.1/evidence/${evidenceId}.png`,
    objectVersionId: "3HL4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY",
    capturedAt: "2026-08-28T15:00:00.000Z",
    retainUntil: "2027-08-28T15:00:00.000Z",
    createdAt: "2026-08-28T15:00:05.000Z",
    ...overrides,
  };
}

class RecordingRepository implements EvidenceAccessRepository {
  listRows: readonly EvidenceArtifactAccessRecord[] = [];
  readRow: EvidenceArtifactAccessRecord | null = null;
  listCalls: unknown[] = [];
  readCalls: unknown[] = [];

  async list(input: Parameters<EvidenceAccessRepository["list"]>[0]) {
    this.listCalls.push(input);
    return this.listRows;
  }

  async readExact(input: Parameters<EvidenceAccessRepository["readExact"]>[0]) {
    this.readCalls.push(input);
    return this.readRow;
  }
}

class RecordingPresigner implements ExactGetObjectPresigner {
  inputs: ExactGetObjectPresignInput[] = [];
  mutate?: (value: ExactPresignedGetObject) => ExactPresignedGetObject;

  async presignGetObject(input: ExactGetObjectPresignInput): Promise<ExactPresignedGetObject> {
    this.inputs.push(input);
    const url = new URL(`https://${ENDPOINT}/${input.key.split("/").map(encodeURIComponent).join("/")}`);
    url.searchParams.set("versionId", input.versionId);
    url.searchParams.set("response-content-type", input.responseContentType);
    url.searchParams.set("response-content-disposition", input.responseContentDisposition);
    url.searchParams.set("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
    url.searchParams.set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD");
    url.searchParams.set("X-Amz-Credential", "ASIAEXAMPLE12345678/20260828/us-east-1/s3/aws4_request");
    url.searchParams.set("X-Amz-Date", "20260828T160000Z");
    url.searchParams.set("X-Amz-Expires", String(input.expiresInSeconds));
    url.searchParams.set("X-Amz-Security-Token", "temporary-session-token");
    url.searchParams.set("X-Amz-Signature", "4".repeat(64));
    url.searchParams.set("X-Amz-SignedHeaders", ["host", ...Object.keys(input.requiredHeaders)].sort().join(";"));
    url.searchParams.set("x-id", "GetObject");
    const result: ExactPresignedGetObject = {
      method: "GET",
      url: url.toString(),
      bucket: input.bucket,
      key: input.key,
      versionId: input.versionId,
      expiresAt: input.expiresAt,
      requiredHeaders: input.requiredHeaders,
    };
    return this.mutate?.(result) ?? result;
  }
}

function service(repository: EvidenceAccessRepository, presigner: ExactGetObjectPresigner, now = NOW) {
  return new HostedEvidenceAccessService({
    repository,
    presigner,
    endpointHostname: ENDPOINT,
    signingRegion: "us-east-1",
    expectedBucketOwner: "111111111111",
    cursorSecret: CURSOR_SECRET,
    clock: () => now,
    downloadTtlSeconds: 60,
    cursorTtlSeconds: 900,
  });
}

test("hosted evidence listing uses tenant-bound opaque keyset cursors", async () => {
  const repository = new RecordingRepository();
  repository.listRows = [
    evidence(EVIDENCE_1),
    evidence(EVIDENCE_2, { capturedAt: "2026-08-28T14:00:00.000Z" }),
    evidence(EVIDENCE_3, { capturedAt: "2026-08-28T13:00:00.000Z" }),
  ];
  const page = await service(repository, new RecordingPresigner()).list(actor, { limit: 2 });
  assert.deepEqual(page.items.map((item) => item.evidenceId), [EVIDENCE_1, EVIDENCE_2]);
  assert.ok(page.nextCursor);
  assert.equal(JSON.stringify(page).includes(BUCKET), true, "the service retains storage fields for the trusted HTTP adapter to screen");
  assert.deepEqual(await decodeEvidenceCursor(page.nextCursor!, TENANT, CURSOR_SECRET, NOW), {
    capturedAt: "2026-08-28T14:00:00.000Z",
    evidenceId: EVIDENCE_2,
  });
  assert.deepEqual(repository.listCalls, [{ tenantId: TENANT, requestedBy: USER, limit: 3, cursor: undefined }]);

  await assert.rejects(
    decodeEvidenceCursor(`${page.nextCursor!.slice(0, -1)}A`, TENANT, CURSOR_SECRET, NOW),
    (error: unknown) => error instanceof TenantSecurityError && error.code === "INVALID_IDENTIFIER",
  );
  await assert.rejects(
    decodeEvidenceCursor(page.nextCursor!, OTHER_TENANT, CURSOR_SECRET, NOW),
    (error: unknown) => error instanceof TenantSecurityError && error.code === "INVALID_IDENTIFIER",
  );
  await assert.rejects(
    decodeEvidenceCursor(page.nextCursor!, TENANT, CURSOR_SECRET, new Date("2026-08-28T16:15:01.000Z")),
    (error: unknown) => error instanceof TenantSecurityError && error.safeStatus === 410,
  );

  const rotatedRepository = new RecordingRepository();
  await new HostedEvidenceAccessService({
    repository: rotatedRepository,
    presigner: new RecordingPresigner(),
    endpointHostname: ENDPOINT,
    signingRegion: "us-east-1",
    expectedBucketOwner: "111111111111",
    cursorSecret: new Uint8Array(32).fill(24),
    previousCursorSecrets: [CURSOR_SECRET],
    clock: () => NOW,
    cursorTtlSeconds: 900,
  }).list(actor, { limit: 2, cursor: page.nextCursor });
  assert.deepEqual(rotatedRepository.listCalls[0], {
    tenantId: TENANT,
    requestedBy: USER,
    limit: 3,
    cursor: { capturedAt: "2026-08-28T14:00:00.000Z", evidenceId: EVIDENCE_2 },
  });
});

test("listing rejects cross-tenant rows returned by a compromised repository", async () => {
  const repository = new RecordingRepository();
  repository.listRows = [evidence(EVIDENCE_1, {
    tenantId: OTHER_TENANT,
    objectKey: `tenants/${OTHER_TENANT}/controls/PCI-DSS-10.2.1/evidence/${EVIDENCE_1}.png`,
  })];
  await assert.rejects(service(repository, new RecordingPresigner()).list(actor, { limit: 10 }), (error: unknown) =>
    error instanceof TenantSecurityError && error.code === "RESOURCE_NOT_FOUND" && error.safeStatus === 404,
  );
});

test("download issuance signs one immutable S3 version and rejects a weakened capability", async () => {
  const repository = new RecordingRepository();
  repository.readRow = evidence();
  const presigner = new RecordingPresigner();
  const issued = await service(repository, presigner).issueDownload(actor, { evidenceId: EVIDENCE_1, expectedRevision: 4 });
  assert.equal(issued.download.versionId, repository.readRow.objectVersionId);
  assert.equal(new URL(issued.download.url).searchParams.get("versionId"), repository.readRow.objectVersionId);
  assert.deepEqual(issued.download.requiredHeaders, {
    "x-amz-checksum-mode": "ENABLED",
    "x-amz-expected-bucket-owner": "111111111111",
  });
  assert.deepEqual(repository.readCalls, [{ tenantId: TENANT, requestedBy: USER, evidenceId: EVIDENCE_1, expectedRevision: 4 }]);
  assert.equal(presigner.inputs[0].responseContentDisposition, `attachment; filename="${EVIDENCE_1}.png"`);

  presigner.mutate = (value) => {
    const url = new URL(value.url);
    url.searchParams.delete("versionId");
    return { ...value, url: url.toString() };
  };
  await assert.rejects(service(repository, presigner).issueDownload(actor, { evidenceId: EVIDENCE_1, expectedRevision: 4 }), (error: unknown) =>
    error instanceof TenantSecurityError && error.safeStatus === 500,
  );
});

test("download issuance rejects drifted SigV4 scopes, duplicate overrides, and unexpected query parameters", async () => {
  type UrlMutation = (url: URL) => void;
  const cases: ReadonlyArray<readonly [string, UrlMutation]> = [
    ["signing time and matching scope date drift from the requested signing instant", (url) => {
      url.searchParams.set("X-Amz-Date", "20260829T160000Z");
      url.searchParams.set("X-Amz-Credential", "ASIAEXAMPLE12345678/20260829/us-east-1/s3/aws4_request");
    }],
    ["credential scope date differs from the signing date", (url) => {
      url.searchParams.set("X-Amz-Credential", "ASIAEXAMPLE12345678/20260827/us-east-1/s3/aws4_request");
    }],
    ["credential scope region differs from the configured endpoint region", (url) => {
      url.searchParams.set("X-Amz-Credential", "ASIAEXAMPLE12345678/20260828/us-west-2/s3/aws4_request");
    }],
    ["credential scope service is not S3", (url) => {
      url.searchParams.set("X-Amz-Credential", "ASIAEXAMPLE12345678/20260828/us-east-1/sts/aws4_request");
    }],
    ["credential scope terminator is invalid", (url) => {
      url.searchParams.set("X-Amz-Credential", "ASIAEXAMPLE12345678/20260828/us-east-1/s3/not_aws4_request");
    }],
    ["response content type is duplicated", (url) => {
      url.searchParams.append("response-content-type", "text/html");
    }],
    ["response content disposition is duplicated", (url) => {
      url.searchParams.append("response-content-disposition", "inline");
    }],
    ["an additional response override is injected", (url) => {
      url.searchParams.set("response-content-language", "en-US");
    }],
    ["an unrelated query parameter is injected", (url) => {
      url.searchParams.set("attacker-controlled", "true");
    }],
    ["the SDK operation identifier is changed", (url) => {
      url.searchParams.set("x-id", "PutObject");
    }],
    ["the payload hash marker is changed", (url) => {
      url.searchParams.set("X-Amz-Content-Sha256", "0".repeat(64));
    }],
    ["an unreturned signed header is added", (url) => {
      url.searchParams.set("X-Amz-SignedHeaders", `${url.searchParams.get("X-Amz-SignedHeaders")};x-amz-meta-hidden`);
    }],
  ];

  for (const [label, mutate] of cases) {
    const repository = new RecordingRepository();
    repository.readRow = evidence();
    const presigner = new RecordingPresigner();
    presigner.mutate = (value) => {
      const url = new URL(value.url);
      mutate(url);
      return { ...value, url: url.toString() };
    };
    await assert.rejects(
      service(repository, presigner).issueDownload(actor, { evidenceId: EVIDENCE_1, expectedRevision: 4 }),
      (error: unknown) => error instanceof TenantSecurityError && error.safeStatus === 500,
      label,
    );
  }

  const repository = new RecordingRepository();
  repository.readRow = evidence();
  await assert.rejects(
    new HostedEvidenceAccessService({
      repository,
      presigner: new RecordingPresigner(),
      endpointHostname: ENDPOINT,
      signingRegion: "us-west-2",
      expectedBucketOwner: "111111111111",
      cursorSecret: CURSOR_SECRET,
      clock: () => NOW,
    }).issueDownload(actor, { evidenceId: EVIDENCE_1, expectedRevision: 4 }),
    (error: unknown) => error instanceof TenantSecurityError && error.safeStatus === 500,
    "endpoint hostname and configured signing region must agree",
  );
});

test("canonical storage validation survives identifier collisions and rejects MIME/key drift", async () => {
  const repository = new RecordingRepository();
  const collisionControl = `PCI.${EVIDENCE_1}.A`;
  repository.readRow = evidence(EVIDENCE_1, {
    controlId: collisionControl,
    objectKey: `tenants/${TENANT}/controls/${collisionControl}/evidence/${EVIDENCE_1}.png`,
  });
  const presigner = new RecordingPresigner();
  const issued = await service(repository, presigner).issueDownload(actor, { evidenceId: EVIDENCE_1, expectedRevision: 4 });
  assert.equal(presigner.inputs[0].key, repository.readRow.objectKey);
  assert.equal(presigner.inputs[0].responseContentDisposition, `attachment; filename="${EVIDENCE_1}.png"`);
  assert.equal(issued.evidence.controlId, collisionControl);

  repository.readRow = evidence(EVIDENCE_1, {
    contentType: "image/png",
    objectKey: `tenants/${TENANT}/controls/PCI-DSS-10.2.1/evidence/${EVIDENCE_1}.json`,
  });
  await assert.rejects(
    service(repository, new RecordingPresigner()).issueDownload(actor, { evidenceId: EVIDENCE_1, expectedRevision: 4 }),
    (error: unknown) => error instanceof TenantSecurityError && error.safeStatus === 500,
  );
});

test("RDS evidence repository establishes tenant context and calls execute-only functions", async () => {
  const calls: Array<Record<string, unknown>> = [];
  let committed = 0;
  let rolledBack = 0;
  const row = evidence();
  const executor: RdsDataApiExecutor = {
    async beginTransaction() { return { transactionId: "transaction-12345678" }; },
    async executeStatement(input) {
      calls.push(input as unknown as Record<string, unknown>);
      if (!input.formatRecordsAs) return {};
      return { formattedRecords: JSON.stringify([{
        tenant_id: row.tenantId,
        evidence_id: row.evidenceId,
        control_id: row.controlId,
        title: row.title,
        description: row.description,
        evidence_type: row.evidenceType,
        source: row.source,
        system_name: row.systemName,
        status: row.status,
        revision: row.revision,
        content_type: row.contentType,
        byte_size: String(row.byteSize),
        checksum_sha256: row.checksumSha256,
        evidence_bucket: row.evidenceBucket,
        object_key: row.objectKey,
        object_version_id: row.objectVersionId,
        captured_at: row.capturedAt,
        retain_until: row.retainUntil,
        created_at: row.createdAt,
      }]) };
    },
    async commitTransaction() { committed += 1; return {}; },
    async rollbackTransaction() { rolledBack += 1; return {}; },
  };
  const repository = new RdsDataEvidenceAccessRepository({
    executor,
    resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:scopeproof-prod",
    secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:scopeproof/runtime-AbCd12",
    database: "scopeproof_acme",
  });
  assert.equal((await repository.readExact({ tenantId: TENANT, requestedBy: USER, evidenceId: EVIDENCE_1, expectedRevision: 4 }))?.evidenceId, EVIDENCE_1);
  assert.equal(committed, 1);
  assert.equal(rolledBack, 0);
  assert.match(String(calls[0].sql), /set_config\('scopeproof\.tenant_id'/);
  assert.match(String(calls[1].sql), /scopeproof\.read_accessible_evidence/);
  assert.doesNotMatch(String(calls[1].sql), new RegExp(BUCKET));
});
