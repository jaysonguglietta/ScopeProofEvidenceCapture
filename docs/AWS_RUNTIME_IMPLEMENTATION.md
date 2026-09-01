# AWS runtime security and evidence lifecycle

This guide describes the production AWS runtime contracts in `lib/aws-runtime`,
the tenant API Lambda in `infra/aws/cdk/runtime/tenant-api`, the PostgreSQL
boundary in `infra/aws/database`, and the GuardDuty promotion worker in
`infra/aws/cdk/runtime/promote-evidence`. It is an implementation and operator
reference, not evidence that the stack has been deployed. Repository changes do
not create AWS resources or customer accounts.

## Security outcome

The hosted runtime is designed around four independent facts that must all be
true before customer evidence is trusted:

1. The request arrived for an exact, active tenant hostname through the
   configured authority path.
2. Cognito signed an unexpired access token for an allowed web or native
   application client, the token includes the exact operation scope, and the
   database still contains an active membership with the required role.
3. The upload capability binds one tenant, control, evidence identifier,
   checksum, byte length, media type, KMS context, key, object path, and short
   expiry using temporary STS credentials and SigV4.
4. GuardDuty scanned the exact quarantine object version, S3 returned an exact
   immutable destination version with the required retention, and PostgreSQL
   atomically committed both lifecycle revisions and a KMS-signed receipt.

Hostnames select a tenant candidate. They never authorize access. Cognito groups,
email domains, editable claims, and client-provided tenant identifiers are not
authorization inputs.

## Runtime components

| Component | Responsibility | Authoritative state |
| --- | --- | --- |
| `DynamoTenantAuthorityResolver` | Strongly consistent exact-host lookup, active/canonical-state validation, and tenant/app-client binding | DynamoDB tenant registry |
| `CognitoJwtVerifier` | Strict RS256/JWKS and access-token verification | Cognito user-pool keys |
| `authorizeApiGatewayRequest` | Request target, exact host authority, bearer token, app-client allowlist, OAuth scope, membership, and RBAC | Request context plus PostgreSQL |
| `HmacTrustedEdgeAuthorityVerifier` | Cryptographically binds a viewer host to one method/path/request and consumes the nonce | Edge secret plus DynamoDB replay row |
| `RdsDataMembershipRepository` | Active principal/membership lookup under tenant RLS | Tenant PostgreSQL database |
| Tenant API Gateway/Lambdas | Answers `GET /health` as an API Gateway mock; routes identity/upload calls to the upload Lambda and metadata listing/exact-version download calls to a separately privileged read Lambda on one exact `api-<tenant>.<domain>` | API Gateway context plus tenant-scoped adapters |
| `UploadIntentIssuer` | Creates one opaque, checksum-bound, short-lived S3 PUT capability | Exact intent contract |
| `DynamoConditionalUploadIntentStore` | Atomically reserves the intent ID and nonce digest | DynamoDB control table |
| `RdsDataUploadIntentProjection` | Creates the corresponding evidence and upload rows through one idempotent procedure | Tenant PostgreSQL database |
| `RdsDataEvidenceAccessRepository` | Lists and resolves downloadable evidence through tenant-scoped execute-only procedures | Tenant PostgreSQL database |
| `HostedEvidenceAccessService` | Issues HMAC-protected tenant-bound cursors and 60-second exact-version GET capabilities | Aurora metadata plus S3 SigV4 |
| GuardDuty promotion Lambda | Verifies the exact scanned version, performs one conditional Object-Locked destination write, and reconciles state | S3, DynamoDB, and PostgreSQL |
| `RdsDataSignedAuditReceiptStore` | Verifies and appends one KMS-signed event into the tenant hash chain | Tenant PostgreSQL database |
| API audit outbox/signer | Durably records successful public API facts, leases a bounded batch, signs each canonical event with tenant KMS, atomically appends it to the hash chain, and retries/dead-letters poison rows | Tenant PostgreSQL, dedicated Lambda/database login, KMS, EventBridge, DLQ, CloudWatch |
| Exact-version legal-hold service | Separately commits requester-only `REQUESTED`, distinct-admin `APPROVED`, durable worker-only `APPLYING`, and exact-readback `APPLIED` state for one exact S3 `VersionId` | PostgreSQL plus S3 Object Lock |
| Legal-hold API/worker | Authenticates request and approval in separate calls, sweeps approved/applying operations, appends or reuses an exact KMS-signed audit receipt, publishes the audit-bound recovery record, and clears the Aurora outbox only after publication acknowledgement | Separate API/worker Lambda roles, PostgreSQL, S3 Object Lock, KMS, DynamoDB, EventBridge, and CloudWatch |

The AWS SDK is kept behind small facades. Tests can therefore exercise command
construction, exact parameters, malformed AWS responses, transaction rollback,
and replay behavior without credentials or network access.

## Configure authentication

Create one verifier per trusted Cognito user pool and bounded web/native client
set. Never
accept these values from an HTTP request.

```ts
import {
  CognitoJwtVerifier,
  RdsDataMembershipRepository,
} from "./lib/aws-runtime/index.ts";

const jwt = new CognitoJwtVerifier({
  issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_EXAMPLE",
  clientIds: ["the-exact-web-client-id", "the-exact-native-client-id"],
  maximumAuthenticationAgeSeconds: 3_600,
  maximumTokenLifetimeSeconds: 3_600,
  clockSkewSeconds: 30,
});

const memberships = new RdsDataMembershipRepository({
  executor: rdsDataExecutor,
  resourceArn: process.env.DATABASE_CLUSTER_ARN!,
  secretArn: process.env.DATABASE_SECRET_ARN!,
  database: process.env.DATABASE_NAME!,
  lookupMode: "security_definer_function",
});
```

The verifier requires an access token with `token_use=access` and an allowed
`client_id`. Authorization then maps each `TenantPermission` to one exact
`scopeproof/...` OAuth scope before the membership lookup. It rejects algorithm
changes, embedded key URLs, duplicate JSON
claims, non-canonical base64url, unexpected `aud`, invalid token lifetimes,
stale authentication, oversized JWKS documents, redirects, weak RSA keys,
duplicate key IDs, and unknown-key refresh floods. Do not substitute an ID token.

For a direct API Gateway custom domain, use `mode: "api_gateway_domain"`. If a
private origin receives a tenant hostname through CloudFront or another edge,
use `mode: "trusted_edge"`; the edge must sign the exact viewer host, API request
ID, method, raw path, timestamp, and nonce. `DynamoEdgeReplayNonceStore` stores
only a domain-separated nonce digest and consumes it with a conditional write.
An ordinary `Host` or `X-Forwarded-Host` header is never trusted.

Every protected route calls `handleAuthorizedApiRequest` with one explicit
`TenantPermission`. The CDK creates one regional API Gateway custom domain and
one Lambda execution role per tenant. The execution role can strongly read only
that exact API-domain registry key and assume only that tenant's data role;
API Gateway's default execute endpoint is disabled. Unauthenticated liveness is
kept outside that execution role. The API exposes:

- `GET /health`, an API Gateway mock that returns only `{"status":"ok"}` and
  never invokes Lambda or assumes the authenticated data role;
- `GET /v1/me`, which requires `evidence:read` and returns the authorized tenant,
  membership, role, and bounded token expiry; and
- `POST /v1/upload-intents`, which requires `evidence:collect`, strictly parses a
  bounded exact-key JSON body, loads the server-side tenant secret, reconciles
  DynamoDB/Aurora, and returns an exact presigned S3 capability;
- `POST /v1/evidence/search`, which requires `evidence:read`, accepts only a
  bounded page size and optional opaque tenant-bound cursor, and returns display
  metadata without bucket, object key, KMS ARN, or version fields;
- `POST /v1/evidence-download-intents`, which requires `evidence:read`, accepts
  only an evidence ID and expected revision, resolves the immutable bucket, key,
  and version server-side, and returns a 60-second exact-version S3 GET
  capability; and
- `POST /v1/legal-hold-requests` plus `POST /v1/legal-hold-approvals`, both of
  which require `retention:manage` and route to a separate legal-control Lambda
  so request and independent approval are different authenticated calls.

All responses are `no-store`, the exact browser origin is allowlisted, and route
failures use safe problem responses. Do not serialize the original exception,
SQL text, ARN, token, presigned URL, or credential. These source routes have not
been deployed or exercised against live Cognito, STS, Aurora, DynamoDB, or S3.

## Issue an upload capability

The route must first authorize `evidence:collect` and derive `tenantId` and
`requestedBy` from the authorized actor. It must validate that `assessmentId`
and `deviceId` belong to that same tenant. The exact client body includes
`assessmentId`, `capturedAt`, `contentType`, `controlId`, `description`,
`deviceId`, `evidenceId`, `evidenceType`, `expectedSha256`, `expectedSize`,
`idempotencyKey`, `metadata`, `source`, `systemName`, and `title`. It must not
include `artifactExpiresAt` or `requiredRetentionUntil`; an unexpected retention
field rejects the exact request shape. The client must generate one
canonical, unpadded, base64url-encoded 256-bit idempotency key for the logical
request (43 characters when generated by `generateUploadIdempotencyKey`) and
reuse that exact key after timeouts or ambiguous responses. Keys from 32 through
96 decoded bytes are accepted; a timestamp, UUID, counter, or human-readable
request ID is not an acceptable substitute.

`capturedAt` is a client assertion, not a retention-policy input. The Lambda
rejects a capture time more than five minutes in the future, reads the tenant's
configured `retentionDays`, and derives both `artifactExpiresAt` and
`requiredRetentionUntil` as exactly `capturedAt + retentionDays`. Those derived
values become immutable idempotency facts. The SECURITY DEFINER
`scopeproof.create_upload_intent` procedure independently reads
`tenant_identity.retention_days` and rejects any projection whose two retention
values differ from that exact result. A collector therefore cannot lengthen or
shorten Object Lock retention through the upload request.

Before secret loading, database projection, or presigning, one DynamoDB
transaction atomically consumes both request budgets: 60 upload-intent requests
per member and 300 per tenant per UTC minute. A limit failure returns 429 without
performing the expensive upload work. Creation has a separate UTC-day quota of
500 new reservations per member and 5,000 per tenant. Those two daily counters
are updated in the same transaction as a new lifecycle, nonce, and request
reservation, so a failed reservation consumes no creation budget and a committed
reservation cannot bypass it.

The server loads a 32-64 byte HMAC key from the tenant's dedicated Secrets
Manager secret and passes its secret bytes as `idempotencySecret` (the generated
64-character `hmacKey` is used as 64 UTF-8 bytes, not base64-decoded). The secret
is server-only: do not return it, accept it from a request, place it in CDK
context, or log it. The tenant stack generates the `hmacKey` value with 64
characters of random secret material. Construct the production store with:

1. `DynamoConditionalUploadIntentStore` as the event-consumer reservation.
2. `RdsDataUploadIntentProjection` as the PostgreSQL projection.
3. `DynamoAndRdsUploadIntentStore` to require both before an upload is returned.
4. `AwsSdkV3ExactPutObjectPresigner` using an S3 client with temporary STS
   credentials.

The application supplies evidence metadata to the combined store and passes the
store to `UploadIntentIssuer`. The issuer derives a stable 128-bit intent ID,
stable 256-bit nonce, and separate stored idempotency digest from the tenant ID,
client key, and server HMAC. It persists only digests and the approved,
secret-screened recovery projection. The raw client key and raw nonce are never
stored, and the public API does not return the nonce. Its digest is bound into
the signed object metadata and verified again by the promotion worker. A retry
receives the same logical intent but a newly signed, short-lived S3 capability.

The caller must send every returned `requiredHeaders` entry exactly as returned.
The signature includes:

- `Content-Length` and an allowlisted `Content-Type`;
- full-object `x-amz-checksum-sha256`;
- tenant, control, evidence, upload-intent, and upload-nonce-digest metadata;
- `aws:kms`, the exact tenant KMS key ARN, and the exact base64 encryption
  context `{scopeproofPurpose:"quarantine",scopeproofTenantId:"..."}`;
- a temporary STS session token; and
- a maximum ten-minute expiry.

The client must not follow redirects or change the path, query, or signed headers.
The authorization header, presigned URL, signed metadata, and STS credentials
must never be logged.

### Cross-service failure behavior

The Dynamo reservation is written before its PostgreSQL projection because the
GuardDuty consumer treats Dynamo as its event authority. One Dynamo transaction
conditionally writes the lifecycle, nonce-reservation, and request-reservation
rows and atomically increments the tenant/member daily creation counters. Before
attempting a write, and after a conditional collision, the adapter uses strongly
consistent reads and accepts only a complete, byte-for-byte match. It proves an
exact existing lifecycle before interpreting a daily-quota collision, so a retry
racing the original commit remains recoverable. It never treats a partial or
changed reservation as a successful retry, and an exact retry does not consume a
second daily creation slot. Every request, including a retry, still consumes the
bounded per-minute request budget.

Every exact first request or retry then executes the equality-checking
`scopeproof.create_upload_intent` database procedure. This is intentional: if an
Aurora commit succeeds but the Data API commit response is lost, the client
retries with the same idempotency key, the service reloads the canonical Dynamo
projection, and the idempotent procedure proves or repairs the database side
before another presign is returned. If Dynamo commits but PostgreSQL does not,
the response fails closed; the same exact retry resumes reconciliation. Changed
upload or evidence metadata returns a conflict. Never synthesize missing
metadata, copy a row between tenants, or mark a Dynamo row promoted manually.

HMAC rotation must preserve this recovery property. Keep the prior secret
version available for at least the longest upload-intent/reconciliation window
(currently intent expiry plus the seven-day lifecycle TTL grace), and make the
composed handler resolve `AWSCURRENT` for new operations and try the internally
held `AWSPREVIOUS` version only to find/reconcile an already reserved intent.
Never let a client select a secret version. The current library accepts one
current and at most one distinct prior 32-64 byte key per issuer instance. The
composed Lambda loads `AWSCURRENT` and optionally `AWSPREVIOUS`; it strongly
looks up the prior derivation only for exact recovery before allowing the
current key to create anything. Do not rotate by simply removing the prior
stage while retry rows may still exist, because the same client key would
derive a new intent ID under the new key. A live rotation/retry drill remains a
production gate.

## List and download immutable evidence

Evidence browsing uses Aurora as the authoritative metadata index; the public
API never lists S3 directly. `scopeproof.list_accessible_evidence` and
`scopeproof.read_accessible_evidence` are `SECURITY DEFINER` procedures that
require transaction-local tenant context and independently recheck active
membership with `evidence:read`. The dedicated evidence-read identity receives execute only on
those procedures, not table privileges. Listing is ordered by
`captured_at DESC, evidence_id DESC`, uses a matching partial index, and is
bounded to 100 returned items.

Pagination cursors are canonical, HMAC-authenticated, tenant-bound, keyset-based,
and expire after 15 minutes. A modified cursor, a cursor from another tenant, an
expired cursor, or a repository row from another tenant fails closed. Listing
responses include bounded display and integrity metadata but omit the bucket,
object key, KMS ARN, and version ID.

Cursor signing uses a purpose-specific Secrets Manager value, not the upload
idempotency HMAC. New cursors use `AWSCURRENT`; the composed Lambda may try the
one distinct `AWSPREVIOUS` version so an in-flight cursor survives a controlled
rotation (the service contract can accept at most two prior keys for other
adapters). The current and prior bytes are copied into the service and wiped from
the loader buffers. Clients cannot select a key version.

Downloads accept only an opaque evidence ID and expected revision. The server
reads the exact promoted S3 bucket, canonical tenant/control object key, and
nonempty immutable `VersionId` from Aurora, then signs `GetObject` for exactly
60 seconds with checksum mode and expected-bucket-owner headers. The client
cannot substitute any storage coordinate. The separate read Lambda can assume
only the tenant read role, whose S3 and KMS permissions are limited to exact
evidence versions under that tenant prefix and the immutable-evidence
encryption context. Application logs must never include the signed URL or its
`X-Amz-*` query values.

## Promote and reconcile evidence

`CleanMalwareScanResult` accepts only GuardDuty `COMPLETED` and
`NO_THREATS_FOUND` events for the configured account, region, malware plan,
bucket, tenant/control key, and exact `VersionId`. The worker then:

1. Strongly reads the Dynamo lifecycle row and verifies every immutable field.
2. Heads and tags the exact quarantine version and compares size, MIME, SHA-256,
   ETag, KMS binding, expiry, and scan tag.
3. Claims the lifecycle revision, a monotonically increasing fence, and a
   bounded lease with Dynamo transactions; the same fence is published to the
   independent PostgreSQL boundary.
4. Persists a durable copy permit, streams at most 25 MiB from the exact source
   `VersionId`, and creates the control-scoped evidence key with
   `If-None-Match: *`, the tenant KMS context, and the exact server-derived
   retention boundary. S3 SDK retries are disabled for this irreversible write.
5. Re-reads the exact destination `VersionId` and verifies checksum, metadata,
   KMS key, retention mode/date, and source version.
6. Produces domain-separated promotion facts, signs their SHA-256 digest with the
   tenant RSA-3072 KMS signing key, and calls
   `scopeproof.reconcile_promoted_evidence` through the ingest-only database role.
7. Commits the upload and evidence CAS revisions plus the signed ingest receipt
   in one PostgreSQL transaction.
8. Commits the exact database receipt and revisions into Dynamo, re-verifies
   idempotent retries, and only then deletes the exact quarantine version.

The ingest database login has no direct table privileges. It can set tenant
transaction context and execute only the reconciliation procedure. The primary
evidence bucket denies both object/delete-marker and exact-version deletion and
denies an evidence `PutObject` that omits the conditional header. If worker A
pauses and worker B takes over, exactly one conditional write can win; the other
attempt adopts the winner's durable attempt/version and reconciles under its
newer fence. A partial S3 result is rediscovered by exact metadata, a partial
database result is rejected, and randomized RSA-PSS retry signatures do not
create duplicate logical receipts.

## KMS-signed audit receipts

Create a canonical `TenantAuditEvent`, sign it with
`signTenantAuditReceipt`, then append it with
`RdsDataSignedAuditReceiptStore`. Production uses only
`RSASSA_PSS_SHA_256` with the configured tenant RSA-3072 signing-key ARN.

The signature input is the digest of:

```text
scopeproof-audit-receipt-v1 NUL canonical-receipt-json
```

The store verifies KMS before opening the transaction. PostgreSQL independently
reconstructs the event and receipt semantics, verifies both SHA-256 values,
serializes the tenant chain head, inserts the immutable event, and returns the
stored receipt. The adapter verifies that stored receipt with KMS again after
commit. An idempotent retry returns the first stored RSA-PSS signature; it never
replaces a receipt merely because a new randomized signature differs.

KMS signatures prove that the configured AWS key signed a digest. They do not
prove that an uncompromised application requested it. Protect `kms:Sign` with a
tenant-specific role, alert on key-policy and signing anomalies, retain CloudTrail
management events, and periodically export public keys and signed checkpoints to
an independently controlled archive.

### Public-API outbox drain

Successful upload-intent, evidence-search, exact-version download-intent, and
legal-hold request/approval handlers call `RdsDataApiAuditOutbox.record(...)`.
`scopeproof.record_api_audit_event(...)` independently validates active
membership/RBAC/resource binding and inserts both the immutable action record and
its delivery state atomically. API identities have no direct table access.

Every minute, one reserved-concurrency signer Lambda leases no more than ten due
rows for 120 seconds. `RdsDataApiAuditOutboxSignerStore` validates the bounded
Data API response, reads the serialized tenant audit head, builds the exact user
actor and action/resource/request event, obtains an RSA-PSS KMS signature, and
calls only `scopeproof.append_signed_api_audit_event(...)`. That specialized
procedure re-derives the outbox digest, event identifier, actor, occurrence time,
request, resource, outcome, and enriched details before it delegates internally
to the generic chain append. Append and delivery completion commit in one
transaction. The signer role is deliberately not granted the generic append
procedure or table access.

The lease is committed before runtime JSON validation. If a database row violates
the safe-details contract, the adapter retains only the validated tenant/outbox/
lease tuple and records `CLAIM_PARSE_FAILED`; it never signs the malformed facts.
Other failures record a stage-only code. Backoff starts at 30 seconds, caps at six
hours, and transitions the row to a persistent dead letter on attempt eight.
Later due rows remain claimable with `FOR UPDATE SKIP LOCKED`. If append committed
but its Data API response was lost, the failure procedure returns
`already_completed`, so retry neither overwrites the original randomized RSA-PSS
signature nor creates a second event.

The worker emits only counts/ages and safe identifiers. Alerts cover any failed
attempt, persistent dead letters, an oldest unsigned age of five minutes, missing
health telemetry, Lambda errors/throttles, and the retained EventBridge invocation
DLQ. Requeue is intentionally owner-only. Operators must correct the producer or
schema first, use `scopeproof.requeue_dead_lettered_api_audit_event(...)` only in
a reviewed break-glass owner session, then verify `completed_at`, the KMS receipt,
and chain continuity. Direct table edits and temporary generic-append grants are
not supported recovery actions.

## Exact-version S3 legal holds

Legal holds operate on a bucket, controlled evidence key, and non-empty S3
`VersionId`; a current-key operation is forbidden. The database enforces two
distinct active tenant administrators, exact evidence-row binding, and immutable
operation facts.

The reconciler uses this order:

1. Commit immutable requester-derived facts as `REQUESTED` in PostgreSQL.
2. Commit a separate, distinct administrator's digest-bound approval as
   `APPROVED`.
3. Let the worker read the already approved operation, then call
   `PutObjectLegalHold` with the exact `VersionId`.
4. Call `GetObjectLegalHold` for that same `VersionId` and require the requested
   postcondition.
5. Commit the approval digest, provider request IDs, and receipt with an
   expected-revision CAS, changing the operation to `APPLIED`.

An S3 or final database failure leaves the operation `APPROVED`. Retrying the
same operation ID and digests reuses its immutable facts, sets/verifies the same
S3 state, and converges. A conflicting retry fails. An operation without a
committed second-person approval never calls S3. Releasing a hold is
allowed only when it is the last active hold for that exact object version;
otherwise S3 must remain `ON`. No runtime role receives `DeleteObject` or
`s3:BypassGovernanceRetention` through this workflow.

The durable workflow has three separate committed phases:

1. `requestExactVersionLegalHoldChange` derives `requestedBy` from one already
   authenticated tenant administrator, writes immutable request facts and digest,
   and produces `REQUESTED`; it accepts no approver identity and performs no S3
   call.
2. `approveExactVersionLegalHoldChange` must run for a second authenticated
   tenant administrator. It binds that independently derived identity to the
   exact operation/request digest and commits `APPROVED`.
3. `reconcileExactVersionLegalHold` is worker-only. It can read but cannot create
   or approve work; only an independently committed approval allows the exact
   S3 `VersionId` update/readback and `APPLIED` CAS.

`requestedBy` and `approvedBy` are security decisions, not request-body fields.
PostgreSQL independently requires distinct active tenant administrators. The CDK
wires authenticated `POST /v1/legal-hold-requests` and
`POST /v1/legal-hold-approvals` to a separate, low-concurrency Lambda with exact
data/control role assumptions. A five-minute EventBridge schedule invokes a
single-concurrency worker that processes at most 25 sufficiently old approved
operations per sweep, verifies exact S3 state, and appends KMS-signed audit
receipts. CloudWatch alarms cover worker errors/failures, approved operations
older than 15 minutes, and requests awaiting independent approval for 24 hours.
Keep the capability unavailable until the stack is deployed, a usable audited
UI/process exists, alerts are delivered, and adversarial live tests pass.

## Database and IAM role separation

Each tenant is provisioned with six distinct `NOINHERIT` database logins and
corresponding Secrets Manager credentials:

- the upload runtime role has no table or sequence privileges and may execute
  only `scopeproof.current_tenant_id()`,
  `scopeproof.resolve_active_membership(text)`, and the exact
  `scopeproof.create_upload_intent(...)` procedure;
- the ingest role has no table grants and may execute only the exact promotion
  reconciliation procedure; and
- the evidence-control role has no table grants and may execute only signed
  audit append plus legal-hold reserve/confirm procedures; and
- the legal-hold API role has no table grants and may execute only membership
  resolution plus legal-hold request and approval procedures; and
- the evidence-read role has no table grants and may execute only tenant context,
  membership resolution, bounded keyset listing, and exact evidence lookup; and
- the API-audit signer role has no table grants and may execute only tenant
  context, one-row leasing, audit-head read, exact outbox-bound append, bounded
  failure transition, and queue-health procedures.

The IAM split mirrors the database split. The tenant data role can resolve its
tenant registry, reserve upload intents and quota counters, retrieve its
upload-idempotency secret, presign exact quarantine writes, and use the
execute-only runtime database secret. It cannot list or read quarantine or
immutable evidence and has no evidence-key decrypt permission. The promoter uses
the ingest identity and has a narrowly scoped KMS signing grant only for
promotion receipts. The tenant evidence-control role receives KMS signing/
verification for application audit receipts plus exact-version
`s3:GetObjectLegalHold`/`s3:PutObjectLegalHold`; it cannot delete evidence or
bypass governance retention. Never merge these roles for deployment convenience.
The separate evidence-read role uses only the evidence-read database secret,
cursor HMAC secret, exact tenant-version S3 read permission, and S3-mediated KMS
decrypt; it cannot create uploads or use the upload idempotency key.
The API-audit signer Lambda uses only its dedicated database secret and cluster,
the tenant audit key for `kms:Sign`/`kms:Verify`, and its pre-created log group;
it cannot assume a tenant data/control role or access S3 or DynamoDB.

## Validation

From the repository root:

```bash
npm ci --ignore-scripts
node --experimental-strip-types --test tests/aws-runtime-*.test.ts tests/aws-postgres.test.ts

cd infra/aws/cdk
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
pnpm run synth \
  -c deploymentEnvironment=dev \
  -c rootDomain=evidence.example.com \
  -c hostedZoneId=Z0123456789EXAMPLE \
  -c 'recovery={"mode":"disabled"}' \
  -c 'tenants=[]'
```

`cdk.json` deliberately leaves `rootDomain` and `deploymentEnvironment` empty.
The example above imports an existing example zone for local synthesis only;
every run must explicitly provide an environment, complete tenant array, and
recovery object, and a reviewed deployment must use the owned domain and real
zone ID or deliberately replace `hostedZoneId` with
`-c createHostedZone=true`. Tenant stacks reject missing recovery configuration;
supplying neither or both Route 53 modes also fails.

Required adversarial cases include a wrong tenant host, ID token, stale token,
revoked membership, replayed edge assertion, traversal control, changed signed
header, permanent AWS credentials, duplicate nonce, expired intent, wrong scan
version, checksum/KMS/retention mismatch, database revision race, conflicting
idempotency digest, forged KMS result, legal-hold current-version request, and an
S3 legal-hold postcondition mismatch.

## Deployment gates

Do not enable customer traffic until all of the following are true:

- the per-tenant API Gateway `/health` mock and authenticated Lambdas have been
  deployed, and `/health`, `/v1/me`, `/v1/upload-intents`, `/v1/evidence/search`,
  and `/v1/evidence-download-intents` pass live host/JWT/scope/membership/STS/
  Data API/DynamoDB/S3 tests. Evidence-read tests must cover two tenants,
  revoked membership, cursor tampering and expiry, current-to-previous cursor-key
  rotation, exact `VersionId` and signed response-header binding, the 60-second
  download capability, and independent per-route throttling/abuse behavior.
  Upload tests must include the 60/300 per-minute request limits, atomic 500/5,000
  daily creation limits, quota-boundary exact retry recovery, and 429 behavior;
- the exact Cognito issuer/client IDs and tenant domains are configuration, not
  request data;
- upload runtime, ingest, evidence-control, legal-hold API, evidence-read, and
  API-audit signer database credentials resolve to six different NOINHERIT roles, and the
  provisioner confirms no managed owner/application role participates in a
  PostgreSQL membership edge, while matching IAM roles cannot cross their
  procedure or object-control boundaries;
- the GuardDuty clean rule, DLQ, alarms, and runbook canaries pass in stage;
- KMS key policies, S3 Object Lock, CloudTrail data events, recovery replication,
  and legal-hold permissions match the synthesized templates;
- two deliberately different tenants pass cross-tenant negative tests;
- the CDK-wired request/approval routes and least-privilege legal-hold worker are
  deployed and prove the three committed phases and
  KMS audit behavior; and
- the API-audit signer proves exact outbox/event binding, single-writer chain
  ordering, ambiguous-commit recovery, malformed-row retry/dead-letter behavior,
  later-row progress, owner-only requeue, and alarm delivery; and
- operators have rehearsed partial upload, promotion, audit, legal-hold, and
  database-recovery scenarios.

The API source, adapters, and IaC policies are implemented and source-tested,
but no AWS resource or customer-facing route was deployed by this work. The
current Cloudflare/Sites application does not automatically use the AWS API.
