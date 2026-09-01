# Security and product remediation status — 2026-09-01

This document records source-level remediation status after the 2026-08-28 adversarial review. Its statements apply only to an exact reviewed commit containing the referenced changes; an uncommitted working tree, branch name, or local build is not closure evidence. It is a change-status and deployment-readiness reference, not a replacement for the threat model in [Security audit — 2026-08-28](SECURITY_AUDIT_2026-08-28.md).

The audit's open questions are intentionally not decided here. Those governance decisions remain with the product, legal, security, privacy, and records owners. This document instead distinguishes controls that now exist in source from external prerequisites that an operator must satisfy and validate before production use.

## Outcome

The current source closes the directly implementable product and security gaps addressed in this remediation batch:

- hosted assessments are bound to an explicit, non-empty system/control scope and a digest-verified, versioned control catalog;
- evidence review decisions, findings, finding transitions, and two-person hold-release decisions are durable and audited;
- large hosted collections use bounded opaque-cursor pagination and server-computed aggregates;
- package generation has a fail-closed preflight and refuses incomplete, unsafe, unapproved, or provenance-pending evidence;
- preflight and build share one behavior-tested eligibility policy, while active assessments bootstrap independently from incrementally loaded history;
- audit-witness failures retry the same immutable checkpoint through atomic leased claims, append-only digest-idempotent delivery attempts, bounded backoff, stale-claim recovery, and terminal operator escalation;
- scheduled maintenance domains are isolated, and poisoned key-rotation records use durable backoff, action-required signaling, and audited recovery;
- native provenance reconciliation uses a sparse due-work queue, two independent durable circular keyset cursors, and separate per-invocation budgets of at most 25 expired reservations and 25 due orphan entries, so poison rows cannot pin the scan or consume another domain's budget;
- CI enforces lint and TypeScript contracts, operational error reporting uses bounded classifications, and credential-shaped test fixtures are generated at runtime;
- managed collection and SBOM work is queued and polled instead of held inside a long browser request;
- the AWS promotion path requires exact-version DLP, signs the durable DLP and promotion facts with KMS, and reconciles the same facts across DynamoDB and PostgreSQL;
- AWS upload-lifecycle maintenance uses a protected tenant directory and additive base-PK V2 sparse index, independent per-tenant budgets, exact seven-day event grace plus buffered TTL, strict provider retry, digest-only malformed-row quarantine, and a durable repeatedly alarmed action ledger resolved only by exact terminal/recovery transactions;
- API Gateway OAuth scopes add an outer authorization layer while each Lambda still validates JWT, tenant host, membership, and role;
- native schema-8 evidence, tokens, S3 configuration, object prefixes, and trust anchors are bound to one tenant/workspace identity, and legacy hosted ingestion requires that signed pair to match the server's exact configured boundary;
- the loopback Local Console uses a one-time URL-fragment nonce exchanged for an in-memory bearer and creates no localhost authentication cookie;
- local capture, lifecycle, and hold state use crash-recoverable Keychain anchors/journals and separate signing domains; and
- expiry cleanup verifies the exact S3 versions, checksums, encryption, and COMPLIANCE retention live before treating a remote copy as durable.
- the signed macOS updater validates ZIP structure, expansion limits, file types, free space, and bounded release-command execution before accepting extraction output.
- legacy hosted APIs consume expected identity headers only on one explicit canonical origin and one acknowledged tenant boundary; the application does not cryptographically authenticate those headers, so production still requires deployed proof that an identity-aware private dispatcher overwrites caller-supplied variants and blocks every direct Worker/preview/origin path.

These are source controls. No AWS resources were created, changed, or deployed as part of this work. No live Cognito, API Gateway, Lambda, Aurora, DynamoDB, KMS, S3, DLP, Route 53, cross-region recovery, Apple signing, or notarization exercise is implied by a passing local test.

## Remediation matrix

| Area | Source status | Enforced behavior | Production evidence still required |
| --- | --- | --- | --- |
| Assessment scope | Implemented | An active assessment requires an explicit catalog, at least one named system, and at least one selected catalog control. Evidence, collection jobs, and SBOMs fail closed if that binding is absent or mismatched. | Approve the exact catalog content and licensed framework source; exercise create/edit/close behavior against a populated staging database. |
| Legacy hosted-header authentication | External production gate remains | Source restricts consumption of legacy platform header names to one exact configured HTTPS origin, requires the explicit single-tenant acknowledgement, and enforces active invitation-backed membership and RBAC. No cryptographically verifiable dispatcher assertion is implemented, and the source does not establish that a supporting private dispatcher is deployed. | Prove an authorized identity-aware dispatcher overwrites all caller identity-header variants, denies direct/preview/origin access, and passes forged/duplicate/mixed-case header and bootstrap tests. |
| Control catalogs | Implemented | The built-in catalog is explicitly identified as the limited **PCI DSS 4.0.1 Scopeproof operations catalog**, not the complete standard. Stored catalog metadata and canonical control JSON must match the source digest. | Install and approve any additional complete/licensed catalogs needed by the engagement. |
| Evidence review | Implemented | Review events are append-only records. Optimistic concurrency binds the event to the winning state transition; collectors/uploaders cannot review their own evidence. | Validate organization role assignments and test concurrent reviewer actions with representative users. |
| Findings | Implemented | Findings are persisted, assessment/control/evidence/job scoped, bounded, evented, and audited. Reviewers can maintain findings; only compliance leads and administrators can accept or close them. Closed is terminal. | Define the organization's severity, SLA, risk-acceptance, and reopening policy before production use. |
| Hosted hold release | Implemented | Release is a 24-hour, digest-bound request. A different administrator must approve the exact immutable hold facts; changing a hold cancels a pending request. | Confirm two named administrators, escalation coverage, and records/legal approval procedures. |
| Pagination and summaries | Implemented | Assessments, evidence, runs, SBOMs, findings, and packages use bounded opaque cursors with stable time/ID ordering. Active assessments load independently of the first history page; older assessment pages are user-requested and de-duplicated. Summary counts are database aggregates, not counts from the visible page. | Load-test maximum supported tenant data and verify UI continuation behavior and accessible focus states. |
| Package preflight | Implemented | Export is blocked for zero eligible evidence, unresolved partial coverage, pending independent screenshot safety, pending native provenance, or the 100-artifact limit. Preflight, selection, and the final audited publication fence use the latest occurrence state. Only an approved, current, fully eligible recollection for the same scoped collection dimensions can clear a partial blocker. Ambiguous publication responses preserve and authoritatively reconcile the candidate object. | Run representative packages and independently verify every manifest, signature, hash, exclusion, coverage result, concurrent insertion/review race, and lost-response recovery. |
| Audit checkpoint recovery | Implemented | Immutable checkpoint rows never change. A compare-and-swap retry record grants one two-minute outbound lease, applies one-minute-to-six-hour backoff, recovers stale claims, and stops after ten failed claims in `action_required`. Each claimed witness call appends a bounded failure or one unique delivered attempt, uses the checkpoint digest as its idempotency key, stores an exact signed receipt binding, preserves ambiguous candidates, cleans up only proven race-loser objects, and invalidates cached failures. | Operate and independently retain the witness/key; inject timeout/crash/race/tamper faults, alert on action-required state, and verify recovery at the unchanged or next audited head. |
| Maintenance and key rotation | Implemented | Failure in retention, collection, SBOM, scheduling, rotation, or checkpoint work cannot suppress later checkpoint/health attempts. Rotation failures are isolated per record, audited with allowlisted codes, exponentially backed off, escalated after five attempts, and marked resolved after recovery. | Connect the action-required events to paging/ticketing, repair poison records, and exercise retained-key retirement and recovery drills. |
| Native provenance reconciliation | Implemented | Migration `0028_native_reconciliation_cursor.sql` adds a sparse due-work queue and revision-CAS-protected independent pending/orphan circular keysets. Each scheduler invocation examines at most 25 expired reservations and, separately, at most 25 due queue entries. Exact finalization/release/quarantine and queue cleanup remain audited CAS operations; finalized, missing, and otherwise terminal entries are drained without reading or deleting R2 bytes. | Run populated and fresh migration replay, poison-row and cursor-wrap tests, separate-budget exhaustion, terminal queue cleanup, cursor-CAS race injection, backlog-age/count alarms, and deployed D1 failure/recovery drills. |
| CI and error hygiene | Implemented; independent-review gate remains | Pull requests run lint, TypeScript checking, builds/tests, migration replay, dependency checks, CodeQL, secret/IaC scanning, and native tests. Server logs use allowlisted error classes; tracked AWS credential-shaped fixtures are generated at runtime. On 2026-09-01, repository Actions were restricted to GitHub-owned actions plus the exact Aqua Security and pnpm action families, with immutable SHA pinning required; web commit signoff and safe branch updates were enabled. `verify`, `macos`, `dependency-review`, and all three advanced CodeQL jobs are strict, GitHub-Actions-bound required checks on `main`. The `production-release` environment permits protected branches only, requires an explicit owner approval, and disables administrator bypass. | Add a second trusted collaborator before setting required PR approvals or `prevent_self_review`; the repository currently has only its owner, so claiming independent approval would lock the workflow or be false. Configure commit-signing infrastructure before requiring signed commits. Verify no external log/APM/request-body collector reintroduces sensitive data. |
| Native updater extraction | Implemented in reviewed source | A signed ZIP is still treated as hostile. The download is copied once to a private same-volume pending archive used for validation, extraction, and publication; its regular-file identity, single-link state, exact size, and SHA-256 are checked around extraction and immediately before rollback-floor persistence and atomic rename. Central/local headers and strict data descriptors must agree, stored/raw-deflate bytes are streamed before extraction to prove actual size and CRC, local records may not overlap, and paths, types, entry counts, expansion, ratios, free space, extracted files, subprocess output, cancellation, and time are bounded. Publication independently verifies the canonical P-256 envelope signature and selected-key window. | Run the protected Developer ID/notarization workflow and clean-Mac malicious/corrupt/archive-bomb and staged-file mutation tests on the exact candidate. |
| Managed background work | Implemented | Managed collector and SBOM requests return `202` and run from durable queue state. One-time SBOM tokens remain request-bound and are never queued for later replay. | Operate scheduler/worker alarms, retry/DLQ procedures, and cost/abuse tests in staging. |
| AWS API authorization | Implemented in source | API Gateway Cognito scopes are route-specific and additive. Lambda handlers still validate RS256/JWKS, issuer, token use, app client, tenant host, active membership, and role. | Deploy only to disposable two-tenant staging first and run the full negative authorization matrix. |
| AWS exact-version DLP | Implemented in source | Production tenant synthesis requires a clean HTTPS scanner endpoint, KMS-encrypted token secret, and explicit policy version. Promotion submits the immutable quarantine bucket/key/version/digest/size/content type, validates a strict response, and fails closed unless it is `CLEAN`. | Approve the scanner's privacy, retention, region, availability, authentication, and efficacy; validate the exact-version contract live. |
| KMS-signed DLP/promotion receipts | Implemented in source | Canonical DLP facts and promotion facts are signed with the tenant RSA KMS audit key and verified before replay/reconciliation. Destination metadata and exact version must match those facts. | Run live KMS sign/verify, key-policy, rotation, disabled-key, replay, and tamper tests; retain verification evidence independently. |
| AWS reconciliation | Implemented in source | Promotion/retry paths compare DLP, S3 version, checksum, encryption, retention, audit, DynamoDB, and PostgreSQL facts and fail on mismatches rather than silently repairing from untrusted state. Rejected-ingest exact receipt replay is resolved before the age gate, and a missing relational receipt can recover for the configured 14-day SQS/DLQ horizon without relaxing canonical fact, revision, tenant, or future-skew validation. | Inject failures between every cross-service write, including a DynamoDB-first commit followed by delayed DLQ redrive, and prove bounded convergence, alarm delivery, and no cross-tenant writes. |
| AWS lifecycle maintenance | Implemented in source | A reserved-concurrency-one scheduled worker queries a protected tenant directory and additive base-PK V2 index without whole-table scans. Per-tenant lifecycle and action budgets isolate padding; issued rows remain recoverable for seven days and TTL follows by fifteen days; malformed rows are CAS-drained into a digest-only durable action ledger; only proven conditional losers are swallowed; and exact promotion/recovery/rejection resolves outstanding action state transactionally. Legacy GSI1 remains dual-written for staged rollback. The safe `maintenanceLifecycleMode=backfill` default disables both EventBridge and the SQS mapping while the separate bounded exact-CAS Lambda migrates one tenant/page at a time. | Use the documented two-deployment GSI procedure: complete every exact-cursor page with zero malformed/conflict rows, finish without a cursor, run a second full pass with zero upgrades and matching current/terminal counts, then separately deploy `maintenanceLifecycleMode=enabled`. Verify both triggers and run delayed-event, cross-tenant poison, ledger resolution, provider throttle, duplicate-delivery, alarm, DLQ, redrive, and rollback drills. No AWS deployment/backfill has been performed by this work. |
| Native tenant/workspace boundary | Implemented in source | New schema-8 native records carry signed, validated tenant/workspace identifiers. Local roots, capture-chain heads, tokens, S3 settings/credentials, S3 prefixes, lifecycle anchors, and legal-hold anchors are scoped to that binding. Legacy hosted ingestion additionally requires the signed pair to equal `LEGACY_TENANT_ID`/`LEGACY_WORKSPACE_ID`; schema-7 cannot be silently rebound into that boundary. The hosted verifier converts canonical variable-width ASN.1 DER scalars to fixed-width IEEE-P1363 and accepts required positive sign padding at every valid scalar width while rejecting non-canonical integer encodings. Switching binding stops the old console, rejects suspended old requests, cancels S3 work, closes the S3 browser, deletes Scopeproof's S3 Keychain items, and resets S3 configuration for the new identity. | Define the authoritative tenant/workspace assignment source, configure the exact pair, and manage endpoint enrollment/transfer and older-evidence recapture procedures. Run CryptoKit-to-Worker vectors for short/high-bit scalars and redundant or missing padding, negative, zero, over-width, invalid-length, and trailing encodings. |
| Local Console authentication | Implemented | A one-time nonce is placed in the URL fragment, which is not sent in the initial HTTP request. JavaScript exchanges it once through the `Scopeproof-Launch` authorization scheme, clears the fragment, and keeps the returned bearer in memory. Every protected request requires that bearer; no localhost auth cookie is set. | Test supported managed browsers, DNS rebinding, malicious origins/extensions, concurrent slow clients, idle timeout, restart, and tenant switching on production endpoints. |
| Native reviewer identity | Implemented | Trust-bearing lifecycle and local legal-hold changes require macOS local-user authentication and record the stable subject, authentication method, and authentication time. | Confirm the intended LocalAuthentication policy and shared-Mac prohibition through endpoint management. |
| Local rollback/crash resistance | Implemented | Capture commits use a tenant-bound Keychain journal and recover only a complete, validated image/manifest/lifecycle set. Capture, lifecycle, and hold heads are monotonic and tenant/workspace scoped; lifecycle and hold signatures use distinct key domains. Missing hold markers fail closed when a committed or pending head exists, and the hold scope is independent of the file path. Legacy signed holds are anchored on first verification. | Exercise power-loss and disk-full failure injection at each write/anchor boundary and confirm operational recovery messages. |
| Native file handling | Implemented | Trust-bearing flows use one bounded regular-file loader, reject links/unsafe containment, recheck digests, and keep unsigned legacy evidence browsing-only. | Run endpoint-specific filesystem, sync-client, backup, FileVault, malware, and EDR validation. |
| Local expiry with S3 copy | Implemented | A local `.s3.json` receipt is not enough. Before cleanup relies on S3, Scopeproof performs live exact-version `HEAD` and Object Lock retention checks for every receipt object and verifies version, checksum, ETag, KMS mode/key, account, prefix, and future COMPLIANCE retention. | Test IAM denial, KMS denial, deleted versions, changed retention, stale sessions, replica failure, and offline behavior. Local deletion must fail closed. |
| Release supply chain | Workflow present; live release not performed | Source includes manual Swift CodeQL and protected Developer ID/notarization workflow controls. | Build from the approved commit, review the workflow run, notarize/staple, verify provenance/attestation/checksums, and publish a new immutable release. The public DMG remains the version named in the release page until that happens. |

## Hosted product behavior

### Create an assessment with explicit scope

The hosted console exposes only reviewed catalogs returned by the catalog API. Select the catalog first, then select one or more controls from that exact version and enter one or more explicit systems. Drafts may be prepared incrementally; activation is rejected until the scope is non-empty and catalog-bound. A later scope reduction is audited separately from an ordinary edit.

The current built-in operations catalog intentionally covers a limited set of PCI DSS 4.0.1 controls used by Scopeproof workflows. It must not be described as the complete PCI DSS standard. Evidence may be collected only when its framework, catalog version, system, and control match the active assessment.

### Review evidence and manage findings

Evidence decisions are persisted as review events. Use separate collector/uploader and reviewer identities: the person who collected or uploaded an occurrence cannot approve it. If a concurrent reviewer has already changed the record, reload it rather than overwriting the newer decision.

Create a finding from the Findings view, bind it to the current assessment and—when applicable—to an in-scope control, evidence item, collection job, owner, severity, and reasonable due date. Reviewers can move ordinary work among Open, In progress, and Resolved states. Acceptance and closure are dispositions reserved for compliance leads and administrators and require a 20–4,000 character rationale. A closed finding cannot be reopened by the current state machine.

### Browse complete data sets

Evidence, collection runs, SBOMs, findings, assessments, and package history are paged. The API returns `page.total`, `page.hasMore`, and an opaque `page.nextCursor`; clients must use that cursor exactly and must not derive or edit it. The console loads the newest active-assessment page separately from recent history so an active workspace cannot be hidden by newer closed records, then exposes an explicit control for older pages. Dashboard and control counts come from server aggregates across the full filtered set, not just the current page.

### Export only after package preflight

The package endpoint returns a preflight for the selected assessment. Resolve every blocker before export. Scopeproof will not create a package when no artifact is eligible, unresolved coverage is partial, an exact screenshot lacks its independent server-safety binding, a native artifact lacks finalized provenance, or more than 100 artifacts would require silent truncation. Preflight and build execute the same latest-occurrence eligibility query; only a newer approved, unexpired, non-partial, fully eligible recollection for the same collection dimensions clears a historical partial blocker. A successful preflight remains advisory until the complete-assessment occurrence/publication fence commits. A lost database response is reconciled against the exact ready row before Scopeproof returns failure or deletes an R2 candidate.

## Native operation changes

### Tenant and workspace selection

The default local identity remains `local/default`. A configured customer/workspace uses:

```text
~/Documents/Scopeproof Evidence/tenants/<tenant>/workspaces/<workspace>/
```

The same normalized identifiers are written into current manifests and bind device tokens, manual S3 credentials, verified S3 destinations, S3 object prefixes, capture-chain anchors, lifecycle anchors, and legal-hold anchors. Do not reuse one customer's token, S3 session, or evidence root after switching identities. The app stops the previous loopback console, rejects any suspended request from it, cancels S3 setup/retry/browse work, closes the old browser, deletes Scopeproof's S3 credential/destination Keychain items, and resets S3 preferences to an empty configuration for the selected boundary. Configure and verify S3 again for the new tenant/workspace.

### Local Console session

Open the Local Console from the shield menu. The launch address contains a high-entropy nonce after `#token=`. Browser URL fragments are not included in HTTP requests; the bootstrap page consumes the nonce once, removes the fragment from history, exchanges it for a separate short-lived bearer, and keeps that bearer only in page memory. Closing/reopening or switching tenant/workspace rotates the session. Do not copy or share the launch URL.

### Authenticated local review and holds

Saving a trust-bearing review or changing a local legal hold invokes macOS local-user authentication. The event records the authenticated subject and uses a dedicated signing/rollback domain. Deleting a hold sidecar does not release it: a committed or pending immutable Keychain head makes the missing marker invalid and blocks retention. Moving the evidence does not change that scope, and a valid legacy signed marker is anchored before use. This is a local integrity control; it does not by itself prove organizational role membership and does not place or release an S3 Object Lock legal hold.

### Expiry cleanup with S3

Local cleanup moves eligible files to Trash; it does not delete hosted or S3 evidence. A local receipt alone no longer establishes a durable remote copy. When cleanup depends on S3, the app must have the matching current temporary AWS session and verified destination, then re-read the exact image and manifest versions plus each Object Lock retention record. Any unavailable, mismatched, expired, non-COMPLIANCE, or unverifiable object blocks local cleanup.

## AWS production prerequisites

The following are operational prerequisites, not unresolved product decisions:

1. Review every CDK context value and provide an owned deployment environment, tenant list, Route 53 mode, and recovery configuration. Example domains and identifiers are not deployable defaults.
2. For each production tenant, configure all exact-version DLP fields together: `dlpScannerEndpoint`, `dlpScannerSecretArn`, `dlpScannerSecretKmsKeyArn`, and `dlpPolicyVersion`. Use a dedicated KMS-encrypted secret and a clean pathful HTTPS scanner endpoint without user information, query, fragment, or non-default port.
3. Apply every D1 migration through `drizzle/0028_native_reconciliation_cursor.sql` before deploying the corresponding hosted application source. Run `npm run db:verify` against fresh and populated fixtures, and confirm the sparse queue, independent cursor state, revision-CAS, and terminal cleanup invariants.
4. Apply the packaged tenant PostgreSQL migration set only through the reviewed provisioner. Do not edit a historical migration in place on an existing database; use the repository's forward migration and require its exact attested marker before activation.
5. Configure distinct tenant KMS keys, S3 buckets/prefixes, Cognito clients/resource-server scopes, least-privilege database roles, alarm recipients, DLQs, CloudTrail, GuardDuty/DLP processing, legal-hold reconciliation, and recovery destinations.
6. Keep customer DNS disabled until the independent activation/readiness state is complete and the two-tenant negative authorization suite passes.
7. Run live exact-version upload, DLP rejection, promotion, replay, KMS receipt, PostgreSQL/DynamoDB reconciliation, legal hold, download, backup/restore, and cross-tenant denial tests with synthetic evidence.
8. Build the Mac release from the approved commit through the protected manual workflow. Verify Developer ID signature, hardened runtime, notarization ticket, staple, SBOM, provenance, attestation, checksums, and rollback-resistant update envelope before publishing it.

## Validation commands

Run these from the repository root before review:

```bash
npm run lint
npm run typecheck
npm test
npm run db:verify
npm run test:cloudformation
npm audit
npm audit --omit=dev

cd infra/aws/cdk
pnpm test

cd ../../../macos/ScopeproofCapture
/usr/bin/env DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test --arch arm64
```

Also synthesize the CDK with explicit non-production context and an empty tenant list before reviewing a deployable tenant context. A local synth verifies templates, not AWS permissions or runtime behavior.

## Release and deployment statement

- No AWS resource was deployed by this remediation work.
- No customer data was sent to AWS by this remediation work.
- No DNS name was created or changed by this remediation work.
- No Apple notarization submission or public DMG publication is part of these source changes.
- A local source build is not evidence that the public GitHub release contains these controls.
- Production authorization still requires the operational and live-validation evidence listed above and in the [AWS platform runbook](AWS_PLATFORM_RUNBOOK.md).
