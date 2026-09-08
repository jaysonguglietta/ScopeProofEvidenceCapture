# Scopeproof — Adversarial Security and Product Readiness Review

Review date: 2026-09-08. Reviewed local and GitHub main commit: f416d18d6692b5b94d251bca0fded358ee1936d8.

This is an investigation and recommendation deliverable, not an implementation or certification. No application code, customer evidence, credentials, GitHub issues/PRs, or AWS resources were changed. A temporary isolated local preview and synthetic tests were used. This report is the only intended tracked-file addition.

## 1. Executive Summary

Scopeproof has a serious evidence-security foundation, but it is not yet one complete, production-qualified, multi-customer product. Its three surfaces must not be conflated:

- The native Mac app offers substantial local capture, redaction, review, evidence browsing, S3 storage and export functionality.
- The existing Sites/Cloudflare console is a separate, explicitly single-tenant evidence-operations application.
- The AWS target contains extensive identity, tenant isolation, upload, audit, legal-hold and recovery infrastructure, but lacks a complete customer frontend and several onboarding/review/administration workflows.

The most important confirmed defects affect local workspace separation, retention/recoverability, assessment export scope, receipt trust, AWS database authorization and delayed upload repair. SBOM output has independently reproduced inventory/diff errors and an official-schema field mismatch. Hosted polling and review feedback also contain deterministic workflow errors.

No remote code execution, internet-accessible authentication bypass, or public cross-tenant exploit was demonstrated. That is not a clean bill of health: deployment-dependent identity trust remains unproven, privileged AWS provisioning has cross-tenant reach, and no live cloud adversarial or disaster-recovery exercise was performed.

Release recommendation:

- Do not qualify the current source for high-assurance multi-customer production.
- Do not use native local retention for a production evidence workflow until chain and decision-history recoverability are fixed and tested. Retention is an explicit, confirmed menu action, not scheduled automatic cleanup.
- Keep AWS customer activation gated on completed workflows and environment-bound isolation, recovery, DLP and incident-response evidence.
- Treat the public 1.8.1 preview as older software, not the reviewed 1.10.0/build-25 source.

GitHub read-only verification found no open issues and 17 open dependency PRs, #96–#112. Main still matches the reviewed commit. Issue closure is not proof that the implementation or operational gates passed. The latest published release remains the older [1.8.1 development preview](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/tag/v1.8.1-development-preview.1).

### Verification performed

| Check | Result | What it establishes |
|---|---|---|
| Root lint and TypeScript checks | Passed | Static quality/type checks for current source |
| Hosted build | Passed | Worker/UI builds; not deployment correctness |
| Root tests | 2 rendered-output tests + 331 tests passed | Mixed pure logic, mocks and source-contract checks; many are not end-to-end |
| Focused AWS review tests | 123 passed | 102 runtime/source-contract checks plus 21 CloudFormation/runtime-hardening checks; overlaps root coverage, not an additive unique-test total |
| Native Swift build/tests | Build passed; 100/104 tests passed | Four Keychain-dependent legal-hold tests failed with five issues; shipped-bundle cause unresolved |
| Synthetic hosted SBOM functions | Reproduced two errors | Nested npm-v1 component omitted; removing one installed version produced zero delta |
| Official CycloneDX schema comparison | Confirmed mismatch | Generator emits bom_ref; schema allows bom-ref and forbids extra component fields |
| Root dependency audit | Flagged fast-uri 3.1.5 | Four reviewed advisories; production-only audit also reports propagated ajv exposure |
| AWS pnpm dependency audit | Zero advisories reported | Point-in-time registry result, not assurance of absence |
| Isolated browser preview | HTTP 200; protected APIs 503 as expected without configuration | Fail-closed unavailable state, Help routing, desktop and 390px mobile shell |
| Live AWS/Jira/GitHub collection, signed Mac GUI, production ingress | Not exercised | No conclusion about their deployed effectiveness |

Native tests used Xcode with temporary scratch/module caches. Failures were concentrated in deleted/moved/pending legal holds and legacy hold-head migration, with Keychain status -50 and missing expected heads. They are a release-test problem requiring investigation, not proof of a shipped-app bypass.

### Evidence index

Paths and line references below are pinned to the reviewed commit. Later edits may move them.

| Ref | Primary source |
|---|---|
| E01 | [Product and release boundaries](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/README.md#L8) |
| E02 | [Legacy identity and permissions](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/lib/server/auth.ts#L36) |
| E03 | [Native workspace root layout](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/macos/ScopeproofCapture/Sources/ScopeproofCapture/Preferences.swift#L25) |
| E04 | [Native discovery, retention and chain verification](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/macos/ScopeproofCapture/Sources/ScopeproofCapture/CaptureHistory.swift#L68) |
| E05 | [Native console artifact lookup](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/macos/ScopeproofCapture/Sources/ScopeproofCapture/LocalConsoleServer.swift#L504) |
| E06 | [Native export validation](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/macos/ScopeproofCapture/Sources/ScopeproofCapture/ValidatedEvidenceArtifact.swift#L143) |
| E07 | [Native package chain gate](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/macos/ScopeproofCapture/Sources/ScopeproofCapture/AssessorPackageExporter.swift#L35) |
| E08 | [S3 upload object set](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/macos/ScopeproofCapture/Sources/ScopeproofCapture/S3StorageService.swift#L327) |
| E09 | [Hosted assessment narrowing](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/lib/server/assessments.ts#L156) |
| E10 | [Hosted package selection](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/lib/server/packages.ts#L122) |
| E11 | [Package eligibility predicates](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/lib/server/package-eligibility.ts#L53) |
| E12 | [Workspace polling/error state](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/app/evidence-console.tsx#L256) |
| E13 | [SBOM list/discovery quota](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/app/api/sboms/route.ts#L16) |
| E14 | [Cloudflare batching](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/lib/server/collectors.ts#L247) |
| E15 | [Hosted SBOM parsing, comparison, formats](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/lib/server/sbom.ts#L163) |
| E16 | [Approval API response](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/app/api/evidence/[id]/route.ts#L37) |
| E17 | [Review domain state transitions](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/lib/server/evidence.ts#L480) |
| E18 | [Evidence drawer and modal behavior](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/app/evidence-console.tsx#L921) |
| E19 | [AWS reader authorization migration](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/infra/aws/database/009_runtime_hardening.sql#L63) |
| E20 | [AWS upload device-proof freshness](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/infra/aws/database/001_tenant_schema.sql#L2383) |
| E21 | [AWS upload projection repair](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/infra/aws/cdk/runtime/repair-upload-projections/index.ts#L35) |
| E22 | [AWS provisioner permissions](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/infra/aws/cdk/lib/tenant-stack.ts#L1472) |
| E23 | [AWS JWT validation](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/lib/aws-runtime/http/jwt.ts#L289) |
| E24 | [AWS public route composition](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/lib/aws-runtime/http/lambda-api.ts#L94) |
| E25 | [AWS frontend infrastructure](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/infra/aws/cdk/lib/shared-platform-stack.ts#L803) |
| E26 | [CI security workflow](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/.github/workflows/security.yml#L1) |
| E27 | [CDK test discovery](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/infra/aws/cdk/package.json#L9) |
| E28 | [Native transfer retry selection](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/macos/ScopeproofCapture/Sources/ScopeproofCapture/AppDelegate.swift#L621) |
| E29 | [Native review canvas](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/macos/ScopeproofCapture/Sources/ScopeproofCapture/CaptureReviewController.swift#L174) |
| E30 | [Native hosted HTTP buffering](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/macos/ScopeproofCapture/Sources/ScopeproofCapture/BackendTrust.swift#L64) |
| E31 | [Native credential accessibility](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/macos/ScopeproofCapture/Sources/ScopeproofCapture/KeychainStore.swift#L62) |
| E32 | [Hosted finding ownership/events](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/lib/server/findings.ts#L61) |
| E33 | [Hosted scheduled assessment choice](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/lib/server/jobs.ts#L151) |
| E34 | [Hosted unavailable-state routing](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/app/evidence-console.tsx#L637) |
| E35 | [Current package overrides](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/package.json#L51) |
| E36 | [Native SBOM parsers](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/blob/f416d18d6692b5b94d251bca0fded358ee1936d8/macos/ScopeproofCapture/Sources/ScopeproofCapture/RepositorySBOMService.swift#L302) |

## 2. System Overview and Trust Boundaries

### Architecture

Native: AppKit menu bar → user-initiated ScreenCaptureKit capture → Vision OCR/manual review/final-pixel scan → signed PNG manifest and local lifecycle records → Documents evidence tree and rebuildable SQLite index. Optional S3, hosted synchronization, Jira handoff and one-time GitHub SBOM generation are separate flows. Keychain holds credentials, signing/trust anchors and rollback heads. A loopback HTTP console uses an expiring session capability; browser JavaScript does not receive AWS keys.

Legacy hosted: browser React console → Worker routes → role/permission checks → D1 domain records plus encrypted R2 evidence/packages. Collector jobs call exact configured providers; screenshots require an independent digest-bound safety receipt. Audit events, signing keys, timestamp services and independent checkpoint delivery support provenance.

AWS target: exact tenant hostname and Cognito access token → API Gateway/Lambda validation → registry and active membership → purpose-specific database/IAM roles. Upload intents bind devices, nonces and evidence metadata. Quarantine, scan results, exact S3 versions, KMS receipts, DynamoDB lifecycle records and Aurora metadata gate promotion. Separate legal-hold and recovery workers operate under narrower identities. Shared provisioning and database infrastructure remain more privileged than customer-facing roles.

### Assets and boundaries

| Boundary | Assets crossing it | Required invariant |
|---|---|---|
| Captured application → native scanner/reviewer | Pixels, URLs, possible secrets/regulated data | Persist/share only the exact reviewed and scanned final pixels |
| Filesystem/sync source → trusted local evidence | PNGs, manifests, reviews, holds, receipts | Verify signatures/digests AND expected active workspace |
| Local console session → native service | Artifact IDs, review commands, download requests | Loopback/session/origin controls plus object-level workspace authorization |
| Native → AWS/hosted/Jira | Evidence bytes, enrollment/session credentials, transfer receipts | Exact destination, short-lived authority, independent receiver-side checks |
| Browser/proxy → legacy Worker | Identity headers and user requests | Identity cannot be supplied by the external caller |
| Authenticated actor → domain records | Assessments, approvals, findings, holds, exports | Current role, independent review, current scope and optimistic concurrency |
| Customer runtime → cloud persistence | Tenant identity, metadata, S3 versions, keys | Tenant guard and least privilege independent of caller-supplied identifiers |
| Provisioning/control plane → all tenant resources | Administrator secrets and deployment authority | Explicit privileged boundary, narrow lifetime, independent audit |
| Operational database → assessor package | Evidence, selection claims, signatures | Completeness, scope and trust claims accurately describe the included bytes |
| Region/account → recovery copy | Immutable objects, keys, metadata, audit history | Restore all required state without losing tenant or provenance authority |

Reviewed assets also include GitHub/S3/Jira credentials, device tokens, package-signing keys, independent witness keys, customer labels and evidence retention decisions. A signed package proves integrity under a key; it does not by itself prove that the key belongs to a trusted organization, that a screenshot was truthful, or that all required controls were satisfied.

## 3. Threat Model

| Persona | Initial access | Realistic attack paths |
|---|---|---|
| Unauthenticated internet attacker | Public application endpoints | Header spoofing if ingress is misconfigured; malformed JWT/body/parser input; resource/cost abuse |
| Valid low-privilege member | Auditor/reviewer account | Object/assessment swaps, stale-state actions, unauthorized lifecycle transitions |
| Malicious collector or compromised Mac | Valid device/session and attacker-chosen bytes | False evidence, malicious manifests, replay, out-of-scope disclosure, forged adjacent receipt files |
| Compromised local browser session | Local console bearer | Reach evidence beyond the selected workspace if object authorization is missing |
| Malicious repository/provider | Lockfiles, archives, pagination/events | Inventory evasion, parser resource exhaustion, misleading completeness |
| Compromised provisioner/operator | Cloud execution/admin identity | Shared database access, persistence, tenant/membership/audit manipulation |
| Ordinary user under failure conditions | Legitimate workflow | Retention-induced loss, stale approvals, blocked repair, accidental wrong-scope packages |

Highest-value adversarial tests are not only malformed-input tests. They are valid-looking operations at boundary transitions: switching workspace, narrowing an assessment, deleting expired local copies, retrying after a lost commit response, revoking a session, and exporting while evidence changes.

## 4. Attack Surface Inventory

| Component | Entry points / attacker-controlled input | Existing controls reviewed | Review limitation |
|---|---|---|---|
| Legacy authentication | Identity headers, request origin, invitations | Exact single origin, explicit single-tenant acknowledgement, allowlisted bootstrap, active membership | External dispatcher not proven |
| Hosted mutation routes | JSON fields, IDs, origin, concurrent versions | Bound queries, RBAC, same-origin mutation proof, size/rate limits, audited CAS | Not every route exercised through authenticated browser |
| Evidence/files | PNG, structured text, metadata, sidecars | Strict PNG/digest/signature checks, redaction, bounded reads, path checks | Local workspace and receipt gaps remain |
| Collectors/network | URLs, pages, provider bodies | Host restrictions, redirect restrictions, budgets, coverage metadata | Live providers not exercised |
| SBOM | GitHub URL/ref/token, archive/lockfiles | Immutable commit, bounded archive, no repository execution, ephemeral one-time token | Parser completeness/schema defects |
| Export | Assessment ID, evidence state, receipts | Approval/freshness/scan/provenance gates, bounded ZIP, signed manifest | Scope and retained-history defects |
| Local console | Session bootstrap, bearer, IDs, browser commands | Loopback listener, short-lived session, index/audit controls | No full native HTTP journey this review |
| S3 | Bucket/prefix/KMS/role/versions | Verified destination, STS production profile, version/checksum/lock validation | No live policy simulation or storage drill |
| AWS identity/API | JWT/host/client/scopes/member/device proof | Signature and strict claim validation, exact tenant/client, per-purpose roles | Session revocation/SQL issue |
| AWS async processing | Duplicate/delayed events, leases, repair records | Idempotency, immutable lifecycle binding, quarantine and signed receipts | Repair freshness conflict |
| AWS legal holds/recovery | Evidence versions, approvals, replica state | Distinct request/approval, exact version, recovery contracts | Customer status UI and live recovery proof absent |
| Build/release | Dependencies, actions, signing identity, update metadata | Lockfiles, pinned action SHAs, audits, manual Swift analysis/release verification | Dependency advisory, omitted suite, old public binary |

Coverage was component-by-component across source, routes, schema, infrastructure, scripts, tests and documentation. Generated dependencies/assets were not exhaustively audited; no claim is made that every line or every hostile input was reviewed.

## 5. Prioritized Findings

Severity is application risk, not simply a dependency scanner label. “Confirmed source defect” is distinct from an observed end-to-end exploit. Product-only failures are additionally specified in section 15.

### SEC-01 — Per-tenant provisioning retains shared database-administrator authority

Severity: High. Confidence: High. Classification: confirmed privileged-boundary design gap; not a public API bypass.

Affected: E22 and provision-tenant/index.mjs around line 687. Each tenant provisioner can retrieve the shared administrator secret, decrypt it and execute SQL against the shared cluster. Normal runtime database separation/RLS cannot contain an administrator capable of changing those controls.

Scenario: compromise one provisioner execution role or Lambda, obtain administrative SQL authority, then access another tenant database or alter membership/schema ownership. Impact includes cross-tenant metadata disclosure, persistent database access and destruction/manipulation of authorization/audit records. This permission alone does not establish access to every tenant's S3 evidence key.

Fix/patch guidance: move cluster-admin operations to a separately approved, short-lived provisioning control plane. Remove shared-admin-secret grants from long-lived per-tenant functions. Give ordinary migrations only the exact tenant database authority needed. Account/cluster-per-tenant is a stronger optional boundary with a cost tradeoff.

Validation: tenant A's ordinary runtime/provisioner must fail to retrieve the cluster-admin secret or access B's database. Test privilege teardown and expired approval. Retain cloud audit evidence. CWE-250/CWE-269; broken access control. Delivery: PROD-16.

### SEC-02 — Authorized local retention breaks the chain and discards unarchived decision history

Severity: High for evidence availability/integrity. Confidence: High. Classification: confirmed source-level recovery defect, not a performed deletion test.

Affected: E04 lines 115–145 and 225–231, E07, E08. Cleanup moves expired PNGs, manifests, review/hold records and transfer sidecars to Trash after checking a locked remote copy. Chain verification requires the number of remaining signed manifests to equal the Keychain sequence. Package export requires that complete chain. S3 upload stores PNG and manifest, not the complete set of signed decision records cleanup removes.

Scenario: an ordinary operator successfully runs retention, then later exports. Missing historical manifests invalidate complete-chain verification. New captures can still advance the Keychain anchor; that does not repair the missing history or unblock package export. After Trash is emptied, restoring the S3 pair cannot reconstruct deleted review/hold history. Impact is blocked exports and potentially permanent loss of decision provenance; the initial Trash operation itself remains recoverable.

Fix/patch guidance: retain an authenticated append-only chain ledger or checkpoint independently of expirable payloads. Archive signed lifecycle/hold history before deleting it, and verify durability of every required record. Represent authorized disposal explicitly. Never “repair” this by allowing arbitrary chain gaps or resetting the anchor.

Validation: synthetic capture → approval → archive → retention → restart → new capture → export and replacement-Mac restore. Tampering/deleting an unauthorized link must still fail. Test partial cleanup and interrupted archive. CWE-664/CWE-703; integrity/recoverability. Delivery: PROD-02.

### SEC-03 — Default native workspace can discover and preview named-customer evidence

Severity: Medium. Confidence: High. Classification: confirmed source-level object-authorization defect.

Affected: E03–E05, LocalEvidenceIndex.swift:101 and EvidenceSearchController.swift:28. The default workspace root is the parent of named tenant/workspace directories. Recursive history discovery does not filter the manifest binding or exclude that subtree. Indexing accepts the discovered entries; console lookup checks ID and path containment, not the active expected binding. Artifact validation chooses the artifact's own trust anchor.

Scenario: after customer A/B captures, return to local/default. A default-console session can discover and request customer evidence. A compromised default-console tab gains broader access than its selected workspace suggests. Scope is one Mac/OS account, not remote cross-account compromise. The OS user already owns these files, but the application still promises narrower workspace handling.

Impact: accidental or malicious cross-workspace disclosure and mixed histories that fail export. Existing S3 binding checks mitigate simple wrong-destination uploads.

Fix: require expectedBinding in discovery, index, lookup, preview and mutations, and compare it to the signed manifest. Exclude tenant subtrees from legacy default discovery or migrate default to a sibling root with an explicit compatibility reader. UI filtering alone is insufficient.

Validation: default/A/B synthetic roots, swapped files, duplicate IDs, legacy manifests and an open console during workspace switching. Every read and mutation must reject another binding. CWE-862/CWE-863. Delivery: PROD-01.

### SEC-04 — Narrowed assessment exports can disclose evidence outside the declared scope

Severity: Medium. Confidence: High. Classification: confirmed source-level scope/integrity defect.

Affected: E09–E11. Active scope may be narrowed. Export selection/counts use assessment_id but not the current systems/controls. The signed package's assessment declaration uses the narrowed scope.

Scenario: collect/approve systems A and B; reduce scope to A; export. B can still be included in a package declaring A. Coverage can also count removed controls against the smaller denominator. This is not an authentication bypass: it is over-disclosure through an authorized export and inaccurate assessor scope.

Fix/patch guidance: either initially forbid narrowing once evidence exists, or implement versioned scope changes with impact preview and an authoritative scope predicate shared by counts, selection and publication fencing. Preserve history; do not silently delete excluded evidence. Apply the same rules to system/control coverage and period semantics.

Validation: narrow two systems/controls to one; assert excluded bytes never enter the ZIP, exclusion counts reconcile, coverage cannot exceed 100%, and a concurrent scope update prevents stale publication. CWE-200/CWE-840. Delivery: PROD-04.

### SEC-05 — Unsigned adjacent receipt files can suppress retries and enter signed exports

Severity: Medium. Confidence: High. Classification: confirmed trust/status gap; assessor impact depends on receipt interpretation.

Affected: CaptureHistory.swift:30–31, E28, E06; UploadService.swift:58 and JiraCloudService.swift:108. Uploaded/S3 status uses receipt-file existence. Retry skips such entries. Export includes bounded receipt bytes without verifying receipt authenticity and exact evidence/destination binding, then signs the containing package.

Scenario: a local process or synchronization source that can write adjacent files adds an empty or fabricated receipt. Normal retry no longer transfers the evidence; an arbitrary receipt may appear inside an otherwise valid signed package.

Impact: false transfer success, missing remote copies and misleading supporting records. A package signature does not make a forged server signature valid. Separate live S3 durability checks still protect the cleanup decision from this simple forgery.

Fix: explicit absent/pending/verified/invalid transfer states; verify expected schema, artifact digest, workspace, destination, operation and applicable signature against independently trusted keys. Invalid receipts require visible recovery. Label intentionally unverified attachments as such.

Validation: empty, malformed, wrong-artifact/tenant/destination and bad-signature receipts must neither suppress retry nor imply successful transfer. CWE-345. Delivery: PROD-03.

### SEC-06 — AWS SQL reader authorization fails open when membership is NULL

Severity: Medium. Confidence: High. Classification: confirmed database-boundary defect, mitigated by public handler checks.

Affected: E19. Missing/inactive membership leaves actor_role NULL. “IF actor_role NOT IN (...)” does not reject SQL NULL. The visibility predicate “actor_role <> 'auditor' OR approved-and-unexpired” can then be true for approved evidence.

Scenario: an actor with the execute-only evidence-read database identity invokes the procedure with a nonexistent/revoked principal. The procedure can return approved retained metadata, including storage coordinates, without active membership. Public HTTP handlers independently resolve membership and their audit-outbox path rechecks it before returning; no unauthenticated HTTP leak or successful public revocation race was demonstrated.

Patch guidance: a forward migration must reject “actor_role IS NULL OR actor_role NOT IN (...)”. Preserve the tenant guard and execute-only grants. Do not rely on modifying a migration already applied to deployed databases.

Validation: execute actual PostgreSQL tests for unknown, revoked, inactive, collector, auditor, reviewer and admin actors. Unauthorized calls must raise 42501. Source-regex tests are inadequate for three-valued SQL logic. CWE-863/CWE-754. Delivery: PROD-14.

### SEC-07 — Delayed AWS upload-projection recovery reuses an already-expired freshness proof

Severity: Medium. Confidence: High. Classification: confirmed source-level convergence/availability defect.

Affected: E20–E21; tenant-stack.ts:1878 schedules five-minute repairs. Fresh device-proof validation rejects signatures older than five minutes before exact existing-intent replay. Repair invokes that path using the original persisted proof. One projection exception also exits before the loop cursor is saved.

Scenario: Dynamo reservation succeeds, Aurora fails or loses a commit response, and retry occurs after six minutes. The legitimate immutable reservation can no longer converge through the fresh-issuance procedure. One poison record delays following work. Sustained attacker-driven denial of service was not demonstrated.

Impact: stranded captures, repeated failure costs and blocked repair progress.

Fix: separate fresh issuance from repair. Check exact committed replay before freshness rejection. For missing projections, use a repair-only procedure bound to the previously authorized immutable reservation and an explicit recovery horizon. Preserve digest/actor/device/nonce binding. Add per-record failure state/backoff and cursor progress.

Validation: failures before/after Aurora commit, six-minute and horizon-expired retries, changed payloads, actor revocation, and a poison row before a valid row. CWE-703/CWE-755. Delivery: PROD-14.

### SEC-08 — Cognito session revocation is not checked at the resource-server boundary

Severity: Medium. Confidence: High for source behavior; live gateway behavior unverified. Classification: bounded stolen-session exposure/design gap.

Affected: E23, membership.ts:195, tenant-stack.ts:87. JWT verification checks signatures, claims, lifetime and authentication age but has no revocation/session-version lookup. Web tokens last one hour; native tokens fifteen minutes. Active membership checks are useful but distinct from revoking one session.

Scenario: a stolen still-valid access token is replayed after Cognito session revocation while application membership remains active. Signature/expiry verification alone can continue accepting it. AWS documents this distinction in [Cognito token revocation](https://docs.aws.amazon.com/cognito/latest/developerguide/token-revocation.html).

Fix: define an explicit revocation SLA. Add actor/session security versions or token-family revocation checks tied to logout/compromise/admin actions. Shorter web token TTL reduces exposure but does not establish immediate revocation.

Validation: issue, revoke and replay tokens against every route; test membership revocation separately, including cache TTL and failure behavior. CWE-613; broken authentication/session management. Delivery: PROD-14.

### SEC-09 — SBOM inventory and comparison can overstate what was actually captured

Severity: Medium. Confidence: High. Classification: reproduced integrity defects plus confirmed native parser limitations.

Affected: E15/E36. Hosted legacy npm fallback reads top-level dependencies only. Comparison collapses ecosystem:name to one version. Successful generation marks coverage complete. Native parsers have related version/format limitations. Hosted CycloneDX uses bom_ref instead of bom-ref.

Reproduction: a synthetic npm-v1 lock with alpha and nested dependency yields one component rather than two. Comparing alpha@1 plus alpha@2 to alpha@2 reports zero additions/removals/changes. Generated component keys include bom_ref; the [official CycloneDX 1.6 schema](https://raw.githubusercontent.com/CycloneDX/specification/1.6/schema/bom-1.6.schema.json) forbids unrecognized component fields and defines bom-ref instead.

Scenario: a repository owner supplies a supported-looking legacy/mixed lockfile; nested dependencies are omitted, or a removed version disappears from the delta. An auditor receives an inaccurate or schema-invalid inventory. This does not bypass a vulnerability scanner: none was demonstrated in this feature.

Fix: support recognized lockfile versions completely or report partial/unsupported structures; compare full package/version identities; use the official field spelling and validate emitted documents against pinned schemas. Record parser versions and unresolved/skipped counts. Preserve the no-code-execution model.

Validation: ground-truth fixtures for nested, multi-version, modern/legacy and mixed manifests; generated CycloneDX/SPDX schema validation; explicit incomplete state. CWE-20/CWE-840. Delivery: PROD-07.

### SEC-10 — Installed fast-uri is affected by newly reported advisories

Severity: Medium for this application's currently demonstrated exposure; upstream advisory severity High. Confidence: High on installed version; Low on reachable application exploit.

Affected: E35, package-lock.json. npm ls resolves fast-uri 3.1.5 through react-server-dom-webpack → webpack → schema-utils → ajv. The override pins an affected version. Audits report four host-normalization/SSRF-related advisories; a production-only graph audit also flags propagated ajv exposure.

No reviewed outbound-request path was shown to use fast-uri with attacker-controlled URLs. Do not claim confirmed Scopeproof SSRF simply because the dependency graph includes it.

Fix: update the relevant override/lock to a compatible fixed version, at least 3.1.6 on this line, and review transitive reachability. Re-run both audits, build, schema validation and network-policy tests; do not bulk-force unrelated major upgrades. The [maintainer advisory](https://github.com/fastify/fast-uri/security/advisories/GHSA-f65p-4m7j-42xc) describes the patched 3.1.6 version.

Scenario/impact: if a reachable consumer normalizes untrusted network destinations with this library, policy and actual destination can disagree. Otherwise the immediate impact is vulnerable dependency inventory and failing release security checks. CWE-918/CWE-20, inherited conditionally. Delivery: PROD-17.

### SEC-11 — Legacy authentication depends on an external, unproven identity dispatcher

Severity: High conditional; administrator takeover is possible if the boundary is absent. Confidence: High in source dependency, Medium in deployment exploitability. Classification: unresolved deployment assumption, not a demonstrated current bypass.

Affected: E02 and Worker ingress. The application reads oai-authenticated-user identity headers after an exact request-origin check. Hostname equality does not authenticate the header values. The repository does not prove that every public/direct/preview ingress strips caller-supplied headers and injects authenticated identity.

Scenario: a reachable direct origin or forwarding proxy accepts attacker-supplied identity headers. The attacker impersonates an existing member or attempts allowlisted initial bootstrap. Impact can include evidence disclosure and administrator functions.

Fix: prove private ingress and overwrite behavior, or verify a signed issuer/audience/expiry-bound assertion in the application. Keep preview/direct origins closed. Do not use the legacy global D1/R2 schema for multiple customers; it is explicitly single-tenant, and subdomains do not change that.

Validation: direct/public/preview paths, duplicate/mixed-case headers, missing assertions, forged member IDs and bootstrap attempts. Perform only against an authorized staging environment. CWE-290/CWE-345. Delivery: PROD-17; AWS customer separation is PROD-15.

### SEC-12 — Some native hosted responses are bounded only after full buffering

Severity: Low. Confidence: High. Classification: defense-in-depth availability gap requiring a compromised/misbehaving approved server.

Affected: E30 and UpdateService.swift around line 929. BackendHTTP.data uses URLSession.data, buffering a complete response. Some callers check limits afterward; other hosted/Jira responses lack equivalent limits.

Scenario: an approved endpoint sends an oversized/chunked response, consuming memory before validation. Impact is Mac app resource exhaustion, not arbitrary remote origin access; HTTPS/origin and redirect checks mitigate who can trigger it.

Fix: streaming per-endpoint limits, bounded error bodies and explicit cancellation/deadlines. Keep archive download limits already present. Test Content-Length absent/false, chunked and decompressed over-limit bodies. CWE-400/CWE-770. Delivery: PROD-17.

### SEC-13 — Required CI commands omit a runtime-hardening test file

Severity: Low. Confidence: High. Classification: confirmed regression-prevention gap.

Affected: E26–E27 and infra/aws/cdk/test/runtime-hardening.test.mjs. The CDK test glob matches only test/*.test.ts. Root tests do not run this directory. The omitted file covers activation approval, migration/rejection wiring; its three tests passed when explicitly invoked during review.

Scenario/impact: a regression can pass documented CI without these security checks executing. This is not a runtime exploit.

Fix: explicitly include TypeScript and .mjs suites, and assert expected discovery in CI. Validation: in a disposable branch, make that suite fail and verify the required check fails; restore before any merge. CWE-693. Delivery: PROD-17.

## 6. Exploitation Chains or Combined-Risk Scenarios

1. Default-console session compromise → missing expected-workspace check → named-customer metadata/preview exposure. Existing OS-level ownership is not a substitute for the selected application workspace boundary.
2. Legitimate remote archive → operator-authorized local cleanup → missing chain links and unarchived decisions → inability to produce a defensible future package. No attacker is needed; an attacker benefits from the resulting evidentiary ambiguity.
3. Approved A/B evidence → narrowed scope A → assessment-ID-only package query → B disclosure inside an A-declared signed package. The signature authenticates an inaccurate scope declaration.
4. Fabricated adjacent receipt → retry suppressed → evidence never transferred → receipt incorporated into a signed local package. Live S3 durability validation prevents treating this alone as a successful retention bypass.
5. Provisioner compromise → shared database admin secret → tenant membership/schema manipulation → persistent cross-tenant metadata access. Same-account regional copies do not inherently contain account/admin compromise.
6. Dynamo-first upload commit → Aurora outage beyond proof freshness → repair rejection → unchanged cursor and repeated failure. This combines two recovery weaknesses, not a claim that arbitrary users can control Dynamo records.
7. Unsafe legacy ingress → forged identity → authorized application functions. Conditional on deployment; do not report it as a verified exposed endpoint.

## 7. Dependency and Configuration Risks

Root audits are no longer clean at this review date. Four advisories apply to fast-uri 3.1.5, including [IPv6 normalization](https://github.com/advisories/GHSA-f65p-4m7j-42xc), [IDN handling](https://github.com/advisories/GHSA-5jgf-p345-68v8), [repeated decoding](https://github.com/advisories/GHSA-fph4-wmhf-6fwf), and [scheme normalization](https://github.com/advisories/GHSA-jqff-g426-hqxp). Those are four advisories on one resolved component, not four established application exploits. AWS pnpm audit returned zero at the time checked. Native Package.swift declares no third-party Swift package dependencies; Apple frameworks/system SQLite still require OS patching.

Supply-chain strengths: action commit pinning, lockfiles, ignore-scripts installation, restricted workflow permissions, dependency review, security scans and release signature/archive verification. Gaps: SEC-10/13, a fixed old Node 22.13.0 CI baseline requiring patch-level review, beta vinext compatibility qualification, and absent proof that the currently published binary contains the reviewed fixes.

Configuration priorities:

- Preserve exact origin, tenant, role, bucket, prefix, account and KMS bindings.
- Keep Compatible-S3 long-lived credentials visibly lower assurance; production mode should retain its temporary-credential requirement.
- Native enrollment-token code uses AfterFirstUnlockThisDeviceOnly, while hosted-authentication documentation describes WhenUnlockedThisDeviceOnly. Resolve the intended lock-state policy and test it; do not inaccurately describe all Keychain items as identical.
- Production scanners, timestamp verifiers, independent witnesses and alarm destinations must be validated as operating services, including data handling and outages.
- Keep signing/notarization/release identity missing-state fail-closed. Filling placeholder values is not release qualification.
- Same-account cross-region backup is a regional-resilience mechanism, not protection against complete account/administrator compromise.
- Cloud cost controls and quotas should be tested under repeated scan/repair failures. No current cost estimate was computed in this review.

## 8. Secure Design Gaps

The main design weaknesses are gaps between individually strong controls:

- A valid signed manifest is accepted without proving it belongs to the active local workspace.
- A valid remote payload copy is treated as sufficient even when local decision history and chain continuity are also required.
- An audited scope change is not applied consistently to export selection.
- A signed package can contain an unverified transfer receipt.
- Fresh-issuance anti-replay rules conflict with delayed repair.
- Signature-valid Cognito tokens are not equivalent to unrevoked sessions.
- Separate tenant runtime roles coexist with shared long-lived administrative authority.
- Static tests can enforce the presence of a guard while missing SQL NULL semantics and normal-use polling interactions.

Independent approval, digest-bound safety checks, immutable exact-version storage, audit fences and no-execution SBOM collection are worth preserving. Do not weaken them to make currently blocked workflows appear successful.

## 9. Recommended Remediation Roadmap

Immediate local/hosted correctness work: PROD-01/02/03/04/06/07, plus the small fast-uri and omitted-test fixes in PROD-17. Add failing regression tests before changes, including real SQL where semantics matter.

Next operational usability: PROD-05/08/09/10/11/12/13. These complete existing workflows rather than adding unrelated modules.

Before any AWS customer activation: PROD-14/15/16/17, with environment-bound, two-tenant negative tests and explicit operational acceptance. Development can proceed without deployment; live validation requires separately authorized staging resources.

Do not close findings solely because documentation changes, a regex test passes, a PR merges, or an issue is administratively closed. Record source fix, regression test, release inclusion and applicable deployment proof separately.

## 10. Security Test Plan

| Test area | Required adversarial cases | Passing evidence |
|---|---|---|
| Identity | Missing/forged/duplicate proxy headers; wrong issuer/client/scope; expired/revoked token; inactive membership | Denial before data disclosure, exact actor audit, session-revocation SLA |
| Tenant/workspace | Default/A/B roots; swapped IDs/files/hosts/cursors/database roles; open session during switch | No cross-boundary list, preview, mutation or capability |
| SQL semantics | NULL/missing/revoked principal, wrong role, valid role matrix; migration replay | Real PostgreSQL 42501 and precise visibility, not just source matching |
| Evidence integrity | Changed pixels, malformed PNG, altered manifest/sidecars, partial chain, forged receipts | Invalid records remain non-trust-bearing; no false success |
| Review/concurrency | Self-approval, stale occurrence, reject/reopen/supersede, two reviewers, new evidence during export | One authoritative transition/event; conflict recovery |
| Scope/export | Narrow system/control/period; over-limit bytes/count; package interrupted after commit | Accurate selection and exclusions; no orphan deletion of committed package |
| Retention | Active/released/invalid hold; verified archive; partial deletion; replacement-device restore | Ledger/decisions recoverable, no silent chain reset |
| Upload repair | Lost response, six-minute delay, poison row, revocation, changed proof | Exact convergence within declared horizon and progress for other records |
| Outbound/parsing | Redirect host swap, private address, XML/JSON depth, archive ratio/path, response overflow | No credential forwarding, execution, traversal or unbounded buffering |
| SBOM | Ground-truth modern/legacy/mixed lockfiles, nested/multiple versions, official formats | Exact fixture inventory/delta; explicit incomplete/unsupported state |
| Release/operations | Missing signing identity, altered update, old version, scanner/witness outage, missed alarm | Fail closed, clear recovery, verified installed binary |
| Disaster recovery | Synthetic tenant restore, exact S3 versions/keys/holds, Aurora and ledger | Measured RPO/RTO and independently repeatable procedure |

No live attack against production or customer data is authorized by this report. Use synthetic fixtures, disposable databases and separately approved staging resources.

## 11. Security Open Questions and Assumptions

1. Is any legacy public/direct/preview ingress reachable without a verified identity dispatcher? Supply actual ingress configuration and staging test evidence.
2. Which deployment and binary are intended for the next release: local-only, one legacy workspace, or AWS customer service? Their gates differ.
3. Is local workspace separation expected to prevent accidental handling only, or to provide strong operator separation? Strong isolation may require separate OS accounts/devices.
4. What is the required retention/disposal policy and which signed records must survive payload expiration? Do not infer legal retention periods.
5. Is immediate session revocation required, and what maximum delay is acceptable?
6. Must recovery survive account-level compromise, or only regional failure?
7. Who independently trusts package-signing and witness keys, and how are key changes communicated to assessors?
8. Which scanner/TSA/witness operators receive evidence or metadata, under what data-residency and retention terms?
9. Are production notification subscriptions, escalation owners and restore drills evidenced?
10. What causes the four Keychain tests to fail on this machine? Reproduce in a signed isolated harness before treating it as environment-only.

These questions do not prevent fixing the confirmed code defects. They do prevent honestly declaring production assurance.

## 12. Product Review Executive Summary

### Product brief reconstructed from current source

Target users: evidence collectors and IT operators; compliance leads defining scope; independent reviewers; external assessors consuming packages; platform administrators supporting customers.

Core problem: collect and organize trustworthy control evidence, prevent unsafe disclosure, preserve provenance and deliver reviewable assessor material.

Primary workflows: setup → scope → capture/collect/SBOM → classify → independent review → findings/recollection → export or explicit Jira handoff; optional S3 archive/browse; operational recovery and eventual disposal.

Main views: native menu/settings/privacy review/Search/Local Console; hosted Overview, Controls, Evidence, SBOMs, Collection runs, Findings, Connections, Settings/Help; planned AWS customer identity/evidence/administration.

Key models: tenant/workspace, actor/membership/device, assessment/catalog/control/system, artifact and occurrence, review/finding, collection/SBOM job, upload intent/exact object version, lifecycle/hold, receipt/checkpoint/package.

Critical edge cases: no permissions/credentials, revoked identity, wrong workspace, expired evidence, missing chain records, partial collection, concurrent review/scope change, failed upload/scan, lost commit response, credential expiry, oversized export and incompatible lockfile formats.

Assumptions: preserve local-first/no-AWS-required use, do not deploy AWS, do not turn the legacy console into multi-tenancy by adding hostnames, and do not claim complete PCI compliance or complete runtime software inventory from limited evidence.

“Done” for the next useful version: a user can independently install, create a correctly scoped capture, inspect/redact it, review/correct it, archive/recover it if configured, and deliver a verifiable package without misleading status or manual database repair. AWS needs its own end-to-end qualification before customer use.

### Product judgment

The greatest opportunity is finishing evidence correctness and recovery, not adding billing, chat, AI scoring or more dashboards. Native capture is the strongest immediately usable product surface. Hosted operations have connected persistence and meaningful security logic but several incomplete interaction paths. AWS is an infrastructure foundation ahead of its product integration.

The visual shell is coherent, and the unavailable state deliberately avoids fake compliance data. However, first-run failure messages are not actionable enough, Help is gated behind a healthy backend, and approval/search/package-history workflows are less complete than the underlying APIs suggest.

## 13. Existing Feature Inventory

“Verified working” applies only to the specifically exercised behavior stated. “Implemented but unverified” means connected source exists. “Partial” includes missing or defective edges found in code. “Broken” is reserved here for an observed failure. “Not found” is bounded to reviewed source. No core capability was classified as Mocked; synthetic screenshot-style thumbnail decoration is not actual evidence content.

| Surface / capability | Status | Evidence / verification |
|---|---|---|
| Native first run/menu/settings | Implemented but unverified | AppDelegate; no signed GUI first-run test |
| Native capture/browser/URL/display | Implemented but unverified | ScreenCaptureKit pipeline; no live capture |
| Scrolling composition | Verified working — test scope | Existing composition tests passed |
| Final-pixel scanner/redaction rules | Verified working — test scope | Pattern tests passed; universal DLP efficacy not established |
| Native privacy review | Partial | Mouse-only fit canvas; E29 |
| Signed artifacts/lifecycle/package primitives | Verified working — test scope | Tests passed; retention interaction remains defective |
| Native workspace isolation | Partial — confirmed defect | E03–E05, SEC-03 |
| Native legal holds | Partial | Four Keychain integration tests failed; cause unproven |
| Native local retention/recovery | Partial — confirmed defect | E04/E07/E08, SEC-02 |
| Local index/session/audit primitives | Verified working — test scope | Existing tests passed; complete GUI/HTTP journey unverified |
| Local/S3 browse and exact download | Implemented but unverified | S3 service and console wired; no AWS call |
| S3 configuration/temporary credential contracts | Verified working — test scope | Existing provider/policy tests passed |
| Native hosted sync/Jira handoff | Implemented but unverified | Compiled origin/enrollment and hosted intermediary required |
| Native one-time SBOM export | Partial | Existing tests pass; parser limitations E36; no native review/package integration by design |
| Native interactive Cognito login | Partial | Future primitives, not integrated app workflow |
| Secure updater verification | Verified working — test scope | Signature/archive/rollback tests passed |
| Current notarized DMG/update installation | Partial | Current source unreleased; public preview older. AppDelegate.swift:1421 downloads/verifies and opens an archive; managed app replacement/relaunch is not implemented |
| Hosted unavailable state | Verified working — browser scope | APIs 503; data hidden; 1280px desktop/390px shell observed |
| Hosted Help during service failure | Broken — observed | Help breadcrumb changes but recovery content remains hidden; E34 |
| Hosted assessment/catalog setup | Partial | Create/select/close UI; draft edit/narrowing API not surfaced; limited catalog |
| Hosted evidence upload/review | Partial | Real artifact reads and independent approval; lifecycle UI/false success gaps |
| Hosted search/filter/navigation | Partial | Filter applies to loaded records; direct SBOM/control links incomplete |
| Hosted provider collectors | Partial | Connected implementations, no live provider validation; Cloudflare skip defect |
| Hosted jobs/scheduling | Partial | Durable jobs/retries exist; status recovery and explicit schedule scope incomplete |
| Hosted managed SBOM polling | Partial — confirmed defect | Discovery quota collides with polling; E12/E13 |
| Hosted npm-v1 parser/multi-version delta | Broken — synthetic reproduction | Expected two components got one; version removal gave zero delta |
| Hosted CycloneDX format | Broken — schema contradiction | Emitted bom_ref prohibited by official schema |
| Findings ownership/remediation | Partial | Backend ownership/events, limited UI |
| Signed hosted packages | Partial | Build/publish checks; scope mismatch, history/re-download UI absent |
| Hosted team/device/Jira setup | Implemented but unverified | Real API paths; invitation is authorization record, not email delivery |
| Hosted retention/readiness administration | Partial | API controls exist; mostly policy-only UI |
| AWS JWT/intent/download/hold logic | Verified working — mock/contract scope | Focused tests pass; SQL/live-cloud semantics not proven |
| AWS reader/reconciliation | Partial — confirmed defects | SEC-06/07 |
| AWS customer onboarding/frontend/review | Not found as complete workflow | E24/E25; models/adapters are not usable customer flows |
| AWS recovery/activation controls | Partial | Contract tests and templates exist; restore/cutover automation and audit-bucket replication are not implemented; no live drill/production acceptance. See infra/aws/cdk/README.md:162 |

## 14. User Journey Review

| Journey | Current path | Breakdown / impact | Recommendation |
|---|---|---|---|
| Download and first run | Older DMG or build current source; permission/settings prompts | Source and public binary differ; setup remains technical | PROD-17, clear release channel and clean-Mac test |
| Establish workspace/storage | Native local default or named workspace; optional S3 | Default root includes named customer descendants | PROD-01 |
| Create scope and start collection | Hosted free-text scope → immediately active assessment → run | No draft/compatibility preview; scheduled destination implicit | PROD-04/05 |
| Capture and inspect | Native capture → OCR → manual canvas → final scan | Tall composites hard to inspect; region editing mouse-only | PROD-12 |
| Repeat collection | Job queue, 4-second workspace polling | Managed SBOM quota can blank all domains; incomplete statuses | PROD-05 |
| Review/correct | Actual artifact drawer → approve/flag | Reject/return/reopen/supersede/history not exposed; false success | PROD-06 |
| Find older evidence | Load pages; loaded-record filters | Results depend on loaded subset; linked SBOM evidence may appear missing | PROD-08 |
| Assign remediation | Flag evidence/run → finding | No meaningful owner assignment/history in UI | PROD-09 |
| Archive and recover | S3 PNG/manifest upload → receipt → local cleanup | Unsigned status receipts; decision records not archived; chain gap | PROD-02/03 |
| Auditor handoff | Approved bounded ZIP/PDF/index, explicit Jira flow | Scope mismatch; no package history/partition workflow | PROD-04/10 |
| Failure recovery | Toast/reload or native retry counts | Help unavailable in outage; per-item failures obscure | PROD-03/05/11 |
| Hold/dispose/admin | Native holds; hosted API; AWS two-person primitives | Customer-visible hold approval/status workflow incomplete | PROD-11/15 |
| AWS customer onboarding | Infrastructure provisioning and narrow routes | No complete member/device/assessment/sign-in/review path | PROD-15 |
| Production release/recovery | Scripts/templates/checks | Tests and live gates incomplete; old public release | PROD-14/16/17 |

## 15. Prioritized Feature Backlog

Priorities: P0 release blocker for the affected advertised workflow; P1 essential before a serious pilot; P2 valuable usability/completeness; P3 exploratory. P0 does not mean every local-only user must wait for AWS development. Efforts are relative engineering scopes, not delivery commitments.

| ID | Deliverable | Classification | Priority | Effort |
|---|---|---|---|---|
| PROD-01 | Enforce native workspace isolation end to end | Production readiness | P0 local multi-workspace | Medium |
| PROD-02 | Preserve chain and decisions through retention/recovery | Production readiness | P0 retention | Large |
| PROD-03 | Verified receipts and actionable transfer recovery | Existing feature improvement | P1 | Medium/Large |
| PROD-04 | Consistent assessment scope from draft to export | Core workflow gap | P0 export correctness | Large |
| PROD-05 | Reliable collections, polling and job recovery | Existing feature improvement | P1 | Medium |
| PROD-06 | Complete and truthful review lifecycle | Core workflow gap | P1 | Medium |
| PROD-07 | Accurate, schema-valid, inspectable SBOMs | Existing feature improvement | P0 auditor SBOM output | Large |
| PROD-08 | Whole-library search and durable navigation | Existing feature improvement | P1 | Medium |
| PROD-09 | Owned remediation findings | Core workflow gap | P2 | Medium |
| PROD-10 | Package history, preflight and complete partitioning | Core workflow gap | P1/P2 | Medium/Large |
| PROD-11 | Actionable first-run, readiness and admin controls | Core workflow gap | P1 | Medium |
| PROD-12 | Accessible inspection and durable user feedback | Existing feature improvement | P1 privacy review | Medium |
| PROD-13 | Requirements-based control coverage | Existing feature improvement | P2 | Medium |
| PROD-14 | AWS authorization, session and repair correctness | Production readiness | P0 AWS | Large |
| PROD-15 | One complete AWS customer evidence workflow | Core workflow gap | P0 AWS launch | Extra Large |
| PROD-16 | Restrict privileged provisioning and prove recovery | Production readiness | P0 high-risk AWS | Large |
| PROD-17 | Release/dependency/integration qualification | Production readiness | P0 production release | Large |

### PROD-01 — Enforce native workspace isolation

Type: improve. Target: consultants/operators handling multiple customers. Evidence: confirmed gap, E03–E05/SEC-03. Confidence: High.

Flow/smallest complete scope: selecting a workspace creates an explicit expected binding passed through discovery, index, search, preview, reviews and exports. Default reads exclude named tenant subtrees. Reject moved or incorrectly bound files before display. Keep legacy reads explicit and safely scoped.

Exclude OS-account isolation and automatic migration of real customer files without approval. Affected: native preferences/history/index/console/Search/validation. Rules: expected binding must match signed identity; duplicate IDs cannot select a foreign record; existing console sessions must be invalidated or stay bound during a switch.

Acceptance: synthetic default/A/B trees produce disjoint lists; direct preview/review IDs reject another workspace; malformed/moved manifests show an actionable quarantine state; restart and switching do not leak stale indexed rows.

Benefit/metric: zero cross-workspace results in the regression matrix. Dependencies: agree on legacy binding interpretation before any path migration. Effort Medium: shared API signature changes plus fixtures. P0: direct customer-data handling boundary. Question: is stronger operator isolation required? Default assumption is application scoping on one OS account.

### PROD-02 — Preserve provenance through retention and restore

Type: complete. Target: evidence custodians/assessors. Evidence: confirmed gap, SEC-02. Confidence: High.

Flow/scope: archive payload plus required signed decisions → verify durable archive → append authorized-disposal record → remove eligible local payload → retain verifiable chain ledger → restore/verify on a replacement test device. Show exactly what is recoverable.

Exclude changing statutory retention policy or weakening signature/hold rules. Affected: history, provenance, lifecycle/hold stores, S3 archive format, exporter and recovery UI. Rules: active/invalid hold blocks disposal; missing remote record aborts; interrupted deletion is resumable; old archive pairs are explicitly incomplete for decision recovery.

Acceptance: full synthetic retention/restart/new-capture/export journey works; every decision survives restore; tampering still fails; partial archive or cleanup shows retryable state without an anchor reset.

Benefit/metric: 100% required-record recovery in fixtures; measured restore success. Dependency: PROD-01 binding model. Effort Large: versioned archival contract, chain evolution and migration safety. P0: otherwise normal operation can destroy exportability. Question: decide which metadata remains after payload disposal; no live deletion is needed to implement fixtures.

### PROD-03 — Verify transfers and expose per-artifact recovery

Type: improve. Target: native operators. Evidence: confirmed gap, SEC-05/E28. Confidence: High.

Flow/scope: queued → running → verified success or actionable failure. Validate hosted/Jira/S3 receipts against artifact/destination/workspace before changing status. Show per-item retry/cancel, credential expiry and last error; refresh temporary credentials during long batches.

Exclude a new cloud queue service or storing one-time repository tokens. Affected: receipt models, transfer services, history/status views, retry coordinator. Rules: file existence is not success; uncertain commits reconcile exact remote state; retries cannot silently duplicate a transfer or overwrite a different destination.

Acceptance: forged/empty receipts remain invalid and retryable; one failed item does not hide later outcomes; interrupted/restarted batches converge; expired credentials prompt safe reauthentication; exports label or reject unverified receipts.

Benefit/metric: false-success rate zero; reduced unresolved-transfer age. Dependencies: trust-key/receipt contract, PROD-01; archive coverage aligns with PROD-02. Effort Medium/Large: shared status model and three integrations. P1: necessary for trustworthy optional synchronization. Question: which existing receiver receipts have independently verifiable signatures?

### PROD-04 — Keep assessment scope consistent from draft to export

Type: complete. Target: compliance leads/reviewers. Evidence: confirmed gap, E09–E11/SEC-04. Confidence: High.

Flow/scope: save/edit draft using catalog and exact system selectors → preview source compatibility → activate → preview any narrowing impact → preserve scope history → export only the declared scope. Start with disallowing unsafe narrowing if a safe migration is not ready.

Exclude expanding the regulatory catalog or deleting historical evidence. Affected: assessment UI/API/model, collector compatibility, coverage queries, package counts/selection/publication. Rules: closed assessments immutable; active expansion requires new assessment; stale changes conflict; changed periods/systems/controls cannot silently relabel evidence.

Acceptance: A/B → A narrowing cannot export B; included/excluded counts reconcile; concurrent narrowing invalidates in-progress stale export; draft validation explains incompatible controls/systems; coverage never exceeds 100%.

Benefit/metric: scope-related package rejection and failed first collection. Dependencies: authoritative scope predicate and regression tests before UI. Effort Large: lifecycle plus selection consistency. P0 for export correctness; draft polish P1. Question: should excluded evidence remain visible as historical/out-of-scope? Recommended yes, visibly separated.

### PROD-05 — Make collection and workspace recovery reliable

Type: improve. Target: operators. Evidence: confirmed defects, E12–E14/E33. Confidence: High.

Flow/scope: explicitly bind source schedule to assessment → queue → accurate queued/running/retrying/completed/partial/failed states → inspect omissions/failure → retry safely. Separate job-status reads from repository discovery; only actual discovery uses its tight quota. Load domains independently and retain last-known data with freshness/error labels.

Exclude sockets and a state-library rewrite. Fix Cloudflare's offset/slice mismatch. Affected: collectors, jobs/schedule model, SBOM GET, console data loaders. Rules: honor Retry-After; keep quotas; fence late responses by assessment/request generation; observe active jobs beyond page one.

Acceptance: ten-minute managed job never blanks unrelated panels; 429/503 affects one domain; older-page work keeps polling; switch-assessment races cannot apply old results; 1/5/6/10/11/250 Cloudflare zones visited once; omissions remain fail-closed.

Benefit/metric: workspace error rate, collection completeness, recovery time. Dependencies: PROD-04 schedule binding, but polling/batch fixes can land first. Effort Medium. P1: ordinary usage triggers failures. Question: desired polling latency; default bounded backoff is adequate.

### PROD-06 — Complete evidence review and make outcomes truthful

Type: complete. Target: independent reviewers and collectors correcting evidence. Evidence: confirmed gaps, E16–E18. Confidence: High.

Flow/scope: inspect actual artifact and latest occurrence → choose server-authorized approve/reject/return/reopen/supersede → provide rationale → see authoritative result and immutable timeline. Invalid/no-op transitions return current state/conflict, not an approved success message.

Exclude bulk or AI approval. Affected: evidence route/domain, drawer, reviews endpoint, occurrence presentation. Rules: latest collector cannot approve their occurrence; replacement for supersession must be eligible; stale reviewer state must reload; double submission produces one event.

Acceptance: each valid transition is keyboard-operable and audited once; rejected evidence requires explicit reopen; changed:false never displays approval success; two concurrent reviewers see accurate results; partial/unscanned/provenance-incomplete evidence remains blocked.

Benefit/metric: review turnaround and false-success rate. Dependencies: PROD-05 reliable state; PROD-12 accessible primitive. Effort Medium because backend transitions already exist. P1: evidence review is a central workflow. Question: which rationale fields are mandatory? Default require them for negative/reopening decisions.

### PROD-07 — Make SBOM outputs accurate and inspectable

Type: improve. Target: operators/external auditors. Evidence: confirmed/reproduced gaps, SEC-09/E15/E36. Confidence: High.

Flow/scope: select supported immutable repository/ref → identify lockfile versions and coverage → generate schema-valid document → inspect components/warnings → compare selected baseline with exact version sets → export provenance-bound results. Share fixtures/contracts between hosted and native implementations.

Exclude repository code/package-manager execution, runtime inventory claims, CVE triage and native assessment integration unless separately selected. Affected: parsers, output builders, comparison model, SBOM UI/docs. Rules: unsupported recognized versions fail or visibly mark partial; skipped/unresolved components cannot be called complete; change details must preserve multiple versions and have pagination.

Acceptance: nested npm-v1 and multi-version fixtures match ground truth; modern/legacy formats are explicitly supported or rejected; CycloneDX/SPDX pass pinned official schemas; component and delta counts reconcile with downloadable detail; token never persists.

Benefit/metric: fixture recall, schema success and missed-delta rate. Dependencies: format support matrix; generation fixes precede inspector UI. Effort Large across two parsers/formats. P0 for auditor-ready SBOM claims. Question: which ecosystems matter first? Prioritize real supported customer repositories, not speculative breadth.

### PROD-08 — Search and navigate the whole library

Type: improve. Target: reviewers/assessors/operators. Evidence: confirmed gap, console.tsx:330/647/709 and evidence route GET. Confidence: High.

Flow/scope: search/filter server-side → query-specific cursor results/counts → open record by ID → retain assessment/view/filter in URL → return to the same result set. Control drilldown preserves its control; SBOM links fetch their evidence directly.

Exclude cross-tenant search/unbounded loading. Affected: console query state, evidence metadata-by-ID contract, pagination and aggregates. Rules: debounce/cancel stale requests; reset cursor on filters; stable timestamp/ID ordering; unauthorized ID remains unavailable without leakage.

Acceptance: find an artifact beyond 500 records without manual page loading; direct link survives reload; older SBOM artifact opens; tied timestamps cause no skips/duplicates; stale responses cannot cross assessments; empty/forbidden/error states differ appropriately.

Benefit/metric: evidence retrieval time and failed-search rate. Dependency: PROD-05 loader behavior. Effort Medium using existing API filtering. P1 at realistic library sizes. Question: exact sortable fields; expose only implemented sort semantics.

### PROD-09 — Make findings an owned remediation workflow

Type: complete. Target: compliance leads/remediation owners. Evidence: confirmed gap, E32 and console findings view. Confidence: High.

Flow/scope: create standalone or evidence/control/job-linked finding → assign active member and due date → owner works/resolves with evidence → privileged lead closes or accepts risk → review timeline. Provide Mine/overdue/severity/status filters and reassignment-needed state.

Exclude automatic Jira synchronization. Affected: finding UI/API, active-member selection, event read model. Rules: ordinary review maintenance separated from privileged disposition; suspended owners are visible, not silently removed; concurrent edits conflict; closed records remain historical.

Acceptance: assignment/edit/filter works beyond first page; unauthorized closure gets 403; resolution records supporting evidence; owner suspension creates clear action; failed save preserves input; stale edits reload with context.

Benefit/metric: unassigned/overdue findings and resolution time. Dependencies: PROD-08 retrieval and existing role matrix. Effort Medium, much persistence exists. P2: improves team handoff after correctness fixes. Question: required risk-acceptance rationale/expiry; do not invent organization policy.

### PROD-10 — Complete package delivery and history

Type: complete. Target: compliance leads/assessors. Evidence: confirmed gap, E10 and packages GET; console discards history rows. Confidence: High.

Flow/scope: preflight count AND bytes → resolve linked blockers → build/reconcile → view history/scope/hash/expiry → re-download authorized package. Add a bounded partition plan whose parts cover the intended selection when limits are exceeded.

Exclude public share links or relaxed approval/download access. Affected: package UI/API/model, preflight/build/selection. Rules: preserve requester/admin authorization, seven-day expiry semantics and no silent truncation; uncertain build response must discover the committed result, not force duplicate export.

Acceptance: over-25-MB selection fails before build; interruption allows history recovery; expired artifact explains rebuilding; forbidden download denied; partitions and exclusion reasons reconcile exactly to the scope; no mislabeled partial package.

Benefit/metric: export success, duplicate builds, time to assessor delivery. Dependencies: PROD-04 scope and PROD-06 review. Effort Medium/Large for durable build/partitioning. P1 preflight/recovery, P2 partition convenience. Question: actual package sizes; measure before increasing memory limits.

### PROD-11 — Provide usable first-run, readiness and administration

Type: complete. Target: new operators/admins. Evidence: confirmed source gaps plus browser-observed Help failure, E34. Confidence: High.

Flow/scope: always-available Help → checklist for identity, two roles, scope, source, canary, review and export → named readiness failures/runbooks → source enable/pause/schedule/retest → safe membership/device/hold administration. Display UTC and next-run preview.

Exclude browser storage of platform secrets or a force-healthy bypass. Affected: Help routing, Connections/Settings, readiness/collector/retention APIs, paged user/device/audit views. Rules: separate diagnostic visibility from secret values; confirmations for revocation; distinct admins for hold release; preserve denied access explanations.

Acceptance: Help works while APIs return 503; error state offers retry/status and safe instructions; invalid schedules rejected; source can be paused; device revoke confirms exact target; hold requester cannot self-release; pending/failed release is not shown as applied.

Benefit/metric: first-run completion and diagnosis time. Dependencies: PROD-05 robust loading and PROD-04 scope. Effort Medium. P1: users cannot reliably recover without it. Question: where configuration runbooks live; use repository docs until an approved operator portal exists.

### PROD-12 — Make inspection accessible and feedback durable

Type: improve/consolidate. Target: keyboard/screen-reader users and anyone reviewing tall screenshots. Evidence: confirmed source gaps, E18/E29; only empty-state responsive shell exercised. Confidence: High in code gaps, Medium in full visual impact.

Flow/scope: native fit/100%/zoom/pan with image-stable redaction regions and keyboard region editing; hosted shared dialog/drawer focus entry/trap/restoration; semantic tables/useful search labels; persistent field/action errors and differentiated success/error notices.

Exclude visual rebranding. Affected: native review canvas; hosted dialogs/drawer/forms/tables/toasts/CSS. Rules: closing an in-flight operation must not erase its outcome; actual artifact or neutral icon must replace misleading synthetic “CAPTURED” thumbnails; redactions remain irreversible after serialization.

Acceptance: long-composite privacy review at 100%; keyboard region add/edit/delete; pointer/keyboard transformations match pixels; full hosted workflow without mouse; focus restored; 320px/200%-zoom usable; failures never show a success checkmark.

Benefit/metric: task completion, accessibility defects, missed visible sensitive text in fixtures. Dependencies: PROD-06 shared review behavior. Effort Medium, incremental primitives not redesign. P1 for privacy inspection; remaining semantics P2. Question: supported assistive technologies; test VoiceOver on Mac first.

### PROD-13 — Replace binary “covered” claims with evidence requirements

Type: improve. Target: compliance leads/assessors. Evidence: confirmed presentation gap and product hypothesis on the desired model; Controls uses Unassigned ownership and presence-based coverage. Confidence: High on present behavior, Medium on proposed requirement granularity.

Flow/scope: define owner and minimum evidence expectations for each scoped control/system/period → show satisfied/missing/expired/partial/review-needed counts → drill to exact blockers. Initially rename binary metrics to “has approved evidence.”

Exclude full automated compliance scoring or a comprehensive PCI catalog. Affected: assessment/control requirement model, summary queries and Controls UI. Rules: evidence presence is not regulatory compliance; superseded/expired/partial records cannot satisfy current requirements; mappings need assessor validation.

Acceptance: two required systems with evidence for one never show fully satisfied; missing owner is actionable; summary agrees with current scope and library; requirement edits preserve historical versions and explain changes.

Benefit/metric: requirement completion and assessor-disputed coverage. Dependencies: PROD-04/06/08. Effort Medium for a deliberately small versioned model. P2: valuable once underlying data is truthful. Question: validate requirements with two actual reviewers before implementing broader scoring.

### PROD-14 — Close AWS authorization/session/reconciliation defects

Type: improve. Target: platform operators/customer security admins. Evidence: confirmed gaps, SEC-06/07/08. Confidence: High.

Flow/scope: forward SQL NULL fix → real database role matrix → session-security version/revocation policy → dedicated immutable-reservation repair with bounded poison-row recovery → actionable repair status. Separate fresh issuance authority from repair authority.

Exclude relaxing freshness globally or deploying to AWS during source work. Affected: SQL migrations, JWT/member authorization, Dynamo/Aurora projection adapters and repair Lambda. Rules: exact actor/device/proof equality; expired/revoked authority policy explicitly defined; retries cannot mint new capabilities.

Acceptance: unauthorized SQL actors raise 42501; revoked sessions fail within declared SLA; six-minute lost-response retries converge; changed reservations fail; poison rows back off while later valid work completes; repair horizon expiry is visible.

Benefit/metric: unauthorized-read matrix zero, repair success/age, revocation latency. Dependencies: session policy and real disposable PostgreSQL harness; no production credentials needed for local work. Effort Large across security semantics and cross-store failure handling. P0 AWS activation. Question: choose revocation and repair horizon before finalizing contracts.

### PROD-15 — Ship one complete AWS customer workflow

Type: add/complete. Target: customer admins, collectors and reviewers. Evidence: confirmed missing workflow, E24/E25. Confidence: High.

Flow/smallest complete scope: customer sign-in/callback → invite/activate first independent roles → enroll/revoke device → create scoped assessment → submit capture → show scan/upload state → independent review → authorized list/download. Add evidence-ID-based legal-hold request, independent approval and applied/failed status; resolve storage coordinates server-side.

Exclude porting every legacy integration, billing, domains beyond configuration, and wiring legacy D1/R2 pages to tenant hostnames. Affected: AWS frontend artifact, public APIs, membership/device/assessment/review models, audit, Amplify source connection. Rules: exact tenant/client binding at every step; no hand-edited SQL required; revoked actors/devices blocked; storage keys never supplied as authority by the UI.

Acceptance: two synthetic tenants independently finish onboarding/capture/review/download; every swapped identifier/host is denied; self-approval and self hold-release denied; scanner outage remains recoverable; mobile/keyboard flow tested.

Benefit/metric: first approved evidence time and customer workflow completion. Dependencies: PROD-14, PROD-16/17 gates. Effort Extra Large: several missing vertical slices, not a frontend toggle. P0 AWS launch only. Question: choose the narrow first customer cohort; local-only delivery can continue independently.

### PROD-16 — Reduce privileged AWS reach and prove recovery

Type: improve. Target: platform/security operators. Evidence: confirmed privilege gap SEC-01; live recovery proof absent. Confidence: High on permission scope, Medium on desired account topology.

Flow/scope: explicit short-lived provisioning approval → tenant-scoped normal operation → immutable privileged-action evidence → synthetic regional restore with exact-version/hold/key/database verification → recorded RPO/RTO and handoff. Remove persistent shared-admin authority from per-tenant functions. Implement the missing operator-driven restore/cutover tooling and define audit-history recovery; current recovery templates do not implement restore/cutover automation or audit-bucket replication.

Exclude automatic production cutover and choosing a new cross-account organization without approval. Affected: provisioning IAM/runtime, recovery runbooks/harness, CloudTrail/audit and release evidence. Rules: restore never silently changes tenant ownership or promotes unverified artifacts; operations keys separate from customer runtime; decommission temporary authority.

Acceptance: tenant A role cannot administer B; revoked provisioning authority cannot be reused; independent operator restores a synthetic tenant and verifies complete history; failed alarm delivery/backup blocks acceptance; limits of same-account recovery stated.

Benefit/metric: privileged exposure lifetime, isolation test results, measured RPO/RTO. Dependencies: approved operator/backup ownership; staging authorization for live drill. Effort Large. P0 for high-risk AWS production, not local use. Question: account-compromise resilience requirement determines whether cross-account backup is mandatory.

### PROD-17 — Qualify source, dependencies and released binaries together

Type: complete. Target: maintainers/operators/new users. Evidence: confirmed advisory/test/release gaps, SEC-10/11/12/13 and current GitHub release. Confidence: High.

Flow/scope: fix fast-uri pin → include omitted suite → real SQL and isolated signed-Keychain tests → bounded native response tests and explicit Keychain policy → verified staging ingress/scanner/witness/alarms → signed/notarized clean-Mac build/install/update → publish commit-bound release evidence and accurate docs/download links.

Exclude automatic merging of dependency PRs, deployment, signing-secret acquisition or release publication during this review. Affected: CI/package locks/test harnesses/native HTTP/release scripts/docs. Rules: no “all clear” with failed tests or waived external gates; preserve dev/production channel distinction; audit report tied to exact source and artifact hash.

Acceptance: both dependency graphs pass policy; intentionally failing omitted suite fails CI; four native failures explained/fixed and suite green in supported signed environment; fresh Mac installs reviewed version; tampered update denied; direct legacy origin cannot accept forged identity; no secrets in logs/artifacts.

Benefit/metric: release lead time, failed installs, escaped regressions and exact source/artifact traceability. Dependencies: preceding P0 fixes; external identities/authorized staging only for their tests. Effort Large, partly external lead time. P0 production distribution. Question: who owns Apple identity, ingress and operational sign-off? Record owners rather than silently waiving gates.

## 16. Features to Simplify, Consolidate, or Remove

- Consolidate native/hosted SBOM format contracts and fixture corpus. Two independent parsers should not silently disagree. Keep native one-time export separate from hosted assessment workflows unless deliberate parity is required.
- Replace source “Configure/Inspect” controls that only show transient instructions with real panels or plainly labeled documentation links. A toast is not a configuration workflow.
- Replace synthetic screenshot-looking thumbnails with actual safely generated thumbnails or neutral type icons.
- Rename “Fully covered” to “has approved evidence” until requirements-based coverage exists. Never equate evidence count with compliance.
- Present one selected operating mode at first run: local-only, local+S3, authorized legacy sync, or future AWS customer service. Do not expose unsupported sign-in as if it were ready.
- Keep advanced replication/Object Lock/KMS options under a readable advanced section with explicit prerequisites, preserving secure defaults.
- Consolidate review state and allowed actions into server-authoritative responses rather than duplicating eligibility logic in UI.
- Do not remove older read-only evidence compatibility casually; label its trust limits and provide a migration/recovery procedure.
- Do not add billing, chat, generalized AI risk scoring, additional frameworks or automatic Jira synchronization until the existing collection/review/handoff paths are complete.

## 17. Recommended Delivery Sequence

| Batch | Scope | Exit criteria |
|---|---|---|
| A — Reproduce and protect | Tests for PROD-01/02/04/07/14; small dependency/test-discovery fixes | Failures demonstrate defects; current baseline retained |
| B — Local evidence safety | PROD-01/02/03 plus native response/Keychain tests | Workspace isolation and full retention/restore/export path |
| C — Honest hosted workflow | PROD-04/05/06/07 | Correct scope, complete collection, truthful review, valid SBOM |
| D — Review and handoff usability | PROD-08/09/10/11/12; initial coverage relabeling | Search/recovery/assignment/export usable without developer help |
| E — AWS narrow vertical slice | PROD-14/15/16 source work | Complete local/stubbed workflow and actual SQL semantics |
| F — Production qualification | PROD-17, live authorized staging and restore tests | Exact artifact, identity, isolation, DLP, alarms and recovery evidence |
| G — Evidence requirement depth | PROD-13 | Reviewer-validated requirements model; no compliance overclaim |

Use small PRs with one independently verifiable invariant each. Recommended closure record: finding/backlog ID, regression test, implementation commit, released artifact hash, environment-specific validation and remaining assumptions. No PRs/issues were created by this review.

## 18. Product Validation and Acceptance Test Plan

### Test environments and data

Use synthetic tenants A/B and local/default, two independent reviewers, revoked and suspended members, a scoped assessment with two systems/controls, long screenshots containing synthetic secret patterns, versioned lockfile fixtures, partial collector pages, expired/held artifacts and a package above current limits. Never use customer tokens or real sensitive screenshots for fixtures.

Local review preview used nonpersistent storage, no remote bindings and no inspector, bound to 127.0.0.1. It was stopped and the temporary browser tab closed after testing. No authenticated production browsing was attempted.

### Journey matrix

| Journey | Required observable acceptance |
|---|---|
| Fresh local install | Correct released version, permission recovery, local capture without AWS requirement, obvious evidence location |
| Workspace/storage setup | Current mode/binding visible; invalid KMS/role/region produces exact field-level recovery; no saved secret displayed |
| First hosted collection | Draft scope, compatible source and explicit destination; successful or clearly partial artifact, never invented data |
| Long privacy review | Zoom/pan/read every region; keyboard redaction; saved pixels and final scan match review |
| Review correction | Return/reject/reopen/supersede/history; accurate conflicts; independent approval |
| Repeated work | Ten-minute polling, paging, stale request fencing, retry-after; no unrelated blank panels |
| Find and assign | Whole-library search, direct older artifact link, owner/due date and historical remediation |
| Archive and restore | Exact durable bytes plus decisions; restart/replacement-device integrity and package export |
| Assessor delivery | Valid formats, true scope, preflight, history/re-download, package verification with trusted key |
| Admin/recovery | Help available in outage, safe revoke, exact independent hold release, actionable maintenance status |
| AWS first tenant | No manual SQL onboarding, complete capture→review→download and negative tenant tests |
| Responsive/accessibility | 320/390/768/1280 widths and 200% zoom; VoiceOver/keyboard; actual populated tables and dialogs |

### Measurable pilot criteria

Use targets as proposed acceptance gates, not measured current performance:

- Zero wrong-workspace results and unauthorized transitions in the full negative matrix.
- Zero false success messages in induced 409/429/503/lost-response scenarios.
- All supported SBOM ground-truth fixtures match and all emitted documents validate.
- Every required retained record survives the synthetic restore drill.
- A new operator completes local first capture and package handoff from documentation without developer intervention.
- One-hour representative job/transfer run recovers from credential expiration and individual failures.
- Search finds known older records without preloading the library.
- No P0 defect, unexplained required-test failure or unvalidated applicable deployment gate is reported as closed.

### Current limitations of product verification

The hosted browser's unavailable state and mobile navigation shell were observed. At 390px the settled page width was 390px; no persistent horizontal overflow was detected in that state. Populated tables, authenticated dialogs, native GUI permissions, VoiceOver, complete capture and live integrations were not tested, so responsive/accessibility readiness is not certified.

Synthetic SBOM tests invoked extracted current pure functions, not the complete API/GitHub path. SQL defects were reasoned from actual PostgreSQL semantics, but no local PostgreSQL executable was available in the agent's environment. Build/source tests passing do not supersede these missing integration checks.

## 19. Product Open Questions and Assumptions

Questions for later validation, not blockers to correcting confirmed bugs:

1. Which first customer/workflow defines the next release: solo local evidence collection, one hosted team, or multiple AWS customers?
2. How many artifacts, customers/workspaces, daily captures and typical package bytes should the pilot support?
3. Which lockfile versions/ecosystems actually appear in repositories provided to auditors?
4. What do assessors require beyond a component list: dependency graph, licenses, hashes, deployed inventory, trusted signing identity or vulnerability assessment?
5. Who owns control requirements, catalogs and cross-framework mapping approval?
6. Must one Mac operator manage several customers, and is switching enough or is stronger OS/account separation needed?
7. What remediation/hold/release responsibilities and retention policy apply?
8. Is Jira handoff sufficient, or is synchronized finding ownership a validated need?
9. What signing/notarization, staging identity and operational owners are available for release qualification?
10. What latency/RPO/RTO/revocation expectations are contractual rather than preferences?

Assumptions: no new AWS deployment, no automatic customer-data migration, no credential collection, no regulatory certification claim, and no generic SaaS expansion during this work. Existing local-first operation and no-execution repository scanning remain deliberate product decisions.

### Five highest-value next actions

1. **PROD-01 — Fix native workspace isolation.** Directly protects customer separation in the currently useful local app.
2. **PROD-02 — Fix retention and provenance recovery.** Prevents ordinary cleanup from destroying future exportability or signed decision history.
3. **PROD-04 — Enforce export scope consistently.** Prevents over-disclosure and misleading signed assessor packages.
4. **PROD-07 — Correct SBOM inventory, delta and schema output.** Restores the accuracy of a specifically requested auditor deliverable; failures are reproducible now.
5. **PROD-17 — Establish a truthful release qualification gate.** Addresses the current dependency advisory, omitted tests, unresolved native failures and old public binary; completes after the source fixes, not instead of them.
# Implementation follow-up

This report preserves the pre-remediation review snapshot. For current source
status, read the [17-item/13-finding ledger](READINESS_IMPLEMENTATION_STATUS.md),
[validation results](READINESS_VALIDATION_2026-09-08.md), and
[publication/local-update record](PUBLICATION_AND_LOCAL_UPDATE_2026-09-08.md).
Do not interpret historical feature gaps as current code status or source
remediation as proof of production qualification.
