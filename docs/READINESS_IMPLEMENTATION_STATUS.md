# Product and security remediation status — September 8

Tracks all 17 product items and 13 security findings from
[the review](SECURITY_AND_PRODUCT_REVIEW_2026-09-08.md). This is a development
implementation ledger, not production certification or evidence that public
GitHub issues have been closed. The initial source-validation pass performed no
AWS deployment, Git push, published release, real evidence disposal or Mac
installation. The separately requested follow-up publication/local update is
recorded in the [publication handoff](PUBLICATION_AND_LOCAL_UPDATE_2026-09-08.md);
it does not waive any remaining source or qualification gate below.

## Product brief and delivery boundary

Users are evidence collectors, independent reviewers, compliance leads,
customer administrators and platform/recovery operators. The core workflow is
scope → collect/capture → inspect → independently review → remediate → hand off
approved evidence, with optional storage and deliberate recovery.

Views include the native Local Console/capture review/search/transfer recovery,
hosted assessment/collection/evidence/findings/packages/requirements/settings,
a separate AWS customer portal, and non-customer recovery CLIs. Key models are
workspace-bound signed artifacts, immutable occurrences and decisions, explicit
assessment scope, requirement revisions, exact receipt identities, finding proof
snapshots, tenant memberships/devices, upload reservations and approved recovery
plans. Concurrency, stale approval, partial transfer, held data, broken history,
untrusted input and A/B isolation fail closed.

Defaults preserve local-first use and customer evidence, do not invent trust or
compliance status, and use append-only migrations. “Source implemented” means
code and local synthetic tests exist. “Qualified” additionally requires relevant
live-service, signed-app and human workflow acceptance. These are not synonyms.

## Product backlog

| Item | Implemented source | Remaining acceptance or scope limit |
| --- | --- | --- |
| PROD-01 workspace isolation | Expected binding on native discovery, index, preview, review and export; default excludes named tenants; Search/console invalidation | Signed-app workspace-switch/VoiceOver qualification; no OS-user isolation claim |
| PROD-02 provenance-safe retention | Full signed-history archive, exact-version durability checks, PNG-only Trash, metadata/anchor preservation and staged same-Mac restore | **Partial:** replacement-Mac trust recovery remains unsupported; old already-lost decision prefixes cannot be reconstructed; live S3 recovery drill required |
| PROD-03 transfer recovery | Artifact/destination-bound device-sealed response envelopes, forged/legacy rejection, bounded per-item recovery UI, cancel/uncertain outcome handling | No independent provider-signature claim; signed-Keychain and real interrupted-transfer qualification required |
| PROD-04 assessment scope | Draft editing/lifecycle, exact catalog/system scope, saved-source compatibility preview, immutable scope after evidence, shared export predicate/CAS | Human pilot and authenticated concurrent browser workflow; preview is not connectivity verification |
| PROD-05 collection recovery | Independent domain loads, explicit discovery, backoff, older-page job watches, Cloudflare pagination and explicit assessment-bound schedules | Real provider/ten-minute job qualification; minutes restricted to deployed quarter-hour ticks, no arbitrary cron/catch-up claim |
| PROD-06 review lifecycle | Actual-byte inspection, server-authorized actions/history, independent latest-creator check, conflict/no-op truthfulness and supersession | Full authenticated keyboard/concurrent-review journey |
| PROD-07 SBOM correctness | Nested npm v1/2/3, multi-version deltas, honest partial formats, official pinned schemas, native/hosted fixtures and inventory/detail download | Assessor ground-truth pilots; no universal parser completeness, CVE or runtime inventory claim |
| PROD-08 whole-library navigation | Server filters/search, exact metadata-by-ID, URL assessment/view/filter/evidence restoration, explicit paging | Large authenticated library/200%-zoom pilot; no cross-tenant search |
| PROD-09 owned findings | Active-owner/due/status/Mine/overdue/reassignment filters, immutable history, 1–10 approved exact-occurrence resolution proofs and closure revalidation | Human remediation/closure pilot; risk acceptance is not resolution; no automatic Jira sync |
| PROD-10 package delivery | History/expiry/requester authorization, shared count/byte/scope preflight, digest-bound bounded partitions and full-plan publication fences | Real assessor multi-part delivery/error/expiry pilot; 1,000 snapshot/100 per-part/25 MiB bounds remain |
| PROD-11 administration | Backend-independent Help, readiness/runbook guidance, collector pause/schedule, device confirmation, hosted hold panel and AWS membership/hold controls | Live canary, external alarms/scanners and two-admin exercise |
| PROD-12 accessible inspection | Native fit/100%/zoom/keyboard region editing, shared web focus/inertness, neutral previews and persistent errors | **Partial qualification:** full VoiceOver, keyboard-only authenticated workflow, 320px/200%-zoom tests remain |
| PROD-13 evidence requirements | Append-only per-control/system owner/minimum revisions, current eligibility, separate missing/expired/partial/review counts and scoped drilldown | Two-reviewer requirements pilot; never a regulatory compliance score |
| PROD-14 AWS correctness | SQL NULL guards, auth_time/session-epoch revocation, immutable ingest-only delayed repair, horizon/backoff/poison isolation; real PostgreSQL tests | Live Cognito/Data API/Dynamo/S3 failure and revocation exercises |
| PROD-15 AWS customer workflow | Separate static Cognito portal, real invitation/member/device/assessment/review/hold APIs, native approved-tenant PKCE enrollment, intent/PNG upload and authoritative scan/review status | Narrow customer workflow source; live two-tenant end-to-end qualification required. Ambiguous uploads are status-checked, not autonomously reissued. No billing, self-service tenant creation or AWS assessor-package parity |
| PROD-16 provisioning/recovery | Central independently approved mapped bootstrap; restricted tenant owner; locked audit replication; signed-inventory isolated restore and separately approved exact-preimage DNS cutover CLIs | **Partial:** recovery API/auth deployment, full reconciliation, primary-write fencing and trusted inventory/CloudTrail completeness are prerequisite work, not computed by CLIs; live RPO/RTO/IAM drill absent |
| PROD-17 release qualification | fast-uri 3.1.6, patched CI Node baseline, TS/MJS discovery sentinel, native streamed response limits; existing manual Swift CodeQL retained | **Open qualification:** legacy ingress, signed Keychain, clean-Mac notarized install/update, live scanner/witness/alarms and exact released-artifact proof |

## Security findings

| Finding | Source remediation and evidence | Residual acceptance |
| --- | --- | --- |
| SEC-01 shared provisioner authority | Central-only shared secret; immutable approved mappings; tenant NOCREATEROLE/NOCREATEDB and own non-delegable owner; SQL/IAM synthesis denial tests | Real Aurora cross-database/Secrets Manager/IAM negative test |
| SEC-02 destructive retention history | Old cleanup disabled; full-history archive and independent signed hold-decision ledger; PNG-only verified disposal preserves metadata/anchors | Same-Mac restoration only; unrecoverable legacy history stays blocked; external S3 drill |
| SEC-03 default-workspace disclosure | Expected workspace required at every native reader/export boundary; named tenant trees excluded; swapped/duplicate fixtures | Signed-app UI/workspace switch qualification |
| SEC-04 scope-exceeding packages | Shared authoritative scope eligibility, immutable active scope, publication/CAS/snapshot fences with actual SQLite tests | Authenticated hosted deployment canary |
| SEC-05 unverified receipts | Validate exact artifact/destination/schema/digests, seal original response with independent device Keychain key; raw or altered receipts cannot suppress retry/export | Device seal is not independent provider signature; live availability rechecked separately |
| SEC-06 SQL NULL bypass | Forward 010 rejects NULL membership using fail-closed predicates; actual PostgreSQL execution/grants and customer role matrix | Aurora/Data API parity |
| SEC-07 delayed/poison repair | Ingest-only repair reuses exact immutable reservation within 14 days; public proof freshness unchanged; backoff/action-required after eight failures | Cross-store outage/concurrency drill and operator repair procedure |
| SEC-08 revoked sessions | Durable epoch/cutoff + verified auth_time on membership lookup, atomic audit/revoke routes and client sign-out | In-flight operations and issued S3 URLs not recalled; external IdP events require tenant cutoff integration |
| SEC-09 SBOM integrity | Nested/multi-version/unsupported-format handling, correct bom-ref, complete version sets and official-schema fixtures | Parser completeness not implied by schema validity |
| SEC-10 fast-uri advisories | Override 3.1.6; current root npm and AWS pnpm lockfile audits report zero known advisories | Repeat on release; audit is not reachability analysis or future guarantee |
| SEC-11 legacy ingress trust | **Not closed.** Separate AWS portal uses Cognito JWT and does not inherit legacy identity headers. No speculative dispatcher trust bypass added | Authorized legacy ingress/direct-origin/forged-header proof or an approved authenticated dispatcher replacement still required |
| SEC-12 native allocation limits | Per-endpoint streaming limits/cancellation for hosted, Jira and update responses; bounded-response tests | Real hostile/decompressed server and signed-app exercise |
| SEC-13 omitted AWS tests | Required commands include TS and MJS; disposable deliberately failing MJS sentinel proves actual command fails | Required remote CI run still needed |

## Migration, build and validation record

D1 migrations 0029 (requirements), 0030 (explicit schedules), 0031 (finding proof)
are append-only. Fresh and populated local replays/integrity checks passed.
AWS 010/011 plus operation grants install schema/owner 5, bundle v7; historical
001 is preserved and the exact guarded transform is recompiled before grants.
Read [workflow instructions](READINESS_WORKFLOWS.md),
[AWS portal](AWS_CUSTOMER_PORTAL.md) and
[bootstrap/recovery boundaries](AWS_BOOTSTRAP_AND_RECOVERY_BOUNDARIES.md).

Local tests use synthetic fixtures. Real PGlite PostgreSQL execution is distinct
from fake AWS adapters, source assertions and a live Aurora deployment. The
optional external PostgreSQL harness is skipped when not configured. Swift
DEBUG tests use isolated memory-backed Keychain state, not customer keys.
Current test totals and final checks are recorded in the
[validation handoff](READINESS_VALIDATION_2026-09-08.md);
no test count substitutes for the acceptance scope above.

## Required next qualification batches

1. Review and merge source through protected CI; include exact Node baseline,
   full root/CDK/CloudFormation suites, migration replays and schema fixtures.
2. Build a signed/notarized release in the approved Apple environment; qualify
   Keychain, privacy permissions, interruption, same-Mac archive/restore, 320px,
   200%-zoom and VoiceOver with synthetic data. Public DMG is unchanged here.
3. Separately authorize two-tenant AWS staging: Cognito enrollment-to-review,
   revocation, scanner/reconciliation failures, least-privilege denial and holds.
4. Complete recovery application/write-fence/reconciliation prerequisites, then
   independently approve a measured restore/cutover drill. Never sign fabricated
   completeness or acceptance gates.
5. Resolve SEC-11 before authorizing the legacy hosted origin for production;
   decide an explicit replacement-Mac trust-recovery design before relying on
   archival as device-loss disaster recovery.
