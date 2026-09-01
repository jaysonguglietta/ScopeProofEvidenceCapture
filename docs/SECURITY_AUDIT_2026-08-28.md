# Scopeproof adversarial security audit

**Review date:** 2026-08-28

**Review target:** the source snapshot reviewed on 2026-08-28, including the legacy Cloudflare/Sites runtime, the native macOS application, the AWS multi-tenant foundation, database migrations, CI/release automation, and operator documentation. Later source changes require their own exact-commit review; this dated report is not proof that an uncommitted or locally installed build contains them.

**Deployment status:** **No AWS resources were deployed or modified during this work.** No production customer environment was tested.

**Assessment type:** source-assisted architecture, application-security, and adversarial design review

## 1. Executive Summary

Scopeproof has materially stronger security controls than a typical evidence-capture utility. The reviewed source now includes strict request bounds, server-side RBAC, invitation-only membership after a one-time bootstrap, encrypted evidence storage, integrity-bound evidence reads, append-only audit events, signed packages, bounded non-executing SBOM generation, hardened native file handling, exact-version S3 controls, strict AWS JWT verification, per-tenant data planes, KMS-signed AWS audit receipts, two-person legal holds, cross-region recovery templates, pinned CI actions, and a production notarization workflow.

The application is **not yet approved for high-risk production use**. The most important remaining issue is architectural: the existing Cloudflare/Sites application trusts platform-injected identity headers and is explicitly single-tenant, while the AWS implementation is a separate, incomplete, source-only runtime. A deployment that exposes the Worker directly or maps multiple customers to the legacy data boundary could cause authentication bypass or cross-customer disclosure. Those are conditional Critical hazards, not confirmed exploits in the intended private Sites topology.

The current source also closes the previously confirmed client-only screenshot-safety gap. Both native uploads and Browser Rendering captures now send the exact PNG to a separately configured OCR service before any evidence persistence; the application checks the returned digest, runs its own bounded sensitive-text policy, persists a digest-bound receipt, and blocks every screenshot lacking a valid canonical receipt from list verification, read, approval, package, and Jira paths. This prevents a compromised Mac from bypassing safety solely by signing a false local declaration. It does **not** establish that the external scanner is trustworthy, private, available, correctly configured, or free from OCR/DLP false negatives. Those remain production-release dependencies because Scopeproof's primary product promise is trustworthy compliance evidence, not merely confidential file storage.

No confirmed remotely exploitable command injection, SQL injection, template injection, path traversal, unsafe deserialization, arbitrary SSRF, or remote-code-execution path was found in the reviewed source. That conclusion is limited to static inspection and local tests. It does not cover a live Cloudflare dispatcher, Cognito user pool, Aurora cluster, IAM policy evaluation, S3 Object Lock behavior, KMS key policy, GuardDuty event flow, DNS/TLS configuration, Apple notarization, or the actual contents of deployed secrets.

### Source-remediation follow-up — 2026-09-01

The subsequent hardening pass confirmed these additional source remediations;
the dated findings below remain unchanged as historical review evidence:

- Audit-checkpoint delivery retries are append-only, restricted to the exact
  checkpoint while it remains the current audit head, witness-idempotent by
  checkpoint digest, and single-winner under concurrency. Losing receipt objects
  are removed, and a newly delivered attempt changes the verification cache key
  so a prior cached failure cannot mask successful recovery.
- Package preflight and final package construction now use one shared behavioral
  eligibility policy, including screenshot-safety, native-chain, expiry,
  approval, and partial-coverage replacement rules. This removes a UI/build
  policy split; final publication still performs its transactional revalidation.
- Assessment browsing uses stable cursor pagination, loads active workspaces
  independently so they cannot disappear behind newer closed assessments, and
  incrementally exposes all remaining active and historical pages without
  silently treating the first page as complete.
- Maintenance domains run in isolated stages so retention, collection, SBOM, or
  rotation failure cannot suppress checkpoint and operational-health work.
  Key-rotation failures persist per-record attempt count, bounded backoff,
  retry/action-required status, safe error code, and audited recovery state so
  one poisoned record does not hot-loop or starve unrelated records.
- The security workflow now enforces both ESLint and a no-emit TypeScript
  typecheck before the existing test, migration, audit, and infrastructure gates.
- The native updater validates signed ZIP central/local records, paths, entry and
  aggregate expansion, compression ratios, file types, and extracted-tree size;
  requires measured temporary free space plus a safety margin; and bounds,
  times out, cancels, and terminates release-verification subprocesses.
- Operational error logging uses a bounded allowlisted error classification
  instead of raw exception messages where attacker/provider data could contain
  tokens or secrets. Secret-scanning test fixtures now generate valid-shaped
  synthetic credentials at runtime instead of embedding literal AWS examples.

These are source controls, not production closure. They do not change the
conditional SP-01 proxy-authentication boundary: deployment must still prove
that the private edge strips attacker-supplied identity headers, injects trusted
identity, and prevents direct Worker access. They also do not prove a live
Cloudflare/AWS deployment, scanner/witness/timestamp-service operation, alert
delivery, recovery, Apple Developer ID signing, notarization, stapling,
Gatekeeper acceptance, or protected release publication.

### Risk summary

| ID | Finding | Severity | Confidence | Status |
| --- | --- | --- | --- | --- |
| SP-01 | Proxy identity headers are a conditional authentication-bypass boundary | Critical | Medium | Conditional deployment hazard; proof required |
| SP-02 | The legacy runtime cannot isolate multiple customers | Critical | High | Confirmed architectural hazard; guarded but not eliminated |
| SP-03 | Assessor package creation could race with a newer evidence occurrence | High | High | Remediated in source; live D1/R2 fault testing remains |
| SP-04 | Hosted screenshot safety trusted a client-originated claim | High | High | Remediated in source; scanner trust/efficacy/privacy remain operational gates |
| SP-05 | Native evidence could become trust-bearing before its device-chain link finalized | Medium | High | Remediated in source; deployed fault testing remains |
| SP-06 | Independent audit-checkpoint delivery lacked receipt authentication | Medium | High | Remediated in source; witness service remains external |
| SP-07 | Production readiness did not validate every symmetric key's strength | Medium | High | Remediated in source; secret entropy remains an operator duty |
| SP-08 | Trusted timestamp failure silently downgraded to server time | Medium | High | Remediated in source; lower-assurance mode cannot report ready |
| SP-09 | AWS implementation covers only a narrow API and remains unvalidated live | High | High | Production release blocker |
| SP-10 | Shared AWS control-plane roles and one account retain broad blast radius | Medium | High | Architectural defense gap |
| SP-11 | DynamoDB lifecycle/control-plane changes lack equivalent immutable data-event evidence | Medium | High | Monitoring gap |
| SP-12 | Same-account recovery does not survive account-level compromise | Medium | High | Resilience gap |
| SP-13 | Alert routing and escalation are not proven operational | Medium | High | Operational production gate |
| SP-14 | Compatible-S3 static keys remain an explicit lower-assurance mode | Low | High | Accepted migration risk; must stay non-production |

### Material remediations verified in the reviewed source snapshot

The following earlier weaknesses were addressed in source during this hardening wave:

- Active-content evidence is blocked at upload and served as an inert attachment; only exact PNG is inline, with a sandbox CSP, `nosniff`, no-store caching, and safe filenames.
- Evidence disclosure now fails closed if its preview/download audit event cannot be committed.
- JSON redaction is structural and key-aware; text, XML, and YAML patterns are bounded.
- Audited D1 compare-and-swap mutations use a transactional guard so a successful state change cannot commit without its required audit event.
- Evidence de-duplication is assessment/system/environment/period scoped, creates occurrence records, invalidates stale approvals on a new occurrence, and handles nullable scope with explicit partial unique indexes.
- The migration chain rebuilds incompatible SQLite tables, uses a windowed occurrence backfill, and provides a duplicate preflight query.
- Device tokens expire, rotate, and are revoked with their owner; permanent membership revocation invalidates dependent device and Jira credentials.
- Disabled collectors and revoked job requesters are rechecked immediately before work.
- SBOM repository discovery is permission-gated, separately rate-limited, and cached; archives remain bounded and non-executing.
- PNG validation uses table-based CRC, ancillary-data limits, streaming decompression accounting, and decoded-size limits.
- Native file access uses root containment, `O_NOFOLLOW`, regular-file/hardlink checks, bounded reads, PNG validation, and digest checks.
- New native evidence uses device-bound P-256 provenance; unsigned schema-6 evidence is explicitly browsing-only and cannot enter trust-bearing workflows.
- Hosted schema-8 manifest parsing accepts native source provenance only as an exact HTTP(S) origin matching `sourceHost`; paths, query strings, fragments, credentials, ports, and host substitution are rejected server-side to prevent URL-secret persistence. Its signed tenant/workspace must exactly match the isolated legacy deployment configuration.
- Hosted native upload now accepts only schema 8, verifies P-256 provenance and the deployment tenant/workspace, pins one signing key to one device, enforces exact session ownership/scope, and advances a server-maintained device chain with a lease/CAS protocol.
- Pending native finalization is explicitly labeled and blocked from byte reads, approval, Jira handoff, and package selection/publication; finalized links are immutable and exact-digest/sequence bound.
- Every new hosted screenshot is independently scanned before persistence. The exact PNG digest is bound to a server-created safety receipt; migration `drizzle/0023_independent_image_safety.sql` persists the receipt fields, and read/approval/package/Jira workflows fail closed for historic or malformed screenshot rows without a valid receipt.
- The Local Console is loopback-only and now rotates launch/session material, enforces expiry, caps connections, and bounds request time.
- Production S3 uses temporary Identity Center/AssumeRole credentials, expected-owner SigV4, redirect rejection, verified bucket posture, exact versions/checksums, and COMPLIANCE Object Lock readback. The KMS ARN is bound to the STS-verified bucket-owner partition/Region/account and direct `DescribeKey` must prove an enabled customer-managed symmetric encryption key; long-lived keys and Governance retention are rejected by the Production profile.
- Assessor-package publication now pins occurrence IDs and the assessment revision, then atomically revalidates latest approval, expiry, coverage, and assessment state before publishing.
- All retained AES and audit-HMAC keys use canonical base64, have explicit length requirements, and are imported/self-tested during readiness.
- Audit checkpoints now require a separately signed, digest/sequence-bound external witness receipt and verify the D1 record, R2 objects, local signature, witness signature, and signed receipt binding.
- Trusted timestamping is fail-closed by default for native evidence; a missing or invalid TSA/verifier result stores nothing, and disabling the policy or omitting TSA configuration fails production readiness.
- AWS source now implements strict Cognito JWT/JWKS validation, active membership checks, upload-intent issuance, exact promotion reconciliation, KMS-signed audit receipts, two-person exact-version legal holds, cross-region backup/recovery, and hardened release workflows.

These are source-level conclusions. “Remediated” does not mean deployed, externally attested, or operationally proven.

## 2. System Overview and Trust Boundaries

### Application architecture

Scopeproof currently contains three related but distinct execution models:

1. **Native macOS application.** `macos/ScopeproofCapture` captures and redacts screenshots, writes PNG/manifest/lifecycle/hold records under `~/Documents/Scopeproof Evidence`, offers a loopback Local Console, generates repository SBOMs, uploads to the legacy hosted API, optionally writes directly to S3, and hands approved evidence to Jira or assessor packages.
2. **Legacy single-tenant hosted application.** `app`, `lib/server`, `db`, `drizzle`, and `worker/index.ts` implement a React/vinext console and Cloudflare Worker backed by D1 and R2. The private Sites layer is expected to authenticate users and inject identity headers. The Worker also calls a separately configured OCR service with exact hosted screenshot pixels and fails closed before persistence when that scan is unavailable, invalid, or detects locally classified sensitive text. This runtime holds one global workspace and must not serve unrelated customers.
3. **AWS multi-tenant target.** `infra/aws/cdk`, `infra/aws/database`, and `lib/aws-runtime` define exact tenant hostnames, Cognito, API Gateway/Lambda, DynamoDB coordination, separate Aurora databases and roles, per-tenant S3/KMS boundaries, malware quarantine/promotion, exact-version reads and legal holds, KMS-signed audit receipts, monitoring, and cross-region recovery. This target has not been deployed.

### Protected assets

- Evidence plaintext, screenshots, SBOMs, exports, and decrypted temporary data.
- Evidence metadata: customer, assessment, control, source, system, timestamps, coverage, approval, retention, hold, and provenance state.
- Provider credentials, Jira OAuth tokens, native device tokens, hosted OAuth refresh tokens, S3/STS credentials, presigned URLs, and database secrets.
- AES encryption keys, HMAC keys, package-signing keys, native provenance keys, KMS signing keys, and update-signing keys.
- Tenant/domain registry entries, Cognito subjects, memberships, roles, device ownership, upload intents, promotion receipts, and recovery ledgers.
- Audit events, checkpoints, CloudTrail objects, legal-hold records, release attestations, and verification material.
- Availability and cost budgets for Workers, Lambda, DynamoDB, Aurora, S3, KMS, GitHub, Jira, Okta, Cloudflare, and OCR/timestamp services.

### Principal trust boundaries

1. **Browser → Sites dispatcher → Worker.** Browser headers and cookies are untrusted. The application assumes the private dispatcher removes caller-supplied `oai-authenticated-user-*` headers and injects authoritative identity values. The Worker itself validates only the exact configured request origin and local membership.
2. **Authenticated user → application authorization.** A user may be malicious, compromised, suspended, or incorrectly assigned. Every mutation must derive role/capability from the current server-side record, require same-origin proof, and enforce object/state scope.
3. **Worker → D1/R2.** D1 metadata and R2 ciphertext must remain consistent across failures, races, key rotation, retention, and deletion. Neither store alone proves evidentiary integrity.
4. **Provider → collector/SBOM parser.** GitHub, AWS, Okta, Cloudflare, browser rendering, archive entries, pagination links, XML, JSON, lockfiles, and OCR responses are attacker-controlled even when the TLS endpoint is genuine.
5. **Mac display/filesystem → native app.** Screen pixels, filenames, sidecars, imported control catalogs, local symlinks/hard links, and legacy artifacts are untrusted. The Mac account and endpoint may be compromised.
6. **Browser → Local Console.** Other local processes and malicious websites may target loopback. The server must authenticate the browser session, validate Host/Origin/fetch metadata, refuse caller-supplied paths/keys, and bound concurrency and parsing.
7. **Mac → legacy hosted API.** The device token and client can be stolen or malicious. The current hosted boundary accepts schema 8 only and verifies its signed tenant/workspace binding, P-256 signature, key pinning, session checks, and server chain CAS to authenticate device origin/continuity. Signed schema 7 remains locally verifiable under its earlier lifecycle contract but cannot cross that hosted tenant/workspace boundary. Neither schema proves honest local OCR, uncompromised execution, or successful completion of the distributed persistence workflow. The server therefore treats the local safety claim as advisory and independently scans the exact PNG before storage.
8. **Hosted Worker → independent screenshot scanner.** Exact screenshot pixels and their digest leave Scopeproof for OCR. TLS to an exact allowlisted origin and a bearer token authenticate the request path, while strict response schema and digest equality bind the response to the submitted PNG. The scanner's OCR completeness, policy behavior, internal security, regional processing, logging/retention, availability, and honesty are external assumptions; the returned result is not separately signed by the scanner.
9. **Mac → STS/S3.** AWS responses, redirects, bucket policies, object listings, ETags, version IDs, KMS settings, and locally cached AWS CLI state cross a high-value trust boundary.
10. **Internet → AWS API Gateway/WAF/Lambda.** Host, OAuth token, JSON, IDs, cursor, body size, request rate, timing, and API Gateway envelope are attacker-controlled. Tenant identity must be resolved from authoritative host/JWT/membership records, never from a request body.
11. **Shared AWS control plane → tenant data plane.** Tenant directory entries, assumed roles, database/secret names, S3 buckets, KMS ARNs, and resource IDs must resolve to one exact tenant. A shared-role compromise is assumed possible.
12. **Quarantine → GuardDuty → promotion.** Object bytes, version, checksum, metadata, malware events, queue envelopes, retries, and partial failures are untrusted until reconciled against authoritative intent and live S3 facts.
13. **CI/release → user machine.** GitHub Actions, dependencies, signing credentials, artifacts, checksums, attestations, Apple notarization, update metadata, and GitHub releases are supply-chain inputs.
14. **Operators/AWS administrators.** Administrators can alter policies, keys, DNS, deployments, logs, retention, and alerting. High-assurance design must limit and independently evidence that power.

### Review coverage by component

| Component | Principal files reviewed | Security focus |
| --- | --- | --- |
| Legacy identity/RBAC | `lib/server/auth.ts`, `app/chatgpt-auth.ts`, `app/api/users/route.ts`, `lib/server/devices.ts` | header trust, bootstrap, invitation, role/status, revocation, device tokens, CSRF |
| Evidence lifecycle | `lib/server/evidence.ts`, `lib/server/packages.ts`, `lib/server/retention.ts`, `lib/server/key-operations.ts`, evidence API routes | validation, redaction, dedupe, review, races, disclosure, encryption, purge, holds, exports |
| Audit/integrity | `lib/server/audit.ts`, `lib/server/checkpoints.ts`, `lib/server/crypto.ts`, migrations | append-only behavior, authenticated chaining, atomicity, key rotation, checkpoint trust |
| Integrations | `lib/server/collectors.ts`, `lib/server/image-safety-config.ts`, `lib/server/image-safety.ts`, `lib/server/external-trust-config.ts`, `lib/server/sbom.ts`, `lib/server/outbound.ts`, `lib/server/jira.ts`, `lib/server/timestamp.ts` | SSRF, redirects, parsing, screenshot safety, monitoring/checkpoint/timestamp configuration, quotas, credential scope, retry safety |
| Native app | `macos/ScopeproofCapture/Sources/ScopeproofCapture` and tests | local files, Keychain, provenance, Local Console, S3/Jira/network, release/update path |
| AWS runtime | `lib/aws-runtime`, Lambda assets, PostgreSQL migrations | JWT, membership, tenant isolation, upload/promotion, exact reads, audit, legal holds |
| AWS infrastructure | `infra/aws/cdk`, `infra/aws/cloudformation`, observability/recovery templates | IAM, KMS, S3, Object Lock, Cognito, WAF, backup, alerting, configuration defaults |
| Supply chain | `package*.json`, CDK lockfile, `.github/workflows`, `Scripts`, `CODEOWNERS` | version pinning, scripts, CodeQL, SBOM, signing, notarization, attestations |

## 3. Threat Model

### Attacker personas

- **Unauthenticated Internet attacker:** probes direct Worker/API origins, identity-header spoofing, OAuth/JWT confusion, large bodies, malformed files, SSRF, XSS, and cost exhaustion.
- **Malicious tenant member:** uses legitimate access to enumerate objects, exploit IDOR, approve own evidence, bypass assessment/retention state, poison audit evidence, or consume shared capacity.
- **Cross-tenant adversary:** is valid for customer A and attempts to use host, IDs, cursors, presigned URLs, role assumptions, or database bugs to access customer B.
- **Compromised Mac/device identity:** uses the legitimate signing operation to forge local safety claims, tampers with local sidecars, steals cached credentials, or attempts to upload secret-bearing evidence. A stolen bearer token without the pinned P-256 key is a narrower threat than full endpoint compromise; the independent pre-storage scan now means even full endpoint control is insufficient by itself to establish a hosted passing receipt.
- **Malicious repository/provider/scanner:** returns oversized or malformed JSON/XML/ZIP/PNG, hostile pagination links, decompression bombs, deceptive dependency metadata, controlled error text, or incomplete OCR. A compromised screenshot scanner can truthfully echo the digest while omitting recognized sensitive text unless its response and efficacy are independently assured.
- **Compromised shared runtime:** obtains Worker, Lambda, provisioner, CI, or deployment credentials and attempts to pivot across tenants or rewrite evidence/control state.
- **Malicious administrator/insider:** changes IAM/KMS/bucket/retention/DNS/logging settings, suppresses alerts, exports customer data, or replaces a signed release.
- **Operational failure:** a well-intentioned operator deploys the legacy app as multi-tenant, uses the placeholder domain, leaves alert subscriptions unconfirmed, loses a key, skips migration preflight, or assumes source templates equal deployed controls.

### Primary adversarial objectives

- Impersonate an administrator or active member.
- Read another user’s or customer’s evidence.
- Introduce fabricated, stale, partial, or secret-bearing evidence into an assessor package.
- Approve one’s own evidence or make a superseded approval appear current.
- Shorten retention, bypass a legal hold, delete immutable evidence, or destroy its key.
- Forge or roll back audit history, receipts, timestamps, or provenance chains.
- Exfiltrate Jira/GitHub/AWS/provider tokens or presigned URLs.
- Turn parsing, collection, cryptographic verification, or cloud calls into denial of service or excessive cost.
- Compromise the build/release path and persist on assessor workstations.

### Representative attack paths

1. Send forged platform identity headers directly to an exposed Worker, claim an existing identity or unused bootstrap administrator, then export evidence.
2. Attach multiple customer hostnames to the legacy global D1/R2 boundary and exploit any missing object filter to read or mutate another customer's records.
3. Control an enrolled Mac and its signing operation, upload a valid schema-8 tenant/workspace-bound PNG with a fabricated local “safety scan passed” claim, and rely on an OCR false negative, compromised scanner, or unsafe policy/configuration to obtain the independently required hosted receipt. The endpoint compromise alone no longer completes this path.
4. Repeatedly interrupt native upload after the general evidence commit but before device-chain finalization, creating provenance-pending artifacts and storage/reconciliation pressure; trust-bearing use remains denied.
5. Compromise a shared AWS/provisioning role, enumerate tenant boundaries, assume per-tenant roles, and access multiple customer control/data planes.
6. Poison or suppress control-plane events so a tenant mapping, upload intent, or recovery state changes without an equivalent immutable event trail.

## 4. Attack Surface Inventory

| Surface | Entry points and attacker-controlled inputs | Implemented controls | Residual concern |
| --- | --- | --- | --- |
| Legacy web edge | URL, Host, identity headers, Origin, fetch metadata, JSON bodies | one exact origin, explicit single-tenant acknowledgement, active membership, RBAC, same-origin mutation proof, body/rate limits | proxy header authenticity and direct-origin isolation are external assumptions |
| Membership/devices | invites, roles, status, bearer device token, app version, signing key | invitation-only after bootstrap, final-admin trigger, permanent revoke, token hash/expiry/rotation, owner status recheck, schema-8 tenant/workspace binding, P-256 pinning, and chain CAS | compromised endpoint can still use its legitimate identity; no hardware/MDM attestation |
| Evidence upload/read | multipart, PNG, JSON/text, metadata, artifact ID, inline/download | content/type/size validation, PNG parser, redaction, AES-GCM, digest, inert response headers, authorization, audit-before-disclosure, exact pre-storage screenshot scan/receipt, all-screenshot read/approval/export gates, pending native provenance fails closed, bounded audited native reconciliation | scanner trust/privacy/availability and OCR false negatives; native reconciliation needs deployed fault/operations proof |
| Evidence review/export | digest, rationale, assessment, occurrence/revision, concurrent mutation | separation of duties, latest-occurrence approval CAS, package occurrence/assessment publication fence, coverage/expiry checks, signed encrypted packages | distributed failure behavior requires deployed D1/R2 fault tests |
| Audit/checkpoints | event details, chain state, delivery endpoint/receipt | canonical event hashes, HMAC, append-only triggers, audited CAS guard, signed R2 checkpoint, pinned witness P-256 receipt and signed receipt binding | witness operation/monotonic divergence monitoring is external and unproven |
| Collectors | provider JSON/XML, pagination, HTTP status, screenshot/OCR | fixed/allowlisted origins, redirect rejection, per-response/page/resource bounds, explicit partial coverage, requester/collector recheck, Browser Rendering scan before artifact persistence | load/cost limits and external OCR efficacy/availability/privacy require production proof |
| Screenshot scanner | exact PNG/base64, digest, bearer credential, OCR text, policy version | clean HTTPS endpoint on exact host allowlist, redirect rejection, timeout/input/response/text bounds, strict response schema, digest equality, local sensitive-text policy, fail-closed persistence/readiness | response is not scanner-signed; compromised/weak OCR can omit content; raw screenshots cross an external privacy boundary |
| Repository SBOM | repo URL, ref, token, ZIP and lockfiles | exact GitHub hosts, immutable commit, no execution, ZIP/ratio/manifest/component caps, ephemeral token, permission and rate limits | parser differentials and provider quota behavior need fuzz/load testing |
| Jira OAuth | OAuth callback, cloud/project/issue, tokens, upload | state binding, exact Atlassian gateway, encrypted tokens, owner/project checks, bounded upload | live tenant/account revocation and Atlassian behavior untested |
| Native filesystem | PNG/JSON/sidecars, roots, symlinks/hardlinks | validated central loader, containment, `O_NOFOLLOW`, bounds, digests, locally verifiable signed schema-7 and tenant/workspace-bound schema-8 provenance; unsigned schema-6/older is browsing-only | local Keychain anchor is not an independent transparency log |
| Local Console | loopback HTTP, Host, Origin, bearer, IDs, concurrency | `127.0.0.1`, one-time URL-fragment nonce exchanged once for a short-lived in-memory bearer, no localhost auth cookie, expiry, connection/time limits, server-side path/key resolution | endpoint compromise still defeats local trust; never expose to LAN |
| Native direct S3 | credentials, AWS CLI profile, bucket/KMS/prefix, object listing/download | temporary Identity Center/AssumeRole in production, strict CLI path/env, expected owner, SigV4, no redirects, COMPLIANCE retention, account/partition/Region-bound KMS `DescribeKey`, schema-4 destination binding, exact version/checksum/lock | compatible mode permits long-lived keys; no endpoint attestation or live IAM/KMS proof |
| AWS tenant API | Host, JWT/JWKS, body, IDs, cursors, request rate | strict RS256 issuer/client/token-use/scope checks, active membership, tenant resolution, bounded parsing, least-privilege roles | only a narrow source-defined API exists; no live validation |
| AWS upload/promotion | intent, nonce digest, bytes, metadata, version, events/retries | atomic tenant/principal quotas, quarantine-only writer, exact intent/version/checksum/KMS/context/scan checks, single-winner promotion | deep content scanning and live GuardDuty/S3 concurrency proof remain open |
| AWS legal hold/audit | request/approval identity, exact S3 version, KMS signature, outbox | distinct-admin two-person state machine, CAS, exact readback, KMS signing/verification, retry/dead-letter paths | no deployed drill, customer UI, or independent checkpoint publication |
| CI/release | dependencies, workflows, secrets, approved commit, DMG/update metadata | exact pins, SHA-pinned actions, CODEOWNERS, dependency review/audit, SBOM, manual Swift CodeQL, hardened signing/notarization/attestation workflow | production workflow has not run and branch protections were not verified here |

## 5. Prioritized Findings

This section includes residual findings and explicit closure records for material defects fixed during the review. A record marked **Remediated in source** describes the exploitable pre-fix condition so that its regression tests and deployment proof remain auditable; it is not counted as an open vulnerability in the release decision.

### SP-01 — Proxy identity headers are a conditional authentication-bypass boundary

- **Severity:** Critical
- **Confidence:** Medium
- **Classification/status:** Conditional deployment vulnerability; exploitability depends on an external hosting guarantee that is not proven by this repository
- **Affected files/functions:** `lib/server/auth.ts` (`assertTrustedRequestOrigin`, `requireApiUser`), `app/chatgpt-auth.ts` (`getChatGPTUser`), Worker/Sites routing configuration
- **Description:** The legacy application treats `oai-authenticated-user-id`, `oai-authenticated-user-email`, and the optional encoded name as authoritative after checking that the request URL's origin equals the one configured origin. Origin equality proves which hostname received the request; it does not cryptographically authenticate those headers. Security therefore depends on an externally supplied identity-aware private dispatcher overwriting all client-supplied identity-header variants, injecting authenticated values, and preventing direct access to the Worker/origin. Repository source does not prove that such a dispatcher is supported, configured, or deployed.
- **Evidence from code:** `requireApiUser` reads identity directly from request headers and uses it to load or create a membership. `assertTrustedRequestOrigin` compares `new URL(request.url).origin` with `TRUSTED_APP_ORIGINS`; there is no signed assertion, mTLS identity, shared-secret proxy header, or platform-verification call in application code. The one-time bootstrap path can create the first administrator when the supplied email is allowlisted and the invariant has not yet been claimed.
- **Exploitation scenario:** If an attacker can reach the Worker directly or the proxy forwards caller-supplied identity headers, the attacker submits a chosen existing user ID/email and acts as that member. Before bootstrap is claimed, an attacker who knows an allowlisted administrator email may try to claim the administrator identity.
- **Potential impact:** Authentication bypass, administrator takeover, evidence disclosure, role/retention changes, device enrollment, Jira access, package export, and audit manipulation through otherwise authorized application paths.
- **Recommended fix:** Make the application origin private and non-routable except through the identity-aware dispatcher. Prove that the dispatcher deletes all inbound identity-header variants before injection. Prefer a cryptographically verifiable proxy assertion with audience, issuer, expiry, request binding, and key rotation, or terminate authentication inside the application. Remove bootstrap capability immediately after an out-of-band first-admin ceremony.
- **Example secure implementation / patch guidance:** Replace direct header consumption with `verifyDispatcherAssertion(request)` that verifies an asymmetric signature over `{sub,email,aud,iss,iat,exp,method,host}` using a pinned issuer/JWKS and returns a branded server-only principal. Network policy should deny the Worker hostname and preview aliases. Add a deployment check that requests the origin directly with forged headers and expects denial before any D1 access.
- **Tests/validation:** Test missing, duplicate, mixed-case, and forged headers through both the public hostname and every direct/preview/origin hostname. Confirm the proxy overwrites rather than appends identity headers. Attempt the unused bootstrap allowlist from outside the dispatcher. Review platform documentation and capture configuration evidence.
- **CWE/OWASP:** CWE-345 (Insufficient Verification of Data Authenticity), CWE-290 (Authentication Bypass by Spoofing), OWASP API2:2023 (Broken Authentication)

### SP-02 — The legacy runtime cannot isolate multiple customers

- **Severity:** Critical
- **Confidence:** High
- **Classification/status:** Confirmed architectural deployment hazard; guarded by fail-closed acknowledgement and exact origin, but not converted into a multi-tenant system
- **Affected files/functions:** `lib/server/auth.ts` (`assertTrustedRequestOrigin`), global D1 schema in `db/schema.ts`/`drizzle`, R2 keys in `lib/server/evidence.ts`, all legacy API routes
- **Description:** The legacy application has one global user, assessment, evidence, device, integration, audit, and object namespace. Rows do not carry an authoritative tenant ID, and the R2 key hierarchy is not a customer security boundary. Authentication and subdomains alone cannot provide tenant isolation.
- **Evidence from code:** The runtime explicitly requires `LEGACY_SINGLE_TENANT_ACKNOWLEDGEMENT=single-tenant-only` and exactly one trusted origin. Core queries such as `listEvidence`, `listAssessments`, user listing, package selection, and audit listing have no tenant predicate because the schema has no tenant column. This is safe only when one isolated D1/R2/key deployment serves one customer/workspace.
- **Exploitation scenario:** An operator maps `client-a` and `client-b` hostnames to one legacy deployment. A valid member of either customer calls ordinary list/read endpoints and receives records from the shared tables because there is no server-side customer discriminator.
- **Potential impact:** Systemic cross-customer evidence disclosure and mutation, privacy breach, invalid compliance packages, shared-key exposure, and incident scope encompassing every hosted customer.
- **Recommended fix:** Never attach tenant hostnames to the legacy runtime. Either deploy one fully isolated legacy stack per customer or complete the AWS tenant runtime and migrate every customer-facing route. Tenant identity must resolve from authoritative host/JWT/membership data and be enforced by separate databases, IAM roles, S3/KMS boundaries, and object ownership checks.
- **Example secure implementation / patch guidance:** Keep the acknowledgement guard, add an explicit deployment denylist for tenant/customer domains, and direct tenant traffic only to the AWS API/UI. For every AWS repository method, accept a branded `TenantActor` rather than a raw tenant string and reconstruct storage/database coordinates from the tenant directory.
- **Tests/validation:** Maintain two synthetic customers and run a complete role × endpoint × object matrix while swapping hostnames, users, object IDs, cursors, database roles, bucket keys, and presigned URLs. Assert both the HTTP result and cloud API trace stay in the selected tenant.
- **CWE/OWASP:** CWE-284 (Improper Access Control), CWE-639 (Authorization Bypass Through User-Controlled Key), OWASP API1:2023 (Broken Object Level Authorization)

### SP-03 — Assessor package creation could race with a newer evidence occurrence

- **Severity:** High
- **Confidence:** High
- **Classification/status:** Confirmed pre-fix integrity/business-logic vulnerability; **remediated in the current source**, with live D1/R2 failure testing still required
- **Affected files/functions:** `lib/server/packages.ts` (`buildAssessorPackage`), `lib/server/evidence.ts` (`storeEvidence`, occurrence triggers/approval projection), `drizzle/0017_demonic_firedrake.sql`
- **Description:** The pre-fix exporter selected approved evidence and then performed slow R2 reads, decryption, hashing, document generation, compression, encryption, and upload without proving at publication time that each selected occurrence was still the latest eligible occurrence. A new observation could reset approval during that interval. The current exporter pins each selected occurrence and assessment revision and conditionally publishes only if every pinned item remains latest, approved, unexpired, and non-partial.
- **Evidence from code:** `buildAssessorPackage` selects `o.id AS occurrence_id` from the latest-occurrence subquery. The final `UPDATE export_packages ... WHERE status='building'` requires the assessment's original `status` and `updated_at`, plus an `EXISTS` predicate for every occurrence proving exact artifact binding, current latest status, approval, expiry, and coverage. `executeAuditedBatch` requires the ready row/digest postcondition; the catch path deletes the pending R2 object.
- **Exploitation scenario:** Before the fix, a collector or device could submit a new observation after selection but before publication, making stale approval metadata appear current in a completed ZIP. The same race now makes the conditional publication change zero rows; the exporter deletes the pending object and fails the build.
- **Potential impact:** Before remediation: misleading assessor packages, stale approval, and disputed evidence freshness. Residual impact is limited to denial/retry if evidence changes during an export or if D1/R2 fails.
- **Recommended fix:** Retain the exact occurrence/assessment CAS and signed occurrence IDs. If package volumes grow, consider a durable `export_package_items` snapshot for easier reconciliation and operational visibility; do not weaken the final latest-occurrence predicate.
- **Example secure implementation / patch guidance:** The implemented pattern at `lib/server/packages.ts` lines 153–171 is the required secure publication fence: bind each `(occurrence_id, artifact_id)` and assessment revision in one guarded audited transition, and delete the staged object on any mismatch.
- **Tests/validation:** Deterministically pause after selection, add a complete or partial occurrence, expire/reject evidence, change assessment state/scope, and resume. Each mutation must prevent `ready`; the staged object must be deleted. Also test two concurrent builders and injected failure before/after R2 put and D1 publish against the deployed D1 compatibility layer.
- **CWE/OWASP:** CWE-362 (Concurrent Execution Using Shared Resource with Improper Synchronization), CWE-367 (TOCTOU Race Condition), CWE-840 (Business Logic Errors)

### SP-04 — Hosted screenshot safety trusted a client-originated claim

- **Severity:** High
- **Confidence:** High
- **Classification/status:** Confirmed pre-fix trust-boundary weakness under the stated compromised-client threat model; **remediated in the current source**. External scanner trust, OCR/DLP efficacy, privacy, availability, configuration, and deployed operation remain residual release risks.
- **Affected files/functions:** `lib/server/image-safety-config.ts` (`evidenceSafetyScannerEndpoint`, `evidenceSafetyScannerToken`, `validateEvidenceSafetyScannerConfiguration`), `lib/server/image-safety.ts` (`scanExactEvidencePixels`, `evidenceSafetyReceiptSha256`), `app/api/native/evidence/route.ts` (`POST`), `lib/server/collectors.ts` (`scanExactBrowserPixels`, Browser Rendering), `lib/server/evidence.ts` (`storeEvidence`, `listEvidence`, `readEvidenceBytes`, `approveEvidence`), `lib/server/packages.ts` (`buildAssessorPackage`), `app/api/native/jira/upload/route.ts` (`POST`), `lib/server/readiness.ts`, `db/schema.ts`, `drizzle/0023_independent_image_safety.sql`
- **Description:** Before remediation, an enrolled device could cryptographically authenticate a false local OCR/DLP declaration; device provenance proved origin, not safe pixels. The current source treats local safety as advisory and sends every native or Browser Rendering PNG to a separately configured service before persistence. The application binds the result to the exact digest, applies its own sensitive-text classifier to returned OCR, stores a canonical server receipt, and makes that receipt mandatory for every screenshot's trust-bearing paths, including historic/non-native rows.
- **Evidence from code:** `scanExactEvidencePixels` validates PNG and size, hashes the exact bytes, requires a clean HTTPS endpoint on an exact host allowlist, rejects redirects through `boundedFetch`, applies a 60-second timeout and 2 MiB response limit, accepts only `{sha256,text,policyVersion}`, requires the returned digest to match, caps text at 1.5 million characters, and runs local `redactText`. The recognized text is consumed for that decision and is not returned in `EvidenceSafetyScan` or persisted. Native upload invokes the scan before trusted timestamping, device-chain reservation, or `storeEvidence`; Browser Rendering invokes the same function before adding the artifact. `storeEvidence` rejects any new screenshot without a digest-matching, canonically hashed receipt. Migration 0023 persists digest, policy, completion time, scanner origin, and receipt hash. `listEvidence`, `readEvidenceBytes`, and `approveEvidence` recompute the canonical receipt hash for every screenshot. Package eligibility, selection, final publication, and per-file reads fail closed, with `readEvidenceBytes` canonically validating every selected artifact before publication. Jira selects the exact approved hosted/native artifact and recomputes its canonical safety receipt before disclosure. Readiness fails when endpoint, token, or host allowlist is absent. The receipt hash is generated by Scopeproof and therefore detects accidental/unauthorized field mutation through application paths but is not an independent scanner signature; a database-capable attacker who can rewrite all receipt fields can recompute it.
- **Exploitation scenario:** Before the fix, malware controlling an enrolled Mac and its signing operation could upload a secret-bearing PNG with a conforming false “passed” manifest. That client-only path now fails if the independent scanner detects the content and stores nothing. A realistic residual path requires a second failure: the scanner is compromised, weak, incorrectly configured, or produces an OCR false negative and returns the correct digest with incomplete benign text; Scopeproof's local text classifier then has nothing sensitive to detect. Non-textual sensitive imagery may also evade OCR by design. Conversely, false positives or scanner outage block evidence ingestion because the design intentionally fails closed.
- **Potential impact:** Before remediation: sensitive-data ingestion/disclosure, poisoned compliance records, false safety attestations, incident-notification obligations, and loss of trust. Residual impact includes the same confidentiality/integrity outcome if the external scanner or OCR policy fails, disclosure of raw screenshots to the scanner operator, and capture availability loss during scanner faults.
- **Recommended fix:** Preserve the exact pre-storage scan, canonical receipt recomputation, and all universal screenshot gates. Operate the scanner under separate security administration with an approved data-processing agreement, region, no-retention/log-redaction policy, least-privilege token rotation, availability SLO, canaries, and incident response. Pin approved policy versions or enforce monotonic policy upgrades. Add scanner-authenticated responses—prefer mTLS plus a pinned scanner signing key over relying on bearer/TLS alone—and preserve a signed response digest in the receipt. Use a seeded secret corpus, image-only sensitive-content cases, and recurring human sampling to measure false negatives/positives; do not market OCR as proof that pixels are harmless.
- **Example secure implementation / patch guidance:** Keep `scanExactEvidencePixels(image, env)` before any R2/D1 write. Extend the strict scanner response with a nonce/request ID, issued/expiry times, model/policy identifiers, findings, and a detached JWS/COSE signature over the exact image digest and result; verify with a pinned, rotatable public key and reject unapproved/rolled-back policies. Store the scanner-signed response digest alongside the existing canonical receipt. If availability requirements later require asynchronous scanning, persist only to an isolated quarantine object path and keep metadata, preview, approval, Jira, and export inaccessible until the same receipt checks pass. Existing pre-0023 screenshots should remain `pending` and be recollected rather than administratively backfilled as passing.
- **Tests/validation:** Existing unit/contract coverage in `tests/image-safety.test.ts`, `tests/security-hardening-wave.test.ts`, and `tests/security.test.ts` verifies exact-host/digest behavior, seeded sensitive text, mismatched digest rejection, receipt binding, migration columns, and source gates. Add route/database integration tests proving no R2/D1 persistence on sensitive, unavailable, malformed, oversized, redirected, or digest-mismatched scans; prove every pre-0023, native, Browser Rendering, and other screenshot without a valid canonical receipt is listed pending and rejected by read, approval, package selection/final publication, and Jira. Exercise policy rollback, token/key rotation, signed-response replay, compromised-scanner text omission, OCR false negatives/positives, image-only secrets, privacy/log retention, timeout/load behavior, and operational canaries against the actual deployed scanner. No live scanner or AWS environment was validated in this review.
- **CWE/OWASP:** CWE-602 (Client-Side Enforcement of Server-Side Security), CWE-345 (Insufficient Verification of Data Authenticity), CWE-200 (Exposure of Sensitive Information), OWASP API10:2023 (Unsafe Consumption of APIs)

### SP-05 — Native evidence could become trust-bearing before its device-chain link finalized

- **Severity:** Medium
- **Confidence:** High
- **Classification/status:** Confirmed pre-fix transactional/provenance gap; **remediated in the current source**. Deployed D1/R2 fault injection remains residual validation.
- **Affected files/functions:** `app/api/native/evidence/route.ts` (`POST`), `lib/server/devices.ts` (`reserveCaptureDeviceChain`, `finalizeCaptureDeviceChain`), `lib/server/evidence.ts` (`storeEvidence`), `lib/server/native-provenance-reconciliation.ts`, `lib/server/jobs.ts`, review/export eligibility queries
- **Description:** Native upload necessarily reserves the device chain, stores encrypted R2/D1 evidence, and only then inserts the immutable native link and advances the head. A process interruption can leave an artifact without the final link. The current source treats that intermediate record as provenance-pending and fails closed across trust-bearing workflows rather than representing it as verified evidence.
- **Evidence from code:** `listEvidence` derives `native_provenance_status='pending'` unless an exact link matches artifact/device/image digest/manifest digest/chain sequence/event hash/pinned provenance key. `readEvidenceBytes` returns 409 for pending native evidence. `approveEvidence` repeats the exact finalized-link predicate both before and inside the approval CAS. `buildAssessorPackage` excludes and explicitly rejects pending native artifacts, repeats the predicate in selection and final publication, and the Jira path requires an exact link. `finalizeCaptureDeviceChain` atomically inserts the link and advances the head; migration `drizzle/0022_native_provenance_quarantine.sql` adds immutable sequence/event/key fields, a per-device sequence uniqueness constraint, and no-update/no-delete triggers. Migration `drizzle/0028_native_reconciliation_cursor.sql` adds a sparse due-work queue and revision-CAS-protected independent circular pending/orphan cursors. Each scheduled `reconcileNativeProvenanceOrphans` invocation examines at most 25 expired reservations and, separately, at most 25 due queue entries. It validates the exact expired reservation, pinned P-256 identity, chain successor, source, image/manifest digest, safety receipt fields, timestamp, owner/device status, and CAS state before atomically creating the same immutable link and advancing the head. Missing/revoked/mismatched reservations are audited and released without advancing the chain; eligible old unlinked artifacts are audited to `returned` with approvals cleared; finalized, missing, and otherwise terminal queue entries are drained. It never reads or deletes R2 bytes.
- **Exploitation scenario:** An outage or isolate termination occurs after encrypted bytes/metadata commit but before provenance finalization. The row may appear in metadata with a pending label, but preview, approval, Jira, and export fail. An exact retry can idempotently complete finalization; it cannot turn a different artifact or sequence into the reserved event.
- **Potential impact:** The pre-fix impact was incomplete chain-of-custody presented as reviewable evidence. Current residual impact is availability/storage during repeated faults or a failing reconciliation page; pending/returned rows and encrypted R2 objects remain preserved but cannot enter trust-bearing workflows.
- **Recommended fix:** Preserve every finalized-link predicate, migration 0022 immutability constraint, the bounded scheduled reconciler, exact CAS predicates, and the no-R2-deletion quarantine policy. Prove the workflow with deployed fault injection and alert on repeated scheduler failure or growing pending/returned state.
- **Example secure implementation / patch guidance:** Keep reconciliation bound to the exact reserved tuple and the one exact artifact's safety/timestamp facts. Finalize only the next predecessor-bound sequence, otherwise release the exact expired reservation and move old unlinked evidence to the audited `returned` state. Never infer a missing predecessor, advance from partial metadata, restore approval, or delete an unresolved object.
- **Tests/validation:** Inject termination/failure after reservation, after R2 put, after artifact/occurrence commit, and during finalization. Before finalization, list metadata must say pending and preview/approve/Jira/export must fail. Exact retry must finalize once; conflicting retry must fail; expired leases must reconcile/quarantine without sequence skip. Run migration 0022 against populated native-link fixtures and verify update/delete/duplicate-sequence rejection. Preserve repeated-genesis, skipped/duplicate/out-of-order, key-substitution, cross-user session, and concurrent-next-event negative tests.
- **CWE/OWASP:** CWE-345 (Insufficient Verification of Data Authenticity), CWE-362 (Race Condition), CWE-639 (Authorization Bypass Through User-Controlled Key)

### SP-06 — Independent audit-checkpoint delivery lacked receipt authentication

- **Severity:** Medium
- **Confidence:** High
- **Classification/status:** Confirmed pre-fix audit-integrity gap; **remediated in the current source**. The independently administered witness service and monotonic external monitoring remain deployment responsibilities.
- **Affected files/functions:** `lib/server/external-trust-config.ts` (`auditCheckpointEndpoint`, `validateAuditCheckpointConfiguration`), `lib/server/checkpoints.ts` (`deliverCheckpoint`, `verifyExternalReceipt`, `createAuditCheckpoint`, `verifyLatestAuditCheckpoint`), `db/schema.ts` (`auditCheckpoints`), `drizzle/0021_immutable_checkpoint_receipts.sql`
- **Description:** The pre-fix verifier trusted mutable local `external_status` and unverified receipt text. The current implementation requires the allowlisted HTTPS witness to return a strict P-256-signed receipt binding checkpoint digest and sequence. It separately stores a locally signed receipt-binding object and validates the audit anchor, checkpoint object, configured package-signing key, witness signature, receipt-object digest, and receipt binding before accepting the checkpoint.
- **Evidence from code:** `auditCheckpointEndpoint` in `external-trust-config.ts` requires an exact clean HTTPS endpoint/host allowlist, rejects an unsafe optional bearer token, and requires `AUDIT_CHECKPOINT_RECEIPT_PUBLIC_KEY`; `validateAuditCheckpointConfiguration` imports that value as a canonical P-256 SPKI public key before readiness can pass. `deliverCheckpoint` in `checkpoints.ts` permits only six receipt fields, bounds the response, and calls `verifyExternalReceipt`. `verifyLatestAuditCheckpoint` fails unless status is delivered and the D1 anchor/count, R2 checkpoint digest/signature/key, canonical external receipt, pinned witness signature, signed receipt envelope, receipt digest, sequence, and checkpoint ID all agree. Migration 0021 adds receipt digest/signature/object-key columns and update/delete guards.
- **Exploitation scenario:** Before remediation, a database-capable attacker could mark failed delivery as successful or replace receipt text. That edit now fails cryptographic reconciliation. Deletion or substitution causes readiness failure. A remaining rollback concern is operational: a fully rolled-back local database/object view can present an older valid receipt until freshness expires unless an independent monitor compares the witness's monotonic latest sequence.
- **Potential impact:** Before remediation: false independent chronology and masked audit rollback. Residual impact: a bounded rollback-detection delay if the independent witness is not itself monitored and queried by operations.
- **Recommended fix:** Retain the signed-receipt checks and immutable migration. Operate the witness under separate administration and keys, publish/monitor its latest monotonic sequence, alarm on local/witness divergence, and periodically export verification material for assessors.
- **Example secure implementation / patch guidance:** The implemented receipt `{version, checkpointSha256, sequence, receivedAt, receiptId, signature}` is the minimum acceptable binding. A future verifier should optionally query a read-only witness endpoint or transparency log for the latest workspace sequence and require it to be no greater than the local verified head, with outage behavior explicitly defined.
- **Tests/validation:** Modify status/receipt/signature/object/key, delete/reorder rows, substitute a witness key, replay a receipt for another digest/sequence, return extra/oversized/malformed fields, and simulate delivery success followed by DB failure. Verification must fail unless the independent signature and every local/R2 binding agree. Also test monotonic rollback alarms against the deployed witness.
- **CWE/OWASP:** CWE-345 (Insufficient Verification of Data Authenticity), CWE-778 (Insufficient Logging), OWASP A09:2021 (Security Logging and Monitoring Failures)

### SP-07 — Production readiness did not validate every symmetric key's strength

- **Severity:** Medium
- **Confidence:** High
- **Classification/status:** Confirmed pre-fix secure-default/configuration gap; **remediated in the current source**. Key generation and custody still require operational evidence.
- **Affected files/functions:** `lib/server/crypto.ts` (`parseKeyring`, `importAesKey`, `hmac`), `lib/server/readiness.ts` (`productionReadiness`), `.env.example`
- **Description:** The pre-fix parser accepted arbitrary non-empty strings in retained keyrings and readiness checked presence rather than every key. The current parser requires canonical base64, exactly 32 decoded bytes for evidence/secret AES keys, at least 32 decoded bytes for audit HMAC keys, a present active ID, and validation/import of every retained entry.
- **Evidence from code:** `base64ToBytes` round-trips canonical base64. `parseKeyring` decodes and length-checks every JSON and legacy entry. `validateConfiguredKeyMaterial` imports every evidence key and computes an HMAC self-test with every audit key. `productionReadiness` reports a failing `key_material` check on any error and separately verifies the package signing keypair.
- **Exploitation scenario:** Before remediation, an operator could configure a one-character audit secret or malformed inactive AES key and receive a misleading readiness result. Those configurations now fail parsing/readiness before the relevant cryptographic operation proceeds.
- **Potential impact:** Before remediation: brute-forceable audit authentication, future decryption/rotation failure, and false readiness. Residual risk is weak source entropy despite correct length; code cannot prove that a 32-byte value was generated randomly or kept confidential.
- **Recommended fix:** Retain all-key validation. Generate secrets only with an approved CSPRNG or managed secret service, prohibit known/example values, document dual-control rotation, and record generation/custody evidence without recording material.
- **Example secure implementation / patch guidance:** Keep `validateConfiguredKeyMaterial` as a required readiness gate. Add deployment-side secret provenance/rotation-age checks and, where practical, move cryptographic operations to a managed KMS/HSM so the application never receives long-lived key bytes.
- **Tests/validation:** Test empty, one-byte, 16-byte, 31-byte, valid 32-byte, malformed 33-byte AES, invalid/non-canonical base64, missing active ID, malformed inactive key, and mismatched package keypair. Readiness must fail for every invalid case. Separately verify the deployment secret source generated at least 256 bits with a CSPRNG.
- **CWE/OWASP:** CWE-321 (Use of Hard-coded or Weak Cryptographic Key), CWE-326 (Inadequate Encryption Strength), OWASP A02:2021 (Cryptographic Failures)

### SP-08 — Trusted timestamp failure silently downgraded to server time

- **Severity:** Medium
- **Confidence:** High
- **Classification/status:** Confirmed pre-fix fail-open/configuration weakness; **remediated in the current source**
- **Affected files/functions:** `app/api/native/evidence/route.ts` (`POST`), `lib/server/timestamp.ts` (`requestTrustedTimestamp`), `lib/server/readiness.ts`
- **Description:** Before remediation, the upload route caught TSA/verifier failure, recorded a weaker server time, and continued. The current route treats timestamping as required unless explicitly disabled and returns 503 before evidence persistence when no verified result exists. The readiness endpoint now fails—not warns—when the flag is false, malformed, or when required TSA/verifier configuration is incomplete, so lower-assurance operation cannot be represented as production-ready.
- **Evidence from code:** `app/api/native/evidence/route.ts` checks `REQUIRE_TRUSTED_TIMESTAMP !== "false"` and returns before `storeEvidence` when issuance/verification fails. `lib/server/readiness.ts` sets `trusted_timestamp_policy` to `fail` unless the flag is valid and timestamping is required, sets `trusted_timestamp` to `fail` unless TSA/verifier/key settings are complete, and calculates readiness from the absence of failures. `.env.example` defaults the flag to true.
- **Exploitation scenario:** Before remediation, an attacker or outage could block the TSA and cause weaker evidence to accumulate silently. Now strict/default upload stores nothing. An operator may explicitly run a development/lower-assurance capture with the flag false, but readiness remains false and cannot support a production-readiness claim.
- **Potential impact:** Before remediation: chronology repudiation, inconsistent assurance, and misleading compliance claims. Residual impact is availability during TSA/verifier outage and the operational risk of ignoring a failing readiness result.
- **Recommended fix:** Preserve the fail-closed upload and readiness behavior. Alert on timestamp failures, monitor certificate/trust-anchor expiry, rehearse verifier-key rotation, and define whether a separately labeled development-only workflow may intentionally use server time.
- **Example secure implementation / patch guidance:** Keep `REQUIRE_TRUSTED_TIMESTAMP=true` in production secrets and deployment checks. A lower-assurance development mode should be clearly named and isolated from customer evidence; never suppress the failing readiness status or select its artifacts for a trusted-time-required package.
- **Tests/validation:** Simulate TSA timeout/TLS failure, verifier outage, invalid token, wrong digest/nonce/origin, unpinned root, replay, stale/future attestation, expired chain, bad signature, malformed flag, and missing configuration. Default/strict mode must store nothing; every disabled/incomplete policy must return `ready=false`; valid pinned issuance must bind the exact image digest.
- **CWE/OWASP:** CWE-754 (Improper Check for Unusual or Exceptional Conditions), CWE-345 (Insufficient Verification of Data Authenticity)

### SP-09 — AWS implementation covers only a narrow API and remains unvalidated live

- **Severity:** High
- **Confidence:** High
- **Classification/status:** Production release blocker, not a confirmed exposed vulnerability; no AWS deployment exists
- **Affected files/functions:** `infra/aws/cdk/runtime/tenant-api`, `tenant-evidence-read-api`, `tenant-legal-hold-api`, `sign-api-audit-outbox`, `lib/aws-runtime`, `infra/aws/database`, `infra/aws/cdk/lib/tenant-stack.ts`
- **Description:** The source now composes a narrow hardened API—health, identity, upload intent, evidence search/download intent, and legal-hold request/approval—but the complete customer UI, onboarding, membership administration, assessment/review/export/integration/offboarding flows are not migrated. None of the JWT, IAM, Aurora, DynamoDB, S3, GuardDuty, KMS, or recovery behavior has been exercised in a live AWS environment.
- **Evidence from code:** The Lambda router exposes only the listed routes. The CDK application has no approved source-connected customer UI release, and documentation explicitly marks the legacy app as single tenant. AWS tests use contract/unit/template assertions rather than deployed services.
- **Exploitation scenario:** The team interprets passing source tests as production closure, exposes tenant hostnames, then discovers an IAM/KMS/event-shape/transaction discrepancy or falls back to a legacy global route for a missing workflow. Attackers target that mismatch to cross tenants, bypass scanning, or produce invalid evidence state.
- **Potential impact:** Cross-tenant exposure, broken authentication, evidence substitution, unprocessed malware, unavailable legal holds, false audit receipts, and prolonged incident response.
- **Recommended fix:** Keep all customer tenant hostnames and data disabled. Complete the AWS-native customer application and every authorization-sensitive workflow, then deploy a disposable two-tenant staging environment with synthetic data. Treat live negative tests and recovery drills as release gates.
- **Example secure implementation / patch guidance:** Publish an endpoint/role/data-store matrix. Every route must consume the strict `TenantActor`, use a purpose-specific database/IAM adapter, enforce current membership and OAuth scope, bound work, write the durable audit outbox in the business transaction, and have cross-tenant negative tests. Do not proxy missing routes to legacy D1/R2.
- **Tests/validation:** Run the complete plan in section 10 against real Cognito, API Gateway/WAF, IAM/STS, DynamoDB, Aurora PostgreSQL 16, S3 Object Lock, KMS, GuardDuty, SQS/EventBridge, CloudTrail, and recovery resources in two disposable tenants.
- **CWE/OWASP:** CWE-693 (Protection Mechanism Failure), CWE-284 (Improper Access Control), OWASP API1/API2/API5:2023

### SP-10 — Shared AWS control-plane roles and one account retain broad blast radius

- **Severity:** Medium
- **Confidence:** High
- **Classification/status:** Architectural defense-in-depth gap; partially mitigated by purpose-separated roles and per-tenant data planes
- **Affected files/functions:** `infra/aws/cdk/lib/shared-platform-stack.ts`, `tenant-stack.ts`, tenant provisioner runtime, tenant directory/role-assumption adapters in `lib/aws-runtime`
- **Description:** Tenant buckets, keys, databases, secrets, roles, and API functions are separated, but shared registry, provisioning, and deployment identities necessarily reference multiple tenants in one account. Compromise of those privileged components or the account administrator can exceed one tenant's boundary.
- **Evidence from code:** Tenant data roles are purpose-separated and exact-resource scoped, while the shared provisioner/control plane creates and verifies tenant resources across the configured tenant set. Recovery also uses the same AWS account. This is a conscious architecture tradeoff, not a missing predicate in a single handler.
- **Exploitation scenario:** An attacker compromises the provisioner/deployment role or an administrator, alters authoritative tenant mappings or assumes/rewrites multiple tenant roles/resources, then exfiltrates or destroys evidence across customers.
- **Potential impact:** Multi-customer compromise, systemic persistence, KMS/bucket-policy changes, false provisioning state, and broad regulatory notification scope.
- **Recommended fix:** Minimize shared-role duration and privileges, use permission boundaries/SCPs and separate deployment from runtime, require MFA/two-person approval for high-impact changes, and consider account-per-tenant for high-assurance customers. Continuously verify effective policies with Access Analyzer and live deny tests.
- **Example secure implementation / patch guidance:** Move tenant provisioning into a dedicated security account/pipeline with short-lived OIDC sessions, explicit tenant-scoped change sets, immutable approval evidence, and no standing runtime credentials. Add an account-per-tenant deployment option behind the same contracts.
- **Tests/validation:** Compromise-test each role in staging: enumerate/assume cross-tenant roles, read secrets, decrypt with other tenant keys, list/write other buckets, invoke provisioners, and modify directory entries. Capture IAM simulation and CloudTrail evidence.
- **CWE/OWASP:** CWE-250 (Execution with Unnecessary Privileges), CWE-269 (Improper Privilege Management), OWASP A01:2021 (Broken Access Control)

### SP-11 — DynamoDB lifecycle/control-plane changes lack equivalent immutable data-event evidence

- **Severity:** Medium
- **Confidence:** High
- **Classification/status:** Confirmed monitoring/audit gap
- **Affected files/functions:** `infra/aws/cdk/lib/observability-stack.ts`, shared DynamoDB tenant/control table, upload/promotion/recovery coordination in `lib/aws-runtime`
- **Description:** The multi-region CloudTrail records management events and exact tenant S3 data events, but the reviewed trail does not configure DynamoDB table data-event selectors. DynamoDB is authoritative for tenant/domain mappings and parts of upload/promotion/recovery coordination, so item-level changes need business audit events or equivalent independently retained evidence.
- **Evidence from code:** `ObservabilityStack` calls `trail.addS3EventSelector` for ingest/evidence buckets. No DynamoDB data-resource selector appears. The shared table has PITR/deletion protection/global replication, which protects recovery but does not create immutable attribution for every item mutation.
- **Exploitation scenario:** A compromised control-plane credential changes a tenant hostname mapping, upload intent, quota, or recovery projection. Management-event CloudTrail shows API use only where applicable but does not retain the item-level old/new facts needed to prove what changed.
- **Potential impact:** Delayed detection, weak forensics, tenant-routing ambiguity, difficulty proving evidence lineage, and ineffective incident scoping.
- **Recommended fix:** Emit an immutable, KMS-signed business audit event for every security-relevant DynamoDB transition and retain it outside the mutable control table. Evaluate CloudTrail DynamoDB data events or Streams-to-immutable-ledger delivery, balancing cost and sensitive-value redaction.
- **Example secure implementation / patch guidance:** Enable a DynamoDB Stream with `NEW_AND_OLD_IMAGES`, filter to approved security item families, canonicalize/redact, sign with a dedicated KMS key, and write append-only Object-Locked audit objects with sequence/checkpoint reconciliation. Alarm on stream lag or delivery failure.
- **Tests/validation:** Mutate each tenant/domain/upload/promotion/recovery item type, prove an independently retained event contains actor/request/item key and safe before/after digest, and verify gaps/replays/out-of-order delivery are detected.
- **CWE/OWASP:** CWE-778 (Insufficient Logging), OWASP A09:2021 (Security Logging and Monitoring Failures)

### SP-12 — Same-account recovery does not survive account-level compromise

- **Severity:** Medium
- **Confidence:** High
- **Classification/status:** Confirmed resilience/administrative-domain gap; source includes strong cross-region controls
- **Affected files/functions:** `infra/aws/cdk/lib/recovery-stack.ts`, `recovery-support.ts`, `recovery-config.ts`, evidence replication/backfill/reconciliation Lambdas
- **Description:** The source creates a second-region global-table replica, COMPLIANCE-locked recovery vault, cross-region Aurora copies, versioned Object-Locked S3 destinations, backfill, exact-version verification, and freshness alarms. Those resources remain in the same AWS account and administrative domain as primary data.
- **Evidence from code:** Recovery configuration validates a single explicit account and formats all source/destination resource ARNs within it. Documentation acknowledges that same-account recovery does not survive account compromise and that the audit bucket is not cross-region replicated.
- **Exploitation scenario:** An attacker with account-level organization/root/administrator control disables or schedules deletion of keys, changes policies, suppresses alarms, or compromises both primary and recovery resources despite regional separation.
- **Potential impact:** Permanent evidence/key loss, unavailable recovery, destroyed forensic trail, and inability to meet RPO/RTO after a control-plane compromise.
- **Recommended fix:** For high-assurance tenants, use a separately administered recovery/archive account with independent root/MFA/key ownership and restricted write-only replication roles. Replicate immutable audit material and test key-loss/break-glass procedures.
- **Example secure implementation / patch guidance:** Parameterize destination account IDs and trust policies, require organization conditions and external IDs where appropriate, deny source-account principals from deletion/retention bypass, and separate KMS administrators. Preserve COMPLIANCE Object Lock and Vault Lock in the destination account.
- **Tests/validation:** Run quarterly restore/cutover drills, simulate primary account loss and KMS disablement, verify exact bytes/versions/retention/legal holds/audit signatures, and demonstrate target RPO/RTO without primary administrator access.
- **CWE/OWASP:** CWE-284 (Improper Access Control), CWE-693 (Protection Mechanism Failure); resilience/control-plane concentration

### SP-13 — Alert routing and escalation are not proven operational

- **Severity:** Medium
- **Confidence:** High
- **Classification/status:** Operational production gate; infrastructure source partially fails closed
- **Affected files/functions:** `infra/aws/cdk/lib/shared-platform-stack.ts`, `recovery-stack.ts`, `observability-stack.ts`, CloudWatch/SNS/budget/security-event configuration
- **Description:** Production recovery synthesis requires an alert email, and topics/logs are KMS encrypted. However, an email subscription requires out-of-band confirmation, and source configuration cannot prove that a human or incident system receives, acknowledges, and escalates alarms. Non-recovery shared alert paths can still be created without a subscriber in non-production.
- **Evidence from code:** `RecoveryStack` rejects production without `alertEmail` and creates an `EmailSubscription`. No custom resource or post-deploy control verifies `Confirmed` status or publishes/acknowledges a canary. The broader deployment was not run.
- **Exploitation scenario:** Malware promotion, audit backlog, legal-hold reconciliation, backup, denied API, root-use, or cost alarms fire to an unconfirmed/abandoned mailbox while operators assume monitoring is active.
- **Potential impact:** Extended attacker dwell time, missed evidence-integrity failures, uncontrolled cost, failed backup/hold obligations, and weak incident response.
- **Recommended fix:** Require an organization-managed SNS/PagerDuty/Security Hub destination, verify subscription state, send a deployment-blocking canary, and test escalation on a schedule. Alert-delivery health must itself be monitored through a separate path.
- **Example secure implementation / patch guidance:** Add a post-deploy validation script or custom resource that lists exact subscriptions, requires at least one confirmed endpoint, publishes a nonce, and waits for an acknowledgement recorded in the release evidence. Prefer HTTPS incident-routing integrations over a single mailbox.
- **Tests/validation:** Test absent, pending-confirmation, disabled, KMS-denied, throttled, and bounced destinations; then trigger each critical alarm class and record time-to-page/acknowledgement.
- **CWE/OWASP:** CWE-778 (Insufficient Logging), OWASP A09:2021 (Security Logging and Monitoring Failures)

### SP-14 — Compatible-S3 static keys remain an explicit lower-assurance mode

- **Severity:** Low
- **Confidence:** High
- **Classification/status:** Accepted migration/configuration risk; Production profile rejects it
- **Affected files/functions:** `macos/ScopeproofCapture/Sources/ScopeproofCapture/S3CredentialProvider.swift`, `KeychainStore.swift`, S3 settings UI, `docs/S3_STORAGE.md`
- **Description:** Production mode uses short-lived IAM Identity Center or one-hop AssumeRole credentials that remain in memory. Compatible-S3 mode still permits manually entered long-lived access/secret keys stored in the device-only Keychain. This is necessary for some S3-compatible services but expands the impact window of a compromised Mac account.
- **Evidence from code:** The credential provider requires temporary credentials in the Production security profile and documents manual static credentials as “Compatible S3 migration exception only.” Keychain items use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`; preferences exclude secret values.
- **Exploitation scenario:** Malware running in the signed-in user's context or an attacker with unlocked Keychain access steals a long-lived compatible-mode key and uses it until manual rotation/revocation.
- **Potential impact:** Unauthorized evidence reads/writes within the principal's policy, persistent access after device loss, and difficult incident containment.
- **Recommended fix:** Keep the mode visibly non-production, require a dedicated no-console prefix/bucket-scoped principal and permissions boundary, surface key age, and add an operator deadline to migrate to temporary credentials. Never accept root, administrator, or broadly scoped keys.
- **Example secure implementation / patch guidance:** Add a verified principal-policy check where supported, an explicit expiring exception record, and periodic reminders. Prefer brokered short-lived credentials, IAM Roles Anywhere, Identity Center, or a hosted upload-intent API.
- **Tests/validation:** Verify Production rejects static keys; Compatible mode never writes them to preferences/logs/receipts; disconnect deletes Keychain entries; rotation invalidates the old key; and a policy simulator denies all buckets/prefixes except the intended scope.
- **CWE/OWASP:** CWE-522 (Insufficiently Protected Credentials), CWE-613 (Insufficient Session Expiration), OWASP A07:2021 (Identification and Authentication Failures)

### Remediated findings and closure evidence

The following issues were confirmed earlier in the review and are remediated in the current source. They should remain regression tests.

| Title | Original severity / confidence | Affected files/functions and evidence | Exploitation/impact before fix | Implemented fix and validation guidance | CWE/OWASP |
| --- | --- | --- | --- | --- | --- |
| Stored same-origin XSS/content sniffing through evidence | High / High | `app/api/evidence/route.ts`, `app/api/evidence/[id]/route.ts`, `lib/server/evidence-response.ts`, `worker/index.ts` | An authorized uploader could store HTML/SVG and have it execute on the trusted app origin, enabling same-origin API actions/data theft. | Exact passive upload allowlist; only PNG inline; all other content is octet-stream attachment with sandbox CSP, `nosniff`, CORP, no-store. Maintain `tests/evidence-response-security.test.ts` and browser tests. | CWE-79, CWE-434, OWASP A03 |
| Audited CAS could commit a mutation without its audit event | High / High | `lib/server/audit.ts`, `drizzle/0019_audited_cas_guard.sql` | A false postcondition could insert zero audit rows while prior D1 mutations committed, breaking accountability. | Transaction-local guard uses aggregate `total_changes()`, a check constraint, conditional audit insert, and cleanup in one D1 batch. Add runtime concurrency/rollback tests against deployed D1. | CWE-778, CWE-362 |
| Evidence read lacked durable disclosure audit | Medium / High | `app/api/evidence/[id]/route.ts` | Authorized users could preview/download sensitive evidence without a durable access event. | Route appends `evidence.previewed`/`evidence.downloaded` before returning decrypted bytes and fails closed on audit failure. Test D1 failure and no-response behavior. | CWE-778, OWASP A09 |
| Key-insensitive text redaction missed structured secrets | High / High | `lib/server/redaction.ts`, `lib/server/evidence.ts` | JSON/YAML/XML values under password/token/private-key fields could be persisted when value regexes did not recognize them. | Structural JSON redaction plus bounded key-aware JSON/YAML/XML handling and fatal UTF-8 decoding. Fuzz nesting, duplicate keys, large objects, and escaped names. | CWE-200, CWE-532 |
| Evidence dedupe erased collection freshness/provenance | High / High | `lib/server/evidence.ts`, `db/schema.ts`, migrations 0013/0017/0018 | Identical bytes could suppress a new observation and preserve an old approval/expiry across assessments/systems. | Scoped partial unique indexes, stable replay IDs, immutable occurrence records, latest-occurrence approval projection, and approval reset on genuine new observations. Run concurrent collect/approve/retry tests. | CWE-840, CWE-362 |
| Migration chain used invalid/high-risk table alteration and quadratic backfill | High / High | migrations 0013, 0015, 0017, 0018; `Scripts/preflight_d1_deduplication.sql` | Populated installations could fail upgrade or spend quadratic time rebuilding occurrences. | Rebuild/backfill device/occurrence tables, window-function latest-row calculation, non-unique interim index, exact final indexes, and duplicate preflight. Replay against a production-scale populated 0012 fixture. | CWE-400, CWE-703 |
| Native PNG parser enabled single-request CPU/memory exhaustion | High / High | `lib/server/native-manifest.ts` (`validatePng`) | A valid device could submit large ancillary chunks/highly compressible pixels and exhaust Worker CPU/memory. | Table CRC, 1 MiB ancillary cap, chunk/pixel/compressed/decoded bounds, and streaming inflated-length/filter checks. Benchmark worst-case files under Worker limits. | CWE-400, CWE-409, OWASP API4 |
| Collector/SBOM/audit work amplification | Medium / High | `app/api/sboms/route.ts`, `lib/server/sbom.ts`, `app/api/audit/route.ts`, `lib/server/audit.ts` | Low-privilege users could repeatedly trigger GitHub discovery or 10,000 sequential HMAC verifications. | Permission-gated discovery, 10/hour quota, five-minute cache; reviewer-only five/min audit route and 30-second head-keyed verification cache. Load test across isolates and shared provider quotas. | CWE-400, OWASP API4 |
| Queued work survived requester/collector revocation | Medium / High | `lib/server/jobs.ts`, `lib/server/sbom.ts`, `app/api/users/route.ts` | Revoked users or disabled collectors could continue outbound calls and persistence through queued retries. | Current user permission and collector enabled state are checked during claim and before outbound calls; permanent revoke invalidates devices/Jira. Test revocation at each lease boundary. | CWE-285, CWE-613 |
| Assessment update returned false success under concurrency | Medium / High | `lib/server/assessments.ts` (`updateAssessment`) | Concurrent close/narrow could make an update a no-op while the API/audit claimed success. | Status/`updated_at` CAS, guarded audit postcondition, and 409 on zero changes. Add deterministic concurrent update tests. | CWE-362 |
| Retention/legal-hold race allowed stale decisions | High / High | `app/api/evidence/[id]/retention/route.ts`, `lib/server/retention.ts`, `lib/server/key-operations.ts` | Evidence could become expired/purged during hold creation or collide with rotation/purge. | Conditional hold insert, postcondition/audit guard, rotation/purge leases, pending/previous object reconciliation, exact-version S3 lock checks. Test injected failures between every R2/D1 phase. | CWE-362, CWE-664 |
| Native local evidence/sidecar paths were insufficiently centralized | High / High | `ValidatedEvidenceArtifact.swift` and native consumers | Symlink/hardlink/replacement attacks could make trust-bearing flows read different files than the reviewed artifact. | Central bounded loader with root containment, `O_NOFOLLOW`, regular-file identity/hardlink rejection, exact PNG/digest/lifecycle validation. Keep filesystem race and malicious-link tests. | CWE-22, CWE-59, CWE-367 |
| Unsigned legacy local evidence entered trust-bearing flows | High / High | `LocalProvenance.swift`, `ValidatedEvidenceArtifact.swift`, lifecycle/hold/upload/Jira/export consumers | Locally forged schema-6 manifests/sidecars could be approved, uploaded, held, or exported as authentic. | Schema-7 P-256 signatures and Keychain anchor; schema-6 is labeled “Legacy unsigned · browsing only” and blocked from trust-bearing actions. Existing artifacts must be recaptured. | CWE-345 |
| Local Console session and resource controls were weak | High / High | `LocalConsoleServer.swift`, `LocalConsoleAssets.swift` | Malicious local/web origins could reuse launch state or exhaust loopback connections. | Per-launch one-time URL-fragment nonce, one-time exchange for a separate short-lived in-memory bearer, no localhost authentication cookie, idle/absolute expiry, 32-connection cap, 15-second deadline, strict Host/Origin/fetch metadata, ID-only resolution. Test DNS rebinding, bearer theft/expiry/replay, and concurrent slow clients. | CWE-346, CWE-400, CWE-613 |
| Native S3 trust relied on inventory/key-name association | High / High | `EvidenceLibrary.swift`, `S3StorageService.swift`, `S3ObjectBrowserController.swift` | A self-consistent or name-matching S3 object could be presented as uploaded local evidence without exact provenance. | Schema-4 destination/receipt binding with exact verified KMS posture, exact version/ETag/checksum/account/settings/local-manifest digest, verified paired manifest before PNG preview. S3-only remains unverified. | CWE-345, CWE-639 |
| AWS client-controlled retention and missing upload quotas | High / High | AWS upload-retention policy, issuer, DynamoDB/RDS adapters | Malicious clients could shorten retention or consume costly signing/database/cloud work. | Server-derived retention with DB equality enforcement; atomic tenant/principal minute and daily-new-intent quotas; exact idempotent retry. Live contention/boundary tests still required. | CWE-602, CWE-840, CWE-400 |
| AWS audit and legal-hold receipts were unsigned/placeholders | High / High | `signed-audit-receipt.ts`, audit outbox signer, legal-hold runtime/database | Database writers could invent receipt strings or claim a logical hold without exact S3 protection. | Tenant RSA-3072 KMS signing/verification, immutable outbox/chain procedures, two-person exact-version S3 hold with readback, durable retry/recovery projection. Live KMS/S3/Aurora tests remain required. | CWE-345, CWE-778 |

## 6. Exploitation Chains or Combined-Risk Scenarios

### Chain A — Direct legacy-origin exposure to administrator compromise

1. An operator exposes the Worker/origin outside the private identity dispatcher.
2. The attacker supplies platform identity headers for an existing user or an unclaimed bootstrap administrator.
3. `requireApiUser` trusts the values after only a destination-origin check.
4. The attacker uses valid server RBAC paths to enroll a device, read evidence, alter membership/retention, or export a package.

**Combined risk:** SP-01 plus an origin/network misconfiguration turns a platform assumption into full application compromise. The correct mitigation is network/proxy proof, not more route-level role checks.

### Chain B — Premature multi-tenant launch to systemic customer exposure

1. Multiple customer subdomains are mapped to the legacy Sites/Worker application while AWS UI/routes are incomplete.
2. Each customer authenticates successfully, creating confidence that isolation exists.
3. Global D1/R2 queries return workspace-wide objects because there is no tenant field or predicate.
4. A routine read/export operation discloses other customers' evidence.

**Combined risk:** SP-02 plus SP-09. WAF, Cognito, and subdomains cannot repair a shared global data model.

### Chain C — Compromised endpoint plus ineffective scanner admits sensitive evidence

1. Malware controls an enrolled Mac process and its device signing operation.
2. It submits secret-bearing PNG pixels with a valid schema-8 signature, exact tenant/workspace, correct chain event, and false passing local-safety declaration.
3. Scopeproof sends the exact PNG to the configured scanner before storage, checks the response digest, and runs local sensitive-text rules; endpoint control alone no longer creates a hosted passing receipt.
4. The chain succeeds only if the external scanner is compromised/misconfigured, OCR omits the sensitive content, the approved policy is too weak, or the content is not recognizable text. Scopeproof then creates a locally valid receipt over an incomplete result and permits later review.

**Combined risk:** The source remediation for SP-04 breaks the direct compromised-client chain, but cryptographic provenance plus digest binding still does not prove OCR completeness. Scanner independence, authenticated results, privacy controls, anti-rollback policy, measurable efficacy, operational canaries, and human review must be treated as one control system rather than independent guarantees.

### Chain D — Interrupted native finalization creates availability/reconciliation pressure

1. A valid deployment-matched schema-8 upload reserves the exact next device-chain event.
2. The general evidence store commits encrypted bytes, metadata, and an occurrence.
3. The Worker terminates or D1 finalization persistently fails before the native link and chain-head advance commit.
4. Metadata labels the artifact pending, while byte reads, approval, Jira handoff, and package selection/publication reject it until the exact immutable link exists.

**Combined risk:** The trust-boundary weakness in SP-05 is remediated: partial persistence fails closed instead of becoming evidence, and a bounded audited scheduler now exact-finalizes or returns unresolved state without deleting R2 bytes. Repeated faults can still consume encrypted storage and operator attention, so deployed failure injection, alerting, and storage-growth monitoring remain necessary availability controls.

### Chain E — Shared AWS control-plane compromise defeats regional recovery

1. A deployment/provisioning/account administrator credential is compromised.
2. The attacker alters tenant mappings or policies and accesses multiple per-tenant roles/resources.
3. DynamoDB item-level changes are not equivalently captured in immutable audit evidence, delaying detection.
4. Recovery remains in the same account and administrative domain.

**Combined risk:** SP-10 + SP-11 + SP-12 can convert one privileged compromise into multi-tenant persistence and destruction. Cross-account archives, signed control-plane audit, and strict deployment separation reduce this blast radius.

## 7. Dependency and Configuration Risks

### Dependency and build posture

- Root runtime and development dependencies are exact-version pinned in `package.json`/`package-lock.json`; direct CDK/AWS SDK dependencies are exact-version pinned in `infra/aws/cdk/package.json`/`pnpm-lock.yaml`.
- GitHub Actions are pinned to full commit SHAs, checkout credentials are not persisted, dependency installation disables lifecycle scripts where feasible, and pull requests use dependency review with a moderate-severity and license gate.
- The SHA-pinned Trivy action blocks unsuppressed High/Critical secret and infrastructure-as-code findings before dependencies are installed. Its one path-scoped exception expires on 2026-11-30 and covers a verified CloudFormation `!Ref` parser false positive; contract tests independently require the exact customer-managed CloudTrail key bindings.
- CI generates CycloneDX dependency SBOMs for the Worker and CDK graph. The macOS production workflow generates a release SBOM, provenance, notarization receipt, checksums, and GitHub attestation.
- The reviewed TypeScript Lambdas use self-contained bundling rather than depending on the Lambda runtime's changing SDK version.
- `vendor/image-size` is a local shim and therefore outside normal registry advisory feeds. Its parsing behavior must remain covered by local tests and code review.
- The root `npm audit` and production-only audit were reported clean during this hardening work. This is a point-in-time result, not proof against malicious maintainer releases, compromised registries, unreported flaws, or license risk.

### Configuration and secret-management risks

- Hosted secrets are expected in Sites/runtime secret storage, not source. `.env.example` contains names/placeholders only. No production credential, private key, or bearer token was identified in the working tree or the accessible 77-commit history scan; deployed secret stores were not examined.
- The legacy runtime must have exactly one HTTPS origin, explicit single-tenant acknowledgement, a closed bootstrap procedure, strong CSPRNG-generated keyrings, an independently administered audit witness, trusted timestamping, a fail-closed bearer-authenticated monitoring receiver, and provider allowlists. Current readiness structurally parses the origin and bounded bootstrap-email allowlist instead of checking only presence, and validates key format/length, scanner endpoint/allowlist/token shape, monitoring endpoint/allowlist/required-token shape, witness receipts, and timestamp trust material. SP-01 still depends on the deployed edge contract; witness/monitor operation and secret entropy cannot be proven from source.
- Every hosted screenshot depends on `BROWSER_OCR_ENDPOINT`, `BROWSER_OCR_ALLOWED_HOSTS`, and `BROWSER_OCR_TOKEN`. Source rejects unsafe endpoints and fails readiness/persistence closed, but it cannot prove the scanner operator, token custody/rotation, policy version, regional processing, retention/logging, privacy contract, OCR quality, or availability. The locally hashed receipt is not a scanner signature.
- Production S3 must use temporary credentials; Compatible S3 static keys are a lower-assurance exception. AWS CLI's own Identity Center cache is outside Scopeproof and must be protected with FileVault, screen lock, IdP expiry, and revocation procedures.
- The CDK context deliberately contains no default domain and requires exactly one of an existing hosted-zone ID or an explicit public-zone creation opt-in. Domain ownership, delegation, certificates, exact tenant DNS, and direct-origin denial still must be approved before any deployment.
- Production COMPLIANCE Object Lock and Vault Lock are intentionally difficult or impossible to shorten. Retention days, legal authority, privacy deletion exceptions, and cost must be approved before stack creation.
- An SNS resource or configured email does not prove delivery. Subscription confirmation and end-to-end paging are mandatory release evidence.
- The Mac production signing/notarization workflow exists but was not run here with protected Apple/GitHub credentials. Development-preview/ad-hoc artifacts must not be represented as production-trusted releases.

### Supply-chain recommendations

1. Require lockfile-frozen installation, tests, SAST/CodeQL, dependency review/audit, IaC scanning, secret scanning, SBOM/provenance generation, and signed artifact verification on protected `main`.
2. Add `cdk-nag`, CloudFormation Guard, IAM Access Analyzer, and deployed-policy diffing to complement template assertions.
3. Compare deployed Lambda/web bundle hashes to approved CI attestations and preserve the mapping in immutable release evidence.
4. Establish an emergency dependency-update process with risk acceptance, rollback, and customer notification criteria.
5. Verify GitHub branch protection, required CODEOWNERS review, environment protection, tag/release permissions, and advanced CodeQL status outside source control.

## 8. Secure Design Gaps

- **Two hosted architectures remain.** The legacy console is feature-rich but single tenant; the AWS runtime is tenant-aware but covers only a narrow API. Operating both without a strict migration boundary creates routing and assurance ambiguity.
- **No complete AWS customer lifecycle exists.** Tenant onboarding, membership administration, assessment/review/export, integrations, suspension, offboarding, customer export, key retirement, and destruction certificates are incomplete or remain legacy-only.
- **Native trust remains endpoint-local.** P-256 signatures and a Keychain anchor detect local tampering, but they are not Secure Enclave/MDM attestation or an independent transparency service. A compromised endpoint can still originate malicious pixels, although it can no longer establish the required hosted safety receipt without the independent scanner also accepting those exact bytes.
- **The screenshot scanner is a high-value external trust, privacy, and availability dependency.** Source now scans native and Browser Rendering pixels independently and fails closed, but the response is not scanner-signed, raw screenshots cross an external boundary, and OCR/DLP is probabilistic. Compromise, policy rollback, omission, false negatives, false positives, outage, retention, or logging behavior cannot be resolved by receipt digest binding alone.
- **The checkpoint witness is an external system.** Signed witness receipts are now verified and immutably bound in source, but separate administration, monotonic-sequence monitoring, availability, retention, and key-rotation evidence cannot be delivered by this repository alone.
- **Native pending-state cleanup is implemented but not operationally proven.** The source now labels and fails closed on pending provenance and runs a bounded audited reconciler/quarantine pass, but D1/R2 crash-point tests, scheduler alerting, storage-growth monitoring, and operator drills remain live-environment gates.
- **Privacy governance is incomplete.** The code enforces technical retention/holds, but customer-specific classification, residency, legal basis, data-subject handling, deletion certificates, breach workflow, and retention exceptions require product and policy design.
- **High-privilege administrative workflows need stronger dual control.** AWS exact-version holds use two people, but tenant provisioning, role changes, key administration, retention policy, support access, offboarding, and destructive recovery actions need comparable policy where risk warrants.
- **Account-level security controls are not packaged.** SCPs, permission boundaries, AWS Config, Security Hub, account GuardDuty/Inspector, Access Analyzer, break-glass controls, and organization-level logging remain outside the templates.
- **Live assurance evidence is absent.** Unit/template tests cannot prove cloud-service semantics, Apple release trust, alert delivery, recovery, or direct-origin isolation.

## 9. Recommended Remediation Roadmap

### P0 — Before any production/customer exposure

1. Prove private dispatcher header stripping/injection and deny every direct Worker/preview/origin route; remove bootstrap after a witnessed first-admin ceremony.
2. Keep the legacy runtime single tenant. Do not route AWS customer hostnames or multiple customers to it.
3. Preserve the independent pre-storage screenshot scan and universal read/approval/package/Jira receipt gates. Before customer use, approve the scanner's security/privacy/region/retention contract, pin acceptable policy versions, add authenticated scanner responses, and prove false-negative/false-positive performance, fail-closed behavior, canaries, rotation, and outage handling in a staging deployment.
4. Preserve the bounded native orphan reconciler and prove its exact-finalize, conditional-loser, audited-returned, no-deletion, and pending-state fail-closed behavior with deployed D1/R2 fault injection.
5. Preserve the fail-closed trusted-timestamp upload/readiness policy and add operational alerting/rotation/expiry monitoring for the TSA verifier path.
6. Operate the external checkpoint witness under separate administration and alert on monotonic local/witness divergence.
7. Preserve the package occurrence/revision fence, schema-8 tenant/workspace/signature/key/session/chain checks, migration 0022 immutable native links, migration 0023 universal screenshot receipts, migration 0028 bounded reconciliation queue/cursors, immutable signed witness receipts, and all-key readiness self-tests as release-blocking regressions.
8. Do not deploy AWS customer data yet. Complete missing AWS customer workflows and deploy only a disposable two-tenant staging environment for the section 10 test matrix.

### P1 — Before a production pilot

1. Run live Cognito/JWT/revocation, IAM/STS, Aurora/RLS/procedure, DynamoDB quota/CAS, S3 Object Lock/GuardDuty/promotion, KMS receipt, legal-hold, and exact-version download tests.
2. Add immutable security audit for DynamoDB control-plane mutations and reconcile it with business/KMS audit heads.
3. Prove at least one confirmed incident destination with canary acknowledgement and escalation.
4. Complete Mac hosted OAuth/discovery/device enrollment and verify refresh rotation/reuse/revocation against deployed Cognito.
5. Run the protected Developer ID/notarization/attestation workflow on an approved commit; require all CodeQL/security checks and verify update rollback protection.
6. Add customer data classification, retention approval, residency, support-access, incident-response, and offboarding runbooks.

### P2 — Before general availability/high-assurance customers

1. Offer account-per-tenant or at least cross-account immutable recovery/audit archives with independently administered keys.
2. Package organization-level SCPs, permission boundaries, Config/Security Hub/GuardDuty/Access Analyzer controls and test break-glass access.
3. Demonstrate target RPO/RTO through restore/cutover drills, exact evidence/package verification, and primary-account-loss exercises.
4. Add continuous tenant-isolation tests, deployed artifact attestation checks, recurring key/retention/alert drift detection, and adversarial cost/load tests.
5. Obtain independent penetration testing and compliance/legal review focused on evidence admissibility, privacy, retention, and customer contracts.

## 10. Security Test Plan

### Authentication and session management

- Forge, duplicate, omit, case-fold, and append platform identity headers through public, preview, and direct origins.
- Exercise bootstrap races, invitation expiry/replay/revocation, suspended/revoked users, final-admin protection, session termination, and dependent credential invalidation.
- Test Cognito tokens with wrong issuer, audience/client, `token_use`, scope, tenant host, subject, `kid`, algorithm, key size, signature, `iat`/`nbf`/`exp`, duplicate JSON fields, and revoked membership.
- Test JWKS redirect, oversize, cache rotation, outage, unknown key refresh, and hostile cache headers.
- Test Mac OAuth state/nonce/PKCE replay, callback hijack, cancellation, token rotation/reuse, sign-out, Keychain corruption, and device loss.

### Authorization and tenant isolation

- Maintain two live synthetic tenants with distinct users, roles, databases, secrets, buckets, keys, app clients, and objects.
- Build a role × endpoint × state matrix covering list/read/create/update/delete/search/export/admin/device/integration/retention/hold actions.
- Swap hosts, tenant IDs, user/membership IDs, device IDs, assessment/evidence/package IDs, cursors, database roles, role ARNs, bucket/key/version IDs, and presigned URLs.
- Verify every deny at HTTP, database, IAM, KMS, and CloudTrail levels; ensure errors do not disclose existence across tenants.

### Input validation, injection, parsing, and outbound requests

- Fuzz JSON depth/width/duplicate keys/Unicode/control characters, multipart boundaries, content types, filenames, URLs, refs, timestamps, IDs, SQL parameters, XML entities, CSV cells, ZIP records, lockfile grammar, PNG chunks/CRC/filter/decompression, and provider pagination.
- Confirm all SQL values remain bound and deploy-time identifiers are allowlisted; run SQL injection payloads through every request field.
- Attempt SSRF through source URLs, provider origins, redirects, pagination links, Jira/OCR/TSA/checkpoint endpoints, DNS rebinding, alternative IP formats, userinfo, ports, and encoded host/path separators.
- Confirm no parser executes repository code, subprocesses, templates, shell interpolation, dynamic imports, or unsafe deserialization.

### Evidence lifecycle and concurrency

- Race occurrence insertion against approval, package selection, assessment close/narrow, expiry, hold, purge, and key rotation.
- Inject failure before/after every D1/R2 mutation, audit insert, key switch, old-object delete, package upload, and checkpoint delivery.
- Verify stable retry identity, no duplicate occurrence on exact replay, approval reset on genuine observation, partial-coverage behavior, and orphan cleanup/reconciliation.
- Prove a disclosure is never returned if audit append fails.
- Validate every exported file digest/signature independently and reject a package if any selected occurrence changes.

### Screenshot safety and external scanner

- Exercise native upload and Browser Rendering with safe PNGs, seeded API keys/tokens/PAN/private-key text, text-free sensitive imagery, obfuscated/low-contrast/rotated text, multiple languages, and deliberately adversarial OCR samples. Establish and approve false-negative/false-positive thresholds rather than assuming a passed OCR result means harmless pixels.
- Reject missing endpoint/token/host allowlist, HTTP, userinfo, port, query/fragment, IP literal, localhost, unapproved host, redirects, DNS rebinding, TLS failure, timeout, 429/5xx, non-JSON, duplicate/extra fields, invalid UTF-8, oversized response/text, digest mismatch, invalid/rolled-back policy, and replayed/signed result. Assert no evidence object, metadata, chain reservation, timestamp, approval, package, or Jira disclosure is created on failure.
- For every native, Browser Rendering, historic pre-0023, and otherwise created screenshot row, remove or alter each of digest, policy, completion time, scanner origin, and receipt hash. Assert the canonical receipt is recomputed, list status is pending, and byte read, approval CAS, package eligibility/selection/final publication, and Jira handoff all fail.
- Compromise-test the scanner contract: return the correct digest with intentionally omitted sensitive text, stale/weaker policy, incorrect model identity, and a valid-looking replay. Add mTLS/scanner-signature tests when implemented and verify key rotation, expiry, revocation, nonce binding, and policy anti-rollback.
- Verify the scanner provider does not retain or expose exact screenshots, bearer tokens, OCR text, or customer metadata in application/provider logs; test regional routing, deletion, incident notification, rate/cost limits, canary alerting, and recovery during scanner outage. No such operational proof was available in this source-only review.

### Native client and Local Console

- Test symlink, hardlink, rename/replace, traversal, alternate root, oversized file, malformed PNG/JSON, digest mismatch, missing lifecycle, forged hold, and unsigned legacy artifacts across every action.
- Verify schema-6 and older remain visibly unverified and browse-only; signed schema-7 remains locally trust-bearing under its earlier lifecycle contract but cannot cross the current hosted tenant/workspace boundary; and signed schema-8 evidence with the exact configured tenant/workspace is required for current hosted upload and hosted trust-bearing workflows.
- Submit forged local safety claims, repeated genesis, skipped/duplicate/out-of-order sequences, key substitution, and foreign session IDs to the hosted endpoint. A false local claim must never bypass the independent exact-image scan.
- Inject faults after native chain reservation, R2/D1 artifact persistence, and during link finalization; pending metadata must remain visible only as pending, while bytes/approval/Jira/export fail. Verify exact retry finalizes once, conflicting retry fails, orphan cleanup is bounded/audited, and migration 0022 rejects link mutation/deletion/duplicate device sequence.
- Test Local Console DNS rebinding, wrong Host/Origin/fetch metadata, stolen/expired/replayed bearer, replayed launch nonce, slowloris, excessive connections, oversized headers/body, and arbitrary ID/path/key input. Confirm that no localhost authentication cookie is created.
- Verify source URLs persist origin only and no secret appears in logs, receipts, index, crash reports, or browser payloads.
- Exercise CryptoKit-to-Worker schema-8 provenance signatures across canonical DER scalar widths, including short magnitudes that require a leading `00` sign octet; accept canonical signatures and reject redundant or missing padding, negative, zero, over-width, invalid-length, and trailing encodings.

### S3, retention, and legal holds

- Test static-key rejection in Production, expired/near-expiry STS, wrong account/principal, unsafe AWS CLI executable/profile, credential process/source/web-identity/role chaining, and SSO logout/revocation.
- Verify Block Public Access, ownership, versioning, exact encryption/KMS context, bucket policy, lifecycle, replication, expected owner, checksums, object versions, retention, and legal-hold readback. Negative-test cross-account/partition/Region KMS ARNs, denied `DescribeKey`, AWS-managed/asymmetric/signing/disabled/pending-deletion keys, and every non-COMPLIANCE Production configuration.
- Attempt redirects, alternate endpoints, path-style confusion, cross-prefix listing, version substitution, ETag/checksum mismatch, duplicate versions, oversized download, and partial-file commit.
- For AWS promotion, test wrong/missing nonce digest, metadata/header/context, MIME, size, checksum, version, GuardDuty tag/event, out-of-order/duplicate queue delivery, stale worker takeover, copy/DB partial failure, and DLQ redrive.
- For legal hold, test same-user approval, digest/version substitution, expiry, concurrent request/release, exact S3 readback mismatch, KMS signing failure, recovery-publication failure, and retry/dead-letter behavior.

### Cryptography, audit, and key management

- Reject malformed/weak/non-canonical keys and self-test every active/retained AES, HMAC, Jira, cursor, package, native, KMS, and update key.
- Verify AES-GCM associated data, IV uniqueness, digest checks, key rotation leases, pending/previous object reconciliation, and safe retirement only after reference scans.
- Tamper with every audit field, reorder/delete events, race appenders, force audit-condition failure, exceed verification limits, rotate HMAC/KMS keys, and verify from a trusted checkpoint.
- Tamper with checkpoint status/receipt/object/sequence/key and prove only an independently signed external receipt can establish an anchor after SP-06 remediation.

### Availability, abuse, and cost

- Benchmark worst-case PNG/ZIP/JSON/XML/collector responses under Worker and Lambda memory/CPU limits.
- Load-test per-IP, per-principal, per-tenant, and provider quotas behind shared NAT; verify atomic behavior at limit−1/limit/limit+1 and during window rollover.
- Exercise retry storms, poison jobs, lease expiry, rate-limit table growth/cleanup, GitHub/OCR/TSA outages, KMS throttling, Aurora cold start, DynamoDB hot partitions, SQS backlog, and budget alarms.
- Confirm partial collection is explicit and never approvable/exportable as complete.

### Cloud, CI/CD, and recovery

- Run `npm ci --ignore-scripts`, lint, full Node tests/build, migration replay from populated fixtures, Swift tests/build, CloudFormation tests, CDK compile/test/synth, dependency audits, secret scan, CodeQL, SBOM generation, and IaC analysis.
- Verify protected branch/CODEOWNERS/environment controls, exact commit release gating, ephemeral Keychain cleanup, Developer ID signing, hardened runtime/entitlements, notarization/stapling/Gatekeeper, checksums, attestations, and updater rollback protection.
- Validate CloudTrail file digests/Object Lock, S3/DynamoDB data evidence, WAF redaction, log secret exclusion, alarms, SNS acknowledgement, and incident escalation.
- Restore/cut over a tenant from cross-region evidence and Aurora backup, verify exact versions/metadata/holds/signatures/audit chronology, and demonstrate RPO/RTO with primary services unavailable.

## 11. Open Questions and Assumptions

1. What exact Sites/Cloudflare contract guarantees identity-header stripping and injection, and how is direct Worker/preview access denied?
2. Has the one-time bootstrap administrator already been claimed and removed from routine operational dependency?
3. Will any deployment ever serve more than one customer from the legacy D1/R2/key boundary? The answer must remain no.
4. Which AWS account/organization model will be used, and which customers require account-per-tenant or cross-account recovery?
5. Which owned domain/hosted zone will be supplied to the deliberately empty CDK context, and who approves DNS/certificate/origin changes?
6. What are the approved customer retention periods, Object Lock mode, legal-hold authority, privacy deletion exceptions, and residency requirements?
7. Is independent RFC 3161 time mandatory for production evidence, or is server-signed time an explicitly lower assurance tier?
8. Which independently operated service will scan native and Browser Rendering screenshots? Who approves its raw-pixel data-processing agreement, regional processing, logging/retention, availability SLO, policy/model versions, false-negative threshold, canaries, and incident response; when will mTLS or scanner-signed responses replace TLS-origin-only result trust?
9. What device identity assurance is required: software P-256 key, Secure Enclave, MDM certificate/attestation, IAM Roles Anywhere, or user-only OAuth?
10. Who owns and independently retains the audit-witness key/receipt store? How are rollback, outage, compromise, and key rotation handled?
11. Which product events require KMS-signed AWS audit receipts beyond uploads and legal holds, and how will customers/assessors independently verify them?
12. What complete AWS route/UI migration plan prevents fallback to legacy global routes for assessments, reviews, packages, integrations, users, devices, and offboarding?
13. What exact GuardDuty malware event/tag behavior is observed in the target account and region? No live contract was captured in this review.
14. Which principals can administer KMS, bucket policies, retention, tenant mappings, provisioners, database owners, support access, and recovery? Which require dual approval?
15. What provider/data-volume limits are expected for the largest customer, and what behavior is acceptable when a safe collection budget is exceeded?
16. What is the authoritative data-deletion/offboarding process, including key retirement, exports, legal holds, backups/replicas, logs, and destruction certificates?
17. What are the target RPO/RTO and incident-notification objectives, and who acknowledges the required canary and quarterly recovery exercises?
18. Have GitHub branch protection, advanced CodeQL, production environment reviewers, Apple signing credentials, and release permissions been configured and independently reviewed?
19. Has repository history, release assets, deployed logs, secret stores, and developer workstations been scanned for prior credential exposure? This review checked source structure, not every historical/external store.
20. Which external assessor requirements define acceptable provenance, timestamp, signature, SBOM format, evidence freshness, and package-verification procedures?

### Release decision

**Do not deploy the AWS stack to production or onboard customer data yet.** The safest next milestone is to prove SP-01 at the actual private edge, preserve the SP-03/SP-04/SP-05/SP-06/SP-07/SP-08 regression gates, operationally validate the independent screenshot scanner and native orphan handling, and deploy the AWS target only to a disposable two-tenant staging account with synthetic evidence. Production approval should require the complete negative authorization matrix, scanner privacy/efficacy/availability evidence, live promotion/legal-hold/audit/alert/recovery drills, a notarized protected release, and documented customer data-governance decisions.

For the AWS-specific historical baseline and detailed remediation addendum, see [AWS_SECURITY_REVIEW.md](AWS_SECURITY_REVIEW.md). For the intended architecture and operating controls, see [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), and [PRODUCTION_OPERATIONS.md](PRODUCTION_OPERATIONS.md).
