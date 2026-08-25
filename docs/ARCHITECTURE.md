# Scopeproof architecture

## System overview

Scopeproof combines a private Cloudflare-hosted evidence console with a local macOS capture application.

| Component | Responsibility |
| --- | --- |
| React/vinext web console | Evidence review, collector and SBOM operations, capture-device enrollment, role administration, audit status, and package export. |
| Cloudflare Worker API | Authentication enforcement, RBAC, input validation, collection/SBOM jobs, bounded lockfile parsing, redaction, encryption, audit events, device uploads, and signed exports. |
| D1 | Users, devices, sessions, collector and SBOM job state, evidence metadata, lifecycle status, package metadata, and append-only audit events. |
| R2 | AES-256-GCM encrypted evidence objects and encrypted assessor packages. |
| Provider collectors | Bounded read-only collection from AWS, GitHub, Okta, Cloudflare, and Cloudflare Browser Rendering. |
| Scopeproof Capture | Explicit ScreenCaptureKit capture, local Vision OCR/redaction, visible stamping, manifests, lifecycle records, loopback Local Console, native search, direct S3 storage, Jira handoff, and local package export. |
| Local Console / SQLite | A `127.0.0.1`-only authenticated browser UI and rebuildable metadata index for local overview, search, preview, filtering, review, and HMAC-authenticated audit events. |
| macOS Keychain | Native device token, expiring S3 credentials, verified S3 account/destination binding, local-console audit key, and device-bound local package signing key. |
| Jira Cloud OAuth | User-consented issue lookup and explicit evidence attachment through Atlassian’s fixed API gateway. |

## Trust boundaries

1. **User and browser → private Sites application:** the private Sites dispatcher strips untrusted identity headers and supplies authenticated values. APIs consume them only on an exact configured canonical origin, validate identity syntax, enforce server-side capability checks, and require same-origin proof for mutations. Direct Worker/preview origins are not trusted web entry points.
2. **Worker → provider APIs:** hosted secrets authorize bounded evidence reads. Provider data is untrusted input and is scanned before encrypted persistence.
3. **Worker → D1/R2:** D1 holds metadata and digests; R2 holds ciphertext. Encryption uses artifact-specific IVs and authenticated associated data.
4. **macOS screen → Scopeproof Capture:** ScreenCaptureKit provides pixels only after macOS permission and an explicit user action. Unreviewed pixels stay in memory; local OCR covers source pixels, the rendered header, and the exact final encoded artifact before persistence.
5. **Browser → native Local Console:** an ephemeral launch URL establishes an HttpOnly SameSite session. The server binds only to `127.0.0.1`, validates the exact Host/Origin/Fetch Metadata boundary, accepts no filesystem paths, and resolves artifacts exclusively by validated evidence ID.
6. **Mac → native upload endpoint:** a revocable bearer token identifies the device and HMAC-authenticates the exact manifest/image digest pair. The server derives metadata only from the versioned manifest and strictly validates PNG structure, decompression bounds, dimensions, digest, and capture-chain consistency before storage.
7. **Scopeproof → assessor/Jira:** exports leave the system through an operator-controlled handoff. Hashes, signatures, visible stamps, and package instructions support independent verification, but destination authorization remains an organizational responsibility.
8. **Scopeproof → Atlassian:** the hosted service exchanges OAuth codes, encrypts rotating tokens with a Jira-specific key, resolves the consented cloud ID, and calls only `api.atlassian.com`. A user/device may access only its own connection and configured project allowlist. The Mac sends approved evidence to Scopeproof, never Atlassian credentials.
9. **Worker → GitHub repository archive:** managed mode accepts a repository only from the configured organization. One-time mode accepts only an exact HTTPS `github.com/owner/repository` URL and a request-scoped token. Both resolve the requested ref through `api.github.com` and follow an archive redirect only to `codeload.github.com`. The archive and every selected manifest are attacker-controlled. The Worker applies byte, entry, decompression-ratio, manifest, UTF-8, and component limits and parses recognized lockfiles without executing repository content. One-time tokens are never persisted or included in audit details.
10. **Mac → AWS STS/S3:** production configuration resolves the caller account through STS, verifies same-account bucket posture, and binds that exact configuration in Keychain. The app generates only regional S3/STS or FIPS endpoints, rejects redirects, and signs expected-owner requests with SigV4. New buckets can receive Block Public Access, ownership enforcement, KMS/DSSE, Object Lock, TLS/KMS policy, Deep Archive, and replication configuration. PUTs require returned SHA-256, encryption, KMS key, and version IDs. Browsing uses `ListObjectVersions`; explicit PNG/JSON downloads bind the version and ETag, validate content/checksum/size, receive quarantine metadata, and commit atomically from a private temporary file. Compatible S3 accepts a long-lived key only as an explicit migration mode; the documented exception constrains a dedicated principal to one bucket/prefix and S3-mediated KMS context.
11. **GitHub Release → Mac tester:** the development-preview DMG and adjacent checksum are public distribution inputs. The operator must verify both came from the intended release and that the digest matches before installation. This detects altered bytes but, because the preview is ad-hoc signed and not notarized, does not create an Apple-trusted publisher boundary. Production distribution instead requires Developer ID signing, notarization, stapling, and the signed update-manifest verification path.

## Native capture data flow

1. The operator selects a window, scrolling evidence sequence, URL, or display and supplies control context, including an optional full page URL. **Capture Frontmost Browser Window** asks a fixed allowlist of browser bundle IDs for the active tab address only after an explicit action, sanitizes it immediately, and prefills it for confirmation. Failure clears the per-capture URL instead of falling back to stale context. **Open URL & Capture** makes its opened URL authoritative; other capture modes use the operator-confirmed Page URL.
2. ScreenCaptureKit captures pixels into process memory; unreviewed pixels are never written to a temporary file. For scrolling evidence, the operator advances the selected browser window and Scopeproof composes 2–8 equal-sized viewports with explicit numbered dividers. It never performs heuristic overlap deletion, and cancellation or failure discards every intermediate frame.
3. Vision OCR detects supported PAN/credential patterns and masks detected rectangles in memory.
4. Scopeproof adds a header above the redacted pixels with the complete sanitized source URL on a dedicated wrapping line. URL credentials are removed, known-sensitive query values are replaced with `REDACTED`, and a sensitive fragment is replaced before rendering or recording; ordinary path, query, and fragment context is preserved.
5. The composited image is scanned again, then the review workspace permits additional irreversible manual masks.
6. Scopeproof encodes the reviewed PNG in memory, decodes and scans those exact bytes, and fails closed if the scan cannot complete or detects remaining sensitive content.
7. The same verified bytes are atomically written and hashed. The manifest records that digest as both the artifact and safety-scan digest with the policy/version and completion time.
8. Review decisions are recorded in a separate hash-chained lifecycle sidecar.
9. Optional upload returns a signed server receipt. Only Approved evidence is eligible for local assessor export.

Optional S3 storage follows the same saved artifact boundary. The Mac re-decodes the immutable manifest and confirms the screenshot digest, evidence ID, control ID, and filename before uploading the PNG and manifest to `<prefix>/<control>/<assessment-period>/<evidence-id>/`. A schema-2 local receipt binds the verified AWS identity, exact S3 versions/checksums, KMS/retention posture, and request IDs. S3 storage and Object Lock do not alter Scopeproof lifecycle state or make an artifact approved.

## Hosted evidence data flow

1. A scheduled/manual job calls a configured provider or receives an authenticated native upload.
2. Textual evidence is scanned and redacted. Browser Rendering returns one PNG; an allowlisted OCR processor scans those exact bytes and echoes their digest before persistence is allowed.
3. SHA-256 supports integrity checking and source/control de-duplication.
4. Evidence is encrypted with AES-256-GCM and stored in R2. D1 stores the IV, associated metadata, digest, review status, and object key.
5. The material action is appended to the HMAC-authenticated audit chain.
6. A different authorized reviewer loads the actual decrypted bytes, confirms the server-verified digest, records a rationale, and may approve. Approved evidence can then be decrypted transiently for a bounded export, re-hashed, indexed, signed with ECDSA P-256, encrypted again for R2 storage, and made available through an expiring download.

## Repository SBOM data flows

### Hosted assessment evidence

1. A compliance lead or administrator selects an active assessment, repository source, ref, and output format. Managed mode uses a repository in `GITHUB_ORG`; one-time mode parses an exact GitHub URL and validates a short-lived token. Server-side authorization, same-origin checks, request-size validation, assessment/control scope, and a per-user hourly quota are enforced before a job is queued.
2. The Worker resolves the ref to a 40-character commit SHA through GitHub's API, then requests exactly one archive for that commit. It does not clone, check out, build, install, or execute repository content.
3. The Worker validates the ZIP directory before extraction and selects only recognized dependency lockfiles. Parsed components are normalized and de-duplicated by package URL with a hard component ceiling.
4. Scopeproof emits CycloneDX 1.6 or SPDX 2.3 JSON containing repository, commit, source-archive SHA-256, manifest, generator, and component provenance.
5. The result is stored through the ordinary encrypted evidence path and linked to an audited `sbom_jobs` record. A completed prior run for the same repository and assessment supplies a bounded added/removed/changed comparison. Repository identity and credential mode are retained; the credential is not.
6. An independent reviewer inspects and approves the linked evidence. Only approved, unexpired evidence is eligible for an assessor package.

One-time work has `max_attempts = 1`. If the request fails or its lease expires, the job fails closed and requires a new token; scheduled processing cannot reconstruct or reuse the credential.

### Native Mac direct export

1. An operator explicitly opens **Generate Repository SBOM…** and submits an exact GitHub HTTPS URL, a masked short-lived token, a ref, and a format. Input validation rejects other hosts, URL credentials, ports, query/fragment data, encoded path separators, unsafe refs, and malformed credentials.
2. A dedicated ephemeral URL session with no cache, cookies, credential store, or redirects calls only `api.github.com`. It resolves the ref to a 40-character commit, reads the bounded recursive Git tree, and requests only recognized lockfile blobs by validated Git object ID.
3. The Mac validates response, tree, manifest, UTF-8, aggregate-size, and component limits; parses the lockfiles in-process; and never invokes a subprocess, archive extractor, package manager, build tool, or repository source file.
4. The generator emits CycloneDX 1.6 or SPDX 2.3 with repository, immutable commit, manifest-set SHA-256, manifest paths, generator, collection method, and component provenance. The operator selects the destination; the app writes JSON and an adjacent checksum with mode `0600`.
5. The token field is cleared at submission and the token is released with the one request. No preferences, Keychain, local index, audit event, log, evidence record, cookie, cache, or retry queue contains it. The output remains a direct export and is not silently promoted into the hosted assessment lifecycle.

## Lifecycle and integrity model

- Capture manifests are immutable records of the final PNG and capture context.
- Local lifecycle schema 2 stores only hash-chained events. Status, owner, reviewer, rationale, tags, supersession, and update time are projections of the final verified event; each event also binds the artifact digest and review/scanner policy versions. Inconsistent or obsolete sidecars are never package eligible.
- Hosted audit events contain the previous event hash, a canonical event hash, and an HMAC. Database triggers block update/delete and reject a stale chain head. State mutations and their required audit insert share one D1 transactional batch, so either both commit or both roll back.
- Package signatures authenticate the canonical manifest with an ECDSA P-256 signing key. The embedded public key enables verification; the fingerprint must be confirmed out of band.
- Hashes and signatures detect alteration. They do not replace source-system access controls, accurate scoping, reviewer judgment, or trusted endpoint security.

## Bounded operations

- Provider inventories, zones, branch-protection checks, URLs, retries, and due jobs are capped.
- Hosted repository SBOMs cap the compressed ZIP at 20 MB, archive entries at 5,000, selected manifests at 100 and 8 MB total, each manifest at 2 MB and 100:1 decompression, unique components at 5,000, generation at ten requests per user per hour, and due-job processing at three jobs per scheduler pass. Native generation caps the Git tree response at 8 MB/5,000 entries, selects at most 100 manifests at 2 MB each/8 MB total, emits at most 5,000 components, and permits one non-retrying run at a time.
- Native screenshot and manifest request sizes are capped and only PNG evidence is accepted.
- Hosted packages contain at most 100 approved artifacts and 25 MB of decrypted evidence and expire after seven days.
- Retry orchestration uses at most three attempts with bounded exponential backoff; authentication and unsafe-content failures do not retry automatically.
