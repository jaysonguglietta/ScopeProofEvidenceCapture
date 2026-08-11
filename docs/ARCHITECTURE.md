# Scopeproof architecture

## System overview

Scopeproof combines a private Cloudflare-hosted evidence console with a local macOS capture application.

| Component | Responsibility |
| --- | --- |
| React/vinext web console | Evidence review, collector operations, capture-device enrollment, role administration, audit status, and package export. |
| Cloudflare Worker API | Authentication enforcement, RBAC, input validation, collection jobs, redaction, encryption, audit events, device uploads, and signed exports. |
| D1 | Users, devices, sessions, collector/job state, evidence metadata, lifecycle status, package metadata, and append-only audit events. |
| R2 | AES-256-GCM encrypted evidence objects and encrypted assessor packages. |
| Provider collectors | Bounded read-only collection from AWS, GitHub, Okta, Cloudflare, and Cloudflare Browser Rendering. |
| Scopeproof Capture | Explicit ScreenCaptureKit capture, local Vision OCR/redaction, visible stamping, manifests, lifecycle records, local search, Jira handoff, and local package export. |
| macOS Keychain | Native device token and device-bound local package signing key. |
| Jira Cloud OAuth | User-consented issue lookup and explicit evidence attachment through Atlassian’s fixed API gateway. |

## Trust boundaries

1. **User and browser → private Sites application:** the private Sites dispatcher strips untrusted identity headers and supplies authenticated values. APIs consume them only on an exact configured canonical origin, validate identity syntax, enforce server-side capability checks, and require same-origin proof for mutations. Direct Worker/preview origins are not trusted web entry points.
2. **Worker → provider APIs:** hosted secrets authorize bounded evidence reads. Provider data is untrusted input and is scanned before encrypted persistence.
3. **Worker → D1/R2:** D1 holds metadata and digests; R2 holds ciphertext. Encryption uses artifact-specific IVs and authenticated associated data.
4. **macOS screen → Scopeproof Capture:** ScreenCaptureKit provides pixels only after macOS permission and an explicit user action. OCR and initial redaction remain local.
5. **Mac → native upload endpoint:** a revocable bearer token identifies the device and HMAC-authenticates the exact manifest/image digest pair. The server derives metadata only from the versioned manifest and strictly validates PNG structure, decompression bounds, dimensions, digest, and capture-chain consistency before storage.
6. **Scopeproof → assessor/Jira:** exports leave the system through an operator-controlled handoff. Hashes, signatures, visible stamps, and package instructions support independent verification, but destination authorization remains an organizational responsibility.
7. **Scopeproof → Atlassian:** the hosted service exchanges OAuth codes, encrypts rotating tokens with a Jira-specific key, resolves the consented cloud ID, and calls only `api.atlassian.com`. A user/device may access only its own connection and configured project allowlist. The Mac sends approved evidence to Scopeproof, never Atlassian credentials.

## Native capture data flow

1. The operator selects a window, URL, or display and supplies control context.
2. ScreenCaptureKit captures pixels into a temporary local PNG.
3. Vision OCR detects supported PAN/credential patterns; detected rectangles are masked.
4. The review workspace permits additional irreversible manual masks.
5. Scopeproof adds a header above the captured pixels containing local date/time/timezone, evidence ID, framework/control, optional Jira key, evidence title/owner, system/environment/period, and source.
6. The final PNG is hashed. A capture manifest and hash-chain event are written beside it; the temporary unredacted PNG is removed.
7. Review decisions are recorded in a separate hash-chained lifecycle sidecar.
8. Optional upload returns a signed server receipt. Only Approved evidence is eligible for local assessor export.

## Hosted evidence data flow

1. A scheduled/manual job calls a configured provider or receives an authenticated native upload.
2. Textual evidence is scanned and redacted; unsafe browser-rendered content is blocked before screenshot persistence.
3. SHA-256 supports integrity checking and source/control de-duplication.
4. Evidence is encrypted with AES-256-GCM and stored in R2. D1 stores the IV, associated metadata, digest, review status, and object key.
5. The material action is appended to the HMAC-authenticated audit chain.
6. A different authorized reviewer loads the actual decrypted bytes, confirms the server-verified digest, records a rationale, and may approve. Approved evidence can then be decrypted transiently for a bounded export, re-hashed, indexed, signed with ECDSA P-256, encrypted again for R2 storage, and made available through an expiring download.

## Lifecycle and integrity model

- Capture manifests are immutable records of the final PNG and capture context.
- Local lifecycle decisions are separate from the capture manifest and hash-chained from `GENESIS`.
- Hosted audit events contain the previous event hash, a canonical event hash, and an HMAC. Database triggers block update/delete and reject a stale chain head.
- Package signatures authenticate the canonical manifest with an ECDSA P-256 signing key. The embedded public key enables verification; the fingerprint must be confirmed out of band.
- Hashes and signatures detect alteration. They do not replace source-system access controls, accurate scoping, reviewer judgment, or trusted endpoint security.

## Bounded operations

- Provider inventories, zones, branch-protection checks, URLs, retries, and due jobs are capped.
- Native screenshot and manifest request sizes are capped and only PNG evidence is accepted.
- Hosted packages contain at most 100 approved artifacts and 25 MB of decrypted evidence and expire after seven days.
- Retry orchestration uses at most three attempts with bounded exponential backoff; authentication and unsafe-content failures do not retry automatically.
