# Development guide

## Repository layout

| Path | Purpose |
| --- | --- |
| `app/` | React/vinext console and API routes. |
| `lib/server/` | Authentication, audit, crypto, collectors, repository SBOM generation, jobs, evidence, devices, timestamps, and packages. |
| `db/schema.ts` | Drizzle/D1 schema. |
| `drizzle/` | Ordered SQL migrations and snapshots. |
| `macos/ScopeproofCapture/` | Swift Package for the macOS menu-bar app, embedded Local Console, SQLite index, and native tests. |
| `infra/aws/cdk/` | AWS-only multi-tenant hosting foundation, tenant resource provisioning, and infrastructure assertions. |
| `scripts/` and `Scripts/` | macOS build entry points retained for compatibility. |
| `tests/` | Rendered-product and security regression tests. |
| `.openai/hosting.json` | Logical Sites project, D1, and R2 declarations. |

## Local web development

Requirements: Node.js 22.13 or newer and npm.

```bash
npm ci
npm run dev
```

Use `.env.example` as the variable inventory. Keep real values in the local/hosted secret mechanism and never commit `.env` files, provider responses, evidence, device tokens, or private keys.

## Validation

Run before every publication:

```bash
npm run lint
npx tsc --noEmit
npm test
./Scripts/verify_migrations.sh
git diff --check
```

`npm test` builds the production Worker bundle, verifies the rendered application/API surface, and runs security regression tests for redaction, audit immutability, native upload validation, assessor packaging, Jira metadata, OAuth boundaries, approved-evidence attachment controls, and bounded non-executing repository SBOM generation.

Native tests:

```bash
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer \
  CLANG_MODULE_CACHE_PATH=/private/tmp/scopeproof-clang-cache \
  SWIFTPM_MODULECACHE_OVERRIDE=/private/tmp/scopeproof-swiftpm-cache \
  swift test --package-path macos/ScopeproofCapture
```

On machines with multiple developer toolchains, select the full Xcode toolchain through `DEVELOPER_DIR`.

### AWS infrastructure validation

The CDK project is deliberately independent from the current Cloudflare application dependencies. It can be built and synthesized without AWS credentials; deployment requires an owned domain, a Route 53 hosted zone, a bootstrapped AWS account, and the migration gates in [AWS multi-tenant hosting](AWS_MULTI_TENANT_HOSTING.md). Use the [AWS platform runbook](AWS_PLATFORM_RUNBOOK.md) for operator commands and the [AWS adversarial security review](AWS_SECURITY_REVIEW.md) for launch blockers; neither document authorizes deploying the legacy web runtime to tenant domains. No AWS resources have been deployed by the current implementation work.

```bash
cd infra/aws/cdk
pnpm install --frozen-lockfile
pnpm run build
pnpm test
pnpm run synth \
  -c deploymentEnvironment=dev \
  -c rootDomain=evidence.example.com \
  -c hostedZoneId=Z0123456789EXAMPLE \
  -c 'recovery={"mode":"disabled"}' \
  -c 'tenants=[]'
```

The checked-in CDK context intentionally leaves `rootDomain` and `deploymentEnvironment` blank. Every synthesis must supply both, the complete tenant array, an explicit recovery object, and exactly one Route 53 mode: an existing `hostedZoneId` (recommended) or the explicit `-c createHostedZone=true` opt-in. Tenant stacks reject missing recovery configuration. `jsontechology.com` is only a planning example; it is not a configured default. Do not deploy any example domain unless the organization controls it. Infrastructure synthesis is not authorization to expose the current D1/R2 application to a second customer; the AWS application, tenant-aware PostgreSQL schema, Cognito membership enforcement, Mac enrollment, and migration/reconciliation work must be complete first.

The checked-in macOS `Info.plist` likewise contains an empty `ScopeproofHostedAPIOrigins` array. Release builds must use `Scripts/configure_macos_release_identity.sh` with one exact pathless `SCOPEPROOF_HOSTED_API_ORIGIN`; unconfigured local release builds remain local-only for HTTPS hosted synchronization. Do not reintroduce a developer, personal, preview, or historical hosted URL as a source default.

The native Local Console is served directly by Scopeproof Capture. It is not the React development server and should remain usable with no hosted environment variables. When changing the console, verify its focused tests, release build, loopback-only listener, per-launch authentication, and unauthorized-request behavior. The unified library may expose normalized display metadata and validated evidence IDs only. Keep filesystem paths, S3 keys/version IDs/ETags, and Keychain credentials inside the native process. S3 previews must remain explicit per-card actions, exact-version/ETag bound, at most 40 MiB, PNG-validated, and removed from private temporary storage after serving.

New native evidence must write only beneath `~/Documents/Scopeproof Evidence`. The known-root compatibility layer may read the legacy `~/Pictures/Scopeproof Evidence` tree, but must resolve symlinks, reject every other path, and prefer the primary Documents copy when an evidence ID exists in both roots. Path changes require native regression coverage plus installation, operator, architecture, security, operations, in-app Help, and changelog updates.

Native S3 changes must preserve generated regional AWS-only endpoints, redirect rejection, temporary-production credentials, expected-owner and destination binding, bounded XML/JSON parsing, KMS/Object Lock/posture checks, returned SHA-256 and version-ID enforcement, exact-version downloads, private temporary files, quarantine metadata, and the 5,000-version/250-MB bounds. Use only synthetic credentials and local request-construction/parser fixtures in tests; never contact S3 with a developer credential.

### Native-to-hosted evidence trust contract

Local-only behavior and hosted ingestion are deliberately decoupled. A Mac must be able to create, browse, review, retain, and export local evidence without `BROWSER_OCR_*`, RFC 3161, D1, R2, or any AWS resource. Do not introduce a hosted availability dependency into local capture.

The hosted native route accepts only the current schema-7 manifest. The canonical unsigned manifest bytes are signed with the Mac's device-only P-256 provenance key; the upload also binds the exact manifest and PNG digests to the audience-bound enrollment credential. Keep the provenance signature, key ID, contiguous `chainSequence`, prior hash, event hash, session scope, dimensions, filename, content types, and final-PNG safety digest in the server validator. Schema-6 and older manifests may remain in an explicit, visibly unverified local browsing/migration path, but trust-sensitive local operations and every hosted upload must fail closed. Tests must prove that unsigned, gap/repeated/out-of-order, bad-GENESIS, mismatched-key, digest-mismatched, and non-canonical manifests are rejected.

Hosted ingestion adds independent controls in this order: validate schema-7 provenance and exact bytes; resolve one active assessment scope; call `scanExactEvidencePixels` on the exact PNG; obtain and verify the required RFC 3161 timestamp; reserve the next device-chain sequence; store the encrypted artifact and scan metadata; then finalize the immutable artifact/manifest/image/event/key link. All downstream read/preview, approval, package/export, and native Jira paths must repeat the scan/finalization eligibility predicate rather than trusting a UI status.

`BROWSER_OCR_ENDPOINT`, `BROWSER_OCR_TOKEN`, and `BROWSER_OCR_ALLOWED_HOSTS` are legacy names retained for configuration compatibility. They now configure the independent server OCR/DLP processor for every hosted screenshot, including native captures. The processor response text is bounded and examined in memory only; never return it from `scanExactEvidencePixels`, place it in evidence/audit/database records, or log it. Persist only the exact digest, policy version, completion time, scanner origin, and receipt digest.

Production readiness must fail if independent scanner configuration is missing or unsafe, if `REQUIRE_TRUSTED_TIMESTAMP` is false/invalid, or if the RFC 3161 issuer/verifier trust material is incomplete. Development may exercise explicit failure fixtures, but must not relabel a readiness failure as production-capable. Replay all migrations through `0023_independent_image_safety.sql`; do not backfill `0022` provenance or `0023` scan fields to make legacy/unbound records eligible. Test recovery by retrying the exact current artifact and proving reconciliation finalizes it without duplicate occurrence multiplication.

## Change discipline

- Preserve server-side authorization; hiding a control in React is not an access-control decision.
- Treat provider content, capture metadata, filenames, Jira values, and package names as attacker-controlled.
- Treat GitHub ZIP structures, Git tree/blob responses, and every lockfile field as attacker-controlled. Do not add repository checkout, command execution, lifecycle scripts, package installation, or an unrestricted archive library path to SBOM generation.
- Use bound SQL parameters and strict size/type limits.
- Never log secrets, decrypted evidence, device tokens, or recognized OCR text.
- Keep original capture manifests immutable; record later decisions in lifecycle/audit records.
- Generate and inspect a forward migration for every D1 schema change. The current ordered migration set runs through `0023_independent_image_safety.sql`; a fresh-database replay and an upgrade replay must both pass.
- Update root, operator, assessor, security, deployment, native, in-app Help, and changelog documentation when behavior or trust boundaries change.

## Extending SBOM support

Add a new ecosystem only when a deterministic lockfile contains pinned versions. Keep hosted and native parser behavior aligned in `lib/server/sbom.ts` and `macos/ScopeproofCapture/Sources/ScopeproofCapture/RepositorySBOMService.swift`; do not invoke the ecosystem's package manager or execute repository-supplied configuration. Preserve the hosted pre-extraction ZIP validation and the native Git tree/blob bounds, recognized-basename allowlists, UTF-8/NUL checks, manifest and aggregate byte limits, component ceilings, package-URL normalization, and immutable commit provenance.

Tests for a parser must cover valid direct/transitive dependencies, duplicate normalization, malformed and oversized input, adversarial names/versions, empty or unpinned manifests, archive traversal-style names, decompression limits, stable CycloneDX/SPDX output, and confirmation that no subprocess or install path is introduced. Update the operator, assessor, security, architecture, deployment, dependency-security, SBOM, and changelog documentation in the same pull request.

Hosted one-time credential changes must preserve exact `github.com` URL parsing, same-origin POST authorization, bounded request size, `Cache-Control: no-store`, masked non-controlled token input, immediate field clearing, absence of browser storage, absence of credential columns/bindings/audit details, one-attempt jobs, and scheduler failure rather than credentialless replay. Native changes must additionally preserve an ephemeral cache/cookie/credential-free session, redirect rejection, API-host restriction, one-run concurrency, no Keychain/preferences/index/audit/log storage, secure file permissions, and no retry. Tests must use obvious synthetic strings and must never call GitHub with a developer token.

## Native release

The current working tree reports bundle version/build `1.10.0`/`24`. It is
**Unreleased**, postdates the public `v1.8.1-development-preview.1` artifact at
`8cd2d5c`, and has no corresponding DMG. Do not rebuild or publish these changes
under the 1.8.1 release identity. Before the next public artifact, re-verify the
allocated version/build, update the changelog/install documentation, and run the
complete release verification path.

Build from the repository root:

```bash
./Scripts/build_macos_capture.sh
```

The app is produced at `DerivedData/Scopeproof Capture.app`. The builder constructs and verifies a fresh staged bundle, then replaces the prior output with a same-volume rename and restores that prior bundle if publication fails; do not replace this with a merge-copy that can retain obsolete resources. `Scripts/run_macos_capture.sh` applies the same staging/verification/rollback rule to `~/Applications` and stops an existing process even with `--no-launch`. Update `macos/ScopeproofCapture/Resources/Info.plist`, `.env.example`, the changelog, and operator documentation together for a new version. Production releases require Developer ID signing, hardened runtime, notarization, stapling, an HTTPS download, and a separately verified digest.

For a clearly labeled ad-hoc testing image, run `./Scripts/build_development_dmg.sh`. It produces a verified drag-to-Applications DMG and SHA-256 file under `DerivedData/`. Never rename or promote that development-preview artifact as a production release.

### Development-preview DMG release

The DMG workflow is intentionally separate from the trusted production updater:

1. Start from the exact reviewed commit and confirm the worktree contains no uncommitted source or generated evidence.
2. Run the complete validation set, including native tests, then run `./Scripts/build_development_dmg.sh` on macOS. Use `--skip-build` only when `DerivedData/Scopeproof Capture.app` was built from the same validated commit in the current job.
3. Confirm the script reports both `DerivedData/Scopeproof-Capture-<version>-development-preview.dmg` and its `.sha256` file. The script requires an ad-hoc signature, creates an `/Applications` shortcut, mounts the image read-only, verifies the bundle signature and disk image, and writes a portable filename-only checksum.
4. Confirm the packaged executable architecture with `file`. A release must state every supported architecture; the 1.8.1 development preview is Apple Silicon (`arm64`) only.
5. Publish both files together as a GitHub **prerelease** tied to the exact reviewed commit. Release notes must state the macOS minimum, architecture, digest-verification command, ad-hoc signature, lack of notarization, Gatekeeper implications, and prohibition on disabling Gatekeeper globally.
6. Download both published assets into a clean temporary folder and run `shasum -a 256 -c <checksum-file>`. Compare GitHub's asset digest and size with the locally validated artifact.

The `scopeproof-macos-development` GitHub Actions artifact is retained for 14 days for CI diagnostics. It is not a durable public release and must not be linked as the user download. The release asset on the GitHub Releases page is the durable tester handoff. Production packaging continues to use `Scripts/publish_release.sh` and must fail closed unless Developer ID identity, hardened runtime, notarization, stapling, update signature, and final-host verification all succeed.

## Publishing checklist

1. Review the complete diff and confirm no evidence or secrets are present.
2. Run web lint, type checking, production build/tests, native tests, and whitespace validation.
3. Replay all migrations into a fresh database and confirm `.openai/hosting.json` packages correctly.
4. Commit the exact validated source.
5. Push to the intended GitHub repository.
6. For hosted-service changes, deploy the same commit to the private Sites project and verify the deployment. Native-only changes do not require a Sites deployment.
7. For native changes, install the exact release build, verify the menu-bar process and Local Console, and record the release outcome.
8. For a development-preview DMG, perform a release-asset round-trip checksum verification and retain the release URL, target commit, asset digest, architecture, CI run, and approver in the release record.
