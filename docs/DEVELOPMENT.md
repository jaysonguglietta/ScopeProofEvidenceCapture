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
npm install
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

The CDK project is deliberately independent from the current Cloudflare application dependencies. It can be built and synthesized without AWS credentials; deployment requires an owned domain, a Route 53 hosted zone, a bootstrapped AWS account, and the migration gates in [AWS multi-tenant hosting](AWS_MULTI_TENANT_HOSTING.md). Use the [AWS platform runbook](AWS_PLATFORM_RUNBOOK.md) for operator commands and the [AWS adversarial security review](AWS_SECURITY_REVIEW.md) for launch blockers; neither document authorizes deploying the legacy web runtime to tenant domains.

```bash
cd infra/aws/cdk
pnpm install --frozen-lockfile
pnpm run build
pnpm test
pnpm run synth
```

`jsontechology.com` is a planning placeholder. Do not deploy it unless the organization controls that exact domain. Infrastructure synthesis is not authorization to expose the current D1/R2 application to a second customer; the AWS application, tenant-aware PostgreSQL schema, Cognito membership enforcement, Mac enrollment, and migration/reconciliation work must be complete first.

The native Local Console is served directly by Scopeproof Capture. It is not the React development server and should remain usable with no hosted environment variables. When changing the console, verify its focused tests, release build, loopback-only listener, per-launch authentication, and unauthorized-request behavior. The unified library may expose normalized display metadata and validated evidence IDs only. Keep filesystem paths, S3 keys/version IDs/ETags, and Keychain credentials inside the native process. S3 previews must remain explicit per-card actions, exact-version/ETag bound, at most 40 MiB, PNG-validated, and removed from private temporary storage after serving.

New native evidence must write only beneath `~/Documents/Scopeproof Evidence`. The known-root compatibility layer may read the legacy `~/Pictures/Scopeproof Evidence` tree, but must resolve symlinks, reject every other path, and prefer the primary Documents copy when an evidence ID exists in both roots. Path changes require native regression coverage plus installation, operator, architecture, security, operations, in-app Help, and changelog updates.

Native S3 changes must preserve generated regional AWS-only endpoints, redirect rejection, temporary-production credentials, expected-owner and destination binding, bounded XML/JSON parsing, KMS/Object Lock/posture checks, returned SHA-256 and version-ID enforcement, exact-version downloads, private temporary files, quarantine metadata, and the 5,000-version/250-MB bounds. Use only synthetic credentials and local request-construction/parser fixtures in tests; never contact S3 with a developer credential.

## Change discipline

- Preserve server-side authorization; hiding a control in React is not an access-control decision.
- Treat provider content, capture metadata, filenames, Jira values, and package names as attacker-controlled.
- Treat GitHub ZIP structures, Git tree/blob responses, and every lockfile field as attacker-controlled. Do not add repository checkout, command execution, lifecycle scripts, package installation, or an unrestricted archive library path to SBOM generation.
- Use bound SQL parameters and strict size/type limits.
- Never log secrets, decrypted evidence, device tokens, or recognized OCR text.
- Keep original capture manifests immutable; record later decisions in lifecycle/audit records.
- Generate and inspect a forward migration for every D1 schema change.
- Update root, operator, assessor, security, deployment, native, in-app Help, and changelog documentation when behavior or trust boundaries change.

## Extending SBOM support

Add a new ecosystem only when a deterministic lockfile contains pinned versions. Keep hosted and native parser behavior aligned in `lib/server/sbom.ts` and `macos/ScopeproofCapture/Sources/ScopeproofCapture/RepositorySBOMService.swift`; do not invoke the ecosystem's package manager or execute repository-supplied configuration. Preserve the hosted pre-extraction ZIP validation and the native Git tree/blob bounds, recognized-basename allowlists, UTF-8/NUL checks, manifest and aggregate byte limits, component ceilings, package-URL normalization, and immutable commit provenance.

Tests for a parser must cover valid direct/transitive dependencies, duplicate normalization, malformed and oversized input, adversarial names/versions, empty or unpinned manifests, archive traversal-style names, decompression limits, stable CycloneDX/SPDX output, and confirmation that no subprocess or install path is introduced. Update the operator, assessor, security, architecture, deployment, dependency-security, SBOM, and changelog documentation in the same pull request.

Hosted one-time credential changes must preserve exact `github.com` URL parsing, same-origin POST authorization, bounded request size, `Cache-Control: no-store`, masked non-controlled token input, immediate field clearing, absence of browser storage, absence of credential columns/bindings/audit details, one-attempt jobs, and scheduler failure rather than credentialless replay. Native changes must additionally preserve an ephemeral cache/cookie/credential-free session, redirect rejection, API-host restriction, one-run concurrency, no Keychain/preferences/index/audit/log storage, secure file permissions, and no retry. Tests must use obvious synthetic strings and must never call GitHub with a developer token.

## Native release

Build from the repository root:

```bash
./Scripts/build_macos_capture.sh
```

The app is produced at `DerivedData/Scopeproof Capture.app`. Update `macos/ScopeproofCapture/Resources/Info.plist`, `.env.example`, the changelog, and operator documentation together for a new version. Production releases require Developer ID signing, hardened runtime, notarization, stapling, an HTTPS download, and a separately verified digest.

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
