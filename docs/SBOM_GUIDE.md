# Repository SBOM guide

Scopeproof can generate an auditor-facing Software Bill of Materials from a GitHub repository in either the native Mac app or the hosted console.

The native Mac workflow is a direct one-time export: it creates CycloneDX or SPDX JSON plus a checksum at a location selected by the operator. The hosted workflow can use managed or one-time repository access and stores the result as encrypted, PCI DSS 6.3.2 assessment evidence with independent review, comparison, audited download, and assessor-package inclusion. A local export is not silently uploaded or treated as approved hosted evidence.

## Choose the workflow

### Native Mac one-time export

Choose **Generate Repository SBOM…** from the Scopeproof shield menu. Enter an exact URL in the form `https://github.com/owner/repository`, a short-lived token selected only for that repository with **Metadata: read** and **Contents: read**, the branch/tag/commit, and the output format. The Mac resolves the ref to an immutable commit, enumerates the bounded Git tree, downloads only recognized lockfile blobs, parses them locally, and asks where to save the JSON and adjacent `.sha256.txt` checksum.

The native token field is masked and cleared at submission. The request uses an ephemeral URL session with no cookies, URL cache, credential storage, redirects, persistence, logging, or retry queue. The token is never written to preferences, Keychain, the Local Console index, evidence files, checksums, or audit records. Scopeproof cannot erase every transient copy from process memory or control endpoint malware, system network inspection, crash collection outside the app, or GitHub access logs. Use a dedicated short-expiry token and revoke it after the run.

Native generation requires no assessment or hosted login. Consequently it does not enforce hosted RBAC or assessment scope, perform prior-run comparison, encrypt or retain the output, create a lifecycle record, request independent approval, or add the file to an assessor package. The operator must validate, classify, retain, approve, and transfer the direct export under organizational policy.

### Hosted assessment evidence

Use the hosted **SBOMs → Generate SBOM** flow when the inventory must be governed as Scopeproof assessment evidence. It supports either the managed organization or a one-time repository credential described below.

## Choose hosted repository access

### Managed organization

Set `GITHUB_ORG` to the one organization operators may inventory. Set `GITHUB_TOKEN` to a GitHub App installation token or fine-grained token limited to the intended repositories with:

- Repository **Metadata: read**, to list repositories and resolve commits.
- Repository **Contents: read**, to download an archive at the resolved commit.

Do not grant write, administration, workflow, issue, or secret permissions. Rotate the credential using the platform secret manager; never put it in the browser, Mac app, repository, or D1.

Apply every migration in journal order through `drizzle/0023_independent_image_safety.sql` before enabling the current application, and run `npm run db:verify` as a deployment preflight. Migration 0012 creates the SBOM job domain; later migrations add the membership, retry-authorization, occurrence/lifecycle, audited mutation, immutable receipt, native provenance/quarantine, and independent screenshot-safety controls used by the surrounding evidence and package workflow. The preflight exercises the populated upgrade path rather than only an empty database. If a GitHub App installation token is used, Scopeproof does not mint or refresh it; an external secret-rotation process must replace the expiring token in Sites. The console labels managed access **Not configured** until both variables are present; one-time access remains available.

### Hosted one-time repository

Choose **One-time repository** in the generation dialog and enter:

- an exact URL in the form `https://github.com/owner/repository` (an optional `.git` suffix is accepted); and
- a short-lived token selected only for that repository with **Metadata: read** and **Contents: read**.

Scopeproof rejects HTTP, other hosts, embedded URL credentials, query strings, fragments, encoded path separators, and extra path segments. The token field is masked and cleared immediately when submitted. The token travels only in the authenticated same-origin HTTPS request, is used in server memory for commit resolution and archive download, and is not written to D1, R2, job rows, evidence, audit details, application logs, settings, browser storage, or the Mac Keychain.

The application cannot control browser extensions, password managers, endpoint malware, upstream network inspection configured by the organization, or GitHub's own access logs. Use a dedicated short-expiry token, decline browser credential saving, and revoke the token after the run. A one-time job receives one attempt and never retries automatically because no reusable credential exists.

The active assessment must include control `6.3.2`. If its system scope is non-empty, it must include the exact `owner/repository`, the owner/organization, or `GitHub`.

## Access model

| Role | View job and linked evidence | Generate | Independently approve | Package inclusion |
| --- | --- | --- | --- | --- |
| Auditor | Yes | No | No | May download an authorized completed package. |
| Reviewer | Yes | No | Yes, when not the evidence creator/uploader | May generate a package from approved evidence. |
| Compliance lead | Yes | Yes | No | May generate a package after independent approval. |
| Administrator | Yes | Yes | Yes, only for evidence generated by another identity | May generate a package after independent approval. |

All authorization is enforced by the API. A disabled button is not the security boundary.

## Generate and review

1. Open **SBOMs** and select **Generate SBOM**.
2. Choose **Managed organization** and select a repository, or choose **One-time repository** and provide the exact URL and short-lived token.
3. Enter a branch, tag, or commit. Scopeproof resolves it to a 40-character commit SHA before downloading content.
4. Choose CycloneDX 1.6 JSON or SPDX 2.3 JSON.
5. Generate the inventory. Review its repository, commit, archive digest, manifests, generator version, component counts, and changes from the prior run.
6. Open the linked evidence, inspect the actual JSON and SHA-256 digest, and have an independent reviewer approve it.
7. Export the assessment package. Approved, unexpired SBOM evidence is included under PCI DSS 6.3.2 like other evidence. Any accompanying native screenshot remains excluded unless its schema-7 P-256 provenance link is finalized on the enrolled device's monotonic chain and it has a matching independent server safety receipt.

The direct **JSON** download is available as soon as generation completes. It is authenticated and audited; approval is required only for inclusion in the assessor package.

Record the assessment ID, repository, requested ref, resolved commit, source-archive SHA-256, generated evidence SHA-256, format, generator version, manifests, component totals, job ID, evidence ID, reviewer, and approval rationale in the workpaper. Deliver the assessor package through the normal approved channel rather than sending a raw GitHub archive.

## Security and operational limits

Scopeproof does not clone a repository or execute repository code, build scripts, lifecycle hooks, package managers, container builds, or dependency installers. The hosted workflow downloads one ZIP from GitHub at the resolved commit and extracts only recognized lockfiles. SBOM JSON is textual evidence and does not pass through the screenshot OCR service; the `BROWSER_OCR_*`-configured independent scanner applies to hosted native and Browser Rendering PNGs, not repository content.

The server enforces a 20 MB compressed archive limit, 5,000-entry limit, 100-manifest limit, 2 MB per manifest, 8 MB total selected manifest data, a 100:1 decompression ratio limit, valid UTF-8 text, and at most 5,000 unique components. Archive redirects are accepted only from GitHub's `codeload.github.com` host. Generation is rate-limited to ten requests per user per hour and uses leased, audited jobs. Managed jobs have bounded retry for transient provider failures; one-time jobs do not retry.

The native Mac generator does not download or extract an archive. It uses only `api.github.com`, rejects redirects, caps the recursive tree response at 8 MB and 5,000 entries, selects at most 100 recognized lockfile blobs, limits each to 2 MB and their decoded total to 8 MB, requires valid UTF-8 without NUL bytes, and emits at most 5,000 unique components. Only one native run may execute at a time and no failed request retries automatically. GitHub's own API rate limits still apply.

Supported inputs are `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `Cargo.lock`, `go.sum`, `Gemfile.lock`, and `composer.lock`. A run fails explicitly when no supported lockfile or pinned component can be found. Unsupported ecosystems require a reviewed parser addition; Scopeproof does not infer a complete inventory from unpinned manifest files.

Managed repository listing is intentionally capped at 250 repositories. If an intended repository is absent, narrow the managed token's selected repositories, use a dedicated Scopeproof GitHub organization/installation boundary, or use one-time access rather than broadening a persistent credential. Generated evidence is valid for 365 days by default but remains subject to the assessment period, ordinary evidence retention, legal hold, approval, supersession, and expiration controls.

## Auditor interpretation

The SBOM proves the dependency inventory parsed from supported lockfiles present at the recorded commit. It does not prove that the same commit was deployed, that every runtime dependency appears in a supported lockfile, or that listed packages are vulnerability-free. Pair it with deployment provenance, release attestations, vulnerability scan results, and change-management evidence.

For repeat runs, Scopeproof records added, removed, and version-changed component names against the most recent completed inventory for the same repository and assessment. The full current SBOM remains authoritative; the change summary is a review aid.

## Troubleshooting and response

| Condition | Meaning and response |
| --- | --- |
| **Managed GitHub connection is not configured** | One or both hosted variables are absent. Configure them in Sites for reusable access, or choose one-time repository access. |
| `INVALID_REPOSITORY_URL` | Enter exactly `https://github.com/owner/repository`; remove query strings, fragments, extra paths, embedded credentials, or a non-GitHub host. |
| `INVALID_GITHUB_TOKEN` | Re-enter a non-empty short-lived token. The submitted field was already cleared and no token was retained. |
| `GITHUB_AUTH_FAILED` | The token is expired, revoked, not installed for the owner, lacks repository selection, or lacks read access. Repair managed access or create a fresh one-time token and run a known-commit canary. |
| `REPOSITORY_OR_REF_NOT_FOUND` | The repository/ref does not exist or is hidden by token selection. Confirm organization, repository selection, spelling, and ref. |
| `ASSESSMENT_NOT_ACTIVE` or scope error | Activate the intended assessment and include PCI DSS 6.3.2 plus the required system scope; do not bypass scope validation. |
| `ARCHIVE_LIMIT_EXCEEDED` or `COMPONENT_LIMIT_EXCEEDED` | The repository exceeds a safety bound. Split the inventory boundary where appropriate or propose a reviewed code/configuration change with load tests; do not disable the limit. |
| `INVALID_ARCHIVE` or `INVALID_MANIFEST` | GitHub returned malformed content or a recognized lockfile is not safe, valid, or parseable. Preserve job/audit metadata, inspect the commit outside Scopeproof in a quarantined engineering workflow, and correct the repository. |
| Job is retrying | A managed-access provider failure was scheduled for bounded retry. If retries exhaust, repair the provider condition before starting a new job. One-time jobs require a new submission instead. |
| `LEASE_EXPIRED` | A one-time or final-attempt job ended before completion. No credential is available to resume it; start a new job with a fresh token. |

After token rotation or parser changes, run `npm run db:verify`, generate both CycloneDX and SPDX canaries from a repository with known pinned dependencies, verify immutable commit/archive provenance and component counts, complete independent approval, and verify inclusion under 6.3.2 in a test assessor package.
