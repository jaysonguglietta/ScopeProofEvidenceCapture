# Repository SBOM guide

Scopeproof can generate an auditor-facing Software Bill of Materials for a repository in the configured GitHub organization. The result is encrypted as evidence, mapped to PCI DSS 6.3.2, independently reviewed through the normal evidence workflow, and included in an assessor package after approval.

## Configure GitHub

Set `GITHUB_ORG` to the one organization operators may inventory. Set `GITHUB_TOKEN` to a GitHub App installation token or fine-grained token limited to the intended repositories with:

- Repository **Metadata: read**, to list repositories and resolve commits.
- Repository **Contents: read**, to download an archive at the resolved commit.

Do not grant write, administration, workflow, issue, or secret permissions. Rotate the credential using the platform secret manager; never put it in the browser, Mac app, repository, or D1.

The active assessment must include control `6.3.2`. If its system scope is non-empty, it must include the exact `organization/repository`, the configured organization, or `GitHub`.

## Generate and review

1. Open **SBOMs** and select **Generate SBOM**.
2. Choose the active assessment and a repository from the fixed organization.
3. Enter a branch, tag, or commit. Scopeproof resolves it to a 40-character commit SHA before downloading content.
4. Choose CycloneDX 1.6 JSON or SPDX 2.3 JSON.
5. Generate the inventory. Review its repository, commit, archive digest, manifests, generator version, component counts, and changes from the prior run.
6. Open the linked evidence, inspect the actual JSON and SHA-256 digest, and have an independent reviewer approve it.
7. Export the assessment package. Approved, unexpired SBOM evidence is included under PCI DSS 6.3.2 like other evidence.

The direct **JSON** download is available as soon as generation completes. It is authenticated and audited; approval is required only for inclusion in the assessor package.

## Security and operational limits

Scopeproof does not clone a repository or execute repository code, build scripts, lifecycle hooks, package managers, container builds, or dependency installers. It downloads one ZIP from GitHub at the resolved commit and extracts only recognized lockfiles.

The server enforces a 20 MB compressed archive limit, 5,000-entry limit, 100-manifest limit, 2 MB per manifest, 8 MB total selected manifest data, a 100:1 decompression ratio limit, valid UTF-8 text, and at most 5,000 unique components. Archive redirects are accepted only from GitHub's `codeload.github.com` host. Generation is rate-limited to ten requests per user per hour and uses leased, audited jobs with bounded retry for transient provider failures.

Supported inputs are `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `Cargo.lock`, `go.sum`, `Gemfile.lock`, and `composer.lock`. A run fails explicitly when no supported lockfile or pinned component can be found. Unsupported ecosystems require a reviewed parser addition; Scopeproof does not infer a complete inventory from unpinned manifest files.

## Auditor interpretation

The SBOM proves the dependency inventory parsed from supported lockfiles present at the recorded commit. It does not prove that the same commit was deployed, that every runtime dependency appears in a supported lockfile, or that listed packages are vulnerability-free. Pair it with deployment provenance, release attestations, vulnerability scan results, and change-management evidence.

For repeat runs, Scopeproof records added, removed, and version-changed component names against the most recent completed inventory for the same repository and assessment. The full current SBOM remains authoritative; the change summary is a review aid.
