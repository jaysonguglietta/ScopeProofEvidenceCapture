# Dependency security policy

Scopeproof treats the deployed Worker bundle and its production dependency graph as the release boundary. Pull requests and weekly CI runs block High and Critical advisories in both the full development graph and the production graph, and retain a CycloneDX SBOM for 30 days.

This release SBOM is distinct from the operator-facing repository SBOM workspace. The workspace generates CycloneDX 1.6 or SPDX 2.3 evidence for repositories supplied by the configured GitHub organization; see [Repository SBOM guide](SBOM_GUIDE.md).

## Temporary advisory exceptions

These exceptions apply only to local development/build tooling. They are not present in `npm audit --omit=dev`, are not imported by the deployed Worker, and do not permit externally reachable development servers.

| Dependency path | Severity | Rationale and compensating controls | Owner | Review by |
| --- | --- | --- | --- | --- |
| `drizzle-kit` → `@esbuild-kit/*` → `esbuild` | Moderate | The advisory affects the esbuild development server. Scopeproof uses this path only for local migration generation; CI installs with scripts disabled and never exposes a development server. Re-evaluate when Drizzle publishes a compatible fixed dependency path. | Platform Security | 2026-09-11 |
| `eslint-plugin-react-hooks` → `@babel/core` | Low | The advisory requires attacker-controlled source-map input during local analysis. Lint runs only against reviewed repository content, with no network listener. Upgrade as soon as the patched Babel release is available. | Platform Security | 2026-09-11 |

Exceptions expire on the listed date. A pull request must update the dependency or explicitly renew the entry with current evidence; silent or permanent acceptance is not allowed.

## Release verification

Before release:

1. Run the full test/build suite.
2. Run `npm audit --audit-level=high`.
3. Run `npm audit --omit=dev --audit-level=high` and require zero production findings.
4. Generate the CycloneDX SBOM from the locked dependency graph.
5. Review any override or local replacement package as first-party security-sensitive code.
