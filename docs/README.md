# Scopeproof documentation

Scopeproof documentation is organized by the person performing the work.

The current downloadable Mac build is the [Scopeproof Capture 1.8.0 development preview](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/tag/v1.8.0-development-preview.1). It is an Apple Silicon-only, ad-hoc-signed testing release; verify its checksum and read the [macOS installation guide](MACOS_INSTALLATION.md) before opening it.

| Guide | Primary audience | Purpose |
| --- | --- | --- |
| [macOS installation](MACOS_INSTALLATION.md) | Mac users and endpoint administrators | Install, launch, update, verify, and troubleshoot the local-first menu-bar application. |
| [Operator guide](OPERATOR_GUIDE.md) | Evidence collectors and reviewers | Capture, classify, redact, review, search, upload, retain, and export evidence. |
| [Jira evidence handoff](JIRA_HANDOFF.md) | GRC coordinators and control owners | Associate evidence with Jira and transfer it without breaking integrity or exposing secrets. |
| [Repository SBOM guide](SBOM_GUIDE.md) | Software inventory operators and assessors | Configure GitHub, generate CycloneDX/SPDX evidence, review provenance, and understand coverage limits. |
| [AWS S3 evidence storage](S3_STORAGE.md) | AWS storage administrators and Mac operators | Configure KMS/Object-Lock evidence storage, temporary credentials, restricted Compatible S3 identities, exact-version integrity, split IAM, monitoring, and recovery. |
| [Assessor guide](ASSESSOR_GUIDE.md) | External assessors and assessment leads | Navigate a package and independently verify hashes, signatures, scope, and review status. |
| [Deployment guide](DEPLOYMENT.md) | Platform and security administrators | Configure identity, roles, secrets, storage, collectors, macOS releases, and production operations. |
| [Security guide](SECURITY.md) | Security engineering and risk teams | Understand trust boundaries, protections, residual risks, and incident actions. |
| [Key management](KEY_MANAGEMENT.md) | Security and platform administrators | Rotate encryption/HMAC keys, retain historical keys safely, and verify independent audit checkpoints. |
| [Production operations](PRODUCTION_OPERATIONS.md) | Service owners and incident responders | Operate backups, recovery drills, monitoring, incident response, single-tenant isolation, and launch authorization. |
| [Architecture](ARCHITECTURE.md) | Engineers and technical assessors | Understand components, data flows, persistence, and integrity design. |
| [Development guide](DEVELOPMENT.md) | Contributors and release managers | Build, test, migrate, package, and release the web and macOS applications. |
| [Release history](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases) | Mac testers and release managers | Download published artifacts and review version-specific integrity and signing limitations. |

Versioned product changes are recorded in the repository [changelog](../CHANGELOG.md). Native application details are also available in the [macOS README](../macos/ScopeproofCapture/README.md) and inside the app under **Help & How to Use…**.
