# Scopeproof documentation

Scopeproof documentation is organized by the person performing the work.

The current downloadable Mac build is the [Scopeproof Capture 1.8.1 development preview](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases/tag/v1.8.1-development-preview.1). It is an Apple Silicon-only, ad-hoc-signed testing release; verify its checksum and read the [macOS installation guide](MACOS_INSTALLATION.md) before opening it.

| Guide | Primary audience | Purpose |
| --- | --- | --- |
| [Getting started](GETTING_STARTED.md) | New Mac users and evaluators | Download or build the app, grant permissions, capture and review evidence, export a package, and configure optional S3, SBOM, Jira, or hosted workflows. |
| [macOS installation](MACOS_INSTALLATION.md) | Mac users and endpoint administrators | Install, launch, update, verify, and troubleshoot the local-first menu-bar application. |
| [Operator guide](OPERATOR_GUIDE.md) | Evidence collectors and reviewers | Capture, classify, redact, review, search, upload, retain, and export evidence. |
| [Jira evidence handoff](JIRA_HANDOFF.md) | GRC coordinators and control owners | Associate evidence with Jira and transfer it without breaking integrity or exposing secrets. |
| [Repository SBOM guide](SBOM_GUIDE.md) | Software inventory operators and assessors | Configure GitHub, generate CycloneDX/SPDX evidence, review provenance, and understand coverage limits. |
| [AWS S3 evidence storage](S3_STORAGE.md) | AWS storage administrators and Mac operators | Configure KMS/Object-Lock evidence storage, temporary credentials, restricted Compatible S3 identities, exact-version integrity, split IAM, monitoring, and recovery. |
| [AWS multi-tenant hosting](AWS_MULTI_TENANT_HOSTING.md) | AWS platform, SaaS, and security administrators | Build the AWS-only hosted target, provision explicit tenant subdomains, isolate customer data, control cost, and execute the staged migration. |
| [AWS platform runbook](AWS_PLATFORM_RUNBOOK.md) | AWS deployment operators and service owners | Validate, review, deploy, provision, test, activate, operate, recover, and retire the AWS platform without confusing infrastructure readiness with customer launch. |
| [AWS adversarial security review](AWS_SECURITY_REVIEW.md) | Security engineering, AppSec, and risk owners | Review confirmed weaknesses, attack paths, residual design gaps, remediation priorities, and required production security tests for the AWS migration. |
| [Assessor guide](ASSESSOR_GUIDE.md) | External assessors and assessment leads | Navigate a package and independently verify hashes, signatures, scope, and review status. |
| [Deployment guide](DEPLOYMENT.md) | Platform and security administrators | Configure identity, roles, secrets, storage, collectors, macOS releases, and production operations. |
| [Security guide](SECURITY.md) | Security engineering and risk teams | Understand trust boundaries, protections, residual risks, and incident actions. |
| [Key management](KEY_MANAGEMENT.md) | Security and platform administrators | Rotate encryption/HMAC keys, retain historical keys safely, and verify independent audit checkpoints. |
| [Production operations](PRODUCTION_OPERATIONS.md) | Service owners and incident responders | Operate backups, recovery drills, monitoring, incident response, single-tenant isolation, and launch authorization. |
| [Architecture](ARCHITECTURE.md) | Engineers and technical assessors | Understand components, data flows, persistence, and integrity design. |
| [Development guide](DEVELOPMENT.md) | Contributors and release managers | Build, test, migrate, package, and release the web and macOS applications. |
| [Release history](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/releases) | Mac testers and release managers | Download published artifacts and review version-specific integrity and signing limitations. |

Versioned product changes are recorded in the repository [changelog](../CHANGELOG.md). Native application details are also available in the [macOS README](../macos/ScopeproofCapture/README.md), the [hosted Cognito authentication contract](../macos/ScopeproofCapture/HOSTED_AUTHENTICATION.md), and inside the app under **Help & How to Use…**.
