# GitHub publication and local Mac update — September 8

This follow-up is separate from the [initial source validation](READINESS_VALIDATION_2026-09-08.md).
The requested scope is documentation, GitHub source publication and replacement
of the existing local Mac app. AWS/Sites deployment, remote migrations, public
DMG publication, notarization and blanket issue closure are excluded.

## Development build

- Version: **1.10.0, build 26**, advanced from the previously running build 25.
- Source branch: `codex/security-product-readiness`, based on `f416d18`.
- Intended installed path: `~/Applications/Scopeproof Capture.app`.
- Signing: local ad-hoc signature, retaining bundle ID `com.scopeproof.capture`.
- Distribution: development source, not a new notarized or public DMG release.

GitHub publication and installed-process verification are pending at this
pre-publication checkpoint. This record will be updated only after those
operations return verified results.

## Checks repeated for this update

The web/server production build passed; 393 tests ran with 392 passed, zero
failures and one optional external PostgreSQL harness skipped. The native
release build and staged bundle signature verification passed with Xcode.
The native suite was rerun and passed all 131 tests in 14 suites. Lint,
typechecking, fresh/populated migration replay and `git diff --check` passed.
See the initial validation record for separate CDK/CloudFormation results.

A bounded pre-publication content/pattern review found no actual credentials,
private key material or customer screenshots among the changed/new files.
Synthetic adversarial fixtures are intentional. This is not certification by a
dedicated secret scanner; protected CI performs its own secret/IaC checks.

## Operator update procedure

1. Check out the exact reviewed commit and require a clean source worktree.
2. Run `./Scripts/run_macos_capture.sh` at repository root. It stages and verifies
   a fresh bundle, stops the previous process, replaces only the application
   bundle and launches that installed path. Evidence, preferences and Keychain
   are outside the bundle and are not removed.
3. Confirm installed version/build with `plutil`, verify the bundle with
   `codesign --verify --deep --strict`, compare the installed executable SHA-256
   with the built executable, and verify the actual running executable path.
4. Confirm a single loopback listener belongs to that process. Do not publish or
   record the Local Console bootstrap nonce or bearer token.

See [installation](MACOS_INSTALLATION.md), [new workflows](READINESS_WORKFLOWS.md)
and [AWS customer onboarding](../macos/ScopeproofCapture/AWS_CUSTOMER_ONBOARDING.md).
The default approved hosted-tenant list remains empty; direct local/S3 workflows
do not require an AWS SaaS deployment.

## Remaining gates

Source fixes exist for 12/13 security findings; SEC-11 legacy ingress identity
is still unproven. Replacement-Mac trust recovery and complete recovery
application/reconciliation/write fencing remain unfinished. Live two-tenant,
scanner/witness/alarms, signed-Keychain, clean-Mac notarization/update and full
accessibility qualification remain required. Pushing source or installing this
development build does not close these gates or make the application
production-certified.
