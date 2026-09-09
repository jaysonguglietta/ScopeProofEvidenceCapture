# GitHub publication and local Mac update — September 8–9

This follow-up is separate from the [initial source validation](READINESS_VALIDATION_2026-09-08.md).
The requested scope is documentation, GitHub source publication and replacement
of the existing local Mac app. AWS/Sites deployment, remote migrations, public
DMG publication, notarization and blanket issue closure are excluded.

## Development build

- Version: **1.10.0, build 26**, advanced from the previously running build 25.
- Source branch: `codex/security-product-readiness`, based on `f416d18`.
- Application implementation commit: `2980ad55dd44cc0a15fade3049882158cf03cb6b`.
- Verified installed path: `~/Applications/Scopeproof Capture.app`.
- Signing: local ad-hoc signature, retaining bundle ID `com.scopeproof.capture`.
- Distribution: development source, not a new notarized or public DMG release.

The implementation was pushed to GitHub and opened as
[PR #113](https://github.com/jaysonguglietta/ScopeProofEvidenceCapture/pull/113).
It is not merged into `main`. Later documentation/test-harness commits on that
PR do not change the installed production executable.

Build 26 was installed and restarted from the path above. The initial macOS
launch returned error -600; retrying the exact installed path with `open -n`
succeeded. Process and bundle checks confirmed version/build and an executable
SHA-256 identical to the built app:

```text
415e4b3d5609c181cb4af11e03098df8401d757c377ea078cbd83ea8ac679c8d
```

The previous build-25 bundle was backed up under the Git-ignored
`DerivedData/.before-build-26.8zZR1A/Scopeproof Capture.app`. Evidence, settings
and Keychain were not reset or removed by installation. The saved
`capture.openLocalConsoleAtLaunch` preference is false; no listener at startup
is expected. Open the Local Console from the shield menu when needed. Visual
inspection was unavailable because macOS Computer Use permission was not granted;
no privacy permissions were changed and no capture was initiated.

## GitHub check status

For implementation commit `2980ad5`, dependency review, the main verification
job and the JavaScript/TypeScript, Actions and manual Swift analysis jobs passed.
The macOS unit-test process terminated with SIGBUS (signal 10) after successful
compilation; its log did not include a crash stack. A test-only follow-up now
initializes AppKit explicitly, closes its test window, runs the presentation
suite independently and collects failure-only test-process crash reports.
Local success is not proof that the runner crash is resolved; inspect the latest
PR checks before merging.

The separate CodeQL alert check reports two high-severity portal alerts:
`js/clear-text-storage-of-sensitive-data` at the transient PKCE transaction
storage and `js/user-controlled-bypass` at the callback-code branch. Both remain
open for security review; neither has been dismissed or suppressed. The stored
transaction includes a one-time verifier/state and public origin/client binding,
not access/ID/refresh tokens; the callback validates the transaction and uses
Cognito token exchange plus server-side JWT/membership authorization. Those
facts inform triage but do not automatically clear the alerts. These new CI
alerts are separate from the original 13-finding remediation ledger.

GitHub also reported four `fast-uri` advisories on unchanged `main`; this branch
pins 3.1.6 and passed dependency review. Default-branch alert closure requires a
reviewed merge and GitHub rescan, not a manual closure claim.

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
