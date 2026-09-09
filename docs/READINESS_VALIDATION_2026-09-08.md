# September 8 implementation validation and handoff

At the initial validation snapshot, the implementation was local and uncommitted on
`codex/security-product-readiness`, based on
`f416d18d6692b5b94d251bca0fded358ee1936d8`. No GitHub push, issue closure, release,
installation, real evidence disposal or AWS deployment was performed during that
pass. The later requested GitHub/local-app update has a separate
[publication handoff](PUBLICATION_AND_LOCAL_UPDATE_2026-09-08.md). The results
below retain their original scope; they do not assert remote CI or live-service
qualification.

## Results on the integrated checkout

| Check | Result | What it establishes |
| --- | --- | --- |
| `npm test` | Build passed; 393 tests: 392 passed, 1 skipped, 0 failures | Integrated web/server tests, actual SQLite and embedded PostgreSQL, official SBOM schemas, provider fixtures and adversarial runtime cases |
| `npm run typecheck` | Passed | TypeScript consistency |
| `npm run lint` | Passed | Configured static lint rules |
| `npm run db:verify` | Passed | Complete fresh and populated D1 migration replay/integrity through 0031 |
| CDK `npm test` (same test script as `pnpm test`) | 34/34 passed, includes TypeScript check | Local synthesis, IAM/contracts, restore/cutover fake-adapter tests, actual failing-MJS discovery sentinel |
| `npm run test:cloudformation` | 18/18 passed | Authentication/storage/monitoring template and policy invariants |
| Native Swift tests, arm64 | 131/131, 14 suites passed | Isolated native security/workflow fixtures, archive/restore, AWS submission/status and original-artifact preservation |
| Native release Swift build, arm64 | Passed | Production-configuration compilation/linking; not code signing or notarization |
| Root `npm audit --json` | Zero known vulnerabilities | Root production/development lockfile advisory result at check time |
| CDK `pnpm audit --json` | Zero known vulnerabilities | Separate pnpm lockfile advisory result at check time |
| `plutil -lint` | Passed | Native Info.plist syntax; approved tenant configuration remains empty by default |
| `git diff --check` | Passed | Whitespace/patch checks |

The skipped test is the opt-in external PostgreSQL harness. Embedded PGlite
tests execute the real PostgreSQL migration/function/grant bundle without AWS;
the skip does not mean all SQL tests were mocked. PGlite is not Aurora/Data API.
Swift tests use DEBUG isolated memory-backed Keychain state, never customer keys.
The old XCTest wrapper can print “0 tests”; the Swift Testing result is the
131-test/14-suite run, not that wrapper.

Local runtime: Node 26.8.1 and Xcode Swift 6.3.3. CI now reads Node 22.23.2 from
`.node-version`; this turn did not execute remote CI on that baseline. Native
builds used XcodeDefault, temporary module caches and a temporary scratch build.
Read-only dependency audit needed network access; it made no cloud changes.

## Reproduce source checks

At repository root:

```sh
npm ci --ignore-scripts
npm run typecheck
npm run lint
npm test
npm run db:verify
npm run test:cloudformation
npm audit
```

For AWS infrastructure, use its pinned package manager and separate lockfile:

```sh
cd infra/aws/cdk
pnpm install --frozen-lockfile --ignore-scripts
pnpm test
pnpm audit
```

For the native source (substitute your installed Xcode path if necessary):

```sh
cd macos/ScopeproofCapture
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift test --arch arm64
DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer swift build -c release --arch arm64
```

These commands do not deploy AWS, migrate a remote database, install an app or
publish a DMG. Use [Getting started](GETTING_STARTED.md) for intentional local
installation and [native AWS onboarding](../macos/ScopeproofCapture/AWS_CUSTOMER_ONBOARDING.md)
for exact approved public configuration. AWS restore/cutover `plan` modes are
offline; their mutating modes require separate explicit authorization.

## UX evidence and limitations

The real loopback development console's Help view was inspected in the browser
at approximately 320px width with protected backend services unavailable. Help
and recovery instructions remained readable; protected data was not replaced
with invented records. This was an outage/empty-shell check, not an authenticated
full-library, VoiceOver or two-customer browser test.

New tests execute 100-artifact package publication with constant 24 normal/27
partition query bindings, including a 1,000-record complete-plan fence. They
also execute collector queue/audit races and ensure a no-op write returns 409,
never a phantom queued job. Schedules accept only quarter-hour minutes matching
the deployed timer. Findings bind exact independently approved occurrences and
reject changed proof during the audited commit and later closure.

## Remaining work—not waived by these checks

See the [full 17/13 status ledger](READINESS_IMPLEMENTATION_STATUS.md). Especially:

- SEC-11 legacy external dispatcher/direct-origin identity isolation is unproven.
- Replacement-Mac trust recovery is not implemented; current archive restore
  requires the original Keychain and original path.
- Recovery API/auth deployment, database/control-plane/evidence reconciliation,
  primary-write fencing, inventory completeness and CloudTrail-chain validation
  remain prerequisites for signed restore/cutover acceptance, not automated
  assertions made true by this CLI.
- Live AWS two-tenant, scanner/witness/alarms/holds/revocation and measured
  restore/cutover exercises remain unrun, in accordance with no deployment.
- Signed-Keychain, notarized clean-Mac installation/update and full accessibility
  qualification still require the release/staging environments.

The 17 product items are tracked individually, not blanket-closed. Source
remediation exists for the 12 security findings other than SEC-11, with the
specific residual and qualification limits recorded separately.
