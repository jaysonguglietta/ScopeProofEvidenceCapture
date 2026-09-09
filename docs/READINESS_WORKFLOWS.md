# Updated evidence workflows

These instructions describe the current development source, not a newly
published or notarized DMG. See the [implementation ledger](READINESS_IMPLEMENTATION_STATUS.md)
for work still pending. Nothing in this change deploys resources to AWS.

## Build and database preparation

Follow [Getting started](GETTING_STARTED.md) for prerequisites and Mac builds.
For the existing single-workspace hosted console:

```sh
npm ci --ignore-scripts
npm run typecheck
npm run lint
npm test
npm run db:verify
npm run dev
```

The development server binds to loopback. Apply the complete reviewed Drizzle
migration sequence through `0031_brave_silver_fox.sql` to the intended database
before using requirements, explicit schedules and finding proof. Never apply an isolated ALTER/CREATE snippet
instead of the migration sequence. `db:verify` uses disposable local databases;
it does not migrate a deployed service. Preserve backups before any authorized
deployment migration. Do not configure the legacy console as a multi-tenant AWS
frontend: those runtimes use different identity and persistence boundaries.

## Workspace and library navigation

Select an assessment before collecting, reviewing or exporting. Native Recent
Captures, Search Evidence, the Local Console and package export now require the
selected customer/workspace binding. Local/default discovery excludes named
tenant subdirectories. Copying another customer's files into a visible directory
does not make them members of the current workspace. Duplicate evidence IDs are
omitted rather than selecting an arbitrary pair.

Hosted Evidence search, status and type filters query the server before pagination;
they are not limited to the first 50 loaded items. Requirements can drill down by
an exact control and exact system. Clear the scope-filter banner to return to the
whole assessment. Load additional pages explicitly. View and loaded assessment
selection are represented in the URL; a bookmarked assessment must still be
available to the current user. Older SBOM evidence can be opened by its ID even
when it is not on the loaded evidence page.

Section failures show a persistent recovery message. Unaffected sections remain
available. Active jobs trigger bounded polling; rate-limit responses respect
Retry-After and repeated failures back off. Refresh after an ambiguous mutation
before trying again. Help remains usable during backend outages. Error messages
are not automatically dismissed or presented with a success checkmark.

## Assessment and collector setup

Create a draft with a supported catalog, exact controls, systems and dates. Edit
the draft under Controls → Assessment lifecycle; save before using source-scope
compatibility preview. That preview compares saved collector configuration to
declared scope; it does not call the provider or prove connectivity. Unknown
Cloudflare zone discovery is reported as unknown, not compatible. Test the source
separately, correct scope, then activate. Existing evidence locks scope; closed
assessments are read-only. Use another assessment to change active scope safely.

In Connections, choose an explicit active assessment for each scheduled source,
enter its supported UTC cron expression and inspect the next-run preview. Minutes
must be 0, 15, 30 or 45 to match the hosted scheduler's 15-minute tick. Pause
requires confirmation. Removing a schedule does not delete run history. Old
schedules migrated without a binding remain inactive until explicitly assigned;
the scheduler never chooses whichever assessment happens to be newest. Loaded
active jobs, including older pages, are polled in rotating bounded batches.

## Independent review

Open the artifact and inspect its actual bytes. Cards show a neutral artifact
placeholder, not a reconstructed screenshot. The review panel retrieves the
latest occurrence's creator, current permitted actions and decision history.

- Needs review: approve, reject or return when server policy permits.
- Rejected/returned: reopen for another review.
- Approved: supersede using an approved replacement in the same assessment/control.
- Expired, purged, foreign-creator and unauthorized states remain blocked by the API.

Enter a 20–1,000 character rationale and confirm inspection. Supersession also
requires the replacement evidence ID. The server rechecks scope, role, independent
review, digest and current state during the mutation. A concurrent or no-op
decision returns a conflict, not a fabricated approval. Reload and inspect the
authoritative state before making another decision. Review history records the
actor, time, action and rationale.

## Evidence requirements—not compliance scores

Open Controls → Evidence requirements. Each explicitly scoped control/system pair
starts with one eligible artifact and an accountable owner. A compliance lead or
administrator can select **Revise**, assign an active owner, choose 1–25 artifacts
and record a specific rationale. Saving creates another revision; it does not
overwrite prior expectations. Closed assessments cannot be revised.

Only the latest independently approved, current, in-scope, complete occurrence
with the required safety/provenance state satisfies an artifact expectation.
System A's evidence cannot satisfy system B. A missing or suspended owner remains
a gap. Use **Inspect evidence** to see the exact control/system library. The
matrix shows missing, expired, partial and review-needed counts separately.
The default is deliberately modest: validate expectations with your assessor;
neither evidence presence nor a satisfied expectation proves regulatory compliance.

## Repository SBOMs

Opening Generate SBOM explicitly discovers managed repositories. Merely viewing
the SBOM workspace or polling job status does not contact GitHub discovery or
consume its discovery quota. One-time tokens remain request-only and are not
persisted for retries.

Hosted npm lockfile versions 1, 2 and 3 have bounded supported parsing. Nested
npm-v1 dependencies and simultaneous versions are retained; direct/transitive
classification for v1 is **Unknown**, not an invented zero. Other currently
heuristic parsers are explicitly partial review aids and cannot be approved as
complete inventory. Native and hosted npm fixture outputs share nested and
multi-version ground truth; do not infer universal ecosystem parity from these
fixtures. Unsupported recognized lockfile versions are rejected explicitly.

Expand **Coverage, manifests and changes** to inspect limitations, the exact
commit, generator version, manifests and version-set changes. Preview lists are
bounded and disclose truncation; the JSON download contains the inventory.
CycloneDX uses the exact `bom-ref` key. Automated tests validate generated
CycloneDX 1.6 and SPDX 2.3 documents against pinned official offline schemas;
schema validity alone does not prove inventory completeness. The inspector
searches component detail, identifies the selected comparison baseline and
compares full version sets. The bounded preview discloses its limit; download
the complete bounded inventory/change detail as JSON instead of inferring that
only visible rows changed.

## Owned remediation findings

Use Findings → Remediation work queue to filter title/description, severity,
status, Mine, unassigned, reassignment-needed or overdue records before paging.
Expand a finding to assign an active authorized owner, choose a due date (end of
day UTC), update status and inspect immutable event history. Suspended/ineligible
owners remain visible with a reassignment warning. Failed saves retain input;
concurrent edits require reload.

Resolving requires a 20–4,000 character explanation and 1–10 current independently
approved, complete artifacts from the same assessment and finding control. Search
the paged evidence picker and inspect the bytes. Saving binds exact occurrence
IDs and SHA-256 values into the finding and history, rechecked during the audited
transaction. Closing a resolved finding revalidates eligibility; a later
unreviewed occurrence blocks closure. Only leads/admins may accept risk or close;
closure requires confirmation and is read-only afterward. Risk acceptance and
old text-only dispositions are expressly not evidence-backed remediation.

## Packages

Export preflight reports eligible/excluded counts, out-of-scope records and
eligible bytes against the 25 MiB evidence-byte limit. Count, selection and final
publication use the same authoritative assessment-scope predicate. Once an
assessment has evidence, its scope cannot change; create another explicitly scoped
assessment instead. There is no silent truncation or silent repartitioning.

Packages lists authorized package history with state, size, digest, creation and
expiry. Only the requester or an administrator can download a package. An expired
package must be regenerated; clicking a stale link does not bypass server expiry.
The artifact list is not a substitute for inspecting a download and verifying its
signature and member hashes.

For large handoffs, open the partition planner. It snapshots at most 1,000
eligible records and divides them deterministically into parts of at most 100
artifacts and 25 MiB evidence bytes. It reports exclusions and refuses a single
oversized artifact; it never silently omits it. Confirm the exact plan before
building a part. Every part revalidates the complete snapshot, not just its own
records, and includes a signed plan digest, part number/count and explicit
NOT COMPLETE ALONE notice. Deliver all parts sharing that digest. A changed
artifact/scope invalidates the plan; regenerate instead of mixing versions.
The existing build quota still applies. After an ambiguous build, inspect
package history before retrying.

## Hosted retention holds

An administrator can inspect the Retention hold panel in evidence details, enter
a 20–1,000 character reason and a future expiry within one year, and explicitly
confirm creation. Release is two-step: request it with a rationale, then have a
different administrator inspect and approve the exact request. Pending requests
expire after 24 hours, and a changed hold invalidates an old request.

This panel controls the legacy hosted retention database. It does not change
direct-S3 Object Lock. AWS exact-version legal holds use their separate tenant
runtime and approval boundary; never substitute browser-supplied storage keys
for an authorized evidence identity.

## Native transfer receipt trust and retention

Hosted, Jira and S3 responses are validated against the expected artifact and
destination and wrapped in a device-signed response envelope. The verification
key is independently held in this Mac's Keychain. A raw, missing, altered or
foreign receipt cannot suppress a pending transfer or enter an assessor package.
The envelope retains the original response as base64 data for later inspection.

This is an authenticated-response/device-integrity seal, **not** independent
authentication of an embedded remote signing key or Jira's server-only HMAC.
It also does not prove the remote object remains available today. Preserve the
original receipt during investigation. For an ambiguous Jira disclosure,
reconcile existing attachments and the server's idempotent operation before
explicitly trying again; never send duplicate evidence simply to clear a warning.

Use the transfer-recovery menu to inspect each artifact/destination independently.
It limits concurrency to two, supports per-item cancellation and refreshes receipt
verification. Errors are sanitized and remain visible for the window. A canceled
transfer can already have committed remotely: reconcile before retrying. Temporary
S3 credentials and workspace/destination authority must be rechecked per item.
Workspace changes invalidate the old window. This is not a durable cloud queue;
restart reconstructs success only from verified receipts.

The old destructive cleanup path remains disabled. **Archive & Expire Old
Payloads…** is a separate explicitly confirmed workflow, at most 100 captures per
run. It preserves complete signed review/hold history, manifests and verified
transfer receipts in a device-sealed archive descriptor referencing exact S3
versions. Before PNG-only disposal it performs live exact-version checksum,
ETag, KMS and future COMPLIANCE-retention checks for every archive member.
Held, changed, missing, legacy-incomplete or unverifiable records stay local.
Only the PNG moves to Trash; metadata, decisions, receipts, descriptors and
Keychain anchors remain. This operation does not delete remote evidence.

**Restore Archived Evidence…** selects an original descriptor and stages verified
exact-version bytes, restoring metadata before the PNG to its original location.
It refuses overwrites, new IDs or trust-anchor adoption. This is **same-Mac**
recovery with the existing Keychain, not replacement-Mac disaster recovery.
Preserve approved backups of both evidence and trust material. A historical
PNG/manifest-only pair or already-lost hold-chain prefix remains incomplete;
the app never manufactures missing history to permit disposal or export.

## AWS source and release gates

See [AWS session and repair migration](AWS_SESSION_AND_REPAIR_MIGRATION.md) for
forward migrations 010/011, resource-server revocation, delayed immutable upload
repair, poison-row recovery and real PostgreSQL tests. AWS CDK
tests now include both `.test.ts` and `.test.mjs`.

The [AWS customer portal](AWS_CUSTOMER_PORTAL.md) is a separate static AWS/Cognito
client, not the legacy Sites/D1/R2 console. Follow its exact deployment-output
configuration, membership/device/scope, evidence-review and two-person hold
instructions. Read [bootstrap/recovery boundaries](AWS_BOOTSTRAP_AND_RECOVERY_BOUNDARIES.md)
before using the separate operator tooling. All AWS execution remains separately
authorized; the local plan/test/build commands are not deployment approval.

Settings → Operational readiness performs explicit read-only checks. Passing
configuration checks does not replace a live ingress/scanner/witness/alarm test,
backup restoration, signed-Keychain qualification, Apple notarization or a clean-Mac
install/update exercise. Do not label a release production-ready while these
gates or the complete AWS customer workflow remain open.
