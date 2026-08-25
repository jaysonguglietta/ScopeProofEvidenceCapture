# External assessor package and verification guide

This guide describes what Scopeproof evidence packages contain and how an assessor can validate them independently. A valid signature or hash proves integrity and provenance within Scopeproof’s custody model; it does not by itself prove that a control is effective or that the captured system was complete.

## Package acceptance

Obtain the following from the evidence owner:

- the assessor ZIP;
- the separate ZIP SHA-256 checksum;
- the package signing-key fingerprint through a different trusted channel;
- the assessment scope, period, systems, and framework version;
- the Jira/workpaper references used for evidence coordination, when applicable.

Treat the package as sensitive. Store it only in an approved assessment workspace with access logging and appropriate retention.

## Local macOS package contents

Browser-window evidence places a live right-side macOS menu-bar pixel strip across the top of the reviewed PNG so the system-displayed date/time and status context remain visible. Full-display evidence includes the real menu bar in the captured display. Treat these pixels and the adjacent local clock reading as corroborating endpoint context, not an independent trusted timestamp: an endpoint administrator can change the clock or displayed content. Use the immutable manifest capture time, signed Scopeproof server receipt, and a verified RFC 3161 attestation when independent time assurance is required.

| Path | Purpose |
| --- | --- |
| `00-READ-ME.txt` | Package identity, scope, policy, and starting instructions. |
| `01-Control-Coverage.csv` | Controls with approved-evidence counts and visible gaps. |
| `02-Evidence-Index.csv` | Artifact index including framework, control, Jira reference, owner, lifecycle status, redactions, hash, and relative path. |
| `03-Package-Manifest.json` | Canonical package manifest and ECDSA P-256 signature envelope. |
| `04-Verification.txt` | Package-specific hash, chain, signature, and signer-fingerprint instructions. |
| `05-Jira-Handoff.txt` | Optional Jira handling policy and mapped issue keys. |
| `Evidence/<framework>/<control>/` | Approved PNGs plus capture manifests, lifecycle records, and available upload receipts. |

Hosted exports contain `00-READ-ME.txt`, `01-Evidence-Index.csv`, `02-Jira-Handoff.txt`, `assessor-report.pdf`, `manifest.json`, `VERIFY.txt`, and the approved artifacts organized under `evidence/<framework>/<control>/`. Approved repository SBOM JSON is stored under `evidence/<framework>/6.3.2/` and is indexed and hashed like other evidence. CSV files neutralize spreadsheet formula prefixes but remain presentation aids; the signed JSON manifest is the authoritative index.

## Verification sequence

1. Calculate SHA-256 for the ZIP before extraction and compare it with the separately delivered checksum.
2. Extract into a protected working directory. Do not execute or preview unexpected active content.
3. Review the Read Me and evidence index. Confirm the framework, period, systems, preparer, package ID, and approved-only inclusion policy match the engagement.
4. Recalculate SHA-256 for every administrative and evidence file listed in the signed package manifest.
5. Canonicalize the manifest payload exactly as stated in the included verification guide and verify its ECDSA P-256/SHA-256 signature using the embedded public key.
6. Compare the public-key SHA-256 fingerprint with the value obtained through the separate trusted channel.
7. For each screenshot, compare its digest with `screenshotSha256` and the adjacent capture manifest.
8. Verify every lifecycle event chain starts at `GENESIS`, each `previousHash` points to the prior event, and the final status is **Approved**.
9. Confirm each Jira issue reference, when present, belongs to the assessment and agrees with the visible screenshot banner and evidence index.
10. Record validation results, discrepancies, exceptions, and follow-up requests in the assessor workpapers.

## Evidence quality review

After integrity validation, determine whether each artifact is sufficient and appropriate:

- The system and environment are in scope.
- The capture timestamp falls within the required period.
- The source and visible settings support the stated control assertion.
- The screenshot is readable and includes enough surrounding context to identify the configuration.
- Redactions do not conceal information necessary to evaluate the control.
- The evidence is current, not duplicated, and not superseded.
- Cross-framework mappings are independently validated rather than accepted as authoritative.

## Repository SBOM review

For CycloneDX 1.6 or SPDX 2.3 evidence mapped to PCI DSS 6.3.2, verify that:

- the repository and 40-character resolved commit are in assessment scope;
- the SBOM metadata records the source-archive SHA-256, parser/generator version, and lockfile paths;
- the evidence-file SHA-256 matches the assessor-package manifest;
- the component inventory is plausible for the repository and each material ecosystem has a supported lockfile;
- repeat-run additions, removals, and version changes were reviewed, while treating the full current document as authoritative; and
- deployment provenance separately demonstrates whether that commit and dependency set reached the assessed environment.

A direct Mac export is not automatically mapped, approved, encrypted, or packaged by the hosted evidence workflow. For that form, verify the adjacent `.sha256.txt` against the JSON, confirm the repository and 40-character commit in the document, inspect the manifest-set SHA-256 and lockfile paths, obtain the organization's separate reviewer/retention record, and confirm the file was transferred from an approved encrypted location. Hosted documents use source-archive provenance; native documents use manifest-set provenance because the Mac reads bounded Git blobs and never downloads an archive.

The SBOM is a static inventory of supported pinned lockfiles. It does not prove deployment, runtime completeness, exploitability, patch status, license compliance, or absence of vulnerabilities. Request deployment attestations, vulnerability scan output, exception records, and change-management evidence where those assertions are required.

## Exceptions

Reject or request replacement evidence when a hash or signature fails, a lifecycle chain is invalid, files referenced by the manifest are missing, the item is not Approved, the screenshot is ambiguous, the timestamp is unsuitable, the ticket association is incorrect, or required control details are hidden by redaction.

Preserve the original package and checksum when escalating an exception. Do not repair, rename, or rewrite evidence files and then represent them as the original package.
