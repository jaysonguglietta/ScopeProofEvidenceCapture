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

| Path | Purpose |
| --- | --- |
| `00-READ-ME.txt` | Package identity, scope, policy, and starting instructions. |
| `01-Control-Coverage.csv` | Controls with approved-evidence counts and visible gaps. |
| `02-Evidence-Index.csv` | Artifact index including framework, control, Jira reference, owner, lifecycle status, redactions, hash, and relative path. |
| `03-Package-Manifest.json` | Canonical package manifest and ECDSA P-256 signature envelope. |
| `04-Verification.txt` | Package-specific hash, chain, signature, and signer-fingerprint instructions. |
| `05-Jira-Handoff.txt` | Optional Jira handling policy and mapped issue keys. |
| `Evidence/<framework>/<control>/` | Approved PNGs plus capture manifests, lifecycle records, and available upload receipts. |

Hosted exports contain `00-READ-ME.txt`, `01-Evidence-Index.csv`, `02-Jira-Handoff.txt`, `assessor-report.pdf`, `manifest.json`, `VERIFY.txt`, and the approved artifacts organized under `evidence/<framework>/<control>/`. CSV files neutralize spreadsheet formula prefixes but remain presentation aids; the signed JSON manifest is the authoritative index.

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

## Exceptions

Reject or request replacement evidence when a hash or signature fails, a lifecycle chain is invalid, files referenced by the manifest are missing, the item is not Approved, the screenshot is ambiguous, the timestamp is unsuitable, the ticket association is incorrect, or required control details are hidden by redaction.

Preserve the original package and checksum when escalating an exception. Do not repair, rename, or rewrite evidence files and then represent them as the original package.
