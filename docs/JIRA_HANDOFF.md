# Jira evidence handoff

Scopeproof provides a controlled, manual Jira handoff. It does not store Jira credentials and does not upload attachments automatically. This keeps the operator in control of the destination ticket, project permissions, and final disclosure decision.

## Configure Jira routing

Open **Scopeproof shield → Capture & Jira Settings…** and configure:

- **Jira site URL:** the organization’s HTTPS Jira base URL, for example `https://company.atlassian.net`.
- **Default project:** an uppercase project key such as `GRC` or `PCI`.
- **Attachment set:** either the individual evidence set or an approved assessor ZIP plus checksum.
- **Include Jira handoff guide:** adds `05-Jira-Handoff.txt` to local assessor packages.
- **Organization instructions:** approved issue type, reviewers, classification, retention, or internal routing requirements.

These settings contain routing and procedure information only. Do not enter a Jira API token, password, cookie, or recovery code.

## Associate a capture with a ticket

Enter an issue key such as `GRC-123` in the capture-classification dialog. Scopeproof validates the format and records the key in:

- the screenshot’s visible banner;
- the filename;
- the immutable capture manifest;
- local evidence search;
- hosted evidence metadata after upload;
- the assessor evidence index and Jira handoff guide.

The issue key is optional because some organizations create the Jira work item after evidence review. If the ticket is created later, do not rename or rewrite an existing immutable evidence set. Record the relationship in approved workpapers or recapture with the correct issue if policy requires the visible association.

## Prepare the attachment

1. Open **Search Evidence…** and select the artifact.
2. Confirm its status is **Approved** and that its framework, control, system, assessment period, owner, redactions, and Jira key are correct.
3. Choose **Copy Jira Comment**. Paste the generated summary into the intended ticket.
4. Attach one of the following complete sets:
   - Evidence set: PNG, capture manifest, review lifecycle, and signed receipt when available.
   - Package handoff: approved assessor ZIP and the separate `.sha256.txt` checksum.
5. Download the attachment from Jira and calculate SHA-256. Compare it with the manifest or checksum supplied by Scopeproof.
6. Record the successful handoff in the assessment workpapers according to organizational procedure.

Do not attach only a screenshot when its integrity and review sidecars are available. Those files establish scope, custody, review status, and tamper evidence.

## Jira comment contents

The generated comment includes the Jira key and URL, evidence ID, framework/control, system/environment, assessment period, capture timestamp, lifecycle status, owner/reviewer, screenshot SHA-256, expected attachment names, and a short statement describing what the evidence proves.

Review the text before posting. Jira permissions, notification recipients, automation rules, marketplace apps, backups, and exports can broaden access beyond the visible assignee list.

## Required safety checks

- The Jira project is approved for the evidence classification.
- External assessors have only the minimum required access.
- The issue does not inherit an unintended public, customer, or broad workspace permission.
- Jira retention, backup, legal-hold, and deletion policies match the assessment requirement.
- The attachment contains no unredacted PAN, sensitive authentication data, browser cookie, password, access token, private key, or unrelated personal data.
- The ticket key in Jira matches the key embedded in the evidence.
- The downloaded attachment hash matches Scopeproof after transfer.

If any check fails, do not attach the evidence. Correct the Jira access model or create a safer handoff channel first.

## Current limitation

Scopeproof 1.3.1 does not create Jira issues, query Jira, change ticket fields, or upload files through the Jira API. A future integration should use organization-approved OAuth, project allowlists, attachment size limits, explicit operator confirmation, immutable upload receipts, and narrowly scoped permissions.
