# Jira Cloud evidence handoff

Scopeproof supports an explicit Jira Cloud attachment workflow through Atlassian OAuth 2.0 (3LO). OAuth tokens are encrypted in the hosted service and never enter the Mac app. Evidence is never sent automatically: the operator must approve an artifact, select the destination issue, review a confirmation containing the live issue summary, and choose **Upload to Jira Cloud**.

The manual **Copy Jira Comment** and attachment workflow remains available when OAuth is unavailable or organizational policy requires a separate transfer channel.

## Connect Jira Cloud

1. Ask the Scopeproof platform administrator to configure the Atlassian OAuth client and apply the Jira database migration.
2. In the Scopeproof web console, open **Connections → Jira Cloud**.
3. Enter the root site URL, such as `https://company.atlassian.net`.
4. Enter 1–20 project keys allowed to receive evidence, such as `GRC, PCI`.
5. Choose **Connect Jira Cloud**, select the intended site on Atlassian’s consent screen, and approve access.
6. Return to **Connections** and choose **Test connection**.

Scopeproof rejects non-Atlassian hosts, embedded credentials, non-root paths, sites that do not match the requested site, and issues outside the configured project allowlist. Each user authorizes their own Jira access; Jira permissions still constrain every request.

## Configure Jira routing

Open **Scopeproof shield → Capture & Jira Settings…** and configure local handoff defaults:

- **Jira site URL:** the organization’s HTTPS Jira base URL, for example `https://company.atlassian.net`.
- **Default project:** an uppercase project key such as `GRC` or `PCI`.
- **Attachment set:** either the individual evidence set or an approved assessor ZIP plus checksum.
- **Include Jira handoff guide:** adds `05-Jira-Handoff.txt` to local assessor packages.
- **Organization instructions:** approved issue type, reviewers, classification, retention, or internal routing requirements.

These Mac settings contain routing and procedure information only. Jira Cloud authentication is configured in the web console. Do not enter a Jira API token, password, cookie, or recovery code into the Mac app.

## Associate a capture with a ticket

Enter an issue key such as `GRC-123` in the capture-classification dialog. Scopeproof validates the format and records the key in:

- the screenshot’s visible banner;
- the filename;
- the immutable capture manifest;
- local evidence search;
- hosted evidence metadata after upload;
- the assessor evidence index and Jira handoff guide.

The issue key is optional because some organizations create the Jira work item after evidence review. If the ticket is created later, do not rename or rewrite an existing immutable evidence set. Record the relationship in approved workpapers or recapture with the correct issue if policy requires the visible association.

## Upload approved evidence from the Mac

1. Open **Search Evidence…** and select an artifact with a Jira issue key.
2. Upload that exact evidence set to Scopeproof if it is still local-only.
3. In the web console, have an authenticated reviewer approve the hosted artifact. Confirm its local lifecycle status is also **Approved** and its review rationale is complete.
4. Choose **Upload to Jira Cloud…**. Scopeproof retrieves the live issue and displays its key, summary, and status.
5. Confirm the destination. Scopeproof sends the redacted PNG, immutable capture manifest, Approved lifecycle record, and server receipt when available.
6. Keep the resulting `.jira.json` receipt beside the evidence set. The hosted audit chain records the Jira attachment IDs and receipt hash.

Before disclosure, the backend independently checks the device token, Jira OAuth grant, requested site, project allowlist, issue visibility, attachment permission, PNG signature and SHA-256, manifest safety state, Jira key consistency, lifecycle status, and every lifecycle chain hash.

## Manual fallback

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

## Current limitations

Scopeproof does not create Jira issues, change fields, delete attachments, or upload assessor ZIPs through the Jira API. A Jira request that times out after Atlassian receives it can have an ambiguous outcome; inspect the issue before retrying to avoid a duplicate attachment. Disconnecting Scopeproof deletes its encrypted OAuth tokens but does not revoke consent inside Atlassian or remove existing attachments.
