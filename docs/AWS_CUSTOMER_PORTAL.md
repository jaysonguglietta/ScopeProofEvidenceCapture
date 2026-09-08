# AWS customer portal: install, configure and use

This is a separate **static AWS frontend**, not the Sites-hosted D1/R2 console.
Source: `infra/aws/customer-portal/`. It calls the tenant API and Amazon Cognito
directly. It has no server credentials, database connection or AWS access keys.
The CDK Amplify app now builds this artifact with platform `WEB`, not `.next`
SSR output. No deployment, AWS user creation or production cutover was performed
as part of this implementation.

## Prerequisites and boundaries

Read [database bootstrap](../infra/aws/DATABASE_BOOTSTRAP.md) and the
[implementation ledger](READINESS_IMPLEMENTATION_STATUS.md) before activation.
Provisioning must finish the reviewed migrations, private roles, initial admin,
tenant registry binding, identity clients, API routes, scanner and audit workers.
The AWS deployment currently requires the configured root/tenant domains; this
change does not add execute-api or arbitrary-host access. Existing scripts require
separate authorization before they may deploy anything.

This first customer workflow uses **operator-assisted existing Cognito users**.
An identity operator creates the user and securely supplies the exact Cognito
subject to the customer administrator. The portal invites that subject; email
is descriptive, not an authentication key. It neither creates Cognito accounts
nor sends invitation emails. A signed-in invited subject can accept its own
unexpired invitation before an active membership exists. The initial administrator
is established through the protected bootstrap workflow, not public signup or SQL
pasted into a browser.

## Build the reviewed static artifact (no AWS calls)

Use the repository's supported Node version. No npm packages are required for
this static build. Obtain the **public** `TenantPortalConfigJson` output from
each reviewed tenant stack. Create a JSON object keyed by its exact hostname:

```json
{
  "customer.example.com": {
    "tenantId": "ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "webOrigin": "https://customer.example.com",
    "apiOrigin": "https://api-customer.example.com",
    "oauthOrigin": "https://auth.example.com",
    "clientId": "replacewiththepubliccognitoclientid",
    "scopes": [
      "openid", "email", "profile",
      "scopeproof/evidence.read", "scopeproof/evidence.collect",
      "scopeproof/evidence.approve", "scopeproof/evidence.export",
      "scopeproof/audit.read", "scopeproof/retention.manage",
      "scopeproof/tenant.manage", "scopeproof/device.manage",
      "scopeproof/jobs.manage"
    ]
  }
}
```

These are examples, **not usable production identifiers**. Copy the exact scope
list from the stack output rather than adding unconfigured scopes. Do not place
passwords, private signing keys, access tokens, access keys, secret keys or a
Cognito client secret in this file. Public web clients must not have a secret.

Set `SCOPEPROOF_PORTAL_CONFIG_JSON` to this reviewed JSON via the build environment
and run:

```sh
node infra/aws/customer-portal/build.mjs
node --test tests/aws-customer-portal.test.mjs
```

Output is `.scopeproof-portal/` with `index.html`, callback HTML, JavaScript/CSS,
`tenant-config.json`, a response-header manifest and a source contract. The build
fails if configuration is missing, extra fields are supplied, origins are not
exact HTTPS origins, or the hostname does not match the tenant web origin.
The public config currently supports at most 100 explicitly named tenants.

CDK declares the static build and security response headers. **It does not
connect a repository or trigger an Amplify deployment.** An authorized operator
must connect the reviewed source branch or upload the reviewed artifact, set the
public build variable, and verify the `/auth/callback` rewrite and response
headers on the actual host. Auto-build and PR previews remain disabled. Do not
replace this artifact with the legacy console's output.

For local source inspection, serve the static directory on loopback. Interactive
login deliberately refuses HTTP/localhost configurations; use the authorized
HTTPS staging hostname for real OAuth tests, not a production-guard bypass.

## First customer workflow

1. Open the exact configured customer hostname and choose **Sign in**. Cognito
   performs authentication and MFA. After returning to `/auth/callback`, the API
   resolves the subject to the current tenant's membership.
2. If invited but not active, choose **Accept my invitation**. An invitation
   expires after seven days. No invitation for another subject is accepted.
3. As administrator, open **Members** to invite a collector and an independent
   reviewer. Assignment, suspension and revocation use the displayed revision.
   Self-administration and removing the last active administrator are protected.
   Changes invalidate earlier sessions. Revocation also revokes the member's
   devices and is not an ordinary reversible pause; use suspension when appropriate.
4. As administrator or compliance lead, open **Assessments**. Create a draft,
   choose the server-owned catalog, and enter exact system names and control IDs.
   Activate only after reviewing the scope. Active/evidenced scope is immutable;
   closing prevents new collection and review, not evidence retention.
5. In the Mac app, use the AWS tenant connection and device enrollment workflow,
   then select the active assessment and scoped control/system before submission.
   Choose **AWS Customer Workspace… → Submit / Check Capture…** after local
   capture/review. It requests an intent, uploads exact bytes once, and queries
   authoritative asynchronous scan/review status. Refresh explicitly; a PUT is
   not approval. See [native AWS configuration and onboarding](../macos/ScopeproofCapture/AWS_CUSTOMER_ONBOARDING.md)
   for bundled public settings, OAuth scope and uncertain-upload reconciliation.
   Browser **Devices** shows enrollment and allows explicit revocation; the browser
   cannot enroll a device on its behalf or invent a device identity.
6. In **Evidence**, load pages and choose **Inspect evidence**. Fetch the artifact.
   The client checks exact evidence revision, expiry, S3 version, byte count and
   SHA-256 before preview/download. JSON is text, never executable HTML. Text
   previews are limited to 64 KiB; downloads contain all verified bytes, up to
   the 25 MiB client safety cap.
7. A different reviewer or administrator can approve/reject current
   `NEEDS_REVIEW` evidence with a 20–2,000 character rationale. Missing promotion
   receipts, changed revisions, unscanned data, out-of-scope evidence, expired
   evidence and self-review remain blocked by the server. A collector cannot
   review other collectors' evidence.
8. Download only the authorized exact artifact. This AWS pilot does **not** imply
   that the Sites assessor-package, finding, collector or SBOM pages are ported.

Lists load 50 records per page, with explicit **Load more** and an end-of-results
message. Refresh the section for newer changes. API failure never populates
sample customers or successful-looking evidence.

## Exact-version legal holds

An administrator opens an artifact → **Legal holds and operations**. The request
contains an evidence ID and expected revision—not an S3 bucket, key or version.
The private server adapter resolves those storage coordinates.

- Select `LEGAL`, `AUDIT` or `SECURITY_INCIDENT`, supply a rationale and confirm.
- Another active administrator inspects the exact request and approves it.
- Refresh operation status until `APPLIED`. `REQUESTED` and `APPROVED` are not
  proof that S3 has changed. Inspect operator alarms when work stays pending.
- Release selects an existing active hold and its current revision. A separate
  administrator must approve release, too. Other active holds still preserve S3
  retention. Request IDs/digests and lifecycle revisions prevent stale approval.

The panel displays the latest 50 holds/operations and explicitly marks truncation;
older history remains in the audited backend. Neither release nor this portal
offers governance bypass or deletes evidence.

## Sessions and recovery

The browser uses authorization-code **PKCE S256**. Only the single-use state and
verifier are in session storage (ten-minute, host/client-bound transaction).
Tokens stay in page memory; refresh/ID tokens are discarded, and reload requires
sign-in. No third-party JavaScript or token-bearing application links are used.
See the [Cognito PKCE documentation](https://docs.aws.amazon.com/cognito/latest/developerguide/using-pkce-in-authorization-code.html).

**Sign out and revoke sessions** asks the resource server to revoke prior
sessions for this customer before opening Cognito logout. If revocation fails,
the page reports failure instead of claiming all sessions ended. **Clear this
page only** discards this page's token but explicitly does not revoke other
sessions. Consult [resource-server revocation](AWS_SESSION_AND_REPAIR_MIGRATION.md)
for cutoff semantics and operator-directed recovery.

## Qualification still required

The source tests validate PKCE/state/config boundaries, bounded responses,
exact-version intents, packaging and real PostgreSQL role/workflow semantics.
They do not replace a real two-tenant end-to-end HTTPS/Cognito/Mac/S3 test,
independent malware/DLP and witness service checks, alarm delivery, verified
backup recovery or signed-app Keychain/notarization qualification. Do not activate
customers or publish a production-ready claim until those gates are recorded.
