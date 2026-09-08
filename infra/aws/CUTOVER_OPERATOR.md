# Explicit acceptance-gated DNS cutover

The separate `cdk/runtime/cutover-operator` CLI implements offline planning,
read-only verification, explicit operator execution and read-only propagation
receipts. Nothing in this change ran against AWS. No production cutover or
recovery readiness is claimed.

```text
node infra/aws/cdk/runtime/cutover-operator/index.mjs plan mapping.json isolated-restore-receipt.json acceptance.json
node infra/aws/cdk/runtime/cutover-operator/index.mjs verify cutover-plan.json acceptance-signature.json
node infra/aws/cdk/runtime/cutover-operator/index.mjs execute cutover-plan.json acceptance-signature.json approval.json ACCEPTED_PLAN_DIGEST
node infra/aws/cdk/runtime/cutover-operator/index.mjs receipt cutover-plan.json submitted-receipt.json
```

The versioned mapping in `contract.mjs` contains the reviewed account, recovery
region, exact public hosted zone, operator role, separate acceptance/approval
KMS keys, tenant IDs, exact DNS names and full before/after CNAME or A-alias
records. It accepts at most forty names, no wildcards, no auth-domain changes,
no weighted/multi-value/failover records, and no account/region inference. Treat
the configuration as reviewed platform deployment output, never customer input.

The plan binds the restored-infrastructure receipt and its digest. An independent
application acceptance receipt must bind the exact mapping digest, restore-plan
digest, restore-receipt hash, target cluster, complete tenant set, primary-write
fence receipt hash and six affirmative gates: database reconciliation, session
reconciliation, evidence reconciliation, audit-chain verification, customer
acceptance and primary-write fencing. A restored cluster alone cannot qualify.

These gates are externally verified **prerequisites**. This CLI does not create
the recovery API/auth/frontend deployment, reconcile the database/control plane,
fence primary writers, or prove signed gate claims. The current infrastructure
still requires that work and an independent acceptance owner before real use.
It does not manufacture an acceptance receipt or accept the isolated restore
tool's `cutoverAuthorized: false` as authorization. Never sign acceptance until
the complete source and destination boundary has been exercised.

Sign SHA-256 of `scopeproof-cutover-acceptance-v1\n` plus canonical acceptance JSON
with the dedicated acceptance ECC_NIST_P256 key, ECDSA_SHA_256 / DIGEST. Supply
the base64 result as `{"signature":"..."}`. Acceptance lasts at most fifteen
minutes. A different approver signs `scopeproof-cutover-approval-v1\n` plus
canonical approval JSON, excluding signature, with the separate approval key.
Approval fields are schemaVersion 1, decision AUTHORIZE_DNS_CUTOVER, planDigest,
operatorRoleArn, approvedAt, expiresAt and signature. Approval must follow
acceptance, lasts at most fifteen minutes and requires the operator to explicitly
supply the same accepted digest. KMS Verify is performed again before execution.

Use separate reviewed IAM/key policies: validation operators alone can sign
acceptance, independent approvers alone can sign DNS approvals, and the cutover
operator can only Verify those keys plus inspect the exact zone/records and
change exact mapped DNS names/types with only CREATE and DELETE actions. Scope
Route 53 IAM with exact hosted-zone ARN and non-vacuous conditions for
`route53:ChangeResourceRecordSetsNormalizedRecordNames`,
`route53:ChangeResourceRecordSetsRecordTypes` and
`route53:ChangeResourceRecordSetsActions`. Deny UPSERT, wildcard names, KMS Sign
and unrelated data-plane writes. This CLI does not provision these prerequisite
roles/key policies or grant itself authority; no application/tenant role may
receive them.

Execution checks caller account/assumed role, exact public zone and every
current record. It submits one batch containing DELETE of each exact reviewed
preimage and CREATE of its accepted target. Route 53 validates this batch
atomically, so concurrent preimage drift fails instead of being silently
overwritten. See the official
[transactional change-batch contract](https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html).
Submission returns a change ID, not success. Receipt verification requires that
exact digest-tagged change to reach INSYNC and every target record to match.
Even DNS_INSYNC does not claim application health.

No automatic retry, rollback or return-to-primary exists. If submission is
uncertain, inspect the original change/DNS state. A deliberate rollback needs
a new exact preimage/target plan, fresh write-fence and acceptance evidence, a
new independent approval and explicit operator acceptance. Tests use fake AWS
adapters to prove contract/failure ordering; a disposable Route 53 drill and
end-to-end recovery acceptance remain release gates.
