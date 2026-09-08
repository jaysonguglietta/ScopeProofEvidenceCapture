import test from "node:test";
import assert from "node:assert/strict";
import { createTenantPostgres, PostgresDataApiExecutor, seedCustomerTenant, seedPromotedEvidence, syntheticIds as ids } from "../helpers/aws-postgres.mjs";
import { RdsDataCustomerRepository, verifyDeviceEnrollment } from "../../lib/aws-runtime/http/customer.ts";
import { sha256Hex, stableJson } from "../../lib/aws-runtime/contracts.ts";
import { RdsDataApiAuditOutboxSignerStore } from "../../lib/aws-runtime/http/audit-outbox-drain.ts";
import { readFile } from "node:fs/promises";
import { createTenantApiHandler } from "../../lib/aws-runtime/http/lambda-api.ts";
import { RdsDataMembershipRepository } from "../../lib/aws-runtime/http/membership.ts";
import { TenantDirectory } from "../../lib/aws-runtime/tenancy.ts";
import { RdsDataExactVersionLegalHoldOperationStore, requestExactVersionLegalHoldChange, approveExactVersionLegalHoldChange } from "../../lib/aws-runtime/evidence/index.ts";

const connection = { resourceArn: "arn:aws:rds:us-east-1:111111111111:cluster:synthetic", secretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:synthetic", database: "synthetic" };
const authTime = new Date(Date.now()-60_000).toISOString();
function request(overrides = {}) { return { requestId: crypto.randomUUID(), actor: { tenantId: ids.tenant, userId: ids.user, membershipId: ids.member, role: "admin", tenantHostname: "test.example.com" }, identity: { signatureVerified: true, tokenUse: "access", subject: "synthetic-admin-subject", authenticatedAt: authTime, jwtId: "synthetic-jti-challenge-12345678" }, ...overrides }; }
const definition = { idempotencyKey: "synthetic-assessment-12345678", name: "September PCI operations", periodStart: "2026-09-01", periodEnd: "2026-09-30", catalogId: "pci-dss-4.0.1-scopeproof-operations-v1", systems: ["payments"], controls: ["6.3.2"], status: "DRAFT" };
const problem = (status) => (error) => error.safeStatus === status;

test("real PostgreSQL customer workflows, execute-only ACLs, immutable scope and atomic audit", async () => {
  const db = await createTenantPostgres();
  try {
    await seedCustomerTenant(db);
    const repository = new RdsDataCustomerRepository({ ...connection, tenantId: ids.tenant, executor: new PostgresDataApiExecutor(db, "scopeproof_test_runtime") });
    const legal = new RdsDataCustomerRepository({ ...connection, tenantId: ids.tenant, executor: new PostgresDataApiExecutor(db, "scopeproof_test_legal") });
    const admin = request();
    const call = (action, body, actor = admin) => repository.invoke({ ...actor, requestId: crypto.randomUUID() }, action, body);
    const members = await call("members.search", { cursor: null, limit: 10 });
    assert.equal(members.items[0].id, ids.user);
    const invite = await call("members.invite", { subject: "synthetic-reviewer-subject", email: "reviewer@example.com", displayName: "Independent reviewer", role: "reviewer" });
    assert.equal(invite.status, "INVITED");
    const reviewerIdentity = { ...admin.identity, subject: "synthetic-reviewer-subject" };
    await assert.rejects(repository.acceptInvitation({ tenantId: ids.tenant, identity: { ...reviewerIdentity, subject: "wrong-subject-123456" }, requestId: crypto.randomUUID() }), problem(403));
    const accepted = await repository.acceptInvitation({ tenantId: ids.tenant, identity: reviewerIdentity, requestId: crypto.randomUUID() });
    assert.equal(accepted.status, "ACTIVE");
    const reviewer = request({ actor: { ...admin.actor, userId: accepted.userId, membershipId: accepted.membershipId, role: "reviewer" }, identity: reviewerIdentity });
    await assert.rejects(call("members.search", { cursor: null, limit: 10 }, reviewer), problem(403));
    const draft = await call("assessments.create", definition);
    assert.equal(draft.status, "DRAFT");
    assert.equal((await call("assessments.create", definition)).id, draft.id);
    await assert.rejects(call("assessments.create", { ...definition, name: "Conflicting retry" }), problem(409));
    const { idempotencyKey: _key, ...edit } = definition;
    void _key;
    const active = await call("assessments.update", { ...edit, assessmentId: draft.id, expectedRevision: 0, status: "ACTIVE" });
    assert.equal(active.revision, 1);
    await assert.rejects(call("assessments.update", { ...edit, assessmentId: draft.id, expectedRevision: 1, status: "ACTIVE", systems: ["other"] }), problem(409));
    await assert.rejects(seedPromotedEvidence(db, { tenant: ids.tenant, assessmentId: draft.id, creatorId: ids.user, systemName: "outside-scope" }), { code: "42501" });
    await seedPromotedEvidence(db, { tenant: ids.tenant, assessmentId: draft.id, creatorId: ids.user });
    const review = { evidenceId: ids.evidence, expectedRevision: 1, decision: "APPROVED", reason: "Reviewed scope, freshness, provenance and content." };
    await assert.rejects(call("evidence.review", review), problem(409));
    assert.equal((await call("evidence.review", review, reviewer)).status, "APPROVED");
    await assert.rejects(call("evidence.review", review, reviewer), problem(409));
    assert.equal((await call("evidence.status", { evidenceId: ids.evidence })).revision, 2);
    const safe = await legal.legalHoldStatus(admin, ids.evidence);
    assert.deepEqual(safe.holds, []); assert.deepEqual(safe.operations, []);
    assert.equal(JSON.stringify(safe).includes("object_key"), false);
    const target = await legal.legalHoldTarget(admin, ids.evidence, 2);
    assert.equal(target.versionId, "synthetic-version-1");
    await assert.rejects(repository.legalHoldTarget(admin, ids.evidence, 2), problem(403));
    const rejectedEvidence = `evd_${"f".repeat(32)}`;
    await seedPromotedEvidence(db, { tenant: ids.tenant, assessmentId: draft.id, creatorId: ids.user, evidenceId: rejectedEvidence });
    assert.equal((await call("evidence.review", { ...review, evidenceId: rejectedEvidence, decision: "REJECTED" }, reviewer)).status, "REJECTED");
    assert.equal((await legal.legalHoldTarget(admin, rejectedEvidence, 2)).versionId, "synthetic-version-1");
    const noReceipt = `evd_${"1".repeat(32)}`;
    await seedPromotedEvidence(db, { tenant: ids.tenant, assessmentId: draft.id, creatorId: ids.user, evidenceId: noReceipt, receipt: false });
    await assert.rejects(call("evidence.review", { ...review, evidenceId: noReceipt }, reviewer), problem(403));
    const modified = await call("members.update", { principalId: accepted.userId, expectedRevision: 1, status: "SUSPENDED", role: "reviewer" });
    assert.equal(modified.status, "SUSPENDED");
    await assert.rejects(call("evidence.status", { evidenceId: ids.evidence }, reviewer), problem(403));
    await call("members.update", { principalId: accepted.userId, expectedRevision: 2, status: "ACTIVE", role: "reviewer" });
    await assert.rejects(call("evidence.status", { evidenceId: ids.evidence }, reviewer), problem(403));
    assert.equal((await call("evidence.status", { evidenceId: ids.evidence }, { ...reviewer, identity: { ...reviewerIdentity, authenticatedAt: new Date(Date.now()+1000).toISOString() } })).status, "APPROVED");
    const count = await db.query("SELECT count(*)::int AS count FROM scopeproof.api_audit_outbox");
    assert.equal(count.rows[0].count, 8); // retries and failed actions did not create false-success audit rows.
    const signer = new RdsDataApiAuditOutboxSignerStore({ ...connection, executor: new PostgresDataApiExecutor(db), signingKeyArn: "arn:aws:kms:us-east-1:111111111111:key/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", kms: {} });
    assert.equal((await signer.claim({ tenantId: ids.tenant, leaseToken: "synthetic_lease_token_12345678", claimedAt: new Date(), leaseSeconds: 60 })).action, "customer.members_invited");
    assert.equal((await db.query("SELECT * FROM scopeproof.list_unaudited_applied_legal_holds(10)")).rows.length, 0);
    await db.exec("SET ROLE scopeproof_test_runtime");
    await assert.rejects(db.query("SELECT * FROM scopeproof.principals"), { code: "42501" });
    await assert.rejects(db.query("SELECT * FROM scopeproof.customer_control_catalogs"), { code: "42501" });
    await db.exec("RESET ROLE");
  } finally { await db.close(); }
});

test("two physical tenant databases reject wrong-tenant context even with colliding IDs", async () => {
  const a = await createTenantPostgres(); const b = await createTenantPostgres();
  try {
    const tenantB = `ten_${"2".repeat(32)}`;
    await seedCustomerTenant(a); await seedCustomerTenant(b, tenantB);
    const wrong = new RdsDataCustomerRepository({ ...connection, tenantId: ids.tenant, executor: new PostgresDataApiExecutor(b, "scopeproof_test_runtime") });
    await assert.rejects(wrong.invoke(request(), "members.search", { cursor: null, limit: 100 }), problem(403));
    const correct = new RdsDataCustomerRepository({ ...connection, tenantId: tenantB, executor: new PostgresDataApiExecutor(b, "scopeproof_test_runtime") });
    await assert.rejects(correct.invoke(request(), "members.search", { cursor: null, limit: 100 }), problem(403));
    assert.equal((await correct.invoke(request({ actor: { ...request().actor, tenantId: tenantB } }), "members.search", { cursor: null, limit: 100 })).tenantId, tenantB);
  } finally { await a.close(); await b.close(); }
});

test("device enrollment proves fresh token-bound P-256 key possession", async () => {
  const actor = request(); const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const der = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const publicKeySha256 = await sha256Hex(der); const signedAt = new Date().toISOString();
  const manifest = { schemaVersion: 1, tenantId: ids.tenant, userId: ids.user, deviceId: ids.device, displayName: "Synthetic Mac", publicKeySha256, challenge: actor.identity.jwtId, signedAt };
  const signature = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, new TextEncoder().encode(`scopeproof-device-enrollment-v1\n${stableJson(manifest)}`));
  const body = { deviceId: ids.device, displayName: manifest.displayName, publicKeySpki: Buffer.from(der).toString("base64url"), signature: Buffer.from(signature).toString("base64url"), signedAt };
  assert.equal((await verifyDeviceEnrollment(actor, body)).publicKeySha256, publicKeySha256);
  await assert.rejects(verifyDeviceEnrollment({ ...actor, identity: { ...actor.identity, jwtId: "different-challenge" } }, body), problem(403));
  await assert.rejects(verifyDeviceEnrollment(actor, { ...body, signedAt: new Date(Date.now()-600_000).toISOString() }), problem(401));
  const db = await createTenantPostgres();
  try {
    await seedCustomerTenant(db);
    const repository = new RdsDataCustomerRepository({ ...connection, tenantId: ids.tenant, executor: new PostgresDataApiExecutor(db, "scopeproof_test_runtime") });
    assert.equal((await repository.invoke(actor, "devices.enroll", body)).status, "ACTIVE");
    assert.equal((await repository.invoke({ ...actor, requestId: crypto.randomUUID() }, "devices.enroll", body)).revision, 0);
    assert.equal((await repository.invoke({ ...actor, requestId: crypto.randomUUID() }, "devices.revoke", { deviceId: ids.device, expectedRevision: 0 })).status, "REVOKED");
    await assert.rejects(repository.invoke({ ...actor, requestId: crypto.randomUUID() }, "devices.enroll", body), problem(409));
    assert.equal((await db.query("SELECT count(*)::int AS count FROM scopeproof.api_audit_outbox")).rows[0].count, 2);
  } finally { await db.close(); }
});

test("actual 010 session cutoff and six-minute upload repair fixture runs after forward011", async () => {
  const db = await createTenantPostgres();
  try {
    await db.exec("CREATE ROLE tenant_scopeproof_test_runtime NOLOGIN");
    const grants = await readFile(new URL("../../infra/aws/database/002_runtime_role.sql", import.meta.url), "utf8");
    await db.exec(grants.replaceAll("__SCOPEPROOF_RUNTIME_ROLE__", "tenant_scopeproof_test_runtime"));
    await db.exec(await readFile(new URL("aws-session-repair-semantic.sql", import.meta.url), "utf8"));
  } finally { await db.close(); }
});

test("HTTP customer routes enforce exact bodies, OAuth scopes, subject acceptance and evidence-ID holds backed by real SQL", async () => {
  const db = await createTenantPostgres();
  try {
    await seedCustomerTenant(db);
    const executor = new PostgresDataApiExecutor(db);
    const repository = new RdsDataCustomerRepository({ ...connection, tenantId: ids.tenant, executor });
    const membership = new RdsDataMembershipRepository({ ...connection, executor });
    const store = new RdsDataExactVersionLegalHoldOperationStore({ ...connection, executor });
    const tenant = { id: ids.tenant, slug: "test", displayName: "Synthetic tenant", appClientId: "synthetic-web-client", appClientIds: ["synthetic-web-client", "synthetic-native-client"], status: "active" };
    const directory = new TenantDirectory([tenant], [{ tenantId: ids.tenant, hostname: "test.example.com", status: "active", canonical: true }]);
    let identity = { ...request().identity, issuer: "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_synthetic", clientId: tenant.appClientId, expiresAt: new Date(Date.now()+900_000).toISOString(), scopes: ["scopeproof/tenant.manage", "scopeproof/evidence.read", "scopeproof/evidence.collect", "scopeproof/jobs.manage", "scopeproof/retention.manage"] };
    const api = createTenantApiHandler({ apiHostname: "test.example.com", allowedOrigin: "https://test.example.com", createRequestRuntime: () => ({
      authentication: { tenants: directory, jwt: { verify: async () => identity }, memberships: membership, authority: { mode: "api_gateway_domain" } },
      customer: (actor, action, body) => repository.invoke(actor, action, body),
      acceptInvitation: (actor) => repository.acceptInvitation(actor),
      legalHoldStatus: (actor, evidenceId) => repository.legalHoldStatus(actor, evidenceId),
      requestEvidenceLegalHold: async (actor, payload) => {
        const location = await repository.legalHoldTarget(actor, payload.evidenceId, payload.expectedEvidenceRevision);
        const { expectedEvidenceRevision: _revision, ...body } = payload;
        void _revision;
        return await requestExactVersionLegalHoldChange(store, { ...body, ...location }, actor.actor, { evidenceBucket: "scopeproof-test-evidence" }, { membershipId: actor.actor.membershipId, requestId: actor.requestId });
      },
      approveLegalHold: (actor, payload) => approveExactVersionLegalHoldChange(store, { ...payload, tenantId: actor.actor.tenantId }, actor.actor, { membershipId: actor.actor.membershipId, requestId: actor.requestId }),
    }) });
    const post = (path, body, method = "POST") => api({ path, httpMethod: method, body: JSON.stringify(body), headers: { authorization: "Bearer aaa.bbb.ccc", "content-type": "application/json", origin: "https://test.example.com" }, requestContext: { domainName: "test.example.com", requestId: crypto.randomUUID() } });
    assert.equal((await post("/v1/customer/members/search", { cursor: null, limit: 10 })).statusCode, 200);
    assert.equal((await post("/v1/customer/members/search", { cursor: null, limit: 10, tenantId: ids.tenant })).statusCode, 400);
    assert.equal((await post("/v1/customer/members/search", { cursor: null, limit: 10 }, "GET")).statusCode, 405);
    assert.equal(JSON.parse((await post("/v1/collector/me", {}, "GET")).body).uploadProofChallenge, identity.jwtId);
    const invited = JSON.parse((await post("/v1/customer/invitations", { subject: "synthetic-second-admin", email: "second@example.com", displayName: "Second administrator", role: "admin" })).body);
    identity = { ...identity, subject: "synthetic-second-admin" };
    assert.equal((await post("/v1/customer/members/search", { cursor: null, limit: 10 })).statusCode, 403);
    const accepted = JSON.parse((await post("/v1/customer/invitations/accept", {})).body);
    assert.equal(accepted.userId, invited.id);
    identity = { ...identity, clientId: "foreign-tenant-client" };
    assert.equal((await post("/v1/customer/invitations/accept", {})).statusCode, 401);
    identity = { ...identity, subject: "synthetic-admin-subject", clientId: tenant.appClientId };
    const draft = JSON.parse((await post("/v1/customer/assessments/create", { ...definition, status: "ACTIVE" })).body);
    await seedPromotedEvidence(db, { tenant: ids.tenant, assessmentId: draft.id, creatorId: ids.user });
    const holdBody = { evidenceId: ids.evidence, expectedEvidenceRevision: 1, operationId: `lho_${"3".repeat(32)}`, holdId: `hld_${"4".repeat(32)}`, expectedHoldRevision: 0, kind: "LEGAL", status: "ON", reason: "Preserve the exact evidence for independent investigation.", changedAt: new Date().toISOString() };
    assert.equal((await post("/v1/legal-hold-requests/by-evidence", { ...holdBody, key: "browser-controlled-key" })).statusCode, 400);
    const requested = await post("/v1/legal-hold-requests/by-evidence", holdBody);
    assert.equal(requested.statusCode, 202, `${requested.body} ${JSON.stringify(executor.lastError)}`);
    const pending = JSON.parse(requested.body);
    const status = JSON.parse((await post("/v1/legal-hold-requests/status", { evidenceId: ids.evidence })).body);
    assert.equal(status.operations[0].state, "REQUESTED"); assert.equal(status.operations[0].requestDigest, pending.requestDigest);
    assert.equal(JSON.stringify(status).includes("tenants/"), false);
    const selfApproval = await post("/v1/legal-hold-approvals", { operationId: pending.operationId, requestDigest: pending.requestDigest, approvedAt: new Date().toISOString() });
    assert.equal(selfApproval.statusCode, 403, JSON.stringify(executor.lastError));
    identity = { ...identity, subject: "synthetic-second-admin" };
    const approved = await post("/v1/legal-hold-approvals", { operationId: pending.operationId, requestDigest: pending.requestDigest, approvedAt: new Date().toISOString() });
    assert.equal(approved.statusCode, 202, `${approved.body} ${JSON.stringify(executor.lastError)}`);
    assert.equal(JSON.parse((await post("/v1/legal-hold-requests/status", { evidenceId: ids.evidence })).body).operations[0].state, "APPROVED");
    identity = { ...identity, scopes: ["scopeproof/evidence.read"] };
    assert.equal((await post("/v1/customer/members/search", { cursor: null, limit: 10 })).statusCode, 403);
    assert.equal((await post("/v1/legal-hold-requests/status", { evidenceId: ids.evidence })).statusCode, 403);
  } finally { await db.close(); }
});
