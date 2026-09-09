import { boundedBytes, validateDownloadIntent, validateLoginTransaction, validatePortalConfiguration } from "/security.mjs";

const $ = (id) => document.getElementById(id);
let configuration, accessToken, me, tokenTimer, currentView = "Evidence", viewEpoch = 0;
const objectUrls = new Set();
const transactionKey = "scopeproof.aws.pkce.v1";
const roles = ["collector", "auditor", "reviewer", "compliance_lead", "admin"];
const writable = () => ["admin", "compliance_lead"].includes(me?.role);
const reviewable = () => ["admin", "reviewer"].includes(me?.role);
const button = (text, run, className = "") => {
  const element = node("button", text, className); element.type = "button";
  element.addEventListener("click", () => action(element, run)); return element;
};
function node(tag, text, className = "") { const element = document.createElement(tag); if (text !== undefined) element.textContent = text; if (className) element.className = className; return element; }
function message(text, error = false) { const element = $(error ? "error" : "notice"); element.textContent = text; element.hidden = !text; }
function clearMessages() { message(""); message("", true); }
async function action(element, run) {
  if (element.disabled) return; element.disabled = true; clearMessages();
  try { await run(); } catch (error) { message(error instanceof Error ? error.message : "The operation failed. Refresh and try again.", true); }
  finally { element.disabled = false; }
}
function releasePreviews() { for (const url of objectUrls) URL.revokeObjectURL(url); objectUrls.clear(); }
function clearSession() { accessToken = undefined; me = undefined; clearTimeout(tokenTimer); releasePreviews(); viewEpoch++; $("content").replaceChildren(); $("navigation").hidden = true; $("session").hidden = false; $("session-actions").replaceChildren(); }
function base64url(bytes) { return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", ""); }
function identifier(prefix) { return prefix + crypto.randomUUID().replaceAll("-", ""); }
async function sha256(bytes) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))].map((value) => value.toString(16).padStart(2, "0")).join(""); }
async function jsonRequest(url, options, maximum = 1048576) {
  const response = await fetch(url, { ...options, credentials: "omit", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(15000) });
  if (!response.ok) {
    await response.body?.cancel();
    const error = new Error(response.status === 409 ? "This record changed or cannot make that transition. Refresh it before retrying."
      : response.status === 401 ? "Your session expired or was revoked. Sign in again."
      : response.status === 403 ? "Your active membership or role does not permit this action."
      : response.status === 404 ? "This record is unavailable in your customer workspace."
      : response.status === 429 ? "Too many requests. Wait a minute, then retry."
      : `The service could not complete the request (${response.status}). No success has been assumed.`);
    error.status = response.status; throw error;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(await boundedBytes(response, maximum)));
}
async function api(path, body) {
  if (!accessToken || !path.startsWith("/v1/")) throw new Error("Sign in before using this workspace.");
  const reply = await jsonRequest(configuration.apiOrigin + path, { method: body === undefined ? "GET" : "POST", headers: { Authorization: `Bearer ${accessToken}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  if (reply.tenantId !== undefined && reply.tenantId !== configuration.tenantId) { clearSession(); throw new Error("The response belongs to a different tenant. Access has been stopped."); }
  return reply;
}
async function signIn() {
  const verifier = base64url(crypto.getRandomValues(new Uint8Array(32))), state = base64url(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  sessionStorage.setItem(transactionKey, JSON.stringify({ verifier, state, createdAt: Date.now(), origin: configuration.webOrigin, oauthOrigin: configuration.oauthOrigin, clientId: configuration.clientId }));
  const url = new URL("/oauth2/authorize", configuration.oauthOrigin);
  for (const [key, value] of Object.entries({ response_type: "code", client_id: configuration.clientId, redirect_uri: configuration.webOrigin + "/auth/callback", scope: configuration.scopes.join(" "), state, code_challenge: challenge, code_challenge_method: "S256", prompt: "login" })) url.searchParams.set(key, value);
  location.assign(url);
}
function signInPrompt(text = "Sign in using your organization’s Cognito account.") {
  $("session").hidden = false; $("connection-state").textContent = text;
  $("session-actions").replaceChildren(button("Sign in", signIn, "primary"));
}
async function establishSession() {
  try { try { me = await api("/v1/me"); } catch (error) { if (error.status !== 403) throw error; me = await api("/v1/collector/me"); } }
  catch (error) {
    if (error.status !== 403) throw error;
    $("connection-state").textContent = "You are signed in, but no active membership was found. An administrator must first invite your existing Cognito subject. Invitations expire after seven days.";
    $("session-actions").replaceChildren(button("Accept my invitation", async () => { await api("/v1/customer/invitations/accept", {}); await establishSession(); }, "primary"), button("Start sign-in again", signIn)); return;
  }
  if (me.tenantId !== configuration.tenantId || !roles.includes(me.role)) throw new Error("Session membership does not match this customer configuration.");
  $("session").hidden = true; $("tenant-name").textContent = `${location.hostname} · ${me.role.replaceAll("_", " ")}`;
  $("session-actions").replaceChildren(button("Sign out and revoke sessions", async () => {
    if (!confirm("Revoke all your existing Scopeproof sessions for this customer? Other signed-in clients will need to authenticate again.")) return;
    await api(me.role === "collector" ? "/v1/collector/sessions/revoke" : "/v1/sessions/revoke", {}); clearSession();
    const logout = new URL("/logout", configuration.oauthOrigin); logout.searchParams.set("client_id", configuration.clientId); logout.searchParams.set("logout_uri", configuration.webOrigin + "/"); location.assign(logout);
  }), button("Clear this page only", () => { clearSession(); signInPrompt("Page token cleared. Other sessions have not been revoked."); }));
  const views = ["Evidence", "Assessments", ...(writable() ? ["Devices"] : []), ...(me.role === "admin" ? ["Members"] : []), "Help"];
  $("navigation").replaceChildren(...views.map((view) => button(view, () => openView(view)))); $("navigation").hidden = false;
  await openView(me.role === "collector" ? "Assessments" : currentView);
}
function section(title, description) { const element = node("section", undefined, "card"); element.append(node("h2", title)); if (description) element.append(node("p", description, "muted")); return element; }
function field(form, label, value = "", type = "text", choices) {
  const wrapper = node("label", label); const input = node(choices ? "select" : type === "textarea" ? "textarea" : "input");
  if (choices) for (const choice of choices) { const option = node("option", typeof choice === "string" ? choice : choice.label); option.value = typeof choice === "string" ? choice : choice.value; input.append(option); }
  else if (type !== "textarea") input.type = type;
  input.value = value; input.required = true; if (!choices && type !== "date") input.maxLength = type === "textarea" ? 2000 : 160;
  wrapper.append(input); form.append(wrapper); return input;
}
function submit(form, label, run) {
  const element = node("button", label, "primary"); element.type = "submit"; form.append(element);
  const errorBox = node("p"); errorBox.setAttribute("role", "alert"); form.append(errorBox);
  form.addEventListener("submit", (event) => { event.preventDefault(); if (form.reportValidity()) action(element, async () => { errorBox.textContent = ""; try { await run(); } catch (error) { errorBox.textContent = error.message; throw error; } }); });
}
function downloadBlob(blob, name) {
  const url = URL.createObjectURL(blob), anchor = node("a"); anchor.href = url; anchor.download = name; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 60000);
}
async function openView(view) {
  currentView = view; const epoch = ++viewEpoch; releasePreviews(); clearMessages();
  for (const item of $("navigation").children) { if (item.textContent === view) item.setAttribute("aria-current", "page"); else item.removeAttribute("aria-current"); }
  $("content").replaceChildren(node("p", "Loading workspace…", "muted"));
  try {
    const output = view === "Evidence" ? await evidenceView(epoch) : view === "Assessments" ? await assessmentsView(epoch) : view === "Members" ? await membersView(epoch) : view === "Devices" ? await devicesView(epoch) : helpView();
    if (epoch === viewEpoch) $("content").replaceChildren(output);
  } catch (error) { if (epoch === viewEpoch) { $("content").replaceChildren(button("Retry this section", () => openView(view))); throw error; } }
}
async function paginated(path, title, description, render, epoch) {
  const output = section(title, description), items = node("div"); let cursor = null; const seen = new Set();
  const next = button("Load more", () => load()); const status = node("p", "", "muted"); status.setAttribute("role", "status");
  output.append(items, status, next);
  async function load() {
    const result = await api(path, { limit: 50, cursor });
    if (epoch !== viewEpoch) return result;
    if (!Array.isArray(result.items)) throw new Error("The server returned an invalid page.");
    for (const record of result.items) { const id = record.id || record.evidenceId; if (!seen.has(id)) { seen.add(id); items.append(render(record)); } }
    cursor = result.nextCursor; next.hidden = !cursor; status.textContent = seen.size ? `${seen.size} records loaded${cursor ? " · more available" : " · end of results"}. Refresh this section to see newer changes.` : "No records yet. Nothing has been pre-populated.";
    return result;
  }
  const first = await load(); return { output, first };
}
async function evidenceView(epoch) {
  if (me.role === "collector") return section("Evidence review is separate from collection", "Collectors can submit from the Mac app and inspect their own transfer status there. A reviewer or administrator independently reviews promoted evidence here.");
  const { output } = await paginated("/v1/evidence/search", "Evidence library", "Artifacts are loaded from this tenant’s API. Downloads are pinned to an immutable S3 version and checked against the expected size and SHA-256 before display or saving.", (record) => {
    const item = section(record.title || record.evidenceId, `${record.controlId} · ${record.systemName} · ${record.source}`);
    item.append(node("span", record.status, "status"), node("small", `Captured ${record.capturedAt} · ${record.byteSize.toLocaleString()} bytes · revision ${record.revision}`), button("Inspect evidence", () => inspectEvidence(record, epoch, item)));
    return item;
  }, epoch); return output;
}
async function inspectEvidence(record, epoch, container) {
  const status = await api("/v1/customer/evidence/status", { evidenceId: record.evidenceId });
  if (epoch !== viewEpoch) return;
  if (status.revision !== record.revision || status.checksumSha256 !== record.checksumSha256) throw new Error("Evidence changed since this list loaded. Refresh the Evidence section first.");
  container.replaceChildren(node("h3", status.title), node("p", `${status.controlId} · ${status.systemName} · ${status.status}`), node("code", status.checksumSha256));
  const actions = node("div", undefined, "actions"), details = node("div"); container.append(actions, details);
  let verifiedBlob;
  const reviewButton = button("Review verified artifact", () => {
    if (!verifiedBlob) throw new Error("Fetch and verify the artifact first.");
    const form = node("form"); const decision = field(form, "Decision", "APPROVED", "text", ["APPROVED", "REJECTED"]); const reason = field(form, "Review rationale (20–2,000 characters)", "", "textarea"); reason.minLength = 20;
    submit(form, "Record independent decision", async () => {
      if (!confirm(`Record ${decision.value.toLowerCase()} for this exact evidence revision?`)) return;
      const reply = await api("/v1/customer/evidence/review", { evidenceId: status.evidenceId, expectedRevision: status.revision, decision: decision.value, reason: reason.value.trim() });
      await openView("Evidence"); message(`Decision recorded: ${reply.status}, revision ${reply.revision}.`);
    }); details.append(form); reviewButton.remove();
  });
  reviewButton.disabled = true;
  actions.append(button("Fetch and verify artifact", async () => {
    const intent = await api("/v1/evidence-download-intents", { evidenceId: record.evidenceId, expectedRevision: record.revision });
    const url = validateDownloadIntent(intent, record);
    const response = await fetch(url, { method: "GET", headers: intent.download.requiredHeaders || {}, credentials: "omit", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(60000) });
    const bytes = await boundedBytes(response, intent.expectedSize);
    if (bytes.byteLength !== intent.expectedSize || await sha256(bytes) !== intent.expectedSha256) throw new Error("Artifact integrity failed. No file was displayed or saved.");
    if (epoch !== viewEpoch) return;
    verifiedBlob = new Blob([bytes], { type: intent.contentType }); details.replaceChildren(node("p", "Exact-version artifact verified against the server’s SHA-256 and size."));
    if (intent.contentType === "image/png" || intent.contentType === "image/jpeg") { const img = node("img"); img.alt = `Evidence for ${status.controlId}: ${status.title}`; img.className = "preview"; img.src = URL.createObjectURL(verifiedBlob); objectUrls.add(img.src); details.append(img); }
    else if (["application/json", "text/plain", "application/vnd.cyclonedx+json", "application/spdx+json"].includes(intent.contentType)) details.append(node("pre", new TextDecoder().decode(bytes.slice(0, 65536))), node("small", bytes.length > 65536 ? "Preview limited to the first 64 KiB. Download contains the complete verified artifact." : "Complete text preview."));
    else details.append(node("p", "This artifact is available as a verified download; it is not executed or embedded."));
    details.append(button("Download verified file", () => downloadBlob(verifiedBlob, `${record.evidenceId}.${intent.contentType === "image/png" ? "png" : intent.contentType === "image/jpeg" ? "jpg" : intent.contentType.includes("json") ? "json" : "bin"}`)));
    reviewButton.disabled = !(reviewable() && status.status === "NEEDS_REVIEW" && status.createdBy !== me.userId && Date.parse(status.expiresAt) > Date.now());
  }));
  if (reviewable()) { actions.append(reviewButton); details.append(node("small", status.createdBy === me.userId ? "You collected this artifact. Another reviewer must decide." : "Only current, unexpired NEEDS_REVIEW artifacts can be approved or rejected.")); }
  if (me.role === "admin") actions.append(button("Legal holds and operations", async () => { const panel = await holdPanel(status); if (epoch === viewEpoch) details.replaceChildren(panel); }));
}
async function assessmentsView(epoch) {
  const path = me.role === "collector" ? "/v1/customer/collector-assessments/search" : "/v1/customer/assessments/search";
  let catalogs = [];
  const { output, first } = await paginated(path, "Assessments and collection scope", "Create a draft, select a catalog and exact systems/controls, then activate it for collection. Active or evidenced scope is immutable; create a new assessment when scope changes.", (record) => {
    const item = section(record.name, `${record.periodStart} – ${record.periodEnd} · ${record.framework}`);
    item.append(node("span", record.status, "status"), node("p", `Systems: ${record.systems.join(", ") || "None"}`), node("p", `Controls: ${record.controls.join(", ") || "None"}`), node("code", record.id));
    if (writable() && record.status !== "CLOSED") item.append(button(record.status === "DRAFT" ? "Edit / activate draft" : "Close assessment", () => {
      const existing = item.querySelector("form"); if (existing) existing.remove(); item.append(assessmentForm(catalogs, record));
    })); return item;
  }, epoch);
  catalogs = first.catalogs;
  if (!Array.isArray(catalogs)) throw new Error("Assessment catalogs are unavailable.");
  if (writable()) { const create = section("New assessment", "Start with a draft. Catalog controls are server-owned; client-entered unknown controls are rejected."); create.append(assessmentForm(catalogs)); output.prepend(create); }
  return output;
}
function assessmentForm(catalogs, record) {
  const form = node("form"); const name = field(form, "Assessment name", record?.name); name.minLength = 2;
  const from = field(form, "Period starts", record?.periodStart || new Date().toISOString().slice(0, 10), "date"), to = field(form, "Period ends", record?.periodEnd || new Date().toISOString().slice(0, 10), "date");
  const catalog = field(form, "Control catalog", record?.catalogId || catalogs[0]?.id || "", "text", catalogs.map((item) => ({ value: item.id, label: `${item.title} · ${item.version}` })));
  const systems = field(form, "Exact system names (one per line)", record?.systems.join("\n") || "", "textarea"); systems.required = false;
  const controls = field(form, "Exact control IDs (one per line)", record?.controls.join("\n") || "", "textarea"); controls.required = false;
  const help = node("p", "", "muted"); form.append(help);
  function showCatalog() { const selected = catalogs.find((item) => item.id === catalog.value); help.textContent = `Available controls: ${(selected?.controls || []).map((item) => typeof item === "string" ? item : item.id).join(", ")}`; }
  catalog.addEventListener("change", showCatalog); showCatalog();
  const status = field(form, "Lifecycle", record?.status || "DRAFT", "text", record?.status === "ACTIVE" ? ["ACTIVE", "CLOSED"] : ["DRAFT", "ACTIVE"]);
  if (record?.scopeLocked) for (const input of [name, from, to, catalog, systems, controls]) input.disabled = true;
  const idempotencyKey = crypto.randomUUID();
  submit(form, record ? "Save assessment revision" : "Create assessment", async () => {
    if (status.value === "CLOSED" && !confirm("Close this assessment? New collection and review will stop; evidence is retained.")) return;
    const lines = (input) => input.value.split("\n").map((line) => line.trim()).filter(Boolean);
    if (from.value > to.value) throw new Error("The period end must be on or after its start.");
    const body = { name: name.value.trim(), periodStart: from.value, periodEnd: to.value, catalogId: catalog.value, systems: lines(systems), controls: lines(controls), status: status.value, ...(record ? { assessmentId: record.id, expectedRevision: record.revision } : { idempotencyKey }) };
    await api(`/v1/customer/assessments/${record ? "update" : "create"}`, body); await openView("Assessments"); message("Assessment saved. The displayed revision is now authoritative.");
  }); return form;
}
async function membersView(epoch) {
  const { output } = await paginated("/v1/customer/members/search", "Members and invitations", "This pilot invites existing Cognito subjects. An operator creates the Cognito account first; this form does not send email or create an identity. Revocation is final and invalidates existing sessions and enrolled devices.", (record) => {
    const item = section(record.displayName, `${record.email} · ${record.status}`); item.append(node("code", record.id), node("small", `${record.role} · revision ${record.revision}${record.invitationExpiresAt ? ` · invitation expires ${record.invitationExpiresAt}` : ""}`));
    if (record.id === me.userId || record.status === "REVOKED") item.append(node("p", record.id === me.userId ? "Self-administration is protected; ask another administrator to change your membership." : "Revoked memberships cannot be reactivated here."));
    else {
      const form = node("form"), role = field(form, "Role", record.role, "text", roles), status = field(form, "Membership state", record.status === "INVITED" ? "REVOKED" : record.status, "text", record.status === "INVITED" ? ["REVOKED"] : ["ACTIVE", "SUSPENDED", "REVOKED"]);
      submit(form, "Update member", async () => { if (!confirm(`Change ${record.displayName} to ${role.value}, ${status.value}? Existing sessions must sign in again.`)) return; await api("/v1/customer/members/update", { principalId: record.id, expectedRevision: record.revision, role: role.value, status: status.value }); await openView("Members"); message("Membership updated and prior sessions invalidated."); }); item.append(form);
    } return item;
  }, epoch);
  const invite = section("Invite an existing Cognito user", "Verify the subject with your identity operator. Email is descriptive, not an authorization identifier."); const form = node("form");
  const subject = field(form, "Verified Cognito subject"), email = field(form, "Email", "", "email"), name = field(form, "Display name"), role = field(form, "Role", "collector", "text", roles); subject.maxLength = 200; email.maxLength = 254;
  submit(form, "Create seven-day invitation", async () => { await api("/v1/customer/invitations", { subject: subject.value.trim(), email: email.value.trim().toLowerCase(), displayName: name.value.trim(), role: role.value }); await openView("Members"); message("Invitation created. Ask the user to sign in at this customer hostname and accept it. No email was sent."); }); invite.append(form); output.prepend(invite); return output;
}
async function devicesView(epoch) {
  return (await paginated("/v1/customer/devices/search", "Enrolled Macs", "Enrollment happens in the Mac application with proof of possession of its Keychain-protected signing key. This browser can inspect or revoke devices, never invent their identity.", (record) => {
    const item = section(record.displayName, `${record.status} · enrolled ${record.enrolledAt}`); item.append(node("code", record.id), node("small", `Owner ${record.principalId} · last seen ${record.lastSeenAt || "not recorded"}`), node("code", record.publicKeySha256));
    if (record.status !== "REVOKED") item.append(button("Revoke this device", async () => { if (!confirm(`Revoke ${record.displayName}? Further collection from this device will be rejected.`)) return; await api("/v1/customer/devices/revoke", { deviceId: record.id, expectedRevision: record.revision }); await openView("Devices"); message("Device revoked."); }, "danger")); return item;
  }, epoch)).output;
}
async function holdPanel(evidence) {
  const result = await api("/v1/legal-hold-requests/status", { evidenceId: evidence.evidenceId });
  const panel = section("Exact-version legal holds", "Requests use evidence identity. The server resolves bucket, key and immutable version. A different administrator approves; APPLIED confirms the worker completed the S3 and database operation.");
  panel.append(button("Refresh operation status", async () => panel.replaceWith(await holdPanel(evidence))));
  if (result.truncated) panel.append(node("p", "Showing the latest 50 holds and operations. Consult the operator audit trail for older history."));
  for (const hold of result.holds) {
    const item = section(`${hold.kind} · ${hold.status}`, hold.reason); item.append(node("code", hold.id));
    if (hold.status === "ACTIVE") item.append(button("Request release", () => { item.append(holdRequestForm(evidence, hold)); })); panel.append(item);
  }
  for (const operation of result.operations) {
    const item = section(`${operation.kind} · ${operation.status} · ${operation.state}`, operation.reason); item.append(node("code", operation.id), node("small", `Requested by ${operation.requestedBy} · changed ${operation.changedAt}`));
    if (operation.state === "REQUESTED" && operation.requestedBy !== me.userId) item.append(button("Approve exact request", async () => {
      if (!confirm(`Approve ${operation.status.toLowerCase()} ${operation.kind.toLowerCase()} for this evidence? Confirm the rationale above.`)) return;
      await api("/v1/legal-hold-approvals", { operationId: operation.id, requestDigest: operation.requestDigest, approvedAt: new Date().toISOString() });
      panel.replaceWith(await holdPanel(evidence)); message("Request approved. Refresh until APPLIED; approval is not proof that S3 was changed.");
    })); panel.append(item);
  }
  panel.append(holdRequestForm(evidence)); return panel;
}
function holdRequestForm(evidence, existing) {
  const form = node("form"); form.append(node("h3", existing ? "Request hold release" : "Request a new hold"));
  const kind = field(form, "Hold kind", existing?.kind || "LEGAL", "text", ["LEGAL", "AUDIT", "SECURITY_INCIDENT"]); if (existing) kind.disabled = true;
  const reason = field(form, "Reason (20–2,000 characters)", "", "textarea"); reason.minLength = 20;
  const operationId = identifier("lho_"), holdId = existing?.id || identifier("hld_");
  submit(form, existing ? "Submit release request" : "Submit hold request", async () => {
    if (!confirm(existing ? "Request release of this exact hold? Another administrator must approve." : "Request retention of this exact evidence version? Another administrator must approve.")) return;
    const reply = await api("/v1/legal-hold-requests/by-evidence", { evidenceId: evidence.evidenceId, expectedEvidenceRevision: evidence.revision, operationId, holdId, expectedHoldRevision: existing?.revision ?? 0, kind: kind.value, status: existing ? "OFF" : "ON", reason: reason.value.trim(), changedAt: new Date().toISOString() });
    form.replaceWith(node("p", `Request ${reply.operationId} recorded: ${reply.state}. Refresh status to see approval and application.`));
  }); return form;
}
function helpView() {
  const output = section("A complete collection-to-review workflow", "This AWS customer portal is separate from the Sites-hosted console and local Mac browser. It uses only the reviewed tenant API and Cognito configuration for this hostname.");
  const list = node("ol");
  for (const text of ["An operator provisions a tenant and bootstraps its first administrator. No AWS infrastructure is created by this page.", "The administrator invites existing Cognito subjects and assigns the least-privileged role.", "A lead creates a draft assessment with exact systems and catalog controls, then activates it.", "A collector signs in from the Mac app, enrolls that device, selects the assessment, and submits evidence. Scanner and promotion status must complete before review.", "An independent reviewer fetches and verifies the immutable artifact, then records approval or rejection with a rationale.", "Administrators request and independently approve exact-version holds. Check APPLIED, not just request acceptance."]) list.append(node("li", text));
  output.append(list, node("p", "This pilot does not provide email signup, billing, tenant creation, cross-tenant navigation or AWS assessor-package delivery. These are not implied by local/Sites feature availability. Production still requires a real two-tenant deployment test, scanner/witness checks and restore qualification.")); return output;
}

async function start() {
  // Remove authorization material from the address bar before further requests.
  const callback = new URL(location.href); const code = callback.searchParams.get("code"), state = callback.searchParams.get("state"), oauthError = callback.searchParams.has("error");
  if (code || state || oauthError) history.replaceState(null, "", "/auth/callback");
  const configurations = await jsonRequest("/tenant-config.json", { method: "GET" }, 200000);
  configuration = validatePortalConfiguration(configurations[location.hostname], location.origin);
  if (oauthError) { sessionStorage.removeItem(transactionKey); throw new Error("Cognito sign-in was not completed. Start sign-in again."); }
  if (code) {
    const serialized = sessionStorage.getItem(transactionKey); sessionStorage.removeItem(transactionKey);
    const transaction = validateLoginTransaction(JSON.parse(serialized || "null"), configuration, state);
    if (code.length > 4096) throw new Error("Invalid authorization response.");
    const reply = await jsonRequest(configuration.oauthOrigin + "/oauth2/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ grant_type: "authorization_code", client_id: configuration.clientId, code, code_verifier: transaction.verifier, redirect_uri: configuration.webOrigin + "/auth/callback" }) }, 32768);
    if (reply.token_type?.toLowerCase() !== "bearer" || typeof reply.access_token !== "string" || reply.access_token.length > 16384 || !Number.isInteger(reply.expires_in) || reply.expires_in < 1 || reply.expires_in > 3600) throw new Error("Cognito returned an invalid token response.");
    accessToken = reply.access_token; // Never persist tokens; ignore/discard refresh and ID tokens.
    tokenTimer = setTimeout(() => { clearSession(); signInPrompt("Your page session expired. Sign in again."); }, reply.expires_in * 1000);
    history.replaceState(null, "", "/"); await establishSession();
  } else signInPrompt();
}
start().catch((error) => { message(error.message, true); if (configuration) signInPrompt("The workspace did not open. Correct the issue or start sign-in again."); else $("connection-state").textContent = "No verified configuration is available for this hostname. Ask the operator to publish its reviewed tenant outputs; do not enter AWS access keys here."; });
