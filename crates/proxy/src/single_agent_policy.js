// SPDX-License-Identifier: Apache-2.0
// Credentials stay in the dashboard request helper. Issuance retries always
// present the original key to the persisted signed-policy engine.
const singlePolicy = (() => {
  let tenant = null, agent = null, epoch = 0, controller = null;
  let agents = [], revisions = [], deployments = [], document = null, locked = true, loading = false;
  let after = "", next = "";
  const intents = new Map(); // bounded, in-memory; never local/session storage
  const enc = encodeURIComponent;
  const owner = () => currentAdmin?.role === "owner";
  const scope = () => JSON.stringify([tenant, agent]);
  const agentUrl = (kind, query = "") => `/admin/v1/tenants/${enc(tenant)}/agents/policy-${kind}?agent_id=${enc(agent)}${query}`;
  const revisionUrl = (revision, action = "") => agentUrl(`revision${action}`, `&revision=${enc(revision)}`);
  const say = text => { $("single-policy-status").textContent = text; };
  const same = stamp => stamp === epoch && tenant && agent;
  const identity = row => row?.tenant_id === tenant && row?.agent_id === agent;
  const sha = async text => Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))), b => b.toString(16).padStart(2, "0")).join("");
  const read = path => request(path, {signal: controller.signal, cache: "no-store"});

  function controls() {
    const intent = intents.get(scope());
    const revoked = agents.find(a => a.agent_id === agent)?.revoked_at_unix != null;
    const latest = deployments.reduce((a, b) => !a || b.deployment_sequence > a.deployment_sequence ? b : a, null);
    const disabled = !owner() || !agent || revoked || locked || loading || intent?.busy;
    $("single-create").disabled = disabled;
    $("single-approve").disabled = disabled || !document || document.approved;
    $("single-deploy").disabled = disabled || !document?.approved || intent?.unresolved;
    $("single-rollback").disabled = disabled || !document?.approved || intent?.unresolved || !latest || latest.revision === document.revision;
    $("single-retry").disabled = !owner() || !intent || intent.busy || revoked || loading;
    $("single-next").disabled = loading || !next;
    $("single-intent").textContent = intent ? `${intent.unresolved ? "Unresolved" : "Recorded"} ${intent.rollback ? "rollback" : "deployment"} intent: ${intent.revision}; key ${intent.key}${intent.result ? `; sequence ${intent.result.deployment_sequence}; signer ${intent.result.idempotency.issuer_key_id}; expires at ${intent.result.idempotency.expires_at_unix}; envelope SHA-256 ${intent.result.idempotency.envelope_sha256}` : ""}. Retry reconciles this exact intent; it never allocates another key.` : "No confirmed deployment intent in this tab.";
  }
  function render() {
    const chosen = $("single-revision").value;
    $("single-revision").replaceChildren(make("option", "Select an immutable revision"));
    revisions.forEach(r => { const o = make("option", `${r.revision} · ${r.approved ? "approved" : "unapproved"}`); o.value = r.revision; $("single-revision").append(o); });
    $("single-revision").value = revisions.some(r => r.revision === chosen) ? chosen : "";
    $("single-document").textContent = document ? `Revision: ${document.revision}\nServer SHA-256: ${document.policy_sha256}\nApproved: ${document.approved}\n\n${document.policy_yaml}` : "Select a revision to review its exact server YAML and digest.";
    // SOU-241: a rejected candidate is shown apart from the active policy,
    // with fixed text for its reason and a safe next step.
    const rejected = d => { if (d.status !== "rejected") return ""; const w = agentRejection.describe(d.rejection_code);
      return `\nRejected candidate (never active; the Agent kept its previous policy): ${w.label}\nReceived by Console ${d.rejected_at_unix ?? "not recorded"} · next step: ${w.next}`; };
    $("single-deployments").textContent = deployments.length ? deployments.map(d => `Sequence ${d.deployment_sequence} · ${d.action} · ${d.status}\nRevision ${d.revision} · SHA-256 ${d.policy_sha256}\nIssued ${d.issued_at_unix} · applied acknowledgement ${d.applied_at_unix ?? "not recorded"}${rejected(d)}`).join("\n\n") : "No recorded issuance.";
    controls();
  }
  function fail(error, stamp) {
    if (stamp !== epoch) return;
    locked = true; document = null;
    say(error.status === 401 || error.status === 403 ? "Authorization changed. Reconnect or refresh; mutations are blocked." : "Unresolved: evidence unavailable or inconsistent. Refresh before any new mutation.");
    render();
  }
  async function load() {
    if (!tenant || !agent) return;
    const stamp = ++epoch;
    controller?.abort(); controller = new AbortController(); loading = true; locked = true; document = null; controls();
    try {
      const [inventory, revs, deps] = await Promise.all([
        read(`/admin/v1/tenants/${enc(tenant)}/agents`),
        read(agentUrl("revisions", `&limit=50&after=${enc(after)}`)), read(agentUrl("deployments"))
      ]);
      if (!same(stamp)) return;
      if (!Array.isArray(inventory) || inventory.some(a => a.tenant_id !== tenant)) throw new Error("Agent identity mismatch");
      if (!inventory.some(a => a.agent_id === agent)) {
        const selected = await read(`/admin/v1/tenants/${enc(tenant)}/agents/enrollment?agent_id=${enc(agent)}`);
        if (!same(stamp)) return;
        if (!identity(selected)) throw new Error("Agent identity mismatch");
        inventory.push(selected);
      }
      if (!Array.isArray(revs) || revs.length > 50 || revs.some(r => !identity(r) || typeof r.approved !== "boolean" || !/^[a-f0-9]{64}$/.test(r.policy_sha256))) throw new Error("Revision identity mismatch");
      if (!Array.isArray(deps) || deps.some(d => !identity(d) || typeof d.revision !== "string" || !/^[a-f0-9]{64}$/.test(d.policy_sha256) || !["activate", "rollback"].includes(d.action) || (d.status === "applied" && !Number.isSafeInteger(d.applied_at_unix)) || !Number.isSafeInteger(d.deployment_sequence) || d.deployment_sequence < 1 || !["issued", "delivered", "applied", "rejected"].includes(d.status)
        || (d.rejected_at_unix != null && (d.status !== "rejected" || !Number.isSafeInteger(d.rejected_at_unix))) || (d.rejection_code != null && (d.status !== "rejected" || typeof d.rejection_code !== "string" || !/^[a-z_]{1,48}$/.test(d.rejection_code)))) || new Set(deps.map(d => d.deployment_sequence)).size !== deps.length) throw new Error("Deployment identity mismatch");
      agents = inventory; revisions = revs; deployments = deps;
      next = revs.length === 50 ? revs[49].revision : ""; locked = false;
      const revoked = inventory.find(a => a.agent_id === agent).revoked_at_unix;
      say(revoked != null ? `Agent revoked at ${revoked}. No further mutations are permitted.` : "Recorded acknowledgements are historical evidence. Current runtime protection is unresolved here; use fleet freshness and the Agent's local status.");
      render();
    } catch (e) { fail(e, stamp); }
    finally { if (same(stamp)) { loading = false; controls(); } }
  }
  async function review() {
    const revision = $("single-revision").value, stamp = ++epoch;
    controller?.abort(); controller = new AbortController(); loading = false; document = null; locked = true; render();
    if (!revision) return;
    try {
      const row = await read(revisionUrl(revision));
      const digest = typeof row?.policy_yaml === "string" ? await sha(row.policy_yaml) : null;
      if (!same(stamp)) return;
      if (!identity(row) || row.revision !== revision || row.policy_sha256 !== digest || typeof row.approved !== "boolean") throw new Error("Unverified revision");
      document = row; locked = false; render();
    } catch (e) { fail(e, stamp); }
  }
  async function checkOwner() {
    const value = await request("/admin/v1/whoami", {cache: "no-store"});
    currentAdmin = value; applyRole();
    if (!owner()) { const e = new Error("Owner required"); e.status = 403; throw e; }
  }
  async function issue(intent) {
    if (intent.busy) return;
    const stamp = epoch; intent.busy = true; controls();
    try {
      await checkOwner();
      // Captured URL/body/key survive selection changes. Do not abort POSTs.
      const value = await request(intent.url, {method: "POST", headers: {"Idempotency-Key": intent.key}, body: JSON.stringify({rollback: intent.rollback, issuer_key_id: intent.issuer, expected_sequence: intent.expected})});
      if (value?.tenant_id !== intent.tenant || value?.agent_id !== intent.agent || value?.revision !== intent.revision || value?.policy_sha256 !== intent.digest || value?.action !== (intent.rollback ? "rollback" : "activate") || value?.idempotency?.key !== intent.key || !/^[a-f0-9]{64}$/.test(value?.idempotency?.envelope_sha256) || typeof value?.idempotency?.issuer_key_id !== "string" || !value.idempotency.issuer_key_id || !Number.isSafeInteger(value.idempotency.expires_at_unix) || !Number.isSafeInteger(value.deployment_sequence)) throw new Error("Issuance evidence mismatch");
      if (intent.result && (intent.result.deployment_sequence !== value.deployment_sequence || intent.result.idempotency.envelope_sha256 !== value.idempotency.envelope_sha256)) throw new Error("Retry changed issuance");
      intent.result = value; intent.unresolved = false;
      if (same(stamp)) { await load(); say("Issuance recorded. Refresh to observe delivery and the exact applied acknowledgement."); }
    } catch (e) {
      intent.unresolved = e.status !== 409;
      if (same(stamp)) { locked = true; say(e.status === 409 ? "Overlap conflict: inventory changed or a group rollout owns this Agent. Refresh, review and explicitly confirm a new intent." : e.status === 401 || e.status === 403 ? "Authorization refused; no further mutations until authorization is restored." : "Deployment outcome unresolved. Retry this exact intent to reconcile persisted server state; do not create another deployment."); }
    } finally { intent.busy = false; if (tenant === intent.tenant && agent === intent.agent) controls(); }
  }
  async function confirmIssue(rollback) {
    if (!document?.approved || locked || loading || !owner()) return;
    const existing = intents.get(scope()); if (existing?.busy || existing?.unresolved) return;
    const issuer = $("single-issuer").value.trim() || null;
    if (!confirm(`Confirm ${rollback ? "rollback" : "deployment"} for Agent ${agent}?\nRevision ${document.revision}\nSHA-256 ${document.policy_sha256}\nSigner ${issuer ?? "configured default"}\nA new higher-sequence signed deployment will be issued.`)) return;
    if (!intents.has(scope()) && intents.size >= 16) {
      const removable = [...intents].find(([, i]) => !i.unresolved && !i.busy);
      if (!removable) { say("Resolve existing intents before opening another Agent deployment."); return; }
      intents.delete(removable[0]);
    }
    const intent = {tenant, agent, revision: document.revision, digest: document.policy_sha256, issuer, rollback,
      expected: Math.max(0, ...deployments.map(d => d.deployment_sequence)), key: crypto.randomUUID(), url: revisionUrl(document.revision, "/deploy"), unresolved: true, busy: false};
    intents.set(scope(), intent); await issue(intent);
  }
  async function mutate(path, body) {
    if (locked || loading || !owner()) return;
    const stamp = epoch; loading = true; controls();
    try { await checkOwner(); if (!same(stamp)) return; await request(path, {method: "POST", body: JSON.stringify(body)}); if (same(stamp)) await load(); }
    catch (e) { fail(e, stamp); }
    finally { if (same(stamp)) { loading = false; controls(); } }
  }
  async function select(id, openAgent = null) {
    epoch++; controller?.abort(); controller = new AbortController(); tenant = id; agent = null;
    agents = []; revisions = []; deployments = []; document = null; locked = true; loading = false; after = ""; next = "";
    ["single-new-revision", "single-yaml", "single-issuer"].forEach(id => { $(id).value = ""; });
    $("single-agent").replaceChildren(make("option", "Select an Agent")); render();
    if (!id) return;
    const stamp = epoch;
    try {
      const values = await read(`/admin/v1/tenants/${enc(id)}/agents`);
      if (stamp !== epoch || tenant !== id) return;
      if (!Array.isArray(values) || values.some(a => a.tenant_id !== id)) throw new Error("Agent identity mismatch");
      if (openAgent && !values.some(a => a.agent_id === openAgent)) {
        const selected = await read(`/admin/v1/tenants/${enc(id)}/agents/enrollment?agent_id=${enc(openAgent)}`);
        if (stamp !== epoch || tenant !== id) return;
        if (selected?.tenant_id !== id || selected?.agent_id !== openAgent) throw new Error("Agent identity mismatch");
        values.push(selected);
      }
      agents = values;
      values.forEach(a => { const o = make("option", `${a.agent_id}${a.revoked_at_unix != null ? " (revoked)" : ""}`); o.value = a.agent_id; $("single-agent").append(o); });
      if (openAgent && agents.some(a => a.agent_id === openAgent)) {
        $("single-agent").value = openAgent;
        $("single-agent").dispatchEvent(new Event("change"));
        $("single-agent").scrollIntoView({block: "center"});
      } else say("Select one Agent to inspect its signed policy history.");
    } catch (e) { fail(e, stamp); }
  }
  $("single-agent").addEventListener("change", () => { agent = $("single-agent").value || null; ["single-new-revision", "single-yaml", "single-issuer"].forEach(id => { $(id).value = ""; }); after = ""; next = ""; revisions = []; deployments = []; document = null; epoch++; locked = true; render(); if (agent) load(); });
  $("single-revision").addEventListener("change", review);
  $("single-refresh").addEventListener("click", () => agent ? load() : select(tenant));
  $("single-next").addEventListener("click", () => { after = next; load(); });
  $("single-first").addEventListener("click", () => { after = ""; load(); });
  $("single-create-form").addEventListener("submit", e => { e.preventDefault(); mutate(agentUrl("revisions"), {revision: $("single-new-revision").value, policy_yaml: $("single-yaml").value}); });
  $("single-approve").addEventListener("click", () => { if (document && confirm(`Approve exact revision ${document.revision}\nSHA-256 ${document.policy_sha256}?`)) mutate(revisionUrl(document.revision, "/approve"), {}); });
  $("single-deploy").addEventListener("click", () => confirmIssue(false));
  $("single-rollback").addEventListener("click", () => confirmIssue(true));
  $("single-retry").addEventListener("click", () => { const intent = intents.get(scope()); if (intent && owner()) issue(intent); });
  return {select, open(id, agentId) { if (id === tenant) return select(id, agentId); }};
})();
