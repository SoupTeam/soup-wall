// SPDX-License-Identifier: Apache-2.0
// Managed Agent policy rollout over the existing group, revision and rollout
// APIs. It uses the page's in-memory authenticated request helper and never
// stores credentials. Server-side Owner role and tenant checks remain the
// authority: hiding controls for other roles is only a convenience. This panel
// manages signed AgentPolicySet revisions only, never Gateway tenant policies.
const rollout = (() => {
  const ACTIVE = new Set(["pilot", "standard", "paused", "rolling_back"]);
  const PHASE = {
    pilot: "Pilot wave issued; workers wait for every pilot's exact applied acknowledgement.",
    standard: "Worker wave issued; waiting for every worker's exact applied acknowledgement.",
    paused: "Paused by an Owner; nothing is issued until Resume.",
    rolling_back: "Rolling back: higher-sequence baseline deployments issued; waiting for their applied acknowledgements.",
    completed: "Completed: every frozen Agent acknowledged the exact revision.",
    rolled_back: "Rolled back: every affected Agent acknowledged its frozen baseline.",
    failed: "Failed: the plan stopped; see the failure reason."
  };
  const STATE = {
    not_issued: "Not issued (waits for its wave)",
    pending: "Issued, applied acknowledgement pending",
    overdue: "Overdue: acknowledgement deadline passed",
    applied: "Exact applied acknowledgement recorded",
    rejected: "Rejected by the Agent",
    conflict: "Conflict: a newer deployment replaced it",
    revoked: "Enrollment revoked",
    unresolved_baseline: "No restorable baseline"
  };
  let tenant = null, group = null, epoch = 0, controller = null;
  let busy = false, blocked = "", groups = [], members = [], revisions = [], plan = null, preview = null;

  const owner = () => currentAdmin?.role === "owner";
  const groupsUrl = () => `/admin/v1/tenants/${encodeURIComponent(tenant)}/groups`;
  const groupUrl = suffix => `${groupsUrl()}/${encodeURIComponent(group)}${suffix}`;
  const say = (text, kind = "note") => { const n = $("rollout-status"); n.textContent = text; n.className = kind; };
  const when = value => value == null ? "Not recorded" : new Date(value * 1000).toLocaleString();
  const age = value => {
    if (value == null) return "";
    const minutes = Math.max(0, Math.floor((Date.now() / 1000 - value) / 60));
    return ` (${minutes} min old, historical acknowledgement; not current health)`;
  };
  const code = text => make("code", text);
  const cell = (row, value) => { const td = make("td"); value instanceof Node ? td.append(value) : td.append(String(value ?? "none")); row.append(td); };
  const table = (headers, rows) => {
    const t = make("table"), head = make("thead"), hr = make("tr"), body = make("tbody");
    headers.forEach(h => hr.append(make("th", h)));
    head.append(hr); t.append(head);
    rows.forEach(r => body.append(r)); t.append(body);
    const wrap = make("div", undefined, "table-wrap"); wrap.append(t); return wrap;
  };

  // The shared helper rejects with `status` for HTTP errors. A missing
  // response, a timeout or a server error leaves a mutation's outcome unknown.
  const ambiguous = e => e.status === undefined || e.status >= 500;

  async function read(path) {
    return request(path, { signal: controller.signal, cache: "no-store" });
  }

  async function loadGroups() {
    const id = tenant, generation = epoch;
    try {
      const value = await read(groupsUrl());
      if (generation !== epoch || id !== tenant) return;
      if (!Array.isArray(value) || value.some(g => g.tenant_id !== id)) throw new Error("Group response identity mismatch");
      groups = value;
      const select = $("rollout-group");
      select.replaceChildren(make("option", groups.length ? "Choose a group" : "No groups yet", ""));
      select.firstChild.value = "";
      groups.forEach(g => { const o = make("option", `${g.name} (${g.group_id})`); o.value = g.group_id; select.append(o); });
      if (group && groups.some(g => g.group_id === group)) select.value = group;
      else { group = null; clearGroup(); }
      say(groups.length ? "Choose a group to review its revisions and rollout." : "No Agent groups in this tenant.");
      return true;
    } catch (e) {
      if (generation === epoch && id === tenant && e.name !== "AbortError") say("Unable to load Agent groups. Refresh to retry.", "error");
      return false;
    }
  }

  function clearGroup() {
    members = []; revisions = []; plan = null; preview = null;
    ["rollout-members", "rollout-revisions", "rollout-plan", "rollout-actions", "rollout-confirm"].forEach(id => $(id).replaceChildren());
    $("rollout-group-detail").classList.toggle("hidden", !group);
  }

  // Reads members, revisions and the persisted plan as one view. A failure
  // keeps nothing half-rendered.
  async function refresh() {
    if (!tenant || !group) return;
    const id = tenant, g = group, generation = epoch;
    const [m, r, p] = await Promise.all([
      read(groupUrl("/members")),
      read(groupUrl("/revisions")),
      read(groupUrl("/rollout")).catch(e => { if (e.status === 404) return null; throw e; })
    ]);
    if (generation !== epoch || id !== tenant || g !== group) return;
    if (!Array.isArray(m) || m.some(x => x.tenant_id !== id || x.group_id !== g)) throw new Error("Member response identity mismatch");
    if (!Array.isArray(r) || r.some(x => x.tenant_id !== id || x.group_id !== g)) throw new Error("Revision response identity mismatch");
    if (p && (p.tenant_id !== id || p.group_id !== g)) throw new Error("Rollout response identity mismatch");
    members = m; revisions = r; plan = p;
    render();
  }

  async function load() {
    const generation = epoch;
    say("Loading group…");
    try {
      await refresh();
      if (generation === epoch) say(`Server state read ${new Date().toLocaleString()}. Acknowledgements are recorded history, not live runtime attestation.`);
    } catch (e) {
      if (generation === epoch && e.name !== "AbortError") { clearGroup(); say("Unable to load this group. Refresh to retry.", "error"); }
    }
  }

  function previewCohort() {
    return { pilots: members.filter(m => m.is_pilot).map(m => m.agent_id).sort(),
             workers: members.filter(m => !m.is_pilot).map(m => m.agent_id).sort() };
  }

  function renderMembers() {
    const root = $("rollout-members"), cohort = previewCohort();
    root.replaceChildren(make("h3", "Current membership (preview targets)"),
      make("p", "This list is this page's own view and is not authoritative. Start asks the server for its preview of the exact cohort before anything is issued; once started, later membership changes never alter the frozen plan.", "note"));
    if (!members.length) { root.append(make("p", "This group has no members.", "empty")); }
    else {
      root.append(table(["Agent", "Preview wave", ""], members.map(m => {
        const row = make("tr"); cell(row, code(m.agent_id)); cell(row, m.is_pilot ? "Pilot" : "Worker");
        const td = make("td");
        if (owner()) { const b = make("button", "Remove", "secondary tiny owner-action rollout-mutation"); b.type = "button";
          b.addEventListener("click", () => mutate(`Remove ${m.agent_id}`, "DELETE", "/members/" + encodeURIComponent(m.agent_id))); td.append(b); }
        row.append(td); return row;
      })));
    }
    if (plan && ACTIVE.has(plan.phase)) {
      const frozen = { pilots: [...plan.pilot_agents].sort(), workers: [...plan.standard_agents].sort() };
      if (JSON.stringify(frozen) !== JSON.stringify(cohort))
        root.append(make("p", "Current membership differs from the frozen cohort of the active plan. The frozen cohort below is what the server deploys.", "outcome-block"));
    }
  }

  function renderRevisions() {
    const root = $("rollout-revisions");
    root.replaceChildren(make("h3", "Signed policy revisions"),
      make("p", "Each revision is an immutable AgentPolicySet. The digest is SHA-256 of the exact YAML bytes; Agents verify it with the signed bundle.", "note"));
    if (!revisions.length) { root.append(make("p", "No revisions for this group.", "empty")); return; }
    root.append(table(["Revision", "Policy SHA-256", "Approval", ""], revisions.map(r => {
      const row = make("tr"); cell(row, code(r.revision)); cell(row, code(r.policy_sha256)); cell(row, r.approved ? "Approved" : "Awaiting approval");
      const td = make("td");
      if (owner() && !r.approved) { const b = make("button", "Review and approve", "tiny owner-action rollout-mutation"); b.type = "button";
        b.addEventListener("click", () => confirmAction({ title: `Approve revision ${r.revision}`,
          lines: [`Policy SHA-256: ${r.policy_sha256}`, "Approval allows this exact digest to be deployed. It issues nothing by itself."],
          expected: r.revision, run: () => mutate(`Approve ${r.revision}`, "POST", `/revisions/${encodeURIComponent(r.revision)}/approve`, {}) })); td.append(b); }
      row.append(td); return row;
    })));
  }

  function renderPlan() {
    const root = $("rollout-plan");
    root.replaceChildren(make("h3", "Server rollout plan"));
    if (!plan) { root.append(make("p", "No deployment has been started for this group.", "empty")); return; }
    const facts = make("dl", undefined, "rollout-facts");
    const fact = (k, v) => { facts.append(make("dt", k)); const d = make("dd"); v instanceof Node ? d.append(v) : d.append(String(v)); facts.append(d); };
    fact("Phase", `${plan.phase}: ${PHASE[plan.phase] || ""}`);
    fact("Revision", code(plan.revision));
    fact("Policy SHA-256", code(plan.policy_sha256));
    fact("Rollout ID", code(plan.rollout_id));
    fact("Signing key", plan.issuer_key_id || "Console default");
    fact("Frozen pilots", plan.pilot_agents.join(", ") || "None");
    fact("Frozen workers", plan.standard_agents.join(", ") || "None");
    fact("Created / updated", `${when(plan.created_at_unix)} / ${when(plan.updated_at_unix)}`);
    if (plan.phase === "paused" && plan.failure_reason?.startsWith("paused:")) fact("Paused during", `${plan.failure_reason.slice(7)} wave`);
    else if (plan.failure_reason) fact("Failure reason", plan.failure_reason);
    root.append(facts);
    const waves = [...plan.pilot_agents.map(a => [a, "Pilot"]), ...plan.standard_agents.map(a => [a, "Worker"])];
    root.append(table(["Agent", "Frozen wave", "Baseline", "Initial / expected / latest sequence", "Recorded state", "ACK deadline", "Last matching applied acknowledgement"],
      waves.map(([agent, wave]) => {
        const s = plan.agents?.[agent] || {}, ack = s.last_matching_acknowledgement, row = make("tr");
        cell(row, code(agent)); cell(row, wave);
        cell(row, plan.previous_revisions?.[agent] ?? "No restorable baseline");
        cell(row, `${plan.initial_sequences?.[agent] ?? "none"} / ${s.expected_sequence ?? "none"} / ${s.latest_sequence ?? "none"}`);
        cell(row, STATE[s.status] || s.status || "Unknown");
        cell(row, when(s.acknowledgement_deadline_unix));
        cell(row, ack ? `#${ack.deployment_sequence} · ${ack.revision} · ${ack.action} · recorded ${ack.status} · applied ${when(ack.applied_at_unix)}${age(ack.applied_at_unix)}` : "None recorded");
        return row;
      })));
    root.append(make("p", "Issued, delivered and applied are separate recorded states. An applied acknowledgement is historical evidence from that Agent; it is not fresh health or runtime attestation.", "note"));
  }

  function button(text, cls, run) {
    const b = make("button", text, cls + " owner-action rollout-mutation"); b.type = "button"; b.addEventListener("click", run); return b;
  }

  function renderActions() {
    const root = $("rollout-actions");
    root.replaceChildren();
    if (!owner()) { root.append(make("p", "Read-only: only an Owner can approve, deploy, promote, pause, resume or roll back.", "note")); return; }
    const phase = plan?.phase, row = make("div", undefined, "inline");
    if (!plan || !ACTIVE.has(phase)) {
      const approved = revisions.filter(r => r.approved), select = make("select");
      select.id = "rollout-start-revision";
      approved.forEach(r => { const o = make("option", r.revision); o.value = r.revision; select.append(o); });
      const label = make("label", "Approved revision", "field"); label.append(select);
      row.append(label, button("Start pilot deployment", "", () => {
        const revision = select.value;
        if (!approved.find(x => x.revision === revision)) { say("Approve a revision before starting a deployment.", "error"); return; }
        reviewStart(revision);
      }));
      if (!approved.length) row.append(make("p", "No approved revision is available.", "note"));
    }
    if (phase === "pilot" || phase === "standard" || phase === "rolling_back") {
      row.append(button(phase === "pilot" ? "Evaluate pilot gate (promote to workers)" : "Evaluate acknowledgement gate", "", () => confirmAction({
        title: phase === "pilot" ? `Promote ${plan.revision} to workers` : `Evaluate the ${phase} gate`,
        lines: [`Rollout ${plan.rollout_id}, policy SHA-256 ${plan.policy_sha256}`,
                phase === "pilot" ? `Workers that receive it if every pilot acknowledged: ${plan.standard_agents.join(", ") || "none"}` : "Processes recorded acknowledgements and expired deadlines.",
                "A missing, stale or rejected acknowledgement keeps the gate closed or rolls back; nothing is bypassed."],
        expected: plan.revision, run: () => mutate("Promote / evaluate", "POST", "/rollout/advance", {}, { expect: plan }) })));
    }
    if (phase === "pilot" || phase === "standard") row.append(button("Pause", "secondary", () => mutate("Pause", "POST", "/rollout/pause", {}, { expect: plan })));
    if (phase === "paused") row.append(button("Resume", "secondary", () => mutate("Resume", "POST", "/rollout/resume", {}, { expect: plan })));
    if (plan && (ACTIVE.has(phase) && phase !== "rolling_back" || phase === "completed")) {
      row.append(button("Roll back", "danger", () => confirmAction({ title: `Roll back ${plan.revision}`,
        lines: [`Rollout ${plan.rollout_id}`, ...Object.entries(plan.previous_revisions || {}).map(([a, r]) => `${a}: restore ${r ?? "nothing (no restorable baseline)"}`),
                "Rollback issues new, higher-sequence signed deployments of each frozen baseline. It never edits history."],
        expected: `rollback ${plan.revision}`, run: () => mutate(`Roll back ${plan.revision}`, "POST", "/rollout/rollback", {}, { expect: plan }) })));
    }
    root.append(row);
    if (blocked === "reconcile") {
      const b = make("button", "Reconcile with server state", "secondary rollout-reconcile"); b.type = "button";
      b.addEventListener("click", reconcile); root.append(b);
    }
    lock();
  }

  // The server, not this page, states what a start would freeze and issue. The preview issues nothing
  // and is not authority: the server rechecks every fact when the typed confirmation is sent.
  const REFUSAL = {
    confirmation_stale: "The cohort, an Agent's authorization, the revision, a baseline or a sequence changed after the preview.",
    confirmation_expired: "The confirmation expired.",
    confirmation_invalid: "The confirmation is no longer valid for this request."
  };
  let refusal = null;

  async function reviewStart(revision, notice) {
    if (busy || blocked || !owner() || !tenant || !group) return;
    const id = tenant, g = group, generation = epoch;
    busy = true; lock(); $("rollout-confirm").replaceChildren(); say("Asking the server for its authoritative preview…");
    try {
      const p = await request(groupUrl("/rollout/preview"), { method: "POST", body: JSON.stringify({ revision }), signal: controller.signal });
      if (generation !== epoch || id !== tenant || g !== group) return;
      if (!p || p.contract_version !== "sw-group-rollout-preview/1" || p.tenant_id !== id || p.group_id !== g || p.revision !== revision || p.executed !== false)
        throw new Error("Preview response identity mismatch");
      preview = { pilots: [...p.pilots], workers: [...p.workers] };
      busy = false;
      showPreview(p, revision, notice);
    } catch (e) {
      if (generation !== epoch || e.name === "AbortError") return;
      if (e.status === 401) { blocked = "session"; say("The admin session is no longer authorized. Reconnect before any further change.", "error"); }
      else if (e.status === 403) { blocked = "role"; say("This admin role does not permit rollout changes. The panel is read-only.", "error"); }
      else say(`The server preview is unavailable (${e.message}). Nothing was issued; no deployment can be started without it.`, "error");
    } finally {
      if (generation === epoch) { busy = false; renderActions(); }
    }
  }

  function showPreview(p, revision, notice) {
    const root = $("rollout-confirm"), box = make("div", undefined, "outcome-block");
    const list = values => values.join(", ") || "none";
    box.append(make("strong", `Server preview: start pilot deployment of ${revision}`));
    if (notice) box.append(make("p", notice, "outcome-block"));
    box.append(make("p", `Policy SHA-256: ${p.policy_sha256 ?? "unknown"}`, "note"),
               make("p", `Server preview pilots: ${list(p.pilots)}`, "note"),
               make("p", `Server preview workers: ${list(p.workers)}`, "note"));
    p.agents.forEach(a => box.append(make("p",
      `${a.agent_id} (${a.wave}): baseline ${a.baseline_revision ?? "none"}, latest sequence ${a.latest_sequence}${a.latest_status ? ` (${a.latest_status})` : ""}${a.authorized ? "" : ", NOT AUTHORIZED"}`, "note")));
    box.append(make("p", `Snapshot SHA-256: ${p.snapshot_sha256}`, "note"));
    if (!p.startable) {
      p.blockers.forEach(b => box.append(make("p", `Blocked: ${b.code}${b.agent_id ? ` (${b.agent_id})` : ""} - ${b.detail}`, "outcome-block")));
      box.append(make("p", "The server will not accept a start for this scope. Nothing was issued. Resolve the blockers, then review again.", "note"));
      root.replaceChildren(box);
      say("The server preview is blocked. Nothing was issued.", "error");
      return;
    }
    root.replaceChildren(box);
    say("Review the server preview, then confirm. Nothing has been issued.");
    confirmAction({ title: `Start pilot deployment of ${revision}`,
      lines: [`Confirmation expires ${when(p.confirmation.expires_at_unix)}. The server rechecks the cohort, authorization, revision, baselines and sequences when you confirm and refuses with zero deployments if anything differs.`,
              "Only pilots receive the policy now. The server issues the worker wave only after every pilot's exact applied acknowledgement is recorded (when it arrives, or when an Owner evaluates the gate). Pause first to hold workers."],
      expected: revision, keep: box,
      run: async () => {
        refusal = null;
        await mutate(`Start ${revision}`, "POST", "/rollout", { revision, confirmation_id: p.confirmation.id }, { started: preview });
        if (refusal) { const code = refusal; refusal = null; reviewStart(revision, `${REFUSAL[code] || "The server refused the confirmation."} Nothing was issued. This is the server's new preview.`); }
      } });
  }

  function lock() {
    document.querySelectorAll("#rollout-panel .rollout-mutation").forEach(b => { b.disabled = busy || !!blocked || !owner(); });
    document.querySelectorAll("#rollout-panel .rollout-reconcile").forEach(b => { b.disabled = busy; });
  }

  function render() { renderMembers(); renderRevisions(); renderPlan(); renderActions(); }

  // Destructive or wave-issuing actions need the exact identity typed back.
  function confirmAction({ title, lines, expected, run, keep }) {
    if (busy || blocked) return;
    const root = $("rollout-confirm"), input = make("input"), ok = make("button", "Confirm", "danger owner-action"), cancel = make("button", "Cancel", "secondary");
    input.id = "rollout-confirm-input"; input.autocomplete = "off"; input.setAttribute("aria-label", `Type ${expected} to confirm`);
    ok.type = cancel.type = "button"; ok.disabled = true;
    input.addEventListener("input", () => { ok.disabled = input.value !== expected || busy || !!blocked; });
    cancel.addEventListener("click", () => root.replaceChildren());
    ok.addEventListener("click", () => { if (input.value !== expected) return; root.replaceChildren(); run(); });
    const box = make("div", undefined, "outcome-block");
    box.append(make("strong", title));
    lines.forEach(l => box.append(make("p", l, "note")));
    const label = make("label", "Type ", "field"); label.append(code(expected), make("span", " to confirm"), input);
    const actions = make("div", undefined, "inline"); actions.append(ok, cancel);
    box.append(label, actions);
    root.replaceChildren(...(keep ? [keep, box] : [box]));
    input.focus();
  }

  // One mutation at a time. An uncertain result is reconciled from persisted
  // server state before anything else may be submitted; nothing is retried.
  async function mutate(label, method, suffix, body, options = {}) {
    if (busy || blocked || !owner() || !tenant || !group) return;
    const id = tenant, g = group, generation = epoch;
    busy = true; lock(); say(`${label}: sending…`);
    try {
      if (options.expect) {
        const fresh = await read(groupUrl("/rollout")).catch(e => { if (e.status === 404) return null; throw e; });
        if (generation !== epoch) return;
        if (!fresh || fresh.rollout_id !== options.expect.rollout_id || fresh.phase !== options.expect.phase) {
          await refresh();
          say("The rollout changed since it was displayed (another operator, an acknowledgement or a deadline). Nothing was sent. Review the current plan.", "error");
          return;
        }
      }
      const result = await request(groupUrl(suffix), { method, body: body === undefined ? undefined : JSON.stringify(body) });
      if (generation !== epoch || id !== tenant || g !== group) return;
      await refresh();
      let note = `${label}: accepted by the server.`;
      if (options.digest && body?.revision) {
        const created = revisions.find(r => r.revision === body.revision);
        if (created && created.policy_sha256 !== options.digest) {
          say(`Revision ${body.revision} has server digest ${created.policy_sha256}, not the digest of the YAML in this form (${options.digest}). Do not approve it.`, "error");
          return false;
        }
        note = `Revision ${body.revision} created. Server digest ${created?.policy_sha256} matches the reviewed bytes. It still needs approval.`;
      }
      if (options.started && result?.rollout_id) {
        const frozen = { pilots: [...result.pilot_agents].sort(), workers: [...result.standard_agents].sort() };
        if (result.confirmation?.replayed) note += " The confirmation had already started this rollout; nothing new was issued.";
        note += JSON.stringify(frozen) === JSON.stringify({ pilots: [...options.started.pilots].sort(), workers: [...options.started.workers].sort() })
          ? " The frozen cohort is exactly the server preview you confirmed."
          : " The frozen cohort differs from the confirmed preview; the frozen cohort shown below is authoritative. Report this.";
        if (result.phase !== "pilot" && result.phase !== "completed") note += ` Current phase: ${result.phase}.`;
      }
      say(note, "ok");
      return true;
    } catch (e) {
      if (generation !== epoch || e.name === "AbortError") return false;
      if (e.status === 401) { blocked = "session"; say("The admin session is no longer authorized. Reconnect before any further change.", "error"); }
      else if (e.status === 403) { blocked = "role"; say("This admin role does not permit rollout changes. The panel is read-only.", "error"); }
      else if (e.status === 409 && typeof e.code === "string" && e.code.startsWith("confirmation_")) {
        refusal = e.code;
        say(`${label} refused: ${REFUSAL[e.code] || e.message} Nothing was issued.`, "error");
        try { await refresh(); } catch (_) { /* the new preview below reads the server again */ }
      }
      else if (ambiguous(e)) { blocked = "reconcile"; say(`${label}: the outcome is unknown (${e.message}). Reading persisted server state before allowing another change; nothing is retried.`, "error"); await reconcile(); }
      else {
        say(`${label} refused: ${e.message}.`, "error");
        try { await refresh(); } catch (_) { say(`${label} refused: ${e.message}. The current state could not be reloaded; refresh to retry.`, "error"); }
      }
      return false;
    } finally {
      if (generation === epoch) { busy = false; renderActions(); }
    }
  }

  async function reconcile() {
    const generation = epoch;
    busy = true; lock();
    try {
      await refresh();
      if (generation !== epoch) return;
      blocked = "";
      say("Reconciled: the plan below is the persisted server state after an uncertain request. Check it before acting again; nothing was retried automatically.", "error");
    } catch (e) {
      if (generation !== epoch || e.name === "AbortError") return;
      blocked = "reconcile";
      say("The server state could not be read. Changes stay disabled until reconciliation succeeds.", "error");
    } finally {
      if (generation === epoch) { busy = false; renderActions(); }
    }
  }

  $("rollout-group").addEventListener("change", () => {
    controller?.abort(); controller = new AbortController(); epoch++; busy = false;
    if (blocked !== "session" && blocked !== "role" && blocked !== "group-reconcile") blocked = "";
    group = $("rollout-group").value || null; clearGroup(); if (group) load();
  });
  $("rollout-refresh").addEventListener("click", async () => {
    if (busy) return;
    if (blocked === "group-reconcile") {
      const generation = epoch;
      busy = true; lock();
      const loaded = await loadGroups();
      if (generation === epoch) {
        busy = false;
        if (loaded) { blocked = ""; say("Reconciled group list: check whether the group was created before acting again. Nothing was retried automatically.", "note"); }
        else say("The group outcome is still unknown. Changes stay disabled; refresh to reconcile the group list.", "error");
        lock();
      }
      return;
    }
    if (blocked === "reconcile") { await reconcile(); return; }
    if (group) load(); else loadGroups();
  });
  $("rollout-create-group").addEventListener("submit", e => {
    e.preventDefault();
    const group_id = $("rollout-new-group-id").value.trim(), name = $("rollout-new-group-name").value.trim();
    groupMutation("Create group", groupsUrl(), { group_id, name }, () => { $("rollout-new-group-id").value = ""; $("rollout-new-group-name").value = ""; group = group_id; });
  });
  $("rollout-add-member").addEventListener("submit", e => {
    e.preventDefault();
    const agent_id = $("rollout-member-id").value.trim(), is_pilot = $("rollout-member-pilot").checked;
    mutate(`Add ${agent_id} as ${is_pilot ? "pilot" : "worker"}`, "POST", "/members", { agent_id, is_pilot })
      .then(done => { if (done) { $("rollout-member-id").value = ""; $("rollout-member-pilot").checked = false; } });
  });
  $("rollout-create-revision").addEventListener("submit", e => {
    e.preventDefault();
    if (busy || blocked || !owner() || !tenant || !group) return;
    const id = tenant, g = group, generation = epoch;
    const revision = $("rollout-revision-id").value.trim(), policy_yaml = $("rollout-revision-yaml").value;
    busy = true; lock();
    digest(policy_yaml).then(async local => {
      if (generation !== epoch || id !== tenant || g !== group) return;
      if (!local) throw new Error("Policy digest unavailable");
      busy = false;
      const done = await mutate(`Create revision ${revision}`, "POST", "/revisions", { revision, policy_yaml }, { digest: local });
      if (done && generation === epoch && id === tenant && g === group &&
          $("rollout-revision-id").value.trim() === revision && $("rollout-revision-yaml").value === policy_yaml) {
        $("rollout-revision-id").value = ""; $("rollout-revision-yaml").value = ""; $("rollout-revision-digest").textContent = "";
      }
    }).catch(() => {
      if (generation === epoch) say("Unable to verify the policy digest. Nothing was sent; review the form and retry.", "error");
    }).finally(() => { if (generation === epoch) { busy = false; lock(); } });
  });
  $("rollout-revision-yaml").addEventListener("input", async () => {
    const value = $("rollout-revision-yaml").value, d = value ? await digest(value) : null;
    if ($("rollout-revision-yaml").value === value) $("rollout-revision-digest").textContent = d ? `SHA-256 of these exact bytes: ${d}` : "";
  });

  async function digest(text) {
    if (!crypto?.subtle) return null;
    const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
    return [...bytes].map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async function groupMutation(label, url, body, done) {
    if (busy || blocked || !owner() || !tenant) return;
    const generation = epoch;
    busy = true; lock(); say(`${label}: sending…`);
    try {
      await request(url, { method: "POST", body: JSON.stringify(body) });
      if (generation !== epoch) return;
      done(); await loadGroups(); if (group) { $("rollout-group").value = group; clearGroup(); await load(); }
      say(`${label}: accepted by the server.`, "ok");
    } catch (e) {
      if (generation !== epoch) return;
      if (e.status === 401 || e.status === 403) { blocked = e.status === 401 ? "session" : "role"; say("This session or role cannot make this change. The panel is read-only.", "error"); }
      else if (ambiguous(e)) {
        blocked = "group-reconcile";
        const loaded = await loadGroups();
        if (generation !== epoch) return;
        if (loaded) { blocked = ""; say(`${label}: the outcome was uncertain. Check the reloaded group list before acting again; nothing was retried.`, "error"); }
        else say("The group outcome is still unknown. Changes stay disabled; refresh to reconcile the group list.", "error");
      }
      else say(`${label} refused: ${e.message}.`, "error");
    } finally { if (generation === epoch) { busy = false; lock(); } }
  }

  // Deep link from the triage overview: selects an existing group of this
  // tenant exactly as the group menu does. Returns false when it is absent.
  async function open(id, groupId) {
    if (!id || id !== tenant) return false;
    if (!groups.some(g => g.group_id === groupId)) { await loadGroups(); if (id !== tenant) return false; }
    if (!groups.some(g => g.group_id === groupId)) return false;
    $("rollout-group").value = groupId;
    $("rollout-group").dispatchEvent(new Event("change"));
    $("rollout-panel").scrollIntoView({ block: "start" });
    return true;
  }
  return { open, select(id) {
    controller?.abort(); controller = new AbortController(); epoch++;
    tenant = id; group = null; busy = false; blocked = ""; groups = [];
    $("rollout-group").replaceChildren(); clearGroup();
    $("rollout-panel").classList.toggle("rollout-read-only", !owner());
    if (id) loadGroups(); else say("Select a tenant to manage Agent policy rollouts.");
  }};
})();
