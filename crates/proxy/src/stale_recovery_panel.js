// SPDX-License-Identifier: Apache-2.0
// SOU-242: stale-restore recovery for the selected Agent
// (sw-console-stale-restore-recovery/1). Everyone with read access sees the
// recovery state; only an Owner can preview evidence and confirm the exact
// phrase. Evidence is read from a local file chosen by the Owner and sent
// only to this Console; it is never stored in the browser. Server text is
// rendered as text, never as HTML.
const staleRecovery = (() => {
  const CONTRACT = "sw-console-stale-restore-recovery/1", TIMEOUT_MS = 15000, MAX_FILE = 160 * 1024;
  const ID = /^[A-Za-z0-9._-]{1,128}$/, DIGEST = /^[0-9a-f]{64}$/;
  let scope = null, epoch = 0, evidence = null, preview = null;
  const int = v => Number.isSafeInteger(v);
  const when = v => int(v) ? new Date(v * 1000).toLocaleString() : "not recorded";
  const statusLine = (text, cls = "note") => { const n = $("recovery-status"); n.textContent = text; n.className = cls; };
  const status = statusLine;
  const base = () => `/admin/v1/tenants/${encodeURIComponent(scope.tenant)}/agents/${encodeURIComponent(scope.agent)}/stale-recovery`;
  function validFence(f) {
    return f && int(f.fence_sequence) && int(f.restored_sequence) && f.restored_sequence < f.fence_sequence
      && typeof f.evidence_revision === "string" && ID.test(f.evidence_revision) && DIGEST.test(f.evidence_policy_sha256)
      && DIGEST.test(f.evidence_bundle_sha256) && typeof f.issuer_key_id === "string" && ID.test(f.issuer_key_id)
      && int(f.credential_generation) && int(f.confirmed_at_unix) && ["fenced", "complete"].includes(f.state)
      && (f.state === "complete") === (f.completion != null)
      && (f.completion == null || (int(f.completion.deployment_sequence) && f.completion.deployment_sequence > f.fence_sequence))
      && (f.unrecoverable_interval == null || (int(f.unrecoverable_interval.from_sequence) && int(f.unrecoverable_interval.to_sequence)));
  }
  function validStatus(d) {
    return d?.contract_version === CONTRACT && d.tenant_id === scope.tenant && d.agent_id === scope.agent
      && ["none", "fenced", "complete"].includes(d.state) && int(d.restored_sequence) && Array.isArray(d.fences)
      && d.fences.length <= 20 && d.fences.every(validFence) && Array.isArray(d.restrictions);
  }
  function validPreview(p) {
    const e = p?.evidence;
    return p?.contract_version === CONTRACT && p.tenant_id === scope.tenant && p.agent_id === scope.agent
      && int(p.restored_sequence) && e && int(e.deployment_sequence) && e.deployment_sequence > p.restored_sequence
      && ID.test(e.revision) && DIGEST.test(e.policy_sha256) && ID.test(e.issuer_key_id) && DIGEST.test(e.bundle_sha256)
      && int(p.latest_restored_sequence) && int(p.next_sequence) && p.next_sequence > e.deployment_sequence && p.next_sequence > p.latest_restored_sequence && DIGEST.test(p.state_binding)
      && typeof p.confirmation === "string" && p.confirmation.length <= 200 && int(p.observation_age_seconds) && Array.isArray(p.restrictions);
  }
  const interval = i => i ? `#${i.from_sequence} to #${i.to_sequence}` : "none";
  function renderFences(d, prefix = "") {
    const root = $("recovery-detail"); root.replaceChildren();
    const f = d.fences[0];
    const status = (text, cls) => statusLine(prefix + text, cls);
    if (d.state === "none") {
      status(`No stale-restore recovery recorded. Latest recorded deployment: #${d.restored_sequence}.`);
    } else if (d.state === "fenced") {
      status(`Recovery fenced at #${f.fence_sequence}, not complete. Deploy an approved revision: it is issued above the fence, and completion needs the Agent's authenticated applied acknowledgement.`, "outcome-other");
    } else {
      status(`Recovery complete: #${f.completion.deployment_sequence} (${f.completion.revision}) above fence #${f.fence_sequence} was applied and acknowledged by the Agent.`, "outcome-ok");
    }
    if (f) {
      const list = make("ul", undefined, "recovery-facts");
      list.append(make("li", `Restored sequence #${f.restored_sequence} · fence #${f.fence_sequence} (${f.evidence_revision}) · issuer ${f.issuer_key_id} · credential generation ${f.credential_generation}`));
      list.append(make("li", `Unrecoverable history interval: ${interval(f.unrecoverable_interval)}`));
      list.append(make("li", `Evidence policy ${f.evidence_policy_sha256}`, "heartbeat-digest"));
      list.append(make("li", `Confirmed by ${f.confirmed_by} at ${when(f.confirmed_at_unix)}`));
      if (f.completion) list.append(make("li", `Applied acknowledgement received ${when(f.completion.applied_at_unix)}`));
      root.append(list);
    }
    const r = make("ul", undefined, "recovery-restrictions");
    d.restrictions.slice(0, 8).forEach(x => r.append(make("li", String(x))));
    root.append(make("p", "Remaining restrictions:", "note"), r);
  }
  // Reads the durable state. Returns true when it was read and shown;
  // `prefix` explains why the read happened (e.g. after a confirmation).
  async function load(prefix = "") {
    if (!scope) return false;
    const generation = epoch, controller = new AbortController(), guard = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const d = await request(base(), { signal: controller.signal, cache: "no-store" });
      if (generation !== epoch) return false;
      if (!validStatus(d)) throw Object.assign(new Error("shape"), { code: "shape" });
      renderFences(d, prefix);
      return true;
    } catch (e) {
      if (generation !== epoch) return false;
      $("recovery-detail").replaceChildren();
      if (prefix) return false;
      if (e.status === 401 || e.status === 403) { status("This session cannot read the recovery state.", "outcome-block"); return; }
      if (e.status === 404) { status("Tenant or Agent not found.", "outcome-block"); return; }
      status(e.code === "shape" ? "A recovery status response had an unexpected shape; it was discarded." : "Recovery state could not be read.", "outcome-other");
      return false;
    } finally { clearTimeout(guard); }
  }
  function resetPreview() {
    preview = null; $("recovery-preview-detail").replaceChildren();
    $("recovery-phrase").value = ""; $("recovery-confirm").disabled = true;
  }
  function renderPreview(p) {
    const root = $("recovery-preview-detail"); root.replaceChildren();
    const e = p.evidence, list = make("ul", undefined, "recovery-facts");
    list.append(make("li", `Restored Console sequence: #${p.restored_sequence} · newest restored record #${p.latest_restored_sequence} (${p.restored_status})`));
    list.append(make("li", `Agent evidence: #${e.deployment_sequence} · ${e.revision} · issuer ${e.issuer_key_id}`));
    list.append(make("li", `Evidence policy ${e.policy_sha256}`, "heartbeat-digest"));
    list.append(make("li", `Agent's authenticated report matches it (received ${p.observation_age_seconds} s before this preview, credential generation ${p.credential_generation})`));
    list.append(make("li", `Unrecoverable history interval: ${interval(p.unrecoverable_interval)}`));
    list.append(make("li", `Next issuance after confirmation: #${p.next_sequence} or higher`));
    root.append(list, make("p", "Type this exact phrase to confirm:", "note"), make("code", p.confirmation, "recovery-phrase"));
    const r = make("ul", undefined, "recovery-restrictions");
    p.restrictions.slice(0, 8).forEach(x => r.append(make("li", String(x))));
    root.append(r);
  }
  async function readEvidence(file) {
    resetPreview(); evidence = null;
    if (!file) return;
    if (file.size > MAX_FILE) { status("Evidence file is larger than a signed policy bundle; it was not read.", "outcome-block"); return; }
    try { evidence = JSON.parse(await file.text()); } catch (_) { evidence = null; status("Evidence file is not JSON.", "outcome-block"); return; }
    $("recovery-preview").disabled = !scope;
  }
  async function runPreview() {
    if (!scope || !evidence) return;
    const generation = epoch; resetPreview();
    try {
      const p = await request(`${base()}/preview`, { method: "POST", body: JSON.stringify({ evidence }) });
      if (generation !== epoch) return;
      if (!validPreview(p)) throw Object.assign(new Error("shape"), { code: "shape" });
      preview = p; renderPreview(p);
      status("Preview only: nothing is recorded until the exact phrase is confirmed.", "outcome-other");
    } catch (e) {
      if (generation !== epoch) return;
      status(e.code === "shape" ? "The preview response had an unexpected shape; it was discarded." : `Recovery stays closed: ${e.message}`, "outcome-block");
    }
  }
  async function runConfirm() {
    if (!scope || !preview || $("recovery-phrase").value !== preview.confirmation) return;
    const generation = epoch, body = JSON.stringify({ evidence, state_binding: preview.state_binding, confirmation: preview.confirmation });
    $("recovery-confirm").disabled = true;
    const controller = new AbortController(), guard = setTimeout(() => controller.abort(), TIMEOUT_MS);
    let prefix, known = true, refused = false;
    try {
      await request(`${base()}/confirm`, { method: "POST", body, signal: controller.signal });
      prefix = "Confirmation recorded. ";
    } catch (e) {
      // A 4xx is the Console's answer for this request. Anything else (no
      // response, a timeout, a 5xx) may have committed: the outcome is
      // unknown. Either way the POST is never repeated automatically; the
      // durable state is read once and shown instead.
      const answered = Number.isInteger(e.status) && e.status >= 400 && e.status < 500;
      known = answered;
      refused = answered;
      prefix = answered ? `Confirmation refused: ${e.message} ` : `Confirmation outcome was unknown (${e.message}). `;
    } finally { clearTimeout(guard); }
    if (generation !== epoch) return;
    // A refusal keeps the chosen evidence so the Owner can preview again;
    // a recorded or unknown outcome clears it.
    resetPreview();
    if (!refused) { evidence = null; $("recovery-evidence").value = ""; $("recovery-preview").disabled = true; }
    statusLine(`${prefix}Reading the recorded recovery state…`, "outcome-other");
    if (!(await load(prefix)) && generation === epoch) {
      $("recovery-detail").replaceChildren();
      statusLine(known
        ? `${prefix}The recorded recovery state could not be read; select Refresh recovery.`
        : `${prefix}The recorded recovery state could not be read, so the outcome is unknown. Select Refresh recovery before doing anything else; do not confirm again until the state is known.`, "outcome-block");
    }
  }
  function select(tenant, agent) {
    epoch++; evidence = null; resetPreview(); $("recovery-detail").replaceChildren(); $("recovery-evidence").value = "";
    scope = tenant && agent && ID.test(tenant) && ID.test(agent) ? { tenant, agent } : null;
    $("recovery-refresh").disabled = !scope; $("recovery-preview").disabled = true; $("recovery-evidence").disabled = !scope;
    if (!scope) { status("Select an Agent in the fleet list to see its stale-restore recovery state."); return; }
    status("Loading recovery state…"); load();
  }
  $("recovery-refresh").addEventListener("click", () => load());
  $("recovery-evidence").addEventListener("change", e => readEvidence(e.target.files?.[0]));
  $("recovery-preview").addEventListener("click", () => runPreview());
  $("recovery-phrase").addEventListener("input", e => { $("recovery-confirm").disabled = !preview || e.target.value !== preview.confirmation; });
  $("recovery-confirm").addEventListener("click", () => runConfirm());
  return { select, clear: () => select(null, null) };
})();
