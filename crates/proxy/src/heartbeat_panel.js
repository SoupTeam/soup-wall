// SPDX-License-Identifier: Apache-2.0
// Opt-in Agent heartbeat status for the selected Agent. Read-only: one GET of
// .../agent-fleet/:agent/heartbeat (sw-agent-heartbeat-status/1) through the
// in-memory authenticated request helper, re-read every 30 s while shown.
// A self-report is never presented as proven enforcement or health.
const agentHeartbeat = (() => {
  const CONTRACT = "sw-agent-heartbeat-status/1", REFRESH_MS = 30000, TIMEOUT_MS = 15000;
  const ID = /^[A-Za-z0-9._-]{1,128}$/, DIGEST = /^[0-9a-f]{64}$/;
  const STATES = ["fresh", "stale", "registered_no_report", "credential_changed", "revoked", "unsupported", "unavailable"];
  let scope = null, epoch = 0, controller = null, timer = null;
  const int = v => Number.isSafeInteger(v);
  const span = s => s < 120 ? `${s} s` : s < 7200 ? `${Math.floor(s / 60)} min` : `${Math.floor(s / 3600)} h`;
  const status = (text, cls = "note") => { const n = $("heartbeat-status"); n.textContent = text; n.className = cls; };
  function valid(d, tenant, agent) {
    const r = d?.reported, p = r?.observed_policy;
    return d?.contract_version === CONTRACT && d.tenant_id === tenant && d.agent_id === agent && STATES.includes(d.status)
      && int(d.observed_at_unix) && int(d.expires_after_seconds) && int(d.current_credential_generation)
      && (d.age_seconds == null || (int(d.age_seconds) && d.age_seconds >= 0))
      && (r == null || (int(r.credential_generation) && int(r.registered_at_unix) && int(r.sequence)
        && (r.last_received_at_unix == null || int(r.last_received_at_unix))
        && (p == null || (int(p.deployment_sequence) && typeof p.revision === "string" && ID.test(p.revision) && DIGEST.test(p.policy_sha256)))));
  }
  function message(d) {
    const age = d.age_seconds == null ? "" : span(d.age_seconds);
    switch (d.status) {
      case "fresh": return [`Authenticated self-report received ${age} before this read (counts as fresh for ${d.expires_after_seconds} s after the Console received it).`, "heartbeat-fresh"];
      case "stale": return [`Stale: the last authenticated self-report was received ${age} before this read, more than ${d.expires_after_seconds} s ago.`, "outcome-other"];
      case "registered_no_report": return ["Registered, but no self-report received yet.", "outcome-other"];
      case "credential_changed": return ["The credential changed after the last self-report; it no longer counts until the Agent registers again with the new credential.", "outcome-other"];
      case "revoked": return ["Credential revoked: self-reports are refused.", "outcome-block"];
      case "unsupported": return ["Not opted in: this Agent sends no heartbeat. Liveness and protection are unknown.", "note"];
      default: return ["Heartbeat status is unavailable on this Console (its observation store is not migrated).", "outcome-other"];
    }
  }
  function render(d) {
    const root = $("heartbeat-detail"); root.replaceChildren();
    const [text, cls] = message(d); status(text, cls);
    const r = d.reported;
    if (r && d.status !== "unavailable") {
      const p = r.observed_policy;
      const list = make("ul", undefined, "heartbeat-facts");
      list.append(make("li", `Self-reported loaded policy: ${p ? `#${p.deployment_sequence} · ${p.revision}` : "none reported"}`));
      if (p) list.append(make("li", p.policy_sha256, "heartbeat-digest"));
      list.append(make("li", `Sequence ${r.sequence} · credential generation ${r.credential_generation} (current ${d.current_credential_generation}) · registered ${new Date(r.registered_at_unix * 1000).toLocaleString()}`));
      if (r.last_received_at_unix != null) list.append(make("li", `Last received by the Console: ${new Date(r.last_received_at_unix * 1000).toLocaleString()}`));
      root.append(list);
    }
    root.append(make("p", "A heartbeat is the Agent's own authenticated report, timed by this Console. It is not runtime attestation, proof of enforcement or a health check. The reported policy is separate from the server-recorded delivery above.", "note"));
  }
  async function load() {
    if (!scope) return;
    controller?.abort(); controller = new AbortController();
    const { tenant, agent } = scope, generation = epoch, signal = controller.signal, guard = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      const d = await request(`/admin/v1/tenants/${encodeURIComponent(tenant)}/agent-fleet/${encodeURIComponent(agent)}/heartbeat`, { signal, cache: "no-store" });
      if (generation !== epoch) return;
      if (!valid(d, tenant, agent)) throw Object.assign(new Error("shape"), { code: "shape" });
      render(d);
    } catch (e) {
      if (generation !== epoch) return;
      $("heartbeat-detail").replaceChildren();
      if (e.status === 401 || e.status === 403) { stop(); status(e.status === 401 ? "Session expired. Reconnect to read the heartbeat status." : "This role cannot read the heartbeat status.", "outcome-block"); return; }
      if (e.status === 404) { status("Tenant or Agent not found.", "outcome-block"); return; }
      status(e.code === "shape" ? "A heartbeat status response did not match the selected Agent or had an unexpected shape; it was discarded." : "Heartbeat status could not be read. Status unknown; it retries automatically.", "outcome-other");
    } finally { clearTimeout(guard); }
  }
  function stop() { clearInterval(timer); timer = null; }
  function select(tenant, agent) {
    epoch++; controller?.abort(); controller = null; stop(); $("heartbeat-detail").replaceChildren();
    scope = tenant && agent && ID.test(tenant) && ID.test(agent) ? { tenant, agent } : null;
    $("heartbeat-refresh").disabled = !scope;
    if (!scope) { status("Select an Agent in the fleet list to see its heartbeat status."); return; }
    status("Loading heartbeat status…");
    load(); timer = setInterval(load, REFRESH_MS);
  }
  $("heartbeat-refresh").addEventListener("click", () => load());
  return { select, clear: () => select(null, null) };
})();
