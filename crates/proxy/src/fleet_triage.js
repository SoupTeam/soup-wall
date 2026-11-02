// SPDX-License-Identifier: Apache-2.0
// Cross-Agent triage overview. Read-only: one bounded server projection
// (GET .../agent-triage, sw-agent-fleet-triage/1) through the in-memory
// authenticated request helper. Filter and page state live only in this
// module's memory, never in the URL or browser storage. It links to the
// existing fleet/history and rollout modules instead of repeating them.
const fleetTriage = (() => {
  const CONTRACT = "sw-agent-fleet-triage/1", MAX_BYTES = 524288, TIMEOUT_MS = 15000, PAGE = 25;
  const ID = /^[A-Za-z0-9._-]{1,128}$/;
  const LABELS = {
    pending: "Pending delivery", rejected: "Rejected", mismatch: "Applied revision differs from latest issued",
    revoked: "Credential revoked", incomplete_history: "Incomplete history", no_ack: "No acknowledgement recorded",
    stale_ack: "Old acknowledgement", no_history: "No delivery recorded"
  };
  const FILTERS = ["attention", ...Object.keys(LABELS), "no_recorded_problem", "all"];
  let tenant = null, epoch = 0, request_ = 0, controller = null, busy = false;
  let cursor = null, pageNumber = 0, seen = new Set(), last = null;
  const status = (text, cls = "note") => { const n = $("triage-status"); n.textContent = text; n.className = cls; };
  const url = q => `/admin/v1/tenants/${encodeURIComponent(tenant)}/agent-triage?${q}`;
  const ago = (observed, at) => {
    if (at == null) return "No acknowledgement recorded";
    const s = Math.max(0, observed - at);
    const text = s < 3600 ? `${Math.floor(s / 60)} min` : s < 172800 ? `${Math.floor(s / 3600)} h` : `${Math.floor(s / 86400)} d`;
    return `${text} before this read (historical)`;
  };
  const deployment = (d, observed, applied) => !d ? (applied ? "No applied acknowledgement" : "No delivery recorded")
    : `#${d.sequence} · ${d.revision} · ${d.recorded_state}${applied ? " · " + ago(observed, d.reported_applied_at_unix) : ""}`;
  const integer = v => Number.isSafeInteger(v) && v >= 0;
  const counts = c => c && ["counted_agents", "scan_limit", "attention", "pending", "rejected", "mismatch", "revoked", "incomplete_history",
    "no_ack", "stale_ack", "no_history", "no_recorded_problem", "matching"].every(k => integer(c[k])) && typeof c.complete === "boolean";

  // A page is used only when every record belongs to the selected tenant and
  // has a known shape; otherwise nothing from it is shown.
  function valid(data, id) {
    if (data?.contract_version !== CONTRACT || data.tenant_id !== id || !Array.isArray(data.agents) || !counts(data.counts) || !integer(data.observed_at_unix)) return false;
    // Counts and page come from one snapshot of the same bounded universe:
    // a page listing more Agents than match is inconsistent and is refused.
    if (data.agents.length > data.counts.matching || data.counts.matching > data.counts.counted_agents || data.counts.counted_agents > data.counts.scan_limit) return false;
    const ids = new Set();
    return data.agents.every(a => a && a.tenant_id === id && typeof a.agent_id === "string" && ID.test(a.agent_id) && !ids.has(a.agent_id) && ids.add(a.agent_id)
      && Array.isArray(a.problems) && a.problems.every(p => p in LABELS) && integer(a.deployment_records) && integer(a.group_count)
      && (a.first_group_id == null || (typeof a.first_group_id === "string" && ID.test(a.first_group_id))))
      && (data.next == null || (typeof data.next.after === "string" && ID.test(data.next.after) && (data.next.after_ack == null || Number.isSafeInteger(data.next.after_ack))));
  }
  function clear() {
    $("triage-summary").replaceChildren(); $("triage-list").replaceChildren();
    $("triage-next").disabled = true; $("triage-first").disabled = true; last = null;
  }
  function summary(data) {
    const c = data.counts, box = $("triage-summary"), grid = make("div", undefined, "triage-counts");
    [["attention", "Need attention"], ...Object.entries(LABELS), ["no_recorded_problem", "No recorded problem"]].forEach(([key, label]) => {
      const b = make("button", undefined, "secondary triage-count" + (data.problem === key ? " selected" : ""));
      b.type = "button"; b.dataset.problem = key; b.setAttribute("aria-pressed", String(data.problem === key));
      b.append(make("strong", String(c[key])), make("span", ` of ${c.counted_agents} · ${label}`));
      b.addEventListener("click", () => { $("triage-problem").value = key; load(); });
      grid.append(b);
    });
    box.append(grid);
    const scope = c.complete ? `Counts and list cover all ${c.counted_agents} enrolled Agents`
      : `Count bound reached: counts and list cover only the first ${c.counted_agents} Agents by ID; later Agents are neither counted nor listed`;
    box.append(make("p", `${scope}. Read ${new Date(data.observed_at_unix * 1000).toLocaleString()}. "No recorded problem" is not proof of health: current liveness and active protection are unknown.`,
      c.complete ? "note" : "outcome-other"));
  }
  function rows(data) {
    const root = $("triage-list");
    if (!data.agents.length) { root.append(make("p", pageNumber > 1 ? "No more Agents on this page." : "No enrolled Agents match these filters.", "empty")); return; }
    const table = make("table"), head = make("tr"), body = make("tbody"), thead = make("thead");
    ["Agent", "Recorded problems", "Latest issued", "Last reported applied", "Records", "Open"].forEach(h => head.append(make("th", h)));
    thead.append(head); table.append(thead);
    data.agents.forEach(a => {
      const tr = make("tr"), problems = make("td"), open = make("td");
      if (a.problems.length) { const ul = make("ul", undefined, "triage-problems"); a.problems.forEach(p => ul.append(make("li", LABELS[p], ["rejected", "mismatch", "incomplete_history"].includes(p) ? "outcome-block" : "outcome-other"))); problems.append(ul); }
      else problems.append(make("span", "None recorded (not proof of health)", "note"));
      const seq = a.latest_issued ? Number(a.latest_issued.sequence) : 0;
      const history = make("button", "History", "secondary tiny");
      history.type = "button"; history.setAttribute("aria-label", `Open recorded history for ${a.agent_id}`);
      history.addEventListener("click", () => fleet.open(a.agent_id));
      open.append(history);
      if (a.first_group_id) {
        const r = make("button", "Rollout", "secondary tiny");
        r.type = "button"; r.setAttribute("aria-label", `Open rollout group ${a.first_group_id} for ${a.agent_id}`);
        r.addEventListener("click", async () => { if (!(await rollout.open(tenant, a.first_group_id))) status(`Rollout group ${a.first_group_id} is not in the rollout list for this tenant.`, "outcome-other"); });
        open.append(r);
        if (a.group_count > 1) open.append(make("span", ` +${a.group_count - 1} group(s)`, "note"));
      }
      tr.append(make("td", a.agent_id), problems, make("td", deployment(a.latest_issued, data.observed_at_unix, false)),
        make("td", deployment(a.last_reported_applied, data.observed_at_unix, true)),
        make("td", seq ? `${a.deployment_records} of ${seq}` : "0"), open);
      body.append(tr);
    });
    table.append(body);
    const wrap = make("div", undefined, "table-wrap"); wrap.append(table); root.append(wrap);
  }

  async function load(after = null) {
    if (!tenant) return;
    controller?.abort(); controller = new AbortController();
    const id = tenant, generation = epoch, mine = ++request_, signal = controller.signal, timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    if (!after) { pageNumber = 0; seen = new Set(); }
    busy = true; clear();
    const problem = $("triage-problem").value, sort = $("triage-sort").value, age = $("triage-age").value, prefix = $("triage-prefix").value.trim();
    if (prefix && !ID.test(prefix)) { busy = false; clearTimeout(timer); status("Agent ID prefix may contain letters, digits, '.', '_' and '-' only.", "outcome-block"); return; }
    const q = new URLSearchParams({ limit: String(PAGE), problem, sort, ack_age_seconds: age, prefix });
    if (after) { q.set("after", after.after); if (after.after_ack != null) q.set("after_ack", String(after.after_ack)); }
    status(after ? "Loading the next page…" : "Loading fleet triage…");
    try {
      const data = await request(url(q), { signal, cache: "no-store" });
      if (generation !== epoch || mine !== request_ || id !== tenant) return;
      if (new TextEncoder().encode(JSON.stringify(data ?? null)).length > MAX_BYTES) throw Object.assign(new Error("size"), { code: "size" });
      if (!valid(data, id) || data.problem !== problem || data.sort !== sort || String(data.ack_age_seconds) !== age || data.prefix !== prefix)
        throw Object.assign(new Error("identity"), { code: "identity" });
      pageNumber++; last = data;
      const repeats = data.agents.filter(a => seen.has(a.agent_id)).length;
      data.agents.forEach(a => seen.add(a.agent_id));
      summary(data); rows(data);
      cursor = data.next; $("triage-next").disabled = !cursor; $("triage-first").disabled = pageNumber <= 1;
      const shown = seen.size, c = data.counts;
      let text = `Page ${pageNumber}: ${data.agents.length} Agent(s). Seen ${Math.min(shown, c.matching)} of ${c.matching} matching${c.complete ? "" : ` among the first ${c.counted_agents} Agents by ID`}.`;
      if (shown > c.matching) text += ` ${shown - c.matching} more seen than the current count: records changed between pages, so the count is not a denominator for them; refresh for a new snapshot.`;
      else if (!cursor && shown < c.matching) text += " Fewer than counted: records changed between pages; refresh for a new snapshot.";
      if (repeats) text += ` ${repeats} Agent(s) repeated from an earlier page because records changed; each page is a separate read.`;
      status(text, repeats || shown > c.matching || (!cursor && shown < c.matching) || !c.complete ? "outcome-other" : "note");
    } catch (e) {
      if (generation !== epoch || mine !== request_ || id !== tenant) return;
      clear();
      if (e.status === 401) status("Session expired. Reconnect to read fleet triage.", "outcome-block");
      else if (e.status === 403) status("This role cannot read fleet triage.", "outcome-block");
      else if (e.status === 404) status("Tenant not found.", "outcome-block");
      else if (e.code === "identity") status("A triage response did not match the selected tenant or filters, or had an unexpected shape; it was discarded.", "outcome-block");
      else if (e.code === "size") status("A triage response exceeded the size bound and was not used.", "outcome-block");
      else status(e.name === "AbortError" ? "Fleet triage timed out. Refresh to retry." : "Unable to load fleet triage. Refresh to retry.", "outcome-block");
    } finally {
      clearTimeout(timer);
      if (generation === epoch && mine === request_) busy = false;
    }
  }

  $("triage-filter").addEventListener("submit", e => { e.preventDefault(); load(); });
  $("triage-refresh").addEventListener("click", () => load());
  $("triage-first").addEventListener("click", () => load());
  $("triage-next").addEventListener("click", () => { if (cursor && !busy) load(cursor); });
  return {
    select(id) {
      epoch++; request_++; controller?.abort(); controller = null; busy = false; tenant = id; cursor = null; pageNumber = 0; seen = new Set(); clear();
      $("triage-problem").value = "attention"; $("triage-sort").value = "agent_id"; $("triage-age").value = "86400"; $("triage-prefix").value = "";
      if (id) load(); else status("Select a tenant to see which Agents need attention.");
    },
    filters: FILTERS
  };
})();
