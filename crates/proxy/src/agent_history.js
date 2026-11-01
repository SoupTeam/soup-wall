// SPDX-License-Identifier: Apache-2.0
// Per-Agent recorded history and incident snapshot. Read-only: it uses only
// the existing fleet detail read (GET .../agent-fleet/:agent) through the
// in-memory authenticated request helper. It never changes rollout or
// credential state and never renders server text as HTML.
const agentHistory = (() => {
  const CONTRACT = "sw-agent-fleet/1", SNAPSHOT = "sw-agent-incident-snapshot/1";
  // Finite bounds for one history build. Reaching any of them leaves the
  // history marked partial; it never extends a bound on its own.
  const BOUNDS = Object.freeze({ page_records: 50, max_pages: 8, max_page_bytes: 262144, max_total_bytes: 1048576, page_timeout_ms: 15000, max_build_ms: 60000 });
  const ID = /^[A-Za-z0-9._-]{1,128}$/, DIGEST = /^[0-9a-f]{64}$/, SEQ = /^[1-9][0-9]{0,15}$/;
  const STATES = ["issued", "delivered", "applied", "rejected"], ACTIONS = ["activate", "rollback"];
  // Text that must never appear in an export, even as a synthetic value.
  const FORBIDDEN = [/sw_agent_[A-Za-z0-9_-]{8,}/, /bearer\s+\S/i, /\beyJ[A-Za-z0-9_-]{8,}/, /(^|[\s"'])(\/home\/|\/Users\/|\/root\/|\/tmp\/|[A-Za-z]:\\)/, /-----BEGIN/, /policy_yaml|bundle_json|token_hash|signature_hex|authorization/i];
  let scope = null, epoch = 0, controller = null, state = null;
  const now = () => Math.floor(Date.now() / 1000);
  const int = v => Number.isSafeInteger(v) ? v : null;
  const when = v => v == null ? "time not recorded" : new Date(v * 1000).toLocaleString();
  const fresh = (tenant, agent) => ({ tenant, agent, summary: null, records: new Map(), pages: [], cursor: null, exhausted: false,
    reasons: new Map(), contradictions: [], malformed: 0, bytes: 0, started: Date.now(), busy: false, error: null });
  const reason = (code, detail) => { if (state && !state.reasons.has(code)) state.reasons.set(code, detail); };

  // Validation keeps only known fields with known shapes; anything else is
  // counted as malformed and dropped, never rendered or exported.
  function record(d) {
    if (!d || typeof d !== "object") return null;
    const r = { sequence: d.sequence, revision: d.revision, policy_sha256: d.policy_sha256, action: d.action, recorded_state: d.recorded_state,
      issued_at_unix: int(d.issued_at_unix), reported_applied_at_unix: d.reported_applied_at_unix == null ? null : int(d.reported_applied_at_unix) };
    if (typeof r.sequence !== "string" || !SEQ.test(r.sequence) || typeof r.revision !== "string" || !ID.test(r.revision)
      || typeof r.policy_sha256 !== "string" || !DIGEST.test(r.policy_sha256) || !ACTIONS.includes(r.action)
      || !STATES.includes(r.recorded_state) || r.issued_at_unix == null || (d.reported_applied_at_unix != null && r.reported_applied_at_unix == null)) return null;
    // Only exact integers: a 16-digit value above 2^53 would round.
    r.seq = Number(r.sequence);
    if (!Number.isSafeInteger(r.seq)) return null;
    return r;
  }
  const sameOrNull = (a, b) => (a == null && b == null) || (a != null && b != null && same(a, b));
  const same = (a, b) => ["sequence", "revision", "policy_sha256", "action", "recorded_state", "issued_at_unix", "reported_applied_at_unix"].every(k => a[k] === b[k]);
  function contradiction(code, detail, sequence = null) {
    if (!state.contradictions.some(c => c.code === code && c.sequence === sequence)) state.contradictions.push({ code, sequence, detail });
  }

  // Merges one validated page. Returns "scope" when the response belongs to
  // another scope and "malformed" when its Agent summary cannot be trusted;
  // then nothing from it is kept.
  function merge(data, before) {
    const a = data?.agent;
    if (data?.contract_version !== CONTRACT || a?.tenant_id !== state.tenant || a?.agent_id !== state.agent || !Array.isArray(data.deployments)) return "scope";
    const enrolled = int(a.enrolled_at_unix), revoked = a.revoked_at_unix == null ? null : int(a.revoked_at_unix);
    if (enrolled == null || (a.revoked_at_unix != null && revoked == null)) return "malformed";
    const latest = a.latest_issued ? record(a.latest_issued) : null, applied = a.last_reported_applied ? record(a.last_reported_applied) : null;
    if ((a.latest_issued && !latest) || (a.last_reported_applied && !applied)) return "malformed";
    if (!state.summary) state.summary = { enrolled, revoked, latest, applied, observed: int(data.observed_at_unix) };
    else if (state.summary.enrolled !== enrolled || state.summary.revoked !== revoked || !sameOrNull(state.summary.latest, latest) || !sameOrNull(state.summary.applied, applied))
      reason("records_changed_while_paging", "Enrollment or latest deployment changed between page reads; rebuild the history.");
    const page = { before_sequence: before, observed_at_unix: int(data.observed_at_unix), records: 0, malformed: 0, overlapping: 0 };
    for (const raw of data.deployments) {
      const r = record(raw);
      if (!r) { page.malformed++; state.malformed++; continue; }
      if (before != null && r.seq >= before) page.overlapping++;
      const old = state.records.get(r.seq);
      if (old) { if (!same(old, r)) contradiction("conflicting_duplicate", `Two reads returned different content for deployment #${r.seq}.`, r.sequence); continue; }
      state.records.set(r.seq, r); page.records++;
    }
    if (page.malformed) reason("malformed_records", "Records with an unexpected shape were dropped.");
    if (page.overlapping) reason("overlapping_pages", "A page repeated records at or after its cursor; duplicates were removed.");
    state.pages.push(page);
    const next = data.next_before_sequence;
    if (next == null) state.exhausted = true;
    else if (typeof next === "string" && SEQ.test(next) && Number.isSafeInteger(Number(next)) && (before == null || Number(next) < before)) state.cursor = Number(next);
    else { state.exhausted = true; reason("invalid_cursor", "The server returned a cursor that does not move to older records; paging stopped."); }
    return true;
  }

  // Pure derivation of what is known from the accepted records.
  function analyse() {
    const s = state.summary, out = { events: [], unresolved: [], reasons: [], coverage: null, status: "incomplete" };
    if (!s) return out;
    // Derived reasons are recomputed on every call; only paging events persist.
    const derived = new Map(state.reasons), reason = (code, detail) => { if (!derived.has(code)) derived.set(code, detail); };
    const seqs = [...state.records.keys()].sort((x, y) => x - y), expected = s.latest ? s.latest.seq : 0;
    const top = seqs.length ? seqs[seqs.length - 1] : 0;
    if (s.latest && top > expected) contradiction("newer_than_latest", `Deployment #${top} is newer than the summary's latest issued #${expected}.`);
    if (s.latest && state.records.has(expected) && !same(state.records.get(expected), s.latest)) contradiction("summary_mismatch", `Latest issued summary differs from the record for #${expected}.`, s.latest.sequence);
    if (s.applied && state.records.has(s.applied.seq) && !same(state.records.get(s.applied.seq), s.applied)) contradiction("summary_mismatch", `Last applied summary differs from the record for #${s.applied.seq}.`, s.applied.sequence);
    // Missing ranges come from the sorted loaded set (at most the bounded
    // number of records), never from walking the numeric sequence space.
    const missing = [];
    let previous = 0;
    for (const n of seqs) {
      if (n > expected) break;
      if (n > previous + 1) missing.push([previous + 1, n - 1]);
      previous = n;
    }
    if (expected > previous) missing.push([previous + 1, expected]);
    const lowest = seqs.length ? seqs[0] : null;
    // A missing run above the lowest loaded record is a hole between pages;
    // one below it is older history that was not (or could not be) loaded.
    if (missing.some(([lo]) => lowest != null && lo > lowest)) reason("sequence_gap", "Loaded pages skip deployment sequences; the timeline between them is unknown.");
    if (missing.some(([, hi]) => lowest == null || hi < lowest)) {
      if (state.exhausted) reason("history_missing", "The server reported no older records, but earlier sequences are absent (missing or expired history).");
      else reason("older_records_not_loaded", "Older records exist beyond the loaded pages.");
    }
    reason("credential_rotations_not_recorded", "The Console keeps no dated record of credential rotations; only enrollment and revocation times are known.");
    reason("fetch_and_rejection_times_not_recorded", "Fetch and rejection are recorded as states without timestamps.");
    const ev = (id, kind, at, r, note, extra = {}) => out.events.push({ event_id: `${state.tenant}/${state.agent}/${id}`, kind, at_unix: at, time_recorded: at != null,
      sequence: r?.sequence ?? null, revision: r?.revision ?? null, policy_sha256: r?.policy_sha256 ?? null, action: r?.action ?? null, note, ...extra, _anchor: r ? r.issued_at_unix : at });
    ev("enrollment/enrolled", "enrolled", s.enrolled, null, "Agent enrolled; first credential issued.");
    if (s.revoked != null) ev("enrollment/revoked", "revoked", s.revoked, null, "Credential revoked; the Agent receives nothing new.");
    for (const n of seqs) {
      const r = state.records.get(n), latest = n === expected;
      if (r.issued_at_unix < s.enrolled) contradiction("issued_before_enrollment", `Deployment #${n} was issued before enrollment.`, r.sequence);
      if (s.revoked != null && r.issued_at_unix > s.revoked) contradiction("issued_after_revocation", `Deployment #${n} was issued after revocation.`, r.sequence);
      if ((r.recorded_state === "applied") !== (r.reported_applied_at_unix != null)) contradiction("applied_time_mismatch", `Deployment #${n} has an applied time that does not match its state.`, r.sequence);
      if (r.reported_applied_at_unix != null && r.reported_applied_at_unix < r.issued_at_unix) contradiction("applied_before_issued", `Deployment #${n} reports applied before it was issued.`, r.sequence);
      // The Console accepts an acknowledgement only for the latest deployment,
      // so an applied time after the next deployment was issued is impossible.
      const following = state.records.get(n + 1);
      if (r.reported_applied_at_unix != null && following && r.reported_applied_at_unix > following.issued_at_unix)
        contradiction("applied_after_superseded", `Deployment #${n} reports applied after #${n + 1} was issued.`, r.sequence);
      ev(`deployment/${n}/issued`, "issued", r.issued_at_unix, r, `${r.action === "rollback" ? "Rollback" : "Activation"} issued.`);
      if (r.recorded_state === "delivered") ev(`deployment/${n}/fetched`, "fetched", null, r, "Fetched by the Agent; time not recorded.");
      if (r.recorded_state === "applied") ev(`deployment/${n}/applied`, "applied", r.reported_applied_at_unix, r, "Agent reported applied (historical report, not current protection).");
      if (r.recorded_state === "rejected") ev(`deployment/${n}/rejected`, "rejected", null, r, "Agent reported rejected; time not recorded.");
      if (["issued", "delivered"].includes(r.recorded_state)) {
        const id = `deployment/${n}/${latest ? "pending" : "superseded"}`;
        ev(id, latest ? "pending" : "superseded", null, r, latest ? "No acknowledgement recorded yet." : "Superseded by a newer deployment without any acknowledgement.");
        out.unresolved.push(`${state.tenant}/${state.agent}/${id}`);
      }
    }
    // Chronological: an event with a recorded time sorts by that time. An
    // event without one stays beside its own deployment's issue time and
    // never moves to "now".
    const order = { enrolled: 0, issued: 1, fetched: 2, applied: 3, rejected: 3, pending: 4, superseded: 4, revoked: 5 };
    // Within one second: enrollment first, revocation last, then by sequence.
    const group = e => e.kind === "enrolled" ? 0 : e.kind === "revoked" ? 2 : 1;
    const key = e => e.at_unix ?? e._anchor, seq = e => e.sequence ? Number(e.sequence) : 0;
    out.events.sort((x, y) => (key(x) - key(y)) || (group(x) - group(y)) || (seq(x) - seq(y)) || (order[x.kind] - order[y.kind]));
    out.events.forEach(e => delete e._anchor);
    if (state.error) reason(state.error.code, state.error.detail);
    if (!state.exhausted && state.pages.length >= BOUNDS.max_pages) reason("page_bound_reached", `Stopped at the ${BOUNDS.max_pages}-page bound for one build; older records were not read.`);
    out.reasons = [...derived].map(([code, detail]) => ({ code, detail }));
    const ranges = []; for (const n of seqs) { const last = ranges[ranges.length - 1]; if (last && last[1] === n - 1) last[1] = n; else ranges.push([n, n]); }
    out.coverage = { expected_deployments: expected, loaded_deployments: seqs.length, loaded_sequence_ranges: ranges, missing_sequence_ranges: missing,
      pages: state.pages.map(p => ({ ...p })), malformed_records_dropped: state.malformed, bounds: { ...BOUNDS } };
    const blocking = out.reasons.filter(r => !["credential_rotations_not_recorded", "fetch_and_rejection_times_not_recorded"].includes(r.code));
    out.status = state.contradictions.length ? "contradictory" : blocking.length ? "incomplete" : "complete_records";
    return out;
  }

  // Only allowlisted, validated fields are copied; the result is scanned once
  // more before it may leave the page.
  function snapshot() {
    const a = analyse(), s = state.summary;
    const pick = r => r ? { sequence: r.sequence, revision: r.revision, policy_sha256: r.policy_sha256, action: r.action, recorded_state: r.recorded_state, issued_at_unix: r.issued_at_unix, reported_applied_at_unix: r.reported_applied_at_unix } : null;
    const times = a.events.map(e => e.at_unix).filter(v => v != null);
    const value = {
      contract_version: SNAPSHOT,
      generated_at_unix: now(),
      source: { api: "GET /admin/v1/tenants/{tenant}/agent-fleet/{agent}", contract_version: CONTRACT },
      scope: { tenant_id: state.tenant, agent_id: state.agent },
      partial: a.status !== "complete_records",
      completeness: { status: a.status, reasons: a.reasons, contradictions: state.contradictions.map(c => ({ ...c })) },
      coverage: a.coverage,
      time_bounds: { earliest_recorded_unix: times.length ? Math.min(...times) : null, latest_recorded_unix: times.length ? Math.max(...times) : null,
        first_page_observed_at_unix: state.pages[0]?.observed_at_unix ?? null, last_page_observed_at_unix: state.pages[state.pages.length - 1]?.observed_at_unix ?? null },
      enrollment: { enrolled_at_unix: s.enrolled, revoked_at_unix: s.revoked },
      summary: { latest_issued: pick(s.latest), historical_last_reported_applied: pick(s.applied), current_protection: "unknown", current_liveness: "unknown",
        note: "Recorded Console evidence only. An applied acknowledgement is a past report, not runtime attestation." },
      unresolved_event_ids: a.unresolved,
      events: a.events
    };
    if (FORBIDDEN.some(p => p.test(JSON.stringify(value)))) throw new Error("Snapshot refused: it would contain text that looks private.");
    value.excluded = ["credentials and tokens", "prompts", "tool payloads", "raw policy bodies", "request auth headers", "private host paths"];
    return { value, text: JSON.stringify(value, null, 2) + "\n" };
  }

  const status = (text, cls = "note") => { const n = $("history-status"); n.textContent = text; n.className = cls; };
  const controls = () => {
    const ready = !!(state && state.summary && !state.busy);
    $("history-more").disabled = !ready || state.exhausted || state.pages.length >= BOUNDS.max_pages || !!state.error?.terminal;
    $("history-preview").disabled = !ready; $("history-download").disabled = !ready;
  };
  function clearView() {
    $("history-summary").replaceChildren(); $("history-timeline").replaceChildren();
    const pre = $("history-snapshot"); pre.textContent = ""; pre.classList.add("hidden");
  }
  const link = (r, label) => {
    if (!r) return make("span", label === "Latest issued" ? "No deployment history" : "No applied acknowledgement");
    const target = $("history-dep-" + r.sequence), node = target ? make("a", `#${r.sequence} · ${r.revision}`) : make("span", `#${r.sequence} · ${r.revision} (not on loaded pages)`);
    if (target) node.href = "#history-dep-" + r.sequence;
    return node;
  };
  function render() {
    clearView(); if (!state?.summary) return;
    const a = analyse(), s = state.summary, cov = a.coverage;
    const ol = $("history-timeline");
    if (!a.events.length) ol.append(make("li", "No records on the loaded pages.", "empty"));
    for (const e of a.events) {
      const li = make("li", undefined, "history-event history-" + e.kind);
      if (e.sequence && e.kind === "issued") li.id = "history-dep-" + e.sequence;
      li.append(make("strong", e.kind[0].toUpperCase() + e.kind.slice(1)), make("span", " · " + when(e.at_unix)));
      if (e.sequence) li.append(make("span", ` · #${e.sequence} · ${e.revision} · ${e.action}`), make("code", e.policy_sha256));
      li.append(make("p", e.note, ["pending", "superseded"].includes(e.kind) ? "outcome-other" : e.kind === "rejected" ? "outcome-block" : "note"));
      ol.append(li);
    }
    const box = $("history-summary"), grid = make("div", undefined, "grid-two");
    [["Latest issued", s.latest], ["Historical last reported applied", s.applied]].forEach(([label, r]) => {
      const card = make("div", undefined, "metric"); card.append(make("h3", label)); const p = make("p"); p.append(link(r, label)); card.append(p);
      if (r) card.append(make("code", r.policy_sha256), make("p", `State: ${r.recorded_state}`, "note"));
      grid.append(card);
    });
    box.append(grid);
    const label = { complete_records: "All deployment records loaded (recorded evidence only)", incomplete: "Incomplete history", contradictory: "Contradictory records" }[a.status];
    box.append(make("p", `${label}. Loaded ${cov.loaded_deployments} of ${cov.expected_deployments} deployment records in ${cov.pages.length} page(s). Current protection and liveness: unknown.`,
      a.status === "contradictory" ? "outcome-block" : a.status === "incomplete" ? "outcome-other" : "note"));
    if (a.unresolved.length) box.append(make("p", `${a.unresolved.length} unresolved outcome(s): pending or superseded without acknowledgement.`, "outcome-other"));
    const list = make("ul", undefined, "history-reasons");
    a.reasons.forEach(r => list.append(make("li", r.detail)));
    state.contradictions.forEach(c => list.append(make("li", c.detail, "outcome-block")));
    box.append(list);
  }

  async function page() {
    if (!state || state.busy) return;
    const mine = state, generation = epoch, before = state.cursor;
    if (state.pages.length >= BOUNDS.max_pages) { reason("page_bound_reached", `Stopped at the ${BOUNDS.max_pages}-page bound.`); render(); controls(); return; }
    if (Date.now() - state.started > BOUNDS.max_build_ms) { reason("time_bound_reached", "Stopped at the time bound for one history build."); render(); controls(); return; }
    state.busy = true; state.error = null; controls();
    controller?.abort(); controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), BOUNDS.page_timeout_ms), signal = controller.signal;
    status(before == null ? "Loading recorded history…" : `Loading records older than #${before}…`);
    const q = new URLSearchParams({ limit: String(BOUNDS.page_records) }); if (before != null) q.set("before_sequence", String(before));
    try {
      const data = await request(`/admin/v1/tenants/${encodeURIComponent(mine.tenant)}/agent-fleet/${encodeURIComponent(mine.agent)}?${q}`, { signal, cache: "no-store" });
      if (generation !== epoch || state !== mine) return;
      const size = new TextEncoder().encode(JSON.stringify(data ?? null)).length;
      if (size > BOUNDS.max_page_bytes || mine.bytes + size > BOUNDS.max_total_bytes) { mine.error = { code: "byte_bound_reached", detail: "A page exceeded the size bound and was not used.", terminal: true }; return; }
      mine.bytes += size;
      const merged = merge(data, before);
      if (merged === "scope") { mine.error = { code: "scope_mismatch", detail: "A response did not match the selected tenant and Agent; it was discarded and paging stopped.", terminal: true }; return; }
      if (merged === "malformed") { mine.error = { code: "malformed_summary", detail: "The Agent summary had an unexpected shape (for example an out-of-range sequence); the response was not used and paging stopped.", terminal: true }; return; }
    } catch (e) {
      if (generation !== epoch || state !== mine) return;
      if (e.status === 401 || e.status === 403) {
        // Lost read authorization: forget what was shown.
        state = null; clearView(); controls(); status(e.status === 401 ? "Session expired. Reconnect to read Agent history." : "This role cannot read Agent history.", "outcome-block"); return;
      }
      if (e.status === 404) { state = null; clearView(); controls(); status("Tenant or Agent not found. Its history is unavailable.", "outcome-block"); return; }
      mine.error = { code: "page_request_failed", detail: e.name === "AbortError" ? "A page timed out; the history is partial. Load older records to retry." : "A page could not be read; the history is partial. Load older records to retry." };
    } finally {
      clearTimeout(timer);
      if (generation === epoch && state === mine) {
        mine.busy = false; render(); controls();
        if (!mine.summary) status(["scope_mismatch", "malformed_summary"].includes(mine.error?.code) ? mine.error.detail : "Unable to load Agent history. Select the Agent again to retry.", "outcome-block");
        else if (mine.error) status(mine.error.detail, "outcome-other");
        else status(`History for ${mine.agent} read ${when(mine.pages[mine.pages.length - 1]?.observed_at_unix ?? null)}. ${mine.exhausted ? "No older pages." : "Older records may exist."}`);
      }
    }
  }

  function select(tenant, agent) {
    epoch++; controller?.abort(); controller = null; clearView();
    scope = tenant && agent && ID.test(tenant) && ID.test(agent) ? { tenant, agent } : null;
    state = scope ? fresh(tenant, agent) : null; controls();
    if (!scope) { status("Select an Agent in the fleet list to build its recorded history."); return; }
    page();
  }
  function preview() {
    try { const pre = $("history-snapshot"); pre.textContent = snapshot().text; pre.classList.remove("hidden"); status("Snapshot preview below. Nothing was sent or changed.");
    } catch (e) { status(e.message, "outcome-block"); }
  }
  function download() {
    try {
      const { value, text } = snapshot(), url = URL.createObjectURL(new Blob([text], { type: "application/json" })), a = document.createElement("a");
      a.href = url; a.download = `agent-history-${value.scope.tenant_id}-${value.scope.agent_id}-${value.generated_at_unix}${value.partial ? "-partial" : ""}.json`;
      document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 0);
      status(`Snapshot downloaded${value.partial ? " (marked partial)" : ""}. Nothing was changed.`);
    } catch (e) { status(e.message, "outcome-block"); }
  }
  $("history-more").addEventListener("click", () => page());
  $("history-preview").addEventListener("click", preview);
  $("history-download").addEventListener("click", download);
  return { select, clear: () => select(null, null) };
})();
