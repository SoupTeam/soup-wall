// SPDX-License-Identifier: Apache-2.0
// Managed Agent enrollment and credential lifecycle over the existing
// /admin/v1/tenants/:t/agents APIs. Uses the page's in-memory authenticated
// request helper. Owner role and tenant checks stay on the server. An issued
// credential lives only in this closure and the transient secret view; it is
// never written to a URL, browser storage, the console log or an attribute.
const enrollment = (() => {
  const ID = /^[A-Za-z0-9_.-]{1,128}$/;
  let tenant = null, epoch = 0, controller = null, agents = [], issuer = null;
  let busy = false, blocked = "", pending = null, secret = null;

  const owner = () => currentAdmin?.role === "owner";
  const base = id => `/admin/v1/tenants/${encodeURIComponent(id)}/agents`;
  const say = (text, kind = "note") => { const n = $("enroll-status"); n.textContent = text; n.className = kind; };
  const when = v => v == null ? "" : new Date(v * 1000).toLocaleString();
  // The shared helper rejects with `status` for HTTP errors; no status or a
  // server error leaves a mutation's outcome unknown.
  const ambiguous = e => e.status === undefined || e.status >= 500;
  const stale = (id, generation) => generation !== epoch || id !== tenant;

  function lock() {
    const disabled = busy || !!blocked || !!secret || !!pending || !owner();
    document.querySelectorAll("#enroll-panel .enroll-mutation").forEach(b => { b.disabled = disabled; });
    document.querySelectorAll("#enroll-panel .enroll-reconcile").forEach(b => { b.disabled = busy; });
  }

  async function load() {
    const id = tenant, generation = epoch;
    if (!id) return null;
    const value = await request(base(id), { signal: controller.signal, cache: "no-store" });
    if (stale(id, generation)) return null;
    if (!Array.isArray(value) || value.some(a => a.tenant_id !== id)) throw new Error("Agent inventory identity mismatch");
    agents = value;
    render();
    return value;
  }

  async function refresh(message) {
    const generation = epoch;
    try {
      await load();
      if (generation === epoch && message !== false) say(message || `Enrollment records read ${new Date().toLocaleString()}. A record is not proof that an Agent is running or protected.`);
    } catch (e) {
      if (generation !== epoch || e.name === "AbortError" || failure(e, "Reading enrollment records")) return;
      say("Unable to load enrollment records. Refresh to retry.", "error");
    }
  }

  function render() {
    const root = $("enroll-list");
    root.replaceChildren();
    if (!agents.length) { root.append(make("p", "No Agents are enrolled in this tenant.", "empty")); lock(); return; }
    const table = make("table"), head = make("thead"), hr = make("tr"), body = make("tbody");
    ["Agent", "Enrollment record", "Credential generation", ""].forEach(h => hr.append(make("th", h)));
    head.append(hr); table.append(head);
    agents.forEach(a => {
      const row = make("tr"), id = make("td"), actions = make("td");
      id.append(make("code", a.agent_id));
      row.append(id, make("td", a.revoked_at_unix == null ? `Enrolled ${when(a.created_at_unix)}` : `Revoked ${when(a.revoked_at_unix)}`),
        make("td", String(a.credential_generation)));
      if (owner() && a.revoked_at_unix == null) {
        const rotate = make("button", "Rotate credential", "secondary tiny owner-action enroll-mutation");
        const revoke = make("button", "Revoke", "danger tiny owner-action enroll-mutation");
        rotate.type = revoke.type = "button";
        rotate.setAttribute("aria-label", `Rotate credential for ${a.agent_id}`);
        revoke.setAttribute("aria-label", `Revoke ${a.agent_id}`);
        rotate.addEventListener("click", () => confirm(`Rotate the credential of ${a.agent_id}`, [
          `Current generation ${a.credential_generation}. A new credential is generated in this browser and shown once.`,
          "The old credential stops working when the server commits the rotation. Install the new one in the Agent's token file right away."],
          a.agent_id, () => rotate_(a.agent_id)));
        revoke.addEventListener("click", () => confirm(`Revoke ${a.agent_id}`, [
          "The Agent's credential stops working immediately; it keeps its last verified policy but receives no new deployments.",
          "Revocation cannot be undone; a new enrollment needs a new Agent ID."],
          a.agent_id, () => revoke_(a.agent_id)));
        actions.append(rotate, revoke);
      }
      row.append(actions); body.append(row);
    });
    table.append(body);
    const wrap = make("div", undefined, "table-wrap"); wrap.append(table); root.append(wrap);
    lock();
  }

  function confirm(title, lines, expected, run) {
    if (busy || blocked || secret || pending) return;
    const root = $("enroll-confirm"), input = make("input"), ok = make("button", "Confirm", "danger"), cancel = make("button", "Cancel", "secondary");
    input.id = "enroll-confirm-input"; input.autocomplete = "off"; input.setAttribute("aria-label", `Type ${expected} to confirm`);
    ok.type = cancel.type = "button"; ok.disabled = true;
    input.addEventListener("input", () => { ok.disabled = input.value !== expected; });
    input.addEventListener("keydown", e => { if (e.key === "Escape") root.replaceChildren(); if (e.key === "Enter" && input.value === expected) { e.preventDefault(); ok.click(); } });
    cancel.addEventListener("click", () => root.replaceChildren());
    ok.addEventListener("click", () => { if (input.value !== expected) return; root.replaceChildren(); run(); });
    const box = make("div", undefined, "outcome-block"), label = make("label", "Type ", "field"), row = make("div", undefined, "inline");
    box.append(make("strong", title)); lines.forEach(l => box.append(make("p", l, "note")));
    label.append(make("code", expected), make("span", " to confirm"), input); row.append(ok, cancel);
    box.append(label, row); root.replaceChildren(box); input.focus();
  }

  // A finite, private installer for the Agent host (POSIX sh with GNU
  // coreutils/findutils). It refuses a linked, foreign or group/other
  // writable directory and a target that is a link or not a private regular
  // file of the user, stages into a fresh exclusive mktemp file (never a fixed
  // name), validates the 52-byte credential and renames it into place.
  // The credential is read from the terminal, never from argv or history.
  const installer = file => [
    "( f=" + file + "; d=$(dirname -- \"$f\")",
    "  [ -e \"$d\" ] || [ -L \"$d\" ] || mkdir -m 700 -- \"$d\" || exit 1",
    "  if [ -L \"$d\" ] || [ ! -d \"$d\" ] || [ ! -O \"$d\" ] || [ -n \"$(find \"$d\" -maxdepth 0 -perm /022)\" ]; then",
    "    echo \"Refused: $d must be your own directory, not a link and not writable by others.\" >&2; exit 1; fi",
    "  if [ -L \"$f\" ] || { [ -e \"$f\" ] && { [ ! -f \"$f\" ] || [ ! -O \"$f\" ] || [ -n \"$(find \"$f\" -maxdepth 0 -perm /077)\" ]; }; }; then",
    "    echo \"Refused: $f is a link or not a private regular file of yours. Inspect it yourself.\" >&2; exit 1; fi",
    "  t=$(mktemp -- \"$d/.agent-token.XXXXXXXXXX\") || exit 1",
    "  head -c 52 > \"$t\"",
    "  if [ \"$(wc -c < \"$t\")\" -ne 52 ] || ! grep -Eq '^sw_agent_[A-Za-z0-9_-]{43}$' \"$t\"; then",
    "    rm -f -- \"$t\"; echo \"Refused: this is not a 52-character Agent credential.\" >&2; exit 1; fi",
    "  mv -fT -- \"$t\" \"$f\" && echo \"Installed $f\" )"
  ].join("\n");

  // ------------------------------------------------------------ secret view
  async function showSecret(value) {
    secret = value;
    $("enroll-secret-agent").textContent = `${value.agent} · generation ${value.generation}`;
    $("enroll-secret-value").textContent = value.token;
    $("enroll-secret").classList.remove("hidden");
    lock();
    $("enroll-secret-copy").focus();
    const steps = $("enroll-secret-steps"), id = value.tenant, generation = epoch;
    steps.replaceChildren();
    try { issuer = issuer || await request("/admin/v1/managed-issuer", { cache: "no-store" }); } catch (_) { issuer = null; }
    if (stale(id, generation) || secret !== value) return;
    const key = issuer ? ` SOUP_MANAGED_AGENT_KEY_ID=${issuer.key_id} SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX=${issuer.public_key_hex}` : "";
    // [explanation, command] pairs; commands never contain the credential.
    const lines = value.kind === "rotate" ? [
      ["On the Agent host, as the Agent's user, with SOUP_MANAGED_AGENT_TOKEN_FILE set to the Agent's token file, run this, paste the credential and press Enter. It refuses unsafe existing files or directories and replaces the file only by an atomic rename:",
       installer('"${SOUP_MANAGED_AGENT_TOKEN_FILE:?set it to the Agent token file}"')],
      ["The running agentfw serve re-reads the file before its next policy fetch; no restart. An Agent configured with the SOUP_MANAGED_AGENT_TOKEN variable cannot reload: restart it with the token file configured.", null],
      ["Check this Agent's next applied acknowledgement in the Agent fleet. The old credential is refused from now on.", null]
    ] : [
      ["On the Agent host, as the Agent's user, run this, paste the credential and press Enter. It stores it in a private file without a newline and refuses unsafe existing files or directories:",
       installer('"$HOME/.agentfw/enrollment-token"')],
      ["Start the existing daemon. Add SOUP_MANAGED_AGENT_TLS_CA_FILE=/absolute/ca.pem for a private CA" + (issuer ? "." : " and the pinned issuer key (SOUP_MANAGED_AGENT_KEY_ID, SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX)."),
       `SOUP_MANAGED_AGENT_CONSOLE=https://CONSOLE_HOST/ SOUP_MANAGED_AGENT_TENANT=${value.tenant} SOUP_MANAGED_AGENT_ID=${value.agent} SOUP_MANAGED_AGENT_TOKEN_FILE="$HOME/.agentfw/enrollment-token"${key} agentfw serve`],
      ["Deploy an approved policy; the Agent fleet then shows its applied acknowledgement. Enrollment alone protects nothing.", null]
    ];
    lines.push(["If the credential is lost before it is stored, it cannot be shown again: rotate the credential to issue a new one.", null]);
    lines.forEach(([text, command]) => { const li = make("li", text); if (command) li.append(make("code", command)); steps.append(li); });
  }

  function clearSecret() {
    secret = null;
    $("enroll-secret-value").textContent = "";
    $("enroll-secret-agent").textContent = "";
    $("enroll-secret-steps").replaceChildren();
    $("enroll-secret").classList.add("hidden");
    lock();
  }

  // ------------------------------------------------------------- mutations
  // Authorization loss on any request (mutation, inventory read or
  // reconciliation) makes the panel read-only until the admin reconnects.
  function failure(e, label) {
    if (e.status === 401) { blocked = "session"; say(`${label}: the admin session expired or is no longer authorized. Reconnect; changes are disabled.`, "error"); lock(); return true; }
    if (e.status === 403) { blocked = "role"; say(`${label}: this admin role does not permit it. The panel is read-only.`, "error"); lock(); return true; }
    return false;
  }

  async function guarded(label, work) {
    if (busy || blocked || secret || pending || !owner() || !tenant) return;
    const id = tenant, generation = epoch;
    busy = true; lock(); say(`${label}: sending…`);
    try { await work(id, generation); }
    finally { if (!stale(id, generation)) { busy = false; lock(); } }
  }

  function enroll(agent) {
    if (!ID.test(agent)) { say("Use 1 to 128 letters, digits, '.', '_' or '-' for the Agent ID.", "error"); return; }
    if (agents.some(a => a.agent_id === agent)) { say(`${agent} is already enrolled in this tenant (duplicate identity). Nothing was sent.`, "error"); return; }
    return guarded(`Enroll ${agent}`, async (id, generation) => {
      try {
        const issued = await request(base(id), { method: "POST", body: JSON.stringify({ agent_id: agent }) });
        if (stale(id, generation)) return;
        if (issued?.tenant_id !== id || issued?.agent_id !== agent || !/^sw_agent_[A-Za-z0-9_-]{43}$/.test(issued?.token || ""))
          throw Object.assign(new Error("enrollment response identity mismatch"), { status: 0 });
        $("enroll-agent-id").value = "";
        await showSecret({ kind: "enroll", tenant: id, agent, generation: issued.credential_generation, token: issued.token });
        say(`${agent} enrolled. Store the credential now; it is shown only once.`, "ok");
        await refresh(false); fleet.reload();
      } catch (e) {
        if (stale(id, generation) || failure(e, `Enroll ${agent}`)) return;
        if (ambiguous(e) || e.status === 0) { pending = { kind: "enroll", tenant: id, agent }; await reconcile(); return; }
        await refresh(false);
        say(agents.some(a => a.agent_id === agent)
          ? `${agent} is already enrolled (duplicate identity). This request issued no credential.`
          : `Enrollment of ${agent} was refused: ${e.message}.`, "error");
      }
    });
  }

  function token() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return "sw_agent_" + btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function rotate_(agent) {
    return guarded(`Rotate ${agent}`, async (id, generation) => {
      let current;
      try { await load(); current = agents.find(a => a.agent_id === agent); }
      catch (e) { if (!stale(id, generation) && !failure(e, `Rotate ${agent}`)) say("Unable to read the current credential generation; nothing was sent.", "error"); return; }
      if (stale(id, generation)) return;
      if (!current || current.revoked_at_unix != null) { say(`${agent} is not an active enrollment; nothing was sent.`, "error"); return; }
      const operation = { kind: "rotate", tenant: id, agent, expected: current.credential_generation,
        operation_id: [...crypto.getRandomValues(new Uint8Array(16))].map(b => b.toString(16).padStart(2, "0")).join(""),
        token: token() };
      await send(operation, generation);
    });
  }

  // Sends exactly the recorded operation. A repeat is only ever explicit and
  // byte-identical, which the server acknowledges without another change.
  async function send(op, generation) {
    try {
      const receipt = await request(`${base(op.tenant)}/${encodeURIComponent(op.agent)}/credential-rotations`, { method: "POST",
        body: JSON.stringify({ expected_generation: op.expected, operation_id: op.operation_id, replacement_token: op.token }) });
      if (stale(op.tenant, generation)) return;
      if (receipt?.tenant_id !== op.tenant || receipt?.agent_id !== op.agent || receipt?.operation_id !== op.operation_id || receipt?.generation !== op.expected + 1)
        throw Object.assign(new Error("rotation receipt identity mismatch"), { status: 0 });
      pending = null;
      await showSecret({ kind: "rotate", tenant: op.tenant, agent: op.agent, generation: receipt.generation, token: op.token });
      say(`Credential of ${op.agent} rotated to generation ${receipt.generation}${receipt.already_applied ? " (this exact request was already committed)" : ""}. The old credential is refused from now on.`, "ok");
      await refresh(false);
    } catch (e) {
      // A body abort in this context can follow a committed mutation. Only a
      // stale context is cancellation; preserve the exact operation to reconcile.
      if (stale(op.tenant, generation) || failure(e, `Rotate ${op.agent}`)) return;
      if (ambiguous(e) || e.status === 0) { pending = op; await reconcile(); return; }
      pending = null;
      await refresh(false);
      say(`Rotation of ${op.agent} was refused (another rotation or a revocation changed the enrollment, or the request was invalid). The credential generated for it is discarded and is not valid.`, "error");
    }
  }

  function revoke_(agent) {
    return guarded(`Revoke ${agent}`, async (id, generation) => {
      try {
        await request(`${base(id)}/${encodeURIComponent(agent)}/revoke`, { method: "POST", body: "{}" });
        if (stale(id, generation)) return;
        await load();
        const row = agents.find(a => a.agent_id === agent);
        say(row?.revoked_at_unix != null ? `${agent} revoked. Its credential is refused; it keeps its last verified policy.` : `Revocation of ${agent} was accepted but the record does not show it yet. Refresh before acting again.`, row?.revoked_at_unix != null ? "ok" : "error");
        fleet.reload();
      } catch (e) {
        if (stale(id, generation) || failure(e, `Revoke ${agent}`)) return;
        if (ambiguous(e)) { pending = { kind: "revoke", tenant: id, agent }; await reconcile(); return; }
        await refresh(false);
        say(`Revocation of ${agent} was refused: ${e.message}.`, "error");
      }
    });
  }

  // Bounded, authoritative reconciliation: one inventory read per attempt,
  // never an automatic resend. Changes stay disabled while `pending` is set.
  async function reconcile() {
    const op = pending, generation = epoch, box = $("enroll-pending");
    if (!op || stale(op.tenant, generation)) return;
    busy = true; lock(); box.replaceChildren();
    const button = (text, cls, run) => { const b = make("button", text, cls + " enroll-reconcile"); b.type = "button"; b.addEventListener("click", run); box.append(b); };
    try {
      await load();
      if (stale(op.tenant, generation)) return;
      const row = agents.find(a => a.agent_id === op.agent);
      if (op.kind === "enroll") {
        pending = null;
        say(row ? `The enrollment of ${op.agent} is recorded, but its one-time credential did not reach this browser. The Console does not keep it: use "Rotate credential" to issue a new one, or revoke it.`
                : `The enrollment of ${op.agent} is not recorded. You may enroll it again.`, "error");
      } else if (op.kind === "revoke") {
        pending = null;
        say(row?.revoked_at_unix != null ? `Server state confirms ${op.agent} is revoked.` : `Server state shows ${op.agent} is not revoked. Revoke again only if you still intend to.`, "error");
      } else if (!row || row.revoked_at_unix != null) {
        pending = null;
        say(`${op.agent} is revoked or absent; the rotation cannot apply and its credential is discarded.`, "error");
      } else {
        const committed = row.credential_generation > op.expected;
        say(committed ? `A rotation of ${op.agent} is committed (generation ${row.credential_generation}). Confirm with the same request to learn whether it was this one; nothing else is sent.`
                      : `The rotation of ${op.agent} is not committed (generation ${row.credential_generation}). You may send the same request once more, or discard it.`, "error");
        button(committed ? "Confirm with the same request" : "Send the same request again", "", async () => {
          if (busy || pending !== op || stale(op.tenant, generation)) return;
          box.replaceChildren(); busy = true; lock();
          try { await send(op, generation); } finally { if (!stale(op.tenant, generation)) { busy = false; lock(); } }
        });
        button("Discard", "secondary", () => { if (pending !== op) return; pending = null; box.replaceChildren(); say("Pending rotation discarded; its credential was never shown and must not be installed.", "note"); lock(); });
      }
    } catch (e) {
      if (stale(op.tenant, generation)) return;
      if (failure(e, "Reconciling the uncertain request")) return;
      say("The outcome is unknown and the server state could not be read. Changes stay disabled until Check again succeeds.", "error");
      button("Check again", "secondary", reconcile);
    } finally {
      if (!stale(op.tenant, generation)) { busy = false; lock(); }
    }
  }

  $("enroll-form").addEventListener("submit", e => { e.preventDefault(); enroll($("enroll-agent-id").value.trim()); });
  $("enroll-refresh").addEventListener("click", () => { if (!busy) refresh(); });
  $("enroll-secret-copy").addEventListener("click", async () => {
    if (!secret) return;
    try { await navigator.clipboard.writeText(secret.token); say("Credential copied. Paste it into the Agent host's token file, then clear your clipboard.", "ok"); }
    catch (_) { say("Copy failed. Select the credential text and copy it manually.", "error"); }
  });
  $("enroll-secret-dismiss").addEventListener("click", () => { clearSecret(); say("Credential cleared from this page. It cannot be shown again.", "note"); });

  return {
    select(id) {
      controller?.abort(); controller = new AbortController(); epoch++;
      tenant = id; agents = []; busy = false; blocked = ""; pending = null;
      $("enroll-agent-id").value = "";
      clearSecret();
      $("enroll-confirm").replaceChildren(); $("enroll-pending").replaceChildren(); $("enroll-list").replaceChildren();
      if (id) refresh(); else say("Select a tenant to manage Agent enrollment.");
    },
    clear() { clearSecret(); }
  };
})();
