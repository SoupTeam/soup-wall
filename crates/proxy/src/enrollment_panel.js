// SPDX-License-Identifier: Apache-2.0
// Managed Agent enrollment and credential lifecycle over the existing
// /admin/v1/tenants/:t/agents APIs. Uses the page's in-memory authenticated
// request helper. Owner role and tenant checks stay on the server. An issued
// credential lives only in this closure and the transient secret view; it is
// never written to a URL, browser storage, the console log or an attribute.
const enrollment = (() => {
  const ID = /^[A-Za-z0-9_.-]{1,128}$/;
  let tenant = null, epoch = 0, controller = null, agents = [];
  let setup = null, setupRequest = null;
  let busy = false, blocked = "", pending = null, secret = null;

  const owner = () => currentAdmin?.role === "owner";
  const base = id => `/admin/v1/tenants/${encodeURIComponent(id)}/agents`;
  const agentAction = (id, agent, action) => agent === "." || agent === ".."
    ? `${base(id)}/${action}?${new URLSearchParams({agent_id: agent})}`
    : `${base(id)}/${encodeURIComponent(agent)}/${action}`;
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
    if (setup && agents.some(a => a.agent_id === setup.agent && a.revoked_at_unix != null)) closeSetup();
    render();
    return value;
  }

  async function readEnrollment(id, agent, generation) {
    try {
      const row = await request(`${base(id)}/enrollment?${new URLSearchParams({agent_id: agent})}`,
        {signal: controller.signal, cache: "no-store"});
      if (stale(id, generation)) return null;
      if (row?.tenant_id !== id || row?.agent_id !== agent || !Number.isSafeInteger(row.credential_generation))
        throw new Error("Enrollment identity mismatch");
      const index = agents.findIndex(a => a.agent_id === agent);
      if (index < 0) agents.push(row); else agents[index] = row;
      if (setup?.agent === agent && row.revoked_at_unix != null) closeSetup();
      render();
      return row;
    } catch (error) {
      if (error.status === 404) return null;
      throw error;
    }
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
      if (a.revoked_at_unix == null) {
        const connect = make("button", "Connection setup", "secondary tiny");
        connect.type = "button";
        connect.setAttribute("aria-label", `Connection setup for ${a.agent_id}`);
        connect.addEventListener("click", () => openSetup(a.agent_id));
        actions.append(connect);
      }
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
    "  p=$(dirname -- \"$d\")",
    "  case \"$f\" in /*) ;; *) echo 'Refused: use an absolute credential path.' >&2; exit 1 ;; esac",
    "  if [ \"$(realpath -e -- \"$p\")\" != \"$p\" ]; then echo 'Refused: use a canonical credential directory.' >&2; exit 1; fi",
    "  [ -e \"$d\" ] || [ -L \"$d\" ] || mkdir -m 700 -- \"$d\" || exit 1",
    "  if [ -L \"$d\" ] || [ ! -d \"$d\" ] || [ ! -O \"$d\" ] || [ -n \"$(find \"$d\" -maxdepth 0 -perm /022)\" ]; then",
    "    echo \"Refused: $d must be your own directory, not a link and not writable by others.\" >&2; exit 1; fi",
    "  if [ -L \"$f\" ] || { [ -e \"$f\" ] && { [ ! -f \"$f\" ] || [ ! -O \"$f\" ] || [ -n \"$(find \"$f\" -maxdepth 0 \\( -perm /077 -o -links +1 \\))\" ]; }; }; then",
    "    echo \"Refused: $f is a link or not a private regular file of yours. Inspect it yourself.\" >&2; exit 1; fi",
    "  t=$(mktemp -- \"$d/.agent-token.XXXXXXXXXX\") || exit 1",
    "  tty_state=",
    "  trap 'if [ -n \"$tty_state\" ]; then stty \"$tty_state\"; fi; rm -f -- \"$t\"' 0",
    "  trap 'exit 1' HUP INT TERM",
    "  if [ -t 0 ]; then",
    "    tty_state=$(stty -g) && stty -echo || exit 1",
    "    printf '%s' 'Paste the credential and press Enter: ' >&2",
    "    IFS= read -r credential || exit 1",
    "    stty \"$tty_state\" || exit 1; tty_state=; printf '\\n' >&2",
    "    printf '%s' \"$credential\" > \"$t\" || exit 1; unset credential",
    "  else head -c 53 > \"$t\" || exit 1; fi",
    "  if [ \"$(wc -c < \"$t\")\" -ne 52 ] || ! grep -Eq '^sw_agent_[A-Za-z0-9_-]{43}$' \"$t\"; then",
    "    echo \"Refused: this is not a 52-character Agent credential.\" >&2; exit 1; fi",
    "  mv -fT -- \"$t\" \"$f\" && echo \"Installed $f\" )"
  ].join("\n");

  const credentialPath = '"$HOME/.agentfw/enrollment-token"';
  const targetPath = '"${AGENT_CREDENTIAL_FILE:-$HOME/.agentfw/enrollment-token}"';
  const shellQuote = value => "'" + value.replace(/'/g, "'\\''") + "'";

  function step(root, text, command) {
    const li = make("li", text);
    if (command) li.append(make("code", command));
    root.append(li);
  }

  function renderCommands() {
    if (!setup) return;
    const root = $("enroll-connection-steps");
    const supplied = $("enroll-console-origin").value.trim();
    let consoleOrigin;
    try {
      const url = new URL(supplied);
      const supported = url.protocol === "https:" || (url.protocol === "http:" && ["127.0.0.1", "[::1]"].includes(url.hostname));
      if (supported && [url.origin, url.origin + "/"].includes(supplied)) consoleOrigin = url.origin + "/";
    } catch (_) { /* Incomplete origin while the operator is typing. */ }
    if (!consoleOrigin) {
      root.replaceChildren(make("li", "Enter a canonical HTTPS origin without a path, query or credentials."));
      return;
    }
    const args = `--console ${shellQuote(consoleOrigin)} --tenant ${shellQuote(tenant)} --agent ${shellQuote(setup.agent)} \\\n  --credential-file ${targetPath} --issuer-keyring "$HOME/.agentfw/trusted-issuers.json"` +
      ($("enroll-private-ca").checked ? ' \\\n  --ca-file "$HOME/.agentfw/console-ca.pem"' : "");
    root.replaceChildren();
    step(root, "Use the installed Linux Agent account and its private home. For an existing connection, read settings.credential_file with inspect. If that path differs from the default, set the shell variable AGENT_CREDENTIAL_FILE to the absolute path before using the installer or the commands below.", "agentfw managed-console inspect");
    step(root, "Obtain the issuer keyring through your trusted provisioning channel and independently verify the expected issuer key. The advertised key above is for comparison only. For a private TLS CA, verify it separately and place the PEM in the private file shown by the CA option. For a publicly trusted Console, use system TLS roots. Confirm that the origin shown is the address reachable from the Agent host.");
    step(root, "Keep the Agent stopped during configuration. For an installed user service, stop and unregister it before applying; register it again after setup. Clear legacy SOUP_MANAGED_AGENT_* settings from the Agent service environment before starting the explicit profile.", "agentfw lifecycle stop");
    step(root, "Review the exact Console, tenant, Agent, private credential, trust files and preview digest.", `agentfw managed-console preview ${args}`);
    step(root, "Repeat the reviewed options and replace PREVIEW_DIGEST with the confirmation printed by preview. A failed apply preserves the previous connection.", `agentfw managed-console apply ${args} --confirm PREVIEW_DIGEST`);
    step(root, "Start the Agent and inspect its configured and authenticated running identities. Verify checks connection and signatures; it does not apply or acknowledge a policy.", "agentfw lifecycle start\nagentfw managed-console inspect\nagentfw managed-console verify");
    step(root, "Review, approve and deploy a signed policy in the selected Agent’s policy panel. Refresh connection evidence after the running Agent fetches it and reports application. Match the revision, sequence and SHA-256 to the recorded application from inspect.");
    step(root, "To disconnect, stop the Agent, preview the change, and confirm with the new disconnect digest before starting again. This stops synchronization and retains the last verified policy and local data.", "agentfw lifecycle stop\nagentfw managed-console disconnect-preview\nagentfw managed-console disconnect --confirm DISCONNECT_DIGEST\nagentfw lifecycle start");
  }

  function closeSetup() {
    setupRequest?.abort();
    setup = null;
    $("enroll-console-origin").value = "";
    $("enroll-private-ca").checked = false;
    $("enroll-connection").classList.add("hidden");
    ["enroll-connection-agent", "enroll-connection-evidence", "enroll-connection-issuer", "enroll-connection-steps"].forEach(id => $(id).replaceChildren());
  }

  async function openSetup(agent, refresh = false) {
    const id = tenant, generation = epoch;
    if (!id || !ID.test(id) || !ID.test(agent)) return;
    if (!refresh) {
      const previous = setup?.agent === agent;
      if (!previous) {
        $("enroll-private-ca").checked = false;
        $("enroll-console-origin").value = location.protocol === "https:" ? location.origin + "/" : "";
      }
    }
    setup = { agent };
    const selected = setup;
    setupRequest?.abort(); setupRequest = new AbortController();
    const options = { signal: setupRequest.signal, cache: "no-store" };
    $("enroll-connection-agent").textContent = `${id} / ${agent}`;
    $("enroll-connection").classList.remove("hidden");
    const trust = $("enroll-connection-issuer"), evidence = $("enroll-connection-evidence");
    trust.textContent = "Reading advertised issuer…";
    evidence.textContent = "Reading policy evidence…";
    renderCommands();
    const [issuer, fleet] = await Promise.allSettled([
      request("/admin/v1/managed-issuer", options),
      request(`/admin/v1/tenants/${encodeURIComponent(id)}/agent-fleet-detail?${new URLSearchParams({agent_id: agent})}`, options),
    ]);
    if (stale(id, generation) || setup !== selected) return;
    if (issuer.status === "fulfilled" && ID.test(issuer.value?.key_id || "") && /^[0-9a-f]{64}$/.test(issuer.value?.public_key_hex || "")) {
      trust.textContent = `Console advertises ${issuer.value.key_id} · ${issuer.value.public_key_hex}. Verify both against the independently supplied issuer keyring.`;
    } else trust.textContent = "Advertised issuer unavailable. Use the independently verified keyring; setup cannot verify a signed policy without the matching issuer.";
    const observed = fleet.status === "fulfilled" ? fleet.value : null;
    if (observed?.contract_version !== "sw-agent-fleet/1" || observed.agent?.tenant_id !== id || observed.agent?.agent_id !== agent) {
      evidence.textContent = "Policy evidence unavailable. Refresh before making an application claim.";
      return;
    }
    const row = observed.agent;
    if (row.revoked_at_unix != null) {
      evidence.textContent = "This Agent enrollment is revoked. Its credential cannot connect.";
      return;
    }
    const latest = row.latest_issued, applied = row.last_reported_applied;
    const state = {issued: "Issued, awaiting fetch", delivered: "Bundle fetched, awaiting application acknowledgement", applied: "Application acknowledged by Agent", rejected: "Candidate rejected", cancelled: "Candidate cancelled"};
    const identity = record => `#${record.sequence} · ${record.revision} · SHA-256 ${record.policy_sha256}`;
    evidence.replaceChildren(
      make("p", latest ? `Latest deployment: ${identity(latest)} · ${state[latest.recorded_state] || "Unknown recorded state"}.` : "No signed deployment issued for this Agent yet."),
      make("p", applied ? `Last authenticated application acknowledgement: ${identity(applied)} · ${when(applied.reported_applied_at_unix)}.` : "No authenticated application acknowledgement yet."),
    );
  }

  // Only the one-time view receives the credential. Setup and its refresh are public metadata.
  function showSecret(value) {
    secret = value;
    $("enroll-secret-agent").textContent = `${value.agent} · generation ${value.generation}`;
    $("enroll-secret-value").textContent = value.token;
    $("enroll-secret").classList.remove("hidden");
    const steps = $("enroll-secret-steps");
    steps.replaceChildren();
    if (value.kind === "rotate") {
      step(steps, "On the Agent host, use inspect to confirm the configured credential path. The command uses the default from setup unless you set AGENT_CREDENTIAL_FILE to the selected path. Paste the credential at the hidden prompt; an atomic rename replaces the old file.", installer(targetPath));
      step(steps, "The running Agent reloads the selected file before its next fetch. Verify the current connection. If the profile is missing, continue with the setup below.");
    } else {
      step(steps, "On the installed Linux Agent host, as its user, run this and paste the credential at the hidden prompt. It stores the exact bytes in a private file.", installer(credentialPath));
    }
    step(steps, "If the credential was lost before installation, it cannot be shown again. Find the same enrollment and rotate it; do not create a second enrollment.");
    lock();
    $("enroll-secret-copy").focus();
    void openSetup(value.agent);
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
        showSecret({ kind: "enroll", tenant: id, agent, generation: issued.credential_generation, token: issued.token });
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
      try { current = await readEnrollment(id, agent, generation); }
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
      const receipt = await request(agentAction(op.tenant, op.agent, "credential-rotations"), { method: "POST",
        body: JSON.stringify({ expected_generation: op.expected, operation_id: op.operation_id, replacement_token: op.token }) });
      if (stale(op.tenant, generation)) return;
      if (receipt?.tenant_id !== op.tenant || receipt?.agent_id !== op.agent || receipt?.operation_id !== op.operation_id || receipt?.generation !== op.expected + 1)
        throw Object.assign(new Error("rotation receipt identity mismatch"), { status: 0 });
      pending = null;
      showSecret({ kind: "rotate", tenant: op.tenant, agent: op.agent, generation: receipt.generation, token: op.token });
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
        await request(agentAction(id, agent, "revoke"), { method: "POST", body: "{}" });
        if (stale(id, generation)) return;
        const row = await readEnrollment(id, agent, generation);
        if (stale(id, generation)) return;
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
      const row = await readEnrollment(op.tenant, op.agent, generation);
      if (stale(op.tenant, generation)) return;
      if (op.kind === "enroll") {
        pending = null;
        say(row ? `The enrollment of ${op.agent} is recorded, but its one-time credential did not reach this browser. The Console does not keep it: use "Rotate credential" to issue a new one, or revoke it.`
                : `The enrollment of ${op.agent} is not recorded. You may enroll it again using the same Agent ID.`, "error");
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

  $("enroll-console-origin").addEventListener("input", renderCommands);
  $("enroll-private-ca").addEventListener("change", renderCommands);
  $("enroll-connection-refresh").addEventListener("click", () => { if (setup) void openSetup(setup.agent, true); });
  $("enroll-connection-policy").addEventListener("click", () => { if (setup) void singlePolicy.open(tenant, setup.agent); });
  $("enroll-connection-close").addEventListener("click", closeSetup);
  $("enroll-form").addEventListener("submit", e => { e.preventDefault(); enroll($("enroll-agent-id").value.trim()); });
  $("enroll-refresh").addEventListener("click", () => { if (!busy) refresh(); });
  $("enroll-secret-copy").addEventListener("click", async () => {
    if (!secret) return;
    const copied = secret;
    try { await navigator.clipboard.writeText(copied.token); if (secret === copied) say("Credential copied. Paste it into the Agent host's token file, then clear your clipboard.", "ok"); }
    catch (_) { if (secret === copied) say("Copy failed. Select the credential text and copy it manually.", "error"); }
  });
  $("enroll-secret-dismiss").addEventListener("click", () => { clearSecret(); say("Credential cleared from this page. It cannot be shown again.", "note"); });

  return {
    select(id) {
      controller?.abort(); controller = new AbortController(); epoch++;
      tenant = id; agents = []; busy = false; blocked = ""; pending = null;
      $("enroll-agent-id").value = "";
      clearSecret(); closeSetup();
      $("enroll-confirm").replaceChildren(); $("enroll-pending").replaceChildren(); $("enroll-list").replaceChildren();
      if (id) refresh(); else say("Select a tenant to manage Agent enrollment.");
    },
    clear() { clearSecret(); closeSetup(); }
  };
})();
