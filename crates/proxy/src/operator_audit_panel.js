// SPDX-License-Identifier: Apache-2.0
const operatorAudit = (() => {
  let tenant = null, selected = null, requestId = 0, controller = null;

  const status = text => { $("operator-audit-status").textContent = text; };
  const rows = $("operator-audit-rows");
  const next = $("operator-audit-next");
  const download = $("operator-audit-download");

  function render(page) {
    rows.replaceChildren();
    for (const event of page.events) {
      const row = make("tr");
      const actor = event.actor_id ? `${event.actor_kind} · ${event.actor_id}` : "Unavailable";
      const source = [event.source_ref, event.source_sequence && `#${event.source_sequence}`, event.source_sha256].filter(Boolean).join(" · ");
      row.append(
        make("td", event.event_id),
        make("td", time(event.received_at_unix)),
        make("td", actor),
        make("td", event.operation),
        make("td", `${event.target_kind} · ${event.target_id}`),
        make("td", event.outcome),
        make("td", source || "—"),
      );
      rows.append(row);
    }
    status(page.events.length ? `Read ${page.events.length} events at ${time(page.observed_at_unix)}.` : "No operator events on this page.");
    next.disabled = !page.next_before;
    download.disabled = page.events.length === 0;
  }

  async function load(before) {
    if (!tenant) return;
    controller?.abort();
    controller = new AbortController();
    const id = tenant, stamp = ++requestId;
    selected = null;
    rows.replaceChildren();
    next.disabled = download.disabled = true;
    status("Loading operator audit…");
    const query = new URLSearchParams({limit: "50"});
    if (before) query.set("before", before);
    try {
      const page = await request(`/admin/v1/tenants/${encodeURIComponent(id)}/operator-audit?${query}`,
        {signal: controller.signal, cache: "no-store"});
      if (stamp !== requestId || tenant !== id) return;
      if (page?.contract_version !== "sw-operator-audit/1" || page.tenant_id !== id ||
          !Array.isArray(page.events) || page.events.length > 50 ||
          page.events.some(event => event.tenant_id !== id) ||
          (page.next_before != null && !page.next_before.startsWith(id + "~"))) {
        throw new Error("Operator audit scope mismatch");
      }
      selected = page;
      render(page);
    } catch (error) {
      if (stamp === requestId && tenant === id && error.name !== "AbortError")
        status("Operator audit unavailable. Reload the latest page to retry.");
    }
  }

  $("operator-audit-load").addEventListener("click", () => load());
  next.addEventListener("click", () => { if (selected?.next_before) load(selected.next_before); });
  download.addEventListener("click", () => {
    if (!selected || selected.tenant_id !== tenant || !selected.events.length) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(selected, null, 2) + "\n"], {type: "application/json"}));
    const anchor = make("a");
    anchor.href = url;
    anchor.download = "operator-audit.json";
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  });

  return {select(id) {
    tenant = id;
    requestId++;
    controller?.abort();
    selected = null;
    rows.replaceChildren();
    next.disabled = download.disabled = true;
    status("Load the latest page to review recorded operator actions.");
  }};
})();
