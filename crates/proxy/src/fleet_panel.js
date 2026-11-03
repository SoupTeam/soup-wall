// SPDX-License-Identifier: Apache-2.0
// Receives the existing in-memory authenticated request helper; never persists tokens.
const fleet = (() => {
  let tenant = null, epoch = 0, listRequest = 0, detailRequest = 0;
  let listController = null, detailController = null, next = null, historyNext = null, selected = null;
  const status = text => { $("fleet-status").textContent = text; };
  const when = value => value == null ? "Not recorded" : new Date(value * 1000).toLocaleString();
  const age = value => {
    if (value == null) return "No acknowledgement recorded";
    const minutes = Math.max(0, Math.floor((Date.now()/1000-value)/60));
    return `${minutes} min old${minutes >= 5 ? " — historical evidence (5+ min); refresh does not renew it" : " — historical evidence"}`;
  };
  const ageNode = (tag, value, className) => {
    const node = make(tag, age(value), className);
    if (value != null) node.dataset.fleetAppliedAt = String(value);
    return node;
  };
  // Recompute elapsed time locally; refreshing the clock never renews an ACK.
  setInterval(() => {
    document.querySelectorAll("#fleet-panel [data-fleet-applied-at]").forEach(node => {
      node.textContent = age(Number(node.dataset.fleetAppliedAt));
    });
  }, 30_000);
  const identity = d => d ? `#${d.sequence} · ${d.revision} · ${d.recorded_state}` : "No deployment history";
  const url = () => `/admin/v1/tenants/${encodeURIComponent(tenant)}/agent-fleet`;
  const valid = (data, id) => data?.contract_version === "sw-agent-fleet/1" && id === tenant;
  const clearDetail = () => {
    detailRequest++; detailController?.abort(); selected = null; historyNext = null; agentHistory.clear();
    $("fleet-agent-detail").replaceChildren(); $("fleet-history-next").disabled = true;
  };
  const renderList = values => {
    const root = $("fleet-list"); root.replaceChildren();
    if (!values.length) { root.append(make("p", "No Agents match this page and filters.", "empty")); return; }
    const table = make("table"), head = make("tr"), body = make("tbody");
    ["Agent", "Enrollment", "Latest issued", "Last reported applied", "Evidence age"].forEach(v => head.append(make("th",v)));
    const thead=make("thead"); thead.append(head); table.append(thead);
    values.forEach(a => {
      const row=make("tr"), cell=make("td"), button=make("button",a.agent_id,"secondary tiny");
      button.type="button"; button.addEventListener("click",()=>loadAgent(a.agent_id)); cell.append(button);
      row.append(cell,make("td",a.revoked_at_unix == null ? "Enrolled" : "Revoked"),make("td",identity(a.latest_issued)),make("td",a.last_reported_applied ? identity(a.last_reported_applied) : "No applied acknowledgement"),ageNode("td",a.last_reported_applied?.reported_applied_at_unix));
      body.append(row);
    }); table.append(body); root.append(table);
  };
  async function loadList(after="") {
    if (!tenant) return;
    listController?.abort(); listController=new AbortController();
    const id=tenant, generation=epoch, requestId=++listRequest;
    next=null; clearDetail(); $("fleet-list").replaceChildren(); $("fleet-next").disabled=true;
    status("Loading enrolled Agents…");
    const q=new URLSearchParams({limit:"25",after,prefix:$("fleet-prefix").value.trim(),enrollment:$("fleet-enrollment").value,delivery:$("fleet-delivery").value});
    try {
      const data=await request(url()+"?"+q,{signal:listController.signal,cache:"no-store"});
      if (generation!==epoch || requestId!==listRequest || id!==tenant) return;
      if (!valid(data,data.tenant_id) || !Array.isArray(data.agents) || data.agents.some(a=>a.tenant_id!==id)) throw new Error("Fleet response identity mismatch");
      renderList(data.agents); next=data.next_after; $("fleet-next").disabled=!next;
      status(`Recorded state read ${when(data.observed_at_unix)}. Page contains ${data.agents.length} Agents. Runtime coverage and liveness remain unknown.`);
    } catch(e) {
      if (generation!==epoch || requestId!==listRequest || id!==tenant || e.name==="AbortError") return;
      status("Unable to load fleet records. Refresh to retry.");
    }
  }
  async function loadAgent(agent, before=null) {
    detailController?.abort(); detailController=new AbortController();
    const id=tenant, generation=epoch, requestId=++detailRequest;
    selected=agent; historyNext=null; $("fleet-history-next").disabled=true; if(before===null)agentHistory.select(id,agent);
    const root=$("fleet-agent-detail"); root.replaceChildren(make("p","Loading Agent history…","empty"));
    try {
      const q=new URLSearchParams({limit:"25"}); if(before!==null)q.set("before_sequence",String(before));
      const data=await request(url()+"/"+encodeURIComponent(agent)+"?"+q,{signal:detailController.signal,cache:"no-store"});
      if(generation!==epoch || requestId!==detailRequest || id!==tenant || selected!==agent)return;
      if(!valid(data,data.agent?.tenant_id) || data.agent.agent_id!==agent || !Array.isArray(data.deployments))throw new Error("Agent response identity mismatch");
      const a=data.agent; root.replaceChildren(make("h3",`Agent ${agent}`));
      root.append(make("p",`Enrolled: ${when(a.enrolled_at_unix)} · Revoked: ${when(a.revoked_at_unix)}`));
      const summaries=make("div",undefined,"grid-two");
      [["Latest issued",a.latest_issued],["Historical last reported applied",a.last_reported_applied]].forEach(([label,d])=>{
        const card=make("div",undefined,"metric");card.append(make("h3",label),make("p",d ? identity(d) : label === "Latest issued" ? "No deployment history" : "No applied acknowledgement"),make("code",d?.policy_sha256||"Digest unavailable"));
        if(d)card.append(make("p",`Issued: ${when(d.issued_at_unix)} · Applied report: ${when(d.reported_applied_at_unix)}`));
        summaries.append(card);
      });root.append(summaries);
      root.append(ageNode("p",a.last_reported_applied?.reported_applied_at_unix,"note"));
      root.append(make("p","Current liveness: unknown · Active protection: unknown · Registry identity: unknown. An acknowledgement records a past report, not a heartbeat.","note"));
      if(a.latest_issued && ["issued","delivered"].includes(a.latest_issued.recorded_state))root.append(make("p","Latest deployment is pending: no matching applied acknowledgement recorded.","outcome-other"));
      if(a.latest_issued?.recorded_state==="rejected")root.append(make("p","Latest deployment was rejected. Any older applied identity remains historical.","outcome-block"));
      if(!data.deployments.length)root.append(make("p","No deployment history on this page.","empty"));
      else {
        const wrap=make("div",undefined,"table-wrap"),table=make("table"),thead=make("thead"),hr=make("tr");
        ["Sequence / revision","Digest","Recorded state","Issued","Reported applied"].forEach(x=>hr.append(make("th",x)));thead.append(hr);table.append(thead);
        const body=make("tbody");data.deployments.forEach(d=>{const row=make("tr");row.append(make("td",`#${d.sequence} · ${d.revision}`),make("td",d.policy_sha256),make("td",d.recorded_state),make("td",when(d.issued_at_unix)),make("td",when(d.reported_applied_at_unix)));body.append(row);});table.append(body);wrap.append(table);root.append(wrap);
      }
      root.append(make("p","Delivery and rejection timestamps are not recorded by the existing store. Pages are separate snapshots; refresh starts from the newest records.","note"));
      historyNext=data.next_before_sequence;$("fleet-history-next").disabled=historyNext==null;
    }catch(e){if(generation===epoch && requestId===detailRequest && id===tenant && e.name!=="AbortError")root.replaceChildren(make("p","Unable to load Agent history. Select the Agent again to retry.","outcome-block"));}
  }
  $("fleet-filter").addEventListener("submit",e=>{e.preventDefault();loadList();});
  $("fleet-refresh").addEventListener("click",()=>loadList());
  $("fleet-next").addEventListener("click",()=>{if(next)loadList(next);});
  $("fleet-first").addEventListener("click",()=>loadList());
  $("fleet-history-next").addEventListener("click",()=>{if(selected && historyNext!=null)loadAgent(selected,historyNext);});
  return { reload() { if (tenant) loadList(); }, select(id) {
    epoch++; tenant=id; listRequest++; listController?.abort(); clearDetail();
    next=null; $("fleet-list").replaceChildren(); $("fleet-next").disabled=true;
    $("fleet-prefix").value="";$("fleet-enrollment").value="all";$("fleet-delivery").value="all";
    if(id)loadList();else status("Select a tenant to view enrolled Agents.");
  }};
})();
