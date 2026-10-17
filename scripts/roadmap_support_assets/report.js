"use strict";

const phase = document.getElementById("phase");
const platform = document.getElementById("platform");
const status = document.getElementById("status");
const cards = document.getElementById("cards");
const byId = new Map(REPORT.capabilities.map(capability => [capability.id, capability]));
const PAGE_SIZE = 8;
let pageNumber = 0;

function element(tag, className, value) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (value !== undefined) node.textContent = String(value);
  return node;
}

function option(select, value, label) {
  const node = element("option", "", label);
  node.value = value;
  select.append(node);
}

option(phase, "all", "All phases");
for (const name of ["Foundation", ...Array.from({length: 7}, (_, i) => `Phase ${i + 1}`)]) {
  option(phase, name, name);
}
option(platform, "all", "All platforms");
for (const name of ["linux", "macos", "windows"]) option(platform, name, name);
option(status, "all", "All statuses");
for (const name of ["unsupported", "missing", "invalid", "incomplete", "mismatch", "unbound",
                    "historical", "component", "pending-review"]) option(status, name, name);

document.getElementById("intro").textContent =
  `Selected source ${REPORT.target_source}. ${REPORT.notice}`;

function fact(dl, label, value) {
  dl.append(element("dt", "", label), element("dd", "", value ?? "not bound"));
}

function evidenceCard(item) {
  const details = element("details", "evidence");
  const heading = element("summary", "", `${item.id} · ${item.status}`);
  details.append(heading, element("p", "reason", item.reason));
  const dl = element("dl", "facts");
  fact(dl, "Report", item.path);
  fact(dl, "Format", item.format);
  fact(dl, "Evidence kind", item.kind);
  fact(dl, "Indexed SHA-256", item.expected_sha256);
  if (item.observed) {
    fact(dl, "Observed source", item.observed.source);
    fact(dl, "Platform / architecture", `${item.observed.platform} / ${item.observed.architecture}`);
    fact(dl, "Execution class", item.observed.execution);
    fact(dl, "Checks", `${item.observed.counts.passed} passed · ${item.observed.counts.failed} failed · ` +
      `${item.observed.counts.skipped} skipped · ${item.observed.counts.expected} required`);
    for (const key of ["implementation", "policy", "registry", "runtime", "server"]) {
      fact(dl, `${key} SHA-256`, item.observed.identity[key]);
    }
  }
  details.append(dl);
  return details;
}

function capabilityCard(cap) {
  const node = element("article", "capability");
  const top = element("div", "cap-top");
  top.append(element("h4", "", cap.title), element("span", `badge ${cap.status}`, cap.status));
  node.append(top);
  node.append(element("p", "scope", `${cap.platform} / ${cap.architecture} · ${cap.host} · ${cap.transport}`));
  node.append(element("p", "reason", cap.blocker));
  const details = element("details", "cap-details");
  details.append(element("summary", "", "Profile and evidence"));
  const dl = element("dl", "facts");
  fact(dl, "Server", cap.server);
  fact(dl, "Tool profile", cap.profile);
  fact(dl, "Declared support", cap.support);
  fact(dl, "Fail mode", cap.fail_mode);
  fact(dl, "Limit", cap.limits);
  details.append(dl);
  if (cap.evidence.length) {
    for (const item of cap.evidence) details.append(evidenceCard(item));
  } else {
    details.append(element("p", "reason", "No indexed report. A guide or passing component build does not fill this gap."));
  }
  node.append(details);
  return node;
}

function render() {
  const chosenPhase = phase.value;
  const chosenPlatform = platform.value;
  const chosenStatus = status.value;
  const matching = REPORT.criteria.filter(criterion => {
    if (chosenPhase !== "all" && criterion.phase !== chosenPhase) return false;
    const relevant = criterion.capabilities.map(id => byId.get(id)).filter(Boolean);
    return (chosenPlatform === "all" && chosenStatus === "all") || relevant.some(cap =>
      (chosenPlatform === "all" || cap.platform === chosenPlatform) &&
      (chosenStatus === "all" || cap.status === chosenStatus));
  });
  const pages = Math.max(1, Math.ceil(matching.length / PAGE_SIZE));
  pageNumber = Math.min(pageNumber, pages - 1);
  const fragment = document.createDocumentFragment();
  for (const criterion of matching.slice(pageNumber * PAGE_SIZE, (pageNumber + 1) * PAGE_SIZE)) {
    const relevant = criterion.capabilities.map(id => byId.get(id)).filter(cap => cap &&
      (chosenPlatform === "all" || cap.platform === chosenPlatform) &&
      (chosenStatus === "all" || cap.status === chosenStatus));
    const section = element("section", "criterion");
    const eyebrow = element("p", "criterion-id", `${criterion.phase} · ${criterion.id} · ${criterion.status}`);
    section.append(eyebrow, element("h2", "", criterion.title));
    if (criterion.review_records.length) {
      section.append(element("p", "review", "Operator-supplied review record; authenticity is not independently verified."));
      for (const record of criterion.review_records) {
        section.append(element("p", "reason", `${record.decision_id}: ${record.decision} · ${record.evidence_id}`));
      }
    }
    if (!relevant.length) section.append(element("p", "reason", criterion.blockers[0]));
    for (const cap of relevant) section.append(capabilityCard(cap));
    fragment.append(section);
  }
  cards.replaceChildren(fragment);
  document.getElementById("summary").textContent =
    `${matching.length} matching criteria · ${REPORT.capabilities.length} indexed capabilities · ` +
    "no automatic phase approval";
  document.getElementById("page-label").textContent = `Page ${pageNumber + 1} of ${pages}`;
  document.getElementById("prev").disabled = pageNumber === 0;
  document.getElementById("next").disabled = pageNumber + 1 === pages;
}

for (const control of [phase, platform, status]) control.addEventListener("change", () => {
  pageNumber = 0;
  render();
});
document.getElementById("prev").addEventListener("click", () => { pageNumber -= 1; render(); });
document.getElementById("next").addEventListener("click", () => { pageNumber += 1; render(); });
render();
