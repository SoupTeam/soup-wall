# SOU-80 offline support report checkpoint (2026-10-17)

This is a sanitized tool demonstration against public reports, **not** a
candidate acceptance decision. The selected target is accepted main
`38c981bddbedfd2b06b80fb4c9af474b9b897ad3`. The SOU-80 command was run
locally from its working tree based on that commit; the final PR commit is a
separate source identity and requires its own candidate evidence. No model,
provider, GitHub API, CI download or private dataset was used.

## Reproduction

From the repository root, use the [operator command](../ROADMAP_SUPPORT_REPORT.md#generate-one-local-report)
with that full source and `docs/operations/evidence` as input. Choose a new
private output name. The generated `report.json` and `index.html` stay in the
operator's private directory; they are not committed. The index declares
38 ROADMAP criteria, 10 scoped capabilities and five selected public reports.

| Capability report state | Count | Observation |
| --- | ---: | --- |
| Historical | 2 | Native create-file 26/26 and HTTPS GET 48/48 at their own earlier SHA values; no inheritance to target. |
| Unbound | 2 | Linux/macOS installed self-test JSON has 5/5 fixture scenarios but no exact clean source SHA. |
| Incomplete | 1 | Shared-session macOS component aggregate retains ten ignored workspace tests. |
| Missing | 4 | Original filesystem, Git, stderr and conditional macOS Intel self-test need retained matching reports. |
| Unsupported | 1 | Windows installed self-test is explicitly unsupported. |

All 38 criteria remain `open`; no phase is reported complete and no human
decision file was supplied. The two accepted original-server profile guides
are indexed with their scoped policy/upstream identity pins, while missing
exact-run reports are exposed. A self-declared `passed` value, component build,
historical SHA or guide cannot replace integrated candidate acceptance.

## Controls actually exercised

`python -B -m unittest discover -s scripts/tests -p test_roadmap_support.py -v`:
**12 passed, zero skipped** on Windows Python 3.12. It checks real sanitized
public data, a matching historical component source, absent and tampered
reports, wrong SHA/platform after rehashing, zero denominator, skipped positive,
inconsistent self-test scenarios, hardlink/oversize input, profile-pin drift, duplicate keys/IDs,
unsafe paths, fake approval in source JSON, stale operator decisions, a matching
generic candidate requiring separate review, and inert HTML with a sentinel
excluded from the report projection.

The same 12 tests also passed on Ubuntu/WSL Python 3.14, zero skipped. A
separate Linux invocation generated the report under native `/tmp`; `stat`
confirmed mode `0700` for the directory and `0600` for both output files. The
selected input checkout was the Windows-mounted repository with LF-pinned
public evidence; the private Linux output was outside that mount.

`test_roadmap_support_browser.js` opened the generated real report in local
Chrome via Playwright: **passed** phase/platform/status filtering, evidence
drilldown, criterion paging, small-screen layout, CSP, malicious title inertness
and zero network requests/page errors. It used the same selected public
evidence, then a controlled malicious title copy with the correct CSP hash.
A synthetic maximum-size view (64 criteria, 128 capabilities, 128 evidence
descriptors) initialized in 247 ms and filtered in 266 ms on local Chrome;
only eight criteria rendered per page. The screenshots
show the sanitized real report:

- [Desktop: Phase 1 historical filter and report detail](sou80-support-desktop.png)
- [Mobile: Foundation and filter controls](sou80-support-mobile.png)

The screenshots contain only the selected public source SHA, scoped profile
names and reasons; no private payloads, identities, raw prompts or report
arguments. The browser test is optional for environments without Playwright/
Chromium; the Python integrity tests do not depend on it.

## Exact changed-input digests

The source checkout base is the selected main commit above. These SHA-256
values identify the bytes exercised before the final single PR commit; they
do not claim the commit SHA is the same as the tested base. The selected
ROADMAP/reports and new tool/index files are pinned to LF in `.gitattributes`;
their staged Git blob bytes equal the bytes used by the local run on Windows.

| File | SHA-256 |
| --- | --- |
| `scripts/roadmap_support.py` | `b7acc8d4a83d05ef36ff3af97c2f76204120be8fc22d9319d1551b43bb8cb230` |
| `scripts/roadmap_support_assets/report.js` | `62bf64d837095c5682a8d09c34459740ff99b51af5e0c979f14689c14bf24e4b` |
| `scripts/roadmap_support_assets/report.css` | `5d53d5243f0680a9b2f5319b9c361e05a8ce55e448652c4ebfe30420d57eddb9` |
| `scripts/tests/test_roadmap_support.py` | `c53c4afd33942d3b3f12ed7b9b38358a606967354a864b045e89745fb0f97ae2` |
| `scripts/tests/test_roadmap_support_browser.js` | `51b7ad754b40d1a62920692d8d2266df4068a8a08332422fa551d9039e1fcf04` |
| `docs/operations/roadmap-support-index.json` | `3c6a96d39133b3c3e740ef9b73ff0ce3b7d12c19439af7c544296e11de0b190e` |

Rust runtime, doctor, Console, onboarding, live benchmark and release code were
untouched. This checkpoint verifies the standalone report tool, not a
security attestation or publication authorization.
