# Private offline Agent audit explorer

The explorer turns one explicitly selected Agent audit JSONL file or a verified
[rotated-history export](AGENT_AUDIT_RETENTION.md#export-and-browse) into a single
local HTML report. It is for reviewing recorded decisions and their limits; it
does not change Agent policy, admission, approvals, the source log, or the host.
The generator and its file-permission claims are supported on Linux. Use a
native Linux filesystem for the output. Windows or WSL-mounted Windows output
permissions have not been accepted for this command.

## Generate a report

From the repository root on Linux, choose the **exact** audit file to inspect
and a new report name in an owner-owned private directory:

```sh
mkdir -m 700 "$HOME/agent-audit-review"
python3 scripts/agent-audit-report.py \
  --input "$HOME/.agentfw/audit.jsonl" \
  --output "$HOME/agent-audit-review/report.html"
```

If the output parent does not exist, the generator creates it with mode `0700`.
It requires the parent to be owned by the current user with no group/other
access and creates the report with mode `0600`. It refuses to overwrite an
existing report, symlinked path components, non-regular input, and unsupported
output filesystems. The source log is read only. The command does not launch a
browser or send the report anywhere. Open the resulting `report.html` locally
in a browser, for example through the browser's **Open File** action.

The report embeds only a strict projection of accepted audit fields. Session,
agent, parent, MCP server and native call identifiers become report-local
aliases. Unknown tool, rule and detector strings also become aliases. Prompts,
arguments, results, raw forensic bodies, egress hostnames, paths, credentials,
approval values, hashes and unknown fields are absent. Aliases are stable
within one report, not across reports. Retain the original audit under its
normal private handling; the report cannot reconstruct all source evidence.

The generator stops at 16 MiB of input, 64 KiB per line, 10,000 source
records, JSON depth 16, or 8 MiB of output. The page renders at most 100 rows
at once. A long line or later-record limit is reported as partial evidence;
malformed lines and unsupported event versions are counted and omitted. An
unsupported version is not interpreted using the current schema. A normal
end-of-file can still leave a call without its result; use the per-event
**Evidence still missing** list before drawing a conclusion.

For bounded retention, first run `--retained-dir ... --output export.jsonl` as
described in the retention guide, then use `--input export.jsonl` here. The
export is private raw evidence. Its metadata distinguishes planned pruning,
missing or corrupt segments, incomplete tails and selected ranges. Those
notices remain visible in the HTML; a selected report is not a complete
external execution history.

## Read the timeline

The summary counts and timeline cover the accepted records in the selected
file. Filter by verdict, event, tool, session alias, UTC date range, or a text
search over projected fields. Select **Details** for rule, detector severity,
structured taint origin, available latency, call alias, and missing evidence.
Use Tab/Shift+Tab to move through controls, Enter or Space on buttons, and the
Previous/Next buttons for pages. On a small screen the timeline scrolls
horizontally inside its labelled region.

Interpret the evidence stage precisely:

| Record | What it supports | What it does not establish |
| --- | --- | --- |
| Hook `pre_tool_use`, shadow | A policy verdict was computed | Enforcement or execution |
| Hook `pre_tool_use`, enforced | The hook returned its decision to the host | That the host executed an Allow call |
| Native `native_call` | Admission or refusal at the native gate | Execution merely because admission was Allow |
| Native `native_result` with `released: false` | The result was withheld from the MCP client | Reversal of any prior side effect |
| Native `native_result` with `released: true` | The result gate authorized release | Its eventual recipient or model consumption without further evidence |
| Hook `post_tool_use` | A host callback was observed | Complete knowledge of side effects |

Native call/result links appear only when matching source identifiers actually
exist and are unambiguous. A missing or inconsistent source link remains
unlinked. Hook decisions do not acquire invented native result links. The
report's **complete** source status means every selected line was parseable and
within the limits; it does not assert that the underlying audit captured every
real-world event.

## Reproduce the owned synthetic demo

This demo uses the existing `agentfw self-test` scripted MCP fixture and a
second isolated `agentfw serve` hook fixture. Both write genuine accepted Agent
audit records. It requires Linux, Python 3, a built Agent binary, and the
repository's local `rule_baseline.py`. It makes loopback requests only and uses
no live model or private dataset. Use a **new** directory on a native Linux
filesystem; the command retains its synthetic raw audit privately for local
verification:

```sh
cargo build --locked -p agentfw --bin agentfw
python3 scripts/sou75_owned_demo.py \
  --agent "$PWD/target/debug/agentfw" \
  --output-dir "$HOME/sou75-owned-demo"
```

The resulting `report.html` is the full owned run. `partial-report.html` comes
from one actual native admission line copied without its later result to test
missing-link presentation. `manifest.json` records aggregate source counts and
the SHA-256 of the combined audit. The demo deliberately inserts synthetic
secret, identity, path and HTML injection sentinels into real hook requests and
fails if a sentinel reaches the report or a script-end sequence remains live.
Its retained workspace, `owned-audit.jsonl`, `partial-audit.jsonl`, self-test
report and daemon logs are **private synthetic source material**, not files to
commit or share. Choose another new output directory for each run.

Run the focused checks with:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_agent_audit_report.py' -v
python3 scripts/check_docs.py
```

With Playwright and a Chromium executable installed locally, run the browser
check against the just-generated **real owned report**:

```sh
SOU75_REPORT_HTML="$HOME/sou75-owned-demo/report.html" \
PLAYWRIGHT_CHROMIUM_EXECUTABLE=/path/to/chromium \
node scripts/tests/test_agent_audit_explorer_browser.js
```

The check compares filters and details to source metadata, attempts the
injected text, checks page interaction at the declared record limit, and
verifies that opening the file makes no network requests. The saved evidence under
[`evidence/sou-75`](evidence/sou-75/README.md) contains only sanitized counts,
hashes, screenshots and a reproduction procedure.
