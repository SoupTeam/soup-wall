# SOU-75 owned offline audit evidence

This record covers an owned, synthetic Agent run. The source JSONL and generated
HTML remain in a private Linux directory and are not committed. The attached
PNG screenshots are views of the report generated from that run, not drawn
events or a static prototype.

## Reproduce

Follow [the operator guide](../../AGENT_AUDIT_EXPLORER.md#reproduce-the-owned-synthetic-demo)
from a Linux checkout. The demo command runs the actual `agentfw self-test`
native MCP fixture, starts an isolated shadow Agent daemon, sends authenticated
hook requests, combines those Agent-written JSONL lines, and invokes the report
generator. The script verifies required source witnesses, sentinel omission,
missing-result disclosure, and private output modes. It leaves a private
`manifest.json` with aggregate counts and source SHA-256.

The run used only the bundled fixture server and rule-baseline classifier. The
synthetic hook requests include an unknown event with opt-in raw capture, a
script-end string in a tool name, a private-path marker, a secret marker and
identity markers. A genuine unsupported-identity hook decision tests identity
redaction. They did not invoke an external service or execute the Bash command
named in the hook request. The native self-test uses its own loopback receiver;
the shadow fixture communicates only with an owned loopback daemon.

## Exact-source run

The final run completed on October 17, 2026 under WSL Ubuntu, using Python
3.14.4 and an `agentfw` debug binary built from accepted main
`afa00125264b227cdc3e249c1cd010a9c59d65a3`. The script ran from the
Windows checkout while all generated files stayed on the native Linux `/tmp`
filesystem. The final command shape was:

```sh
python3 scripts/sou75_owned_demo.py \
  --agent "$AGENTFW_BIN" \
  --output-dir /tmp/sou75-owned-demo-20261017-final
```

`$AGENTFW_BIN` was the built Linux binary. The directory was newly created by
the script with mode `0700`; the raw audit and both HTML reports were verified
as mode `0600`. The source has 14 real Agent-written records: 9 from the native
MCP self-test and 5 from the isolated hook fixture. Native audit metadata has
three allowed admissions, one denied admission and one withheld result. Hook
metadata has two shadow Deny decisions. These are source counts, not invented
UI events.

| Private artifact | SHA-256 for this one run |
| --- | --- |
| Combined Agent-written audit JSONL | `e9076966fd14c167ce85b94aedee531d6b5563373900efbfa962c50e32d8af1c` |
| Full generated HTML report | `da884993ed8105a2c852c374d310f0a83356955c4a78ba05c1e640cfec126b4c` |
| Intentional one-line excerpt JSONL | `64368b2e8a0c96924e101abaf68614c3e97bc6ac4e22e12b2f4d9a88b225f3a4` |
| Excerpt generated HTML report | `a5f77b2f0e4aa61182e1600d4b01d9112149023f48dc6a6d60b348e040c6b7d0` |
| `overview.png` | `70d649a01fb7a3151198750483ae621a128470cb37b52be5689b1cbcd9d90d45` |
| `filtered-detail.png` | `9c8a92aae1c196a02cab446a9dbc7f483c13ffb1eae275fbaea2c2c31bfc6e3d` |

Those hashes bind the recorded evidence to this specific run; timestamps and
owned workspace identities make new run hashes differ. The script succeeded,
the report generator accepted all 14 full-run records, and its checks found
none of the six synthetic sentinel strings or executable script-end sequence
in the generated HTML. The raw JSONL and HTML are intentionally excluded from
the repository. [overview.png](overview.png) and
[filtered-detail.png](filtered-detail.png) are Chrome browser captures from
this exact generated report. The latter selects the one `Ask` `native_result`
and opens its detail: `Released: no`, injection detector severities, the policy
rule, a call alias and the reason that prior side effects may remain. No raw
identity, path or secret appears in either capture.

The browser check was run against this same `report.html` and passed: all 14
records loaded; the three allowed native admissions and one withheld result
matched the source audit metadata; the shadow Deny, filters and detail view
worked; injected script text remained inert; and opening the report produced
zero network requests or page errors. Its 10,000-record synthetic stress case
initialized in 623 ms and filtered in 154 ms on this workstation. Those times
are one local observation, not a general performance guarantee. Run the
portable command in the [operator guide](../../AGENT_AUDIT_EXPLORER.md#reproduce-the-owned-synthetic-demo)
to repeat the checks with a new owned report.

The intentionally partial report is generated from one actual allowed
`native_call` record with its later `native_result` absent from the selected
excerpt. It should show **No linked result record in this report** even though
that one-line excerpt is syntactically complete. This tests honest missing
evidence without claiming the underlying full Agent run was truncated.
