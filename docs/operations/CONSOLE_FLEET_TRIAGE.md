# Console: fleet triage overview

The **Fleet triage** section at the top of each tenant's Agent fleet shows
which enrolled Agents have recorded delivery or credential problems, lets you
filter and sort them, and opens the existing per-Agent history or rollout
group for one of them. It is read-only.

Everything it shows is what the Console recorded. An acknowledgement and its
age are history: they are not current liveness or active protection, and an
Agent with no recorded problem is **not** reported as healthy.

## Recorded problems

| Problem | Recorded condition |
| --- | --- |
| Pending delivery | the latest deployment is `issued` or `delivered` (fetched) with no acknowledgement |
| Rejected | the latest deployment was reported `rejected` |
| Applied revision differs from latest issued | the last reported applied revision or policy digest is not the latest issued one |
| Credential revoked | the enrollment is revoked |
| Incomplete history | fewer deployment records are stored than the latest sequence (missing or expired history) |
| No acknowledgement recorded | deployments exist but none was ever reported applied |
| Old acknowledgement | the last reported applied time is older than the selected age (15 minutes to 7 days, default 1 day) |
| No delivery recorded | no deployment was ever issued to the Agent |

"Needs attention" is any of these. "No recorded problem" is the rest.

## Counts and denominators

Each count reads "N of T", where T is the number of enrolled Agents counted
in the same server snapshot as the page. The server counts at most 10,000
Agents per request, the first 10,000 by Agent ID, and pages are drawn from
that same set: a listed Agent is always one that was counted. A larger tenant
is shown as partial ("counts and list cover only the first 10,000 Agents by
ID; later Agents are neither counted nor listed"); its totals are not
full-fleet totals. The status line says how many matching Agents you have
seen so far ("Seen 25 of 38 matching"). A page that lists more Agents than
its own snapshot counts as matching is refused.

Each page is a separate read. If records change between pages (for example
an Agent acknowledges a deployment), an Agent can repeat or drop out, or more
Agents can be seen than the latest count; the status line says so, never uses
the count as a denominator for the extra Agents, and **Refresh triage**
starts a new snapshot.

## Filters, sort and paging

- **Recorded problem**: one problem, needs attention, no recorded problem or
  all Agents. The count buttons apply the same filter.
- **Old acknowledgement after**: the age threshold for "Old acknowledgement".
- **Sort**: Agent ID, or oldest acknowledgement first (Agents with no
  acknowledgement come first).
- **Agent ID prefix**: letters, digits, `.`, `_` and `-` only.
- 25 Agents per page; **Next page** and **First page**.

Filters and page state stay in the page's memory. They are never written to
the URL or browser storage, and switching tenant resets them.

## Opening an Agent

- **History** selects the Agent in the fleet list and builds its recorded
  history ([CONSOLE_AGENT_HISTORY.md](CONSOLE_AGENT_HISTORY.md)).
- **Rollout** opens the Agent's first rollout group (by ID) in the managed
  rollout panel; "+N group(s)" shows other memberships. Rollout changes keep
  their own Owner-only confirmations there.

## API and safety

The section reads `GET /admin/v1/tenants/:t/agent-triage` (contract
`sw-agent-fleet-triage/1`) with `problem`, `sort`, `ack_age_seconds`,
`prefix`, `limit` (1 to 100) and the keyset cursor `after` (plus `after_ack`
for the age sort). Unknown parameters or values are refused with 400. It uses
the same read authorization as the fleet inventory (Owner, Operator, Viewer)
and returns 404 for an unknown tenant. Counts and page come from one read
snapshot on SQLite and PostgreSQL. No credentials, policy bodies or signed
bundles are selected.

The browser uses a page only if every record names the selected tenant, has
a known shape and matches the requested filters; a reply that arrives after a
tenant change is ignored. 401, 403, 404, timeouts and errors clear the list.

## Verification

```sh
cargo test --locked -p llm-firewall --test fleet_triage
python3 -B -m unittest scripts/tests/test_console_fleet_triage_browser.py
cargo build --locked -p llm-firewall -p agentfw
python3 -B scripts/console-fleet-triage-acceptance.py --no-build --backend sqlite --output /tmp/triage
python3 -B scripts/console-fleet-triage-acceptance.py --no-build --backend postgres --output /tmp/triage
```

The PostgreSQL run needs local PostgreSQL server binaries including `psql`
(`--pg-bin DIR`) and an ordinary user. CI runs both in the Agent fleet
workflow. Evidence: [2026-11-02](evidence/CONSOLE_FLEET_TRIAGE_2026-11-02.md).
