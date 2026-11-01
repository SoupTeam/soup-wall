# Console: recorded Agent history and incident snapshot

The Console admin page (`/admin`) shows a **Recorded Agent history** panel
under each tenant's Agent fleet. Select an Agent in the fleet list and the
panel builds a chronological view of what this Console actually recorded for
it, flags unresolved and contradictory outcomes, and can export a bounded,
non-secret incident snapshot.

It reads only the existing fleet detail API
(`GET /admin/v1/tenants/:t/agent-fleet/:a`, contract `sw-agent-fleet/1`) with
its keyset cursor (`before_sequence`). It uses the same read authorization as
the fleet list (Owner, Operator and Viewer), adds no server route and sends no
change: building, previewing or downloading never rotates a credential or
changes rollout state.

The panel shows recorded Console evidence. It is **not** runtime attestation:
current protection and liveness are always shown as unknown.

## What the timeline contains

| Event | Source record | Time |
| --- | --- | --- |
| Enrolled | enrollment record | enrollment time |
| Issued | deployment record (sequence, revision, policy digest, activate or rollback) | issue time |
| Fetched | deployment state `delivered` | not recorded |
| Applied | deployment state `applied` (a past Agent report) | reported time |
| Rejected | deployment state `rejected` | not recorded |
| Pending | the latest deployment, still `issued` or `delivered` | none |
| Superseded | an older deployment that never got an acknowledgement | none |
| Revoked | enrollment record | revocation time |

Events are ordered by recorded time. An event without a recorded time stays
next to its own deployment's issue time; it is never placed at "now".
Credential rotations have no dated record in the Console, so the timeline
cannot show them and says so.

The summary keeps three things apart: the **latest issued** deployment, the
**historical last reported applied** deployment (both link to their timeline
entries), and the unknown current protection. Pending and superseded
deployments are listed as unresolved outcomes.

## Completeness

The history is one of:

- **All deployment records loaded**: sequences 1 to the latest issued sequence
  are all present, with no contradiction. This is still not a health signal.
- **Incomplete history**: something is missing. The reasons are listed, for
  example older records not loaded yet, a gap between pages, history the
  server no longer returns, dropped malformed records, a failed or timed-out
  page, or a bound reached.
- **Contradictory records**: two reads disagree about the same deployment, a
  summary does not match its record, or times are impossible (applied before
  issued, applied after the next deployment was issued, issued before
  enrollment or after revocation).

Deployment sequences are contiguous per Agent, so the latest issued sequence is
the denominator: "Loaded 50 of 56 deployment records in 1 page(s)". Missing
ranges are computed from the loaded records only, so their cost does not grow
with the sequence number. Sequences must be exact integers up to 2^53 - 1; a
larger value is treated as malformed, never rounded.

## Bounds and paging

One history build reads at most 8 pages of 50 records, 256 KiB per page and
1 MiB in total, with a 15 second timeout per page and 60 seconds per build.
The first page loads when you select the Agent; **Load older records** reads
the next page. Reaching a bound stops paging and marks the history partial.

Every response must name the selected tenant and Agent and the fleet contract.
A response for another tenant or Agent is discarded and stops paging. Replies
that arrive after you switch Agent or tenant are ignored, so pages from two
scopes are never combined. Repeated records are removed by sequence; a repeat
with different content is a contradiction. A 401 or 403 clears the panel; a
404 means the tenant or Agent no longer exists.

## Incident snapshot

**Preview incident snapshot** shows the JSON in the page; **Download snapshot
JSON** saves the same JSON as
`agent-history-<tenant>-<agent>-<time>[-partial].json`. The format is
`sw-agent-incident-snapshot/1`:

- `scope`: the tenant and Agent; `source`: the API and contract read.
- `partial` and `completeness`: status, reasons and contradictions.
- `coverage`: expected and loaded deployments, loaded and missing sequence
  ranges, every page read (cursor, read time, record counts) and the bounds.
- `time_bounds`: earliest and latest recorded event times and page read times.
- `enrollment`, `summary` (latest issued, historical last applied, protection
  and liveness `unknown`), `unresolved_event_ids` and `events`, each with a
  stable `event_id` such as `<tenant>/<agent>/deployment/4/applied`.

Only validated, allowlisted fields are copied: identifiers, sequence numbers,
revision names, policy digests, actions, states and times. Credentials and
tokens, prompts, tool payloads, raw policy bodies, request authentication
headers and host paths are never read into the snapshot. Before any preview or
download the JSON is checked for credential, bearer, JWT, private key and host
path shapes; if one appears the export is refused.

## Verification

```sh
python3 -B -m unittest scripts/tests/test_console_agent_history_browser.py
cargo build --locked -p llm-firewall -p agentfw
python3 -B scripts/console-agent-history-acceptance.py --no-build --backend sqlite --output /tmp/history
python3 -B scripts/console-agent-history-acceptance.py --no-build --backend postgres --output /tmp/history
```

The acceptance seeds Agents only through the existing admin and Agent APIs,
runs the unchanged `agentfw serve` to apply and reject real signed bundles,
then drives the panel in Chromium as a Viewer. The PostgreSQL run needs local
PostgreSQL server binaries (`--pg-bin DIR`) and an ordinary user. CI runs both
in the Agent fleet workflow. Evidence:
[2026-11-01](evidence/CONSOLE_AGENT_HISTORY_2026-11-01.md).
