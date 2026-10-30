# Console: managed Agent policy rollout

The Console admin page (`/admin`) has a **Managed Agent policy rollout** panel
under each tenant's Agent fleet. It is a browser workflow over the existing
[staged group rollout](MANAGED_AGENT_GROUP_ROLLOUT.md) APIs and signed
`AgentPolicySet` bundles. It adds no rollout engine: the server freezes cohorts,
signs deployments, evaluates acknowledgement gates and keeps every decision.
It manages Agent policies only, never the Gateway model allowlist or tenant
policy versions.

## Who can do what

| Role | In the panel |
| --- | --- |
| Owner | create groups and membership, create and approve revisions, start a pilot deployment, evaluate the gate, pause, resume, roll back |
| Operator, Viewer | read groups, revisions and the server plan; no change controls |

The server checks the role and tenant on every request; hiding controls is
only a convenience. The admin token stays in the tab's memory (never in a URL,
browser storage or reports), as for the rest of the Console. If a request is
refused with 401 or 403, the panel becomes read-only until you reconnect.

## Workflow

1. **Select the tenant**, then an **Agent group** (or create one). Add enrolled
   Agents and mark pilots. Current membership is only a **preview**.
2. **Create a revision**: paste the AgentPolicySet YAML. The panel shows the
   SHA-256 of these exact bytes and, after creation, checks that the server
   digest is the same. A mismatch says "Do not approve it".
3. **Review and approve**: type the revision ID to approve that exact digest.
   Approval issues nothing.
4. **Start pilot deployment**: choose an approved revision, check the preview
   cohort and type the revision ID. The server then freezes the actual cohort;
   the panel says whether it matches your preview. Only pilots are issued.
5. **Promotion**: the server issues the worker wave only after every pilot's
   exact applied acknowledgement (Agent, sequence, revision, digest) is recorded.
   **Evaluate pilot gate** asks the server to re-check it and process expired
   deadlines; it never bypasses the gate. An offline or rejecting pilot keeps
   workers on their old policy (or rolls back on rejection or deadline).
6. **Pause / Resume** hold or continue the saved wave. A paused plan survives a
   Console restart.
7. **Roll back**: the confirmation lists each Agent's frozen baseline; type
   `rollback <revision>`. The server issues new, higher-sequence signed
   deployments of those baselines and reports `rolled_back` only after their
   applied acknowledgements.

## Reading the plan

The plan table shows the frozen pilots and workers, revision, policy SHA-256,
rollout ID, initial / expected / latest sequence per Agent, the recorded state
and the last matching applied acknowledgement. Issued, delivered and applied are
separate recorded states. An applied acknowledgement is historical evidence from
that Agent with its age; it is not fresh health or runtime attestation.

## Safety behaviour

- One change at a time: buttons are disabled while a request is in flight.
- Before pause, resume, evaluate and rollback the panel re-reads the plan. If
  the rollout ID or phase changed (another Owner, an acknowledgement or a
  deadline), nothing is sent and the new plan is shown.
- If a change gets no clear answer (network loss, timeout, server error), the
  panel never retries. It reads the persisted server state first and keeps all
  changes disabled until that read succeeds (**Reconcile with server state**).
- Switching tenant or group discards late responses for the old selection.

## Verification

```sh
python3 -B -m unittest scripts/tests/test_console_rollout_browser.py
cargo build --locked -p llm-firewall -p agentfw
python3 -B scripts/console-rollout-acceptance.py --no-build --output /tmp/console-rollout
```

The browser regressions use bounded API fixtures. The acceptance runs one
disposable private Linux deployment: a SQLite Console, an owned private-CA HTTPS
edge, one pilot and two worker `agentfw serve` daemons and Chromium as Owner,
plus Viewer/Operator checks. CI runs both in the Agent fleet workflow.
Evidence: [2026-10-29](evidence/CONSOLE_AGENT_ROLLOUT_2026-10-29.md).
