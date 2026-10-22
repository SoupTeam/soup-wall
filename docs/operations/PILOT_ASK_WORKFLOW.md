# Run-scoped operator Ask in the installed Claude pilot

This opt-in Linux workflow connects the [pilot launcher](CLAUDE_PILOT_LAUNCHER.md)
to the accepted [single-use broker](SELECTED_MCP_ASK_APPROVAL.md). Without
`--ask-wait-seconds`, existing launcher behavior is unchanged. No global Claude
configuration, daemon configuration or approval deadline is modified.

## Prerequisites

Use the verified installed original filesystem and Git read-only profiles and
the accepted `rule_baseline/git_readonly_v1/rule_baseline.py` classifier bytes.
The daemon must already enforce the selected policy, have the combined original
registry, disable the optional judge, and enable native approval and liveness:

```yaml
enforce: true
native:
  # Retain your installed registry_path and registry_sha256.
  approval:
    ttl_seconds: 120
  liveness:
    default_lease_seconds: 4
    max_lease_seconds: 60
    maintenance_interval_ms: 500
```

The daemon must bind to loopback. Restart it explicitly after configuration
changes. Missing approval/liveness, a policy mismatch, changed assets, fixtures
or unsupported platforms cause refusal before starting the host. This feature
does not prepare runtime assets or install a classifier for you.

Use the same `agentfw` executable for launcher, collectors and operator CLI.
Opt-in run timeouts must be 1–3600 seconds. Updating the executable while a run
is live invalidates its operator selection; start a fresh run after an update.

## Two terminals

In terminal 1, start the actual host with the explicit wait option:

```sh
agentfw pilot-launch --home "$HOME/.agentfw" \
  --claude /absolute/path/to/claude \
  --workspace /absolute/path/to/workspace \
  --fs-profile /absolute/path/to/filesystem-profile \
  --git-profile /absolute/path/to/git-profile \
  --classifier /absolute/path/to/git_readonly_v1/rule_baseline.py \
  --policy /absolute/path/to/selected-policy.yaml \
  --ask-wait-seconds 25 -p 'Perform the selected read-only work.'
```

The launcher prints a random run ID. Keep terminal 1 for host output. In
terminal 2, select the same daemon home and that exact live run:

```sh
agentfw pilot-approval --home "$HOME/.agentfw" --run RUN_ID list
agentfw pilot-approval --home "$HOME/.agentfw" --run RUN_ID inspect PENDING_ID
# Read the exact arguments, expiry and binding shown by inspect. Then decide:
agentfw pilot-approval --home "$HOME/.agentfw" --run RUN_ID \
  approve PENDING_ID --binding EXACT_BINDING_SHA256
# Or reject just that request:
agentfw pilot-approval --home "$HOME/.agentfw" --run RUN_ID \
  reject PENDING_ID --binding EXACT_BINDING_SHA256
```

List shows server/tool, pending ID, expiry and binding, without arguments.
Approve requires successful explicit inspection of the same arguments/binding.
Control characters in the explicit inspection output are escaped. Do not tee
inspection output into general logs or export it with qualification evidence.
Never paste bearer tokens or child grants into either terminal.

The CLI reports `decision_submitted` separately from dispatch/release, which it
does not observe. A successful command is not proof that the server executed or
that the host consumed a result. There is no approve-all, automatic consent,
stdin decision channel or timeout-as-consent. Same-user CLI authorization is
not proof of physical human presence or protection against OS compromise.

## Boundaries and lifecycle

Only the accepted original read-only invocation Ask can wait. The effective
wait is bounded by the chosen 1–25 seconds, broker TTL and existing relay
deadline. Hard Deny, unknown/partial classification, result Ask/Deny, mutators,
network/resource execution and unsupported tools cannot be rescued.

Run selection checks the authenticated daemon instance/registry, live collector
session/epoch and the digest of its verified child authority. A session label,
description or tool argument cannot establish ownership. Private, bounded run
metadata contains no grants. Its exact bytes are anchored by a sealed Linux
descriptor held by the live launcher, whose PID start time and executable are
checked. Altering the file cannot redirect operator decisions to another run.

Profile/classifier/policy/config changes, stale instances, wrong runs and
replay refuse. Broker revalidation, ledger spending, taint and incomplete
history remain authoritative. An Allow peer can still proceed while Ask waits.

On normal host exit or interruption, the launcher terminates its owned group,
rejects only its exact observed unused requests and waits for existing lease
retirement (including approved-but-unused grants). Its private run metadata is
removed. Daemon loss/restart produces failure and leaves retirement to the
existing broker/liveness machinery; no approval is replayed after restart.
Other runs, pending calls, workspaces and processes are preserved.

At most 16 run directories and a bounded number of inspection receipts exist.
Metadata reservations are serialized. Abrupt launcher SIGKILL cannot run a
destructor: stale metadata never authorizes continuation because the process
identity/held descriptor is gone. Inspect such stale directories before manual
removal; the CLI never broad-deletes another run to make capacity.

## Qualification

`scripts/qualify-pilot-ask.py` uses the actual launcher/Claude executable, pinned
original servers and an owned loopback provider with no paid traffic. It checks
zero target kernel effects before approval, exactly one after approval,
correlated refusal on reject/expiry, useful continuation, an Allow peer,
cross-run isolation, metadata tampering, replay, cancellation, restart and
cleanup. Arguments and raw syscall traces remain private; exported evidence
contains identities, digests, bounded counts and correlated outcome states.
The existing Linux original-filesystem CI job runs this command; no new matrix
or exemption replaces current-source CI, CodeQL or candidate admission.
