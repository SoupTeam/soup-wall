# Run a prepared Linux pilot

SOU-116 composes the accepted [preparation](PILOT_RUNTIME_PREPARATION.md),
[restricted launcher](CLAUDE_PILOT_LAUNCHER.md) and
[operator Ask workflow](PILOT_ASK_WORKFLOW.md). It does not build or download
anything, choose another policy, edit global Claude settings, or install a service.

Use a clean reviewed checkout on native Ubuntu 24.04 x86_64, as a non-root user.
Supply the `selection` path returned by completed SOU-111 preparation from that
exact commit. The generation must still be selected by its `current.json`.
Its original filesystem and Git workspaces remain distinct: Claude starts in the
filesystem workspace, and each original MCP server sees only its own pinned root
as `/workspace`. No profile or receipt is rewritten to combine roots.

```sh
python3 -B scripts/pilot-run.py \
  --selection /absolute/preparation/generations/GENERATION/selection.json \
  --expected-commit "$(git rev-parse HEAD)"
```

This default validates source, selected executable/artifact hashes, profiles,
package trees, libraries and the completion marker, and prints a plan. It does
not execute selected programs, connect to a daemon, create state or launch Claude.
An invalid selection returns nonzero with a finite reason code.

After reviewing the plan, add `--run`:

```sh
python3 -B scripts/pilot-run.py --run \
  --selection /absolute/preparation/generations/GENERATION/selection.json \
  --expected-commit "$(git rev-parse HEAD)" \
  --timeout-seconds 180 \
  --prompt 'Read /workspace/notes.txt with filesystem, then inspect Git status.'
```

Configure provider authentication/transport explicitly in the operator shell
using the normal `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` and optional
`ANTHROPIC_BASE_URL`. These values are passed in memory, never written into the
selection, rendezvous or report. Qualification uses an owned loopback scripted
provider and synthetic data; it makes no paid-provider or live-model claim.

The command creates a random `0700` directory under the system temporary
directory (or an explicit canonical `--state-root` outside both workspaces and
the checkout). It writes private daemon configuration, a merged original-tool
registry and `0600` tokens there. The selected policy and classifiers are not
edited; the accepted Git read-only classifier supports both original servers.
Only this invocation's daemon starts. Readiness requires authenticated native
features and the existing nonce-checked protection-status query, with the exact
binary, current configuration, registry and owned process identity. The existing
launcher also verifies the selected policy against the enforcing daemon.

By default a free loopback port is chosen. `--port PORT` requests a particular
port; an occupied port is refused, even if an operator service looks compatible.
Existing services are not adopted, changed or stopped. A competing listener in
the bind/start interval cannot authenticate with this invocation's fresh token;
the host cannot start without verified readiness.

## Ask and lifecycle

Ask remains disabled by default. Add `--ask-wait-seconds 25` for the accepted
explicit operator flow. The startup message contains the temporary daemon
`home`. In a second terminal, while the run is live:

```sh
agentfw pilot-approval --home /reported/run/.agentfw --run RUN_ID list
agentfw pilot-approval --home /reported/run/.agentfw --run RUN_ID inspect PENDING_ID
agentfw pilot-approval --home /reported/run/.agentfw --run RUN_ID \
  approve PENDING_ID --binding EXACT_BINDING_SHA256
```

Use the selected Agent executable, read the live run ID under that home's
`pilot-runs`, and follow the existing [Ask guide](PILOT_ASK_WORKFLOW.md).
Inspection is mandatory before one exact approval; there is no approve-all,
automatic consent, authority copied by the operator, or new signature scheme.

Private `host.private.log` and `daemon.private.log` exist only while the run is
active. Treat them as sensitive; they are not diagnostic-export artifacts.
The final bounded JSON reports completion or a concrete finite failure reason.
Completion means the selected launcher exited successfully; it does not claim
that every model-proposed operation was allowed. The read-only profiles continue
to refuse mutations and ungranted tools before original-server execution.

Normal completion, launcher errors, timeout, SIGINT, SIGTERM and daemon loss stop
the owned launcher, allow its host/Ask cleanup to complete, stop the owned daemon,
and remove private runtime state. Separate user services, processes, prepared
assets and workspace files remain. Cleanup failure is explicit and retains the
private directory for recovery. SIGKILL/power loss cannot run Python cleanup;
Linux parent-death signals stop the direct owned children, but an abandoned
private directory may need manual removal after its process identities are
confirmed dead. No broad process-name kill or directory sweep is performed.

The actual-host acceptance harness is
`scripts/qualify-prepared-pilot-run.py`. It uses the already prepared selection,
genuine pinned Claude Code and original filesystem/Git servers. Its independent
wire/syscall controls cover useful calls, refused mutation, exactly-once Ask,
useful continuation, cancellation, timeout, daemon loss and owned-only cleanup.
Only bounded sanitized reports are retained. Source, package and workspace
identities are compared before and after qualification.
