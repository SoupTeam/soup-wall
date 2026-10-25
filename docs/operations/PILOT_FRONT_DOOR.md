# Linux pilot: guided first use (`scripts/pilot.py`)

One command takes an operator through the existing Linux read-only
filesystem/Git pilot: **preview**, **prepare**, **run** and **status**. It is a
front door over the accepted scripts, not a new installer:

| Step | Reuses |
| --- | --- |
| native Git and bubblewrap | `prepare-native-pilot-prerequisites.py` (SOU-115) |
| Agent executables | `build-native-pilot-inputs.py` (SOU-119) |
| pinned servers and selection | `prepare-installed-pilot.py` (SOU-111, SOU-134 roots) |
| protected run | `pilot-run.py` (SOU-116), restricted launcher, `--tools ""` and strict MCP |
| live status | `agentfw protection-status` |
| approvals and stop | `agentfw pilot-approval` (existing contract) |

Each step keeps its own verification, receipts, transactions and failure codes.
Supported platform: native Ubuntu 24.04 x86_64, as an ordinary (non-root) user.
WSL and other platforms are not supported by this flow.

## 1. Preview (no effects)

Use a clean reviewed checkout and an absolute private prefix outside the
checkout, outside your project and not your home directory itself:

```bash
repo="$HOME/soup-wall"
prefix="$HOME/soup-wall-pilot"
python3 -B "$repo/scripts/pilot.py" preview --prefix "$prefix" \
  --filesystem-workspace /home/me/projects/app \
  --git-workspace /home/me/projects/repo \
  --allow-download
```

Preview prints (stderr) a short summary and (stdout) a JSON report:

- the platform check, the exact source commit and whether the tree is clean;
- every input, as supplied (path and SHA-256) or as produced by a named step;
- the filesystem and Git roots (omit both options to use generated demo
  workspaces), the private prefix layout and the planned effects of `--apply`;
- every missing prerequisite, with what to supply.

Preview never starts a daemon, Claude host or MCP server, never edits a
project, Git repository or Claude configuration, never creates or changes a
selection, never downloads or builds, and never contacts a model provider. It
does not create the prefix. It runs only the accepted read-only plans (and
`git` to read the checkout identity).

### Inputs

All runtime inputs are explicit; nothing is chosen from `PATH`.

| Option | Without it |
| --- | --- |
| `--git PATH --bwrap PATH` | built by the native step into `PREFIX/native` (needs `--git-archive`/`--bwrap-archive` or `--allow-download`) |
| `--agentfw --git-launcher --sandbox-tests` | built from this commit by the Agent step into `PREFIX/agent` (exact Rust 1.94.1, installed in advance; never auto-installed) |
| `--node-archive TAR_XZ` or `--node --npm` | pinned Node 22.22.0 archive downloaded with `--allow-download` and digest-checked |
| `--claude PATH` | locked Claude Code 2.1.251 installed with `npm ci --ignore-scripts` (needs `--allow-download`) |
| `--python PATH` | the interpreter that runs `pilot.py`, resolved and recorded |
| `--python-archive --npm-cache --wheelhouse` | offline inputs; otherwise `--allow-download` |
| `--native-output DIR`, `--agent-output DIR` | reuse an existing SOU-115/SOU-119 generation directory |

Downloads happen only in `prepare --apply` and only with `--allow-download`.

## 2. Prepare (explicit)

```bash
python3 -B "$repo/scripts/pilot.py" prepare --apply --prefix "$prefix" \
  --filesystem-workspace /home/me/projects/app --git-workspace /home/me/projects/repo \
  --allow-download
```

Without `--apply`, `prepare` only shows the plan. With it, the steps run in
order and stop at the first failure, naming the step and its reason. Each step
keeps its accepted transaction: a failed step leaves the previous selected
generation and unrelated files unchanged. The result is a selection that is
**prepared, not active**. The explicit options are recorded in
`PREFIX/front-door.json` (mode 0600), so repeating `prepare --apply --prefix`
alone verifies and reuses the same generation. Use `--rebuild` for a new
generation (the old one is kept), for example after changing project roots.

Project roots must be existing, canonical, owned by you and not group/other
writable; Git must be a supported standalone repository (see
[existing project guide](PILOT_EXISTING_PROJECT.md)). Nothing in a project is
created, repaired or edited.

## 3. Run

```bash
python3 -B "$repo/scripts/pilot.py" run --prefix "$prefix" \
  --prompt 'Read README.md with the filesystem tools, then show the latest Git commit.'
```

Set the provider transport in your shell as for `pilot-run.py`
(`ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`, optional `ANTHROPIC_BASE_URL`);
it is passed in memory and never written. Other options are passed unchanged:
`--timeout-seconds`, `--ask-wait-seconds`, `--state-root`, `--port`.

`run` first checks the recorded selection (present, prepared from this clean
commit, still the selected generation) and then starts the accepted
`pilot-run.py --run` with a fixed argument list, never a shell string. The host
runs with `--tools ""` and the strict MCP configuration; each server sees only
its own root as `/workspace`. The JSON report is printed unchanged and the exit
status is the same. **Ctrl-C** reaches the run supervisor, which stops its own
daemon and host and reports `pilot_cancelled`; a TERM or HUP sent to `pilot.py`
is forwarded; if the supervisor dies by a signal, `pilot.py` exits by the same
signal. Already performed reads are not undone.

## 4. Status

```bash
python3 -B "$repo/scripts/pilot.py" status --prefix "$prefix"
```

| Protection | Meaning |
| --- | --- |
| `observed-live` | an owned enforcing daemon answered an authenticated `protection-status` query just now |
| `configured-not-running` | a verified selection exists; nothing is protected until `run` |
| `unavailable` | a run or selection exists but cannot protect now: its daemon does not answer, or the selection is stale |
| `unknown` | state could not be read safely |
| `not-configured` | nothing prepared under this prefix |

The selection is shown as `configured`, `stale` (with the reason) or `missing`.
Status reads only; it does not start, stop or repair anything and never prints
tokens, environment or private logs. Use `--state-root` if the run used one.

## Approvals and emergency stop

These are the existing noninteractive commands; `pilot.py` adds none. Ask is off
unless the run uses `--ask-wait-seconds` (up to 25). The run prints its private
daemon `home` on stderr when it starts, and `status` lists the run ID. From a
second terminal, with the **selected** `agentfw` executable:

```bash
agentfw pilot-approval --home HOME --run RUN_ID list
agentfw pilot-approval --home HOME --run RUN_ID inspect PENDING_ID
agentfw pilot-approval --home HOME --run RUN_ID approve PENDING_ID --binding EXACT_BINDING_SHA256
agentfw pilot-approval --home HOME --run RUN_ID reject PENDING_ID --binding EXACT_BINDING_SHA256
agentfw pilot-approval --home HOME --run RUN_ID stop
```

Inspect before each single decision; there is no approve-all and no automatic
approval. `stop` revokes both collectors and stops the exact owned launcher; see
[Ask workflow](PILOT_ASK_WORKFLOW.md) and [emergency stop](PILOT_EMERGENCY_STOP.md).

## Errors

| Message (`reason`) | What to do |
| --- | --- |
| `not_prepared` | run `preview`, then `prepare --apply` |
| `stale_source`, `candidate_source_mismatch` | the selection is from another commit: check out the reviewed commit or prepare again |
| `dirty_source` | commit or remove local changes; use a clean checkout |
| `selection_not_current`, `preparation_marker_mismatch` | the recorded selection is no longer selected: prepare again |
| `selected_artifact_changed`, `selected_executable_changed` | an input changed after preparation: `prepare --apply --rebuild` |
| `native_ubuntu_required_wsl_is_separate`, `ubuntu_24_04_required`, `non_root_operator_required` | use native Ubuntu 24.04 x86_64 as an ordinary user |
| `owned_daemon_not_ready`, `authenticated_readiness_failed` | the private daemon could not be verified; no host started |
| `owned_daemon_lost` | the daemon stopped during the run; the run failed closed |
| `pilot_cancelled`, `pilot_timeout` | the run stopped and cleaned up its own processes |
| `owned_process_cleanup_failed` | follow the [storage recovery runbook](PILOT_STORAGE_RECOVERY.md) |
| `missing_inputs` (prepare) | run `preview` and supply the listed items |
| a step name with its own reason (prepare) | see that step's guide; earlier selections are unchanged |

## Qualification

`scripts/qualify-pilot-front-door.py` exercises the command on native Ubuntu
24.04 with the pinned original servers, genuine Claude Code 2.1.251 and the
existing owned scripted loopback provider (no model account or paid call):
zero-effect preview (independent `execve`/`connect` trace), prepare and reuse on
owned existing project roots, status before, during and after a run, one useful
original read and Git history call, refused write, Git reset and send with
independent witnesses, stale and changed selection refusals, Ctrl-C
cancellation with owned cleanup, and unchanged project and user configuration.
The native CI job runs it with that job's exact source-built inputs. It does
not measure live-model effectiveness or general product readiness.

WSL reproduction: this flow refuses WSL by design
(`native_ubuntu_required_wsl_is_separate`); running the same `preview` command
in WSL2 Ubuntu 24.04 shows that refusal and no other effect.

Evidence: [first-use run, 2026-10-25](evidence/PILOT_FRONT_DOOR_2026-10-25.md).
