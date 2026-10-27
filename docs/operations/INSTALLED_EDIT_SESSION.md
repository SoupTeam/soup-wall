# Installed private-output edit session

SOU-161 adds an explicit `agentfw edit-session` entry on native Linux x86_64.
The existing installed read-only pilot remains the default. This entry does not
upgrade an existing MCP profile and never runs an original server's `write_file`.

## Supported boundary

Use an operator-owned private output directory on a supported local Linux
filesystem. The operator must be the sole writer; cooperating Agent operations
also use the accepted directory lock. This is not compare-and-swap against
arbitrary external writers. Shared or concurrently mutable project trees are
unsupported. Existing replacement rules remain unchanged: one regular direct
child, one link, private metadata, fixed old identity and SHA-256, and at most
4096 UTF-8 bytes. Creation uses the existing no-clobber executor.

Install the reviewed Agent and its verified pilot component first; see
[the installed pilot guide](PILOT_INSTALLED_FRONT_DOOR.md). Select the repository
pinned genuine Claude Code 2.1.251 Linux executable. All runtime paths must be
canonical, protected regular files. Preparation records the installed component,
source identity, interpreter, classifier, Agent and Claude digests. Changed
inputs require a fresh explicit preparation.

## Preview and explicit preparation

Create separate private directories for output, immutable plans and run state.
The state and plan directories must be outside the output tree. Use absolute
canonical paths. This example permits creation and subsequent reads of exactly
`report.txt`, plus reads of `source.txt`:

```sh
agentfw edit-session preview \
  --home /absolute/agent-home --claude /absolute/claude \
  --root /absolute/private-output --private-sole-writer \
  --read source.txt --read report.txt --create report.txt

agentfw edit-session prepare --apply --out /absolute/plans/report-plan \
  --home /absolute/agent-home --claude /absolute/claude \
  --root /absolute/private-output --private-sole-writer \
  --read source.txt --read report.txt --create report.txt
```

`preview`, and `prepare` without `--apply`, do not write state or grant execution
authority. Preparation publishes a new directory without replacing an existing
plan. Save its displayed `profile_sha256`. No registry, execution or authority
JSON needs to be written by hand. At most eight direct-child targets may be
selected; wildcards, hidden names, aliases and create-plus-replace combinations
are rejected.

For replacement select `--read report.txt --replace report.txt`. Preparation
captures that exact old object and content digest. The generated tool schema
requires those fixed old facts; it never silently refreshes an outdated version.

## Run and decide Ask

Place the prompt in a bounded private UTF-8 file, then run:

```sh
agentfw edit-session run --plan /absolute/plans/report-plan \
  --sha256 DISPLAYED_PROFILE_SHA256 --state /absolute/runs \
  --prompt-file /absolute/prompt.txt
```

Provider inputs come from the operator's supported provider environment, as for
the accepted pilot. Only the intended genuine Claude host receives them. Its
settings, user home, plugins, hooks and executable search path are isolated;
builtins and unselected MCP servers are disabled. There is no paid-provider
requirement for the qualification: it uses an owned scripted loopback provider.

The command prints the private run directory. From a second terminal:

```sh
agentfw edit-session ask --run /absolute/runs/edit-RUN_ID list
agentfw edit-session ask --run /absolute/runs/edit-RUN_ID inspect PENDING_ID
agentfw edit-session ask --run /absolute/runs/edit-RUN_ID approve PENDING_ID \
  --binding DISPLAYED_BINDING_SHA256
# Or:
agentfw edit-session ask --run /absolute/runs/edit-RUN_ID reject PENDING_ID
```

Inspect shows the exact target, operation, identities and old/new digests. It
redacts raw arguments for both create and replacement. A decision applies to one
exact pending call. Approval cannot redeem a different binding, replay a spent
call, override independent Deny floors or survive a daemon epoch change.
The existing 120-second approval lifetime is unchanged. Run lifetime is bounded
by 180 seconds, including the Ask wait. Ctrl-C cancels the owned run.

The daemon owns a compiled declaration-only adapter with no filesystem API or
external discovery runtime. All selected operations pass through the existing
classifier, native resource broker, approval and executor. The runtime pins the
adapter as part of the reviewed Agent image and rechecks root identity for every
call. Authenticated transport is single-use and bound to the exact profile,
server and host session; reconnecting requires a new run. The default daemon
cannot activate this endpoint through caller-supplied configuration.

## Outcomes and recovery

A host completion is not a claim that every proposed edit succeeded. Read the
native audit and verify the resulting bytes through the selected read tool.
An interrupted run is failed/indeterminate. If publication committed before a
result was lost or withheld, the bytes remain committed: cancellation does not
roll them back and this entry never automatically retries the mutation.

Private run state retains the audit and exact native approval records. Host
stdout/stderr are drained within fixed caps; only byte counts and digests are
retained, never raw model output or provider credentials. A killed daemon cannot
approve stale records: Ask requires the matching live authenticated epoch.
Prepare a new plan after independently inspecting an uncertain target.

## Qualification

`python3 -B scripts/qualify-installed-edit.py` is inert. The explicit `--run`
qualification installs exact Agent/Claude bytes outside the checkout, installs
the verified component, then uses the genuine restricted host with an owned
scripted provider. It independently checks useful read/create/read and
read/replace/read, Ask decisions, stale inputs, links, changed bindings, replay,
cancellation, daemon loss, fresh epochs and postcommit interruption. It checks
output bytes/inodes, an unrelated sentinel, discovery mutation dispatch and owned
process cleanup. This is development qualification, not a live-model efficacy or
production-readiness claim. The registered `linux-installed-edit` job runs with
read-only source, private writable scratch and no external network.

Current qualification evidence belongs under
[`evidence/sou-161/`](evidence/sou-161/README.md). Final shared Ready qualification,
admission and merge remain with the reviewer.
