# First-use onboarding (`agentfw onboard`)

One installed-Agent flow for a new Linux user profile: **preview** a concrete
plan, **apply** exactly that plan, and get a truthful `verified`, `configured`,
`failed` or `incomplete` result. It composes the accepted components and adds
no installer or security engine of its own:

| Step | Accepted component |
|---|---|
| Token and profile | `agentfw install` |
| Agent binary and daemon | [`agentfw lifecycle install/start/stop/remove`](AGENT_LIFECYCLE.md) |
| Identity check | [`agentfw protection-status`](AGENT_LIFECYCLE.md#authenticated-runtime-protection-diagnostics) |
| Host connection | [`agentfw mcp-connection connect/inspect/disconnect`](CLAUDE_MCP_CONNECTION.md) |
| Isolated behavior check | [`agentfw self-test`](SELF_TEST.md) |

Roadmap: Phase 5. Phase 4 stays open: nothing here measures live-model
effectiveness. No model, package or provider is downloaded or contacted, and
no service is installed.

## Inputs

All inputs are explicit, absolute and link-free. Nothing is discovered.

| Flag | Meaning |
|---|---|
| `--agent`, `--agent-sha256` | Installed `agentfw` and its reviewed digest |
| `--classifier rule-baseline`, `--classifier-script`, `--classifier-sha256`, `--classifier-python` | Local Task 1 classifier for the isolated self-test |
| `--registry`, `--registry-sha256` | Reviewed `sw-native/1` registry for the selected server |
| `--policy`, `--policy-sha256` | Optional reviewed policy; omitted means the shipped default policy |
| `--workspace` | Reviewed workspace the server works in (owned, not world-writable) |
| `--agent-home` | New `.agentfw` directory to create (its parent must be private and yours) |
| `--host-config`, `--server` | Claude Code JSON file (`0600`) and the existing reviewed `mcpServers` entry |
| `--port` | Loopback port for the new daemon (default 8787) |
| `--probe-tool`, `--probe-args` | Optional harmless call that verifies the connected server |
| `--report` | New JSON report file; an existing file is never replaced |

The selected server entry must be a stdio command with an absolute, link-free
executable (use `readlink -f`), string arguments and no environment values.
Registries that need a server profile or resource executor (for example the
[filesystem profile](MCP_REAL_FILESYSTEM.md), which uses its own documented
launch) are refused, because the accepted connection does not configure them.

## 1. Preview (read-only)

```sh
agentfw onboard preview <inputs> --report ./onboard-preview.json
```

Preview checks the platform, every asset digest, Python, the registry and
policy, the workspace, the Agent home, the host config and selected entry,
the port and the probe. It prints the exact paths, each check with an action,
the planned changes, what is not changed, and a **plan SHA-256**. It writes
nothing except its report. It never changes permissions, settings, services
or credentials.

| Check status | Meaning |
|---|---|
| `ok` | Ready |
| `refused` | Missing or invalid asset, unsupported profile, unsafe permissions; follow the action |
| `conflict` | Something already exists that onboarding must not adopt or overwrite (an existing Agent home, a listener on the port, an entry already wrapped by someone else) |

## 2. Apply (explicit)

```sh
agentfw onboard apply <same inputs> --plan-sha256 <digest from preview> --report ./onboard-apply.json
```

Apply recomputes the whole plan and refuses unless the digest matches, so a
host-config edit, a changed asset or a new listener after preview stops it
before any change. It then runs these steps. Each step is journaled in
`<agent home parent>/.soup-wall-onboarding/journal.json` (private) before it
runs:

1. create the Agent home (`0700`);
2. write `onboarding/registry.json`, `onboarding/policy.yaml` and `config.yaml`
   (enforce, loopback port, pinned registry digest) with `create_new`;
3. `agentfw install` (token);
4. `agentfw lifecycle install onboard-<digest prefix>`;
5. `agentfw lifecycle start`, with a fresh check that no foreign listener took the port;
6. verify identity: authenticated `protection-status` must show enforcing mode,
   the lifecycle PID, the Agent digest, the registry digest and the policy digest
   expected from the reviewed policy;
7. `agentfw mcp-connection connect` for the selected entry only;
8. `agentfw mcp-connection inspect` with the explicit probe, if one was given;
9. the installed `agentfw self-test` in its own isolated workspace.

After every step the journal also records an **inventory** of the Agent home it
created: each entry the step created or changed (kind and SHA-256), never
following links. Entries that existed before a step and were not recorded stay
foreign. Cleanup uses only this record (see [Undo](#3-undo)).

A lock prevents two operations on one Agent home. Each command runs in its own
process group with a cleared environment and a bounded time.

### Outcomes

| Result | Exit | Meaning |
|---|---|---|
| `verified` | 0 | Configured, identity matches, the probe returned an admitted result and the self-test passed |
| `configured` | 6 | Configured and identity matches, but no probe verified the connected server |
| `failed` | 3 | A verification contradicted the plan (identity mismatch, probe failure or self-test failure) |
| `incomplete` | 4 | Interrupted, timed out, missing or conflicting; the report says what to do |
| `refused` | 4 | Preview/revalidation refused; nothing changed |
| `unsupported` | 5 | Not Linux; nothing changed |
| `plan_ready` / `undone` | 0 | Preview ready / undo completed |

The report keeps **configured** (daemon identity and configuration) separate
from **verified** behavior (`host_probe`, `self_test`). The self-test runs its
own temporary daemon. It shows that the installed Agent's admission path works,
**not** that your configured host is protected. `coverage` reports the host
session, other MCP servers, Claude hooks and model context as `unknown`, because
onboarding observes no Claude Code session.

### Failure, retry and interruption

- **Failure before configuration** (for example a listener that appears on the
  port during apply): onboarding rolls back only its proven changes in reverse
  order: lifecycle stop/remove, then the exact files it wrote (by digest), then
  the recorded entries of the Agent home it created. Anything untracked or
  changed is retained and reported as a conflict, and the journal stays
  (`rollback_conflict`) so `undo` can finish later. Automatic rollback never
  purges: a non-empty audit log is kept like in an ordinary undo.
- **Verification failure after configuration**: nothing is silently rolled
  back; the result is `failed` and the next step is `undo`.
- **Interruption** (SIGINT, SIGTERM, SIGHUP or the time bound): the current step
  finishes, then apply stops with `incomplete`. Completed steps stay journaled and
  nothing is rolled back. Rerun the same `apply` to resume, or run `undo`.
- **Crash or SIGKILL**: rerun the same `apply`. Steps are idempotent: an existing
  owned file must have the exact planned bytes, an already active or running
  lifecycle is reused, and `mcp-connection` resumes its own pending transaction.
- **Safe retry**: rerunning `apply` after success re-verifies identity, the probe
  and the self-test without changing anything.

## 3. Undo

```sh
agentfw onboard undo --agent <agentfw> --agent-home <home> --host-config <file> \
  --server <name> --report ./onboard-undo.json [--purge-agent-home]
```

Undo reverses the recorded onboarding:

1. `mcp-connection disconnect` restores only the selected entry and keeps later unrelated edits;
2. `lifecycle stop` and `lifecycle remove`;
3. the exact files onboarding wrote are removed, matched by digest;
4. in an Agent home onboarding created, only entries that still match the recorded
   inventory are removed, bottom-up; directories only when empty, and the home
   itself only when nothing is left. Nothing is deleted recursively.

| Found in the Agent home | Undo | Undo `--purge-agent-home` |
|---|---|---|
| Recorded entry, unchanged | removed | removed |
| Non-empty `audit.jsonl` | kept (`retained`) | removed |
| File or directory not recorded (for example `grants/operator-notes.txt`) | kept, `conflict` | kept, `conflict` |
| Recorded file changed since its step | kept, `conflict` | kept, `conflict` |

On a conflict undo returns `incomplete` (exit 4), keeps the journal
(`rollback_conflict`) and reports only a count and the top-level directory names,
never paths. The earlier steps (connection, lifecycle, owned files) stay
reversed. Review or move the preserved files, then run undo again.
`--purge-agent-home` only adds the audit log; it never removes untracked or
changed files. When only the audit log is left, the journal remains
(`undone_audit_retained`) so a later purge can finish. If the selected entry or
an owned file was edited externally, undo stops with `incomplete` and overwrites
nothing. `apply` refuses to resume an undone or conflicted onboarding.

`mcp-connection` keeps its private `.soup-wall-*` recovery files beside the
host config by design. They can contain the original entry; remove them only
after review.

## Privacy

Reports contain digests, statuses, counts, step timings and check results. They
never contain tokens, probe arguments or results, host settings, server
arguments or raw paths; paths appear only as a 16-character digest. The console
preview prints exact paths so you can review them; do not share console output
if your paths are private.

## Acceptance

The acceptance runner sets up owned clean Linux homes outside the source
checkout. Each home has an installed copy of the Agent, the rule baseline, the
accepted admission fixture server and its registry, plus sentinel files,
entries and settings that must survive:

```sh
cargo build --locked --release -p agentfw
python3 scripts/onboarding-acceptance.py --agentfw target/release/agentfw --out target/onboarding-evidence
```

| Scenario | What it shows |
|---|---|
| `success_retry_undo` | preview is read-only, apply is `verified`, retry re-verifies, undo keeps the audit log, purge removes it, sentinels survive, no processes remain |
| `missing_or_wrong_classifier` | refusal with an action; nothing created |
| `existing_active_config` | an existing Agent home is a conflict; its files are untouched |
| `occupied_port_foreign_listener` | an occupied port is a conflict; a listener that appears after preview stops apply at revalidation |
| `interrupted_and_killed_apply` | SIGINT stops at a step boundary; rerun resumes to `verified`; SIGKILL during verification recovers |
| `external_edit_conflicts` | a host edit after preview invalidates the plan; an edited wrapped entry or owned file blocks undo without overwrite |
| `rollback_after_listener_race` | a listener that appears during apply is not adopted; only proven changes are rolled back |
| `foreign_files_in_agent_home` | operator files inside `grants/` and `onboarding/` survive undo, purge and an automatic rollback with a `conflict`; the journal stays; undo finishes cleanly once they are removed |
| `unsafe_host_config` | a non-private host config is refused and its permissions are not changed |

```sh
cargo test --locked -p agentfw --lib onboarding
cargo test --locked -p agentfw --test onboarding
```

The Rust checks cover read-only preview and digest binding, refusals with
actions, conflicts for an existing home and a foreign listener, digest
enforcement, unsafe host files, undo without a record, report non-overwrite,
undo and rollback that preserve untracked or changed files inside runtime
directories, audit retention without purge, and an inventory that does not follow links.

See the [SOU-69 evidence](evidence/SOU69_ONBOARDING_2026-10-18.md).

## Limits

- Linux, local user, no service. Other identity modes and platforms are refused or unsupported.
- One selected plain native-admission server per onboarding. Profile-launched
  servers keep their own documented setup.
- The accepted connection wrapper does not pass classifier settings to the host
  collector; host calls are admitted by the daemon policy and registry. The
  classifier is exercised by the isolated self-test.
- The legacy Claude HTTP hook still fails open; onboarding neither configures
  hooks nor claims coverage for them.
