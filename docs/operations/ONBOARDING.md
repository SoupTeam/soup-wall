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
| `--server-profile`, `--server-profile-sha256` | Optional accepted original-server profile (`profile.json` from the filesystem or Git profile installer); see [below](#original-filesystem-and-git-profiles) |
| `--report` | New JSON report file; an existing file is never replaced |

The selected server entry must be a stdio command with an absolute, link-free
executable (use `readlink -f`), string arguments and no environment values.
A registry that belongs to an original-server profile is refused unless that
profile is selected with `--server-profile`. Registries that need a resource
executor remain refused.

## Original filesystem and Git profiles

Two accepted read-only Linux profiles can be onboarded as a persistent connection:
the original [filesystem server](MCP_REAL_FILESYSTEM.md) (`filesystem-readonly-v1`)
and the original [Git server](GIT_MCP_PROFILE.md) (`git-readonly-v1`). Install the
profile first with its accepted installer; onboarding never downloads, builds or
installs anything. Then select it explicitly. One profile and one selected server
entry per onboarding; each profile is qualified separately.

| Input | Filesystem profile | Git profile |
|---|---|---|
| `--server-profile` | `<install>/profile.json` | `<install>/profile.json` |
| `--registry`, `--policy` | `<install>/registry.json`, `<install>/policy.yaml` | same |
| `--classifier-script` | `rule_baseline/rule_baseline.py` | `rule_baseline/git_readonly_v1/rule_baseline.py` |
| `--workspace` | the workspace the profile was installed for | the synthetic repository the profile was installed for |
| Selected entry | `command`: the pinned Node runtime; `args`: the installed `server-filesystem` entry point and `/workspace` | `command`: `<install>/package/python/bin/python3.11`; `args`: `-I -B -m mcp_server_git --repository /workspace` |

`--classifier-python` must be the real interpreter path (for example
`readlink -f /usr/bin/python3`): a regular, single-link executable owned by you or
root and not writable by group or others, because the connected entry persists it.
Preview refuses any other interpreter (hosted tool caches are often group-writable);
onboarding never changes its permissions. Example:

```sh
agentfw onboard preview <inputs> \
  --registry /srv/git-profile/registry.json --registry-sha256 <sha256> \
  --policy /srv/git-profile/policy.yaml --policy-sha256 <sha256> \
  --server-profile /srv/git-profile/profile.json --server-profile-sha256 <sha256> \
  --classifier-script /opt/soup-wall/git_readonly_v1/rule_baseline.py --classifier-sha256 <sha256> \
  --workspace /home/me/synthetic-repo --server git --report ./onboard-preview.json
```

**Preview** additionally checks, and binds into the plan digest:

| Check | Refused when |
|---|---|
| `server_profile` | `profile.json` changed after review, is not an accepted read-only profile, or names another workspace |
| `profile_registry` | a registry tool carries another profile's result contract, or none carries this one |
| `profile_runtime` | the pinned runtime, the complete installed package/dependency tree, bubblewrap, Git binaries, ELF libraries or the repository rules differ from the profile (verified with the same code the collector runs at startup) |
| `sandbox_support` | bubblewrap lacks `--ro-bind-fd`, unprivileged user/PID/mount/network namespaces or seccomp filters are unavailable, or (Git) Landlock ABI 3 is missing |
| `server` | the selected entry is not the profile's original command and arguments |

The plan digest covers the profile bytes, every runtime pin, the classifier source
and interpreter digests and every destination. Any change after preview refuses
apply before anything is changed.

**Apply** adds one owned file, `<home>/onboarding/classifier.py`: a private copy of
the reviewed classifier, so a later edit of the source cannot change the running
classifier. `mcp-connection connect` then persists only these launch settings in
the selected entry, as structured arguments of `/usr/bin/env -i`:
`AGENTFW_MCP_SERVER_PROFILE`, `AGENTFW_WORKSPACE`, `AGENTFW_CLASSIFIER=rule-baseline`,
`AGENTFW_RULE_BASELINE` (the owned copy) and `AGENTFW_CLASSIFIER_PYTHON`, besides the
existing `PATH`, `HOME` and `USERPROFILE`. No other environment is inherited, and no
setting comes from model or server metadata. The collector starts the original
server inside its accepted sandbox with that classifier and the daemon policy.

**Verification** keeps configured identity (`protection-status`) separate from
behavior. After `mcp-connection inspect` attributes the entry and its launch
settings to this onboarding, onboarding starts the connected entry itself and, in
one session, requires:

1. the original initialization and discovery, unchanged;
2. a useful original read: `list_directory` of `/workspace` (filesystem) or
   `git_status` (Git), or the explicit `--probe-tool` call;
3. a refused change: `write_file` of a new file, or `git_create_branch`, with an
   independent witness taken on the host, outside the sandbox: a bounded snapshot
   of the workspace (including `.git`) is unchanged and the target does not exist;
4. a useful continuation in the same session.

Only then is the result `verified` (`host_probe.status: verified_profile_witness`,
details in `profile_witness`, as digests). The isolated self-test still runs; it
never verifies the selected server by itself, nor do process existence or HTTP
readiness.

**Recovery and undo** use the same journal. An interrupted apply resumes; the
published entry always carries the profile launch settings, so a partial
publication never runs the server outside its profile. If the profile, its
runtime or the classifier copy changes after apply, `mcp-connection inspect` no
longer reports the entry `configured`, and the collector refuses to start the
server. Undo removes the owned classifier copy only with its recorded bytes.

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
created (kind and SHA-256 per entry, never following links). An entry is recorded
only if all of these hold:

- it is a **known output of that step's own operation** (for example `token` for
  `agentfw install`, `versions/agentfw-onboard-<prefix>` for `lifecycle install`,
  the daemon's `audit.jsonl`, `native-token` and runtime directories for
  `lifecycle start`, a `manifests/claude-*.json` session manifest for the probe).
  Identity, connection, self-test and other read-only steps produce nothing here,
  and a directory never implies its contents;
- the step changed it;
- before the step it was absent or still had its recorded bytes.

A file that only appears while a step runs is therefore never adopted, and a retry
keeps earlier digests, so files the operator added or edited stay foreign.
Runtime files the Agent writes after apply (for example later session manifests)
are not recorded either; undo preserves them for review. Cleanup uses only this record (see [Undo](#3-undo)).

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
| The manifest record of the connection onboarding created (`manifests/<its server id>-<digest>.json`), still a manifest record | removed | removed |

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
| `foreign_files_in_agent_home` | an operator file created in `grants/` while verification runs is not adopted; operator files inside `grants/` and `onboarding/` are not adopted by a retry and survive undo, purge and an automatic rollback with a `conflict`; the journal stays; undo finishes cleanly once they are removed |
| `unsafe_host_config` | a non-private host config is refused and its permissions are not changed |

```sh
cargo test --locked -p agentfw --lib onboarding
cargo test --locked -p agentfw --test onboarding
```

The Rust checks cover read-only preview and digest binding, refusals with
actions, conflicts for an existing home and a foreign listener, digest
enforcement, unsafe host files, undo without a record, report non-overwrite,
undo and rollback that preserve untracked or changed files inside runtime
directories, a retried verification step followed by rollback that keeps an
operator-replaced file, an operator file created while a read-only step runs,
per-step known outputs, audit retention without purge, and an inventory that does not follow links.

See the [SOU-69 evidence](evidence/SOU69_ONBOARDING_2026-10-18.md).

### Profile acceptance

`scripts/onboarding-profile-acceptance.py` installs each profile with its accepted
installer into owned roots outside the checkout and drives the installed Agent:

```sh
cargo build --locked --release -p agentfw --bins
python3 scripts/onboarding-profile-acceptance.py --agentfw target/release/agentfw \
  --node /abs/node-v22.22.0/bin/node --npm /abs/node-v22.22.0/bin/npm \
  --bwrap /abs/bubblewrap-0.13.1/bwrap --git /abs/git-2.51.2/git --git-sha256 <sha256> \
  --git-launcher target/release/agentfw-git-sandbox --out target/profile-onboarding-evidence
```

| Scenario (per profile) | What it shows |
|---|---|
| `full_cycle` | calibration: the same original server, unprotected on a scratch copy, reads and performs the change; preview read-only with profile checks; apply `verified`; persisted launch settings are exactly the narrow structured set; the acceptance client independently reads the original result through the entry, sees the change refused with an unchanged workspace and continues; retry re-verifies; undo restores the entry; purge leaves nothing |
| `changed_after_preview` | a changed dependency file, changed `profile.json` or changed entry after preview refuses apply before any change |
| `missing_sandbox_support` | in a user namespace that forbids further namespaces, preview refuses `sandbox_support` |
| `occupied_foreign_port` | an occupied port is a conflict; a listener after preview refuses apply |
| `operator_edits` | a changed runtime after apply is not `configured` and the entry fails closed; a changed `profile.json` is not `configured`; an edited wrapped entry blocks undo; unrelated operator edits survive undo |
| `interrupted_and_retry` | SIGINT after publication keeps the profile launch (`configured`) and rerun resumes to `verified`; SIGKILL during the witness recovers; an early interruption is undone without touching the entry |

See the [profile onboarding evidence](evidence/PROFILE_ONBOARDING_2026-10-20.md).

## Limits

- Linux, local user, no service. Other identity modes and platforms are refused or unsupported.
- One selected server per onboarding: a plain native-admission server, or the
  original filesystem or Git server under its accepted read-only profile. No
  arbitrary server, resource executor, multi-server transaction or shared-host
  delegation is configured; a scoped two-server host session is a separate launcher.
- Without a profile, the connection wrapper does not pass classifier settings to
  the host collector; host calls are admitted by the daemon policy and registry.
  With a profile, the collector classifies with the owned classifier copy. The
  rule baselines have known gaps (for example `directory_tree` stays unknown/Ask);
  they are reported, not relabelled.
- Undo removes only entries recorded during apply. Runtime files the Agent writes
  later, while you use it, are preserved and reported as a conflict; review and
  remove them, then run undo again.
- The legacy Claude HTTP hook still fails open; onboarding neither configures
  hooks nor claims coverage for them.
