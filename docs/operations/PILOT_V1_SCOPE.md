# Linux pilot v1 scope (`linux-v1`)

The v1 Linux pilot is **one** supported configuration: native Ubuntu 24.04 x86_64 as an ordinary
user, the pinned Claude Code 2.1.251 host, the original reviewed filesystem and Git MCP
servers, the existing rule baseline and explicit enforcement. This guide freezes that scope as a
versioned descriptor, [`profiles/pilot/linux-v1/scope.json`](../../profiles/pilot/linux-v1/scope.json)
(`sw-pilot-scope/1`), and wires it through the existing installed entry points. It is release-scope
integration: not another launcher, policy engine or readiness framework. The descriptor selects
and describes; it **never grants authority, adds a capability or certifies acceptance**, and
missing external acceptance remains `NOT_READY` rather than an approval.

## Select the scope

```sh
agentfw pilot preview --prefix "$PREFIX" --scope linux-v1 ...      # reports scope.selected and scope.refused
agentfw pilot prepare --apply --prefix "$PREFIX" --scope linux-v1 ...
agentfw pilot run --prefix "$PREFIX" --scope linux-v1              # asserts the prefix was prepared inside the scope
agentfw pilot status --prefix "$PREFIX"                            # always reports the scope state
```

The same options work from a checkout as `python3 -B scripts/pilot.py ...`. Selection is explicit and
opt-in: without `--scope` the front door behaves exactly as before and reports
`scope.state: unselected` with nothing claimed. Once a prefix is prepared with `--scope linux-v1`
the choice is recorded in its private `front-door.json` with the descriptor's SHA-256 and is sticky: a
later `prepare` of that prefix keeps enforcing it, and a prefix never changes scope silently.

When the scope is selected:

* **Excluded options refuse before execution.** `--git-profile` other than `git-readonly-v1`,
  `--git-worktree-binding`, `--filesystem-roots-binding` and `--workspace-snapshot` stop `prepare` with
  `scope_excludes_capability` before any directory, download, build or selection step; `preview` lists them
  under `scope.refused` and in `missing`.
* **A nonconforming selection refuses.** The prepared selection is checked against the descriptor before
  it is recorded and again before every `run` (`scope_selection_nonconforming`): the policy, both
  classifiers, both profile formats/policies/registries and the Git profile binding must be the v1
  ones, with no multi-root, linked-worktree or snapshot extension. A changed descriptor refuses with
  `scope_document_changed`; a drifted binding in the accepted sources refuses with `scope_binding_changed`.
  All of this happens before a daemon, host or server starts.
* **Status says what it observed.** `status` reports `scope.state`
  (`unselected`, `conforming`, `nonconforming`, `document-changed`, `unavailable`, `not-evaluated`) and
  `scope.mode` (`enforce` only for a live run of this exact selection that answered the authenticated
  enforce-requiring query, otherwise `not-running`, `unavailable` or `not-configured`). Shadow is outside
  the scope: a daemon that is not enforcing fails that query and is reported `unavailable`, never
  protection. `scope.qualification` is always `unqualified`: the scope itself claims no acceptance.

## Supported operations

Filesystem (8): `get_file_info`, `list_allowed_directories`, `list_directory`, `list_directory_with_sizes`, `read_file`, `read_multiple_files`, `read_text_file`, `search_files`.
Git (6): `git_diff`, `git_diff_staged`, `git_diff_unstaged`, `git_log`, `git_show`, `git_status`.

Each is a conditional Allow: it needs the pinned schema, bounded arguments, the selected root,
classification and result inspection. A valid read never becomes a write. Everything else the selected
registries expose is refused before execution:

| Server | Operations | Why |
| --- | --- | --- |
| filesystem | `create_directory`, `edit_file`, `move_file`, `write_file` | The selected read-only profile has no dispatch for effect tools; policy additionally hard-denies the recognized effect classes before execution. |
| filesystem | `read_media_file` | Media reads have no result profile in the selected registry; unsupported by the selected profile. |
| filesystem | `directory_tree` | Known classifier-coverage gap: the call is unknown, policy Ask, and the collector refuses it. It is not an authorized operation. |
| git | `git_add`, `git_branch`, `git_checkout`, `git_commit`, `git_create_branch`, `git_reset` | Git mutation and branch enumeration have no dispatch in the selected read-only profile; policy additionally hard-denies the recognized effect classes. |

## Support matrix

Every path is supported, conditional or explicitly unsupported, with its fail mode. This table is generated from the
descriptor and checked against it by `scripts/tests/test_pilot_scope.py`.

<!-- scope-matrix:begin (generated from profiles/pilot/linux-v1/scope.json) -->

| Area | Item | State | Fail mode | Entry / note |
| --- | --- | --- | --- | --- |
| platform | Native Ubuntu 24.04 x86_64, ordinary non-root user | **supported** | refused-before-execution | agentfw pilot preview\|prepare\|run\|status |
| platform | WSL2 Ubuntu | **unsupported** | refused-before-execution | native_ubuntu_required_wsl_is_separate; a separate WSL flow has its own scope |
| platform | macOS and Windows | **unsupported** | refused-before-execution | Separate native guides; the Linux pilot refuses them |
| platform | Other distributions, architectures or root | **unsupported** | refused-before-execution | ubuntu_24_04_required, non_root_operator_required |
| host | Claude Code 2.1.251 from the locked package (npm ci --ignore-scripts) | **supported** | refused-before-execution | pilot prepare pins and verifies the host image; version mismatch refuses |
| host | Other Claude Code versions and other agent hosts | **unsupported** | not-selected-by-this-scope | Never selected; no authority is inferred |
| transport | stdio MCP through the original reviewed filesystem and Git servers | **supported** | refused-before-execution | Selected profiles with pinned package, runtime and library identities |
| transport | Other MCP transports and unreviewed servers | **unsupported** | not-selected-by-this-scope | Not part of the selection; unknown tools are refused |
| tool-family | Filesystem reads and listings (8 operations) | **supported** | hard-deny-before-execution | Allow only after pinned schema, bounded arguments, workspace, classification and result inspection |
| tool-family | Git status, log, diff and show (6 operations) | **supported** | hard-deny-before-execution | Same conditional Allow with the exact bounded Git arguments |
| tool-family | Filesystem writes and Git mutations | **unsupported** | hard-deny-before-execution | Refused before execution; no approval downgrade |
| tool-family | Network, delete and privilege-changing actions | **unsupported** | hard-deny-before-execution | Hard Deny before execution |
| enforcement | Explicit enforcement | **supported** | reports-unavailable-never-protection | Reported only by an authenticated enforce-requiring query of a live run of this selection |
| enforcement | Shadow (observe-only) mode | **unsupported** | not-selected-by-this-scope | The pilot is never prepared in shadow mode and shadow is never reported as protection |
| enforcement | Single-use exact-call Ask approval | **conditional** | opt-in-restricts-or-operates-only | --ask-wait-seconds (up to 25) with agentfw pilot-approval inspect, then one exact decision |
| provider | Owned scripted loopback provider for qualification | **supported** | not-selected-by-this-scope | Synthetic data; no model account or paid call |
| provider | Operator-supplied live provider | **conditional** | opt-in-restricts-or-operates-only | Named provider profiles; live-model effectiveness is not measured or claimed |
| operator-controls | Project presets, maintenance mode, resource-budget presets, policy candidates and activation, configuration recovery, update coordination | **conditional** | opt-in-restricts-or-operates-only | Opt-in lifecycle or restriction-only controls with their own focused qualification; none widens the v1 authority |
| capability | Other Git capability profiles (file revisions, local refs, shallow, local clone, tracked symlinks) | **unsupported** | refused-before-execution | --git-profile other than git-readonly-v1 is refused when this scope is selected |
| capability | Linked-worktree Git profile | **unsupported** | refused-before-execution | --git-worktree-binding is refused when this scope is selected |
| capability | Multi-root read-only filesystem profiles | **unsupported** | refused-before-execution | --filesystem-roots-binding is refused when this scope is selected |
| capability | Private workspace snapshots and file links | **unsupported** | refused-before-execution | --workspace-snapshot is refused when this scope is selected |
| capability | Private edit, create-file and HTTPS executors | **unsupported** | not-selected-by-this-scope | Separate opt-in profiles; never selected by the pilot front door |
| surface | Gateway, Console, identity and storage backends | **unsupported** | not-selected-by-this-scope | Outside the local Linux pilot |

<!-- scope-matrix:end -->

Named project presets are one of those conditional controls: `agentfw pilot project check` labels the preset's selection
with `scope_conformance` (`conforming`, `nonconforming` or `unavailable`) but does not enforce a scope, because a preset is
not a scope selection. A preset whose selection is not `conforming` is outside v1.

Conditional rows are opt-in controls with their own focused qualification. They do not widen the v1
authority and are not part of the frozen claim; selecting the scope does not require them and does not
silently enable them.

## Bound identities

The descriptor binds, and the loader recomputes on every use from the accepted sources, so drift refuses instead of
being trusted:

| Binding | Value |
| --- | --- |
| Installed front-door policy (`scripts/qualify-installed-pilot.py:PILOT_POLICY`) | `dba24a1b419040d5f5dad62dfd485db6637c9359f37b9642f458101793062dbc` |
| Filesystem classifier (`rule_baseline/rule_baseline.py`) | `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd` |
| Git classifier (`rule_baseline/git_readonly_v1/rule_baseline.py`) | `8a57c58d5bad5b8b2572ac7a5b6a85ba068f97482d12b4a60e94302bad318474` |
| Filesystem profile `filesystem-readonly-v1`: registry / profile policy | `63d12de143f0f13a7ef63ad0271697ad8d29fcac66b8ccfa7a68ba8f94431de7` / `55b0f70c4e7a59a4668eb83189ab6b1fbb7865f8b3baa5ef4a0f29c7db015eec` |
| Git profile `git-readonly-v1`: registry / profile policy / selection binding | `5e22a49a07329335f42f95a48a969c869b5ba84fffcc2739f21a3a70c6437385` / `788a52b8c5159cb40f6ccc2752ad1c9920cd94d55029f1aa81880bc3d7b5a67c` / `693d13f29d8d169871085b47e4469cd95bbc49ee44ef3688fbe83f73f79f8512` |
| Claude Code 2.1.251 locked package | `6eb6fd9ccda39b10b4cd21e3236fa179330ce4252a3405f193093722be3668e6` |
| Node 22.23.4 archive | `1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce` |

The installed entry points select the front-door policy above. The separately documented
[`linux-readonly-v1` preset](LINUX_PILOT_POLICY.md) (policy `8a8a8f7e7147a977...`)
is a recipe for the individual-server acceptance commands; it is **not** what `agentfw pilot` selects and the scope does not
claim it. `python3 -B scripts/pilot_scope.py --check` recomputes every binding and verifies the descriptor and this guide.

## What this scope does not claim

* No universal-firewall claim: it covers the selected calls of the two original read-only servers on this
  platform, not arbitrary agent behavior, other tools, hosts or platforms.
* No live-model effectiveness claim: qualification uses an owned scripted loopback provider and synthetic data.
* No acceptance: exact-source qualification evidence is separate, retained with failures, and shared Ready CI,
  security review and admission remain maintainer-owned. Missing external acceptance remains `NOT_READY`.

## Qualification

`scripts/qualify-pilot-scope.py` (focused workflow mode `installed_focus: pilot-scope`) runs the selected scope through the
installed commands outside the checkout and reuses the existing acceptance commands: the installed front-door driver
for preview/prepare/status/refusal and useful filesystem and Git reads with refused effects, then
`scripts/qualify-installed-pilot.py --run` and the first-use demo `scripts/pilot-demo.py --run` against the
scope-selected generation for independent zero-effect witnesses, the explicit single-use Ask control, daemon loss and cleanup. It also proves that an excluded capability refuses with zero starts and that status separates
enforce, unavailable and unqualified. Failed or incomplete attempts are retained, not rewritten.
