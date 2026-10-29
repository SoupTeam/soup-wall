# Offline pilot workspace compatibility

`agentfw pilot-workspaces` inspects two explicitly selected roots without starting
Git, helpers, a daemon, the MCP servers or a model. It does not repair the project,
change permissions, download anything or contact remotes. The caller receives one
bounded JSON report even when compatibility cannot be established.

```sh
agentfw pilot-workspaces --workspace /owned/files --git-workspace /owned/repository
agentfw pilot-workspaces --workspace /owned/files --git-workspace /owned/repository \
  --git-profile-kind local-clone
```

Select existing canonical absolute roots. Inspection does not create them. The
default remains the original `sw-mcp/git-readonly/1` grammar. Passing inspection
does not authorize launch from a cached report: protected startup and each
profile's runtime checks remain authoritative. This command does not verify
installed assets, sandbox enforcement, storage recovery or live-model protection.
It does not implement the guided CLI.

## Versioned response

Format: `sw-pilot-workspace-inspection/1`. The accepted `--git-profile-format` remains available for all six reviewed formats.
`--git-profile-kind` is an optional short spelling and conflicts with an explicit
format; neither field can combine capabilities. Fields are additive to the previous
success response: `status: supported-read-only` and `executed: false` remain.

| Field | Meaning |
| --- | --- |
| `state` | `supported`, `conditional`, `unsupported` or `unavailable` |
| `profile` | Selected filesystem/Git format, compiled validator-contract digest, identity kind and `installed_assets_verified: false` |
| `checks` | Bounded checked conditions, fixed role/category, state, finite reason code or null, and a safe English next action |
| `executed` | Always false: no tool/helper execution |
| `launch_authorized` | Always false |
| `runtime_protection_verified` | Always false |
| `revalidate_at_launch` | Always true |

Exit 0 means layout-compatible (`supported` or explicitly `conditional`). This
preserves existing preparation callers selecting a reviewed format. A conditional
result still requires the selected runtime proof and cannot authorize launch.
Unsupported and unavailable return nonzero (currently 1), after the JSON report. Argument parsing
retains clap's usage errors. An incomplete inspection dominates other partial
findings. A refused root has no implied passing checks for its descendants.

The digest identifies the compiled validator sources and selected format, not an
installed runtime profile or its policy. No absolute root, arbitrary filename,
config value, file content, remote URL, credential or underlying error is printed.
The schema never incorporates untrusted error text or filenames into next actions.

Examples below are abbreviated shapes, not measured runtime evidence:

```json
{"format":"sw-pilot-workspace-inspection/1","state":"supported","status":"supported-read-only","executed":false,"launch_authorized":false}
```

```json
{"role":"git","check":"selected_production_repository_validator","state":"unsupported","reason":"git_config_unsupported","next_action":"Select a separate repository compatible with the chosen profile; inspect the reported category without executing helpers or repairing this repository."}
```

```json
{"role":"git","check":"source_stable_across_inspection","state":"unavailable","reason":"source_changed","next_action":"Stop concurrent writers and repeat inspection; never reuse this result for launch."}
```

## Authority, profiles and limitations

The command calls the existing `sandbox::validate_workspace_path` and selected
production Git repository validator. There is no second Git/config parser.
Canonical/operator-owned roots without group/other writes are required. A
conservative metadata guard refuses special files and shared-write entries. Links
are refused except Git links under the explicitly selected tracked-symlinks
profile, where the existing production graph validator remains authoritative; a filesystem profile may support individual operations
on a wider tree, but this inspector cannot report a fully checked tree for it.

| Selected kind | Offline result when layout passes |
| --- | --- |
| `v1` | Supported for original narrow repository compatibility only |
| `local-clone` | Conditional: production layout/config/attributes checks pass, but protected runtime index/object proof is still required |
| `local-refs`, `file-revisions` | Conditional: selected production layout validator passes; runtime object/view proof remains mandatory |
| `shallow` | Conditional: production shallow layout validator passes; bounded shallow object/view proof remains mandatory |
| `tracked-symlinks` | Conditional: production link graph/layout validator passes without following links; runtime index/object proof remains mandatory |

No profile activation or new Git semantics are introduced. In particular,
ordinary-clone remote metadata cannot turn inspection into a network operation,
and a local-clone success is not substituted for the default v1 refusal.

Finite diagnostics include:

| Category | Reason codes |
| --- | --- |
| Host/roots | `native_linux_required`, `canonical_root_required`, `owned_private_root_required` |
| Permissions/types | `shared_write_access`, `unsafe_link_or_special_file` |
| Git layout | `git_standalone_required`, `git_worktree_indirection_unsupported` |
| Attributes/submodules | `git_attributes_unsupported`, `git_submodules_unsupported`, `git_nested_attributes_or_submodules` |
| Objects/profile | `git_object_indirection_unsupported`, `git_shallow_requires_selected_profile`, `git_local_metadata_unsupported`, `profile_not_inspected_offline`, `selected_profile_requires_runtime_proof` |
| Configuration/hooks | `git_config_unsupported`, `git_hooks_unsupported` |
| Incomplete inspection | `inspection_bound_exceeded`, `source_changed`, `inspection_io_unavailable`, `validator_unavailable` |

Unknown production failures map to unavailable, not success. Existing production
limits remain unchanged. Inspector metadata snapshots separately cap each tree
at 32 levels, 32,768 entries including the root, 4 MiB aggregate relative-path
bytes and 4,096 bytes per relative path. At most two initial snapshots plus one
comparison snapshot are retained; output contains no entry inventory. The report
has at most six conditions. Only production validators read bounded control
files; the stability guard reads metadata, not ordinary file contents.

The accepted response field `git_profile_format` is retained alongside the bounded
profile identity. No caller must infer a format from repository data.

Linux roots and traversal directories are pinned by descriptors without following
symlink components. Before/after identity, mode, ownership, size and mtime/ctime
checks refuse observed concurrent changes, including replacing a selected root.
The original v1 validator reuses the existing local-clone descriptor/bounded-read
primitives to avoid following a swapped `.git` directory while reading config.
Access-time changes caused by filesystem reads are not an asserted invariant.
This is a non-atomic observation of a live filesystem, not a snapshot lease:
changes after inspection always require fresh protected-runtime validation.

## Production selection is a separate contract

Preparation and `pilot-run` use the internal `--validate-selection` spelling of
`pilot-workspaces`. It preserves the accepted production question: whether the
canonical owned roots and the explicitly selected Git profile can be selected.
It reuses the same descriptor-pinned root check and production Git validator,
and checks root stability before returning. It does not inventory every filesystem
leaf. Its distinct `sw-pilot-workspace-preflight/1` response explicitly says
`inspection_complete: false`, `launch_authorized: false` and
`runtime_protection_verified: false`.

This distinction matters for a project containing an outside symlink: default
full inspection still refuses it with `unsafe_link_or_special_file`, while the
existing runtime can select the root and independently refuse attempts to access
that leaf. The preflight never authorizes a path, grants a tool, changes policy or
reuses a cached inspection. Protected profile/startup and per-call checks remain
mandatory. A guided inspector consumer must require the inspection format and
must not treat the preflight as a complete inspection report.

The original six CLI witnesses keep their expected states. An additional
`selection-preflight` syscall witness checks the separate root contract with the
same symlink fixture, without opening the outside target or claiming inspection.

## Focused verification

Run on an owned Linux checkout with Rust and `strace` already available:

```sh
cargo fmt --all -- --check
cargo test --locked -p agentfw --lib pilot_workspaces
cargo test --locked -p agentfw --lib mcp::server_profile::git
cargo build --locked -p agentfw --bin agentfw
python3 -B -m unittest discover -s scripts/tests -p test_pilot_workspace_witness.py -v
python3 -B scripts/check_pilot_workspaces.py --agentfw target/debug/agentfw \
  --expected-commit "$(git rev-parse HEAD)" --output /tmp/sou144-witness-new
```

Use a new output directory. The driver creates only synthetic fixtures in an
owned temporary directory. Independent before/after file-content/metadata
snapshots, helper traps and syscall tracing check zero helper/child, network and
write/repair attempts by the inspected executable. The driver's fixture setup,
Git source lookup, tracing and report output are outside the inspected process.
The command is not run against an operator's project. Missing Linux/strace or a
failed case produces a retained incomplete report and non-passing exit; no skip
becomes success. Raw temporary traces are not published; only hashes and finite
counts are retained. The report records source, driver and binary identities;
retain the exact build command with it to establish binary provenance.

[Development evidence and current blockers](evidence/sou144/README.md).
