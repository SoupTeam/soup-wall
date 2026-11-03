# SOU-204 schema upgrade analyzer evidence (2026-11-03)

Evidence for [Offline MCP schema upgrade review](../../MCP_SCHEMA_UPGRADE_REVIEW.md).
All observations come from one Windows 11 x64 host (non-elevated) with rustc
1.99.1. The files below are stored verbatim (`-text`).

| File | Content |
| --- | --- |
| [`evidence.json`](evidence.json) | Source binding, accepted dependencies, protected files, 32 demonstration scenarios |
| [`windows-trace.json`](windows-trace.json) | Execution-level process/Winsock trace, with positive controls |
| [`profile-lifecycle-comparison.txt`](profile-lifecycle-comparison.txt) | Historical: parallel agentfw lib suite at the accepted base vs head |
| [`agentfw-lib-sequential.log`](agentfw-lib-sequential.log) | Complete raw output of one sequential agentfw lib suite run on the final code |
| [`runs/`](runs/) | Complete outputs of 13 scenarios |

## Source binding

- **Changed files** (`source.changed_files_git_blob`): the line-ending-normalized
  git blob id (`git hash-object --path`) of each of the 41 files that differ
  from base `b385e7506ab26896637f348e3180e52d1fc6d423` or are new. These ids are
  platform-independent and equal `git rev-parse <commit>:<path>` in the commit
  that contains this evidence. The combined manifest digest (SHA-256 over
  `path\0blob\n` lines) is
  `b0d8c6496ef9e79adfd78bf8f57e6ae37ba6b9721df6fde28d4c7519209c31d6`.
  `source.working_tree_sha256` is informational only: on this Windows checkout
  (`core.autocrlf=true`) four pre-existing files have CRLF working copies.
  The evidence was generated before the commit, when HEAD was still the base.
  This directory is excluded, so there is no circular self-hash.
- **Unchanged accepted dependencies** (`accepted_dependencies`): 25 inputs the
  analyzer, fixtures or demonstration rely on. These are the snapshots,
  identities and notices, the SOU-65 pair, the pilot manifest, both installers
  and `pilot_provider.py`, the reused Rust modules, and the Cargo and toolchain
  files. Each is checked with read-only git: `git rev-parse <base>:<path>`
  equals `git hash-object --path=<path>`, and `git diff --quiet` passes. All 25
  are unchanged and are anchored by the base revision.
- **Reproduced registries:** the output of the accepted installer `registry(…)`
  functions. The filesystem installer has git blob `7e1d44ab…`; the Git
  installer has git blob `52e67a45…` and is called with all three capability
  flags `False`. Both blob ids equal the base blobs. They are **reproduced, not
  observed installed operator state**.
- **Binary:** `target/debug/agentfw.exe`, SHA-256
  `53932b344f22bcaa666480e0e7e20f3dd071486ab8afa2842dab5a46b6991f92`. The
  demonstration and the trace used the same binary. It is a debug build.

## Demonstration: 32 of 32 PASS

Each scenario ran twice with identical results. HOME/USERPROFILE and cwd were
fresh, empty directories and were never written. The protected files were
unchanged, and the real `~/.agentfw` did not exist.

| Scenario | Exit | Classification / refusal | `byte_identical` | Findings |
| --- | --- | --- | --- | --- |
| `fs-identical`, `git-identical`, `operator-authoring-declarations` | 0 | byte_identical | true | 0 |
| `declaration-only-control` (proposed = current registry) | 0 | byte_identical | true | 0 |
| **`declaration-only-drift`** (synthetic proposal changes one `action_class`) | **5** | **review_required** | **true** | 1 (`declared_action_changed`) |
| `fs-keys-reordered` | 5 | raw_bytes_differ_identities_equal | false | 0 |
| `fs-tools-reordered` | 5 | inert_metadata_only | false | 1 |
| `fs-metadata-inert` / `git-metadata-inert` | 5 | inert_metadata_only | false | 4 / 3 |
| `fs-malicious-metadata` | 5 | review_required | false | 5 |
| `fs-tools-added-removed` | 5 | review_required | false | 4 |
| `fs-required-default-type-enum` | 5 | unsupported_present | false | 14 |
| `fs-nested-array` | 5 | review_required | false | 7 |
| `fs-result-capability` | 5 | review_required | false | 3 |
| `fs-destination-controls` / `…-declared` (synthetic control declarations) | 5 | unsupported_present | false | 8 / 11 |
| `fs-unsupported` | 5 | unsupported_present | false | 12 |
| `git-semantic` / `snapshot-only-git-semantic` | 5 | unsupported_present | false | 17 / 10 |
| `git-extreme-bound` (after `maxLength` = u64::MAX) | 5 | unsupported_present | false | 3 |
| `extreme-bound-before-snapshot-only` (before `maxLength` = u64::MAX) | 5 | review_required | false | 1 |
| `git-recursive-ref` | 5 | unsupported_present | false | 6 |
| `invalid-*` (5), `control-missing-declarations`, `control-identity-mismatch`, `control-stale-registry`, `control-oversized`, `extreme-bound-before` (with registry) | 2 | duplicate_json_member, duplicate_tool, malformed_json, incomplete_snapshot, depth_exceeded, missing_declarations, identity_digest_mismatch, declaration_binding_mismatch, input_too_large, declaration_binding_mismatch | – | – |

Every `fs-*`/`git-*` upgrade, `invalid-*`, `extreme-*` and `control-*` input,
and every proposed registry, is a labelled synthetic mutation (see the fixture
`MANIFEST.json`).

## Side effects: separated by kind of evidence

| Kind | What was shown | Scope |
| --- | --- | --- |
| Source inspection | Unit test `analyzer_source_has_no_process_network_or_install_path` | Static text of the three analyzer modules |
| Execution-level instrumentation | `windows-trace.json`, 8/8 PASS. Each of six analyzer runs (two valid declaration-bound, malicious metadata, and three refusals) had 1 process creation, 0 child processes, 0 calls to the 14 trapped ws2_32 entry points, and no network provider DLL. Positive controls detected a socket+connect and a child process | Win32 debugger (`DEBUG_PROCESS`) and one-shot int3 breakpoints in ws2_32; non-elevated |
| Observed filesystem effects | The demonstration and CLI tests | Isolated HOME/cwd, protected-file and input digests |

**Not observed:** kernel-level or raw AFD networking, packets (no elevation),
and Linux/macOS.

## Review-pack records (exact, from `runs/`)

These come from `runs/fs-destination-controls-declared/review-pack.json`.
`registry:tools[10]` is the labelled **synthetic** control declaration, because
no accepted filesystem/Git declaration has destination selectors. A
declaration reference marks relevance; `adverse_under_current_declaration`
additionally requires a stated `contradiction`.

| Record | Arguments | `schema_validity` | `semantic_expectation` | `contradiction` |
| --- | --- | --- | --- | --- |
| `E-378e7391db071bc0` destination array | `{"destination":["sw-review-destination-1","sw-review-destination-2"],…}` | schema_valid | adverse_under_current_declaration | "registry:tools[10] declares the destination selector /destination against a single value in the before schema; the after schema admits several values through that one selector" |
| `E-e2c20d949c303503` new `/options` subtree | `{"options":{"notify":{"destination":"sw-review-placeholder"}},…}` | schema_valid | **unknown_requires_manual_review** (declaration cited for relevance only) | null |
| `E-2d20328ccc4a5bb8` type change at the declared selector | `{"destination":["sw-review-placeholder"],…}` | schema_valid | behavior_change_vs_before_schema | null |
| `E-d1db2d9a29af2ccd` before-schema scalar shape | `{"destination":"sw-review-placeholder",…}` | schema_invalid | rejected_by_schema | null |
| `E-9e18f3a552ec109b` `list_directory` | `null` | not_applicable | unknown (unsupported) | null |

`runs/extreme-bound-before-snapshot-only/review-pack.json` contains
`E-99eee244cdd9e84d`: `unconstructible`, `bound_edge`, "No finite bound edge
exists for this change." This input previously aborted the process with an
arithmetic-overflow panic.

Every record carries `runtime_enforcement: not_observed`,
`semantic_safety: not_established` and `human_approval: none`.

## Full agentfw library suite

### Sequential run on the final code (current)

Command: `cargo test --locked -p agentfw --lib -- --test-threads=1`. It ran
once, with output redirected to `agentfw-lib-sequential.log` and Cargo's exit
status captured separately (no pipe):

- exit status **0**;
- **790 tests: 788 passed, 0 failed, 2 ignored**, 0 filtered out, 141.92 s;
- all 44 `profile_lifecycle` tests passed.

The run used the final library and test code bound above. Afterwards only the
demonstration script's binding method changed (from working-tree SHA-256 to git
blob ids); no library or test source changed, so the log still applies.

This sequential pass does **not** show that the parallel flake below is fixed;
it only shows that every test passes when tests do not run concurrently.

### Parallel profile_lifecycle failures (historical, previous review round)

`profile-lifecycle-comparison.txt` (`cargo test --locked -p agentfw --lib`,
default parallelism) was recorded during the previous review round. The base
ran in a detached worktree at `b385e750` with its own target directory. No
change in any round touches `profile_lifecycle`.

| Configuration | Runs with failures |
| --- | --- |
| Accepted base | 4 of 6 |
| Head (previous round) | 3 of 3 |
| Head (previous round) with `--skip schema_upgrade` | 3 of 3 |

All captured failures say "agent port is occupied by an unowned process". The
flake reproduces at the accepted base; the samples are too small to compare
rates.

## Focused checks (final working tree)

| Check | Result |
| --- | --- |
| `python scripts/schema-upgrade-fixtures.py --check` | 26 fixtures current |
| `cargo test --locked -p agentfw --lib schema_upgrade` | 30 passed, 0 failed |
| `cargo test --locked -p agentfw --test mcp_schema_upgrade_cli` | 5 passed, 0 failed (19 manifest fixtures through the binary) |
| `cargo test --locked -p agentfw --lib profile_author` / `--test cli_startup` | 3 / 1 passed |
| `cargo test --locked -p agentfw --lib -- --test-threads=1` (full library suite, sequential, once) | exit 0; 788 passed, 0 failed, 2 ignored |
| `cargo +stable clippy --locked -p agentfw --all-targets -- -D warnings`; `rustfmt --check` | clean |
| Fixture and evidence byte round-trip (`git hash-object --path` vs `--no-filters`) | all equal |
