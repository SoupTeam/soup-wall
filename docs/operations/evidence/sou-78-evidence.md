# SOU-78: Transactional Installed MCP Profile Upgrades and Rollback Without Stale Authority

## Handoff and current acceptance status (2026-10-18)

**INCOMPLETE — not ready for acceptance.** Antigravity session
`d78c8d26-227d-4173-9898-649c2b3ba413` stopped after step 9046 because its
provider quota was exhausted. Base commit: `2b8185a`; seven pre-existing dirty
files were preserved. The latest added absent-config witness initially failed:
its recorded process had no responding health endpoint. It now checks the
ownership validator directly with mismatched and matching baseline controls.

Continuation adds exact-preview approval (generic `yes` rejected), same-server
binding, reconstruction of compiled authority from reviewed source/declarations,
resource-manifest verification, bounded state reads and recovery-path validation.
Test bundles now use the production inert compiler rather than fabricated review
metadata. Unknown Agent YAML fields already fail closed under the strict config
schema; supported unrelated settings have a regression control.

Remaining Linear acceptance gaps:

- Transactional integration with an existing owned Linux Claude Code connection,
  including publication/ownership journal and preserving unrelated host entries.
- Runtime profile-generation binding and independent stale grant/receipt/Ask
  witnesses. A monotonic number in profile-state.json alone is insufficient.
- Preserving authenticated host taint/incomplete-history floors across transitions;
  restarting the daemon currently loses in-memory history.
- Real Linux daemon/collector upgrade, rollback and injected-crash exercise with
  useful reads, removed-authority refusal and independent zero-execution ledgers.
- Pending-host-restart reporting and Linux service-specific witnesses. Upgrade and
  rollback CLI dispatch now explicitly refuses macOS/Windows before mutation.

Final continuation checks on macOS:

- `cargo test --offline --locked --workspace --all-features`: **1417 passed,
  0 failed, 11 ignored** across 61 completed test suites.
- `cargo clippy --offline --locked --all-targets --all-features --workspace -- -D warnings`:
  **PASS, zero warnings**.
- `cargo fmt --check`: **PASS**.
- Test export byte-compared against all 843 tracked non-documentation source
  inputs. Exact snapshot and changed-Rust hashes are retained in
  `sou-78-continuation-2026-10-18.json`.
- The first full run hit three self-test environment failures because the
  sandbox refused `/bin/ps`. A narrow exception for that trusted read-only
  executable restored the process cleanup witness; the final full run passed.
  Target code remained unable to write to the repository or use external network.
- These are local source checks, not Linux runtime acceptance or CI evidence.

Status output now separates configured state, managed daemon configuration
verification, stopped/unavailable runtime, conflict and incomplete recovery.
Host reload remains explicitly `unverified`.

No PR exists for this branch at this checkpoint. No release or completion claim.

## Historical Antigravity evidence (before continuation; not current-head proof)

## Overview

Issue **SOU-78** delivers transactional installation, upgrade, rollback, status inspection, and crash recovery for operator-authored MCP profiles (`agentfw mcp-profile`). It builds on the inert authoring primitives from SOU-65 and provides end-to-end transactional lifecycle guarantees, zero stale authority across upgrades and rollbacks, atomic `config.yaml` updates, and automatic baseline restoration upon daemon failure.

Implementation was developed in pair-programming collaboration with local Codex (`~/.local/bin/codex`), strictly adhering to Test-Driven Development (TDD) and clean-tree verification.

---

## 1. Scope & Implementation Matrix

| Component | File | Changes & Guarantees |
|---|---|---|
| Core Types & Bundle Verification | `crates/agentfw/src/mcp/profile_lifecycle.rs` | Implemented `bundle_digest`, `verify_bundle_files`, `ProfileState`, `OperationRecord`, `OperationJournal`, and `InstalledRecord`. Enforces safe paths, non-symlink verification, bounded file size, and deterministic SHA-256 calculation across all 6 bundle files. |
| Transaction Lifecycle Engine | `crates/agentfw/src/mcp/profile_lifecycle.rs` | Implemented `ProfileManager` with `install`, `upgrade`, `rollback`, `status`, and `recover`. Coordinates immutable bundle staging under `revisions/<bundle-sha256>/`, atomic write of `config.yaml`, advisory file locking, and monotonic generation authority. |
| Semantic Diff Integration | `crates/agentfw/src/mcp/profile_author.rs` | Extracted `compute_profile_diff` and `ProfileDiffSummary`. `upgrade` and `rollback` check for authority changes and enforce `--accept-diff` confirmation. |
| CLI Dispatch | `crates/agentfw/src/mcp/profile_author.rs` & `crates/agentfw/src/main.rs` | Wired `Install`, `Upgrade`, `Rollback`, `Status`, and `Recover` subcommands under `agentfw mcp-profile` with optional `--home` routing. |
| Integration Test Suite | `crates/agentfw/tests/mcp_profile_lifecycle.rs` | End-to-end CLI lifecycle test, zero stale authority monotonicity test, and crash recovery test. |
| Operations Documentation | `docs/operations/MCP_PROFILE_LIFECYCLE.md` | Comprehensive operational guide covering bundle layout, zero stale authority, atomic config updates, crash recovery, and CLI usage. |
| Release Notes | `CHANGELOG.md` & `docs/ROADMAP.md` | Documented SOU-78 capabilities, generation monotonicity, and crash resilience. |

---

## 2. Invariants & Security Guarantees

1. **Zero Stale Authority (Strictly Monotonic Generation):**
   - Every activation (`install`, `upgrade`, `rollback`) increments `generation: u64` monotonically.
   - Rolling back to an identical prior byte revision advances generation from $N$ to $N+1$, preventing any lingering collector or client session from presenting stale or replayed authority.
   - Stale generation tokens presented with `--expect-generation` fail closed.

2. **Immutable Revisions Repository:**
   - Bundles are staged into content-addressed directories `<HOME>/.agentfw/mcp-profiles/revisions/<bundle-sha256>/`.
   - Staging directory is created with `0700` permissions; files are written with `0600` permissions and fsync before atomic rename.
   - Revisions are read-only and immutable; existing revisions are validated before reuse.

3. **Atomic Configuration Updates:**
   - `config.yaml` is updated via a temporary file in `self.home`, fsynced, permissions set to `0600`, and atomically renamed to `config.yaml`.
   - Automatically configures `native.registry_path` pointing to the staged `registry.json` and `native.registry_sha256`.

4. **Crash Resilience and Automatic Compensation:**
   - Durable journaling records operation state before mutating configuration or daemon.
   - If the candidate profile causes daemon startup failure or fails health verification, the engine automatically rolls back `config.yaml` to the previous healthy baseline and restarts the previous daemon before reporting an error to the operator.
   - Interrupted transactions can be reconciled at any time via `agentfw mcp-profile recover`.

5. **Mutual Exclusion:**
   - Advisory locking (`.lock`) via non-blocking `try_lock()` prevents concurrent mutation across multiple CLI sessions.

---

## 3. Verification Evidence

### Unit Tests
```text
running 11 tests
test mcp::profile_lifecycle::tests::profile_state_serde_roundtrip ... ok
test mcp::profile_lifecycle::tests::bundle_digest_fails_on_missing_file ... ok
test mcp::profile_lifecycle::tests::bundle_digest_computes_deterministic_sha256 ... ok
test mcp::profile_lifecycle::tests::bundle_fails_when_tool_authority_tampered_in_registry ... ok
test mcp::profile_lifecycle::tests::bundle_digest_fails_on_symlink ... ok
test mcp::profile_lifecycle::tests::recover_preserves_journal_on_foreign_config_when_initial_was_absent ... ok
test mcp::profile_lifecycle::tests::bundle_digest_fails_on_cross_file_mismatch ... ok
test mcp::profile_lifecycle::tests::profile_manager_cas_rejects_concurrent_config_mutation ... ok
test mcp::profile_lifecycle::tests::profile_manager_crash_recovery_restores_config ... ok
test mcp::profile_lifecycle::tests::upgrade_fails_when_active_registry_externally_superseded ... ok
test mcp::profile_lifecycle::tests::profile_manager_lifecycle_install_upgrade_rollback ... ok

test result: ok. 11 passed; 0 failed; 0 ignored; 0 measured; finished in 0.49s
```

```text
running 3 tests
test mcp::profile_author::tests::privileged_names_cannot_be_relabelled_read_only ... ok
test mcp::profile_author::tests::imported_tools_remain_unreviewed ... ok
test mcp::profile_author::tests::run_dispatches_lifecycle_status_and_recover ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; finished in 0.00s
```

### Integration Tests (`tests/mcp_profile_lifecycle.rs`)
```text
running 3 tests
test zero_stale_authority_monotonicity ... ok
test crash_recovery_restores_clean_baseline ... ok
test cli_mcp_profile_lifecycle_e2e ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; finished in 1.33s
```

### Formatting & Linting
- `cargo fmt --all -- --check`: **PASS (exit code 0)**
- `cargo clippy --workspace --all-features --all-targets --locked -- -D warnings`: **PASS (exit code 0, 0 warnings)**

---

## 4. Codex Review Resolution
1. **Binding Approval to Actual Registry Authority:**
   - Bundles are validated using production `NativeState::from_bytes`.
   - Every tool in `registry.json` is cross-verified against `profile.json`, checking that `digest(tool_entry) == authority_sha256`, `action_class`, `result_provenance`, and `schema_sha256`. Any subtle modification of authority in `registry.json` fails bundle verification immediately.
2. **Crash Recovery Baseline Daemon Restart:**
   - Evaluates whether daemon was running or stopped; uses `restart_or_start_daemon` so it correctly starts if the candidate daemon exited or cleared process state.
   - Verifies the running process's `config_digest` matches the baseline digest before declaring recovery success.
3. **Supersession Checks Before Automatic Compensation:**
   - During failure rollback in `install`, `upgrade`, and `rollback`, verifies current on-disk `config.yaml` digest matches target before restoring baseline. If modified externally, refuses to overwrite and retains failed journal.
4. **Active Registry Supersession Check:**
   - `upgrade` and `rollback` check that `config.yaml`'s `native.registry_path` and `registry_sha256` still match the active bundle on disk; foreign configuration modifications fail closed with conflict.
5. **Lifecycle Ownership Coordination:**
   - Coordinates `lifecycle.lock()` during journal creation and `config.yaml` write; checks post-write status to detect any concurrent start.
