# SOU-78: Transactional Installed MCP Profile Upgrades and Rollback Without Stale Authority

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
running 6 tests
test mcp::profile_lifecycle::tests::profile_state_serde_roundtrip ... ok
test mcp::profile_lifecycle::tests::bundle_digest_fails_on_missing_file ... ok
test mcp::profile_lifecycle::tests::bundle_digest_fails_on_symlink ... ok
test mcp::profile_lifecycle::tests::bundle_digest_computes_deterministic_sha256 ... ok
test mcp::profile_lifecycle::tests::profile_manager_crash_recovery_restores_config ... ok
test mcp::profile_lifecycle::tests::profile_manager_lifecycle_install_upgrade_rollback ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; finished in 0.26s
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

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; finished in 1.28s
```

### Formatting & Linting
- `cargo fmt --all -- --check`: **PASS (exit code 0)**
- `cargo clippy --workspace --all-features --all-targets --locked -- -D warnings`: **PASS (exit code 0, 0 warnings)**
