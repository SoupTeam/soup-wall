# Transactional MCP Profile Lifecycle (SOU-78)

## Overview

`agentfw mcp-profile` provides transactional installation, upgrade, rollback, status inspection, and crash recovery for operator-authored MCP admission profiles.

While SOU-65 established inert profile authoring (`import`, `validate`, `explain`, `diff`, `compile`), SOU-78 manages the installed lifecycle of these profiles under `<HOME>/.agentfw/mcp-profiles/` and binds them to the active daemon configuration (`config.yaml`).

## Principles

1. **Immutable Revision Repository:**
   Compiled profile bundles (comprising the six required files: `native-config.json`, `operator-declarations.json`, `profile.json`, `registry.json`, `resource-profiles.json`, and `source-snapshot.json`) are staged under `<HOME>/.agentfw/mcp-profiles/revisions/<bundle-sha256>/` with restrictive permissions (`0700` directories, `0600` files). Once staged, revision bundles are strictly read-only and content-addressed.

2. **Deterministic Bundle Digest:**
   The bundle SHA-256 digest is computed deterministically over sorted bundle file entries:
   ```text
   SHA-256(
     "native-config.json:<sha256>\n" +
     "operator-declarations.json:<sha256>\n" +
     "profile.json:<sha256>\n" +
     "registry.json:<sha256>\n" +
     "resource-profiles.json:<sha256>\n" +
     "source-snapshot.json:<sha256>\n"
   )
   ```

3. **Zero Stale Authority (Strictly Monotonic Generation):**
   Every profile activation—including initial `install`, `upgrade`, and `rollback`—increments the state `generation: u64` monotonically. Even when rolling back to an identical prior bundle, the new activation receives a strictly greater generation (`N + 1`).
   When combined with the daemon's fresh `instance_id` generated upon restart, any lingering collector process, child proxy, or client attempting to present stale authority immediately fails closed.

4. **Atomic Configuration Updates:**
   Active profile selection is stored directly in `<HOME>/.agentfw/config.yaml` under `native.registry_path` and `native.registry_sha256`. Updates to `config.yaml` use atomic write-sync-rename patterns with private `0600` permissions.

5. **Crash Resilience and Automatic Rollback:**
   Operations are tracked in an atomic journal (`profile-state.json`) through distinct phases:
   - `Staged`: Bundle files copied to revision cache.
   - `ConfigWritten`: `config.yaml` atomically replaced.
   - `DaemonRestarting`: Daemon restarting and awaiting managed health verification.
   - `Verified`: Daemon attested matching new instance and config digest.
   - `RollingBack`: Reverting configuration due to candidate startup failure.
   - `Failed`: Operation failed and baseline was restored.

   If the daemon fails to boot or pass health verification after a profile change, the `ProfileManager` automatically rolls back `config.yaml` to the prior healthy baseline and restarts the daemon before returning an error to the operator.

6. **Advisory Locking:**
   All mutations are protected by an advisory lock (`.lock`) using `try_lock()` to prevent race conditions from concurrent CLI invocations.

## Operator CLI Reference

### 1. Install Initial Profile

```bash
agentfw mcp-profile install --profile /path/to/compiled-profile [--expected-bundle-sha <sha256>]
```
- Validates the bundle files.
- Stages the bundle in immutable revisions storage.
- Updates `config.yaml` to enforce native admission.
- Sets initial `generation: 1`.
- Fails closed if a profile is already active.

### 2. Upgrade Profile

```bash
agentfw mcp-profile upgrade \
  --profile /path/to/new-compiled-profile \
  [--expected-bundle-sha <sha256>] \
  [--expect-generation <u64>] \
  [--accept-diff <"yes"|sha256>]
```
- Compares new profile with active profile using semantic diff.
- If authority expands (new tools or changed authorities), requires explicit operator confirmation via `--accept-diff`.
- Increments generation monotonically.
- Restarts running daemon and verifies fresh instance attestation.
- Automatically reverts to previous profile if daemon startup fails.

### 3. Rollback Profile

```bash
agentfw mcp-profile rollback \
  [--revision <bundle-sha256>] \
  [--expect-generation <u64>] \
  [--accept-diff <"yes"|sha256>]
```
- Defaults to rolling back to `previous_bundle_sha256` if `--revision` is omitted.
- Advances generation monotonically (`N + 1`) to prevent replay attacks.
- Re-binds daemon `config.yaml` to the target revision.

### 4. Status

```bash
agentfw mcp-profile status
```
Outputs privacy-safe JSON with:
- Current `generation`.
- `active_bundle_sha256` and `previous_bundle_sha256`.
- Number of staged revisions in cache.
- Daemon running status and instance ID.
- Any in-progress journal record.

### 5. Recover Interrupted Transaction

```bash
agentfw mcp-profile recover
```
- Inspects pending `in_progress` journal in `profile-state.json`.
- Restores prior baseline configuration if transaction crashed after config modification.
- Restarts healthy baseline daemon if needed.
