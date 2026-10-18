# Transactional MCP Profile Lifecycle (SOU-78)

> Implementation in progress (2026-10-18). This module is a daemon-profile foundation.
> It does not yet satisfy SOU-78's owned Linux connection transaction or shared-risk
> continuity requirements. Do not treat local profile tests as acceptance evidence.

## Overview

`agentfw mcp-profile` provides transactional installation, upgrade, rollback, status inspection, and crash recovery for operator-authored MCP admission profiles.

While SOU-65 established inert profile authoring (`import`, `validate`, `explain`, `diff`, `compile`), SOU-78 manages the installed lifecycle of these profiles under `<HOME>/.agentfw/mcp-profiles/` and binds them to the active daemon configuration (`config.yaml`).

## Principles

1. **Immutable Revision Repository:**
   Compiled profile bundles (comprising the six required files: `native-config.json`, `operator-declarations.json`, `profile.json`, `registry.json`, `resource-profiles.json`, and `source-snapshot.json`) are staged under `<HOME>/.agentfw/mcp-profiles/revisions/<bundle-sha256>/` with restrictive permissions (`0700` directories, `0600` files). The manager never edits an existing revision; reuse revalidates its content-addressed identity. File permissions are private, not an OS immutability guarantee.

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
   Generation currently protects CLI compare-and-swap only. It is not yet bound
   to collector grants, receipts or Ask approvals. A daemon restart changes process
   identity but does not by itself prove host-risk continuity or host reload.

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

### Preview before upgrade or rollback

```bash
agentfw mcp-profile preview --profile /path/to/new-compiled-profile
agentfw mcp-profile preview --revision <previous-bundle-sha256>
```

Without either option, preview selects the recorded previous revision for rollback.
Review `diff` and pass `approval_sha256` to the corresponding apply command. Preview
reads and validates source documents without staging or activating a revision.
The two profiles must refer to the same original server identity.

### 2. Upgrade Profile

Upgrade and rollback CLI commands require Linux; macOS and Windows refuse before
profile mutation. Low-level library tests on other platforms are not support evidence.

```bash
agentfw mcp-profile upgrade \
  --profile /path/to/new-compiled-profile \
  [--expected-bundle-sha <sha256>] \
  [--expect-generation <u64>] \
  --accept-diff <preview.approval_sha256>
```
- Compares new profile with active profile using semantic diff.
- Every upgrade and rollback requires exact preview approval; `yes` is rejected. The digest binds operation, home, source/target bundles, next generation, source/target config and lifecycle snapshot. Any change requires a fresh preview.
- Increments generation monotonically.
- Restarts running daemon and verifies fresh instance attestation.
- Automatically reverts to previous profile if daemon startup fails.

### 3. Rollback Profile

```bash
agentfw mcp-profile rollback \
  [--revision <bundle-sha256>] \
  [--expect-generation <u64>] \
  --accept-diff <preview.approval_sha256>
```
- Defaults to rolling back to `previous_bundle_sha256` if `--revision` is omitted.
- Advances the CLI generation monotonically (`N + 1`); runtime stale-authority protection remains an acceptance gap.
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

## Status interpretation and bounded evidence

`configuration_status` reports `configured`, `conflict` or `not_configured` after
revalidating the active bundle and selected native config. `runtime_status`
distinguishes `daemon_configuration_verified`, `unavailable_daemon_stopped`,
`unavailable`, `conflict` and an `incomplete` journal. These attest the managed
daemon configuration only. `host_reload_status` remains `unverified`; publication
and daemon health do not prove an already running Claude Code host reloaded it.

State reads are limited to 10 MiB, input Agent config to 1 MiB, and the recent
operation history to 1024 records. Recovery rejects unsafe operation identifiers
and displaced paths outside the journal's owned operation. The current journal is
never discarded when retaining the bounded recent history.
