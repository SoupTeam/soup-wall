# Managed Agent lifecycle

The lifecycle commands manage one Agent binary per user profile under
`~/.agentfw/versions`. They do not edit Claude Code settings or replace the
existing `agentfw install` instructions for manual hook setup. Configuration,
tokens, audit records and files outside the managed versions directory remain
in place when the managed binary is removed.

Build the candidate for the target operating system, then obtain its SHA-256
from the artifact itself. On Linux:

```sh
cargo build --locked -p agentfw --release
sha256sum target/release/agentfw
agentfw lifecycle install 0.3.0 /absolute/path/to/agentfw --sha256 DIGEST
agentfw lifecycle start
agentfw lifecycle status
```

On macOS, use `shasum -a 256 target/release/agentfw` instead of `sha256sum`.
On Windows, use `Get-FileHash -Algorithm SHA256 .\agentfw.exe` and pass the
lowercase digest to `agentfw.exe lifecycle install`. Use a build made for the
same host architecture. A candidate is capped at 256 MiB and must match the
operator-supplied digest before it enters managed storage.

## Routine operations

```sh
agentfw lifecycle status
agentfw lifecycle stop
agentfw lifecycle start
agentfw lifecycle restart
agentfw lifecycle upgrade 0.3.1 /absolute/path/to/new-agentfw --sha256 DIGEST
agentfw lifecycle rollback
agentfw lifecycle remove
```

`status` returns JSON with the active and previous versions, the recorded
process, its verified running state and an explanation. A healthy managed
process must answer an authenticated loopback request with its unique instance,
PID, binary digest and startup configuration digest. Startup waits up to 30
seconds for that response. Stop sends an authenticated shutdown request to that
instance; it never signals a PID alone. If a recorded process cannot be
verified, the command refuses to replace or stop it. A listener on the Agent
port that is not owned by this lifecycle is reported as a conflict.

`upgrade` verifies and stages the candidate while the current Agent is still
available. If the new version fails to start, the manager restores and starts
the previous version. `rollback` selects the previous verified binary and
restarts it when the Agent was running. Configuration changes are reported as
drift until restart; stop remains available in that state.

If an operation is interrupted, inspect `status` and run
`agentfw lifecycle recover`. Recovery returns to the version recorded before
the interrupted change. When a recorded PID is live but its managed identity
cannot be verified, recovery refuses to proceed. Resolve that process
manually before retrying. Missing or modified stored binaries also cause a
refusal. The manager does not silently adopt a manual installation or a
foreign daemon.

`remove` stops the owned process and deletes only recorded managed binaries
and the lifecycle manifest. It leaves `config.yaml`, tokens, audit data and
unrelated files untouched. Audit deletion is a separate operator action.

## Local verification

```sh
cargo test --locked -p agentfw --test lifecycle
cargo test --locked -p agentfw
cargo clippy --locked -p agentfw --all-targets -- -D warnings
```

On Windows, run the native check against a locally built Windows executable:

```powershell
.\scripts\test-agent-lifecycle-windows.ps1 -AgentBinary .\target\debug\agentfw.exe
```

The Windows script creates a disposable profile and uses an unused loopback
port. It checks install, start, upgrade, rollback, failed startup restoration,
stop, restart and removal. No service registration or host settings are
required. The Linux integration test runs the same lifecycle in a temporary
profile. macOS behavior needs a native run on a macOS host before it can be
claimed as verified.
