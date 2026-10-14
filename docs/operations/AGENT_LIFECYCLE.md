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
same host architecture. A candidate is capped at 512 MiB and must match the
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

On Windows, use PowerShell 7 under a standard user whose temporary directories
are owned by that user. Run the native check against a locally built executable:

```powershell
.\scripts\test-agent-lifecycle-windows.ps1 -AgentBinary .\target\debug\agentfw.exe
cargo test --locked -p agentfw --test lifecycle -- --ignored --nocapture --test-threads=1
```

The five Rust lifecycle tests are explicitly ignored in ordinary Windows test
runs, which can use an Administrators-owned hosted-runner profile. They must be
run separately with `--ignored`; an inaccessible profile then fails instead of
returning early as a successful test. A green ordinary test run alone is not
Windows lifecycle acceptance.

The Windows CI job uses `scripts/ci-windows-lifecycle.ps1` to provision a unique,
temporary standard user, copy the compiled Agent and lifecycle test binary, and
run all five tests. Its retained `windows-lifecycle-standard-user` artifact
records the source commit, binary hashes, actual user/owner SIDs, non-admin
status, case counts, raw test output, timeouts and cleanup outcome. Success
requires five executed passes, zero ignored cases, matching binaries and
successful account/staging cleanup. Provisioning is restricted to ephemeral
GitHub Actions runners; workstation users should run the commands above.

Each lifecycle CLI call has a 90-second test deadline. After the CLI exits,
captured output must close within five seconds. A retained pipe is reported
separately from a command that never exits; the Rust test attempts authenticated
cleanup of its own managed daemon before failing. The outer Windows CI launcher
has a 600-second deadline and cleans only its disposable account and processes.
These test deadlines do not change production startup or authorization limits.

### Windows output pipe regression

On 2026-10-14, the [standard-user Windows run](https://github.com/SoupTeam/soup-wall/actions/runs/38545040023/job/115788883563)
executed all five cases: four passed and one failed. The tested merge commit was
`d6467a7b798d3e8e2d889df1487402590b6f2947` (PR head
`f526579242e453efbb01ff979d7dc3bdbd5645a0`). The retained artifact records Windows
build 26100, PowerShell 7.6.6, a non-administrator token, matching user/profile
owner SIDs, and successful cleanup.

The `start` CLI exited with code zero and the managed Agent was healthy, but
the captured output did not close within five seconds. The test stopped its
authenticated daemon and reported a failure instead of waiting indefinitely.
The daemon had inherited the CLI's output pipes despite using separate standard
streams of its own.

Windows lifecycle CLI commands now clear `HANDLE_FLAG_INHERIT` on their own
standard handles before starting a runtime or child. This uses
[SetHandleInformation](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-sethandleinformation);
the CLI keeps its streams open for its own output. The managed child still uses
null input/output and its private launch log. This is CLI initialization, not a
change to the caller's handles when using the `Manager` library API directly.
The regression requires both output pipes to close and the CLI's success message
to reach the caller while the managed Agent remains healthy. A passing run after
the fix must retain all five executed cases under the standard user.

The [next run](https://github.com/SoupTeam/soup-wall/actions/runs/38545895102/job/115792036819)
passed start, upgrade and rollback, then hit the 90-second command deadline while
trying the deliberately invalid Windows executable. The lifecycle CLI also sets
[`SEM_FAILCRITICALERRORS`](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode)
at startup, preserving existing error-mode flags, so loader errors return to the
CLI instead of waiting for a system dialog. The failed-upgrade regression requires
an explicit restoration error and independently checks that the old Agent is
running again. This setting is confined to the lifecycle CLI process and its
children; it does not change Windows settings for other applications.

### Manual Windows check

The Windows script creates a disposable profile and uses an unused loopback
port. It checks install, start, upgrade, rollback, failed startup restoration,
stop, restart and removal. No service registration or host settings are
required. The Linux integration test runs the same lifecycle in a temporary
profile. macOS behavior needs a native run on a macOS host before it can be
claimed as verified.
