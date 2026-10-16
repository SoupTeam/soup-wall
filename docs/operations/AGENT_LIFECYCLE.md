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

## Opt-in Linux user service

A Linux user with a working `systemd --user` manager can register an installed
Agent as a background service (SOU-52, roadmap Phase 5, following SOU-29 and
SOU-18). Registered profiles route lifecycle start, stop, restart, upgrade,
rollback and recovery through systemd. Plain `serve` refuses this profile.
Run `service uninstall` before removing or migrating
its installed versions. Other profiles continue to use the existing lifecycle.

Install an Agent version using the commands above first. Run service commands
from a regular executable owned by your user, without hard links or write access
for other users. The installed version is suitable; a Cargo build output can have
hard links, so copy it to a private executable path before using it as a launcher
source. The service makes and verifies its own stable copy.

```sh
# The default profile is ~/.agentfw; --home selects a different installed profile.
agentfw service preview
agentfw service install
agentfw service start
agentfw service inspect
agentfw service restart
agentfw service stop
agentfw service uninstall

agentfw service --home /absolute/path/to/agent-profile preview
```

`preview` prints JSON containing the exact unit definition and paths without
creating files or contacting systemd. The profile must already exist. `install`
creates a **user** service but does not start it, enable it at login, or change
linger. It does not require sudo. It uses the account's home directory from the
user database for `~/.config/systemd/user`, independently of a profile-specific
`HOME`. A manager configured with a different unit search path must load that
exact file or registration fails. No system service or session policy is changed.
Without an existing user manager, service commands fail explicitly. Logout and
reboot behavior remains controlled by the user's existing session configuration.

The unit name is `agentfw-<SHA-256 of canonical profile path>.service`.
`<profile>/service/ownership.json` records the UID, profile, unit and launcher
paths, digests, filesystem identities, and installation/removal phase. Unit and
launcher replacement, symlinks, writable parents, drop-ins, unexpected enablement,
and a different loaded unit cause refusal. A repeated install of an unchanged
owned service is safe. The Agent profile, service directory and their parents must
not be writable by another user (root-owned sticky temporary directories are
allowed). Do not manually edit the generated unit or add systemd overrides.

The private launcher checks the active installed version, records a fresh
instance, and replaces itself with `lifecycle serve-managed` using `exec`.
Systemd therefore supervises the **Agent's PID**. `ExecStartPost` verifies the
existing authenticated `/lifecycle/v1` response after every start, including an
automatic restart. It matches the recorded PID and instance, active executable,
and configuration digest; systemd's `active` label alone is insufficient.
`inspect` returns these observations as JSON. `ready: false`, an `error`, or an
incomplete phase is not a healthy service; the inspect command itself can still
exit successfully because it successfully produced a diagnostic report.

Readiness waits up to 30 seconds; systemd bounds startup to 35 seconds.
`Restart=always`, `RestartSec=2s`, and three starts per 60 seconds bound crash
recovery. Explicit `service stop` uses `systemctl stop`, which suppresses automatic
restart. Shutdown requests use the existing authenticated endpoint; systemd
bounds shutdown to 30 seconds and cleans only this unit's control group. A live
PID whose identity cannot be verified is never adopted or stopped by the CLI.
After a rate limit, inspect the underlying failure before retrying; the CLI does
not reset the limiter during ordinary startup or automatic crash recovery.
A transaction restoring its original working version can reset an already failed
unit once before its explicit recovery start. Waiting for the interval and then
explicitly starting is sufficient once an ordinary crash-loop problem is resolved.

Service operations use a separate nonblocking operation lock. The lifecycle
state lock is brief and is released before waiting on systemd or health replies.
Concurrent management commands fail rather than starting a second instance.
Interrupted registration/removal remains recorded. `uninstall` can remove verified
remaining files from an incomplete installation, but a modified or replaced file
requires explicit operator investigation; the tool will not repair or delete it
as its own. If the manager cannot complete a request, inspect before retrying.

`uninstall` stops a verified service and removes only its owned unit, launcher
and ownership record. Uninstall refuses an unfinished lifecycle transaction;
run `lifecycle recover` first. Installed versions, configuration, keys, tokens, audits and
unrelated files remain. The service directory and its coordination lock may remain
for safe serialization. The unit discards process stdout/stderr instead of writing
request payloads or tokens to the journal. Manager state and authenticated identity
are available through `inspect`; application audit remains in the Agent profile.

### Service updates and recovery

Use the current CLI with the same profile selected for service installation:

```sh
agentfw lifecycle upgrade 0.3.1 /absolute/path/to/new-agentfw --sha256 DIGEST
agentfw lifecycle rollback
agentfw lifecycle recover
agentfw lifecycle status
agentfw service inspect
```

The lifecycle commands use the default profile under the caller's home directory.
For another profile, select its parent as the caller's home, as with the existing
lifecycle commands. `service --home` selects the profile directory directly.

The service coordinator verifies and stages the candidate before stopping the
current version. The existing lifecycle journal records both versions and whether
the service was running. State locks are released before any systemd or health
wait. The stable launcher executes the selected installed version; only the two
journaled versions may launch during a transaction. The unit definition and
launcher are not replaced by an Agent version update.

A running update must reach authenticated readiness on the new PID/instance.
If startup fails, the coordinator cancels queued restarts, restores the old
version and verifies its readiness. It returns an error describing the failed
update even after successful restoration. A failed explicit rollback similarly
restores the original version. If restoration cannot finish, the journal remains
and the command reports incomplete recovery. Restore the missing verified binary
or resolve the reported conflict, then retry `lifecycle recover`.

An initially stopped service stays stopped during upgrade, rollback and recovery.
Staging and hash verification do not establish runtime readiness in that case;
start explicitly to validate the selected version. Recovery of an interrupted
transaction restores its original version and recorded running intent. Ordinary
start/stop/restart, another update, and uninstall refuse a pending transaction.
Concurrent commands fail on the service operation lock. `inspect` includes the
transaction, interruption flag, ownership phase and verified runtime identity.

A registration created by SOU-52 part 1 has an older stable launcher. The new CLI
checks its transaction protocol **before staging or stopping** and refuses updates
if it is too old. Migrate the registration using the new CLI:

```sh
agentfw service stop
agentfw service uninstall
agentfw service install
# Start only if this profile was previously running.
agentfw service start
```

This preserves installed Agent versions, configuration, keys, tokens and audit.
A newly installed launcher reports `transaction_protocol: 1` in `service preview`.
For interrupted registration, uninstall removes a partial copy only when its
recorded filesystem identity still matches. An incomplete older record without
an identity requires an exact full hash match. Unidentified or replaced files
remain for operator investigation. Interrupted removal can resume with its unit
file already absent and a stale stopped definition still cached in systemd.

### Real Linux service acceptance

Run on an actual Linux host with its user manager, Python 3.11 or newer, and a
built Agent. Building in the pinned Docker toolchain is fine; running a service
inside a build container is not evidence for this procedure.

```sh
python3 scripts/test-agent-service.py --run \
  --agentfw /absolute/path/to/agentfw \
  --suite full --output target/agent-service-full.json
python3 -m unittest discover -s scripts/tests -p test_agent_service.py -v
```

The explicit `--run` creates a unique temporary profile and unit. The output must
not already exist. The default `full` suite runs 19 cases; `--suite core` runs
only the original seven and is insufficient for final acceptance. The core covers nonmutating preview and repeat install,
authenticated startup, useful allowed and denied local MCP calls with independent
execution witnesses and unchanged IDs/arguments/results, crash recovery and a
useful follow-up call, persistent explicit stop, repeated-crash limits, rejection
of an edited unit, and data-preserving repeated uninstall. MCP calls use the
existing trusted local fixture and rule-based classifier, with no external model
or provider. The full suite also checks manager unavailability, a replaced
launcher, unexpected drop-ins, occupied ports, a live unverified PID, concurrent
commands, running and stopped updates/rollback, killed update coordinators,
failed restoration and recovery retry, and interrupted registration/removal.
It checks that keys survive and tokens/payloads do not appear in the report or
the owned service's journal and launch logs. This does not claim containment of
an arbitrary MCP server.

The report records exact source revision, whether tracked sources were dirty,
environment, binary/configuration digests, process IDs, instances, recovery times,
failures and `not_run` cases. Missing user-manager access, missing journal evidence,
or an unexecuted case never becomes a pass. No tokens or request/result contents
are retained in the report. Failed cleanup leaves the recorded temporary profile
for investigation instead of deleting unidentified service files.

Some systemd versions preserve the last crash `Result=signal` when a restart is
rate limited. The acceptance driver requires the user manager's own structured
`unit_test_start_limit` journal event for the exact unique unit, plus stopped
process observations; a generic failed state alone does not prove the limit.
The [upstream unit limiter](https://github.com/systemd/systemd/blob/v259/src/core/unit.c)
and [service lifecycle documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html)
describe the relevant systemd behavior. Closing SOU-52 requires both implementation
PRs to be accepted and a full real-manager pass on the accepted source. A core
pass, a mock manager, or a passing Rust/Python suite alone does not establish that.
The final PR retains the sanitized exact-source JSON report and binary hashes;
repeat the command above in the target Linux environment before operational use.


## Authenticated runtime protection diagnostics

`agentfw protection-status` queries `GET /diagnostics/v1/protection` using the
existing hook token. It is separate from `preflight`, `lifecycle status`, `/health`
and managed-policy `/health` metadata; their schemas and behavior are unchanged.
The endpoint contract is `sw-protection-status/1` and requires Bearer authentication
plus a fresh 16–128 character `x-agentfw-status-nonce` challenge. Responses echo the
challenge and have `Cache-Control: no-store`. Prefer the CLI so credentials are not
put into shell history or copied into reports:

```sh
agentfw protection-status
agentfw protection-status --home /absolute/profile/.agentfw --query-only
agentfw protection-status --query-only --require-enforce --expect-instance INSTANCE
agentfw protection-status --expect-policy-sha256 DIGEST --expect-registry-sha256 DIGEST
```

Exit codes are **1** for unavailable/authentication/malformed/stale/mismatched
responses, **2** for unknown protection or unmet `--require-enforce`, and **0** only
with explicit `--query-only` after successful validation. Query-only confirms
retrieval, never execution coverage. Shadow mode remains shadow; a healthy daemon
never turns an unknown path into protected. The output distinguishes `query` from
`protection`. Errors contain fixed codes, never raw server bodies, credentials,
config parser details, tool calls or local file paths. No token, profile, lifecycle
lock or configuration is created or rewritten by the query. Redirects and proxies
are disabled; reads and response size are bounded, with a 1–5 second timeout.

The snapshot reads the **actual active Agent policy** under the engine mutex,
including its managed revision/sequence/source digest at the same instant. Its
`agent-policy-json/1` SHA256 hashes the parsed operator policy serialized in Rust
struct field order, including rule order, messages and defaults; it is not the
original YAML byte hash. The binary digest identifies the engine and its mandatory
safety floors. Managed source SHA256 remains separate. Config uses the same JSON
struct serialization (`Config`) and reports the loaded startup configuration,
not a new parse of disk. The CLI compares this digest with its current local config
and rejects drift. Editing policy/registry files alone never changes reported active
state; policy changes in the engine do. Registry ID/digest/tool count come from the
installed in-memory native registry; absent evidence is `unknown`, never an empty
unrestricted capability. Policy/registry expectation flags compare explicit known
identities. A running instance has a fresh ID, PID and start time; managed instances
reuse the existing lifecycle identity. Its raw lifecycle config digest is labelled
separately from the loaded JSON config digest. Missing binary evidence stays null.

| Path | Capability and limit |
| --- | --- |
| Legacy HTTP hook | Supported inspection; **fail-open** on unavailable daemon, timeout or internal failure; configured host wiring is unknown |
| MCP manifest | Supported metadata check, not execution coverage |
| Native admission | Supported only with loaded registry, enforcing mode and no optional judge; requires a trusted collector |
| Unbound/unsupported MCP resource executor | `unsupported`, reason `resource_executor_unsupported` |
| Bound resource executor | Configured resource policy presence is reported; actual executor/runtime coverage stays `unknown` |
| Arbitrary-server containment | `unsupported` |
| Verified model consumption | `unknown` |

All path `execution_coverage` values remain **unknown**. Three bounded counters and
last-seen timestamps record authenticated HTTP contact with `/hook`, `/mcp` and
`/native/v1`, including malformed/fail-open requests. They do not claim inspection,
execution, result delivery or model consumption. Unauthenticated requests and status
queries do not advance counters. No raw content or per-session history is retained.
Policy/config/registry and counters are captured under a consistent lock order;
concurrent rollout cannot mix an old policy digest with a new managed revision.

Reproduce the focused runtime, loopback-client and real-binary CLI tests:

```sh
cargo test --locked -p agentfw --test protection_status
```

CI retains source SHA, source-file hashes, results and the real test daemon's
`runtime.json` snapshot in `runtime-protection-status`.
Fixtures cover authentication, live policy replacement and concurrency, disk drift,
missing registry, legacy fail-open contact, native contact, shadow/unavailable,
nonce/instance/digest mismatch, stale/overclaimed replies, bounded errors, and a real
daemon's PID/binary identity. These component checks do not complete SOU-15 or
independent SOU-18 installation/active-protection acceptance. They add no grants,
activation, managed-bundle, executor or lifecycle transaction behavior.
