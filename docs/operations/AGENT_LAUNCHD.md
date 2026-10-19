# macOS user-session Agent service

The macOS backend of `agentfw service` manages one installed Agent in the
current non-root user's launchd domain. It reuses the
[lifecycle installation and transaction journal](AGENT_LIFECYCLE.md).
The acceptance target is native macOS ARM64. Intel execution, automatic login
startup, system LaunchDaemons, live-model efficacy and arbitrary-child sandboxing
are outside this qualification.

## Install and explicitly start

Install the reviewed executable and configuration first. Use an absolute,
canonical Agent home with no symlink components, owned by the current user;
service files and journals must not be writable by other users. On macOS use
the canonical `/private/var/...` path when a temporary directory is exposed
through `/var`. Commands below assume `$HOME/.agentfw` is that installed home.

```sh
agentfw lifecycle install release-1 /owned/agentfw --sha256 EXPECTED_SHA256
agentfw service --home "$HOME/.agentfw" preview
agentfw service --home "$HOME/.agentfw" install
agentfw service --home "$HOME/.agentfw" inspect
agentfw service --home "$HOME/.agentfw" start
agentfw service --home "$HOME/.agentfw" inspect
```

Preview writes nothing. Install writes an installation-scoped plist and a
verified launcher inside the Agent's private `service/` directory. It does not
load or start a job, install a login item, write `Library/LaunchAgents`, or change
launchctl enable/disable overrides. Repeated install verifies existing ownership.
The label is derived from the canonical Agent home; separate homes get separate
labels. A conflicting port, existing lifecycle process or duplicate label is
refused.

Install selects the available `gui/<uid>` domain, or the same user's `user/<uid>`
domain if no GUI domain is available, and records that choice. Subsequent
commands require the recorded domain. No unavailable session is replaced with a
detached daemon. The transient job lasts for its domain's lifetime: a GUI logout
removes a GUI-domain job, while the user domain can outlive that GUI session.
Reboot removes either job. Use explicit `stop` to guarantee removal, and explicit
`start` to load it again in a supported user session.

Start uses structured `launchctl bootstrap` arguments. The plist contains an
explicit `ProgramArguments` array; the recorded launcher executes the selected
lifecycle binary directly. Neither operation invokes a shell.

## Readiness, crashes and explicit stop

Inspect reports `registered`, `installed`, `available`, `loaded`, `running`,
`verified` and `ready` separately, alongside the domain, launchd PID/state,
authenticated health identity and any conflict/error. `running` is an observation
of a PID, not a protection verdict. `verified` requires the job's recorded path,
program and arguments, the native executable path, lifecycle instance, binary
digest and configuration digest to match the authenticated Agent response.
The existing native self-test/MCP witnesses establish actual enforcement.

The plist requests restart after unsuccessful exit with a 10-second throttle.
The launcher also persists a limit of three starts in a rolling 60-second window.
An exhausted or invalid restart journal exits without executing another Agent;
the job can remain loaded but unverified. Clock rollback cannot erase the window.
Inspect the cause, explicitly stop, then start to reset this budget. Repeated
`start` on an already verified service does not reset crash accounting.

```sh
agentfw service stop
agentfw service inspect
agentfw service start
agentfw service restart
```

Stop validates ownership, then uses `bootout` to remove the job and its restart
demand. It waits for the owned process to disappear. It does not send a signal
to an arbitrary PID or merely request an exit that KeepAlive would reverse.
Explicit stop remains stopped. Direct `agentfw serve` and detached lifecycle
starts cannot bypass a service registration.

## Upgrade, rollback and interrupted operations

```sh
agentfw lifecycle upgrade release-2 /owned/replacement --sha256 EXPECTED_SHA256
agentfw lifecycle status
agentfw lifecycle rollback
agentfw lifecycle recover
```

The existing lifecycle transaction verifies/stages the replacement, records the
previous version and running intent, stops only the owned launchd job, selects
the candidate and checks authenticated readiness after restarting. Failed
startup restores the prior version and running intent. A stopped upgrade or
rollback stays stopped. `lifecycle recover` compensates an interrupted switch
using the same durable journal; it does not guess a version or clear a live
unverified PID.

Install/remove phases are also journaled. After interruption, `service uninstall`
can remove recorded partial artifacts and a new install can follow. A partial
file is removable only when its recorded device/inode still matches. An
unrecorded artifact or replaced inode is a conflict requiring operator inspection,
not permission to delete it. Edited plists, replaced launchers, foreign loaded
jobs and invalid ownership records are refused. Restore an intentionally edited
artifact from its known version before retrying; never delete an ownership record
to bypass verification.

## Removal and retained data

```sh
agentfw service stop
agentfw service uninstall
agentfw service uninstall  # idempotent
```

Uninstall unloads the positively owned job and removes its plist, launcher,
restart journal and ownership record. It preserves lifecycle versions, policy,
registry, trust material, tokens, audit history and unrelated files/processes.
The private service directory and operation lock remain as synchronization
artifacts. Use the existing lifecycle removal command separately when appropriate.
Nothing is installed in another user's profile or a system launchd domain.

## Native acceptance and evidence

The [recorded native qualification](evidence/launchd/QUALIFICATION.md) retains
the passing run and the failed development controls with exact source identities.

From the exact reviewed checkout, on a disposable non-root macOS ARM64 runner:

```sh
cargo build --locked -p agentfw --bin agentfw
python3 -B scripts/test-agent-launchd.py --run-owned-launchd \
  --agentfw target/debug/agentfw --expected-commit "$(git rev-parse HEAD)" \
  --output /owned/new-launchd-evidence
```

The opt-in driver copies the executable, shipped policy and rule classifier out
of the checkout. It reuses the bundled native self-test MCP server and accepted
MCP harness/receiver. Positive read/send controls calibrate execution and receipt
witnesses before protected read, synthetic-secret send refusal and useful
follow-up work. Real launchd controls exercise crash recovery, exhaustion,
explicit stop, conflicts, updates, rollback, interrupted transactions and removal.
An unrelated process/file sentinel must survive. Cleanup checks the manager,
process inventory and owned artifacts independently.

The report retains the exact source, binary/plist/configuration identities,
PIDs/instances, timings, successful and failed controls and cleanup outcome.
It omits tokens and launchd environment dumps. Missing prerequisites, a skipped
scenario or failed cleanup cannot pass. The existing `agent-lifecycle-macos` CI
job runs this driver only when selected for full qualification; Draft PRs retain
the repository's inexpensive checks. Linux service regressions remain in their
existing suites. Qualification evidence must identify an actual native run;
compilation or Linux mocks alone do not establish native launchd behavior.

Apple's [launchd guide](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
describes user agents and explicit program arguments. Consult the installed
`launchctl(1)` and `launchd.plist(5)` manuals for the runner's OS version; unknown
runtime output or unavailable identity fields fail closed.
