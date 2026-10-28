# Terminal Ask Inbox

Use the same installed `agentfw` binary that launched the owned Linux pilot.
The launch must have Ask continuation enabled. Take the home and run ID from
its launch output, then open a second terminal:

```sh
agentfw pilot-approval --home /absolute/private/run/.agentfw --run RUN_ID watch
```

The inbox shows the run, daemon instance, registry digest and pending requests.
To inspect the first request, enter:

```text
inspect 1
```

Read the server/profile, tool, complete arguments, expiry and binding digest.
Then enter `approve` or `reject`. Every new request needs its own inspection
and decision. Enter alone leaves the request pending. `refresh` redraws the
list; its contents refresh at the configured interval. `quit`, EOF and Ctrl-C
close only the watcher.

An approval submits a decision. It does not prove that the original server ran
the call or that its result was released. Existing policy and result checks
still apply. Denied calls cannot be approved through this inbox.

If a request expires, disappears, changes or is decided by another operator,
select and inspect a current request. A stopped run or restarted daemon makes
the inbox unavailable. Start a new watcher using the new run's identity.

Limits: 16 pending requests, 128 ASCII input bytes per command, 16 KiB per
complete escaped display, 1 MiB of output and one hour per watcher. A display
over the limit cannot record an inspection or enable an interactive decision.
Refresh defaults to two seconds and accepts `--refresh-seconds 1` through `30`.
Daemon requests and blocked terminal writes have two-second timeouts. Output
uses escaped ASCII JSON, including non-ASCII and terminal-control characters.

The existing `list`, `inspect`, `approve`, `reject` and `stop` commands remain
available. See [the Ask workflow](PILOT_ASK_WORKFLOW.md) for launch prerequisites
and [emergency stop](PILOT_EMERGENCY_STOP.md) to stop an owned run.

## Verification

```sh
cargo test --locked -p agentfw --lib pilot_approval
python3 -B scripts/qualify-ask-inbox.py --help
```

The native acceptance driver reuses the original Ask workflow with the actual
Claude Code executable, pinned filesystem/Git profiles and an owned loopback
provider. It records exact source and runtime hashes, independent original
dispatch counts, useful results, refusal cases and watcher exit controls.
It makes no paid provider calls. Raw arguments and terminal transcripts stay
in private temporary storage; the report contains bounded observations and
transcript hashes. Container tests alone do not establish native Ubuntu acceptance.
