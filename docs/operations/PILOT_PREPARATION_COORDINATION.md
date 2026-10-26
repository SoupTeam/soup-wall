# Concurrent pilot input preparation

The native Git/bubblewrap prerequisite builder and the Agent source builder
coordinate independently for each private output root. This changes neither
the installed pilot selection contract nor the runtime qualification gate.
Start with the [prerequisite inventory](PILOT_NATIVE_PREREQUISITES.md) and
[source-build inventory](PILOT_SOURCE_BUILD.md); both plans remain read-only.

## Prepare, wait, and reuse

Run the normal `--prepare` or `--build` command from those guides. With no
wait option, an invocation that encounters an owner of the same output root
returns bounded JSON `status: busy`, `reason: preparation_in_progress` and exit
code `3`. To wait explicitly, add `--wait-seconds N` with `0 < N <= 2700`:

```sh
python3 -B scripts/prepare-native-pilot-prerequisites.py --prepare \
  --wait-seconds 2700 "${native_args[@]}"
python3 -B scripts/build-native-pilot-inputs.py --build \
  --wait-seconds 2700 "${source_args[@]}"
```

The second process holds no authority from a PID, timestamp or lock filename.
It waits for an exclusive kernel lock on an open descriptor, then rechecks
current inputs, the selected marker, complete private receipt, output hashes
and generation tree. A matching result is `reused`, with `contended` and
`waited_seconds`; no second compiler invocation occurs. A changed source,
toolchain, Python interpreter, selected dependency directory, archive digest,
build option, binary or receipt fails closed. `--rebuild` explicitly performs
a new build after the lock becomes available, retaining the old marker until
the new generation is fully verified. The result never claims active
protection.

The lock file is an empty, persistent, owned `0600` regular file under an
owned `0700` root. Do not remove or replace it, even after a crash: an owner
death releases the kernel lock automatically, and a later owner can reuse a
fully verified generation or create a new one. Incomplete generations and the
first bounded failure record remain private for diagnosis. An unsafe symlink,
FIFO, hardlink, changed lock name or changed output root is refused. A waiter
that reaches its deadline returns `status: busy`, `reason:
bounded_wait_expired`, exit code `3`; cancellation closes its descriptor
without interrupting the owner. Distinct output roots do not block each other.

Prerequisite receipts now also bind the selected Python interpreter and
bounded hashes of explicit Meson and `pkg-config` dependency directories.
Reuse of an older prerequisite receipt lacking these fields is refused;
`--prepare --rebuild` creates a new receipt while preserving the prior marker
until publication succeeds. Directory identity inspection is capped at 25,000
entries and 512 MiB. An unresolved link in a selected package directory is
recorded as unresolved; if its target appears, reuse refuses the changed
directory identity. Existing links outside the selected directory are refused.
The existing pinned archive hashes, compiler hashes,
library checks, build bounds and download opt-in remain required.

## Reproduction and native evidence

The following one command runs independent subprocess races for both builders:

```sh
python3 -B -m unittest scripts.tests.test_pilot_preparation_coordination -v
```

Its compiler work is explicitly simulated. The production lock, complete
receipt verification and atomic marker publication execute in separate
processes. The suite covers simultaneous first creation, same and different
inputs, bounded busy/wait, failed and killed owners, cancelled waiters,
unsafe lock records, changed lock names and unrelated live builders. Its
append-only invocation witness distinguishes one build from two requests.

The focused native Ubuntu 24.04 workflow exercises the same pair with real
pinned Git/bubblewrap and Agent source builds, then continues the accepted
original-server pilot qualification:

```sh
gh workflow run mcp-real-filesystem.yml --repo SoupTeam/soup-wall \
  --ref BRANCH --field native_preparation_only=true \
  --field preparation_concurrency=true
```

Read `sou111-native-preparation-RUN_ID/concurrent-preparation.json` and the
separate source/native timing and runtime reports. The concurrency report
counts completed build generations and compiler logs: two requests with one
completed build mean one duplicate build was avoided **for that run**. The
waiter's elapsed time includes waiting and full verification; it is not a
standalone warm-cache latency or a measured wall-clock saving. Build success
is separate from the original-server runtime result, namespace controls and
active protection. Do not publish private raw compiler logs or inputs.
