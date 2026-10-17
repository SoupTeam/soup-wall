# Generic native MCP diagnostic output

The enforcing `agentfw mcp --native-admission` collector owns the generic server's
stderr pipe. It discards child bytes in fixed-size reads and emits only bounded
metadata. Stderr is never forwarded to host stdout/stderr, copied into ordinary
audit, included in an error message or written to a hidden capture file.

This closes an alternate diagnostic-output channel. It does not confine a generic
server's filesystem, network, subprocess or other operating-system effects. The
selected original filesystem and Git relays retain their existing Linux sandbox
and separately reviewed stderr handling.

## Fixed bounds

The generic path uses `sw-mcp/native-stderr/1` diagnostic metadata with these
reviewed constants, rather than accepting limits from the untrusted server:

| Bound | Value |
| --- | --- |
| Read buffer | 8192 bytes |
| Total permitted stderr | 1,048,576 bytes |
| Maximum observed bytes including the overflow probe | 1,048,577 bytes |
| Read attempts | 4096 |
| Absolute open-pipe lifetime | 3600 seconds; incoming bytes do not reset it |
| Optional normal-exit observation | 2 seconds |
| Kill and reap | 3 seconds |
| Drain shutdown/join | 1 second |

Existing native HTTP request deadlines, including the session-end request, still
apply. These bounds do not promise a complete teardown in one second or a bound on
whole-process RSS. A short chunk, invalid UTF-8, terminal-control sequence or
missing newline is just a byte sequence; the drain does not allocate a line
buffer or decode child text.

A stderr EOF below quota is normal and does not stop useful stdout traffic. Byte
or read exhaustion, open-pipe lifetime, read failure and task failure make the
transport uncertain. No further successful native result release is authorized
from that uncertainty. Shutdown has a bounded join/abort path so a descendant
holding the write end cannot keep the diagnostic task alive indefinitely.

The metadata outcomes are `eof`, `byte_limit`, `read_limit`, `lifetime`,
`read_failure`, `shutdown_timeout` and `task_failure`. A failed operation may already
have changed a file or performed another server action. Discarding stderr and
withholding its result do not roll back an already committed effect.

## Safe metadata and process ownership

The collector emits a start record with the diagnostic version, server PID,
static ownership kind and fixed bounds. Its final stderr record contains only
`outcome`, `received_bytes`, `read_chunks` and `released: false`. The final server
record reports process/drain cleanup verification, transport completion and a
static reason code. No child bytes, command, server-provided identifier, source
string or stderr hash is part of these runtime diagnostics.

On Unix, the generic server starts in its own process group before execution.
The collector retains the live, unreaped group leader until group termination and
bounded reaping, which avoids reusing an already reaped PID as a group authority.
Owned descendants that stay in the group are terminated during normal MCP EOF,
cancellation, failures and daemon-loss teardown. A descendant can deliberately
escape a Unix process group with `setsid` or a similar mechanism. This is not a
Unix containment boundary, and an uncatchable collector `SIGKILL` cannot run its
normal cleanup. Those cases are not claimed as covered cleanup.

On Windows, the child starts suspended, is assigned to a non-inheritable
kill-on-close Job Object, and resumes only after ownership succeeds. Launch
failure never falls back to an unowned running child. Job-handle ownership gives
Windows a stronger process-exit cleanup boundary than a Unix process group.

The generic collector uses this ownership for native launch and supported inline
file/GET paths; their existing authorization, effect accounting and receipt
contracts remain. Selected filesystem/Git relays keep their own implementation.
The legacy non-enforcing manifest proxy still inherits child diagnostics and is
not covered by this native boundary. Native connection wrappers retain
`--native-admission`; their probe launches discard diagnostic streams. The trusted
Windows connection broker's own inherited diagnostics do not authorize raw stderr
inheritance from an MCP server.

## Owned Linux reproduction

From a clean exact checkout with Python 3, Cargo and Linux procfs:

```sh
cargo build --locked -p agentfw --bin agentfw
python3 -B -m unittest discover -s scripts/tests -p test_sou76_native_stderr.py -v
python3 -B scripts/verify-sou76-native-stderr.py --run \
  --agentfw "$PWD/target/debug/agentfw" --expected-commit "$(git rev-parse HEAD)" \
  --output /tmp/sou76-native-stderr-evidence
```

The output directory must be new and outside the checkout. Without `--run`, the
driver prints a plan and starts no processes. The required Linux run fails when
prerequisites or positive evidence are missing; it does not silently skip.

The driver starts the actual Agent daemon and generic native MCP collector with
an owned Python fixture. An independent parent captures the collector's actual
stdout and stderr in bounded private memory. It first calibrates this observer
against an intentionally unprotected owned child emitting the same public,
synthetic-secret, ANSI, binary and no-newline fixture bytes. No real credential or
external service is used.

The protected cases cover emissions before initialization and during useful
calls, exact original UTF-8 read-result bytes, an independently observed exclusive
file publication, a denied result followed by useful work, an unaffected peer,
startup and active-call floods, cancellation of dispatched work, early EOF,
partial stdout, daemon loss, and a descendant retaining stderr after its parent
exits. The active-call flood deliberately commits an owned publication before
flooding; the report preserves that effect instead of describing it as cancelled.
A parent-controlled startup barrier records each server PID/start time before
short-lived failure cases can exit. Descendant cleanup is witnessed before any
private fallback kill; requiring parent fallback makes the acceptance fail.

The report stores exact source/binary/driver/fixture/config/policy/registry
identities, stream hashes and byte counts, marker-presence booleans, observed
protocol-frame hashes, allowlisted metadata, sanitized admission chronology,
filesystem observations and owned PID/start-time cleanup witnesses. It stores no
raw stdout/stderr capture, canary payload or secret marker. The only public marker
payloads are intentional synthetic fixture definitions in source. Unknown stream
bytes are discarded even when the run fails; failure output uses static codes.

The required [Linux and native-platform workflow](../../.github/workflows/native-mcp-stderr.yml)
prints a bounded sanitized summary even on failure and retains evidence for
30 days. Its native launch regressions run on Linux, macOS and Windows. Read-error,
read-count and lifetime edge cases also have focused helper tests; an injected
reader failure is not described as an actual operating-system read error. Existing
[filesystem](../../.github/workflows/mcp-real-filesystem.yml) and
[Git](../../.github/workflows/mcp-real-git.yml) workflows remain the selected original
server regression gates. A control-test pass alone is not proof that the real
Linux demonstration executed. This increment makes no arbitrary-server sandbox,
live-model efficacy, Phase 4 or final-release claim.
