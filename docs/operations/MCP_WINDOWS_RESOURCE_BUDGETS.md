# Aggregate Windows resource budgets for owned native MCP children

SOU-96 extends the existing native child Job Object. This is an explicitly
configured resource boundary, not filesystem/network confinement, a new
original-server profile, or permission to widen tool/resource/egress authority.
The default manifest, native configuration and unconfigured launch are unchanged.

## Operator configuration

Set `AGENTFW_MCP_WINDOWS_BUDGET` on the **native admission collector** to an
operator-owned JSON file. Server replies, tool metadata and model text cannot
select this file or modify a running Job. For example:

```json
{
  "format": "sw-mcp/windows-job-budget/1",
  "memoryMaxBytes": 268435456,
  "memoryPressureBytes": 167772160,
  "activeProcessMax": 12,
  "cpuUserMillis": 10000,
  "wallMillis": 20000
}
```

The file must be a regular disk file owned by the collector account, with a
protected DACL containing only that account and SYSTEM allow entries. Prepare
this ACL before use. Loading never repairs permissions. The actual open handle
is checked before content is read; concurrent writers/deleters and a final
reparse-point component are refused. The maximum configuration size is 4096
bytes. Duplicate/unknown keys, missing fields and non-integer values are refused.
No configuration paths or account identifiers enter the budget diagnostics.

| Field | Version 1 supported range and meaning |
| --- | --- |
| `memoryMaxBytes` | 64 MiB–16 GiB, multiple of 64 KiB; aggregate Job committed memory hard ceiling |
| `memoryPressureBytes` | 32 MiB up to, but excluding, the hard ceiling, multiple of 64 KiB; terminal aggregate pressure threshold |
| `activeProcessMax` | 2–256; aggregate simultaneously active Job processes, including the primary server; reaching saturation is terminal |
| `cpuUserMillis` | 100–300000 ms; aggregate **user-mode CPU time** across Job members, including exited descendants |
| `wallMillis` | 1000–3600000 ms from budget installation; absolute deadline, including startup |

Version 1 chooses CPU time, not a CPU rate guarantee. Kernel-mode CPU time is
reported separately and is not included in the user-time ceiling. Working-set,
reserved address-space, machine-wide commit, filesystem space and unrelated
processes are not covered by `memoryMaxBytes`. Version 1 requires 64-bit Windows
10/Server 2016 or newer and an absolute drive-qualified `.exe` command. Relative PATH
lookup, batch/UNC/device commands and non-ASCII environment names are refused.
Argument/environment values preserve UTF-16, including Unicode and quotes.
The private launch adapter accepts the native collector builder’s inherited
environment plus explicit additions/removals; it is not a general `Command`
replacement supporting `env_clear` or `raw_arg`. Unsupported API/OS or inherited-Job combinations
fail closed; limits are never silently omitted. A missing environment variable
preserves normal behavior; a set variable naming a missing/invalid file refuses
launch. Transparent proxy mode and original-server sandbox selection refuse this
option. Linux cgroup budgets remain a separate configuration and implementation.

## Launch, exhaustion and cleanup

The unnamed, non-inheritable Job has kill-on-close, aggregate memory, active
process and aggregate CPU-time limits installed before the suspended child is
created. Its private completion port and memory-pressure notification are also
installed before execution. The configured launch uses
[`PROC_THREAD_ATTRIBUTE_JOB_LIST`](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
to create the process **already inside** the Job. Collector death between process
creation and resume therefore closes the last Job handle and terminates the
suspended process. Membership verification must succeed before its single
primary thread is resumed. An explicit three-handle list inherits only private
stdin/stdout/stderr pipe ends; Job, completion-port and parent pipe handles are
not inherited. Spawn, configuration or atomic assignment failure cannot create
an unowned running server; resume failure terminates/reaps the owned child.
There is no unowned fallback. Native nested Jobs are supported when Windows accepts the
hierarchy, including a more restrictive inherited parent. Neither breakaway flag
is enabled. An incompatible inherited Job is refused before server instructions.

A 10 ms monitor observes only the owned Job, with fixed-size queries and a
bounded private completion queue. It also checks the absolute deadline. Every
host write/flush poll rechecks the budget, including a previously blocked write.
Observed pressure/exhaustion, limit drift or uncertain observation closes the
gate permanently and terminates the owned Job. The existing bounded child reap,
stderr drain, collector close/cancellation and authenticated session retirement
paths remain responsible for cleanup and invalidation of pending authority.
Completed effects remain executed; no event claims rollback. Independent Jobs
and live siblings do not share a budget or terminal flag.

Windows rejects allocations beyond the hard memory ceiling; it does not make
every handled allocation failure fatal. Hard-limit completion messages are
best-effort. The explicit lower pressure threshold, guaranteed notification
facility and retained peak counter give an additional terminal signal. A single
rejected allocation that never reaches that threshold is not an independently
attested memory-pressure event. Do not claim that every application-handled OOM
is immediately detected. All live work still has the absolute wall deadline.
CPU-time enforcement is periodically evaluated by Windows, not an exact
nanosecond stop. Acceptance retains the actual observed overshoot and cleanup
times; a missed/late witness is a failed or incomplete run.

The host account and administrators remain trusted. This does not contain
host-level handle theft, code injection, a broker/service launching unrelated
work, or hostile same-account host administration. It does not qualify an
arbitrary Windows MCP server for filesystem or egress isolation. Standard native
authorization, liveness and the [stderr boundary](NATIVE_MCP_STDERR.md) continue to
apply. See also [Linux resource budgets](MCP_LINUX_RESOURCE_BUDGETS.md).

## Native Windows acceptance

Under a genuine standard user (not a filtered administrator), use an exact clean
source and its built `agentfw.exe`. Generate a source manifest outside the
checkout containing `{"commit":"<full SHA>","files":{"relative/path":"<SHA256>"}}`
for every tracked file. Work from a fresh private directory outside the checkout:

```powershell
python -I C:\reviewed-source\scripts\verify-windows-mcp-budgets.py --run `
  --agentfw C:\private-acceptance\agentfw.exe `
  --native-test-binary C:\private-acceptance\native-tests.exe `
  --source-commit <full-40-character-source-SHA> `
  --source-manifest C:\private-acceptance\source-manifest.json `
  --output C:\private-acceptance\new-evidence
```

The native test binary must come from the same clean source (`cargo test --locked
-p agentfw --lib --no-run --message-format=json` identifies the executable).
The harness runs both atomic launch controls with `--exact` under this same
standard user and finite outer Job; zero/ignored tests cannot count as a pass.
Two additional short, isolated controls compare Windows raw Job peak accounting
with actual private committed memory after rejected `VirtualAlloc` and heap
requests, both with and without pressure notifications. Each has its own 64 MiB
hard Job limit, finite CPU/process bounds and a 10-second parent deadline. Their
raw counters and kernel error codes remain in the report. These controls do not
waive the resource scenarios or turn an exceeded/missing witness into a pass.

The harness assigns itself to an outer finite Job **before** starting any Agent
or fixture: 1 GiB committed memory, 64 processes, 120 seconds user CPU and a
240-second outer watchdog. Its controlled workers have finite allocation,
process and time bounds even if the production boundary fails. Do not run
resource stress without those outer limits.

All 20 scenarios are mandatory: useful work and denied breakaway; aggregate
memory pressure and hard allocation refusal, descendant count, measured CPU and wall exhaustion; pending call
cancellation; collector death; six fresh exhaustion/restart cycles; and missing,
invalid, unsafe-ACL, failed-spawn and transparent-mode refusals. The same
independent allowed sibling must return useful original content after every
case. Real process handles, birth times, per-process committed-memory/CPU
counters, exit observations and an already executed file effect are independent
of the collector's budget diagnostics. Late results, forced cleanup, missing
witnesses and partial runs cannot pass. The real suspended assignment failure
also has focused native Windows Rust regressions using an actual incompatible
kernel handle and closing the last Job handle before resume, without a production
fault-injection option. Refusal scenarios require the specific expected fixed
reason, not merely a nonzero exit code. The acceptance explicitly opts into the
existing authenticated native liveness lease (2 seconds) to witness autonomous
pending-authority expiry after collector death; resource opt-in does not silently
enable or change liveness defaults.

`results.json` retains every completed case, failure/incomplete status, source
manifest/binary/Python/fixture/harness/configuration hashes, bounded counters and cleanup
outcomes. Bootstrap failures before the first case retain sanitized exception
type, OS error number and function/line identities. Raw server stdout/stderr, private payloads, credentials and arbitrary
local paths are not shareable evidence. Preserve failed and late reports.

The existing central Ready-for-review `agent-windows-security` job builds the
actual candidate and runs `ci-windows-mcp-budgets.ps1` under a disposable standard
account, outside the checkout. Its unique staging directory is under
`ProgramData` with a protected DACL allowing only that disposable user, SYSTEM
and the runner account; no parent or runtime permissions are widened. This avoids
requiring the standard user to enumerate the runner’s private temporary parent.
The CI launcher resolves the image’s real 64-bit CPython base runtime and copies
its executable, DLLs and standard library into that same private stage, excluding
site-packages and caches. It bounds the copy, rejects reparse points,
verifies every copied hash and retains a runtime manifest containing only relative
standard-library paths and hashes.
This avoids executing a runner-only Python shim from the disposable account.
The standard-user report’s Python executable hash must match the launcher.
After the native harness exits, the fixture user restores only descendants to
the stage’s existing private ACL so the runner can remove Agent-created
protected files. The stage root keeps its protected user/SYSTEM/runner-only ACL;
it is never reset to ProgramData permissions. This cleanup happens after native
observations and cannot turn a failed scenario into a pass.
It retains source identities and all outcomes even
on failure. There is no added per-push matrix or activation/selection policy.
Keep the PR Draft until implementation is ready for qualification. A passing
macOS unit test or a Job API mock does **not** establish Windows acceptance.

No Windows acceptance result is claimed by this source document; use the exact
current-source CI artifact and independently inspect its counters and failures.
