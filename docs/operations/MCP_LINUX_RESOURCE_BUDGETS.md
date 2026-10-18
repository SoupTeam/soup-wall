# Aggregate Linux resource budgets for selected MCP servers

The accepted filesystem and Git profiles can opt into an operator-owned cgroup-v2
budget. It covers the selected bubblewrap process tree, including descendants and
threads. It composes with the existing read-only workspace, private namespaces,
network denial, pinned runtime and native admission. It does not establish
arbitrary-server semantic correctness or add a Windows/macOS sandbox.

Set `AGENTFW_MCP_LINUX_BUDGET` to a private regular JSON file before starting the
selected native collector. The file is at most 16 KiB, owned by the collector's
effective user, not writable by other users, and opened without following its
final symlink. Duplicate and unknown fields are rejected.

```json
{
  "format": "sw-mcp/linux-cgroup-budget/1",
  "delegationRoot": "/sys/fs/cgroup/operator-service/budgets",
  "memoryMaxBytes": 536870912,
  "pidsMax": 64,
  "cpuQuotaMicros": 100000,
  "wallMillis": 120000
}
```

All fields are required. These are example explicit values, not silently applied
defaults. Without this environment variable the existing selected profile remains
compatible and is labelled `unbudgeted`. A requested unsupported or invalid budget
is refused; there is no unenforced successful fallback. Generic arbitrary-command
native MCP and inline file/HTTPS executors do not gain this cgroup guarantee.

| Field or fixed control | Units and accepted meaning |
| --- | --- |
| `memoryMaxBytes` | 64 MiB–16 GiB, multiple of 64 KiB; `memory.max` for kernel-charged memory across the tree |
| `pidsMax` | 16–4096 tasks; `pids.max` counts threads as well as processes |
| `cpuQuotaMicros` | 1000–1600000 µs per fixed 100000 µs period; aggregate fair-scheduler CPU bandwidth |
| `wallMillis` | 1000–3600000 ms from owned budget creation, including startup/discovery and execution |
| `memory.swap.max` | Always 0; no swap allowance |
| `memory.oom.group` | Always 1; group OOM treatment |
| `cpu.max.burst` | 0 where the kernel provides the interface |
| Observation/cleanup | Nominal 25 ms polling; cgroup empty/removal wait is bounded to 3 s, separately from child reap and stderr cleanup |

Memory accounting is kernel-charged usage, not process RSS. Linux permits brief
`memory.max` overshoot for some allocations. CPU quota throttles runnable work and
permits temporal scheduling bursts; it is not a cumulative CPU-time allowance and
does not itself terminate the server. The explicit wall lifetime terminates a
continuously busy server. There is no separately enforced idle timeout. Ancestor
limits can impose a stricter effective bound. A Node server's libuv/V8 threads
consume task capacity before useful calls begin; choose a practical startup budget.

The runtime accepts an already prepared, private `0700`, effective-user-owned,
empty-process delegation root on a cgroup-v2 domain hierarchy, with `cpu`, `memory`
and `pids` already enabled for children. Existing owned sibling leaves may coexist.
Paths are walked without symlink components; the exact root/leaf identities,
root controller settings and supported domain hierarchy are validated. The runtime only
creates its fresh `agentfw-mcp-<32 hex digits>` child, configures its controls,
attaches the child before exec and verifies membership. It does not enable parent
controllers, alter services, change global limits, or fix host permissions.
The sandbox does not mount writable cgroupfs or retain cgroup descriptors across
exec. Descendants inherit the boundary; missing interfaces, membership uncertainty
or limit/controller drift fail closed.

Only the standard `/sys/fs/cgroup` hierarchy is supported. A same-UID or privileged
host operator is trusted. Sampling cannot attest to a limit loosened and restored
between observations; the untrusted sandbox itself receives no such control access.

```sh
chmod 600 /operator/private/budget.json
AGENTFW_MCP_LINUX_BUDGET=/operator/private/budget.json \
AGENTFW_MCP_SERVER_PROFILE=/operator/private/profile.json \
agentfw mcp --native-admission --id filesystem-budgeted -- \
  /operator/pinned/node \
  /operator/private/package/node_modules/@modelcontextprotocol/server-filesystem/dist/index.js \
  /workspace
```

Use the existing registry, policy, runtime identities, workspace and classifier
environment from the [filesystem installation instructions](MCP_REAL_FILESYSTEM.md)
or [Git profile guide](GIT_MCP_PROFILE.md).
The same opt-in variable applies to the accepted selected Git launch profile.
It does not rewrite the installed profile, policy or approval authority.

| Environment | Requested budget outcome |
| --- | --- |
| Linux x86-64, selected filesystem/Git, prepared delegated cgroup v2 and existing bubblewrap prerequisites | Supported enforced path |
| Linux missing delegation, ownership, controllers or required kernel interfaces | Explicit refusal before server execution |
| Ordinary hosted CI without explicit preparation | Negative/refusal checks; no positive containment claim |
| Dedicated disposable SOU-79 CI service | Explicit narrow systemd delegation, real positive acceptance |
| Windows or macOS | Unsupported for this Linux cgroup profile; existing native guarantees retain their separate scope |

`mcp_real_budget_start`/`mcp_real_budget_end` identify enforced versus unbudgeted
launches and bounded safe metadata. Fixed terminal reasons include
`mcp_budget_memory_exhausted`, `mcp_budget_pids_exhausted`,
`mcp_budget_wall_expired`, `mcp_budget_limit_drift`,
`mcp_budget_membership_unverified`, `mcp_budget_observation_failed`, and
`mcp_budget_cleanup_unverified`; controller loss can report
`mcp_budget_controller_unavailable`. Resource failure stops transport, retires pending
native work and verifies cleanup. A dispatched operation may already have run;
withholding its result does not undo its effects.

The selected Linux runtime also uses [owned crash supervision](MCP_LINUX_CRASH_SUPERVISION.md)
outside this server budget. Once its private owner is armed, collector loss can
stop the selected server and remove this launch's leaf without running collector
destructors. Preparation before owner creation can still leave an empty leaf;
cleanup is unverified for that window and may require exact owned-leaf operator
removal. Process cleanup does not acknowledge immediate native retirement:
unreachable native state retains its existing expiry/refusal behavior. Never
remove an unrelated cgroup as recovery.

## Reproducible disposable Linux acceptance

[The dedicated workflow](../../.github/workflows/sou79-resource-budgets.yml) builds
the exact candidate, checksum-pinned Node v22.22.0 and bubblewrap v0.13.1. The
original locked `@modelcontextprotocol/server-filesystem@2026.8.31` package remains
unchanged for useful reads, concurrent FIFO calls, cancellation and a live peer.
A separately hashed owned fixture uses the same production selected-profile,
bubblewrap, admission and cgroup launch path for memory growth, process/thread
pressure, CPU load, wall expiry, denied results and operator-injected limit drift.
It is explicitly labelled as an adversary, not the original upstream server.

Only this job invokes `sudo systemd-run` to create one fresh disposable unit with
`User=` and `Delegate=cpu memory pids`. An outer 2 GiB/no-swap, 256-task, 200% CPU,
15-minute envelope supervises all potentially exhausting cases. Inside that unit,
the unprivileged acceptance process moves itself to an owned manager leaf, enables
controllers only within that unit, and prepares its private budget root. Other CI
jobs retain their prior permissions. No host cgroup-root ownership, sysctl or
AppArmor changes are made. Unit teardown belongs to systemd; normal successful
acceptance must independently observe every server leaf removed before returning.

The parent observer reads effective controls, kernel OOM/PID/CPU counters, charged
memory peak, task peak, actual host PID/start-time membership and disappearance.
Its 2 ms sampling interval is not a hard real-time guarantee; event counters and
kernel peak accounting supplement samples.
Control-read `ENOENT`/`ENODEV` during kernel teardown is quarantined for at most
250 ms without accepting further resource samples. Only independently observed
disappearance of the same pinned leaf resolves it; a live or replaced leaf, late
disappearance, or permission error fails acceptance.
The owned memory test permits at most
32 MiB observed accounting overshoot beyond its requested cap; this is an explicit
acceptance bound, not a claim of a universal kernel overshoot ABI. CPU evidence
requires actual nonzero workload, throttling and measured aggregate usage within
the rate plus declared sampling/period tolerance. Parent fallback killing makes
the run fail and cannot serve as production cleanup evidence.

The required run reports passed/failed/skipped denominators and exact source,
binary, original server, fixture package, configuration and per-budget identities.
Missing Linux, positive execution or any prerequisite fails; a plan-only command
starts no process and cannot count as acceptance. Protocol/stderr observers keep
fixed private buffers, scan synthetic stderr canaries, and persist only hashes,
static metadata and kernel witnesses. No raw child stdout/stderr or secret-bearing
logs are artifacts. Sanitized reports and build identities are retained for 30 days.

The supported kernel must provide `memory.peak` and `cgroup.kill`. `pids.peak` is
used when available; otherwise the reported task peak is a sampled lower bound.
The 25 ms monitor period is nominal, not a maximum scheduling/reaction latency.
The three-second cgroup cleanup wait is separate from process reap and stderr
draining; synchronous kernel operations are not given a hard real-time deadline.
Exposed pinned files and workspace/package trees must not introduce HugeTLB-backed
memory outside the charged-memory guarantee. HugeTLB creation paths are denied;
unexposed host mounts do not become part of the sandbox merely by existing.

Primary references: [Linux cgroup-v2 semantics](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html)
and [systemd v249 delegation/resource controls](https://github.com/systemd/systemd/blob/v249/man/systemd.resource-control.xml).
