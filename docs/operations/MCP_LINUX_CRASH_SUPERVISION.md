# Owned crash supervision for selected Linux MCP servers

The selected original [filesystem](MCP_REAL_FILESYSTEM.md) and
[Git](GIT_MCP_PROFILE.md) profiles use a production owner outside the server's
resource budget and a trusted PID 1 inside its private PID namespace. This
extends process ownership through unexpected collector loss. It retains the
existing pinned upstream servers, read-only mounts, network restrictions,
bounded stderr handling and independent native admission for calls and results.
Generic arbitrary-command MCP and the inline file/HTTPS executors have separate
lifecycle contracts; selecting this boundary does not extend their guarantees.

This ownership is automatic for the selected Linux filesystem/Git launch. It has
no new operator configuration or public helper command. Continue using the
installed profile, registry, policy and optional resource-budget configuration.
The existing selected-profile refusal on unsupported platforms remains explicit.

## Ownership and startup

The trusted outer owner is a separate invocation of the same Agent executable.
It owns the selected bubblewrap child, its private control connection and the
exact resource handles delegated for this launch. It runs outside the selected
server's cgroup so exhausting the server's quota cannot consume the only cleanup
owner. The collector retains its ordinary resource monitor and structured exit
path; the crash owner does not replace quota accounting.

Bubblewrap runs the trusted inner owner as PID 1 with `--as-pid-1`. A private
descriptor passed through `--sync-fd` binds it to the outer owner's lifetime.
The inner owner establishes its lease before starting the original server.
Invalid startup, missing lease authority or loss of the private channel is a
failure, never permission to run an unsupervised original server. There is no
named reconnect endpoint and no recovery by presenting an old numeric PID.

The launch is armed only after the collector receives and validates private
owner readiness. Resource preparation precedes the outside owner's creation:
if the collector is killed in that earlier window, no original server has
started, but a newly created empty cgroup leaf may remain. Cleanup is unverified
for that window. Inspect only the exact owned leaf and its recorded identity
before operator removal; never sweep a shared delegation root. Once the outside
owner exists, its inherited sealed launch plan and retained handles let it
finish cleanup independently of the collector.

The inner owner makes its control descriptor close-on-exec and prevents it from
being inherited by the original server. It becomes nondumpable before spawning
that child, preventing the sandboxed child from using ptrace or process-FD
inspection to acquire the lease or alter its supervisor. Child diagnostics and
MCP bytes are not interpreted as owner control messages.

The selected sandbox keeps its existing no-new-privileges, capability, namespace,
seccomp and, for Git, Landlock restrictions. The trusted executable is mounted
read-only from its retained executable identity. A missing executable dependency
or unsupported supervision prerequisite refuses startup. The owner does not
download a helper, modify an installed profile or weaken a sandbox to recover.

## Failure and cleanup

Collector death closes its private owner connection. The outer owner closes
server transport, stops the owned sandbox and descendants, and verifies the
owned resource boundary before returning. It uses retained process/resource
authority, not a later process-name lookup or a broad same-user kill command.
Cancellation and ordinary EOF use the same ownership and cleanup path.

The PID namespace supplies a second boundary: unexpected inner PID 1 death
terminates the namespace's remaining processes, including descendants that
double-fork or call `setsid`. The private lease covers the outer owner's failure;
the collector also treats owner loss as transport failure. Existing bubblewrap
parent-death handling remains part of the boundary. No destructor is required to
run in an abruptly killed collector for this path to stop the selected server.

With an explicit [Linux resource budget](MCP_LINUX_RESOURCE_BUDGETS.md), cleanup
uses only this launch's retained cgroup-v2 handles. Successful cleanup requires
the owned leaf to become empty and removable. The owner never scans a shared
delegation root and kills an unfamiliar leaf, enables a parent controller or
repairs a host service. Missing delegation still refuses a requested budget;
there is no unbudgeted fallback for a budgeted launch.

| Fixed runtime bound | Value and scope |
| --- | --- |
| Owner startup | 3000 ms for private startup and namespace identity |
| Owner observation | Nominal 25 ms polling, outside the server budget |
| Owner heartbeats | Sent to the collector and namespace PID 1 every nominal 100 ms |
| Liveness lease | 1500 ms absolute monotonic deadline; EOF or invalid input also stops the namespace |
| Expected shutdown intent | 500 ms for the private owner acknowledgement before collector-owned budget cleanup |
| Owned cleanup | 3000 ms wait for resource cleanup and process reaping |

The lease supplements the kernel parent-death chain. Its userspace polling can
be delayed by scheduling or the server's own CPU budget; it is not a universal
1500 ms maximum SIGKILL reaction time. The outer owner and collector retain
cleanup authority outside that budget. Existing stderr and native-request
deadlines are separate; the table does not sum them into an end-to-end SLA.
Collector-side expiry also withdraws protected result delivery if the outside
owner is stopped or otherwise cannot renew its lease. Buffered old heartbeat
bytes cannot renew an expired absolute deadline. Explicit requested shutdown has
its separate bounded cleanup wait.

Collector loss here means process death or closure of its private owner channel.
A live collector suspended with `SIGSTOP` or stuck without closing that channel
does not expire a separate collector-to-owner lease. The existing SOU-79 wall
monitor remains collector-dependent in that case. This increment covers abrupt
collector death and owner death/stall; it does not claim a general collector-hang
watchdog.

Bounded metadata uses `sw-mcp/linux-crash-owner/1`, a fresh startup instance,
process/start-time identities and fixed bounds. Runtime state distinguishes
`mcp_owner_active`, `mcp_owner_cleanup_verified`,
`mcp_owner_cleanup_unverified`, `mcp_owner_lost`,
`mcp_owner_liveness_expired`, `mcp_owner_control_failed` and
`mcp_owner_control_invalid`; an unexpected sandbox exit can report
`mcp_owner_sandbox_failed`. Cleanup observations separate process reaping,
namespace termination and owned resource removal. `runtime_failure` preserves an
earlier observed failure even when cleanup later succeeds. Expected shutdown
intent is acknowledged before the collector kills a budgeted leaf, so normal
cleanup does not erase an earlier fault or become an unexpected server failure.
These are static outcomes, not child-supplied descriptions or acknowledgements
of native retirement.

Process death and resource removal are distinct observations. A report must
identify which was verified and retain an unverified outcome when the runtime
could not observe completion. Polling periods and cleanup waits are operational
bounds, not a hard real-time scheduler or kernel-failure guarantee. A malicious
same-UID host operator, administrator and kernel failure remain outside scope.

## Recovery and native authority

Restart creates a new collector, owner, private channel and startup identity.
It does not reconnect to the previous server or reuse a previous pending call,
receipt or native grant. A surviving sibling collector keeps its own process
and resource ownership. Stale handles and an old session are not authority over
the replacement.

Terminating a process does not undo an effect that happened before the crash.
In-flight work remains uncertain unless an independent effect witness can
establish its outcome. A withheld result is not a rollback acknowledgement.

Process cleanup is also separate from daemon/session retirement. A collector
killed with `SIGKILL` cannot finish its normal authenticated session-end request.
When the daemon or network is unavailable, existing expiry and refusal behavior
remain explicit. This boundary does not claim immediate native authority
retirement or acknowledgement by an unreachable daemon. A fresh connection
does not restore pending authority from the dead collector.

## Disposable native Linux reproduction

The [required workflow](../../.github/workflows/sou86-crash-supervision.yml) and
[one-command driver](../../scripts/verify-sou86-crash-supervision.py) keep baseline
inventory separate from candidate protection acceptance. The baseline is the
accepted `2af2f35b326e0f70660b5c4cbde8134fe4ab9751` runtime. It already has
bubblewrap PID-namespace and parent-death containment after successful startup;
an observed baseline process disappearance is not evidence of newly implemented
owned resource cleanup.

For candidate acceptance, use a clean exact checkout on disposable Linux x86-64,
Python 3.12, cgroup v2 with systemd delegation, working unprivileged namespaces,
and the reviewed Node `22.22.0`, bubblewrap `0.13.1` and Git `2.51.2` assets.
The workflow contains their archive hashes and builds both exact candidate
executables with `cargo build --locked -p agentfw --bins`. The original Git
server installer uses its committed hash-locked Python dependencies. Replace the
absolute asset paths below with those prepared assets; the output directory must
be new and outside the checkout.

```sh
sou86_unit="sou86-$(date +%s)-1"
sou86_git=/absolute/reviewed-git-2.51.2/git
sudo systemd-run --quiet --wait --pipe --collect --unit="$sou86_unit" \
  --property="User=$(id -un)" --property="Group=$(id -gn)" \
  --property='Delegate=cpu memory pids' \
  --property=MemoryMax=2G --property=MemorySwapMax=0 \
  --property=TasksMax=256 --property=CPUQuota=200% \
  --property=RuntimeMaxSec=15min --property=KillMode=control-group \
  --working-directory="$PWD" /usr/bin/env "PATH=$PATH" \
  python3 -B scripts/verify-sou86-crash-supervision.py --run --mode acceptance \
  --agentfw "$PWD/target/debug/agentfw" \
  --node /absolute/node-v22.22.0/bin/node --npm /absolute/node-v22.22.0/bin/npm \
  --bwrap /absolute/bubblewrap-0.13.1/bwrap \
  --git "$sou86_git" --git-sha256 "$(sha256sum "$sou86_git" | cut -d' ' -f1)" \
  --git-launcher "$PWD/target/debug/agentfw-git-sandbox" \
  --expected-commit "$(git rev-parse HEAD)" --runtime-source-commit "$(git rev-parse HEAD)" \
  --disposable-systemd-unit="$sou86_unit.service" --output /tmp/sou86-new-acceptance
```

Only this explicit disposable service receives delegated controls. The driver
runs as the ordinary caller inside it, verifies that exact fresh unit, and
prepares manager/budget children within it. It does not change host-root
ownership, sysctls, other services or global controller settings. For baseline
inventory, the workflow instead passes `--mode baseline-inventory` with the
separately built accepted runtime and its exact `--runtime-source-commit`.

Baseline inventory records its deadline observation before any explicitly
labelled harness recovery. It cannot produce a successful protection-acceptance
claim. Candidate evidence must exercise the production owner, original pinned
servers and separately identified adversarial fixtures. The independent parent
must observe disappearance before fallback cleanup; requiring harness recovery
fails protection acceptance.

Evidence separates useful original-server work, in-flight collector death,
outer/inner owner failure, detached descendants, cancellation, repeated crashes,
restart, unaffected peers, process disappearance and owned leaf removal. Exact
source, executable, original package, fixture and configuration identities bind
the observations to the candidate. Missing native Linux prerequisites,
incomplete observation or cleanup cannot become passing skips. Plan mode starts
no protected process and is not runtime acceptance.

For an armed candidate launch, the independent native observer requires owned
processes and its cgroup leaf to disappear within 10 seconds of the injected
failure. This is the disposable acceptance deadline under the documented host
prerequisites, separate from nominal runtime poll periods and daemon retirement.
The required candidate denominator is 22 protected cases, including outside-owner
`SIGSTOP`, `SIGKILL`, wrapper/PID 1 loss and the private descriptor/inspection
boundary. The five accepted-runtime baseline cases and separate pre-arm startup
inventory do not inflate that protection denominator. Independent useful peer
calls before and after failures establish that cleanup stays within its owner.

Only fixed safe metadata, identities, counts and independently witnessed effects
belong in retained reports. Raw MCP stdout, child stderr, private control bytes,
credentials and synthetic secret-marker payloads are not diagnostic artifacts.
The [stderr contract](NATIVE_MCP_STDERR.md) remains unchanged.

Primary references: [bubblewrap v0.13.1 implementation](https://github.com/containers/bubblewrap/blob/v0.13.1/bubblewrap.c),
[Linux PID-namespace teardown](https://github.com/torvalds/linux/blob/v6.8/kernel/pid_namespace.c),
[parent-death signal semantics](https://man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html),
[nondumpable process semantics](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html)
and [cgroup-v2 cleanup](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html).
