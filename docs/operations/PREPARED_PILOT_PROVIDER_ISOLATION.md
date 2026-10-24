# Provider input isolation for the prepared pilot (SOU-143)

The operator still selects the same seven provider inputs:
`ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_BASE_URL`, `HTTP_PROXY`,
`HTTPS_PROXY`, `NO_PROXY`, and `SSL_CERT_FILE`. They belong to the selected
pinned Claude/provider client. They are not MCP execution authority.

## Observed starting point and changed process graph

The previous prepared entry copied these values into a shared environment used
for daemon startup, readiness probes, the native launcher, and stop confirmation.
The native host boundary already cleared ambient executable configuration and
selected only these seven provider inputs. Original-server and classifier spawns
also already cleared their environments. Those existing downstream boundaries
are not evidence that the daemon or intermediate collector was isolated.

The new routing is:

| Process | Provider values | Reviewed inputs |
| --- | --- | --- |
| Prepared Python entry | Transient operator input | Existing validated selection and private run state |
| Source/version/ELF diagnostics | Absent | Fixed system PATH, locale, disabled global Git config; installed toolchain homes only for explicit compiler lookup |
| Prerequisite/build children | Absent | Existing finite tool paths, private HOME/TMPDIR, pinned build options |
| Owned daemon | Absent | Private home/registry/policy and existing native authentication |
| Readiness and stop CLI | Absent | Same private home and selected exact binary |
| Native launcher | Absent from its environment | Anonymous sealed provider-input FD, consumed once before host exec |
| Selected Claude host | Selected seven inputs only | Existing fixed restricted flags and private executable configuration |
| MCP spawn utility | Empty overrides for the seven names | Fixed host environment; no provider values |
| Collector | Absent | `env -i` followed by finite existing native/profile/classifier inputs |
| Original filesystem/Git processes | Absent | Existing server sandbox environment clearing |
| Classifier | Absent | Existing isolated adapter environment |

The Python entry and native launcher are trusted transient input producers. The
launcher must read the selected values to hand the selected inputs to the authenticated host bootstrap;
this is not a claim of secrecy against the operator or arbitrary same-UID ptrace.
No credential broker, new token authority or ambient provider lookup is introduced.

## Anonymous transport and failures

The Linux prepared entry uses a bounded anonymous `memfd`, sealed against writes,
growth and shrinkage. Only the native launcher inherits that one descriptor.
The launcher verifies the seal, anonymous regular-file identity, size, strict JSON
(no duplicate or unknown keys), and permitted values, then closes it before child
execution. No provider values are stored in a selection, MCP configuration,
argument, run report, audit capability, or credential carrier on disk. Native
child-authority tokens keep their existing independent authenticated contract.

`--provider-env-fd` is an internal optional native-launcher input. Existing direct
`pilot-launch` invocations keep explicit operator environment support. When a
carrier is supplied it is authoritative: missing entries never borrow ambient
credentials. Requested prepared execution without an API key/auth token returns
`provider_unavailable` before launching a daemon or host. There is no automatic
login, alternate host, unprotected retry or credential fallback. Default plan
inspection needs no provider access. Non-Linux carrier use is unsupported.

Claude's MCP config replaces all seven provider fields with empty strings at
its spawn boundary. The `/usr/bin/env -i` utility then gives the collector only
its finite constructed inputs, discarding host/project/loader/Git/proxy ambient
configuration. An empty override contains no provider value. Actual behavior of
the pinned host must be observed; writing a JSON override alone is not proof.

Private output keeps the existing size cap and cleanup rules. A bounded streaming
redactor removes the exact selected values and JSON-escaped forms **before** log
writes, including secrets crossing pipe chunks and truncated prefixes at EOF.
Public failures retain the existing finite-code boundary and never echo raw
exceptions or subprocess output. Ordinary state is removed; authenticated stop
state retains its existing recovery semantics. No support artifact should contain
raw successful-exec environment traces.

## Qualification

Local boundary controls:

```sh
python3 -B -m unittest scripts.tests.test_pilot_provider scripts.tests.test_pilot_run
cargo test -p agentfw --lib pilot_
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

The sealed-carrier tests require Linux; a macOS skip is an unavailable result,
not a passing Linux observation. Use the accepted pinned native Ubuntu 24.04
preparation and the existing owned scripted loopback provider:

```sh
python3 -B scripts/qualify-prepared-pilot-run.py --selection ABSOLUTE_SELECTION \
  --expected-commit FULL_COMMIT --strace /usr/bin/strace \
  --verify-provider-isolation --output ABSOLUTE_NEW_OUTPUT
```

This opt-in extension supplies seven distinct synthetic inputs, captures kernel
successful `execve` environment arrays privately, and exports only finite role
counts and presence/absence booleans. Incomplete/missing role evidence cannot
prove isolation. An independent loopback handler verifies expected synthetic
request authentication. A 401 case deliberately echoes owned canaries through the
error path; the next useful run is a fresh restart. Ordinary cancellation, host
crash, daemon loss, timeout, exact Ask and emergency stop reuse the existing
original-server witnesses. Raw trace arrays, argv, provider values and live paid
provider traffic are excluded from retained evidence.

Required final qualification includes actual pinned-host environment observations,
useful filesystem/Git operations, startup/missing-provider refusal, rejection,
restart, stop, retained-state/log redaction and owned cleanup. Do not substitute
mock command inspection or a CLI preview for those results. Preserve every failed
and incomplete attempt. Final shared CI/admission/main integration is TL-owned.

## Focused native first slice

The existing manual `sou79-resource-budgets.yml` workflow accepts
`prepared_focus: "143"` on this branch. This selects only native Ubuntu
24.04 compile/unit/Clippy controls in a transient ordinary-user service. Candidate
source is read-only, writes stay in isolated scratch (plus the explicitly owned
delegation for budget controls), and candidate execution has only private
loopback networking. Dependency fetch is a separate trusted setup step that
requires manifests and Cargo configuration to match reviewed main
`04efdf1d959599238a0a9a3eb42cbe26b3531b74`. Raw target logs remain private;
retained artifacts contain bounded status, hashes and projected compiler messages.

This is a compile/capability slice, not original-host or final admission evidence.
The default `off` keeps the existing manual budget qualification unchanged.

For the complete actual-host route set both `prepared_focus: "143"` and
`prepared_host: true` in that manual workflow. The successful same-source native
binaries are reused read-only. Trusted setup verifies the accepted profile locks,
fetches pinned upstream inputs into private scratch and seeds offline npm/wheel
caches. Only the existing exact job-scoped bubblewrap permission is provisioned;
no host-wide namespace setting is relaxed. Candidate preparation and all provider
traffic then run offline in a private network namespace. A separate parent-side
projection requires all thirteen normal/preflight cases and four stop cases,
independent process/protocol/log/artifact observations, and zero remaining owned
processes. Its negative controls reject missing/contradictory evidence. Raw traces,
private logs and process identities stay in disposable scratch.

## Host helper execution boundary

The pinned Claude itself probes system Git during startup. Its trusted Bun
preload is embedded in Agent and supplied through a sealed anonymous code FD.
The host initial exec receives no provider values. Ambient Bun/Node preload
settings are discarded; a private empty Bun configuration and disabled env-file
loading prevent project configuration from selecting additional code.

Before Claude application code starts, the preload installs provider-free Node
child_process and Bun spawn boundaries, including explicit child environments
and Node's low-level asynchronous spawn. The unreviewed native Bun shell path
refuses rather than becoming a credential-bearing fallback. MCP collectors retain
the existing finite environment and original filesystem/Git sandbox boundaries.

Only after these boundaries are installed does the preload request input over a
private Unix datagram socket. The native parent requires kernel SCM_CREDENTIALS
matching the exact spawned host PID and operator UID. It then supplies at most
16 KiB of strict, selected JSON. The host closes both inherited descriptors,
removes bootstrap metadata, and sets the seven provider inputs for its own client.
An ignored/failed preload, forked sender or missing greeting receives no inputs;
startup fails within the bounded handshake window and uses owned group cleanup.
No provider JSON is stored on disk or passed in argv. This is the reviewed pinned
host boundary, not a sandbox for arbitrary hostile JavaScript inside that host.

The native qualifier independently checks successful exec environments and the
same host PID's actual recvfrom/close syscalls, plus authenticated loopback
requests. Public evidence contains no packet bytes, keys, paths or PIDs. It still
requires useful original filesystem/Git operations, restart, stop and log/error
redaction. The earlier execute-only Landlock experiment is retained as failed:
its inherited mount restriction prevented original MCP namespace startup.
