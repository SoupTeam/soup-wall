# Agent self-test (`agentfw self-test`)

One command checks an already installed Agent end to end and writes a
versioned JSON report. It runs a small, safe MCP exercise in a temporary
workspace that it creates, owns and removes. It is a supported product command
for operators, not a development scorecard: every result comes from witnessed
behavior, never from health or configuration checks alone.

Roadmap: Phase 5 (first useful installed experience). Phase 4 stays open; this
command makes no live-model or attack-effectiveness claim.

## Requirements

- **Linux, macOS or native Windows.** Supported profiles are `linux-stdio-mcp-admission-v1` on
  Linux, `macos-stdio-mcp-admission-v1` on macOS and `windows-stdio-mcp-admission-v1`
  under a non-elevated Windows token. See the [Windows operator guide](WINDOWS_SELF_TEST.md).
  Other platforms print and
  record `unsupported` (exit 5) and claim no protection.
- An installed `agentfw` executable, selected explicitly with `--agent`. It is
  never discovered from `PATH`.
- The locally installed Task 1 classifier `rule_baseline.py`, its expected
  SHA-256 (the revision you reviewed), and a Python 3 interpreter.

No Cargo, Docker, source checkout, network access, model download or provider
account is needed. A missing or wrong asset produces an actionable
`incomplete` result (exit 4). There is no substitute classifier and nothing is
downloaded.

## Run it

On Linux:

```sh
agentfw self-test \
  --agent /opt/soup-wall/bin/agentfw \
  --classifier rule-baseline \
  --classifier-script /opt/soup-wall/classifier/rule_baseline.py \
  --classifier-sha256 "$(sha256sum /opt/soup-wall/classifier/rule_baseline.py | cut -d' ' -f1)" \
  --classifier-python /usr/bin/python3 \
  --report ./agentfw-self-test.json
```

On macOS:

```sh
agentfw self-test \
  --agent /opt/soup-wall/bin/agentfw \
  --classifier rule-baseline \
  --classifier-script /opt/soup-wall/classifier/rule_baseline.py \
  --classifier-sha256 "$(shasum -a 256 /opt/soup-wall/classifier/rule_baseline.py | cut -d' ' -f1)" \
  --classifier-python /usr/bin/python3 \
  --report ./agentfw-self-test.json
```

Compare the printed SHA-256 with the revision you reviewed instead of trusting
the file you are testing. Optional flags:

| Flag | Meaning |
|---|---|
| `--work-parent DIR` | Existing directory for the owned workspace (default: the system temporary directory) |
| `--daemon-port PORT` | Preferred first loopback port; if it is busy, a free port is used |
| `--timeout-seconds N` | Bound for the whole run, 10 to 600 (default 120) |
| `--keep-workspace` | Keep the workspace (synthetic data only) for inspection |

`--report` must be a new file in an existing directory. An existing file is
never replaced; in that case nothing runs and the exit code is 4.

## Exit codes

| Exit | Result | Meaning |
|---|---|---|
| 0 | `passed` | Every scenario was witnessed and cleanup completed |
| 3 | `failed` | A witness contradicted an expectation (for example, a refused send reached the receiver) |
| 4 | `incomplete` | Something was missing, unavailable, interrupted, timed out or not cleaned up; protection is not established |
| 5 | `unsupported` | The platform has no supported profile |
| 2 | (usage) | Invalid command-line arguments |

## Controlled path

The exercised path is exactly:

scripted stdio MCP client → `agentfw mcp --native-admission` collector →
selected `rule-baseline` classifier → owned `agentfw serve` daemon
(`/native/v1`, shipped default policy, bundled registry) → bundled fixture MCP
server → owned `127.0.0.1` receiver.

The fixture MCP server is the hidden `agentfw self-test-fixture` command of the
running binary. It offers `read_document` (registry: `read_only`, untrusted
result) and `send_http` (registry: `network`, egress host from `/url`). It reads
only the owned notes and posts only to the exact owned receiver URL. The
policy is the shipped default policy embedded in the binary, unchanged.

## Scenarios

| Scenario | Expected and witnessed |
|---|---|
| `allowed_read` | `read_document` executes once; the client receives the exact note bytes; request and result bytes are unchanged |
| `adversarial_result` | `read_document` of a synthetic injected note executes, but its result is withheld (`ask-injection-in-result`); the marker never reaches the client |
| `protected_send_refused` | `send_http` with the synthetic AWS example key is refused (`deny-secret-egress`); the MCP child ledger and the receiver record zero executions and zero connections |
| `useful_read_after_refusal` | A later `read_document` still executes and returns the exact note bytes |
| `daemon_loss` | The owned daemon is killed; a benign protected send then never reaches the MCP child or the receiver, and the collector stops |

Witnesses are independent of the Agent's own decision: the fixture server
records each frame it receives before acting, and the receiver counts every
connection and body. For each of the first four scenarios a classifier receipt
must show the pinned classifier revision and `policy: reached`. A Deny or Ask
receipt alone is never counted as a pass.

## Report (`sw-self-test/1`)

| Field | Content |
|---|---|
| `result`, `exit_code`, `explanation` | Overall outcome and a one-line reason |
| `identities` | SHA-256 of the Agent binary, runner, classifier source (with the expected value and Python version), policy, registry and fixture bundle |
| `configured` | Daemon start attempts, health, authenticated `protection-status` (mode, owning PID, policy and registry identity), released manifest and a direct receiver control. This is configured state, **not** witnessed protection |
| `scenarios` | Per scenario: status, expected behavior, observed outcome, MCP child executions, receiver deliveries and connections, latency, byte checks and receipts (classification and native audit verdict/rule) |
| `summary`, `cleanup`, `duration_ms` | Status counts, what was stopped and removed, total time |
| `controlled_path`, `limitations` | The exact path above and what is not claimed |

Statuses are `passed`, `failed`, `unavailable` (a prerequisite was missing, so
the scenario did not run), `unsupported` and `incomplete` (started but not
finished). The report contains no credentials, tokens, user paths, host
configuration, invocation arguments, note text or synthetic key.

## Isolation and bounds

- The workspace is created as a new `0700` directory named
  `agentfw-self-test-<random>` with an owner marker. Its `home` is HOME for
  every child, so the operator's own `~/.agentfw`, settings, services and audit
  files are never read or changed.
- Children get a cleared environment (`PATH=/usr/bin:/bin`, the owned HOME,
  TMPDIR and XDG directories). No inherited `AGENTFW_*`, provider or proxy
  variables reach them.
- Each child leads its own process group and is stopped with its group. A
  group is signalled only while its leader is still unreaped, so no unrelated
  process can be targeted.
- Removal checks the canonical parent, the name prefix, the owner marker and
  that the path is a real directory. Anything else is reported and left alone.
- Time is bounded per run (`--timeout-seconds`), per reply (15 s) and per daemon
  start (30 s). Client frames are limited to 512 KiB, the receiver to 32
  connections and 64 KiB bodies, and log reads to 8 MiB.

## Failure handling

| Situation | Behavior |
|---|---|
| Busy port | The daemon exits with `port_in_use`; up to three attempts use fresh free ports |
| Another process answers health | The authenticated status PID must equal the owned daemon, or the attempt is rejected |
| Daemon binary differs from `--agent` | The attempt is rejected (`daemon_binary_identity_mismatch`) |
| Startup failure or timeout | `unavailable` scenarios and the start attempts in `configured.daemon`; exit 4 |
| Malformed, truncated or oversized reply | That scenario is `incomplete`, so the run cannot pass; a stopped collector leaves later scenarios `incomplete` |
| SIGINT, SIGTERM or SIGHUP | Owned processes are stopped, the workspace is removed, and the report says `Interrupted`; exit 4 |
| Cleanup failure | `cleanup` names the reason; exit 4; the retained workspace path is printed, not stored in the report |

## What this does not show

- Claude Code, model context or live-model effectiveness: the client frames are scripted.
- Coverage for other MCP servers or tools: each needs its own reviewed registry.
- How a client uses a released result after it leaves the collector.
- An approval channel: the opt-in [SOU-48 Ask approval](NATIVE_ASK_APPROVAL.md) is not
  enabled, so Ask is enforced as a correlated refusal.
- An OS sandbox: the collector is an admission boundary for stdio MCP frames.

## Checks

```sh
cargo test --locked -p agentfw --lib self_test
cargo test --locked -p agentfw --test self_test
```

The integration suite runs the built binary from a temporary directory outside
the repository. It covers a full pass after a forced port collision,
interruption, a missing and a wrong classifier revision, a daemon that cannot
start, refusal to replace an existing report and the fixture server's
destination check. See the [SOU-61 Linux evidence](evidence/SOU61_SELF_TEST_2026-10-16.md)
and [SOU-77 macOS evidence](evidence/sou-77-evidence.md).

### Native macOS acceptance scope

The retained native macOS positive evidence covers ARM64. Intel x86-64 remains conditional until a native positive run is retained. The integration acceptance requires a working local Python 3 interpreter and fails if it is missing; it does not count unavailable prerequisites as a passing skip.
