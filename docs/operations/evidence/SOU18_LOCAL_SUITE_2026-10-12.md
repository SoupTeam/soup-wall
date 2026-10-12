# SOU-18 combined local run, 2026-10-12

The new combined runner passed disposable installation, seven status/MCP cases
and 30 paired latency measurements on a fresh build of main after classifier
PRs #77 and #78. This is bounded fixture evidence. Final generic SOU-15,
actual-host and administrator merge-protection acceptance remain open.

The [selected JSON evidence](SOU18_LOCAL_SUITE_2026-10-12.json) includes the
aggregate report, original status frames, installation checks, raw measured
durations and hashes of the full local artifacts. Follow the
[combined-run procedure](../CLEAN_SETUP_ACCEPTANCE.md#run-the-local-probes-together)
to reproduce it. The three existing probes and their contracts are unchanged.

## Candidate and build

| Item | Observed value |
| --- | --- |
| Candidate | `ea418600b8a03559bc822e81c9dc05f4ed1c1b43`, clean detached checkout |
| Agent SHA-256 | `f41d546526402fbdd8c6a054bd21a61ec75e61defd6cdcfb62d58059e9b66a94` |
| Rule baseline SHA-256 | `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd` |
| Build | Pinned `deploy/Dockerfile.test`, Rust/Cargo 1.98.1, locked dependencies |
| Runtime | Linux x86_64, kernel `7.0.0-38-generic`, glibc 2.43, Python 3.14.4 |
| Hardware | AMD Ryzen 7 4800H, 16 logical CPUs, 15,245,704 KiB reported memory |
| Container limits | Linux amd64, network disabled, read-only root, no capabilities, 2 CPUs, 2 GiB |

All **292 build-manifest input hashes** matched the clean candidate. The
extracted Agent matched the build manifest and every probe's recorded binary.
The runner was invoked from its separate development checkout; its own hash is
recorded independently. Source and binary remained stable throughout the run.
The evidence JSON also records policy, schema, profile and generated config
hashes. Generated paths and ports make some config hashes specific to this run.

The existing Docker baseline passed **144 cases**, with no failures or skips.
This baseline includes deterministic classifier/judge fixtures and does not
measure general classifier quality. Docker build time was **25.518 seconds**
with warm layer/Cargo caches, not a cold installation measurement.

## Installation and execution

All six installation checks passed, including preservation of unrelated
synthetic settings, token non-disclosure and removal of the owned installation.
In the status probe, installation of the supplied binary through daemon
readiness took **26.309 ms**; through MCP discovery it took **237.624 ms**.
These single observations exclude compilation and downloads.

All seven status cases passed:

| Case | Preflight exit | Executions | Client observation |
| --- | --- | --- | --- |
| Enforcing read | 0 | 1 | Original useful result and call ID |
| Enforcing delete / Deny | 0 | 0 | Correlated policy refusal |
| Enforcing send / Ask | 0 | 0 | Confirmation refusal, no receiver delivery |
| Enforcing result withholding | 0 | 1 | Refusal without the server's private fixture marker |
| Daemon unavailable | 2 | 0 | Collector fails, no result or direct fallback |
| Daemon recovered | 0 | 1 | Original useful result in a fresh session |
| Shadow daemon | 4 | 0 | Native collector refuses |

The final server ledger matched the three expected executions. Original native
frames, arguments and IDs were retained. The inventory file stayed unchanged,
the independent receiver remained empty and owned temporary profiles were
removed. The shadow configuration disables native admission, as required by the
existing implementation; this is not evidence of native shadow protection.

## Warm paired MCP duration

The existing latency probe used persistent direct/protected sessions, one
excluded warmup pair and 30 measured pairs of identical useful reads. The direct
server is an unprotected measurement control. Protected timing includes
per-call Python classifier startup.

| Measurement | p50, ms | p95, ms |
| --- | --- | --- |
| Direct request | 0.375 | 0.567 |
| Protected request | 77.586 | 98.476 |
| Paired added duration | 77.199 | 98.096 |

All 60 measured observations had complete execution/result witnesses, with
zero fixture false interruptions and zero execution anomalies. These counts
are not population accuracy or false-positive estimates. No numeric latency
threshold is agreed, so `acceptance_passed` remains `false`. The earlier dated
run used a different candidate and environment; these timings do not establish
a controlled performance regression.

## Reproduction and retained evidence

Build this candidate using the pinned Docker procedure, extract its Agent and
compare its hash with `fixture.build.agentfw_sha256`. From a checkout containing
the combined runner, run:

```sh
python3 scripts/run-sou18-acceptance.py --run \
  --repo /absolute/path/to/clean/ea418600-candidate \
  --agentfw /absolute/path/to/extracted/agentfw \
  --expected-commit ea418600b8a03559bc822e81c9dc05f4ed1c1b43 \
  --pairs 30 --output /absolute/path/outside/candidate/new-suite-run
```

The full local reports and sanitized witness files are retained under ignored
`target/sou18-evidence/2026-10-12/{build,suite}` in the contributor's workspace.
Their sizes and SHA-256 values are in the committed JSON. This selected evidence
is not a replacement for those files; CI retains its own complete `sou18-suite-*`
artifacts for the actual tested merge commit. The first development run is also
retained locally; the committed record describes the final runner revision.

Local regression checks passed: **302 script tests** with 5 native-Windows
skips, and **44 benchmark tests** with 18 skip records. Benchmark skips require
an explicitly selected AgentDojo checkout/runtime or disposable Agent; two are
class-level skips, so subtraction does not give a passed-test count. The script
suite includes 17 new runner regressions for incomplete evidence, wrong source,
modified witnesses, timeout, output preservation and Windows latency skips.

Rust/Cargo were absent on the host, so fmt, clippy and the full workspace suite
were deferred to required CI. The pinned container baseline was run locally.
Native macOS/Windows, WSL2, actual Claude/Codex hosts and external models were
not run locally. Direct server launches and other unintegrated host paths remain
outside this evidence. No GitHub settings were changed, and no live
administrator merge-gate cases were performed.
