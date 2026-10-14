# SOU-18 integration evidence, 2026-10-13

The combined runner passed all four requested stages on current main at
`64aacd77668ec7dc0a4913036ebf3bde35fc3635`: setup, status/MCP, paired latency
and the accepted SOU-17 generic boundary matrix. This checks the merged
classifier/policy integration. Final acceptance still depends on SOU-15's
operation-level constrained executor and an actual supported host run.

PR #93 supplies resource preparation and retains `resource_executor_unsupported`.
It does not complete constrained execution. The generic matrix uses controlled
classifier replies with the production policy/admission path; it does not measure
classifier accuracy or demonstrate arbitrary-server containment.

## Candidate and environment

| Item | Recorded value |
| --- | --- |
| Candidate | `64aacd77668ec7dc0a4913036ebf3bde35fc3635`, clean detached checkout |
| Agent SHA-256 | `cd5700cf11c27917abc920a1ab7a0645f70f485b82900ae027387144f622feac` |
| Build | Pinned Docker test image, locked dependencies, Rust/Cargo 1.98.1 |
| Native probes | Linux x86_64, kernel 7.0.0-38-generic, Python 3.14.4, 16 logical CPUs |
| Docker fixture | linux/amd64, 2 CPUs, 2 GiB, no network, read-only root, no capabilities |
| Suite start | 2026-10-13 17:14:38 UTC |

All 318 build-manifest input hashes matched the clean candidate. The extracted
Agent matched the manifest and every child report. The wrapper ran from the
development checkout; its own source hash is recorded separately. Source and
binary remained stable and owned temporary profiles were removed.

The Docker baseline passed **146 cases**, without failures or skips. Its
deterministic fixtures are not a general classifier-quality evaluation.
The cached Docker build took 27.026 seconds. This is not cold-install timing.

## Observed behavior

| Stage | Result | Scope |
| --- | --- | --- |
| Setup | 6 checks passed | Disposable install, settings preservation, preflight states, token non-disclosure and removal |
| Status/MCP | 7 cases passed | Useful Allow, zero-execution Deny/Ask, withheld result, outage, recovery and shadow refusal |
| Paired latency | 30 measured pairs passed | Identical useful reads through persistent direct/protected sessions, plus one excluded warmup pair |
| Generic boundary | 15 cases passed | Mixed/unknown actions, ordinary policy decisions, malformed replies and independent execution/result witnesses |

The status ledger contains the three expected executions. The separate receiver
remained empty. The generic matrix contains four executions, 505 released
original-result bytes, and the single expected local mixed-action delivery.
Malformed classifier replies remain technical failures; they are not counted as
policy Deny decisions. Neither unconfirmed Ask nor Deny reaches the executor.

| Warm MCP measurement | p50, ms | p95, ms |
| --- | --- | --- |
| Direct request | 0.359 | 0.579 |
| Protected request | 66.184 | 108.233 |
| Paired added duration | 65.819 | 107.654 |

Protected timing includes per-call Python classifier startup. There were zero
fixture false interruptions and zero execution anomalies in the 60 measured
observations. No numeric performance limit is agreed. These counts do not
estimate population accuracy or false-positive rates, and comparisons with
earlier dated runs are not controlled performance comparisons.

The inherited status report retains its original, now-stale limitation about
unknown/mixed routing. The separate generic report tests that merged behavior;
this change corrects future status reports without rewriting historical bytes.

## CodeQL configuration and live observations

The read-only audit at 17:05:54 UTC observed active main ruleset **24846282**
with CodeQL security threshold `high_or_higher` and alert threshold `errors`.
Existing required checks and one approving review remain configured. Current
main had successful Rust, Python and Actions analyses and zero open alerts in
the observed default-branch inventory. This observation predates the canary.
No GitHub settings, bypass permissions or alert dismissals were changed here.

The default-setup endpoint returned 403 and classic branch protection returned
404. Those are unavailable observations, not evidence of missing protection.
Bypass actors were not available in the saved ruleset view. The account has push
access but not administration access.

[Disposable PR #100](https://github.com/SoupTeam/soup-wall/pull/100) tested a clean
static fixture, then an intentional scanner-only finding. The fixture was never
executed and is absent from this implementation branch. The PR was closed
without merging at **17:28:27 UTC**; its saved `mergedAt` is null.

| Case | Observed scanner evidence | Live rule verification |
| --- | --- | --- |
| Clean analyzed head `ec6bce2c23e810e792c5841c029e33b101074384` | Rust, Python and Actions analyses match this exact head; separate CodeQL results check succeeded with no new alerts | Unverified: rule-specific permission to proceed was not available |
| New head `ba8e52686d3c849287a9d06fefbe2d7320b3309f` awaiting analysis | All three analyses were in progress and CodeQL results were queued; earlier-head success was retained separately | Unverified: generic `BLOCKED` does not identify the blocking rule |
| Controlled finding on `ba8e52686d3c849287a9d06fefbe2d7320b3309f` | [Alert #94](https://github.com/SoupTeam/soup-wall/security/code-scanning/94), `py/code-injection`, critical/error; separate CodeQL results check failed | Unverified: scanner failure is observed, but rule-specific rejection was not available |

The finding meets the observed rule thresholds. The pending, clean and finding
snapshots are retained independently. They do not certify the three live merge
gate cases: the available browser was signed out, the rule-suite endpoint
returned 404, and public GraphQL exposed only aggregate merge status. Required
review and an unrelated CI failure also blocked the clean PR. No merge was
attempted to probe protection. Administrator verification of the actual scanning
rule's clean/pending/finding results remains necessary.

At the retained finding snapshot, Python and Actions analyses matched the new
head while Rust was still running. The results check both reported the critical
finding and warned about the missing Rust configuration. Previous-head Rust
success is not counted as current. This is sufficient to demonstrate detection
of the Python fixture, but not completion of all analyses on the finding head.

The unrelated clean-control CI failure was in
`managed_lifecycle_restores_last_working_version`: a generated instance ID began
with a hyphen and the managed child rejected it as an option (`unexpected
argument '-y'`). The retained `gate-clean-all-features.log` shows the exact
failure. The canary changed only two static fixture files; it did not change
the lifecycle implementation. This failure must not be attributed to CodeQL.

## Reproduction and review

The [manifest](SOU18_INTEGRATION_2026-10-13.json) records source/binary identity,
independently recomputed stage grades and every retained file hash. The
[compressed witness bundle](SOU18_INTEGRATION_2026-10-13.witnesses.json.gz)
contains full child reports and their original synthetic artifacts, including
complete latency rows, generic classifier inputs/replies, native audit records,
executor/receiver evidence and the client/server transcripts. The build manifest,
all 146 case logs, local test logs and public GitHub observations are included.
The Agent executable, private profiles and credentials are excluded.

The bundle is UTF-8 JSON compressed with gzip. Each `files` entry has `text`,
`bytes` and `sha256`; `text.encode("utf-8")` reconstructs the original bytes.
Inspect and verify it without executing retained source:

```sh
python3 - <<'PY'
import gzip, hashlib, json
from pathlib import Path
root = Path("docs/operations/evidence")
manifest = json.loads((root / "SOU18_INTEGRATION_2026-10-13.json").read_text())
raw = (root / manifest["archive"]["file"]).read_bytes()
assert hashlib.sha256(raw).hexdigest() == manifest["archive"]["sha256"]
bundle = json.loads(gzip.decompress(raw))
for name, item in bundle["files"].items():
    data = item["text"].encode("utf-8")
    assert len(data) == item["bytes"]
    assert hashlib.sha256(data).hexdigest() == item["sha256"], name
print(bundle["files"]["suite/generic/report.md"]["text"])
PY
```

Before packaging, the wrapper independently regraded every child report using
the candidate's accepted helpers and checked the generic/latency artifact hashes.
The full recorded classifier reply table and all final witnesses remain available
for another reviewer to regrade; the archive is not a summary-only selection.

Follow the [combined-run procedure](../CLEAN_SETUP_ACCEPTANCE.md#run-the-local-probes-together)
and retain the matching build manifest. With the wrapper from this change:

```sh
python3 scripts/run-sou18-acceptance.py --run --include-generic \
  --repo /absolute/path/to/clean/64aacd7-candidate \
  --agentfw /absolute/path/to/extracted/agentfw \
  --expected-commit 64aacd77668ec7dc0a4913036ebf3bde35fc3635 \
  --pairs 30 --output /absolute/path/outside/candidate/new-suite-run
```

Omitting `--include-generic` preserves the existing three-stage behavior and
schema. With the flag, all four stages are required. Missing witnesses, changed
inputs, failed children or unsupported stages cannot become a suite pass.
Linux and macOS CI request the generic stage and retain complete artifacts.
Native Windows explicitly skips latency and generic probing, producing an
incomplete suite rather than a pass.

Local checks passed: **374 script tests** with 10 skip records and **44 benchmark
tests** with 18 skip records. Script skips were five optional Playwright browser
checks and five native-Windows checks. Benchmark skips require an explicit
AgentDojo checkout/runtime or disposable Agent; two skips are class-level records.
The runner suite includes five new regressions for generic witnesses, identity,
missing stages, forbidden execution, late delivery and Windows skips.

Rust/Cargo are absent on the host. Full workspace tests, fmt and clippy are
delegated to CI; the pinned Docker baseline above ran locally. No native macOS,
Windows, WSL2, actual Claude/Codex client or external model experiment ran locally.
The local `pass` retains `acceptance_passed=false` and does not close SOU-18.
