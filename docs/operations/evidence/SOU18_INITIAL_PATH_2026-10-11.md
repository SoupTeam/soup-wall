# SOU-18 initial-path evidence, 2026-10-11

The selected local MCP path passed installation, status, execution and result
checks on Linux. This is partial SOU-18 evidence: final generic SOU-15 acceptance,
actual host coverage and live CodeQL merge-gate evidence remain open.

The [machine-readable evidence](SOU18_INITIAL_PATH_2026-10-11.json) retains the
seven status cases, original synthetic frames, paired timings, source identities
and read-only GitHub observations. Reproduce with the
[setup and acceptance procedure](../CLEAN_SETUP_ACCEPTANCE.md).

## Candidate and environment

| Item | Recorded value |
| --- | --- |
| Source | `02f1ab05d1cdc7711dfe4efd18a3798c32a5394b`, clean detached checkout; accepted PR #72 |
| Agent binary SHA-256 | `12fe382eb106aa99d951b5d34833035b76fe1b70e1786dcc01157ebe90105100` |
| Build | Existing pinned `deploy/Dockerfile.test`, Rust/Cargo 1.98.1, locked dependencies |
| Runtime | Native Linux x86_64, kernel `7.0.0-34-generic`, glibc 2.43, Python 3.14.4 |
| Hardware | AMD Ryzen 7 4800H, 16 logical CPUs, 15,245,728 KiB reported memory |
| Container baseline | Linux amd64, network disabled, read-only root, no capabilities, 2 CPUs and 2 GiB |
| Classifier | Existing real `rule-baseline/python`; no model or external provider calls |
| Harness | Scripted Claude Code stdio MCP frames through the production collector |

The source worktree was separate from the new probe's development checkout.
The Docker build manifest's input hashes all matched that clean candidate. The
extracted Agent hash matched the built Agent and all subsequent probes. The JSON
records classifier, schema, fixture, policy, registry/profile and config hashes.
Generated configs include disposable paths/ports, so their hashes identify this
run; they are not expected to remain identical between runs.

The cached Docker build took **35.347 s**. Installing the supplied Agent into a
disposable fixture profile and waiting for daemon readiness took **18.873 ms**;
the same timer reached MCP discovery at **126.863 ms**. These are single local
observations. They exclude downloads, source compilation and system-wide
installation. They do not establish cold setup time.

## Observed behavior

All seven status cases passed. Execution is counted from the independent server
ledger, with original frames compared byte for byte. An independent loopback
receiver remained empty in these cases.

| Case | Preflight exit | Executions | Client result |
| --- | --- | --- | --- |
| Enforcing read | 0 | 1 | Original useful result and call ID |
| Enforcing delete / Deny | 0 | 0 | Correlated policy refusal; inventory unchanged |
| Enforcing send / Ask | 0 | 0 | Correlated confirmation refusal; no receiver delivery |
| Enforcing result withholding | 0 | 1 | Refusal; server's private fixture marker absent |
| Daemon unavailable | 2 | 0 | Collector exits unsuccessfully; no result or direct fallback |
| Daemon recovered | 0 | 1 | Fresh session delivers the original useful result |
| Shadow daemon | 4 | 0 | Native collector refuses; no result |

Native admission requires enforcement in the production configuration. The
shadow test uses a valid configuration without native admission; it proves that
this native collector cannot silently treat that shadow daemon as enforcing.
It does not claim shadow mode protects arbitrary calls.

The final ledger contained exactly the three expected execution frames. Source
and binary identity stayed stable, the original inventory stayed unchanged,
and the owned profile was removed. The separate installation probe also passed
all six checks, including token non-disclosure, preservation of unrelated
synthetic settings and rollback of its owned installation.

Two earlier probe-development attempts were rejected correctly by production:
a string progress token and an invalid shadow/native configuration. Both test
inputs were corrected before this recorded run. They are not product defects.

Additional checks on the same Agent:

- Existing Docker fixture baseline: **103 passed, 0 failed, 0 skipped**. Its
  deterministic judge mocks remain distinct from the real-classifier run.
- Existing real-baseline demonstration: **9 scenarios and 7 boundary checks
  passed**. This includes local sends and a pinned unfamiliar `publish_report`
  tool, original IDs/arguments/results, secret-send blocking and result withholding.
- That nine-case demonstration recorded 0 classification errors, 0 false blocks
  and 0 enforcement failures. These fixture counts are not population accuracy
  or false-positive estimates, and do not certify arbitrary unseen tools.

## Paired MCP latency

The existing SOU-17 probe compared 30 identical useful reads through persistent
direct and protected sessions, after excluding one warmup pair. The direct path
was an unprotected local measurement control. Timing includes request/response,
collector, daemon and per-call Python classifier startup.

| Measurement | p50, ms | p95, ms |
| --- | --- | --- |
| Direct fixture request | 0.248 | 0.485 |
| Protected request | 39.939 | 53.121 |
| Paired added duration | 39.695 | 52.733 |

Mean paired added duration was 41.812 ms. All 60 measured observations had complete
execution/result witnesses, with 0 false interruptions and 0 execution anomalies.
The JSON preserves every measured pair and the excluded warmup count. No numeric
latency limit has been agreed; the probe's `acceptance_passed` remains `false`.
These results do not close release or generic integration acceptance.

## Reproduction

Use a clean checkout of the candidate and a separate checkout containing the
new status probe. Keep outputs outside the candidate. Commands below assume
Linux with Docker; replace example absolute paths with fresh local paths.

```sh
git worktree add --detach /tmp/sou18-candidate 02f1ab05d1cdc7711dfe4efd18a3798c32a5394b
cd /tmp/sou18-candidate
python3 scripts/test-environment.py --output /tmp/sou18-reproduction/build
```

The build prints a unique result directory containing `image-id` and the source
manifest. Use that exact image, then compare the exported Agent's SHA-256 with
`fixture.build.agentfw_sha256` in its `results.json`:

```sh
RUN_DIR=/absolute/path/to/printed/build/result
IMAGE_ID=$(cat "$RUN_DIR/image-id")
(set -C; docker run --rm --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges:true --entrypoint cat "$IMAGE_ID" \
  /opt/soup-wall/target/debug/agentfw > /tmp/sou18-reproduction/agentfw)
chmod 700 /tmp/sou18-reproduction/agentfw
sha256sum /tmp/sou18-reproduction/agentfw
python3 scripts/clean-setup-acceptance.py --run \
  --agentfw /tmp/sou18-reproduction/agentfw \
  --output /tmp/sou18-reproduction/clean-setup.json
python3 /absolute/path/to/probe-checkout/scripts/verify-sou18-status.py --run \
  --repo /tmp/sou18-candidate --agentfw /tmp/sou18-reproduction/agentfw \
  --expected-commit 02f1ab05d1cdc7711dfe4efd18a3798c32a5394b \
  --output /tmp/sou18-reproduction/status
python3 scripts/measure-sou17-latency.py --repo /tmp/sou18-candidate \
  --agentfw /tmp/sou18-reproduction/agentfw --pairs 30 \
  --expected-commit 02f1ab05d1cdc7711dfe4efd18a3798c32a5394b \
  --output /tmp/sou18-reproduction/latency
python3 scripts/mcp-admission-demo.py --agentfw /tmp/sou18-reproduction/agentfw \
  --classifier rule-baseline --out /tmp/sou18-reproduction/demo.json
```

The recorded latency/demo processes used the existing setup helper's private
child environment, with inherited credentials excluded. The new status probe
does this itself. Use a disposable credential-free environment for standalone
latency/demo commands. No user shell environment, service registration or real
host settings were changed in the recorded run.

Full local artifacts are retained under `/tmp/sou18-evidence-20261011`; their
sizes and hashes appear in the JSON. The committed JSON is a selected evidence
record, not a byte-for-byte copy of every raw report. In particular it omits
historical analyses that do not match the audited SHA and duplicate tracked-file
hash maps. Native CI produces separate run-specific artifacts.

## Platform limits and validation

Only native Linux x86_64 and the Linux amd64 container were measured locally.
Linux arm64, macOS, Windows and WSL2/Docker Desktop were not run on this machine.
The new probe is wired into Linux/macOS/Windows CI; inspect that PR's artifacts
before adding native coverage. A macOS runner does not prove both Mac architectures.

Actual Claude Code was explicitly skipped because its executable was absent.
Actual Codex was not run and remains outside the initial accepted host scope.
The POSIX paired-latency probe does not support native Windows. Direct server
launches, HTTP hooks that fail open and separately launched OS commands remain
outside the verified native path.

Local regression validation:

- Script suite: 275 tests run, 5 native-Windows skips, no failures; includes 11
  new regressions against false success from missing or contradictory witnesses.
- Benchmark suite: 44 tests run, 18 skip records, no failures. Two skip records
  are class-level; these counts must not be subtracted to infer passed tests.
  Skips require an explicit pinned AgentDojo checkout/runtime or disposable Agent.
- Rust fmt/clippy/workspace tests were not run directly on this host because
  Rust/Cargo were absent. The required CI jobs run those checks separately.
- Documentation check: 72 Markdown files and 342 local links, 0 errors.

## GitHub evidence and administrator handoff

Read-only observation at **2026-10-11 09:21:24 UTC**, targeting the same
`02f1ab0` main commit, found successful CodeQL Rust, Python and Actions analyses
matching that SHA. The head did not move during collection. The open-alert
inventory returned **0**; no alerts were dismissed by this work. This is separate
from the earlier [SOU-17 triage record](CODE_SCANNING_TRIAGE_2026-10-11.md), which
contains its own timestamp and disposition proposals.

Audit status remains `incomplete`: default setup returned HTTP 403 and classic
branch protection returned HTTP 404. Effective main rules were readable and
contained no `code_scanning` rule. Observed ruleset `24846282` retains one review,
stale-review dismissal, resolved threads, strict required checks, deletion and
force-push protection. Analysis success and zero observed alerts do not prove a
merge gate. No separate results check was observed for this main commit.

The authenticated account has push/triage access, not maintain/admin access.
The remaining administrator handoff to @winux125 is:

1. Read the active CodeQL default setup and confirm its languages and PR/main
   coverage. Keep existing scanning; do not add a duplicate workflow.
2. Review the [disabled additive ruleset example](../../../deploy/github-code-scanning-ruleset.example.json).
   Enable an approved CodeQL main rule for High-or-higher security alerts and
   error-level alerts without replacing existing review/check protections.
   Record before/after rules, applied rule ID and any bypass actors.
3. Follow the [three disposable-PR gate cases](../CLEAN_SETUP_ACCEPTANCE.md#administrator-configuration-and-live-gate-evidence):
   clean analyzed head, new head without completed analysis, and a controlled
   qualifying finding. Record the current SHA, results check and actual scanning
   rule decision. A block due only to a missing review does not count. Close
   test PRs without merging.

All three live cases remain **`not_run`**. Settings were not changed. Final SOU-18
closure also needs the agreed SOU-15 candidate and its generic action/resource
matrix, coordinated with SOU-17. This evidence accepts only the bounded initial
path and does not mark that dependency complete.
