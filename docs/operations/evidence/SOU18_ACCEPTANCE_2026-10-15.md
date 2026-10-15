# SOU-18 candidate acceptance, October 15, 2026

Owner: userarlan. Candidate: `4f428e4b983111e5b2480e40d658628e3d198fe7`
from main, after PRs #113, #115 and #116. This is the final runtime handoff named
in [SOU-18](https://linear.app/soup-wall/issue/SOU-18/task-12-verify-clean-setup-and-actual-active-protection-status).
The runtime changes have been accepted through SOU-17; this report supplies the
remaining setup, status, actual-host and scanning observations for review.
Issue acceptance still requires the repository's normal review and merge.

The selected local checks pass. This is an internal iteration for the declared
paths, not a product release or a claim that every host path is protected.
The [manifest](SOU18_ACCEPTANCE_2026-10-15.json) and
[witness archive](SOU18_ACCEPTANCE_2026-10-15.witnesses.json.gz) retain the source,
binary/configuration identities, raw observations, CI metadata and regrading
record. Earlier dated reports, including failed attempts, are not replaced.

## Source and environment

- Runtime checkout: clean `4f428e4b983111e5b2480e40d658628e3d198fe7` before and
  after the runs. The opt-in development classifier from #115 is not enabled.
- Local Agent SHA-256:
  `85de5abd45917110b0577a2737b3153edfb41fd72ea1e1e840d9c1c96e916253`.
  All 356 build input hashes were matched to the candidate. Rust/Cargo 1.98.1,
  locked dependencies, debug build. The existing Docker build cache was reused.
- Local machine: Linux 7.0.0-38-generic, x86_64, Ryzen 7 4800H, 16 logical CPUs,
  about 14.54 GiB RAM; Python 3.14.4. Container execution: 2 CPUs, 2 GiB, read-only
  root, no network, no capabilities, unprivileged UID 1000.
- Actual host: Claude Code 2.1.296, Linux x86_64 vendor executable SHA-256
  `24972e3bc859fab2b46ed4c1e51f7d6130f06d3bd550811a114640de3370d0de`.
  npm package and native package integrity are in `claude-provenance.json` in
  the archive. Node 24.22.0 was used for installation with scripts disabled.
  Vendor license applies; the executable is not redistributed.
- Host provider: local scripted Messages fixture, no external model, paid
  request or account. Registry-only stdio MCP, strict local MCP configuration,
  built-in host tools disabled, disposable profile.
- Classifier: `rule-baseline/python`, `sw-classification/candidate-1`, SHA-256
  `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd`.
  Registry SHA-256 `a8cf35f613afa82bb4c10664ab04bc0fff110396369c801cbb6f1bf3c1e8980d`;
  host fixture policy SHA-256 `c5a7c87cbae0a96b6e6be78e5815a0035f131ceb7d452518e955dfb79927be8d`.
  Each setup/resource probe also records its own distinct policy/config hashes.

## Results and platform matrix

The [exact-main CI run](https://github.com/SoupTeam/soup-wall/actions/runs/38626806548)
completed successfully. Downloaded artifact identities, job names and run IDs
are retained. Local grades were recomputed from the raw witnesses; CI combined
stages and standalone status reports were independently regraded as well.

| Environment | Observed result | Scope |
| --- | --- | --- |
| Local Linux x86_64 | 153/153 Docker fixtures; setup 6/6; status 7/7; generic 15/15; resources 10/10 | Built from the exact candidate; no Docker test failures or skips |
| Linux x86_64 CI, Python 3.12.3, 4 CPUs | Setup 6/6; status 7/7; generic 15/15; 30 latency pairs | Native scripted fixture, not an actual Claude session |
| macOS arm64 CI, Darwin 24.6.0, Python 3.14.7, 3 CPUs | Setup 6/6; status 7/7; generic 15/15; 30 latency pairs | Native scripted fixture; actual Claude not run on this platform |
| Windows Server 2025 AMD64 CI, Python 3.12.10, 4 CPUs | Setup 6/6; status 7/7; standard-user lifecycle 5/5, zero ignores | Real native Windows job, owned regular-user SID, cleanup confirmed |
| Linux amd64 and arm64 container CI | 153/153 fixtures on each architecture | Native architecture runners; Linux containers, no host certification |
| Local actual Claude Code | 9/9 scenarios and all host checks; separate daemon-outage probe passes | Selected trusted MCP fixture, scripted provider |
| Native Intel Mac, WSL2, Docker Desktop; actual Claude on Mac/Windows | Not run on this candidate | Explicit missing environments, no inferred pass |

Windows lifecycle and setup binaries have different hashes because the jobs
build different feature sets. The manifest preserves both; they are not treated
as one binary. POSIX generic/latency probes and the constrained resource executor
are not claimed supported on native Windows. Native Windows refuses unsupported
resource execution. The earlier Windows lifecycle defects were repaired in
accepted PR #106; this run again executed all five tests without early skips.

Setup preserves unrelated synthetic settings, verifies shadow/enforcing/
unavailable and recovery, then removes owned state. Status is compared with
executor/receiver/client observations, including a deliberately direct,
unprotected path. A displayed enforcing label does not prove coverage outside
the configured collector.

Resource checks cover allowed broker reads, result withholding, invalid paths,
symlinks, unsupported operations and same-session recovery after 70 read errors.
Unsupported tools are rejected before native admission: no native reservation,
no executor call, no receiver effect. Allowed constrained reads run inside the
broker; the unconfined child tool executor remains unused. These are selected
operation-level tests, not arbitrary-server containment or a general OS sandbox.

## Actual host and daemon outage

The actual Claude process proposed all nine fixture scenarios. Allowed read,
send and unfamiliar `publish_report` calls completed with original arguments
and host call metadata. Deny and Ask produced zero execution/delivery. A result
containing the synthetic injection marker was withheld after one execution;
result blocking does not undo an already executed call. Useful work continued.
There were zero classification mismatches in these nine samples, zero false
blocks and zero enforcement failures. This is fixture correctness evidence,
not an estimate of general classifier accuracy.

The additional [outage probe](../../../scripts/verify-sou18-claude-outage.py)
first requires a useful read through that actual host. It stops only its owned
daemon, verifies unavailable status, then proposes a benign local send. Claude
receives an error, the server ledger remains at the first read, and the receiver
remains empty. Original proposals, classifier records and native read/result
bindings are checked independently.

Two classification records are expected: local classification and policy still
run for the send after daemon loss. The authoritative verdict is Allow, while
native admission is unavailable and no native send event exists. The collector's
fallback adapter verdict is Deny; the report treats this as transport failure,
not a policy refusal. This distinction prevents a false outage pass caused by
a policy that would have rejected the request anyway.

Two initial versions of this new probe's grader failed: one did not account for
Claude's trailing token-budget reminder; the other expected only one classifier
record. Their reports remain in the archive. The final grader accepts only the
exact observed reminder suffix and verifies both classifier records. Six test
methods exercise positive utility, missing evidence, changed identity, unwanted
effects and policy/transport confusion. The corrected actual-host run passes.

Disposable host profiles and tokens were removed. Only selected synthetic
witnesses are retained, checked against the owned token values before cleanup.
No real profile, credentials or vendor binaries are included.

## Timings

Each latency run contains 30 paired direct/protected reads and one excluded
warmup pair. Values below are milliseconds. Protected duration includes the
Python rule baseline, local daemon admission, fixture execution and result
delivery. It is not classifier-only latency or a constrained-resource benchmark.

| Environment | Stage prebuilt install | Direct p50 / p95 | Protected p50 / p95 | Paired overhead p50 / p95 |
| --- | ---: | ---: | ---: | ---: |
| Local Linux | 90.195 | 0.350 / 0.512 | 75.722 / 90.431 | 75.456 / 90.009 |
| Linux CI | 161.867 | 0.237 / 0.301 | 46.309 / 48.333 | 46.064 / 48.135 |
| macOS CI | 45.968 | 0.345 / 0.590 | 57.426 / 78.052 | 57.078 / 77.463 |
| Windows CI | 124.384 | Not measured | Not measured | Not measured |

All three paired runs report zero fixture false interruptions and execution
anomalies. Local cached image build took 28.381 seconds and container tests
46.821 seconds. Install timings stage an already-built binary; they are not
cold compilation or a full service deployment. The proposed 15/50 ms targets
were not accepted pass/fail limits; the measured overhead is reported as-is.

## CodeQL merge rule

Live gate verification is recorded in `gate-live-results.json` in the archive.
The controlled PR is [#117](https://github.com/SoupTeam/soup-wall/pull/117).
Its two commits only change a disposable static fixture outside runtime/test
paths; the vulnerable expression is never executed or merged.

| Case | Exact head | Analysis and result | Authenticated merge-panel observation |
| --- | --- | --- | --- |
| Clean analyzed change | `74edf38576bc2b564313a241e6e0d106317f631c` | Rust/Python/Actions success; separate results check 116203193379 success, no new alerts | Scanning rejection cleared; review still required |
| New head with pending analysis | `15f2110bb8f2599688bf1969da3afb68964186ea` | Previous clean head is no longer sufficient; Rust analysis pending | `Code scanning is still expecting 1 result from CodeQL for 647f7ef or 15f2110.` |
| Controlled qualifying finding | Same `15f2110...` | All three analyses succeed; results check 116205573646 fails for Critical `py/code-injection`, alert #94 | `CodeQL has detected 1 security relevant alert blocking this code from being merged.` |

The clean run is [38667609845](https://github.com/SoupTeam/soup-wall/actions/runs/38667609845);
the finding run is [38668363103](https://github.com/SoupTeam/soup-wall/actions/runs/38668363103).
Analysis IDs 1956379454/1956360585/1956359937 correspond to clean Rust/Python/Actions;
1956419350/1956389687/1956389012 correspond to the finding head. Both sets identify
the exact head, not an assumed merge-ref association. The UI's separate merge
commit labels are preserved in the pending excerpt. Other review/conversation
requirements also blocked merging; they are not used as evidence of scanning
enforcement. No merge or bypass was attempted. The PR was closed without merging.

The active [main ruleset 24846282](https://github.com/SoupTeam/soup-wall/rules/24846282)
requires CodeQL High-or-higher security alerts and error-level alerts. The
administrator's October 13 SOU-18 comment records the applied setting and
unchanged non-scanning rules/bypass actors. This work changes no setting,
bypass, approval or alert disposition. Review requirements remain independent.

The current-main read-only audit observes Rust, Python and Actions analysis,
PR and main-push runs, and the separate alert-bearing `Code scanning results /
CodeQL` check. `Analyze (...)` success means upload completed, not that findings
permit merge. The default-setup endpoint returns 403 and classic branch
protection 404 with this access; the saved audit remains incomplete and keeps
its original live-case `not_run` flags. The separate authenticated observations
supplement it. Dockerfile, HTML, PowerShell and Shell appear in the repository
language inventory without corresponding CodeQL analysis evidence; they remain
coverage gaps. No duplicate workflow was added.

The main inventory still contains one open Critical alert. The
[SOU-17 triage report](CODE_SCANNING_TRIAGE_2026-10-14.md) identifies #112 as an
evidence-backed false-positive recommendation awaiting authorized disposition.
It was not dismissed. A clean PR's lack of new findings does not mean main has
zero alerts. SOU-44/45 runtime repairs were accepted through #113/#116; scanning
does not prove those execution boundaries.

## Reproduction and validation

Follow [clean setup acceptance](../CLEAN_SETUP_ACCEPTANCE.md), using a clean
checkout at the recorded candidate and a matching build manifest. Run the
combined suite with `--include-generic --pairs 30`, the resource probe, the
actual-host demo with `--classifier rule-baseline`, and the actual-host outage
probe. Use fresh output paths. Exact source/probe hashes and saved commands
are in the manifest/archive. Live merge-rule cases require a separate disposable
PR and authenticated rule observations; do not merge the canary.

To check the retained bytes without executing any archived content:

```sh
python3 - <<'PY'
import gzip, hashlib, json
from pathlib import Path
root = Path('docs/operations/evidence')
manifest = json.loads((root / 'SOU18_ACCEPTANCE_2026-10-15.json').read_text())
raw = (root / manifest['archive']['file']).read_bytes()
assert hashlib.sha256(raw).hexdigest() == manifest['archive']['sha256']
files = json.loads(gzip.decompress(raw))['files']
assert len(files) == manifest['archive']['file_count']
for name, item in files.items():
    data = item['text'].encode('utf-8')
    assert len(data) == item['bytes'], name
    assert hashlib.sha256(data).hexdigest() == item['sha256'], name
print('Archive and all retained file hashes verified')
PY
```

Local validation: 482 Python tests pass with 25 environment skips; 44 benchmark
tests pass with 18 skips; workspace formatting passes. Python skips cover five
optional Playwright checks, one native Windows batch launcher, fifteen TLS
runtime fixtures and four Windows-only storage/DPAPI checks. Benchmark skips
require an explicitly selected pinned AgentDojo checkout/runtime or disposable
native Agent. The first benchmark
attempt could not bind loopback sockets in the execution sandbox; its diagnostics
are retained, and the rerun with loopback access passes. Full native workspace
Clippy/tests rely on the linked exact-main CI and this PR's checks; Cargo is not
installed on the local host. The Docker fixture suite is a separate bounded run.

Remaining exclusions: arbitrary MCP servers and direct OS commands, full Codex
host acceptance, external models, actual-host performance, complete service
management/upgrade and Console rollout. Transactional Claude connect/disconnect
is the separate SOU-50 increment. Review this declared scope and the missing
environments when accepting SOU-18; none is silently converted into success.
