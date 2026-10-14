# SOU-18 resource-executor evidence, 2026-10-14

The combined candidate passes the existing Docker and four-stage local suites.
The independent resource probe passes nine cases and fails recovery after
repeated read errors. **This candidate does not pass final acceptance.**

[Windows lifecycle PR #106](https://github.com/SoupTeam/soup-wall/pull/106)
was merged at 10:38:49 UTC. Its head was
`1de347a89892558a27416bbd979a8a3907f39cdd`.
[SOU-15 PR #107](https://github.com/SoupTeam/soup-wall/pull/107) remained open at
`ff235b9e36b6e1c147729817efb0f010f7332a31`, with changes requested. Both saved
PR snapshots contain 27 successful checks. Passing CI did not resolve the
execution-boundary findings in review.

## Exact candidate and build

| Item | Value |
| --- | --- |
| Combined candidate | `a86d6eba16d41daec5996679b60d7a7af00b9b73` |
| Candidate tree | `eac83882e9aa9080c2d8cad178a98b9533e2f5b5` |
| Original main | `d940d9e71bd7074e9f368961e7393e0d52a85e91` |
| Agent SHA-256 | `1d8150bead96ce7691cd42f0548d96e6e6e0891b57aad8fe51a8c8df9744c01e` |
| Build | Pinned Docker fixture, locked dependencies, Rust/Cargo 1.98.1 |
| Native probes | Linux x86_64, kernel 7.0.0-38-generic, Python 3.14.4, 16 logical CPUs |
| Docker runtime | linux/amd64, 2 CPUs, 2 GiB, no network, read-only root, no capabilities |

The candidate combines the two PR heads through local merge commits. It is
retained on `integrated-acceptance-candidate`; no GitHub PR was merged by this
verification. The pre-resource candidate tree equals main `219a19d` after the
maintainer merged #106. This is a reproducible pre-merge candidate, not a
team-approved final release revision.

All **326 build input hashes** matched the clean candidate. The extracted Agent
matched the build manifest and child reports. Sources and binary remained
stable throughout the probes. The new probe's source and fixture hashes are
recorded separately because it ran from the development checkout.

The cached Docker build took **24.471 seconds**; container execution took
**37.189 seconds**. These are not cold-build measurements. Staging and installing
the existing binary in the setup probe took **48.566 ms**; that excludes source
compilation and system service installation.

## Results

| Surface | Observed result |
| --- | --- |
| Docker baseline | 146 passed, no failures or skips |
| Disposable setup | 6 checks passed |
| Status and MCP behavior | 7 cases passed, including outage and recovery |
| Generic classification boundary | 15 cases passed with controlled classifier replies |
| Paired warm latency | 30 measured pairs passed, plus one excluded warmup pair |
| Resource/startup checks | 9 passed, 1 failed |

The resource probe uses the real rule baseline, existing fixture policy,
production collector and native admission. It preserves each submitted call ID
and checks classified argument hashes. The discovery-only child records all
received frames and never implements file reads. Successful broker reads must
return the unique contents of the permitted fixture file while the child's
execution ledger remains empty. Native result hashes bind both released and
withheld content to that file and the original call.

| Resource case | Result | Independent observation |
| --- | --- | --- |
| Absolute permitted path | Pass | Useful file content released; zero child tool calls |
| Relative permitted path | Pass | Same boundary and useful result through the relative path |
| Existing unlisted file | Pass | `native_resource_not_allowed`; zero child tool calls |
| Parent traversal | Pass | `resource_path_traversal` before classification |
| Static symlink | Pass | `resource_path_link` before classification |
| Unsupported read tool | Pass | `resource_executor_unsupported`; no child call or native result |
| Injected file content | Pass | Native result withheld; private marker absent from complete client output |
| Different existing workspace | Pass | `resource_workspace_mismatch` before classification |
| Missing workspace | Pass | Collector exits before handshake; no tool call submitted or server startup observed |
| Repeated invalid UTF-8 reads, then useful read | **Fail** | 64 correlated read errors, then collector exit 1; useful continuation missing |

For the last case, the probe intends 70 invalid UTF-8 reads followed by a benign
read without reconnecting. The first 64 return `resource_read_failed`. Attempt
65 receives no response, and the collector reports `MCP admission request
rejected`. The attempted useful follow-up also receives no response. The child
ledger stays empty and the synthetic files remain unchanged. Zero child calls
does not turn this availability failure into a pass. Full attempted inputs,
responses, classification records, native audit and stderr are retained.

The reviewer independently reported the same reservation-exhaustion problem in
the [SOU-15 review](https://github.com/SoupTeam/soup-wall/pull/107#pullrequestreview-5516594069).
Our probe reproduces the persistent-session failure. That review also reports
a parent-directory replacement race that permits an outside read, and asks for
bounded reading. We did not independently reproduce the race in this run.
The static symlink case above does not test concurrent replacement and does not
resolve that finding. The resource executor needs those fixes before acceptance.

All owned resource profiles were removed, including after the failing case.
Every resource artifact hash was verified and every resource grade was
recomputed from the retained observations before packaging.

## Timing scope

| Warm MCP measurement | p50, ms | p95, ms |
| --- | ---: | ---: |
| Direct request | 0.283 | 0.382 |
| Protected request | 40.627 | 41.823 |
| Paired added duration | 40.441 | 41.658 |

These are persistent-session measurements of the existing registry-only read
path, including per-call Python classifier startup. They are **not** timings
of the new constrained resource executor. The 60 measured observations contain
zero fixture false interruptions and zero execution anomalies. No numeric
latency limit is agreed; this is not a population accuracy or false-block rate.
Per-case resource timings are retained separately and include one observation
per ordinary case, not a warm performance distribution.

## Reproduction and retained evidence

Follow [the setup and resource procedure](../CLEAN_SETUP_ACCEPTANCE.md#check-operation-level-resource-execution).
Use the probe revision recorded in the [manifest](SOU18_RESOURCES_2026-10-14.json)
and a separate clean candidate checkout:

```sh
git fetch origin integrated-acceptance-candidate
git worktree add --detach /tmp/sou18-resource-candidate \
  a86d6eba16d41daec5996679b60d7a7af00b9b73
cd /tmp/sou18-resource-candidate
python3 scripts/test-environment.py
```

Retain the Docker output directory and its `image-id`. Extract
`/opt/soup-wall/target/debug/agentfw` and `/opt/soup-wall/fixture-build.json`
from that image using `docker create`, `docker cp` and removal of the owned
container. Check the Agent hash and every build-manifest input against the
candidate. From the checkout containing the new probe, run:

```sh
python3 scripts/run-sou18-acceptance.py --run --include-generic \
  --repo /tmp/sou18-resource-candidate --agentfw /absolute/path/to/extracted/agentfw \
  --expected-commit a86d6eba16d41daec5996679b60d7a7af00b9b73 \
  --pairs 30 --output /absolute/path/to/new-suite
python3 scripts/verify-sou18-resources.py --run \
  --repo /tmp/sou18-resource-candidate --agentfw /absolute/path/to/extracted/agentfw \
  --expected-commit a86d6eba16d41daec5996679b60d7a7af00b9b73 \
  --output /absolute/path/to/new-resources
```

Expected on this immutable candidate: the four-stage suite exits 0; the resource
probe exits 1 for the recovery failure. After the SOU-15 fix, use its newly
agreed exact commit and rebuild. Do not reuse this binary or rewrite this dated
report as evidence for another revision.

The [compressed witness bundle](SOU18_RESOURCES_2026-10-14.witnesses.json.gz)
retains complete child reports and raw artifacts, all Docker case logs, build
provenance, test logs, public PR/review snapshots and the probe source. Each
UTF-8 `files` entry has `text`, `bytes` and `sha256`; the companion manifest
contains the archive hash and per-file hashes. The Agent binary, credentials
and private profiles are excluded. Verify without executing archived source:

```sh
python3 - <<'PY'
import gzip, hashlib, json
from pathlib import Path
root = Path("docs/operations/evidence")
manifest = json.loads((root / "SOU18_RESOURCES_2026-10-14.json").read_text())
raw = (root / manifest["archive"]["file"]).read_bytes()
assert hashlib.sha256(raw).hexdigest() == manifest["archive"]["sha256"]
bundle = json.loads(gzip.decompress(raw))
for name, item in bundle["files"].items():
    data = item["text"].encode("utf-8")
    assert len(data) == item["bytes"]
    assert hashlib.sha256(data).hexdigest() == item["sha256"], name
report = json.loads(bundle["files"]["resources/results.json"]["text"])
print(report["status"], report["rows"][-1]["grade"])
PY
```

Local checks passed: workspace formatting, **390 script tests** with 10 skips,
and **44 benchmark helper tests** with 18 skips. Script skips require optional
Playwright browsers or native Windows. Benchmark skips require an explicit
AgentDojo checkout/runtime or disposable Agent; two are class-level skip records.
The new probe has 12 regression tests. Existing-output preservation and refusal
of a mismatched candidate were also checked. Native Cargo is absent; full
workspace Clippy/tests for this change are delegated to PR CI.

## Still required

- Fix the SOU-15 review findings and repeat SOU-17/SOU-18 on the same agreed
  candidate. This branch supplies verification, not an executor repair.
- Complete actual supported-host and intended platform/architecture acceptance
  on that candidate. Claude Code is absent locally. No actual host, native Mac,
  native Windows or WSL2 run is claimed by this report. The separate Windows
  lifecycle CI evidence for #106 does not certify this combined candidate.
- Obtain administrator confirmation of the CodeQL rule-specific clean, pending
  and finding merge outcomes. The configured rule and scanner evidence remain
  documented in the [October 13 report](SOU18_INTEGRATION_2026-10-13.md);
  no GitHub settings or merge gates were changed or tested here.

The inherited suite fields still say `pending_sou15` and `acceptance_passed=false`.
They are preserved. The resource report supplies narrower new evidence and an
explicit failure; it does not close SOU-15, SOU-17 or SOU-18.
