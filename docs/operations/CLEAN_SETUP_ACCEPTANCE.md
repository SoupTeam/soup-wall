# Clean setup, status and scanning preparation

This procedure implements independent preparation and bounded initial-path verification for
[SOU-18](https://linear.app/soup-wall/issue/SOU-18/task-12-verify-clean-setup-and-actual-active-protection-status)
(F02, U01, U04 and F06/L02). It reuses the existing Agent and fixture build.
It does not introduce another classifier, MCP harness or admission contract.

See the dated [initial-path results](evidence/SOU18_INITIAL_PATH_2026-10-11.md)
for the measured candidate, platform limits and remaining administrator work.
The [combined-run evidence from October 12](evidence/SOU18_LOCAL_SUITE_2026-10-12.md)
records a fresh build after the accepted classifier updates.
The [October 13 integration recheck](evidence/SOU18_INTEGRATION_2026-10-13.md)
adds the accepted generic classifier/policy matrix and complete raw reports.

## Run the local probes together

The [combined runner](../../scripts/run-sou18-acceptance.py) executes the existing
disposable installation check, seven status/MCP cases and paired latency probe
in sequence. Use Python 3.10+, a clean candidate checkout and an Agent built for
the runtime platform. Build first with the native or pinned Docker procedure
below; retain its source, compiler, cache state and binary hash. The runner does
not compile the Agent or attest a supplied binary's source.

```sh
CANDIDATE_DIR=/absolute/path/to/clean/candidate
CANDIDATE_SHA=$(git -C "$CANDIDATE_DIR" rev-parse HEAD)
python3 scripts/run-sou18-acceptance.py --run --include-generic \
  --repo "$CANDIDATE_DIR" --agentfw "$CANDIDATE_DIR/target/debug/agentfw" \
  --expected-commit "$CANDIDATE_SHA" --pairs 30 \
  --output /absolute/path/outside/candidate/new-suite-run
```

`--include-generic` adds the accepted
[SOU-17 generic boundary probe](../../scripts/verify-sou17-generic-boundary.py).
Its 15 synthetic reply cases check valid single/mixed/unknown/empty shapes
reaching production policy, hard-Deny precedence, and malformed replies stopping
before policy or execution. Independent executor, receiver and complete client
transcript witnesses are regraded. This checks runtime wiring, not classifier
quality, actual no-op behavior or operation-level resource confinement.

Omit this flag for the original three-stage command or an older candidate that
does not contain the generic probe. Schema version 1 and the original child
report formats remain unchanged; `required_stages` records the requested stages.
A requested generic failure, skip or incomplete result prevents suite success.

For a separate candidate, invoke the runner from a checkout containing this
script. It records both the runner hash and
the candidate's probe hashes. Replace `--agentfw` with the extracted binary when
using the Docker build. Without `--run`, no probes or reports are created.

Each probe runs with a private temporary child profile and no inherited provider
credentials. Real host settings and service registrations are untouched. The
output directory must be new and outside the candidate. It contains:

- `results.json` and `report.md`: combined outcome, identities and stage results.
- `setup.json`: installation, preservation of synthetic settings and rollback.
- `status/results.json`: independent execution and delivery evidence for seven cases.
- `latency/results.json` and its companion files: 30 paired reads by default,
  one excluded warmup pair, raw witnesses and p50/p95 added duration.
- `generic/results.json` and its companion files, when requested: all 15 cases,
  original frames, classifier emissions, native decisions and final effect witnesses.

Exit **0** means all requested bounded probes passed. Exit **1** means a probe
reported a failure. Exit **2** means incomplete evidence, an unsupported skip,
invalid input, changed source/binary or a process timeout. A success label or
zero child exit alone is insufficient: the runner checks report schemas,
identities, required observations and recomputes the status/latency grades.
Failed or partial child reports are retained. Process diagnostics are discarded
to avoid retaining inherited private text; read the sanitized child report for
the failure reason. Missing child evidence remains explicitly incomplete.

Setup, status and latency timeouts are 120, 180 and 240 seconds; the optional
generic stage has a 120-second wrapper limit and its own 90-second active limit.
On timeout the runner terminates
its owned process tree and stops subsequent probes. Such a run does not certify
cleanup: inspect its owned temporary directories before removing leftovers.
Ordinary completion removes the temporary profiles.

Linux and macOS CI include the generic stage and retain `sou18-suite-*` artifacts
on success or failure. Output directories include the run ID and attempt to
avoid reusing evidence on a rerun. Native Windows can run setup and status, but
the latency and generic probes are POSIX-only: the runner records `skip` for
each requested unsupported stage and exits **2**.
Existing Windows setup/status CI remains separate. A Linux container pass does
not establish native Mac, Windows or WSL2 coverage.

This command covers the selected trusted local fixture. It keeps
`generic_candidate_acceptance=pending_sou15`, `actual_host=not_run` and
`acceptance_passed=false`, including on exit 0. It does not measure general
classifier accuracy or prove CodeQL merge protection. Repeat it on the final
agreed candidate and complete the remaining host, constrained-resource and
administrator checks separately.

## Disposable installation and status checks

The [setup script](../../scripts/clean-setup-acceptance.py) needs Python 3.10+
and an `agentfw` binary built for the machine running it. It copies that binary
into a fresh temporary directory, runs `agentfw install` with a private child
profile, and starts only its own loopback daemon. Real user settings and service
registrations are not edited. The generated profile, tokens and copied binary
are removed on both success and ordinary failure. An interrupted machine or
forced termination can require removal of the generated `soup-wall-setup-*`
directory from the OS temporary directory after confirming no owned process remains.

With no arguments, the script prints its scope and starts no processes:

```sh
python3 scripts/clean-setup-acceptance.py
```

Use the [development prerequisites](../DEVELOPMENT.md) for a native source
build. For an explicitly selected toolchain, install Rust 1.98.1 and run:

```sh
rustup run 1.98.1 cargo build --locked -p agentfw --bin agentfw
python3 scripts/clean-setup-acceptance.py --run --agentfw target/debug/agentfw --output target/clean-setup.json
```

On native Windows use `python` and `target/debug/agentfw.exe`. An output path
must be fresh. Existing evidence is never overwritten. Keep the build command,
compiler version, source commit, dirty-state information and binary hash with
the report. A supplied binary's hash does not by itself prove its source commit.

The script checks installation output for token disclosure and verifies that
an unrelated synthetic Claude settings file is unchanged. It then checks:

| Stage | Expected health / required-enforcement preflight |
| --- | --- |
| Shadow daemon | `enforce=false`, exit 4 |
| Enforcing daemon | `enforce=true`, exit 0 |
| Owned daemon stopped | Unavailable, exit 2 |
| Owned daemon restarted | `enforce=true`, exit 0 |
| Rollback | Owned installation and profile removed |

The JSON contains config/policy/binary hashes and status assertions. It omits
tokens, raw subprocess output, raw private arguments and inherited credentials.
Missing classifier/profile revision support is reported as `null`, not inferred.
Source identity is recorded separately from supplied-binary provenance.

`stage_install_ms` measures copying the supplied binary, excluding compilation
and downloads. `warm_preflight_cli_ms` contains 20 measured samples after an
excluded warm-up, with nearest-rank p50/p95. These include CLI startup and the
health request. They are **not MCP/classifier overhead or complete setup time**.
Keep the OS, architecture, CPU model, memory and build/download duration alongside
the report for a performance comparison. No acceptance threshold is invented here.

### Pinned Docker route

Run the existing fixture baseline using its pinned Rust/base-image/package
inputs and `Cargo.lock`:

```sh
python3 scripts/test-environment.py
```

Its output names a unique directory under `target/test-environment/`. Set
`RUN_DIR` to that printed directory, then run the setup check against the exact
built image, using a fresh output filename:

```sh
RUN_DIR='/absolute/path/to/the/printed/result-directory'
IMAGE_ID="$(cat "$RUN_DIR/image-id")"
docker run --rm --network=none --read-only --cap-drop=ALL \
  --security-opt=no-new-privileges:true --pids-limit=256 --cpus=2 --memory=2g \
  --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,exec,nosuid,nodev,size=256m \
  --mount "type=bind,src=$RUN_DIR,dst=/results" --entrypoint python3 "$IMAGE_ID" \
  /opt/soup-wall/scripts/clean-setup-acceptance.py --run \
  --agentfw /opt/soup-wall/target/debug/agentfw --output /results/clean-setup.json
```

Use Linux or the documented [WSL2 route](../DEVELOPMENT.md#running-from-windows-with-wsl2)
for these shell commands. Docker on macOS/WSL2 proves Linux-container behavior
only. Keep `results.json`, `fixture-results.json`, `image-id` and
`clean-setup.json` together: the build manifest records source-input hashes.
This separate setup container needs `exec` on its temporary filesystem because
it executes the staged binary there. The normal fixture baseline is unchanged.

Existing Linux, macOS and Windows CI jobs also run the setup script and retain
separate artifacts. Their addition is not evidence that those jobs passed.
Use the reviewed [SOU-10 support matrix](../../contract/updated_contract2.md).
Record every missing target as unverified rather than expanding coverage from a
container pass. Linux container evidence and native OS evidence remain separate.

### Compare status with actual MCP execution

The [status witness probe](../../scripts/verify-sou18-status.py) reuses the
accepted demonstration server, production collector and real rule baseline.
It requires a clean, exact candidate checkout and its separately built Agent.
Keep the build command, lockfile/toolchain and matching binary hash as provenance.
The output must be a new directory outside that checkout; the probe reserves it
before starting fixtures. With no `--run`, it starts no processes.

```sh
CANDIDATE_DIR=/absolute/path/to/clean/candidate
CANDIDATE_SHA=$(git -C "$CANDIDATE_DIR" rev-parse HEAD)
python3 scripts/verify-sou18-status.py --run \
  --repo "$CANDIDATE_DIR" --agentfw "$CANDIDATE_DIR/target/debug/agentfw" \
  --expected-commit "$CANDIDATE_SHA" \
  --output /absolute/path/outside/candidate/new-status-run
```

On Windows use `python`, the `.exe` binary and an explicit checkout SHA. The
Linux, macOS and Windows CI jobs supply their actual checkout SHA and retain
`sou18-status-*` JSON artifacts, including failures. Read their recorded platform
and outcome before claiming native coverage.

| State / case | Independent requirement |
| --- | --- |
| Enforcing, benign read | Preflight exit 0; exactly one original executor frame; original useful result and ID delivered |
| Enforcing, Deny or Ask | Preflight exit 0; correlated policy refusal; zero executor frames and receiver deliveries |
| Enforcing, result withheld | Tool executes once; the server produces the marker; the client receives a refusal without it |
| Daemon stopped | Preflight exit 2; existing collector refuses; no new execution or result |
| Daemon recovered | Preflight exit 0; a fresh session executes a useful read and delivers the original result |
| Shadow daemon | Preflight exit 4; native collector refuses; no execution or result |

Native registry configuration requires enforcement. The shadow case therefore
uses a valid shadow configuration with native admission disabled. It does not
claim a native enforcing session can operate in shadow mode. The final ledger
is reconciled after the collectors stop; the original inventory file and empty
receiver are checked independently. Owned temporary profiles and processes are
removed, including on ordinary failures. Forced termination can still require
manual cleanup of the owned OS-temporary `sou18-status-*` directory.

Results bind source before/after, binary, classifier, fixture, schema, policy,
profile and configuration hashes. The recorded frames contain only synthetic
local data, and fixture credentials must not appear in retained JSON.
`initial_path_verified` covers only these seven cases. Generic SOU-15 acceptance
stays pending; actual Claude/Codex and arbitrary servers are not certified.
Exit 0 means the bounded probe passed, 1 means a witness mismatch, and 2 means
incomplete evidence or an invalid run request.

`install_and_daemon_ready_ms` and `install_and_mcp_connect_ms` measure installation
of the supplied binary into a disposable profile through daemon readiness and
MCP discovery respectively. They exclude source compilation, downloads and
system-wide installation. Retain build duration separately, with cache state.
Per-case request times are individual observations, not warm percentiles.

For warm overhead, reuse the [paired SOU-17 measurement](../../scripts/measure-sou17-latency.py)
on the same clean candidate and binary (native Linux/macOS):

```sh
python3 "$CANDIDATE_DIR/scripts/measure-sou17-latency.py" \
  --repo "$CANDIDATE_DIR" --agentfw "$CANDIDATE_DIR/target/debug/agentfw" \
  --expected-commit "$CANDIDATE_SHA" --pairs 30 \
  --output /absolute/path/outside/candidate/new-latency-run
```

It excludes one warmup pair and compares identical useful reads in persistent
direct/protected sessions. Preserve raw pairs and p50/p95, not just averages.
Its direct server is an unprotected measurement control. Windows latency is
explicitly unsupported by that POSIX probe; do not substitute CLI timings.

### What still requires the integrated candidate

The disposable installation script always reports `protection_verified=false`. Daemon posture alone
cannot establish that any host call was protected. The HTTP hook can fail open;
direct MCP server launches bypass native admission. See
[the existing MCP boundary](MCP_STDIO_ADMISSION.md).

The seven-case probe verifies the accepted initial path. Repeat it and the
paired measurement on the same final SOU-15 candidate used by SOU-17, and review
the generic action/resource matrix separately. PR #82 implemented routing for
valid unknown/mixed/empty replies; the optional generic stage verifies those
policy boundaries. A selected-fixture pass does not resolve unsupported
operation-level resource execution. Record the
supported host, transport, schemas, result content and unprotected paths for that
candidate. Run the existing real-Claude acceptance separately when available.
Any numeric performance gate must come from an accepted team protocol; the
current measurement does not invent one.

## Read-only GitHub scanning audit

The [audit script](../../scripts/github-code-scanning-audit.py) uses an already
authenticated GitHub CLI. It only makes GET requests and writes a local report.
It never modifies security settings, dismisses alerts or creates PRs.

```sh
python3 scripts/github-code-scanning-audit.py --output target/github-main-audit.json
python3 scripts/github-code-scanning-audit.py --pr 35 --output target/github-pr35-audit.json
```

Replace the example PR number with the candidate under review. Reports include
the target SHA, a final head recheck, observed languages, default setup,
workflow inventory, effective main rules, branch-protection details, checks,
analysis revisions and open-alert counts. They exclude alert snippets and
private diagnostic text. Lists are paginated; access failures are explicit.

Exit 0 means evidence collection completed, not that merge protection works.
Exit 2 means evidence is incomplete, such as a 403/404 or a moving head.
The report never sets `merge_protection_verified=true` from configuration alone.
Old analyses do not count as current. Merge-ref analyses require separate
verification that their tested merge contains the current PR head.

The existing repository has CodeQL analysis checks for Rust, Python and GitHub
Actions. A successful `Analyze (rust)` job proves analysis/upload success, not
the alert-bearing merge decision. Confirm the actual results-check name and
GitHub app on the candidate; do not require an unrelated job just because its
name contains CodeQL. Confirm actual PR-to-main and default-branch coverage.
Repository languages without analysis evidence remain coverage gaps.

Before adding a workflow, inspect the active default setup with an administrator.
No CodeQL workflow in the checkout does not mean scanning is disabled. This
preparation deliberately adds no duplicate CodeQL workflow.

### Readable offline report

After collecting the JSON above, convert it to Markdown with the
[report script](../../scripts/github-code-scanning-report.py):

```sh
python3 scripts/github-code-scanning-report.py \
  --input target/github-main-audit.json \
  --output target/github-main-audit.md
```

For a PR, use its saved audit JSON instead. On Windows, use `python` instead of
`python3`. The converter needs Python 3.10+ and only its standard library;
it needs neither GitHub credentials nor network access. Keep the original JSON
beside the Markdown report. Conversion does not refresh the saved observations.

An audit exit code of 2 can still leave a valid, incomplete JSON report. Inspect
that file and run the converter separately; do not discard access failures or
replace missing evidence with a pass. The converter accepts schema version 1,
preserves recorded statuses, and labels missing/null values as `not recorded`.
It refuses invalid input, unsupported schema versions and existing output paths.
Use a fresh Markdown filename for each report.

The converter's exit code 0 means **the document was created**, even when the
audit is incomplete. Exit code 2 means conversion failed. Neither a generated
report nor a successful analysis/upload job proves that a finding blocks merge.

For the administrator handoff, review the recorded target SHA, observation time
and head recheck first. Then compare the analysis jobs with the separate results
check, including its app, exact-head match and conclusion. Review the observed
rulesets, effective main rules and thresholds alongside unavailable observations.
An empty rule list or a 403/404 response does not prove the absence of protection.
The final table keeps all three administrator gate cases and their saved statuses,
including `not_run`; conversion never runs those cases or changes GitHub settings.

### Administrator configuration and live gate evidence

Coordinate repository settings with @winux125 and follow the current SOU-18
implementation review requirements. The
[disabled ruleset example](../../deploy/github-code-scanning-ruleset.example.json)
targets `main`, requires CodeQL, High-or-higher security alerts and error-level
alerts. It is an additive example, not a replacement for existing review/status
protections. Importing it disabled does not enable a merge gate. Record the
administrator, applied ruleset ID, thresholds, bypass actors, plan/access limits
and before/after configuration when an administrator enables the reviewed rule.

Verify on a disposable PR targeting main, which must never be merged:

| Case | Required evidence |
| --- | --- |
| Clean analyzed head | Current head analysis and results check; scanning rule permits progression, subject to other review/check requirements |
| Missing or pending analysis after a new commit | New head SHA and the actual rule rejection/pending reason; previous-head success is insufficient |
| Controlled qualifying finding | Scanner-detected synthetic finding at the configured threshold, results check and actual rule rejection |

Coordinate the harmless detection fixture with the administrator and security
reviewer. Keep it only on the disposable branch, never execute its vulnerable
path, and close the test PR without merging. A generic `BLOCKED` merge state
caused by missing reviews does not prove a scanning-rule rejection. Preserve the
head SHA, analysis ID, rule result, thresholds and timestamps for each case.

Until all three cases are observed, retain `not_run`/unverified evidence.
False-positive dismissals need the authorized reviewer's recorded rationale;
do not lower thresholds or silently bypass findings. Link
[SOU-17](https://linear.app/soup-wall/issue/SOU-17/task-11-independently-verify-failure-overlap-and-replay-behavior)'s
triage report and remediation issues when supplied. A clean PR does not resolve
the existing alert inventory.

Configuration references:
[GitHub merge protection](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/manage-your-configuration/set-merge-protection),
[ruleset API](https://docs.github.com/en/rest/repos/rules#create-a-repository-ruleset),
[code scanning API](https://docs.github.com/en/rest/code-scanning/code-scanning).
