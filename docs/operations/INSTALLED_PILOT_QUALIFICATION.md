# Installed development pilot qualification

SOU-100 runs one installed Linux x86-64 Agent with the original pinned filesystem
and Git MCP servers through the selected Claude Code 2.1.251 executable. The
Messages provider is an owned loopback script. This measures actual-host
interoperability, useful execution, refusal and recovery. It does not measure a
live model's effectiveness, certify pilot readiness, or complete Phase 4.

The runtime uses the existing per-server rule baselines and an explicitly scoped
variant of the [combined proof policy](../../scripts/verify-sou62-sou63-combined.py),
including Ask for a read derived from MCP content. Result injection requires
medium severity, matching the accepted [Git profile](../../profiles/mcp/git-readonly-v1/policy.yaml).
The filesystem-only proof policy's LOW heuristic also matches
ordinary 40-character Git object IDs, so its unconditional detector rule falsely
interrupts original Git history. The initial failure is retained; detectors and
shipped policies are unchanged. Calibration requires both useful original Git
history with its object ID and withholding a real original-server injection
result. This scoped threshold is not evidence that every LOW finding is benign.
It does not install a product preset,
train a model, change an existing host profile, or implement another kit builder.
The ordinary filesystem/Git profile installers remain the preparation interface.

## Inputs and one qualification command

Use a clean exact checkout. Follow the existing locked build and pinned runtime
preparation in [filesystem acceptance](MCP_REAL_FILESYSTEM.md) and
[Git acceptance](GIT_MCP_PROFILE.md). The executable steps, including Node,
bubblewrap, Git, Claude Code and library-test selection, are in the existing
[Linux workflow](../../.github/workflows/mcp-real-filesystem.yml). No sysctl,
AppArmor, seccomp or host permission relaxation is part of this procedure.

After the normal build, record `sw-installed-pilot-selection/2` in a private
JSON file outside the checkout. The workflow's `PILOT_SELECTION` step is the
executable example. It records `source()` from the driver (commit, tree, clean
state and digest of every tracked file), plus absolute paths and SHA-256 for:

| Role | Selected input |
| --- | --- |
| `agentfw`, `git_launcher` | `agentfw` and `agentfw-git-sandbox` from the same locked build |
| `sandbox_tests` | The actual Agent library-test executable from Cargo JSON |
| `node`, `npm` | The accepted filesystem profile's pinned Node distribution |
| `bwrap`, `git` | The accepted bubblewrap and Git builds |
| `claude` | The existing locked actual Claude Code host package |
| `python` | The explicit Python interpreter for the classifiers and witnesses |
| `filesystem_classifier`, `git_classifier` | Explicit selected single-file rule classifiers; never substituted with checkout defaults |
| `policy` | Explicit selected YAML policy, copied byte-for-byte |

Each data asset has its own absolute path and SHA-256 and a 1 MiB bound; it need
not be executable. The sidecar also declares `expected_refusal` with `verdict`
(`ask` or `deny`, never `allow`) and an exact `rule` identifier for the forbidden
derived read. Both the actual host error and native audit must match it, with no
FIFO reader; an independent conversation must still perform that same read.
The workflow explicitly selects the accepted baseline files and materializes
the stated proof policy. A later accepted versioned classifier/policy can be
selected by changing these sidecar inputs and the expected refusal, without
editing the driver or modifying another owner's pinned artifacts. Unsupported
single-file interfaces or changed policy behavior fail qualification; there is
no fallback to the old baseline. This does not implement installed-worker
preparation/readiness (SOU-102) or certify a future combined candidate.

The sidecar is caller-attested build evidence, not a signed binary provenance
certificate. Retain Cargo build JSON, runtime archive hashes and the selection
with the run. The command rechecks all selected files and source before/after;
a digest supplied by the same caller is not an independent publisher signature.

```sh
python3 -B scripts/qualify-installed-pilot.py --run \
  --selection /absolute/private/selection.json \
  --expected-commit FULL_REVIEWED_COMMIT \
  --output /absolute/private/new-run-directory
```

Omitting `--run` prints the protocol without executing anything. Output must be
new and outside the checkout. Rerunning never overwrites an earlier failed run.
For a later accepted combined candidate, repeat the existing build, record its
new exact selection, and use the same command with a new output directory.
An older report cannot qualify that later candidate.

Agent, Git launcher and the two exact selected classifier files are staged in a new
private temporary directory. Both original profile installers prepare their
locked packages there. The merged native registry retains every original tool
schema and profile declaration. The host project, Agent home, policy and server
profiles are outside the source checkout. No personal Claude state or inherited
provider credentials are used. Downloading the already pinned runtime assets is
preparation; protected collector startup never downloads a server.

The filesystem witness directory and synthetic Git repository are separate
owned roots. The accepted Git profile forbids special files throughout its
repository: filesystem FIFO witnesses must not be placed in that repository or
hidden from its validator. Both selected servers keep their original virtual
`/workspace` mapping and independently recorded profile identities.

## Fixed exercise and witnesses

The original denominator is **12 cases**, retained even after a failed setup:

1. Exact installed source, binaries, classifiers, policy, registry and profiles.
2. The required real filesystem and Git sandbox positives, with no fallback.
3. Witness calibration: original useful bytes, useful Git object IDs versus a
   withheld original injection result, an original controlled write,
   each negative FIFO's actual reader, repository kernel OPEN observations, and
   an owned loopback receiver. The controlled write is an executed effect; the
   driver explicitly removes only its synthetic calibration file afterwards.
4. Actual Claude reads a guide and original Git history in one parallel proposal.
5. Actual Claude reads the working file and original Git diff in another proposal.
6. Actual Claude encounters an untrusted path, proposes the resulting FIFO read,
   receives the selected native Ask/Deny without a FIFO reader, proposes an unsupported Git reset,
   then continues useful reads on both servers. The reset refusal belongs to the
   selected read-only profile before native admission; it is not a policy Deny.
7. A genuinely independent Claude conversation successfully reads that same
   FIFO and Git history. It must not inherit the affected conversation's risk.
8. Explicit MCP client calls on the same installation: eight independently
   observed blocked reads, one queued cancellation, one in-flight cancellation,
   seven correlated useful replies, reusable capacity and a useful Git sibling.
   The in-flight call **executed** before cancellation; no rollback is claimed.
9. SIGKILL of one useful collector, automatic original-process cleanup and lease
   expiry without SessionEnd, useful surviving Git sibling, fresh collector epoch
   and useful reconnection. This is one integrated crash, not another stress suite.
10. Actual-host useful read, daemon SIGKILL before a FIFO proposal, correlated
    host error with no reader, new daemon instance, explicit old-grant rejection,
    then a **fresh** Claude conversation with fresh grants and useful results.
    An outage error is technical unavailability, not a policy decision.
11. The same executable command rejects changed candidate identity, a missing
    sandbox executable and a changed staged classifier. Child failed results
    remain in separate directories; the controls do not become positive runs.
12. Exact workspace/repository snapshots, unrelated process/file survival up to
    teardown, all owned process cleanup, unchanged source/assets and stage removal.

Original server output and actual provider-returned useful bytes must agree.
Git text block arrays are decoded without dropping non-text or extra fields;
filesystem structured text keeps its separate exact shape.
The withheld original Git injection result requires one actual non-shadow native
result Deny with an injection finding for the exact host, agent and tool, plus
the same rule in the correlated error and no delivered injection bytes. The
rule identifier is observed from the selected policy, not fixed to the initial
proof policy's name. An unrelated refusal or technical failure cannot substitute.
Replayed authority must receive an explicit native HTTP 409 instance-mismatch response for the same
old grant. The collector's intentionally generic rejected-request stderr and
an EOF alone are insufficient; diagnostic response bodies stay out of its log.
Parser errors, absent tool results, host retries, missing hooks, lost responses
and an empty delivery ledger alone are not prevention evidence. FIFO probes are
calibrated on the same inodes before negative observations. Kernel Git OPEN
observations distinguish refusal from repository access during the unsupported
reset. Exact snapshots include the Git index and objects. The receiver is only a
calibrated observation here: no general egress protection is certified by a
two-server read-only exercise.

## Bounds, outcomes and evidence

Limits are declared before execution: two required benign workflows, zero
false interruptions, 180 seconds per exercise case, 600 seconds for preparation,
15 seconds for collector reclamation/daemon restart, 150 seconds per Claude
process, 32 provider requests per host run, 8 MiB per retained host/log stream,
and a 256 KiB public result. The reused MCP observer caps frames at 256 KiB,
256 observed records and 64 pending frames. An overflow, partial EOF or unread
late reply fails final qualification; expected useful replies cannot hide it.
Individual subprocesses have their own timeouts;
case totals exceeding the declared bound fail even if output arrives late.
The enclosing CI job also retains its existing 40-minute hard timeout.

`report.json` contains passed/failed/incomplete/unsupported distinctions, the
original denominators, false interruptions, per-tool end-to-end latency, setup
and recovery durations, exact installed identities and remaining blockers. Every
mandatory case must pass; a supported component's historical CI is not imported
as a current installed-system pass. An unavailable Linux sandbox cannot become
a skip or a fallback positive. macOS and native Windows are outside this pilot;
WSL requires its own actual Linux run and does not inherit a hosted Linux result.

Output is private (`0700` directory, `0600` report/logs). Original **owned
synthetic** host frames, failures, late output and sanitized collector/native
audit logs remain alongside the bounded content-free summary. Original-server
reference results, provider-observed tool results and complete owned MCP wire
transcripts are retained for independent regrading. Host settings,
environments and bearer/proof files are never retained. Do not point this
development-only exercise at customer workspaces or treat its targeted token
redaction as a general user-data scrubber.

## Remaining work for October 22–24

Until this exact installed candidate has completed every required positive, its
status is **unqualified**, irrespective of other green component checks. Read
the run's `remaining_blockers` first and retain its initial failed artifacts.
Fix an in-scope runtime defect only with its failing witness, focused regression
and useful continuation. Re-run on the resulting exact candidate.

Keep these owner boundaries explicit when converging on the final candidate:

| Priority | Boundary / owner | Required follow-up |
| --- | --- | --- |
| P0 | Installed runtime / SOU-100 | Reproduce and resolve mandatory failures on current accepted source; no readiness claim while any case is failing |
| P0 | Classifier / SOU-97 | Re-run with the accepted classifier increment; report any unsupported benign tool with exact tool/schema/arguments and current classification, rather than changing classifier behavior here |
| P1 | Kit / SOU-87 | Reuse the accepted archive's exact assets when available; archive composition and kit-negative controls stay with that owner |
| P1 | Persistent onboarding / SOU-101 and host launcher owner | Hand over a minimal reproduction for setup/host-launch defects; this temporary stage is not persistent onboarding or a new launcher |
| P1 | Installed classifier readiness / SOU-102 | Adopt and qualify its accepted explicit startup/readiness interface; this single-file baseline run does not measure prepared installed workers |
| P1 | Support report / SOU-80; CI scheduling / SOU-91 | Supply exact run identities/results; do not invent report validation support or alter scheduling policy in this driver |

These are convergence requirements, not fabricated discoveries or reasons to
wait before running accepted main. No sealed evaluation data, training, paid
provider call, release, prerelease or registry publication is authorized here.

## Matched installed-host development measurement (SOU-106)

The opt-in extension uses the same selected binaries, profile installers, daemon,
original filesystem/Git servers and Claude Code host as the procedure above.
It does not enable Ask approval or replace the selected policies/classifiers.
The versioned public workload is
[`installed-pilot-workload-v2.json`](../../scripts/benchmarks/installed-pilot-workload-v2.json).
Its 12 supported benign multi-step variants include listing/search, batched and
optional reads, Git status/log/diff/show, parallel calls and continuation. Eight
mutator variants are explicitly **profile-unsupported**, not policy Deny examples.
Nested edit arguments are exercised as refused mutations, not claimed supported.

From an ordinary checkout of the exact candidate, after the existing preparation
procedure has produced a private selection file, run:

```sh
python3 -B scripts/qualify-installed-pilot.py --run --matched-development \
  --selection /absolute/private/selection.json \
  --expected-commit FULL_CANDIDATE_COMMIT \
  --output /absolute/private/new-matched-result
```

The command requires Linux x86-64 and the original selected host. It creates its
runtime workspaces outside the checkout. It never reads a contributor's private
worktree, calls a paid provider or uses real task data. The default command
without `--matched-development` remains compatible. The workflow dispatch input
`matched_development_only` selects one focused native Ubuntu job; do not launch
the whole native matrix for each sample.

The workload is saved before candidate execution, then each variant runs control
and protected with identical normalized operations, owned fixture bytes and
selected assets. Control is the original server through the actual host, without
admission. Protected uses the existing admission path. Absolute control paths
are translated from the same `/workspace` arguments and normalized in result
comparison; there is no tool implementation replacement. Effects are witnessed
from file/index bytes and kernel OPEN observations during the adverse batch.
Owned originals are restored before the protected arm; a control that does not
produce its expected effect cannot establish prevention. Refusal must be explicit,
produce no independent forbidden effect/open, and permit useful continuation.

`report.json` retains every arm, including failures and unexecuted rows;
`progress.json` is an incomplete checkpoint only. `scorecard.md` summarizes
counts and nearest-rank p95 using the existing matched-report distribution.
Source/selection verification, asset/daemon preparation, host startup, first
batch and subsequent call observations are distinguished. Already-built binary
build time is **not measured**. Fresh host processes do not imply cold OS caches;
control-first ordering can bias overhead. Parallel result observation includes
host/provider processing and is not isolated server execution time. The 1000 ms
p95 overhead investigation budget is engineering guidance, not an approved
security/efficacy threshold. Existing per-host deadlines are retained.

The gate rejects absent/duplicate pairs, identities/operations/schema drift,
skips, missing calibration, invalid timings, forbidden effects and supported
benign failures. A deliberately broken pair-list fixture checks the gate itself;
it is separate from runtime evidence. Missing setup or runtime evidence fails.
Raw owned evidence remains private; share only inspected sanitized summaries.
These scripted controls do not measure live-model effectiveness, prove model
consumption, close Phase 4, or certify pilot readiness.

The first v1 attempt is retained in [SOU-106 evidence](evidence/sou106/README.md).
Version 2 corrects a `tail=1` request that selected the original server's trailing
empty line: `tail=2` requests the intended useful line without changing the
expected content. Search-followed-by-read interruptions remain failures.
