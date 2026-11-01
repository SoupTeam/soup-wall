# Source-bound native performance comparison (SOU-203)

`scripts/native_performance.py` compares two retained native performance reports offline (Ask,
installed host or preparation). It
explains whether a difference can be read at all before it shows one. It reads JSON and local
git objects only. It runs no measurement, changes no producer, timeout, budget or policy, and
makes no network call.

The results are engineering latency diagnostics. They are not a security or protection
qualification, not task effectiveness and not pilot or product readiness. No budget is approved.

## Command

```powershell
python scripts/native_performance.py `
  --baseline SUMMARY.json [--baseline-manifest MANIFEST.json] [--baseline-receipt RECEIPT.json] `
  --candidate SUMMARY.json [--candidate-manifest MANIFEST.json] [--candidate-receipt RECEIPT.json] `
  [--paired] [--repository <git checkout>] --out-dir <new-or-empty-directory>
```

| Input | Contract | Role |
|---|---|---|
| `--*` | one report of a supported family (below) | Retained report with every per-trial value |
| `--*-manifest` | the series `manifest.json` (series only) | Plan declared before the first trial; binary digests, kernel, machine |
| `--*-receipt` | `sw-native-pilot-agent-source-build/1` (series only) | Binds the agentfw/git_launcher digests and the cargo build profile |
| `--repository` | local git checkout (default: this one) | Witness for source identity and report custody |

### Supported report families

| Family | Producer | Primary endpoint | Status |
|---|---|---|---|
| Ask series, `sw-ask-series/1` (SOU-141) | `qualify-ask-series.py` | `continuation_ms` | supported; genuine evidence reproduced |
| Ask qualification, `sw-pilot-ask-acceptance/1` (SOU-124) | `qualify-pilot-ask.py` | `continuation_ms` | supported; genuine evidence reproduced (counts, p50, p95) |
| Installed host, `sw-installed-pilot-matched/1` (SOU-106) | `pilot_measurement.py` via `qualify-installed-pilot.py` | `host_start_ms` | supported; genuine evidence and gate reproduced |
| Native preparation, `sw-native-pilot-prerequisites/1` | `prepare-native-pilot-prerequisites.py` | `stage_seconds` (s) | supported; **synthetic controls only**: no genuine receipt is retained in the repository |
| Preparation marker, `sw-pilot-preparation/1` | `prepare-installed-pilot.py` | none | rejected as `no_performance_endpoints`: a completion marker without timing fields |

Families never compare with each other: different endpoints, units and producer formats are
`non-comparable`. The SOU-122 `preparation-summary.json` is a genuine but unversioned CI summary
(no `format`, single values). It is not an accepted producer contract and is not read.

Output files: `comparison.json` (`sw-native-performance-comparison/1`), `report.md`, `strata.csv`
and `trials.csv` (every planned trial of both sides). On rejection only `comparison.json` and
`report.md` are written, with the reason code.

| Exit | Meaning |
|---|---|
| 0 | `compatible` or `stratified-only` |
| 1 | Valid evidence, `incomplete` or `non-comparable`: no difference is reported |
| 2 | Rejected evidence (malformed, tampered, contradicted): nothing is compared |
| 3 | Usage error, for example a non-empty output directory |

Reproduce the committed evidence bundle and the controls:

```powershell
python scripts/native_performance_evidence.py --check
python -m unittest discover -s scripts/tests -p test_native_performance.py -v
```

## What is verified

| Item | Method | SOU-141 retained evidence |
|---|---|---|
| Report custody | The git blob id of the bytes read must be a committed blob reachable from HEAD. A CRLF checkout copy is accepted only when its LF bytes are that blob (recorded as `crlf_to_lf_checkout`). | verified |
| Source | `source.tree` must equal the commit's tree, and `files_sha256` is recomputed from every committed blob. A mismatch is a rejection. | verified |
| Workload/harness | SHA-256 of `qualify-pilot-ask.py` and `pilot_ask_latency.py` at the source commit | verified |
| Binaries | Manifest digests are self-declared. A receipt binds agentfw and git_launcher to the same source. | declared only |
| Build profile | `--release` / `--profile` in the receipt's `cargo build` command, otherwise `dev` | not retained |
| Published aggregates | Every per-run latency, diagnostic sample, diagnostic distribution, pooled value, status, blocker list and attempt ledger is recomputed from the retained trials with the producer's own functions. Any difference is a rejection. | reproduced |
| Trace | Series: requested mode inferred from runs the summary itself marks validated (producer-declared). Ask report: its own `trace_requested`, absent in the retained SOU-124 report. The observed strace mode is never retained. | declared only |
| Host instance | Not recorded by the producer | not retained |

## Observation contract (`sw-native-performance-observation/1`)

- **Trials**: every planned trial `rNN/<profile>/<index>` has exactly one status:
  `measured` (row present, passed, finite non-negative duration), `failed` (row present, not
  passed), `timed_out` (no row, run failed with `series_<n>_timeout`), `incomplete` (no row in a
  recorded run) or `not_run` (planned run never recorded). Trials of unqualified runs stay in
  the population and are counted as excluded.
- **Endpoints** keep their own clock, observer and unit. `continuation_ms` is the harness
  monotonic decision-to-result time and is the only one with the 3000 ms p95 criterion.
  `first_pending_asset_verification_ms` is a collector-clock lower bound of the first-pending
  wait, never the 5 s pending measurement. `post_observed_total_ms` and per-stage values are
  collector-clock internal verification. No value from one clock is subtracted from another,
  and stages are never summed into a new duration.
- **Conditions**: a `cold` run is `post_cache_drop_setup_rewarmed`. The cache drop must satisfy
  the producer's own predicate, and a true-cold claim is rejected. Retroactive runs stay
  `declared_<kind>_unverified`.
- **Strata** are `(profile, condition)`. Profiles and conditions are never pooled.

### Installed host (`sw-installed-pilot-matched/1`)

- **Trials**: one per `(case, arm)`, id `r01/<case>/<arm>`, stratum `<arm>/<kind>` (control or
  protected; benign or refusal). The plan, order and `operation_sha256` of every row are checked
  against the workload file read from git at the source commit, by its `workload_file_sha256`.
  Status: `passed` is `measured`; `failed` is `failed`, or `timed_out` when the reason names a
  timeout or deadline; `incomplete` with `not_executed` is `not_run`, otherwise `incomplete`.
- **Endpoints** (driver monotonic clock, ms, separate boundaries, never subtracted):
  - `host_start_ms`: host spawn to the first scripted proposal. This is the primary endpoint,
    required by every gate revision.
  - `host_elapsed_ms`: spawn to exit. Not written by the oldest producer revision.
  - Per-call latency: `call/first_batch_ms` and `call/steady_state_ms`, measured from a proposal
    to its observed result. Calls in one batch share completion observation.
  - Report-level, single values never compared: `preparation_ms`,
    `source_and_selection_verification_ms` and `asset_install_and_daemon_prepare_ms`.
  - Observable Ask latency is `not_applicable`: the workload has no Ask decision.
- **Provenance**:
  - verified from git: source tree and `files_sha256`, the workload file, and the
    `driver_sha256` and `extension_sha256` blobs;
  - self-declared: binaries, profiles, policy and registry (`policy_sha256` must equal
    `selected.policy`).
- **Gate**: reproduced with the accepted `pilot_qualification.matched_gate` only when the gate code
  at the source commit is byte-identical to it (SOU-106 `ce4f76d`). Otherwise it is listed as not
  reproduced (`41e3f10`, `bd1c17c`).
- **Outcomes**: row status and the gate are the producer's development workflow outcomes. A
  protected refusal is the producer's own witness, never security effectiveness. The
  within-report control/protected pairing is reported, never used to pair two reports.
- **Condition**: `fresh_host_per_arm_os_cache_uncontrolled`. Any other `os_cache` claim is
  rejected (`true_cold_claim_unsupported`).
- **No substitution**: in a measured arm, `host_start_ms` must be below `host_elapsed_ms` and
  every call at most `host_elapsed_ms`. These are nested boundaries on the same clock, so no
  subtraction is involved. A violation is rejected as `endpoint_substitution`.
- **Denominators**: distributions use measured arms only, so failed arms are counted, never
  imputed. A stratum with a failed arm (for example 10 of 12 protected benign arms) is
  `incomplete_denominator` and is never compared. Per-call distributions count calls, which are
  dependent within an arm. Every report is one cluster on one runner, so no interval is computed.

### Native preparation (`sw-native-pilot-prerequisites/1`)

- **Trials**: one trial per stage (`r01/git`, `r01/bwrap`), endpoint `stage_seconds` in seconds.
- **Conditions**: `built_from_source` and `reused_verified_checkpoint` are separate strata.
- **Status**: a completed receipt holds only completed stages. A failed preparation writes no
  receipt, so failed and incomplete stages are not representable, and a receipt claiming one is
  rejected (`receipt_stage_contradiction`).
- **Source**: the receipt names only a commit (`commit_verified_tree_not_declared`).
- **Shape**: the receipt must carry exactly the fields the producer writes; anything else is
  `report_shape_invalid`.

### Per-family text

`scope`, `percentile_definition`, the dependence reason in `inference`, `engineering_targets`
and `observer_semantics` are composed from the families present in a comparison. Ask criteria
(3000 ms continuation p95, 5000 ms first-pending bound) and the strace trace statement appear only
for Ask families. The observer and trace semantics per family:

| Family | Timing observer | Trace |
|---|---|---|
| Ask series and qualification | `qualify-pilot-ask.py` harness monotonic clock; collector clock for stages | strace seccomp-bpf requested; the observed mode is not retained |
| Installed host | `qualify-installed-pilot.py` driver monotonic clock, fresh host per arm, scripted loopback provider | none recorded |
| Native preparation | `prepare-native-pilot-prerequisites.py` stage timers (seconds) | not applicable |

## Classification

Precedence: rejection, then contradiction, then missing evidence, then strata.

| Classification | Rule |
|---|---|
| `non-comparable` | A verified contradiction: platform, kernel, machine, CPU count, verified host instance, producer format, endpoint or unit, trace mode, build profile, sample plan, measurement harness, or a declared pairing with different trial sets |
| `incomplete` | Missing independent evidence (custody, source or source contents, binaries, build profile, host instance), a reported `MemTotal_kb` difference (`mem_total_differs_materiality_unassessed`: it can differ between boots of one host, it proves no host difference, and no tolerance is approved), `--paired` without a pairing basis, or no comparable stratum |
| `stratified-only` | Global evidence is consistent, but some strata are unmatched or have an incomplete denominator. Only the listed comparable strata may be read. |
| `compatible` | Every stratum is matched, complete and comparable |

The same summary, manifest and receipt bytes on both sides form an **identity control**. It is
reported in `identity_control`, apart from the classification. Its trials pair by identity, so
all paired differences must be zero. It proves the comparator, not a change between revisions,
and it never stands in for provenance: identical evidence is classified by the same source,
binary, build and custody rules as any other pair. The genuine SOU-141 identity control is
therefore `incomplete` (binaries and build profile unverified). Two different reports have no paired design in this producer, so
only marginal percentile differences are given for them. These are labeled
`difference_of_marginal_percentiles_not_percentile_of_paired_differences` and are never
presented as a percentile of paired improvements. Different source revisions are allowed
(`source_revision_differs`) once both are verified.

## Statistics

- Percentile: nearest rank, the value at rank `ceil(q * n)` of the ascending unrounded sample
  (`pilot_ask_latency.summarize`). The published SOU-141 distributions round to 0.001 ms first.
  Reproduction uses that convention.
- Each stratum side reports n, p50, p95, min, max, the three highest trials, a per-run
  breakdown, the first trial per run and per-stage distributions. No observation is dropped.
- Inference is `descriptive_only`. A stratum has at most 2 runs (clusters) on one host, which is
  below the 10 effective clusters of DEC-SOU153-20261027. That bootstrap is approved only for
  AgentDojo families, and trials within a run are dependent. No interval is computed.

## Bounds

Inputs must be regular non-symlink files: summary 8 MiB, manifest 64 KiB, receipt 1 MiB. JSON is
strict (duplicate keys, NaN/Infinity, overflowing literals and invalid UTF-8 are rejected), with
nesting depth 32, at most 6 runs, 100 samples per profile and 1200 trials per report. Each
output file is limited to 8 MiB. The output directory must be new or empty.

## Known limitations

- The SOU-141 series retain no build receipt and no host instance. So two different SOU-141
  reports can never be `compatible`. A cross-revision comparison needs the producer to retain
  both (an external producer change, outside SOU-203).
- The raw `stage-events.jsonl` is not retained, so the `stages` aggregates are reported but not
  reproduced.
- Custody proves that the bytes are committed, not that the producer executed them. The binaries
  themselves are not retained, so their digests cannot be re-hashed.
- An Ask qualification report publishes only counts, p50 and p95. A changed trial at another rank
  is not detectable from its own aggregates. Its per-trial integrity rests on custody, so an
  uncommitted copy is always `incomplete`.
- The retained SOU-124 report declares no `files_sha256`, no `trace_requested`, no platform and no
  condition. Its source is verified to commit and tree only (`source_contents_unverified`).
- Installed host: binaries, profiles and policy are self-declared, and no build receipt is
  retained. The report records no platform, host or trace mode. The gate of the two older
  SOU-106 reports cannot be reproduced with the accepted gate code.
- Preparation: no genuine `sw-native-pilot-prerequisites/1` receipt is retained, so this adapter
  is demonstrated on synthetic receipts only. A failed preparation leaves no receipt to read.
