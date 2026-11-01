# Source-bound native performance comparison (SOU-203)

`scripts/native_performance.py` compares two retained native Ask latency series offline. It
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
| `--*` | `sw-ask-series/1` `summary.json`, or `sw-ask-series/1-retroactive` | Retained series with every per-trial value |
| `--*-manifest` | the series `manifest.json` | Plan declared before the first trial; binary digests, kernel, machine |
| `--*-receipt` | `sw-native-pilot-agent-source-build/1` | Binds the agentfw/git_launcher digests and the cargo build profile |
| `--repository` | local git checkout (default: this one) | Witness for source identity and report custody |

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
| Trace | Requested mode via the producer's `validate_report` gate on qualified runs; the observed strace mode is not retained | requested only |
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

## Classification

Precedence: rejection, then contradiction, then missing evidence, then strata.

| Classification | Rule |
|---|---|
| `non-comparable` | A verified contradiction: platform, kernel, machine, host environment, host instance, producer format, endpoint or unit, trace mode, build profile, sample plan, measurement harness, or a declared pairing with different trial sets |
| `incomplete` | Missing independent evidence (custody, source, binaries, build profile, host instance), `--paired` without a pairing basis, or no comparable stratum |
| `stratified-only` | Global evidence is consistent, but some strata are unmatched or have an incomplete denominator. Only the listed comparable strata may be read. |
| `compatible` | Every stratum is matched, complete and comparable |

The same summary, manifest and receipt bytes on both sides form an **identity control**. Its
trials pair by identity, so all paired differences must be zero. It proves the comparator, not
a change between revisions. Two different reports have no paired design in this producer, so
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
