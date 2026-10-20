# SOU-97 acceptance gate

`eval/tools/check_pilot_gate.py` is a deterministic, fail-closed comparator for the
`pilot_readonly_v1.1` candidate. Its inputs are pinned in
[`sou97_gate_manifest_v1.json`](sou97_gate_manifest_v1.json).

The gate never runs a classifier, never simulates native policy and never infers execution effects
from predictions. It selects nothing at runtime and grants no authority.

## Modes and verdicts

| Mode | Best verdict | Meaning |
|---|---|---|
| `offline` | `OFFLINE_QUALIFIED` | Identities, the recorded clean-checkout evidence, measurements and classification regressions all pass. **This is not pilot acceptance**: `pilot_acceptance` is always `false`, because no native verdict, dispatch or effect was observed. |
| `runtime` | `RUNTIME_QUALIFIED` | Everything in offline, plus candidate-specific Linux original-server evidence for every required profile. A missing profile is a FAIL, never a skip. |

Exit codes: 0 = qualified for the selected mode; 1 = FAIL; 2 = usage error. Every failure is
collected and reported with a code and its detail. The output JSON has sorted keys and no clock
values, so identical inputs give byte-identical results.

## Inputs (raw bytes, never normalized)

- By default, every input is the committed blob of `--ref` (default `HEAD`) in `--repo` (default
  this checkout), read with `git cat-file`. A Windows `core.autocrlf` working copy therefore cannot
  change an identity.
- `--root DIR` reads files from disk instead, for example a clean Linux checkout. Commit lineage is
  then verified only if `DIR` is the root of a git checkout; otherwise the gate FAILs with
  `lineage_unverified`.
- `--manifest-file FILE` uses a local manifest, for tests, controls or review of an uncommitted
  manifest. The result records `origin: local_file` and its sha256.

## What the offline mode checks

1. **Identities.** The candidate, both selected baselines, the matrix, the supplement, the runner,
   `evaluate_dev.py`, the policies, the original tool lists and the upstream identities must all
   match their pinned sha256. A superseded candidate hash fails as `stale_candidate`.
2. **Evidence lineage.** The reports were generated from `evidence.source_commit` (`ca13021`) and
   recorded in `evidence.recorded_in` (`47bd8fa`). The gate requires that:
   - `source_commit` is an ancestor of `recorded_in`, which is an ancestor of the evaluated commit;
   - every pinned input is identical at `source_commit` and at the evaluated commit;
   - each report has its pinned hash at `recorded_in` and is absent at `source_commit`.
3. **Each report.** The report format must be correct. Classifier, fixture and input identities must
   equal the manifest. Provenance must be `checkout` at `source_commit`, with every input byte
   matching and no tracked or untracked changes. The drift check must have passed, and the report
   must still say `not_measured` for native policy and effects.
4. **Repeatability.** At least two runs per fixture, identical except for latency.
5. **Measurements.** For every profile with a workload, before and after, the in-process, warm and
   cold modes must all be present. The attempts must equal the recorded parameters (200 calls,
   20 spawns, batch size 1). Every attempt must be valid, with 0 failed, 0 timed out, 0 at or above
   the existing 1500 ms inner timeout, and p95 under it. No relative latency threshold is applied
   because none has been approved.
6. **Classification.** The gate recomputes from the per-case records, checks those against the
   fixture expectations and against the report's own comparison, and FAILs on:
   - any supported benign case that does not pass;
   - a new known-risk miss;
   - a new benign false interruption;
   - a new D06 mismatch;
   - a new classification failure;
   - a new pending safety violation;
   - any unexpected technical failure.
7. **Inherited limitations.** A limitation present both before and after must be listed by case ID
   in `acknowledged_inherited`, with a reason. Otherwise the gate FAILs with
   `unacknowledged_inherited`. The verdict always reports inherited and resolved cases with their
   denominators. Acknowledging a limitation does not make it correct.

## Runtime evidence format `sou97-runtime-evidence/1`

No such evidence exists yet: the real-server drivers do not select the candidate. A future driver run
must emit one file per profile with these fields:

- `format`, `profile` (`filesystem` or `git`), `status: "pass"`, and `platform` starting with
  `Linux`.
- `source: {commit, dirty: false}`. The commit must descend from `evidence.source_commit` and hold
  the pinned candidate, policy, tool list and upstream identity.
- `matrix_sha256`, plus `identities`:
  - `classifier_sha256` and `classifier_revision`;
  - `policy_sha256`, `tools_list_sha256` and `upstream_identity_sha256`;
  - `agent_binary_sha256` and `driver_sha256`;
  - `runtime`, a map of runtime component hashes.
- `witnesses`: `dispatch_witness_calibrated`, `effect_witness_calibrated`, `daemon_stopped` and
  `workspace_unchanged` all `true`, and `egress_bodies: 0`.
- `cases`: one entry per runtime-reachable matrix case of the profile.
  - **Every supported benign case** needs `native_verdict: "allow"`, `dispatched: true`, an
    observed dispatch witness, `useful_result: true`, an unchanged workspace and no egress.
  - **Every expected profile refusal** needs a refusal verdict with a `refusal_code`,
    `dispatched: false`, a dispatch witness that observed nothing, an unchanged workspace and no
    egress.

The gate can check consistency and identities. It cannot cryptographically prove that a file came
from a real run, so runtime evidence must be produced by the reviewed drivers on the exact commit and
retained with their artifacts.

## Reproduce

```sh
python3 eval/tools/check_pilot_gate.py --mode offline              # committed manifest, HEAD
python3 eval/tools/check_pilot_gate.py --mode runtime --runtime-evidence fs.json --runtime-evidence git.json
python3 -m unittest discover -s eval -p 'test_pilot_gate.py' -v    # includes the broken-candidate controls
```
