# Local learned classifier preparation (SOU-16)

This optional CPU pipeline prepares a learned reference candidate for
[SOU-16](https://linear.app/soup-wall/issue/SOU-16/task-10-run-an-open-model-classifier-pilot-in-shadow-mode).
It returns semantic `actions` and separate Boolean `unknown`, never a policy
verdict, permission or executed tool call. The semantic reference is the owner's candidate
[contract 0.4-approved, D01-D10](https://github.com/SoupTeam/soup-wall/blob/5a3ff08fae333cd15bdf80345a240ca527a8872b/contract/updated_contract2.md).
Full SOU-10 contract review and production integration remain separate.
Technical inference exceptions remain separate failures for the caller to stop
before policy/execution; the evaluator records them separately from labels.

**Status: pipeline preparation, not a completed approved pilot.** On 9 October,
@aisarasd confirmed that the local linear baseline is suitable
for the first pilot. SOU-13 data remains preliminary; she expects split manifests
by 11 October and training/calibration data after review. No approved dataset
has yet been supplied. Shared evaluation fixtures from PR #52
never enter training or calibration. Development smoke results below cannot
establish holdout generalization, production gates or task acceptance.

## Candidate and limits

The candidate is newly trained logistic regression with five sigmoid action
heads and a separate unknown head. It is original Apache-2.0 code under this
repository's license. Python 3.10+ and the standard library suffice: no external
weights, model downloads, Torch dependency, API or paid compute. It is a learned
reference baseline, not a pretrained language model or encoder fine-tune.
The coordinator accepted this candidate for the first SOU-16 pilot; a reviewed
open encoder can be compared later if required. No encoder has been trained.

Hashed binary features use name, schema/property keys and actual arguments.
Descriptions stay bounded input data but are excluded from learned features;
changing a description cannot change a prediction. Runtime validation against
the admitted pinned schema belongs to the adapter. Hash collisions and limited
linear capacity can harm generalization. This is not a security boundary.
Inputs are bounded to 16 KiB, 2,048 JSON nodes, depth 16 and 512 distinct tokens.
Oversize/malformed input fails without truncating actual arguments. Inference
receives no IDs, family, split or gold labels.

## Unknown labels and calibration

Each action label is `true`, `false` or `null`. `null` contributes **no action
loss, decay or gradient** for that head. A fully unknown example can supervise
only the separate unknown head; a completely unannotated row changes no weights.
`false` explicitly supervises absence and is never inferred from missing data.
Partial examples preserve known positive effects and mask undetermined heads.

Training uses only train rows, shuffled with a fixed seed. Calibration changes
only thresholds on a separate family-disjoint split. The exploratory grid is
negative {0.1,0.2,0.3}, positive {0.7,0.8,0.9}; its objective weights critical
misses at 20, other misses at 1, false positives at 2, lost unknown at 20 and
abstention at 0.5. These starting values need review; they are not agreed
production criteria. Confidence is binary certainty, not calibrated joint
correctness or authorization.

Actions above the positive threshold survive. Intermediate scores, a positive
unknown-head score or more than half unseen feature bins retain unknown. This
heuristic can still miss unfamiliar semantics or abstain too often. Predicted
no-op remains an untrusted model claim and grants no permission.

## Development smoke check

```sh
python -m unittest experiments.local_classifier.test_model -v
python -m unittest experiments.local_classifier.test_ledger -v
python -m experiments.local_classifier.pilot smoke \
  --baseline-path rule_baseline \
  --output-dir target/local-classifier-smoke
```

Smoke builds its own tiny synthetic examples. Its toy split tags do not
establish unseen tool families: names/patterns intentionally repeat for plumbing
checks. Evidence always says `development_smoke`, `approval=null` and
`official_heldout_run=false`. Output must be new or empty; weights stay in ignored
`target/`. The baseline is now available in main from
[PR #53](https://github.com/SoupTeam/soup-wall/pull/53), initially frozen at
`000136c51884e0c204ac51b77c29c5c302f7256a`.

## Approved-data experiment

The loader accepts this experimental local dataset shape; it does not redefine
the shared adapter/classifier/policy contract:

```json
{
  "format": "soup-wall/classifier-dataset/1",
  "cases": [{
    "id": "training-example", "family": "reviewed-file-family", "split": "train",
    "input": {"tool_name": "read_file", "raw_arguments": {"path": "fixture/notes.txt"}},
    "labels": {"read": true, "write": null, "delete": null, "send_data": null,
               "change_permissions": null, "unknown": true}
  }]
}
```

An actual dataset requires nonempty train/calibration/holdout splits, unique IDs
and reviewed family annotations. The loader rejects family overlap and
cross-split semantic duplicates, including description-only variations.
Validation cannot prove annotation correctness. The example above is not an
approved dataset. A separate review file records its exact byte digest:

```json
{
  "format": "soup-wall/classifier-data-approval/1",
  "approval_reference": "<actual coordinator review link>",
  "source": "<reviewed dataset origin>",
  "license": "<reviewed dataset license>",
  "dataset_sha256": "<exact reviewed SHA-256>"
}
```

The review record asserts experimental provenance, not execution authorization.
Do not invent review references or relabel evaluation fixtures as training data.
Dataset JSON is bounded to 16 MiB/10,000 rows. Duplicate keys and non-finite
constants are rejected; validation and digesting consume the same bytes.

```sh
python -m experiments.local_classifier.pilot train \
  --dataset /path/to/approved.json --approval /path/to/review.json \
  --seed 42 --dimensions 512 --epochs 60 --output-dir target/approved-linear
python -m experiments.local_classifier.pilot evaluate \
  --dataset /path/to/approved.json --approval /path/to/review.json \
  --model-dir target/approved-linear \
  --baseline-path /path/to/frozen-rule-baseline \
  --run-authorization /custodian/pilot-run.json \
  --run-ledger-dir /custodian/shared-run-ledger
```

Train never passes holdout rows into fitting or threshold selection. Explicit
evaluation verifies the calibrated model digest and reviewed dataset, then
reserves holdout before inference using exclusive file creation. Repeating in
that artifact directory fails, even after an interrupted attempt. This local
guard cannot prevent copying artifacts or recreating runs: honest one-shot
evaluation also requires coordinator review and an external run ledger. After
inspecting holdout results, do not retune and call the same split untouched.

### Reviewed run ledger

Official evaluation now also requires a custodian-issued run record and an
existing shared ledger directory outside the model artifacts. The run record
binds the reviewed dataset bytes, frozen calibrated model and the exact baseline
source used in the comparison. It is an experimental bookkeeping format, not
the shared classification or execution-approval contract:

The loader compiles and hashes the same captured baseline source bytes (bounded
to 1 MiB), bypassing timestamp-based bytecode caches. Equal-size edits with the
same timestamp cannot execute old code under a new recorded digest. The supplied
baseline is reviewed trusted Python code; this loader is not a sandbox.

```json
{
  "format": "soup-wall/classifier-run-authorization/1",
  "run_id": "<reviewed experiment identity>",
  "holdout_id": "<custodian's stable identity for the untouched test manifest>",
  "approval_reference": "<actual review link for the frozen experiment>",
  "dataset_sha256": "<exact reviewed dataset SHA-256>",
  "model_sha256": "<frozen calibrated model SHA-256>",
  "baseline_sha256": "<frozen rule_baseline.py SHA-256>"
}
```

The custodian retains the same `holdout_id` and ledger for all copies/rebuilds
using those held-out cases. Changing model directories or `run_id` cannot reserve
that identity again in the same ledger. Exclusive file creation reserves the
attempt before holdout inference; interrupted attempts stay consumed. A separate
completion receipt binds the reservation and saved evaluation digests, while the
original reservation remains intact. Copying artifacts without their local marker
is covered by a regression check. Concurrent reservations admit only one attempt.

The JSON review reference is an assertion, not authenticated approval. The caller
can still select another ledger, forge a record or change `holdout_id`; filesystem
bookkeeping cannot prevent a dishonest experimenter. The reviewer/custodian must
control and reconcile the ledger, review identities and retain failed attempts.
This workflow grants no tool execution permissions or production acceptance.

### SOU-13 handoff prerequisites

When the test inputs and gold are withheld from the model author, use the
[separate custodian CLI](#separate-development-and-custodian-data) below. The older
`pilot train/evaluate` commands require a combined three-split dataset; they do
not implement that data-custody arrangement.

The 10 October checkpoint contains only provisional development fixtures. It
does not supply approved pilot data, a final dataset license or frozen family
manifests. A technical review of these fixtures does not invent human sign-off.
Do not train or issue a real run authorization from that checkpoint alone.

Before training, SOU-13's owner and named reviewer must release reviewed labels
with rationale/evidence and the agreed dataset license. Export the five tri-state
action targets and separate unknown directly; check each known mask against null.
Do not derive negative targets from missing actions in `contract_view`. Pending
disputes and technical-error cases stay outside the training/evaluation export.

Freeze train/validation/calibration/test manifests before candidate variants or
tuning, with aliases and near-duplicate templates grouped by family. Keep the
validation manifest in the reviewed provenance; this linear pilot fits only train
and calibrates only calibration. The experimental export calls test `holdout`.
The export and all original manifests need review before their digest is approved;
the local three-split loader cannot independently establish the original four-way
family partition. A separate test custodian reviews held-out gold without exposing
it to the candidate author during development. Lock the same baseline source for
both the model comparison and the externally recorded experiment.

For D05 out-of-scope shell calls, the contract owner confirmed on 10 October
that both safely retained actions and complete abstention are valid with unknown
true. A reviewed experimental row can optionally carry `accepted_outputs`:

```json
{
  "accepted_outputs": [
    {"actions": ["read"], "unknown": true},
    {"actions": [], "unknown": true}
  ]
}
```

This field is evaluation metadata, never inference input or training supervision.
It requires gold unknown true; each alternative retains unknown and contains only
proven positive actions. The approved dataset digest covers the alternatives.
Report `contract_scored` / `contract_matches` separately from action-label errors,
exact fully annotated matches and abstentions. For the accepted empty answer above,
read retention still records an FN while contract matching passes. Null action
labels remain masked. This does not approve unknown=false or change the runtime
contract. DEV-09's missing admission remains a separate barrier test; an admitted
opaque tool with neutral identity is the suggested classification replacement.

Evidence reports per-label critical misses/false positives with known-label
denominators, technical failures, unknown/coverage, mixed examples, p50/p95,
source/model/dataset hashes and peak process RSS. Traced Python allocation and
process RSS are distinct measurements. No GPU, external API or executor is used.
Zero API spend does not mean local CPU use is free. Policy outcomes and execution
enforcement are not measured.

### Separate development and custodian data

The `custodian` CLI addresses the SOU-13 handoff that contains development data
only. Train accepts no test file, test labels or run authorization. The independent
custodian receives the frozen model and training report, holds the test data,
reviews the linked provenance and performs the single comparison. Neither CLI
changes the shared runtime contract or grants tool execution authority.

After reviewed labels and explicit dataset-use approval, the development export has
`format: "soup-wall/classifier-development-dataset/1"` and `cases` with the same
row fields as the earlier local dataset: `id`, `family`, `split`, `input`, `labels`
and optional evaluation-only `accepted_outputs`. Nonempty `train`, `validation`
and `calibration` splits are required. Validation is retained for partition and
provenance checks only; it supplies neither fitting nor threshold supervision.
Test rows are rejected, even if supplied accidentally. This command has no smoke
mode; its unit tests use explicitly artificial review records and toy data only.

For the SOU-13 separated JSONL exports, join labels and model inputs by matching
ID, verify input hashes and mask agreement, and copy true/false/null action targets
and separate unknown directly. Use the reviewed leakage group as `family` so
aliases and related templates remain in one split. Copy only the original `input`
into inference data; IDs, family, split, gold, traces and rationale are not model
features. Exclude pending, admission-rejection and technical-error rows. A
provisional directory named `pilot` is not data approval. The final release must
review the export and its digest; do not automatically convert the provisional
11 October checkpoint into approved training data.

For SOU-13's authorized Gold JSONL export, use the conversion command after
separately running its reviewed verifier from the repository. Preserve the UTF-8
JSON verification report and obtain the exact `GOLD_EXPORT_MANIFEST.json` SHA-256
from the dataset owner outside the export. Do not execute an unreviewed script
copied from a received archive. Both self-consistency and anchored integrity must
report PASS. An internal usage decision such as `SOU13-USAGE-2026-10-12` permits
only its recorded scope; it does not grant public licensing or publication.

```sh
# Verify the actual approved Gold release using the reviewed SOU-13 tooling.
python -I -B eval/sou13/scripts_cp2/verify_gold_export.py /private/gold-dev \
  --expect-manifest-sha256 OWNER_PUBLISHED_DIGEST > /private/verified.json

python -m experiments.local_classifier.gold_import \
  --gold-export /private/gold-dev --verification-report /private/verified.json \
  --expect-manifest-sha256 OWNER_PUBLISHED_DIGEST \
  --review-reference ACTUAL_OWNER_RELEASE_AND_REVIEW_REFERENCE \
  --holdout-id CUSTODIAN_ISSUED_STABLE_ID --expected-cases 179 \
  --output-dir /private/converted-dev
```

The 179-case CP2 scope excludes historical CP1 and sealed test. Conversion
rechecks manifest/file/input hashes, paired IDs, confirmed status, tri-state masks,
development splits and alias-group separation. Only original tool inputs become
features. Output is `development.json`, `development-review.json` and
`conversion.json`; existing output is never overwritten. Run `custodian train`
below using these development files. Import neither trains nor accesses test.
A JSON receipt asserts prior verification without authenticating a reviewer;
the owner-published digest, actual release/use decisions and independent custody
remain required. On Windows, capture the receipt as UTF-8 without a BOM; legacy
PowerShell `>` emits UTF-16 and is unsuitable for the report.

The separate development approval is a bounded JSON object with exactly:

```json
{
  "format": "soup-wall/classifier-development-approval/1",
  "approval_reference": "<actual development labels/license review>",
  "source": "<reviewed development export origin>",
  "license": "<approved dataset license>",
  "dataset_sha256": "<exact development JSON bytes>",
  "split_manifest_sha256": "<reviewed frozen public split manifest identity>",
  "holdout_id": "<custodian's stable identity for the withheld test>"
}
```

Use the same reviewed public manifest digest convention on both sides (for
example its verified canonical `manifest_sha256`, rather than mixing it with the
file-byte digest). The custodian validates the original four-way manifests and
hidden assignments; the CLI's digest assertion cannot establish that review.

```sh
python -m experiments.local_classifier.custodian train \
  --development-dataset /path/to/reviewed-development.json \
  --development-approval /path/to/development-review.json \
  --seed 42 --dimensions 512 --epochs 60 \
  --output-dir target/reviewed-linear
```

The model author passes `model.json`, `training.json`, their model digest, the
development export/review and the pinned source/configuration to the custodian.
The custodian's separate test export uses
`format: "soup-wall/classifier-holdout-dataset/1"`, identical row fields and only
nonempty `holdout` rows. Its approval has exactly the development-approval fields
above, with `format: "soup-wall/classifier-holdout-approval/1"`, its own source,
review reference and test-export `dataset_sha256`, plus
`development_approval_sha256` binding the exact development review file bytes.
`split_manifest_sha256` and `holdout_id` must match the development approval.
These are experimental bookkeeping formats, not implementation contracts between
adapter, classifier, policy and executor.

The existing two-candidate external run authorization and ledger remain supported.
For this path its `dataset_sha256` binds the custodian's reviewed **holdout export**,
while model provenance separately binds the development export/review. The run's
`holdout_id` must match both approvals. Freeze and review the same baseline source
bytes before evaluation, using an exact Git blob when platform newline conversion
could change the recorded digest.

```sh
# Run only by the independent test custodian after model and run review.
python -m experiments.local_classifier.custodian evaluate \
  --development-dataset /custodian/reviewed-development.json \
  --development-approval /custodian/development-review.json \
  --holdout-dataset /custodian/reviewed-test.json \
  --holdout-approval /custodian/test-review.json \
  --model-dir /custodian/frozen-model \
  --baseline-path /custodian/frozen-baseline \
  --run-authorization /custodian/run.json \
  --run-ledger-dir /custodian/shared-run-ledger
```

### One experiment with additional frozen classifiers

Agree all participants before the first held-out prediction. To include SOU-14's
generic classifier alongside the model and the original `900cc3a` baseline, add
`--additional-classifier generic_rule_v1=/custodian/frozen-generic-rule` to the
custodian command. The directory must contain the reviewed `rule_baseline.py`
exporting `classify(input)`. It is trusted experimental code, not tool metadata;
the custodian must review it before loading. This option never replaces the
original baseline. Training rejects additional-classifier arguments without
opening their sources.

For a run with additional participants, the authorization must also contain an
exact ID-to-source-SHA-256 map. For the agreed source after PR #78:

```json
"additional_classifiers": {
  "generic_rule_v1": "d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd"
}
```

This member belongs in the same run authorization object as the existing model,
baseline and dataset digests. Missing, changed or unrequested participants fail
before reservation and prediction. Each source is executed and hashed from the
same captured bytes; preserve exact Git blob bytes on Windows. All participants
share one external ledger reservation and one result receipt. A failed comparison
still consumes the experiment; adding a participant after a completed run cannot
reopen the same holdout. Reports retain `candidate` and `baseline`, plus
`additional_classifiers` and `additional_classifier_sha256` keyed by agreed ID.
No intermediate test results or test-based tuning are allowed.

Every participant receives only a deep copy of the original input and uses the
same evaluator and gold masks. In each label's metrics, `eligible_*` counts the
full annotated population, while `known`, `positive` and `negative` count only
valid predictions. FN/FP rates use scored positive/negative denominators;
technical failures are reported separately and do not become semantic errors.
Null targets remain masked, never inferred negatives. Unknown metrics include
both population and scored positive/negative counts.

`missed_when_unknown_false` records each omitted known-positive action where the
prediction did not abstain. `critical_known_action_misses` counts calls missing
at least one known-positive write/delete/send_data/change_permissions action
with predicted unknown false, divided by scored calls containing a known risky
action. Its eligible and scored counts expose failures excluded from that rate.
This is classification risk, not an observed policy allow or execution bypass.
`mixed_positive_retention` includes cases with at least two proven positive
actions even if other targets are null, and measures whether all proven actions
survive. Existing `mixed_cases` and exact-match fields still require full labels.

`coverage` retains its valid-output denominator; `coverage_total` divides valid
non-abstaining predictions by all calls, exposing technical failures. Abstentions
and `abstention_rate` concern valid outputs. Each candidate is called once per
case, with p50/p95 latency measured in that same experiment, including failed
calls. Independent latency work must use development fixtures, not reopen test.

Before first prediction, evaluation rejects changed model provenance, mismatched
review/manifest/test identities and shared case IDs, families or semantic inputs
across development and holdout. Description-only differences do not bypass the
duplicate check. These exact checks do not detect every near-duplicate template;
family review remains required. The custodian reads reviewed gold for validation
but must not disclose it to the model author before freezing the experiment.

The same external identity is reserved before inference and remains consumed on
failure or after copying model artifacts. Receipt and result hashes are retained.
Report per-label errors/denominators, unknown, coverage, mixed actions, latency,
RAM and all source/data/model hashes; independently review continue/revise/reject.
Files and review references assert provenance without authenticating a reviewer.
The custodian must retain and control the ledger and stable identities. This
preparation establishes no actual SOU-13 training result or held-out quality metric.

```sh
python -m unittest experiments.local_classifier.test_model \
  experiments.local_classifier.test_ledger \
  experiments.local_classifier.test_custodian \
  experiments.local_classifier.test_gold_import -v
```

## Dated evidence and recommendation

[9 October development evidence](evidence/2026-10-09-smoke.json) records an actual
60-epoch CPU training attempt on eight development examples, eight calibration
examples and eight development probes. This is learned training, not mocked
probabilities. It retains source hashes, masked-label counts, external baseline
hash, timings and resource observations; weights and datasets are not published.

**Recommendation: continue with the agreed linear candidate after data review.**
A small local linear run is feasible on this workstation. Developer
results do not support adoption/rejection of an open encoder and do not satisfy
SOU-16's untouched-family evaluation. Keep the issue in progress until code
review, agreed data, actual pilot comparison and continue/revise/reject decision
are reviewed.
