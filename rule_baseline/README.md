# Rule-based classifier baseline

This module supplies the owner-maintained Task 1 diagnostic classifier. It
accepts tool metadata and actual arguments and returns multi-action labels plus
an independent `unknown` flag. It never executes tools or issues Allow/Ask/Deny.
Names, argument keys and limited shell patterns are heuristics, not proof of
an unfamiliar tool's complete behavior. Scores are not calibrated probabilities.

From the repository root, with Python 3.10+:

```sh
python3 -m unittest discover -s rule_baseline -p 'test_*.py' -v
python3 eval/eval_runner.py eval/fixtures/soup_task1_evaluation_cases_v0.4.json \
  eval/fixtures/soup_task1_challenge_cases_v0.1.json \
  --classifier-path rule_baseline --out-dir /tmp/soup-wall-classifier-evaluation
```

On Windows use `python` and a local output directory. Input commands are treated
as data. The second command currently exits 1: the frozen core/challenge sets
produce 49/55 scored matches, six classification mismatches and zero scored
technical errors; three pending cases remain unscored. These synthetic fixtures
are diagnostic regressions, not held-out accuracy or production security evidence.
The historical labels are not changed to make the classifier pass. CI runs every unit
regression in this directory and the frozen core regression suite explicitly. Challenge
mismatches remain recorded for review instead of being presented as passed cases.

## Reply envelope (SOU-14, interface step)

The semantic core is `actions` plus the independent Boolean `unknown`. Additional fields are
descriptive and bounded: `evidence` (at most eight `{action, source, weight, detail}` rows that never
echo argument values), `definition_estimate` (what the tool name and schema alone suggest, kept distinct
from the invocation result) with `definition_invocation_diff`, flags, and `failure`. A technical failure
is `status="error"` with `failure.code` of `classifier_invalid` or `classifier_internal_error`;
`classifier_timeout` is raised by the daemon. It is never a valid unknown classification. The file stays a
single stdlib-only source because the daemon executes one verified snapshot; it never imports siblings.
Replies are bounded to 12 KiB. UTF-8 JSON input is bounded to 1 MiB excluding the newline;
invalid UTF-8 is a technical failure. An oversized or malformed frame is refused and the next
frame can still be processed.

## Generalization to unfamiliar tools (SOU-14, step 2)

Rules for tools without a per-name rule read whole tokens of argument keys (`invite_email` is a
recipient, `group_by` is not a permission), the action words of the tool name, and the declared schema:

- A recipient key plus a different content key is `send_data`; a local path sent to a URL or recipient
  with no inline content is also `read`; a `source`/`src` argument is `read`.
- `share`, `invite`, access nouns (`sharing`, `visibility`, `member`) and `principal`/`role` arguments are
  `change_permissions`; removing a member is an access change, not a delete. A delete verb is turned into
  an access change only when its own object is the access noun (`remove_user_access`); in
  `delete_file_and_grant_access` the delete is kept next to `change_permissions`, and a `delete: true`
  flag counts as a delete. The object of a verb is read clause by clause: in `delete_file_and_remove_member`
  each clause keeps its own effect, and a clause that names both an access noun and a data noun
  (`delete_member_file`) is ambiguous, so it keeps the delete, adds the access change and is `unknown`.
- Partial knowledge is `unknown` with the proven actions kept: a category guessed from a noun alone and not
  supported by the arguments, a compound name (`a_and_b`) with an unrecognised part, an argument that names
  code to run (`plugin`, `callback`, `*processor`), and arguments that violate the declared schema
  (`args_schema_violation`, checked against `pinned_schema` first).
- A tool named only `run` or `call` is a generic runner: what it runs is not in its arguments, so a
  guess from `mode` or similar values stays `unknown` unless a shell command is visible. Workflow-style
  names are different, their `steps` are read one by one. The same holds for a runner clause in a compound
  name (`read_and_run` keeps `read` and is `unknown`); a visible shell command or parsed steps resolve it.
- Not claimed: a tool that only receives text is not proven to have no effect (`text_stats` stays unknown),
  and `dry_run=true` is reported as `dry_run_declared` while the write is still reported.

An unfamiliar name such as `quartz_17` is classified from its arguments, not refused. These rules are
heuristics; the measured effect, including errors, abstentions and the data they were developed on, is
reported with the evaluation and not claimed here.

## Evaluation, pinned versions and handoff (SOU-14, step 3)

`evaluate_dev.py` measures a classifier on the SOU-13 development exports and writes `evaluation.json`
and `EVALUATION.md`. The committed result is [EVALUATION_SOU14.md](EVALUATION_SOU14.md).

```
python rule_baseline/evaluate_dev.py --exports <sou13 package>/exports --classifier rule_baseline/rule_baseline.py \
    --baseline <old rule_baseline.py> --baseline-label 900cc3a --out-dir out/
```

It reports, with the denominators shown in the report: exact match per split, per-label precision and
recall, critical misses (an expected risky label missing while `unknown=false`), mixed-action quality,
abstentions and coverage, technical failures, and batch-size-1 latency in process, with a warm process and
with a new `python -I -u` process per call. Two reference rows (always abstain, always no-effect) show what
a blanket answer scores, so a refusal is not mistaken for generalization. Only these measured candidates
are compared: the baseline at `900cc3a` and this file. `test_evaluate_dev.py` checks the arithmetic on a
few synthetic cases and does not need the SOU-13 package.

What the numbers are not: the splits were visible while the rules were written, the labels are
`provisional`, and the closed test is held by its custodian. They are development numbers.

**Pinned revision.** The classifier is one stdlib-only file with no configuration file. Its behaviour is
fixed by the file and its constants (`THRESHOLD = 0.5` decides which actions are reported; `MAX_*` bound
input and reply sizes; `INTERFACE = "sw-classifier-core/0.4"`). To pin it for Task 7 or the daemon, record
the git commit of `main` that contains it and the `sha256` of `rule_baseline.py`; the report prints the
hash of the measured file (the file as committed, with LF line ends; on a Windows checkout with CRLF use
`git show HEAD:rule_baseline/rule_baseline.py` to get the same bytes). After any change to the file or a constant, run the evaluation again.

**Handoff to SOU-15.** The reply keeps `actions`, `unknown`, `confidence`, `uncertainty`, `reason`, plus
`evidence`, `definition_estimate`, `definition_invocation_diff` and `failure`. Five shapes now reach the
bridge and `map_classification` still accepts only the first one:

| Reply | Meaning |
|---|---|
| one action, `unknown=false` | a known single action |
| two or more actions | mixed call; keep every action |
| actions plus `unknown=true` | partial knowledge: the listed actions are proven, more may exist |
| no actions, `unknown=true` | nothing matched; the policy side must ask or deny |
| no actions, `unknown=false` | every command is a proven no-op (D07) |

A technical failure is `status="error"` with `failure.code` one of `classifier_invalid`,
`classifier_timeout`, `classifier_internal_error`; the policy is not reached.

## Interface and remaining integration work

`classify(input)` is the local Python interface consumed by the
[shared evaluation runner](../eval/README.md). The result currently includes the
local `status` convention and diagnostic fields. Invalid input is represented by
`status="error"`; evaluation records it as a technical error, never a successful
unknown classification. The runtime adapter must use the agreed failure channel,
validate pinned schemas and preserve every policy restriction before this source
is connected to admission. The module alone does not implement that integration.

An explicit no-op is valid for the shared runner, but the baseline still uses
unknown when no rule matches. Shell support is a bounded heuristic scanner;
unsupported syntax and uncertain tool semantics need further review. This source
is an independent preparation increment for SOU-5/SOU-14, not acceptance of the
complete contract or a production enforcement path.
