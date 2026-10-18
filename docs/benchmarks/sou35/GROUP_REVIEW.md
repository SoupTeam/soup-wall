# Importing an approved grouped review

An independent human may review presented family rules once, with exact record
bindings, rather than manually inspect every record. The method must be stated
accurately. The AI's mapping from rules to records remains a proposal until the
human explicitly adopts the exact mapping. This does not authorize a split,
freeze, training, scoring or development export.

`sou35.group_review` bridges that review into the existing v2 gate. It creates a
**new ledger**, preserving the original pending ledger, records and labels. An
unsigned JSON receipt records the claim and external decision reference; hashes
provide integrity, not human authentication. The custodian must verify that
reference against the actual human decision. No flag makes AI review human.

## Prepare privately

Run from `eval/sou35` in a checkout without consumed SOU-13 sealed material:

```sh
python -m sou35.group_review prepare \
  --pool private/pool --records private/records/candidates.jsonl \
  --rulings private/source-ledger.json \
  --review-package private/approved-family-review.zip \
  --review-package-sha256 <verified-package-sha256> \
  --out private/group-review-plan.json
```

The accepted handoff format is `sou35-completed-human-family-review/1`, with an
exact inventory and SHA-pinned `sou35-human-family-rule-decision/1` documents.
Preparation cross-checks every record ID, row digest, family, outcome, original
target and group decision. It rejects stale or incomplete inventories, duplicate
bindings, conflicting evidence dispositions and AI-attributed decisions. It
never marks a record reviewed. Standard output contains only counts and a profile;
the plan itself contains private identifiers and must stay private.

The default profile remains `sou35-strata-v1` under existing SOU-10 semantics.
The separately approved synthetic schema view is available only by explicitly
passing `--profile sou35-synthetic-schema-semantics-v1`. It is recorded in the
plan, authorization, ledger, feasibility report and export manifest. It does not
change D04, grant runtime tool authority or silently relabel a default-profile
evaluation. Never combine scores from these profiles as one experiment.

## One genuine human attestation, then apply

The external human authorization is a private JSON document:

```json
{
  "version": "sou35-group-review-authorization-v1",
  "plan_sha256": "<exact SHA from the reviewed plan>",
  "eligibility_policy": "sou35-strata-v1",
  "review_method": "human_family_rules_with_exact_record_mapping",
  "reviewed_by": "<actual independent human reviewer>",
  "reviewer_kind": "human",
  "reviewed_at": "<actual ISO-8601 decision timestamp>",
  "decision_ref": "<externally verifiable human mapping decision>",
  "independent_of_generation": true,
  "adopt_exact_group_mapping": true
}
```

These are assertions the human must actually make, not defaults. Do not infer
independence from a person's title, different username, or approval of rules.
If the original decision omitted independence or exact mapping adoption, obtain
that specific missing attestation; do not ask for a new manual 160-record review.

```sh
python -m sou35.group_review apply \
  --pool private/pool --records private/records/candidates.jsonl \
  --rulings private/source-ledger.json --plan private/group-review-plan.json \
  --authorization private/group-review-authorization.json \
  --out private/imported-ledger.json
```

Apply refuses missing/false independence, wrong reviewer/profile, a changed plan,
or a changed source ledger. It only transcribes pending entries. Prior accepted,
rejected and disputed adjudications remain unchanged. The resulting entries name
the grouped method and original group decision; they do not claim manual human
inspection of each record. Reload validates the import receipt and refuses
removed/changed method, mapping or authorization metadata. Existing frozen
manifests are invalidated by the new rulings digest and cannot be reused.

Semantic questions remain separate. If an existing pending question has actually
been resolved, the authorization may include `semantic_decisions`, a list of
ordinary v2 question decisions with `question_id`, `status`, `reviewed_by`,
`reviewer_kind`, `reviewed_at` and `decision_ref`. Each requires its own genuine
decision reference. An import never infers DATA-USE or HUMAN-REVIEW approval,
overwrites a prior ruling, or turns internal evaluation permission into training
or export authorization.

## Requirements remain in force

- The full default 13-feature requirements for validation, calibration and test
  are unchanged. A grouped review does not make an infeasible split feasible.
- Mechanical hidden-default ceilings still lower human evidence claims.
  Program-only/information-limited evidence stays outside primary scoring.
- Disputed full-unknown exclusions, known partial-unknown actions, technical-error
  separation and private closed-test bans remain in force.
- The existing custody commit/draw, frozen manifest, original generation
  provenance, export authorization and private-output checks remain mandatory.
- Output files are new private files (0600); no existing ledger/report is replaced.
  No custody material is opened by this import.

After import, the custodian reruns strict feasibility with the accepted profile
and verified closed-test restrictions. Only after it passes may a separately
authorized custody/draw/freeze proceed. A potential upper bound is not acceptance.
