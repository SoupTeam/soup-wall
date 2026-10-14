# generic_rule_v2 (SOU-34)

A separately identified revision of the generic classifier. The frozen candidate
`rule_baseline/rule_baseline.py` (sha256 `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd`)
is byte-identical and keeps the SOU-14 held-out result. **This revision has no held-out result. It is not
enabled in production admission and no generalization claim is made.**

- File: `rule_baseline/rev2/rule_baseline.py`, sha256 `d0b4fc02720ee5ff38dec73d5992c6bdee9eda8595282e33015e60d07ce33ea5`
- `REVISION = "generic_rule_v2"`, `INTERFACE = "sw-classifier-core/0.4"`, `THRESHOLD = 0.5`, `TIME_BUDGET_S = 1.0`
- Select it explicitly: `python3 eval/eval_runner.py <fixtures> --classifier-path rule_baseline/rev2 --out-dir <out>`
- Regressions: `rule_baseline/test_rev2.py`. Report: `eval/evidence/sou34/README.md`.

What changed against the frozen candidate

1. D06: arguments that are not an object under a declared object schema (E01 null, E02 array) return
   `status=error`, `failure.code=classifier_invalid`. A per-call time budget gives `classifier_timeout`, an
   unexpected exception or a malformed own reply gives `classifier_internal_error`. None of them is
   reported as `actions=[]`, `unknown=true`.
2. D07: a proven no-op (`actions=[]`, `unknown=false`) only for a pure-computation definition: a narrow
   reviewed name vocabulary (checksum, hash, validate, ...), a data-only object schema, arguments inside it,
   no effect-bearing keys, no injection-like description, no compound with an unresolved part.
3. Mixed actions: vocabulary for assign/reassign/unassign (write, plus access change through the
   argument roles), offboard/deprovision/onboard/provision (access change, offboard also delete),
   ack/acknowledge/nack/dequeue (delete). A name without a recognised verb whose only evidence is a
   role-like argument key stays partial `unknown=true`.
