# SOU-150 independent original-result regression

This is retained failure evidence for SOU-109, not a production correction.
PR #256 at `f5e7c759d75ac0c90b141e7b13a33e7720e50c47` independently
ran original Git native acceptance in run `40186301242`. Downloaded artifact
`12595784493` has valid ZIP CRC. Its report SHA256 is
`61a1db20e2d608e71427b68b689d0c281753b1d0fd5b4218eb0ec9c25e45e696`,
matching the author's published digest. Report source before/after is identical.

The unwrapped request id 10 calls `git_show` at `HEAD`. Its exact response line
is retained in `crates/agent/tests/fixtures/result_detector/sou150-original.jsonl`
with line-ending conversion disabled. The single text channel contains the benign
diff for two tracked link objects (`nested/relative-link` and `tracked-link`).
The protected native response is `git-profile-refuse-result-injection`; five
other original reads matched. This does not establish that unwrapped execution
has no effects: the author's separate index-change observation remains intact.

`evidence/sou109-sou150-source.json` records the artifact/run, source, profile,
request/response hashes, native refusal and policy hash. The captured policy
is byte-identical to this branch's unchanged shipped pilot policy. No author
driver was executed or merged, no model was run, and the previous 58-case
evaluation set and labels are unchanged.

An active positive regression expects Allow for the original decoded channel:
`cargo test --locked -p soup-wall-agent --test result_detector sou150_captured`.
Observed on this branch: **0 passed, 1 failed, 0 ignored**, actual Deny versus
expected Allow. This is a detector/policy preview, not another native run or
proof of delivery. Keep the failure visible until a reviewed common correction
passes it together with the retained attack, secret and authority controls.
The independent native failure and our preview agree; neither is called fixed.

Review 5642199318 accepts the previous SDPA diagnostic only. The next production
mechanism still needs a bounded design decision; PR #215 remains Draft and
SOU-109 In Progress. SOU-146 and SOU-150 dependencies remain open.
