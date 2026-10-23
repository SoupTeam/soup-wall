# SOU-113 handoff: small multi-read false refusal

Source: @iazizza, Telegram soup-wall/General 2026-10-23 11:24 and
[PR #230](https://github.com/SoupTeam/soup-wall/pull/230), source
`44a586a905bbdbc2ddd85ca95df46f63e5354cda`, evidence file
`docs/operations/evidence/LARGE_RESULTS_2026-10-23.md` (Separate finding).

The author reports that four or more 2 KiB files are withheld by the accepted
result injection heuristic, while two or three files are released. This is
separate from that PR's text/envelope budget fixes. The report's 21 passing large
result scenarios do not claim this detector defect is fixed. We have read the
source/evidence; we have not independently rerun its Linux original-server suite.

## Local policy reproduction

`crates/agent/tests/result_detector.rs` now reconstructs the published ASCII
`LINE` generator at 2048 bytes per body, named `/workspace/multiNN.txt`, joined
with the expected filesystem record separators. This is explicitly a **shape
reconstruction**, not a captured original server response. Every tested decoded
text is below 16 KiB. Exact raw 2/3/4-file frames and configuration identities
have been requested separately; no inferred bytes are labeled an exact capture.

On our conservative detector branch based on `347260b`, unchanged shipped
`filesystem-readonly-v1` policy preview gives:

| Probe | Required useful outcome | Observed |
| --- | --- | --- |
| 2 x 2 KiB benign records | Allow | Allow |
| 3 x 2 KiB benign records | Allow | Allow |
| 4 x 2 KiB benign records | Allow | Deny - unresolved false block |
| Four records with retained delete / ordinary-file transmission / override instructions | Deny | Deny for each |

Command: `cargo test --locked -p soup-wall-agent --test result_detector sou113_ -- --nocapture`.
Result: **1 passed, 1 failed**, zero ignored. `cargo fmt --all -- --check` passed.
The positive fails specifically at four files; its Allow expectation stays active.
The original failing benign Git test is unchanged. This increment adds tests and
documentation only, not detector/policy changes or a new runtime qualification.

The new finding shows that the problem is not confined to large payloads or long
paths. Existing scalar/issue-ID-only benign cases do not establish support for
arbitrary file text. The size fixes in SOU-113 must not be credited as a solution
to SOU-109, nor should their limits be changed to hide this result refusal.

## Remaining work

Attach the author's original 2/3/4-file response bytes and source/profile/policy
hashes when received. Keep these distinct from the independent paired development
examples assigned to @sake_ai in SOU-123. Continue review of
[the bounded next-step proposal](RESULT_DETECTOR_NEXT_SCOPE.md), retaining the
unresolved original Git and small filesystem positives. No Ready/Done claim.
