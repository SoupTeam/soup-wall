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

## Original capture received and verified (12:09 handoff)

The author supplied `multi-read-2-3-4-original-bytes.tar.gz` in the work DM.
Archive SHA256: `1807ab5bf23d9c1ca4b8f7a0b32b5b8140d22d27bc0126e0888f6da654910b79`.
All 18 manifest/input/output/configuration/workspace files matched `SHA256SUMS`.
They are retained byte-for-byte under
`crates/agent/tests/fixtures/result_detector/sou113-original/`, with Git text
conversion disabled. The manifest hash is
`75e27713be0871c697913965fe3361e4abfe4bf24628172f47cd70490bc4dcf5`.

Run `python -B scripts/verify-sou113-capture.py` to check file hashes, original
request IDs/paths, both content channels, call/result binding and the reported
daemon inspected-content hash against original server bytes. For 2/3 files the
host response equals the server bytes; the four-file host response contains the
exact withheld-result envelope without the payload. This verifies capture
consistency, not an independent rerun of the author's server or syscall witness.
The archive's binary/tool identities are reported metadata, not binaries verified
locally by this intake. No code from the archive was executed.

| Files | Raw response bytes | Decoded text bytes (each channel) | Captured verdict |
| --- | --- | --- | --- |
| 2 | 8514 | 4151 | Allow |
| 3 | 12722 | 6229 | Allow |
| 4 | 16930 | 8307 | Deny |

The four-file **frame** is above 16 KiB, but each inspected **text** is below it.
The recorded refusal is `filesystem-profile-refuse-result-injection`, not a text
budget refusal. Do not describe the entire wire response as below 16 KiB.

Source identity in the supplied manifest is PR head
`44a586a905bbdbc2ddd85ca95df46f63e5354cda`, tree
`cb3b2ea3750dc3bc19c46375abe8a6734e4b6226`. The author separately identifies
implementation tree `0d3eacc7d6eb7cc4ea23e7174ed47ad25f33cc63`; these identities
are retained as reported, not conflated. Profile hash
`2fef9cd998b8dddf2a18a37aca2df8579daadd495e77ca08059c43dee3eb1619` differs
from the earlier evidence because its workspace path differs. Registry and policy
hashes are checked from included bytes; the policy also equals our shipped v1 bytes.

The positive Rust test now reads both channels from the captured responses instead
of reconstructing the benign text. All six channels are checked: only both
four-file channels fail the unchanged Allow expectation. Focused run remains
**1 PASS / 1 FAIL**, no ignored tests. The attack helper remains explicitly a
synthetic variation. This is still a policy-preview reproduction, not host/daemon
execution qualification. The original benign Git expectation remains unchanged.

## Remaining work

Exact captures are now retained; they remain distinct from the independent paired
development examples assigned to @sake_ai in SOU-123. Continue review of
[the bounded next-step proposal](RESULT_DETECTOR_NEXT_SCOPE.md), retaining the
unresolved original Git and small filesystem positives. No Ready/Done claim.
