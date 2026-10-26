# Run evidence and limits

Final code evaluated: d18da37aaace7a73b4e8488fd3280d26d27185dc, atop
7bbe9a5e1fed3e0555b6dc0782486fe5beb7aa66. Subsequent evidence/documentation-only commits
store these files and the handoff; they do not change the evaluated code.

`baseline-only-*` is the final frozen replay: 9 cases, 7 evaluated, 3/3 attacks
refused, 0/4 supported benign cases released; PMF201/256 remain unsupported.
The false refusals PMF50/200, git_show and git_diff remain unresolved.
Evidence capacity is the existing daemon DEFAULT_TAINT_CAP (10,000).
No model calls and no live runtime qualification. SOU-109 remains open.

`historical-pre-gate-*` preserves the earlier ac32bec2e2be85413f9529334d422d7ca1550f43
run, which used a 1,024-entry test fixture capacity. It released PMF50, but did
not authenticate runtime origin. PMF200 reached the independent evidence-capacity
refusal. Do not treat these as verified filesystem utility improvements.

`historical-origin-control-failed.log` preserves the negative control that failed
against the pre-gate implementation: plausible output, correct static profile and
current receipt did not prove which executable ran. The final native test log
shows this control passing after relief was disconnected.

Final checks: native 64 passed/1 replay ignored, parser 5 passed,
agent 170 passed, core 96 passed. All use --no-default-features.
The explicit ignored replay was then run once by the checked-in wrapper.
The original nine inputs, labels, fixed policies/signatures/classifier were not
changed after observing results. Git calls remain component-only reconstructions.
The external execution/IPC acceptance contract is in result-format-evidence.md;
this slice does not implement or authorize a competing launch service.

Handoff ownership: SOU-155 @Nari_Ab (after SOU-142) owns Linux verified launch /
runtime-Call-result IPC binding. SOU-156 @konung3 owns the Git resolved-object-kind /
sealed-view witness. Assigned contract: October 27, 12:00; delivery: October 28,
12:00. Neither implementation is part of this Draft. All production paths remain
baseline-only until independent acceptance, including commit-shaped Git blobs.
The operation document lists each removed/isolated relief hook explicitly.
