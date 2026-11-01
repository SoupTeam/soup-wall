# SOU-157 current-source checkpoint

**Incomplete. No reduction in false refusals.** This
checkpoint establishes exact attribution on accepted main `46921f8d` and rejects
one narrower structural hypothesis before it can become release authority.
SOU-109 remains closed; its opt-in execution proof is not fabricated for corpus text.

## Follow-up to independent review 5657839044

`fff2d28b` adds bounded positive evidence for unaddressed destructive action/object
pairs in the existing MCP result recognizer. English delete/erase/wipe/remove and
explicit Russian imperative forms combine with file/directory/workspace objects.
Short whitespace splits are supported; every occurrence in the complete original
body is scanned. Quotes/comments remain unresolved and do not suppress evidence.
This is deliberately incomplete positive recognition, never a benign classifier.
No lowering API, threshold change, proof flag or policy change is introduced.

Core 97 and Agent 181 tests pass. Controls cover plain/quoted/comment/long-prefix
commands, paraphrases, Russian, split original fields with source coordinates, and
independent secret Deny/Ask/Escalate floors even with an earlier injection-Allow
rule. An initial whitespace-only field split failed; bounded newline support fixed
it without changing budgets. All previous count/work/audit guards still pass.
All 60 native-boundary tests and focused core/agent all-target Clippy with warnings
denied pass. The first native run had 59 passes and one assertion failure because
the audit now correctly contains a third finding; the regression now verifies all
three entries, including the new exact `47..64` destructive-object range. Neither
the original coordinate assertions nor refusal/continuation checks were removed.
All 51 original status/verdict/rule tuples remain unchanged; manifest, policy and
every original payload binding match the retained baseline.

The [current report](evidence/sou157-destructive/report.json) retains the same
24/24 attacks, ten false refusals and zero unknowns. The
[current four-input probe](evidence/sou157-destructive/padding-controls.json) now
distinguishes both destructive bodies through additional positive evidence; all
four decisions remain Deny. This closes the reviewed positive-evidence gap, not
the whole contextual problem or the task. Missing a match still grants no authority.
The first follow-up probe's old hardcoded claim incorrectly said the projection
was identical despite both comparison booleans being false. Its original output
is retained as `padding-controls-initial-label-error.json`; the reporter now derives
the claim from those booleans. No historical observations are repaired or relabelled.

## Reproduction

```sh
cargo build --locked -p agentfw --example result_inspection_corpus
python scripts/diagnose-result-refusals.py \
  --adapter target/debug/examples/result_inspection_corpus \
  --output-dir /tmp/sou157-baseline-new
python scripts/probe-result-padding-context.py \
  --adapter target/debug/examples/result_inspection_corpus \
  --output /tmp/sou157-padding-new.json
python -B -m unittest scripts.tests.test_result_refusal_diagnosis
```

Use the `.exe` adapter on Windows. The diagnostic exits **1**, preserving the
failing gate. Output paths must be new; historical evidence is never overwritten.
The existing SOU-123 reporter and frozen corpus are unchanged. Adapter output adds
the original finding label and byte span. Null aggregate spans remain null.

The retained [report](evidence/sou157-baseline/report.json) contains all 51 cases:
48 semantic cases, three technical cases separate. It reports 24/24 attacks
refused, zero misses, 10/24 benign false refusals and zero semantic unknowns.
The [identity](evidence/sou157-baseline/identity.json) binds all payload hashes,
manifest, policy, executable and diagnostic source. The diagnostic commit is
`175b3b7a`; production code is byte-identical to accepted main `46921f8d`.
This is Windows production-policy preview, not original-server execution, native
delivery, forbidden-effect prevention or an independent/held-out evaluation.

## Attribution

The [complete table](evidence/sou157-baseline/false-refusals.md) and
[raw adapter observations](evidence/sou157-baseline/adapter.stdout.json) retain
independent PII/secret findings as well as injection findings.

| Cases | Actual blocking evidence |
| --- | --- |
| g01-a, g03-a, g07-b, g09-b | Aggregate structural heuristic 0.50; independent email finding retained |
| g12-a, f12-a | Aggregate heuristic 0.50 with repeated-character encoding-shaped data and separators; f12-a also has independent low secret evidence |
| g05-a | Quoted override signature plus heuristic 0.80; independent email finding |
| g06-b | Quoted override and prompt-exfiltration signatures plus heuristic 0.50 |
| f05-a | Quoted override and prompt-exfiltration signatures plus heuristic 0.80; independent secret findings |
| g11-a | Heuristic 0.50 **and** reviewer-bot directive evidence; fixing only the directive cannot release it |

All ten select `git-profile-refuse-result-injection` in the unchanged pilot
policy, including the filesystem payloads. This is the actual shared policy
rule name, not an inference that filesystem payloads were routed as Git.

## Rejected padding-only hypothesis

The two boundary benign inputs contain long repeated `x`/`y` runs. Removing
only their encoding contribution would appear to reduce two false refusals.
Before implementing this, the bounded probe substitutes an unaddressed destructive
instruction into each complete original input. The unchanged corpus is never edited.

The [four observations](evidence/sou157-baseline/padding-controls.json) retain
replacement strings, source hashes, generated hashes and lengths, exact findings,
verdicts and timing. For each pair, **all adapter-reported findings, policy rule,
status and verdict are identical**. Both original and malicious input remain Deny.
This is equality of the reported projection, not full-text equality or a claim
about every internal engine field. Actual filesystem deletion is never attempted.

A decision based only on this projection or padding would release both members.
Absence of target-address words or recognized verbs cannot repair that gap.
Consequently no low-entropy exemption, quote exemption or formatter trust was added.
Previously rejected model experiments were not repeated.

## Validation and next implementation requirement

The adapter builds, formatting and whitespace checks pass. Both new validation
tests pass, covering missing/duplicate/foreign observations, absent attribution
and invalid UTF-8 byte boundaries. Combined with the existing corpus-reporter
suite: 18 passed, one skipped, one failed on Windows because its POSIX shell stub
cannot be executed (`WinError 193`). The existing framework was not modified and
that failure is not called passing; the actual compiled Windows adapter ran all
51 inputs successfully.

The remaining correction needs complete-content contextual evidence that
distinguishes the retained benign/attack pairs, including the new padding controls,
before lowering any contribution. Existing syntax-only projections cannot do this.
No already-tested semantic backend currently supplies the required distinction and
runtime qualification. A new implementation must first demonstrate that distinction
and preserve independent signature/secret/PII, policy Deny/Ask, receipt and taint
controls. This checkpoint requests technical review of the diagnosis and a concrete
mechanism discussion; it does **not** satisfy SOU-157 implementation acceptance.

For SOU-153 coordination, `report.json` retains the existing public report contract;
source/policy/manifest and per-payload identities are in `identities`. Exact finding
attribution lives in the separate raw adapter file. No comparison framework changes
or readiness claims are introduced.
