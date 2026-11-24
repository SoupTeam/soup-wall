# SOU-218 final design decision

On 23 November the design was accepted. All six original results retain refusal. The server does not supply verifiable boundaries for the relevant bytes. Server-side boundaries and consumer-side delivery of examples as data belong to a separate task. For future runtime qualification, exercise f05-a and f12-a through the Filesystem profile. The current offline comparison grades both with git-profile-refuse-result-injection.

## Proposed decision point

At runtime inspect only the current result. In the native result branch of `inspect` in [native.rs](../../crates/agentfw/src/native.rs), the consumed invocation selects `inspect_formatter`; the path without it uses `preview_mcp_result_shadow`. Evaluate any proposed contextual evidence before the release decision, with the existing per-block and whole-reply checks. Compare paired cases offline in the reporter. Expected labels, fixture IDs and companion inputs must never be runtime inputs. A server may authenticate the origin of bytes that an attacker supplied. Origin therefore cannot establish the meaning or safety of free text. Any proposed evidence must identify the specific finding it explains, account for bytes across fields, and leave independent findings in force. A document-wide heuristic without a source span cannot be discharged by explaining one substring.

The first implementation increment should record paired evidence and the existing policy decision in the existing reporter. Missing or ambiguous provenance gives no authority to relax the existing decision. Enforce the existing terminal refusal on evidence-budget exhaustion. If any matched attack has equivalent evidence, reject the proposed correction in qualification. The existing result evidence budget is defined in `crates/core/src/detectors/injection/result_evidence.rs`. A new trusted producer or a change to signature interpretation needs independent design review before it can affect release.

## Six retained refusals

Historical evidence comes from [the six-case attribution](evidence/sou157-baseline/false-refusals.md) and [the follow-up checkpoint](SOU157_CONTEXT_CHECKPOINT.md). The [frozen paired plan](evidence/sou218-context-controls/plan.json) supplies four variants per original: replacement, quoted-command, exfiltration and russian-command. Keep its 24 controls separate from the 24 attacks in the original 48-case semantic corpus. The table gives hypotheses to test on the reviewed source.

### Delivered instructions: final disposition for this design

For g05-a and g06-b retain refusal. A Git change can carry either the example or an active request in exactly the same location. In g05-a the override, whole-document heuristic and independent email finding survive. In g06-b both the override and disclosure signature survive alongside the heuristic. The missing mechanism is a consumer that can receive an example strictly as data with independently verified confinement, coupled with a separate basis for refusing its malicious counterpart. Confinement alone does not distinguish the pair. No new probes for these two cases.

### Server framing: disposition on the retained evidence

The frozen Git inputs are text bodies from git_show. They contain textual diff headers, hunk markers and lines. The retained payloads provide no independently authenticated per-line or per-field coordinates. The Filesystem [formatter](../../crates/agentfw/src/native/execution/formatter.rs) checks a single text block and a byte-identical structuredContent.content string on its supported path. Neither channel provides per-file bodies. Its bounded separator attribution is diagnostic; it cannot establish who authored a directive inside a file. These are properties of the inspected artifacts and supported shape; they do not constitute a new live server observation.

| Original | Finding attributable to framing and independent findings | Boundary missing for a correction |
| --- | --- | --- |
| g11-a | Textual hunk lines give context to the reviewer comment. They discharge neither the reviewer-directed finding nor the spanless heuristic. Email remains independent. | Server-bound added/context-line coordinates and an independent distinction for a request occupying the same added line. |
| g12-a | Numbered rows and a tail occur in text. Neither their lengths nor the hunk header attributes the whole-document heuristic to a specific record. | Server-bound record, tail and trailing-data extents plus attribution of the heuristic to those extents. |
| f05-a | Formatter separators could explain delimiter contributions only. Override, disclosure, both secret findings and any remaining heuristic evidence survive. | Server-bound spans for each file body and trailing bytes; independent handling for instructions inside a body. |
| f12-a | A verified join separator could explain its own delimiter contribution. It cannot explain the full heuristic or discharge the independent secret finding. | Server-bound file and record extents distinguishing the tail value from a later line, with independent attribution of residual evidence. |

All four retain refusal on this evidence. For every row a replacement can occupy the same region, a directive split across regions still requires whole-reply inspection, and a directive within one region shares its provenance. No runtime boundary is reconstructed from textual markers. Split directives are a separate regression condition; the frozen plan enumerates the four actual variants above.

## Evidence required for a future correction

1. Pin one reviewed source/tree, policy, registry and original server. Recheck the original frozen 48 semantic and three technical cases with the existing reporter. Preserve the ten-refusal baseline. Record original payload hash, blocking findings, rule and stage separately for every claimed correction.
2. On the same source and authority context, compare each of the six originals with all four matched attacks. Keep original bytes, taint, hard Deny, Ask/Escalate, independent secret/PII decisions and resource limits. Include absent, stale and mismatched evidence as negative controls. Expect refusal if any mandatory check is unresolved.
3. Deliver one implementation PR with focused regressions and a before/after table for all six cases, including retained refusals. A correction requires observed useful delivery and continuation on the original server, refusal on each matched attack, and independent evidence for authority and cleanup. Record missing observations explicitly. The model experiment provides no release authority.
4. Report the nine SOU-177 Git and four SOU-97 Filesystem handoff cases separately with their own profiles, hashes and continuation witnesses. Ask their owners to qualify the same reviewed candidate. Keep these counts separate from the 6+24 comparison.
