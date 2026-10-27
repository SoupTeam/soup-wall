# SOU-157: authorized single NLI shadow screen

Baubek authorized one public-only ModernBERT screen on 27 October 2026 at
18:07 (Telegram message 1642, confirmed in Linear). This is diagnostic evidence,
with no production policy authority. The additive detector in PR #280 remains
unchanged. A negative entailment score is not evidence of benignness.

## Frozen protocol

`evidence/sou157-nli/protocol.json` freezes 65 ordered cases, complete channel
bytes, hashes, expected labels and three hypotheses before inference. It includes
the original 51 SOU-123 cases, 12 supplemental controls and two existing destructive
padding counterexamples. Expected labels are only for subsequent scoring and are
never passed to the model. Technical and non-English inputs are Unknown without
inference. Full input plus hypothesis and special tokens must fit 8192 tokens;
there is no truncation, windowing or chunk rescue.

Model: `MoritzLaurer/ModernBERT-large-zeroshot-v2.0`, revision
`a51e07b524299e309dd2b88d48b0cfa2bd9ec598`, Apache-2.0. Asset SHA-256 hashes,
tokenizer, label mapping and dependency versions are locked in
`scripts/sou157-nli-lock.json` and `scripts/sou157-nli-runtime.json`.
The runner additionally checks the entire protocol hash before starting.

CPU float32, SDPA, batch size 1, at most four threads. A Windows Job Object
limits the entire worker process tree to 8 GiB committed memory and kills its
descendants on close. Startup is limited to 120 seconds. There is no warmup.
Each case has one total 10-second deadline including transport, tokenization and
all three sequential hypotheses. The first timeout or worker failure stops the
run; remaining cases are explicitly not run, not classified as successes.
The exclusive run claim prevents replay under a different output directory.

Action entailment >=0.9 with both benign hypotheses <=0.1 yields `instruction`.
Action <=0.1 and at least one affirmative benign hypothesis >=0.9 yields
`benign_evidence`. Other outcomes are Unknown. These diagnostic categories do
not bypass production findings or authorize a production allow decision.

## Evidence requirements

Retain identity, raw logits and scores, token counts, stage journals, errors,
elapsed times and process-tree peak committed memory (not RSS). Distinguish
cold startup from subsequent cases. Report all 65 cases, separating original
48 semantic cases, three technical cases and 14 supplements, including skipped,
Unknown and unattempted rows. No substitutions, retries, paid calls or training.

Preflight unit tests exercise conservative score decisions, complete original
input preservation and actual Windows Job memory/timeout/descendant cleanup.
They do not load the model or consume the authorized inference run.

## Observed outcome and disposition

The one run completed at frozen commit `4dcae71123b7d19c6e979b68dbea2be3903f2e29`.
See [all 65 cases](evidence/sou157-nli/results.md) and raw journals beside it.
There were 42 submitted cases, no timeout/OOM/worker failure, 181.282 seconds
total, 23.719 seconds cold startup, and 2,687,791,104 bytes (2.503 GiB) peak
committed worker-tree memory. First-case latency was 3.250 seconds; the following
41 submitted cases had median 3.500 and maximum 9.765 seconds. Cleanup verified
zero surviving owned processes.

All 48 original semantic cases are Unknown: 24 ambiguous full-text scores,
20 unsupported-language cases and four over-context cases. The three technical
inputs remain separate Unknown. Of 14 supplements, three benign discussions
produce affirmative benign evidence, nine attacks and two benign cases remain
Unknown (including both over-context destructive padding controls). Thus the
whole set is 3 benign-evidence / 62 Unknown / 0 instruction. This is not attack
recall, a safe Allow result, or a reduction of production false refusals.

The tokenizer emitted one retained maximum-length warning referencing its own
512-token metadata for a 56,662-token input. The pinned model configuration has
8192 positions; every complete pair was independently counted against 8192 before
forward execution. Those oversized inputs were not forwarded. No inference error
or silent truncation occurred. Full stderr remains in the evidence directory.

Reject this declared candidate as a solution under the agreed bounds. Do not
retune thresholds/hypotheses on these observations, replay the run or substitute
another model without separate authorization. Production remains at the retained
24/24 attack refusals, ten benign false refusals and zero semantic unknowns;
the 62 shadow Unknown results do not replace those production outcomes.

The next review question is a bounded non-model direction: whether shared
daemon-owned formatter attribution can distinguish verified filesystem separators
(B16-B19) from identical attacker-controlled bytes, using the existing verified
runtime identity. Any proposal must retain full-body content scanning, matched
malicious controls, unauthenticated baseline behavior and independent policy floors;
text appearance or the NLI result cannot supply provenance. This is a design
question, not an implemented witness or a fresh SOU-97 runtime qualification.
Quoted-signature and other unresolved cases remain blocked. SOU-157 stays
In Progress and PR #280 stays Draft pending independent review and an actual
production correction; the negative experiment does not satisfy acceptance.
