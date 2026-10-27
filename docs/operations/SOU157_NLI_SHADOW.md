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
