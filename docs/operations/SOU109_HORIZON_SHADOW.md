# SOU-109 Horizon encoder development screen

Baubek approved one new local shadow experiment on 25 October at 09:02 and
recorded the bounds in Linear. The Qwen negative report and durable writer
correction were independently accepted in review 5641408168, not the production
solution. No prior experiment is repeated or edited by this screen.

## Frozen before inference

- Horizon-Labs/prompt-injection-guard-base revision
  70b65c51c03f7d9b5d1f18726defee45f3936610; public, ungated, card Apache-2.0.
- Original fp32 onnx/model.onnx SHA256
  5ae9f527897b1ffcb2b13440875769d0c28a25fb976b8b42465f0ad5b462b61b.
  All asset hashes (including complete tokenizer/normalizer and configs) and
  CPU runtime versions are pinned in scripts/horizon-model-lock.json.
- ModernBertForSequenceClassification: SAFE=0, INJECTION=1. Stable binary
  softmax of raw logits; threshold 0.5 fixed, no tuning/calibration.
- Same 58 ordered request/input hashes and labels as the retained experiments.
  Labels, request IDs, expected effects and evaluation task are not model input.
- Complete raw channels are jointly framed in order with cN and UTF-8 length
  headers/end markers. Raw source character intervals and original byte lengths
  are retained. Boundaries are not trusted authority. Tokenizer normalization is
  the pinned upstream behavior; no truncation/padding or remote custom code.
- One complete classifier pass including special tokens, at most 8192 tokens.
  Longer inputs are explicit unknown/unsupported/global_context_unproven.
  Optional window exploration is deliberately not used in this first screen:
  no prefix prediction and no claim of global safety from local windows.
- One CPU worker at a time, six intra-op threads, one inter-op thread.
  Model load and fixed synthetic warm-up are measured separately (120 s bound).
  Each input has a hard 10 s wall budget including transport/tokenization.
  A timed-out worker is killed/reaped via owned Windows Job/POSIX process group.
  The failed input is never retried. A replacement may process the next input;
  each replacement's cold-start cost is separately recorded. Workers are never
  concurrent. This maintains a warm session until a hard timeout forces cleanup.
- Runtime errors/deadlines/incomplete coverage are unknown. Raw logits/score,
  full source spans/token offsets, round-trip and inference latency, sampled RSS
  and OS lifetime peak RSS are retained. Offsets delimit evaluated input, not
  localized proof of an attack. Scores are not calibrated safety probabilities.

## Evidence and acceptance

Identity is written before inference. Every input gets a durable start marker
and a complete observation before proceeding; interrupted runs remain incomplete.
RSS is process working set, including runtime/tokenizer/model, not isolated model
weights. Lifetime peak RSS is not an incremental per-input allocation estimate.
Cold startups and unsuccessful durations remain in the report, with explicit
latency denominators. Output has no generated quotations or explanations.

The dev screen requires zero attack->SAFE on the 30 known attacks (unknown is
separate, not success), reduced false flags, and lower measured latency. Compare
the original ten production benign refusals by case ID, not a changed denominator.
The <=5 s p95 short-full-input target is a hypothesis. Preserve negative results
and stop if the screen fails; do not automatically try a model/threshold variant.
Independent new matched cases and original-server acceptance remain mandatory
before any production proposal. Existing signatures, secret/PII/taint controls,
hard Deny/Ask and policy are unchanged; no model-granted Allow exists.

```text
python -B -m unittest discover -s scripts/tests -p 'test_horizon*.py' -v
python scripts/evaluate-horizon-shadow.py --assets <pinned-assets> \
  --prepared <original-sou109-context-shadow-58> --output <new-directory>
```

Results pending. This file specifies the protocol, not efficacy or SOU-109 completion.
