# Offline instruction-target evidence after review 5631657038

`scripts/analyze-instruction-targets.py` implements the next bounded development
step, outside production. It observes explicit assistant/AI-agent addressing
near execution or disclosure requests and records original UTF-8 evidence spans,
the candidate target, requested effect and redirection beyond the evaluator's
trusted read-and-summarize task kind. Tool text cannot set that task kind.

This is a small English pattern-based **candidate extractor**, not a general
semantic classifier. Its finite patterns are not grounds for treating unmatched
text as safe. No model, external service, protected-path dependency, parser
shortcut, changed policy or release authorization is introduced.

## Contract and limits

- Output is `instruction_candidate` or `unknown`, never benign/Allow. Missing
  target/effect evidence, invalid input, unsupported task kind and limits abstain.
- `analyze_channels` inspects all supplied original text channels separately;
  duplicate content is not discarded and a harmful secondary channel is retained.
  The existing batch contains one exact-text observation per case, not both raw
  MCP response fields; do not claim that this report tests original dual delivery.
- 64 KiB per text, 16 channels, 256 KiB decoded total, 384-character target/effect
  window and 32-evidence bound. Whole text is scanned for targets; a harmless
  prefix cannot suppress a tail. Limit reports remain unknown.
- Corpus labels and `forbidden_effect` annotations enter reporting only, never
  extraction. Unknown is not a negative training label or permission.
- Quotation/claims of human context cannot suppress evidence. A quoted addressed
  attack can therefore false-trigger; that limitation has an explicit test.
- Candidate evidence may only support a future additional restriction. It must
  never remove an existing Deny/Ask, secrets/PII, identity or resource finding.
  No candidate-to-policy composition is implemented in this offline increment.

## Reproduction and first-batch result

```
python -m unittest discover -s scripts/tests -p test_instruction_targets.py -v
python scripts/analyze-instruction-targets.py crates/agent/tests/fixtures/result_detector/sou123-first-batch.json
```

Six test groups pass: no safe output on missing evidence, secondary-channel/tail
coverage, UTF-8 offsets/split target, limits/unsupported contexts, label isolation
and quoted-attack non-bypass. Evidence with corpus/script hashes is retained in
`evidence/sou109-instruction-target-first-batch.json`.

| Author label | instruction_candidate | unknown |
| --- | ---: | ---: |
| benign | 0 | 6 |
| harmful instruction | 6 | 0 |

This is development on the already-read first batch, not independent validation,
not a claim of general accuracy and not a production confusion matrix. In
particular, six benign abstentions do **not** fix four production false blocks.
The detector/policy preview still has the previously recorded four benign Denys
and two harmful Allows. Those active failing tests/labels remain unchanged.

Full 24-pair evaluation, further paraphrases/languages, the original Git/four-file
positives, all existing attack refusals, unknown/error handling at the real
boundary and independent original delivery/useful-continuation evidence remain
required. Remaining SOU-123 pairs were promised for October 24, 12:00. Keep
#215 Draft and SOU-109 In Progress. Do not declare the requested fix complete.

## Handoff integrity validation

Before analysis the runner now verifies UTF-8 SHA256 for every case, unique case
IDs, exactly two members per pair, matching paired family/task/effect context,
supported author labels and bounded batch size (1..24 pairs, 256 KiB decoded).
Malformed, partial or corrupted pairs fail the run before producing observations.
An explicit author `unknown` remains unknown in reporting and never becomes a
negative label. Author labels/effect descriptions still do not enter extraction.

Eight test groups pass, including tampered bytes/hash/context, duplicate IDs,
incomplete pairs, label changes and explicit unknown preservation. The new report
`evidence/sou109-instruction-target-verified-batch.json` retains script/corpus
hashes and explicitly records `verified_pairs=6`, `full_24_pairs_present=false`.
The prior report remains historical evidence tied to its original script hash.
Results remain six harmful candidates and six benign abstentions. This prepares
the remaining handoff; it neither supplies the missing pairs nor fixes the
production false blocks/misses.
