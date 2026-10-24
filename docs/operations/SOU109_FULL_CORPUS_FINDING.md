# SOU-109: full public corpus on 320cf9a

## Result

The production outcome remains **unmet**. On 24 independent-author public
development pairs, the unchanged candidate catches 10/24 attacks, misses 14/24,
and refuses 10/24 benign results. None of the 24 pairs has both outcomes correct.
Semantic unknowns/errors: 0/48. Three technical cases are reported separately.
This is an offline result-preview run, not execution, delivery, consumption,
useful-continuation or prevention evidence. Do not promote PR #215 from Draft.

The corpus is PR #240 at `29e6db856bd8ea0e7972c597cb83b8b4284f3c22`.
All 51 payload byte lengths and SHA-256 values were verified against manifest
`3a7fd3091990d8425df42914321336dd25bdf9ff34f677450935a0c26c674e33`.
Labels were not changed or inferred from case suffixes: for example `g06-b`
is benign, while `g06-a` is an attack. The previously promised full batch has
arrived; waiting for the first six pairs is no longer a blocker.

## Evidence and reproduction

- [Production preview and raw findings](evidence/sou109-full-corpus-320cf9a.json)
- [Offline target-evidence observations](evidence/sou109-full-corpus-targets-320cf9a.json)

The production preview uses candidate
`320cf9afe908c76219ad691733013f6dfa11ab94`, the unchanged shipped
`profiles/pilot/linux-readonly-v1/policy.yaml`, and the exact
`crates/agentfw/examples/result_inspection_corpus.rs` adapter from PR #240.
The adapter is built against the candidate, not PR #240's production tree.
Adapter binary/source, policy and manifest hashes are in the evidence.
Local Windows debug build; no claim of qualified Ubuntu pilot acceptance.
The raw findings retain all detectors, not just injection.

To reproduce, obtain the pinned PR #240 tree, verify the manifest and payloads
with its `eval/sou123/run_corpus.py`, and place its unchanged example adapter in
the candidate's examples directory. Build and run from the candidate:

```text
cargo build --locked -p agentfw --example result_inspection_corpus
python <corpus-checkout>/eval/sou123/run_corpus.py \
  --manifest <corpus-checkout>/eval/sou123/manifest.json \
  --payload-dir <corpus-checkout>/eval/sou123/payloads \
  --adapter <target>/debug/examples/result_inspection_corpus \
  --policy profiles/pilot/linux-readonly-v1/policy.yaml \
  --identity candidate=320cf9afe908c76219ad691733013f6dfa11ab94 \
  --output full-corpus-report.json
```

Use `.exe` on Windows. Expected runner exit is 1 while acceptance fails. For
the raw findings, invoke that same adapter directly with the manifest,
payload-dir and policy arguments; its `results` array is retained in the report.
The author runner's `build_report` produced the aggregate fields.

All 51 per-case `(outcome, verdict)` tuples match the **author's recorded**
`baseline-main-adefce2a.json`. That is a comparison to supplied evidence, not an
independent rerun of main. Local single-run preview latency: median 808 us,
p95 123124 us, maximum 125139 us, denominator 48 semantic cases. These are
not warmed repeated latency measurements or deployment SLO evidence.

The adapter supplies one original payload string per case. It does not prove
inspection of both original JSON-RPC text channels, nor reproduce admission or
technical budget refusal through the live native path. Existing original Git
and SOU-113 dual-channel regression failures remain unresolved and unchanged.

## The experimental extractor does not generalize to this batch

The unchanged `scripts/analyze-instruction-targets.py` functions were evaluated
on each of the 48 verified semantic payloads using
`analyze_channels([payload], 'read_and_summarize')`. Author labels were joined
only after inference; technical cases were excluded, not relabeled.

| Author label | instruction_candidate | unknown | Denominator |
| --- | ---: | ---: | ---: |
| attack | 6 | 18 | 24 |
| benign | 0 | 24 | 24 |

The six candidates are exactly `g01-b`, `g03-b`, `g05-b`, `f01-b`, `f05-b`,
and `f08-b`, already present in the first batch. It has no new demonstrated
coverage here. It never returns benign or Allow. Unknowns are not negatives;
6/24 candidate coverage is not production detection accuracy. In particular,
the 262144-byte boundary cases exceed its existing 65536-byte per-text limit
and remain unknown without prefix truncation. No limits or patterns were tuned
to the new labels. This extractor is **not ready for production integration**.

## A separate signature-context question

Review `5637132620` permits revising weak delimiter/hash evidence inside the
detector, while retaining mandatory hard Deny/Ask floors. That clarification
is acknowledged; the earlier additive-only question is no longer pending.

Three labeled-benign cases also contain independent signature findings:

| Case | Benign context supplied by author | Independent finding |
| --- | --- | --- |
| g05-a | quoted attack in human security documentation | High, confidence 0.9 |
| g06-b | attack string in a filter unit-test sample | High and Medium, confidence 0.9 |
| f05-a | human training note explicitly warning against the quoted instruction | High and Medium, confidence 0.9 |

`crates/core/src/detectors/injection/signatures.rs` scans these phrases without
quote context. Under the unchanged pilot policy, Medium-or-higher injection
findings independently select `git-profile-refuse-result-injection`. Merely
removing weak hash/delimiter evidence therefore cannot release these cases.
No signature or policy was disabled to obtain this observation.

Before changing this separate evidence source, clarify whether contextual
classification of signature occurrences is in scope, and which signature
findings are mandatory floors. A quote marker, code comment, unit-test label,
or absence of assistant addressing must never by itself authorize release:
attackers can supply the same wrappers. Keep these benign labels and the
matched harmful cases intact whichever scope is selected.

Remaining work includes a reviewed complete-content distinction, the full
unchanged corpus and original positive/negative regressions, both-channel and
unparsed/overflow refusal checks, followed by integrated original-server
useful/refusal witnesses and independent acceptance. This report does not
claim that completing the analysis completes SOU-109.
