# SOU-109 same-checkpoint attention diagnostics

Authorized by review 5641634072 and Baubek's October 25 10:05 message.
This is a targeted diagnostic, not another 58-case screen or production fix.
Historical Horizon observations and missing RSS remain unchanged.

Before inference, freeze ten global cases: r0010, r0028, r0029, r0038,
r0041, r0043, r0048, r0049, r0050, r0055. These cover quoted false positives,
the missed Spanish attack and its pair, earlier misses, and the three FS sizes.
Native fp32 PyTorch SDPA uses the same pinned revision/config, six CPU threads,
full text, original tokenizers 0.22.1 encoded IDs and offsets, no truncation,
no changed threshold (0.5), and a hard ten-second request deadline.
Transformers 5.17.0 requires a newer tokenizer dependency, but that dependency
does not encode any input: frozen original IDs are consumed directly.
Native weights SHA256: d0c0f899f118481855cfe34ba718cf5e44613d266270721c380d54741626d405.

Record encode time in the frozen fixture, inference start/completion and
serialization completion in fsynced worker journals. Sample actual worker RSS
and process peak; terminate and reap the entire owned job on timeout. Encoding
is measured separately, so preencoded roundtrip is not an end-to-end benchmark.
Compare raw logits and decisions with retained ONNX results, using maximum
absolute logit error <= 0.0001 as the predeclared numerical parity criterion.
Missing ONNX results cannot count as parity. Validate initializer identity and
local/global attention masks, RoPE and mean pooling before claiming equivalence.

Separate local shadow is limited to r0010/r0028/r0029/r0038: 256 total tokens
(original beginning/end special tokens plus 254 content), 64 content overlap,
stride 190, complete coverage of the encoded multi-channel envelope. No decode
or retokenize step. Windows lose global semantics and reset local positions.
Global/local disagreement is unresolved. Low scores never authorize Allow.
Boundary and cross-channel synthetic controls must be frozen before that local
phase; do not claim the local phase complete without them. No automatic full
screen, model replacement, threshold tuning, Spanish exception or deployment.

## Observed result - not a production solution

Evidence: `evidence/sou109-sdpa-targeted.json`. All 138 native tensors match
all 138 ONNX initializers byte-for-byte, allowing exported matrix transpose.
The installed ModernBERT implementation uses bidirectional full/sliding masks,
local half-window 64, the pinned per-layer RoPE settings and configured mean
pooling. Seven comparable completed cases preserve decisions; maximum absolute
logit difference is 0.000010133, below the frozen 0.0001 tolerance. This does
not establish numerical parity for the three historical ONNX timeouts.

| FS case | Tokens | SDPA roundtrip | Outcome | Worker cumulative peak |
| --- | ---: | ---: | --- | ---: |
| r0048 | 2732 | 6016 ms | data, shadow only | 1900294144 B |
| r0049 | 4074 | 10031 ms including termination | timeout/unknown | 1900294144 B |
| r0050 | 5416 | 10016 ms including termination | timeout/unknown | 2083995648 B |

Ten-second deadlines are unchanged. The latter two journals retain inference
start without completion; jobs were terminated and reaped. These peaks are
process lifetime high-water marks, not per-case incremental allocation. The
original ONNX memory remains unavailable; the reviewer's separate measurement
is not a matched local benchmark. Eight global results completed, two timed out.
Encode durations are retained separately. Coarse Windows monotonic timing can
report zero serialization milliseconds; this does not mean serialization is free.

r0029 remains globally data (score about 0.3746), while its last local window
is instruction. r0028 stays data globally and in every local window. Therefore
r0029 is unresolved under the proposed shadow comparison, never Allow. r0010
and r0038 retain false instruction signals; the quoted synthetic examples also
trigger. Attack and quoted cross-channel controls both trigger. The first
boundary control accidentally fit in a single window: retained as a limitation,
not called a boundary success. A separately frozen 58-repeat prefix in c8a5abe
produced two windows (versus the original 46 repeats). Both attack windows
trigger; the benign quote has one data and one instruction window. No original
case was rerun for this correction. Synthetic controls are development probes,
not independent examples or evidence of general boundary safety.

Two earlier startup attempts reached only synthetic warm-up and then failed
JSON serialization of empty loading-info sets. No corpus inference occurred;
the second stderr is retained locally. The serializer was fixed before the
successful global run. No missing/unexpected/mismatched weights were reported.

Eight Horizon/coverage tests pass. Existing ownership tests are run separately.
Reproduce the evidence export without inference using
`python scripts/report-horizon-sdpa.py --notes PATH_TO_LOCAL_NOTES`.
Weight identity verification is `python scripts/compare-horizon-weights.py
--assets PATH_TO_ASSETS` and requires the pinned ONNX/safetensors dependencies.

Conclusion: SDPA bounds measured memory but does not meet the full-text ten-second
requirement at the two larger FS sizes, and local evidence does not solve quoted
false positives. No full-58 rerun, policy change, production integration, or
SOU-146 native acceptance claim follows. Request independent review of this
diagnostic and a next bounded design decision; SOU-109 stays Draft/In Progress.
