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
