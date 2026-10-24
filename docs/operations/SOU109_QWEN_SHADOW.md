# SOU-109: agreed Qwen shadow experiment

Baubek selected local Qwen3.5-9B Q4_K_M via llama.cpp in Telegram on
24 October at 15:19 and reiterated the assignment at 15:39. This resolves
the backend selection request in #215. No paid API or production change.
Independent review 5637914731 confirms the preceding native scope correction
at 3daf4eb with 56 native tests passing. The ten benign refusals remain.

## Frozen candidate and protocol

- Model: `unsloth/Qwen3.5-9B-GGUF`, revision
  `3885219b6810b007914f3a7950a8d1b469d598a5`, file
  `Qwen3.5-9B-Q4_K_M.gguf`, 5,680,522,464 bytes.
  SHA-256 `03b74727a860a56338e042c4420bb3f04b2fec5734175f4cb9fa853daf52b7e8`.
- Runtime: upstream llama.cpp `b11852`, Windows CPU x64 archive SHA-256
  `89d28c3d7d810a57524f4c9b13397b2485cbe32937fb302c09c1b04d2a6b3e06`.
  The runner verifies the archive and every extracted runtime file before launch.
- Local CPU only, six threads, one slot, 67584-token context, batch 256,
  microbatch 64, Q8_0 K/V cache with Flash Attention, thinking off,
  temperature zero, seed 109, 512 output tokens, 3600-second request deadline.
  CPU avoids claiming the complete 5.7 GB model fits the laptop's 4 GB GPU.
- Loopback-only owned server with no Web UI, context shifting disabled.
  The runner always terminates/reaps its server. It stops the batch on request
  timeout/disconnection rather than overlap a potentially still running request.
- 58 complete inputs from `prepare-result-context-evaluation.py`: 48 public
  semantic cases, original Git, three original dual-channel filesystem results,
  six additional attack controls. Three technical cases remain separate.
- Labels and source IDs are never supplied to the model. Full channels and
  evaluation-task context are serialized into the user message, with an explicit
  untrusted-data assessment instruction. The model has no tools or executor.
- Apply the model's own chat template, tokenize the entire prompt, then send the
  exact token array to native `/completion`. No prefix fallback. Oversize input
  becomes unknown without inference. Accepted responses must confirm the entire
  prompt token count, no truncation and EOS rather than output-token exhaustion.
- Strict output: assessment, uncertainty, target, effect, and up to three exact
  channel quotations. All quotes must occur in the specified original channel;
  their original UTF-8 byte spans are derived locally. Invalid fields, invented
  evidence, incomplete generation or failures produce unknown. Model uncertainty
  is uncalibrated and cannot grant execution or erase detector evidence.
- Retain raw observations, hashes, prompt/schema/settings, elapsed time, errors
  and label comparisons. The public set is development evidence, not held-out
  safety qualification. A full batch can still contain unknowns/unsupported
  contexts; those are not successes. A timeout-aborted batch is incomplete.

## Reproduction

The initial default-cache CPU attempt at 8c29d0b was manually stopped before
the first model assessment: server working set reached 10,019,688,448 bytes
and free physical memory fell to approximately 329 MiB. Its two connection-error
observations are technical unknowns, not model accuracy results. The replacement
uses Q8_0 K/V cache to reduce memory without shortening the prompt. The request
deadline is extended for the four 256 KiB public inputs; observed CPU prompt
throughput in the aborted attempt was about 36 tokens/second. This is a resource
configuration correction, not a label/prompt change based on predictions.

The second, Q8-cache startup still left only approximately 316 MiB free RAM
with the unnecessarily large 131072 context. Before reducing context, full
tokenization of the four long inputs measured 65844, 65859, 63559 and 63572
tokens respectively, including the complete chat template. The context is now
67584, above the maximum full prompt plus 512 output tokens. No text was cut.
The second startup is also retained as an aborted technical attempt; neither
aborted run is an accuracy claim. The final full run uses a fresh output folder.

```text
python -B -m unittest discover -s scripts/tests -p test_qwen_result_context.py -v
python scripts/evaluate-qwen-result-context.py --assets <verified-local-assets> \
  --prepared <sou109-context-shadow-58> --output <new-output-directory>
```

The assets directory contains the named GGUF, original runtime ZIP and its
`runtime/` extraction. The prepared request/reference SHA-256 values are pinned
in the runner. Outputs must be a new directory. Weights and local output paths
are not committed. Four protocol tests pass, covering secondary-channel Unicode
and repeated spans, invented evidence, invalid uncertainty/extra authority fields,
and full-prompt/EOS requirements. Inference results are not yet claimed here.

Sources: [pinned model](https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/blob/3885219b6810b007914f3a7950a8d1b469d598a5/Qwen3.5-9B-Q4_K_M.gguf),
[pinned runtime release](https://github.com/ggml-org/llama.cpp/releases/tag/b11852),
[native server protocol](https://github.com/ggml-org/llama.cpp/blob/b11852/tools/server/README.md).
