# SOU-109 pinned local development experiment

Implements the next offline step requested in [review 5615670403](https://github.com/SoupTeam/soup-wall/pull/215#pullrequestreview-5615670403).
Research observations only: no agent imports, production detector changes, tool
execution or Allow/Deny/Ask output. SOU-109 remains incomplete; the original benign
Git policy regression still fails. Independent public development paraphrases were
requested from the team and remain explicitly pending. No private/sealed inputs.

## Candidate and reproduction

Candidate: `protectai/deberta-v3-base-prompt-injection-v2`, revision
`90c9989b1a342275dd0d1a95aad283c04e075671`, publisher's ONNX export. This is the
existing repository fetch script's candidate, now pinned for this experiment.
The [pinned model card](https://huggingface.co/protectai/deberta-v3-base-prompt-injection-v2/blob/90c9989b1a342275dd0d1a95aad283c04e075671/README.md)
declares Apache-2.0 and English-only limitations. Upstream is archived. French and
Russian probes remain to reveal limitations, not claim multilingual support.

Download `onnx/model.onnx`, `onnx/tokenizer.json`, `onnx/config.json`, `LICENSE`,
and `README.md` from that repository's `/resolve/<revision>/<file>` URLs. Store
their basenames in a local directory. `scripts/result-model-lock.json` pins all
five SHA256 values; the runner checks each before launch. Weights: 738,563,188
bytes; tokenizer: 8,648,886 bytes. No runtime download or remote model code.

Use an isolated Python 3.11 environment:

```sh
python -m pip install onnxruntime==1.23.2 tokenizers==0.22.1 numpy==2.3.4
python -B -m unittest discover -s scripts/tests -p test_local_result_model.py -v
python -B scripts/evaluate-local-result-model.py --model-dir /path/to/assets --output /new/path/report.json
```

Observed host: Windows, Ryzen 5 5600H, approximately 16 GB installed RAM.
Only CPUExecutionProvider, two intra-op and one inter-op threads; GPU unused.
Provision several GB available RAM and at least 1 GB disk for assets plus runtime.
Peak memory is not measured. No paid API, external inference or training.

## Coverage and bounds

Full input is tokenized with truncation/padding disabled. All tokens are covered
in windows of at most 510 content tokens plus CLS/SEP, stride 384, including the
final partial window. No prefix-only scan or attack-dependent early exit.
Tokenizer normalization still applies; windows lose long-range context. Full token
coverage is not proof of correct classification.

Maximum injection probability >=0.95 yields `instruction`; <=0.05 across all
windows yields `data`; otherwise `unknown`. Thresholds are uncalibrated. `data`
never authorizes release. Invalid logits/errors/timeout/malformed output abstain.
The checkpoint's pinned SAFE/INJECTION mapping is checked explicitly.

Bounds: 64 KiB UTF-8 per input, 256 windows, 64 cases, 4 KiB response line and
256 KiB per output stream. Reads and event queue are bounded incrementally.
Startup: 60 seconds; each case: 30 seconds; total worker run: 300 seconds. These
are generous **offline measurement limits**, not the proposed 500 ms production
target. Hash verification and bounded cleanup overhead are reported separately.

Windows worker waits for stdin until assigned to a kill-on-close Job; failed
assignment aborts before loading. POSIX worker owns a new process group. Success,
failure and timeout terminate/reap the owned tree. Input writes run separately so
blocked pipes cannot bypass the parent deadline. Protocol/cleanup failure invalidates
the run. No arbitrary executable or model endpoint is accepted. Operator-owned
assets must remain unchanged between hashing and loading, like the existing loader.

## Dataset and reporting

Original 16 paired cases are unchanged: exact benign Git fixture, review attacks,
multilingual and response-forging text. Add benign filesystem sizes 200/201/256 to
existing 50. These are result probes, not evidence that unsupported 201/256 input
calls execute. B20/B38 remain separate pre-dispatch issues.

First Git inference is cold; the identical second is a warm repeat excluded from
quality counts. Record startup, inference and roundtrip latency separately. Report
unsafe false-benign, benign false-block, benign/attack unknown, timeout and error
counts by Git/filesystem family. Unknown is neither correct nor a negative label.
Keep input hashes, observations, dependencies, source state and script hash.

This small public set is not an independent held-out safety estimate. Independently
authored paraphrases remain pending. Uncalibrated probabilities, domain shift and
window context are limitations. Even zero observed misses cannot authorize production
use, remove hard policy restrictions, or close SOU-109.
