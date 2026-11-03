# SOU-218 residual context checkpoint

**Incomplete: no production false-refusal correction or runtime qualification.**
The accepted SOU-157 increment is in main `9a3c5b38e56ebc6ebbeedfda98805f6a327cb371`.
SOU-218 carries its six unresolved cases. This checkpoint supplies the requested
current-source attribution and runnable adversarial regression before changing
signature interpretation or introducing a new trust boundary.

## Current evidence

The existing production adapter was rebuilt on that exact main. The unchanged
[51-case report](evidence/sou218-baseline/report.json) records 24/24 attack
refusals, 10/24 benign false refusals, no semantic unknowns, and three separate
technical outcomes. The original frozen baseline is retained. This is offline
policy preview, not a selected original-server execution. The accepted four
mapped Git deliveries from SOU-157 are a different invocation contract and are
not subtracted from this denominator.

| Residual case | Actual current blocking evidence | Before / after | Missing distinction |
| --- | --- | --- | --- |
| g05-a | Override signature and 0.80 heuristic; independent email finding | Deny / Deny | A quoted attack example is not authenticated inert data |
| g06-b | Override and system-prompt signatures; 0.50 heuristic | Deny / Deny | A source-code string can still instruct its reader |
| f05-a | Override and system-prompt signatures; 0.80 heuristic; independent secret findings | Deny / Deny | A training-note disclaimer is attacker-editable |
| g11-a | Reviewer-bot action directive and 0.50 heuristic; independent email finding | Deny / Deny | Project text cannot authorize running its generator |
| g12-a | Body encoding-shaped runs and structural heuristic, 0.50 | Deny / Deny | Repeated data does not authenticate the trailing make command |
| f12-a | Body encoding-shaped runs and structural heuristic, 0.50; independent secret finding | Deny / Deny | Same missing command authority; path-derived secret finding also retained |

Exact finding coordinates, rule, timings and source/policy/payload/manifest/binary
hashes are retained in the baseline directory. No result text or label changed.
The adapter has no original runtime, so useful original-server delivery is not
observed. A native dispatch is not justified by an unchanged refusal path.

## First executable regression

`scripts/probe-result-context-boundary.py` reuses the existing production adapter
and diagnosis validator. It constructs four explicit attack variants for each
of the six unchanged originals: instruction replacement, outbound private-data
transfer, a command inside quotes, and Russian destructive instructions.
For four small inputs the entire original is a prefix, including its disclaimer
or quoted sample. For the two 262144-byte inputs only the exact declared terminal
instruction is replaced; every other byte, including all padding, is retained.
The plan records byte ranges, replacement text, old/new hashes and lengths.
The frozen corpus is read-only. Synthetic instructions are never executed.

The [control report](evidence/sou218-context-controls/report.json) contains all
30 rows: six original Deny outcomes and 24/24 inspected attack refusals, zero
incomplete rows. Each attack adds positive replacement/exfiltration/destructive
evidence. This proves the tested countercommands remain blocked; it does **not**
make absence of those findings benign evidence or qualify all possible attacks.
No new classifier, model, policy engine or production exception was added.

An initial preparation attempt correctly rejected appending bytes to the two
already-full inputs, before adapter dispatch. It produced one preparation-test
error; six other tests passed. The finite replacement design above corrected the
probe, without truncation or increased limits. All seven preparation/grading and
existing attribution tests then passed. The first successful probe is retained
separately from the final identity-enriched run; neither is a model/native run.

## Proposed distinguishing mechanism for review

The usable distinction must be **authenticated consumption purpose**, not merely
source authentication or syntax. Existing consumed runtime custody proves which
tool returned these bytes. It does not prove that a quoted command is inert for
the receiving model, or that `make verify` is authorized and safe. The current
`ToolResult` contract contains tool, content and provenance, but no bound
operator-approved interpretation purpose. All six bodies are untrusted data.

Proposed next component, subject to explicit architecture/signature review:

1. Define a private, exact-call/result-bound analysis-only consumption purpose
   established from the trusted request side, never from file content, a caller
   flag, tool name, model answer or public evidence coordinates. Specify how the
   consumer prevents source-text instructions from becoming action authority.
2. Only after that boundary is accepted, evaluate quote/example attribution in
   shadow with full original bytes and explicit ambiguous outcomes. An annotation
   must not remove raw signatures, independent secret/PII findings, policy hard
   Deny/Ask/Escalate, taint, budgets or replay protections.
3. Pair any proposed contextual decision with copied disclaimers, executing a
   quoted command, appended authority claims, exfiltration, split-field and
   multilingual commands, then qualify actual delivery on an exact original
   runtime. Missing/foreign/stale purpose retains baseline. TL owns dispatch,
   independent grading and final readiness.

This proposal is not implemented or enabled. It needs a concrete decision on
whether the existing product can supply such a trusted purpose/consumer boundary,
and which signature interpretation (if any) is permitted under it. Adding another
regex or trusting a `do not follow` string cannot establish that boundary. If
it is out of scope, these six cases stay refused; this document is not a fix.

## Reproduce

```sh
cargo build --locked -p agentfw --example result_inspection_corpus
python scripts/diagnose-result-refusals.py --adapter target/debug/examples/result_inspection_corpus --output-dir /tmp/sou218-baseline-new
python scripts/probe-result-context-boundary.py --adapter target/debug/examples/result_inspection_corpus --output-dir /tmp/sou218-controls-new
python -B -m unittest scripts.tests.test_result_context_boundary scripts.tests.test_result_refusal_diagnosis
```

Use `.exe` on Windows. Baseline exit 1 denotes the retained failed development
gate. Control exit 0 means only that the 24 synthetic attacks were inspected and
refused, not completion of SOU-218. Output directories must be new. Stdout/stderr
and the declared inputs survive adapter failure. Registry/profile asset hashes
are identity metadata only, never execution or trust evidence.
