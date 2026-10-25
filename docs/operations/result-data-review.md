# Experimental complete-result review

This opt-in Linux path can resolve a result refusal caused solely by weak
structural injection evidence. It is not general prompt-injection protection,
an automatic permission, or completion of SOU-109. The default stays disabled.

This is a proposed extension to detector evidence derivation, not the existing
advisory/tightening-only judge contract. An affirmative model assessment can
remove a structural finding and change a prior Deny to Allow. Keeping the same
policy YAML does not make that decision semantics unchanged. Enabling this path
requires review of that explicit authority change; the independent hard floors
below are not exceptions to that review.

The daemon owns an offline CPU worker for Horizon-Labs
`prompt-injection-guard-base`, revision
`70b65c51c03f7d9b5d1f18726defee45f3936610`. The fixed ONNX SHA-256 is
`5ae9f527897b1ffcb2b13440875769d0c28a25fb976b8b42465f0ad5b462b61b`.
The worker embeds every asset hash, requires onnxruntime 1.23.2, tokenizers
0.22.1 and numpy 2.3.4, and uses CPUExecutionProvider with six intra-op threads.
No model assets or Python dependencies are downloaded by the daemon or CI.
No remote code, custom-op libraries, external tensor files or pickle are loaded.

## Operator installation

Install the reviewed dependencies in an owner-private Python venv and copy the
six pinned model assets (including `onnx/model.onnx`) into a separate private
directory. Both roots must be owner-private, with real directory ancestors and no
untrusted writable ancestor. Standard trusted sticky parents such as `/tmp`
are supported. Make the runtime tree read-only before pinning: remove all write
bits from its files/directories, preserving execute bits; the root can be 0500.
Model assets can also be installed read-only. Only standard
venv Python aliases and `lib64 -> lib` symlinks are supported.
Ancestors, runtime entries and canonical interpreter ancestors must belong to
root or the daemon's effective user. A private leaf under a different user's
directory is rejected even if that ancestor has mode 0755.

These are trusted operator assets: keep the runtime, its configuration, system
interpreter and model outside **every tool-writable workspace**. Do not enroll
unreviewed dependencies by merely hashing them. The runtime-tree hash is an
installation pin, not a dependency provenance or reproducible-build attestation.

After reviewing the installation, compute its local pins:

```sh
agentfw result-review-pin --runtime-dir /private/runtime --assets-dir /private/assets
```

This prints a `result_data_review` YAML block. It does not modify configuration,
enable the worker, or attest to model accuracy. Explicitly add the block to the
daemon's existing operator configuration. Native admission must be configured,
enforcement enabled and the optional external judge disabled. Restart the daemon.

The worker starts asynchronously, with a separate 120-second startup budget.
Query `/native/v1/result-review` with the native bearer token: only `ready: true`
means the model and exact runtime passed startup. `/health` alone is insufficient.
Until readiness, all original decisions remain unchanged.

## Result boundary

Only supported selected original-server MCP **value results** are eligible.
Already-Allow results have no new model requirement. A dry run must find that
the current refusal could be resolved by removing only the weak structural
atoms; otherwise no model call is made.

Every original decoded text channel participates, including duplicates, empty
strings, CRLF and original order. The model scores the complete ordered envelope
and every complete raw channel. There is no truncation, deduplication, window-only
permission, record hash exception, tool-name permission or policy change.
Here "no policy change" means the policy file is unchanged, not that the
detector's evidence or the resulting decisions are unchanged.
Any view above 8192 tokens is unsupported. Limits are 64 channels and 1 MiB total
decoded UTF-8 text; framed requests are limited separately to 2 MiB.
Literal special-token spellings in caller text are tokenized as data; only the
tokenizer post-processor inserts trusted model boundary IDs. Original bytes are
neither removed nor rewritten to achieve this.

`data` requires every view to complete and their maximum injection score to be
at most 0.05. This is a fixed experimental cutoff, **not a calibrated probability**.
Scores at least 0.5 produce `instruction`; intermediate scores are `unknown`.
Neither outcome creates a permit. Technical failures and incomplete coverage
also create no permit.

Inference has a 1400 ms wall deadline. At most one request runs; busy calls do
not queue. The worker's Linux address space is capped at 6 GiB (or the inherited
lower limit), file descriptors at 128, and core dumps disabled. This is an
address-space ceiling, not a reserved-memory or whole-machine availability guarantee.
A timeout, bad binding, oversized reply or worker failure retires and
reaps the owned process. No restart happens inside a result request. Restarting
the daemon is required to re-enable a retired reviewer. The existing five-second
native RPC timeout is unchanged.

A private in-process permit binds the exact complete channel input digest and
is never accepted from the native wire. After inference, the daemon rechecks the
receipt, session authority, current policy and original channels. Signatures,
remaining body evidence, independent detectors, resource controls and provenance
retention remain authoritative. Original evidence is retained before release.
Actual use is recorded as `native_result_data_review_base` with the model pin.
Positive recipient/action and instruction-replacement evidence in the original
result also prevents the reviewed alternative. These incomplete recognizers
are additional refusal evidence; their absence never establishes safety.

## Qualification limits

The initial CPU feasibility run resolved two short original Git-show inputs and
refused their matched synthetic attack. The four-file Git diff with request ID
21 remained uncertain;
large filesystem results are not qualified. These measurements are development
evidence, not a held-out result or blanket permission for real-server responses.
SOU-109 and dependent acceptance tasks remain open until their complete original
scenarios pass with independent execution and host-delivery witnesses.

Rollback: remove `result_data_review` and restart. This restores the original
detector path. Keep the existing policy and dataset labels unchanged.
