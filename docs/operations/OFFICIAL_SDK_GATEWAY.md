# Official Python SDK Gateway acceptance

This bounded fixture suite sends actual official SDK requests through the built
Gateway to owned loopback HTTP servers. It uses no provider credentials, external
model, paid service, private dataset or arbitrary shell executor.

## Reproduce

Use Python 3.11 and the repository's Rust toolchain from a clean checkout. Install
the isolated SDK environment once:

```sh
python3 -m venv /tmp/soup-sdk-venv
/tmp/soup-sdk-venv/bin/python -m pip install --require-hashes -r scripts/requirements-sou92.txt
cargo build --locked -p llm-firewall --bin llm-firewall --message-format=json > /tmp/sou92-build.jsonl
/tmp/soup-sdk-venv/bin/python -B -m unittest discover -s scripts/tests -p test_sou92_sdk.py -v
```

Then run the complete acceptance with one command, using a fresh output path
outside the repository:

```sh
/tmp/soup-sdk-venv/bin/python -B scripts/verify-sou92-sdk.py --run \
  --gateway "$PWD/target/debug/llm-firewall" --expected-commit "$(git rev-parse HEAD)" \
  --output /tmp/sou92-results.json
```

On Windows, use the virtual environment's `Scripts/python.exe` and the `.exe`
Gateway executable. The runner itself uses portable Python APIs. The focused
`Official SDK Gateway compatibility` workflow builds its exact checkout and
retains Cargo build records, binary hash, source identity and runtime evidence.
It is registered with the existing CI selection table for Gateway changes.
PR qualification runs the same steps as `Components / gateway-sdk / official-sdk`
through the generated shared workflow. The focused workflow remains manually
dispatchable; it does not start a duplicate PR run. Regenerate component jobs with
`python scripts/ci_components.py` after changing the focused workflow.

## Coverage and independent witnesses

The full matrix contains **99 cases**: three APIs (Chat Completions, Responses,
Anthropic Messages), ordinary and streaming delivery, 13 scenarios in both modes,
three additional shadow controls in both modes, and cancellation in streaming
mode. Each case also makes a useful followup through the same Gateway process.

- Allowed reads and two-call responses require exact call IDs, names and parsed
  arguments, unchanged Unicode model text, actual file content and independent
  read receipts. Chat and Responses arguments are interleaved across calls;
  Anthropic blocks follow the provider's sequential block protocol. All HTTP
  bodies are additionally fragmented independently of event boundaries.
- A synthetic documented AWS example credential sent to an owned receiver is
  denied by the built-in agent policy. Egress to a second owned loopback address
  exercises Ask: it remains blocked without a human approval path.
- A destructive call uses the existing capability policy restricted to
  `read_file`. Its bounded fixture executor maps exactly one declared destructive
  call to removal of a fresh canary file, without invoking a shell. Ordinary
  destructive commands are not assumed to be denied by the default agent policy.
- Each secret, Ask and destructive fixture also runs with enforcement disabled.
  These calibration controls must produce the actual receiver body or remove
  the owned canary. They are separate processes and disposable configurations.
- Unsupported provider tool types and novel executable types must be refused.
  Invalid JSON, incomplete streams/responses, upstream 503, timeout, request and
  response byte limits and client cancellation must leave the executor untouched.
  A parser exception alone is never accepted as proof of protection.
- Useful recovery must succeed after every original case. Client retries are
  explicitly zero; the independent upstream request ledger rejects repeats.

The executor checks identities and arguments before accepting a capability.
The receiver hashes actual delivered bodies. The grader separately checks
completion, file effects, receiver effects, requests and cleanup; an API error
alone cannot establish a useful positive or calibrated negative result.

## Evidence and acceptance rules

The JSON report records the exact Git commit before and after the run, binary
SHA-256 before/after, SDK and transitive dependency versions, dependency lock
hash, actual configurations and policy hashes, per-case request/effect ledgers,
latency, completion, cleanup and explicit pass/fail/incomplete counts. Cargo
build records retained by CI tie the binary build to its checkout; a binary hash
alone does not prove where an externally supplied executable came from.

A `.partial.jsonl` file is flushed after each case. An interrupted run is
incomplete. Dirty or subset diagnostic runs require `--dev` and cannot claim
acceptance. A full clean stable run with all 99 expected results is required.
Report `release_acceptance` remains false: independent review is separate from
automated compatibility acceptance. Temporary directories are removed only
after child termination and fixture thread shutdown are verified.

Dependency provenance, versions, license metadata, upstream project links and
all permitted wheel hashes are in [the dependency manifest](evidence/SOU92_DEPENDENCIES.json).
The hash-locked requirements permit wheels only. Their upstream license notices
remain in installed distributions; this repository does not vendor SDK code.

## Limitations and diagnostic findings

This qualifies synchronous official Python SDK clients against deterministic
owned upstream fixtures. It does not claim live-model quality, async SDK support,
real provider service acceptance, native MCP qualification or production release
acceptance. Gateway currently uses a local typed verdict, not an optional remote
verdict field. Its existing `adapter_projection_is_privacy_safe_and_tightens_escalate`
test checks unresolved escalation without a fallback becomes Ask. That unit
boundary is separate from this SDK matrix; remote-verdict fault injection is
not claimed here.

Streaming uses the SDKs' public typed iterators (`create(stream=True)`). Their
optional accumulating snapshot helpers can throw before `response.created` or
`message_start` when Gateway refuses early. Those helper failures were retained
as failed diagnostic runs; they were not counted as protection or retried.
Applications using those helpers must handle early refusal explicitly.

Cancellation is exercised before completion. Once a caller has executed an
allowed side effect, withholding a later response cannot roll it back.
The fixtures do not execute the model's shell text. Destructive behavior is
strictly the explicit canary capability described above.

References: [OpenAI streaming](https://developers.openai.com/api/docs/guides/streaming-responses),
[OpenAI tool calls](https://developers.openai.com/api/docs/guides/function-calling),
[Anthropic Python SDK](https://platform.claude.com/docs/en/cli-sdks-libraries/sdks/python).
