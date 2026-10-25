# Bounded offline Agent policy replay

`agentfw replay` continues to summarize historical verdicts from an audit log by
default. `agentfw replay --offline` explicitly opts into a simulation of supplied
legacy Agent events against one or two supplied policies. It never selects an
installed policy, reads an Agent home, executes an event's tool, calls a judge,
model or provider, or creates runtime authority. A simulated Allow is a policy
result for the declared data; it does not admit a real action.

This supports roadmap Phase 3 policy composition inspection and Phase 5 operator
explanations. It uses the production `AgentFirewall` and `AgentPolicySet`
evaluator, including first-match operator rules and shipped hard-refusal floors.
The additive trace is captured during that evaluation. It does not match rules
again to reconstruct an explanation.

## Run a declared simulation

Build from the selected checkout, then supply both files explicitly:

```sh
cargo build --locked -p agentfw --bin agentfw
./target/debug/agentfw replay --offline \
  --input crates/agentfw/tests/fixtures/offline-replay/sequence.json \
  --policy crates/agent/policies/agent-default.yaml --format text
./target/debug/agentfw replay --offline \
  --input crates/agentfw/tests/fixtures/offline-replay/sequence.json \
  --policy crates/agent/policies/agent-default.yaml \
  --compare-policy crates/agentfw/tests/fixtures/offline-replay/weak-policy.yaml \
  --output /absolute/owned/directory/new-report.json
```

Each policy receives a fresh in-memory firewall. Neither the comparison nor a
second invocation inherits taint from another simulation. `--output` creates a
new private file; its parent must already exist. Without it, the bounded report
is written to stdout. JSON is the default; `--format text` renders the same
redacted explanation data. Offline options require `--offline`; `--log` conflicts
with it. Historical use remains `agentfw replay --log /explicit/audit.jsonl`.

| Exit | Meaning |
| --- | --- |
| 0 | Every event has a complete supported simulated result, including Ask or Deny |
| 2 | A report was produced with unsupported or insufficient context |
| 1 | File, format, bound, rendering, private export or partial/closed-output failure |

Clap reports invalid command-line combinations separately. Runtime input and
policy errors use fixed reason codes and omit raw parser diagnostics and paths.

## Frozen v1 input and policy contract

Input is a single JSON document in format `sw-policy-offline-input/1`:

```json
{
  "format": "sw-policy-offline-input/1",
  "context": {"history": "complete_from_start", "judge": "disabled"},
  "events": [
    {"complete": true, "event": {
      "session": "owned-example", "agent": "main", "parent": null,
      "seq": 1, "at_ms": 0, "kind": "tool_call", "tool": "Read",
      "args": {"file_path": "/owned/example.txt"}
    }}
  ]
}
```

`complete: true` declares the original complete event payload, including the
entire argument object or result content. It is an operator assertion about
simulation data, not authenticated provenance. Do not reconstruct complete
arguments or results from a redacted audit record. Omitted arguments, identity,
source or other required context produce `insufficient_context`. The simulator
does not infer a missing payload from a verdict, detector name or summary.
The argument object is evaluated as supplied under the legacy event contract;
this mode does not validate a tool executor's schema or assert that an executor
would accept or run those arguments.

Supported events are `tool_call` and `tool_result` for `Read`, `Grep`, `Glob`,
`NotebookRead`, `TodoRead`, `WebFetch`, `WebSearch`, `Bash`, `Write`, `Edit` and
`MultiEdit`. Mixed legacy argument strings use production maximum-severity
classification. A result requires string `content` and explicit `source`:
`{"origin":"user_prompt"}`, `{"origin":"local_project"}`,
`{"origin":"local_system"}` or `{"origin":"network","host":"owned.example.invalid"}`.
Sources are declared data only. The simulator neither reads referenced paths nor
resolves or contacts declared hosts.

A document contains one session and top-level agent, with no non-null parent,
and strictly increasing unsigned `seq`. `session`, `agent`, `seq` and `at_ms`
are required; omitted/null `parent` means top-level. Identity strings are nonempty,
control-free and at most 128 UTF-8 bytes. Native/MCP/subagent provenance,
manifest/lifecycle events, native baseline/classifier annotations, grants,
sessions, authority and judge extensions are unsupported. Unknown fields are
rejected before the permissive production event decoder; duplicate JSON keys
are errors even inside arguments. An unsupported event never reaches inspection
and cannot record its payload as taint. It leaves a sticky gap in the private
simulation history, so later events cannot acquire a permissive final verdict
from the omission.

`history` is `complete_from_start` or `incomplete`; `judge` must explicitly be
`disabled`. Missing values are insufficient; supplied unsupported values or
fields are unsupported. Incomplete history marks production provenance
incomplete. The actual evaluator can still emit a trace, including its mandatory
Ask floor, but `simulated_verdict` remains null for every subsequent event.
No historical runtime state is consulted to fill the gap.

Policies use the production `AgentPolicySet` YAML schema, identified in this
adapter as `agent-policy-set-yaml/1`. This adds no new policy language. Existing
production defaults for omitted rule conditions, rule lists, allowlist and
`default` apply (an omitted default is Allow). Use an explicit `default` when
reviewing a policy. Unknown/duplicate YAML fields fail through the production
parser. Anchors, aliases and tags are excluded before YAML decoding in this
bounded subset. The lexical precheck distinguishes plain scalars (where internal
apostrophes and quotes are data), quoted scalars and comments. Quoted scalars
must close on one physical line; block scalars (`|`/`>`), explicit complex keys,
Unicode NEL/line/paragraph separators and flow nesting above 32 are unsupported
(`offline_policy_yaml_subset`). Use single-line quoted strings with escapes for
messages requiring line breaks. Each policy is explicit; there is no implicit shipped or local
policy selection. The shipped Deny floor is still mandatory inside production
evaluation and its exact policy bytes are separately hashed in the report.

This v1 scope is `legacy-agent-event-inspection/1`. It does not simulate the
native MCP `compose_production_policy` classifier action vector, native resource
admission, runtime grants, installed executor roles or live judge behavior.
Requesting these through input extensions yields unsupported context.

## Read an explanation

Reports use `sw-policy-offline-report/1`, `simulated: true` and
`protection_claim: false`. SHA-256 identities cover the original input and policy
bytes, including whitespace, rather than normalized JSON/YAML. The evaluator
scope, Agent version and shipped floor policy identity make the interpretation
explicit. Array `index` and rule `index` are zero-based; `seq` retains the supplied
event order.

For each supported event, the report records:

- The first matching operator rule ordinal and SHA-256 of its name, or
  `operator_default`; its verdict and declared fallback.
- The floor actually applied, if any: `shipped_hard_deny` with shipped rule ordinal
  and name hash, or `incomplete_provenance_ask`. An operator Deny is already final
  at the policy layer and does not claim a second applied floor.
- The actual pre-resolution verdict, fallback and final simulated verdict when
  context is sufficient. `judge_disabled_fallback` explains an Escalate resolved
  by the existing production fallback; `no_judge_executed` never means a judge
  examined the content and found no injection.
- Safe derived signals: action class, sensitive-path flag, risk score, built-in
  detector counts, egress count, taint source kind/sequence, incomplete provenance
  and retained taint entry count. Raw arguments, results, rule names/messages,
  session/agent identifiers, environments, hosts and paths are omitted.

Locate an operator rule by ordinal in the **exact hashed policy file**, then
compare its name hash. Inspect the referenced shipped policy for a hard floor.
Review `reason_codes`, the declared context and safe signals before changing a
rule. `--compare-policy` marks verdict, status and trace/reason changes event by
event; it does not rank a policy as safer or claim a detection rate.

For an unsupported record, `trace` and `simulated_verdict` are null. Codes such as
`unsupported_event_fields`, `unsupported_event_kind`, `unsupported_tool`,
`unsupported_result_source`, `unsupported_parent_context`,
`event_context_identity_changed` and `event_order_invalid` identify the declared
boundary. Missing fields use codes such as `missing_or_invalid_event_identity`,
`missing_or_invalid_arguments`, `missing_result_content`, `missing_result_source`
and `event_not_declared_complete`. Supply the original complete supported data or
keep the result incomplete; do not fill fields with permissive guesses.

## Resource and file boundaries

All limits are failures, without truncation or partial success:

| Resource | v1 bound |
| --- | --- |
| Input document | 1 MiB before JSON parsing |
| Each explicit policy | 64 KiB before YAML parsing; 64 rules |
| Events | 1–64; each record at most 32 KiB of compact JSON encoding and 8192 value nodes |
| JSON | depth 32; 65536 total value nodes; keys 128 bytes; individual strings 32768 bytes |
| Sum of event string values | 512 KiB before any evaluation |
| Policy scalars | rule name/detector 128 bytes; message 2048; at most 128 egress entries of 256 bytes |
| Encoded report | 1 MiB before publication; same cap for JSON and text |
| Filesystem path | 4096 bytes after absolute resolution; at most 64 normal components; no `..` |

CLI file I/O is supported on Unix. It opens every ancestor with descriptor-based
no-follow traversal, accepts regular input files only, reads at most limit+1,
and rejects metadata/length changes during a read. FIFO, device, directory and
symlink inputs fail. Supply quiescent owned files. On macOS `/var` and `/tmp` may
be symlinks; use their real `/private/var` or `/private/tmp` paths. A non-Unix CLI
returns `offline_platform_unsupported`; Windows private export is not claimed.

Export uses a pinned parent descriptor and exclusive no-follow creation with
mode 0600. It verifies ownership, regular type and a single link, writes the
complete pre-bounded report and syncs it. Existing files and symlinks are never
overwritten. On failure it removes only its own matching newly created inode when
that identity can be verified. The parent must be owned and quiescent; concurrent
renames by another writer are not a trusted report publication mechanism.
Stdout uses complete-write and flush checks; a closed pipe fails explicitly.

## Reproduce the exact-source synthetic qualification

The fixtures in `crates/agentfw/tests/fixtures/offline-replay/` are newly authored
owned synthetic data under the repository license. They contain no external
corpus, customer input, real secrets or detection-rate evidence. The sequence
covers ordinary reads, ordered network taint, sensitive paths/destinations,
mixed argument severity, overlap and first-match fallback, and shipped hard Deny.
Unit tests add the combined incomplete-provenance Ask floor, forged extensions,
unknown tools, missing original data, bounds and redaction negatives. CLI tests
compare real subprocess reports with ordinary production inspection and confirm
that the trace preserves outcomes and provenance state.

From a **clean committed checkout**, first inspect the plan, then opt in to the
owned build and controls. Use the full 40-character source SHA, an absolute Cargo
path and a fresh output directory outside the source:

```sh
python3 scripts/verify-sou152-offline-replay.py --expected-commit FULL_SOURCE_SHA
python3 scripts/verify-sou152-offline-replay.py --run \
  --expected-commit FULL_SOURCE_SHA --cargo /absolute/toolchain/bin/cargo \
  --output /absolute/owned/new-qualification
```

The driver checks commit/tree/clean status before and after, builds the binary and
CLI test from that source with `cargo --locked --offline` in a fresh private target,
and runs all three CLI tests. It records exact binary, driver, fixture, policy,
parity-report and bounded process-log hashes in private `report.json`; the
sanitized details are in private `parity.json`. Temporary build files are removed.
Populate the dependency cache beforehand if needed. No workflow dispatch, gate
configuration, provider, model or full CI admission is part of this driver.
The selected local toolchain/dependency cache remains a trust assumption.

Independent controls first execute an owned marker-writing command, connect to
an owned loopback receiver, read disposable state canaries and demonstrate a
FIFO reader/writer rendezvous. The simulated events then reference that command,
receiver and FIFO. The test checks no command marker, connection or sampled FIFO
open, unchanged private inputs/state, absent home discovery and no Agent authority
creation. FIFO polling alone cannot exclude every short-lived read.

On macOS, an additional sandbox attempt denies process forks, network operations,
file writes, fake Agent-home reads and the target FIFO read. It positively
calibrates state-read/write/fork/network denials and opening the exact FIFO
tool target before calling the offline CLI. A bounded Python helper opens that
FIFO read-only with `O_NONBLOCK` and closes it, first successfully without the
sandbox and then with a required denial under the exact target filter. The
parity report names `target_read` among the calibrated denials, and the driver
requires it before accepting a passed sandbox claim.
Unavailable sandbox support is recorded as unavailable, never passed; the driver
then reports `passed_with_limits` and makes no syscall-level no-read claim.
Other hosts retain the same explicit limitation. These local checks are bounded
synthetic evidence; platform deployment acceptance and native MCP qualification
remain separate.
