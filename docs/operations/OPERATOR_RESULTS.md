# Pilot Operator Results

Use `agentfw pilot-approval --output json-v1 --home HOME --run RUN COMMAND`.
Commands: `list`, `inspect ID`, `approve ID --binding SHA256`,
`reject ID --binding SHA256`, and `stop`.
Without `--output`, the existing interface remains unchanged. This option does
not enable a terminal watcher or a streaming protocol.

## Record

Each parsed invocation writes one JSON document to stdout. The document uses
ASCII escapes, ends with a newline, and is smaller than 16 MiB. Runtime errors
do not write raw diagnostics to stderr. CLI syntax errors and help remain Clap
output; they are not completed operator invocations.

```json
{
  "format": "sw-pilot-operator-result/1",
  "operation": "approve",
  "outcome": "decision_submitted",
  "reason": "approval_submitted",
  "identity": {
    "run_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "run_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "instance_id": "example-instance",
    "registry_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
    "pending_id": "example-pending",
    "binding_sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
  },
  "data": {
    "pending_id": "example-pending",
    "state": "decision_submitted",
    "decision": "approve",
    "dispatched": "not_observed",
    "released": "not_observed"
  }
}
```

`identity` is null until the selected run is verified. Pending identity is added
only after the authenticated live observation and protected pending file agree.
Run hashes describe the verified record, not a promise that the run stays live.
Paths, tokens, signatures and internal error strings are never copied into an
error record. Only explicit `inspect` includes complete arguments, with the
existing bounded input and escaping checks. `list` exposes summaries only.

## Outcomes

| Operation | Outcome | Meaning |
| --- | --- | --- |
| list | listed | Verified pending snapshot, possibly empty. |
| inspect | inspection_presented | Complete escaped arguments were presented. |
| approve | decision_submitted | Exact single-use decision submitted; execution and result delivery are not observed. |
| reject | rejection_submitted | Rejection written; result delivery is not observed. |
| stop | stop_confirmed | Existing authenticated receipt confirms owned process and namespace cleanup. |

Failure outcomes are `refused`, `unavailable`, or `unknown`. After a verified
stop intent has been persisted, a failure is `stop_requested`, never
`stop_confirmed`. It does not claim complete revocation, protection, cleanup,
or rollback of effects already performed.

Reasons come from typed producer failures, not searches through error text.
They include `unsafe_run_record`, `run_unavailable`, `run_expired`,
`run_stopping`, `selection_changed`, `daemon_unavailable`, `daemon_refused`,
`daemon_identity_changed`, `pending_unavailable`, `pending_expired`,
`binding_changed`, `inspection_required`, `decision_conflict`,
`stop_ownership_unverified`, `stop_unconfirmed`, `unsupported_platform`,
`invalid_input`, `output_unavailable`, `output_limit`, and `unknown`.
`pending_unavailable` does not guess whether a missing request was decided,
expired or removed by a restart. Unmapped failures remain `unknown`.

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Operation completed as described by its outcome. |
| 2 | Invalid CLI syntax; no result contract. |
| 3 | Explicit refusal or invalid selection/input. |
| 4 | Run or daemon unavailable. |
| 5 | Unknown or incomplete result, including unverified stop ownership. |
| 6 | Output could not be delivered or exceeded its bound. |

Read the process exit code as well as the document. Inspection proof is saved
only after the argument document is fully written and flushed. A later receipt
failure leaves the already emitted `inspection_presented` record unchanged and
returns nonzero; it must not be treated as permission to approve. No second
record is appended. A closed or partially written output channel may contain no
valid document; the command returns nonzero and never invents a replacement
success. Do not automatically retry a mutating command after unknown output.

## Checks

```sh
cargo test --locked -p agentfw --test pilot_results
cargo test --locked -p agentfw --lib
python3 -B -m unittest discover -s scripts/tests -p test_operator_results.py -v
```

`scripts/qualify-operator-results.py` reuses the accepted original filesystem/Git
host qualification and authenticated broker, with structured operator calls.
It accepts the same pinned tool paths as `scripts/qualify-pilot-ask.py`.
Use a clean checkout and a new output directory outside the repository.
Run it on native Ubuntu 24.04, not Docker or WSL. It retains safe result metadata,
original independent dispatch/effect witnesses, source identity and failed
attempts. Supply a new output directory for each attempt; an existing directory
is refused rather than overwritten. Scripted operator/provider inputs do not prove physical human presence
or live-model efficacy. Local container tests are not native acceptance.

For the focused hosted run, dispatch `mcp-real-filesystem.yml` on the candidate
branch with `operator_results_only=true`. Leave the other mode switches off.
The existing native lane supplies the pinned tools and job-scoped sandbox
permission. It retains `sou140-operator-results/operator-results.json` in its
artifact, including failed attempts. This development run is not merge admission.
