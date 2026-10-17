# Provenance memory budgets

The Agent bounds the selected provenance tracker's retained storage in bytes and
contexts. Losing evidence never makes an active context clean. The native/MCP
path refuses an unrecordable result before releasing its original bytes and
requires confirmation for protected work after history loss.

This is a retained-provenance accounting boundary. It does not bound whole-process
RSS, transient request parsing, audit files, judge spans, manifests, classifier
workers or unrelated stores. Existing request and executor limits still apply.

## Defaults and configuration

`provenance` is an additive daemon configuration section. An absent section, or an
absent field inside it, uses the reviewed default. Unknown fields fail parsing.
The configuration is applied by `agentfw serve`, including its selected native/MCP
runtime. Standalone guarded CLI constructors retain their safe default tracker
limits; they do not load this per-home override.

Existing `AgentFirewall::new(policy, entry_cap)` and `TaintTracker::new(entry_cap)`
retain their signatures and apply these defaults; the explicit limits API returns
validation errors. The existing entry cap still applies independently to both
FIFO indexes.

```yaml
provenance:
  per_session_bytes: 8388608
  total_bytes: 67108864
  max_sessions: 512
  max_input_bytes: 262144
  max_source_bytes: 1024
  max_literal_bytes: 4096
  max_session_id_bytes: 256
```

| Field | Meaning |
| --- | --- |
| `per_session_bytes` | Charged retained storage for one tracked context, including its identifier and inline session state |
| `total_bytes` | Aggregate charged retained storage, including the outer context table |
| `max_sessions` | Maximum tracked contexts; a shared host and each collector's private epoch consume separate contexts |
| `max_input_bytes` | Maximum UTF-8 bytes inspected by one tracking/checking operation |
| `max_source_bytes` | Maximum combined bytes in the source's owned metadata strings |
| `max_literal_bytes` | Maximum accepted URL/path literal bytes before retaining or lowercasing it |
| `max_session_id_bytes` | Maximum UTF-8 bytes in a tracked context identifier |

The allocation model is reviewed against Rust 1.94.1. For a freshly allocated
`HashMap<K,V>` with nonzero usable capacity, the charge is
`next_power_of_two(fresh_capacity + 1) * (size_of::<(K,V)>() + 1) + 256`
bytes. The final term conservatively accounts for alignment/control slack. Queue
backing storage is charged at its actual capacity times its element size, and
owned strings at their actual capacities. The outer context table is included
globally; a context also includes its inline table-entry state, so adding the
per-context figures is not an exact reconstruction of the aggregate.

Accounting uses checked arithmetic. It includes fingerprint mark storage, source
string capacities, literal string capacities, duplicated literal FIFO keys,
queue backing capacities, context identifiers and a conservative allocation model
for map buckets/control storage. Container allocations remain charged at their
allocation high-water mark while retained. Removing one string does not pretend
the container shrank. Repeated values do not add queue keys indefinitely. Fixed
tracker headers and allocator bookkeeping are outside this metric; charged bytes
are not a measurement of the allocator or RSS.

A record can evict older entries in its own FIFO indexes to fit. This marks that
context incomplete. Global pressure cannot silently discard another live
context's evidence or loss marker. If the complete current input cannot remain
represented, recording fails explicitly. Large literals and source metadata are
bounded before copying them into retained storage. Input is bounded before
fingerprinting. UTF-8 byte lengths, including lowercase expansion checks, apply
rather than character counts.

Zero byte/context budgets refuse new native context registration. Zero input,
source, literal or entry capacity can make untrusted content unrecordable; it
never authorizes a result merely because no evidence was retained. The legacy
library/hook entry points preserve their accepted signatures and conservatively
mark unrepresented history instead of allocating an unbounded tombstone map.

## Enforcement and diagnostics

Native registration reserves every required tracking context before publishing
session authority. Capacity exhaustion gives HTTP 409 with
`native_provenance_context_capacity`. No native session grant is created and the
MCP child is not started.

Native call admission also bounds the complete serialized argument envelope by
`max_input_bytes` before issuing any call grant. Exceeding it returns a correlated
Deny with `native_provenance_input` and marks required contexts incomplete;
approval opening refuses the same oversized envelope. This is separate from the
library's per-leaf argument checks.

For an untrusted native result, the runtime checks every decoded text block and
all required private/shared-host records before allowing release. It rechecks the
whole delivery after recording, so a later block cannot evict an earlier block
from the same delivery and still produce Allow. An unrecordable result returns
`verdict: deny`, `release: false` and `native_provenance_unrecordable`, followed by
a bounded reason such as `native_provenance_literal` or
`native_provenance_global_bytes`. The pending call is consumed, required contexts
remain incomplete, and the original result bytes are withheld. This does not undo
a server action that already ran.

Once history is incomplete, ordinary policy still applies. A nonsensitive
ReadOnly call can continue, and a fitting new result can be admitted. A protected
operation that would otherwise Allow or Escalate becomes Ask with
`taint-history-incomplete`. Existing Ask and hard Deny retain their stronger
outcomes. A single-use native approval permits its exact approved invocation;
it does not clear history loss or authorize subsequent work.

The authenticated native diagnostics endpoint, `GET /native/v1/instance`, adds:

```json
{
  "provenance": {
    "accounting_revision": "sw-provenance-storage/1",
    "limits": {"per_session_bytes": 8388608, "total_bytes": 67108864, "max_sessions": 512, "max_input_bytes": 262144, "max_source_bytes": 1024, "max_literal_bytes": 4096, "max_session_id_bytes": 256},
    "usage": {"retained_bytes": 0, "max_session_retained_bytes": 0, "sessions": 0, "incomplete_sessions": 0, "fingerprints": 0, "literals": 0, "legacy_unknown_history": false}
  }
}
```

These are aggregate counters and effective loaded limits. They expose no raw
result, literal, source string or per-context identifier. Existing native
instance/registry/binding fields remain. Native audit records include
`provenance_incomplete`; refusals retain the existing correlated call/binding and
content hashes without storing raw content.

The legacy HTTP hook has already received a host event and cannot retract content
from a model context. Its fail-open host behavior remains visible. The fixed
`legacy_unknown_history` state makes missing legacy history conservative; this
increment does not turn that hook into the native execution boundary.

## Lifecycle and recovery

An authenticated end or expiry retires an isolated native epoch and releases its
accounting. Repeated start cannot reset an existing loss marker. A reconnect gets
a fresh private epoch, but it does not clear the shared host's history. One child
ending, an unrelated collector exiting, a hook end while children are active, or
a single approved action cannot erase shared history.

For an isolated context, finish or cancel its pending work, discard its model
context and derived plans, then close the collector through its normal lifecycle.
A new context can use the recovered tracking capacity. For a shared host, the
current runtime has no authenticated final host-retirement endpoint. Its charged
entry remains even after the last collector closes, until the daemon exits.
Capacity recovery demonstrated here applies to isolated/private epochs only.
Child retirement or reconnect cannot reset shared-host history. There is no unsafe
reset command. A new Agent instance requires the operator to discard old host
contexts and stop their collectors first. The Agent cannot attest that the host discarded a model context;
renaming a session or restarting the daemon while reusing that context is unsafe.

When investigating saturation, inspect the effective limits, `retained_bytes`,
`max_session_retained_bytes`, `sessions`, `incomplete_sessions` and the native
refusal reason. Limits are immutable after tracker construction; editing configuration does not
hot-reload them. Raising a byte limit requires a restart and declared fresh
contexts, after the old host contexts have been discarded. It cannot reconstruct
lost evidence or make reuse of an old context safe.

## Required owned Linux demonstration

Build and run from a clean exact candidate with Python 3 and Linux procfs:

```sh
cargo build --locked -p agentfw --bin agentfw
python3 -B -m unittest discover -s scripts/tests -p test_sou72_provenance_budget.py -v
python3 -B scripts/verify-sou72-provenance-budget.py --run \
  --agentfw "$PWD/target/debug/agentfw" --expected-commit "$(git rev-parse HEAD)" \
  --output /tmp/sou72-provenance-evidence
```

The output directory must be new and outside the candidate checkout. Omitting
`--run` prints the procedure without executing it. With `--run`, unavailable
Linux/runtime prerequisites fail; they never become a passing skip.

The driver starts the production Agent daemon and generic native-admission MCP
collector with an owned Python fixture. `read_metadata` returns synthetic
untrusted text. SideEffecting `publish_note` exclusively creates a disposable
file. The parent calibrates useful execution and independently observes exact
bytes, hashes and publication absence; backend dispatch records supplement that
file witness. No original filesystem profile, paid model or external service is
required. This tests native provenance enforcement, not a new sandbox profile.

The cases exercise byte-budget pressure and early-marker eviction, correlated
unrecordable-result withholding, duplicate-value accounting, useful work below
budget and after saturation, an unaffected peer, hard Deny, single-use approval
with sticky history, global pressure, session-capacity refusal/recovery, shared
child exit/reconnect, an admitted RPC failure, and dispatched cancellation whose
result never reaches the client. Cancellation after dispatch is reported as such;
result withholding does not imply zero backend executions.

`report.json` records exact source/tree, Agent/driver/fixture identities,
configuration/policy/registry hashes, effective limits, bounded charged-accounting
samples, independent file witnesses and owned process cleanup. Sampled daemon
and collector RSS is in a separate section and is not graded as the tracker
budget. The required [Linux workflow](../../.github/workflows/provenance-memory.yml)
prints a bounded JSON summary even on failure and retains sanitized evidence for
30 days. A passing control-test suite alone is not evidence that the Linux
production demonstration ran. This increment does not claim Phase 4 completion.
