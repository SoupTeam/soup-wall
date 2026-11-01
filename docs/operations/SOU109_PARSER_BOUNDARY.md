# SOU-109: isolated parser and future evidence boundary

This Draft originally started at `3c9cfb08c0f1498676dcc70de131bd2f324dd13b`
(#268) and now merges accepted main
`379f9f9a17ec7369acaa65455d26f745c36ab866` (#275), preserving branch history.
It supersedes #271's implementation proposal without importing that branch's
experimental model-review ancestry.
The old branch `codex/sou109-structural-evidence` at
`9cc4cb77ce1bb66effc934018dc3b401675ea01b` and its evidence remain intact.

Production behavior is unchanged relative to accepted main `379f9f9a`, including
#275's tightening and bounded positive evidence. It is not unchanged relative to
the older `3c9cfb08`. The only edit to existing Rust
is two module declarations inside `native::tests`, already gated by `cfg(test)`.
The parser and boundary controls live below that test module. There is no model
reviewer/config/permit, detector or agent API, trusted-span input, result relief
wiring, runtime launcher or Git object authority in this diff. In particular the
old result-data-review prototype is not ported. General result-directive evidence
is inherited from accepted main #275; it is not a parser relief path. No policy/signature/threshold/label/timeout changes are included.

## What the parser establishes

The test-only private `ParserCandidate` checks consistency of the reviewed
filesystem success format: `${path}:\n${body}\n` records joined by `\n---\n`.
It requires the two original selected result channels with equal bytes, exact
argument/path order, unique expected headers and boundaries, and a contiguous
UTF-8 byte partition. It records path, fixed header, body and trailer ranges;
only the fixed separator offsets are candidate formatting. Body/path bytes are
never promoted to authority, even when they resemble headers or instructions.

Unknown profile/schema, changed call/frame/argument scope, incomplete/mismatched
channels, repeated paths/headers, ambiguous ordering, oversized input and exhausted
scan budget reject the candidate. Parser bounds are 1 MiB/channel, 256 paths and
one 32 MiB charged full-text-search budget for the complete reply, shared by both
original channels. The counter reserves searches before running them; identical
channels are not deduplicated or given separate allowances. A focused test proves
that channels which each fit separately cannot together spend more than 32 MiB.
These are test-only experiment bounds, not changes to production admission limits.
A future consumer must share remaining work with #275's positive collector within
one production 32 MiB reply allowance; it must not stack two independent budgets.
The experiment's `Option` candidate and budget-exhaustion marker do not implement
the future typed production failure/audit interface.

Scope hashes cover static formatter identity, contract, registry, session, Call,
tool/schema, call binding, argument digest, raw frame and ordered channels.
They detect inconsistent inputs; they do not authenticate execution, live session,
receipt expiry or origin. `ParserCandidate` is not an authorization certificate.
A different executable can emit identical bytes and satisfy every syntax check.

## Production controls in this Draft

`successful_parser_candidate_without_runtime_witness_keeps_native_baseline`
constructs a real native receipt under the selected filesystem profile/schema,
then demonstrates that a successful parser candidate does not change native's
refusal. It checks ordinary 50-file output and its instruction-bearing control,
the untouched raw-frame hash, receipt consumption and replay rejection.

`commit_shaped_git_blob_without_kind_or_sealed_view_witness_keeps_baseline`
keeps refusal for commit-shaped Git bytes and their instruction-bearing control.
A blob can contain those same bytes. This synthetic control does not launch Git
or establish resolved object kind. The original owned-blob evidence remains in
#271's preserved branch; it is not recast as current-main qualification.

`wire_cannot_supply_future_execution_or_object_authority` verifies that forged
trust/span/evidence/runtime/object-kind/sealed-view/permit fields are rejected by
the existing strict native request parser. The untouched ordinary two-file result
still receives the existing baseline Allow. Baseline-only means no lowering an
existing finding or verdict, not a new blanket refusal for ordinary content.

The six parser tests cover Unicode/full partition, ambiguous/repeated
headers, wrong order/path, errors/bounds, wire claims and mutated scope/channel
inputs. These are component controls, not the full public dev corpus, model
accuracy, runtime binding acceptance or original-host utility qualification.
No new full-corpus efficacy claim is made. SOU-109 stays open.

## Contract to consume future SOU-155 / SOU-156 evidence

SOU-155 (Nariman / @Nari_Ab) owns verified Linux launch and authenticated
runtime/Call/result IPC binding and can start immediately. Waattoo owns the
remaining SOU-142 outside-cleanup-owner-loss work; SOU-155 does not wait for it.
SOU-156 (Olzhas / @konung3) owns original Git resolved-object-kind/sealed-view
evidence. Their assigned contract is due October 27 at 12:00 and delivery
October 28 at 12:00. This Draft neither waits for
nor duplicates those implementations. The contract below specifies required
properties, not a new wire schema or a collector-supplied trust flag.

| Required evidence/check | Owner | Consumer behavior on absence or mismatch |
| --- | --- | --- |
| Executable/runtime/package verified at actual launch; no replacement gap between verification and execution | SOU-155 | Preserve actual-main baseline |
| Authenticated daemon-owned execution identity and epoch/session through collector IPC | SOU-155 | Preserve baseline; static SHA/profile/liveness alone is insufficient |
| Same registry/profile/schema, admitted tool/arguments, exact Call/receipt and execution | SOU-155 | Reject crossed/stale/replayed witness; never use parser offsets as authority |
| Same complete raw result frame and ordered original channels, including duplicate/empty channels | SOU-155 | Preserve baseline on changed, missing, extra or reordered data |
| Git selector resolved to verified object kind/id in the same sealed view used for the returned result | SOU-156 plus SOU-155 binding | Preserve baseline for unknown kind/view and commit-shaped blobs |
| Full original evidence retention, current policy and successful audit before any release | Existing native boundary | Preserve original refusal/fail closed on admission or audit failure |

SOU-155 owns the private one-use common join capability consumed by SOU-156.
It is not the collector ingress token and cannot be supplied as a trust flag.
The future consumer must verify that capability and join execution evidence,
Git evidence where needed, parser scope and every ordered original result byte.

TL integration decision: no generic override of a raw verdict. Attribution may
discharge only weak formatter contributions with proved exact origin/coordinates
and an exclusive causal role in the injection refusal. Independent secret, PII,
taint, signature, directive, path/body findings, Ask/judge floors and opaque policy
cases preserve baseline. Ordinary #275 preview/floors stay unchanged. This Draft
does not implement that causal-discharge decision or promise semantic quote or
signature false-refusal fixes.

Optional proof absent selects baseline; invalid native Call/receipt refuses;
exhausted shared work/evidence budget gives incomplete Deny/not-inspected, never
a clean miss or a caught-attack score. Parser ambiguity grants no attribution.
Full original retention and durable audit-before-release remain required.

Acceptance must exercise the actual verified launch -> IPC -> native Call ->
result path. Include another executable producing identical output, replaced
runtime/package, wrong epoch/session/Call/arguments/frame/channel order, expired or
reused receipt, and Git blob/tree/unknown-kind or changed-view controls. This Draft
implements none of those runtime/object witnesses and claims no passing tests for
them. Independent acceptance is required before any production relief reconnects.

## Reproduction

Use the repository pin Rust 1.99.1 and no model features:

```sh
cargo test -p agentfw --lib --no-default-features native::tests
cargo check -p agentfw --lib --no-default-features
```

The focused subset is `native::tests::result_parser` (six parser and three native
boundary tests). Exact source/diff, compiler identity and final check logs accompany
the handoff. Production inspection uses accepted main's bounded
`mcp_result_evidence` and `preview_native_mcp_result` for untrusted MCP-host results;
its other deliveries retain their existing preview path. No parser offsets or
candidate authority are connected to either production path.

Remaining consumer interfaces are intentionally unresolved here: the private
capability/expiry/consumption schema and exact frame/channel custody from SOU-155;
the same-capability object-kind/OID/sealed-view witness from SOU-156; and a typed
shared-budget/causal-discharge integration that preserves every independent floor.
All require separate implementation and acceptance before production relief.
