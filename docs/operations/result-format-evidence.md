# Result parser prototype: baseline-only Draft

SOU-109 remains open. This Draft does not enable filesystem or Git relief in
native/1. The filesystem parser and its scoped evidence object compile only under
`cfg(test)`. Production supplies no attributed spans, retains every original weak
signal and does not invoke the experimental model reviewer. Configuring a reviewer
is rejected; even a complete test-only DataPermit cannot lower native/1 baseline.
Positive signature/directive evidence can strengthen an assessment. Policy YAML,
signatures, thresholds, authority, receipts, original evidence retention and
successful audit-before-release remain required.

## Missing trust edge

A static entrypoint SHA/profile/schema identifies reviewed source, not the process
that produced a result. Collector liveness authenticates instance/epoch/owner;
child grants cover server/tools/resources. Neither authenticates the launched
executable to the native Session/Call. The sandbox checks package/runtime files
when launching, but no authenticated runtime witness reaches native result
inspection. A collector can therefore submit plausible equal formatter channels
under a correct registry/profile/schema and a current receipt without proving that
formatter ran. The regression
`matching_profile_from_unverified_other_runtime_cannot_claim_formatter_origin`
keeps that result denied. The earlier relief implementation failed this control.

Relevant boundaries are `native/liveness.rs`, `native/child_authority.rs`,
`mcp/admission.rs`, `mcp/admission/real_server.rs`, and `mcp/server_sandbox.rs`.
Private fields, no deserializer and scope hashes prevent wire forgery of a parser
object; they do not supply the missing runtime provenance.

## Parser component contract (test-only)

The successful pinned Node formatter emits `${path}:\n${body}\n` records joined by
`\n---\n`, and duplicates the complete string in the two original result channels.
The proof requires both original channels, equal values, exact admitted path order,
one occurrence of every expected header, exactly one complete boundary for each next
record, and a contiguous role partition covering every UTF-8 byte. Paths and bodies
remain untrusted. Only the three hyphens of proven fixed separators are attributed.
Duplicate paths, nested/repeated expected headers, errors, incomplete parsing,
unknown identity/schema, mismatched channels/bindings, and work-budget exhaustion
produce no attribution. There is no greedy boundary choice or recursive search.
The charged full-text searches are bounded to 32 MiB per channel / 64 MiB total.

The detector inspects original full strings, not a body-only replacement. Any residual
body/path/unknown delimiter, imperative or opaque-token contribution preserves the
original aggregate heuristic severity/confidence. Signatures and other detectors
are never subtracted. Positive recipient/action and supersession findings use the
existing general result visitor, independently of attribution. Original per-channel,
ordered concat/newline and complete historical-envelope signature paths remain.
Absence of any positive finding is not the attribution proof and creates no grant.

No formatter attribution or model-data audit marker is emitted by production.
A direct component preview with parser offsets is a parser experiment, not a
native release or real-server qualification.

## Relief wiring removed or isolated

Compared with the earlier ac32bec prototype, the final Draft:

- Gates the entire native `result_evidence` module under `cfg(test)`; production
  cannot derive or consume its parser certificate.
- Removes `ResultEvidence::derive`, nonempty `attributed_spans` and formatter
  relief selection from native result inspection. Every production MCP result
  receives empty attribution plus additive positive evidence only.
- Removes the `complete_data` / `review_used` path and the call to
  `preview_native_result_after_data_review_with_positive` from native/1.
  A matching test-only permit is ignored.
- Removes reviewer invocation from the handler and worker startup from native
  configuration; `with_result_data_review(Some(...))` fails before startup.
- Removes native formatter-attribution and model-data relief reason/audit markers.

Core/agent attribution-preview APIs remain component prototype primitives; they
are not a production origin authority. Reconnecting them or changing the empty
spans requires a separate reviewed change after independent binding acceptance.
Commit-shaped Git blobs retain baseline through the same production path.

## External execution/IPC acceptance contract

Assigned follow-ups (recorded by the parent in SOU-109): SOU-155, @Nari_Ab,
provides daemon-owned verified Linux launch and runtime/Call/result binding over
IPC after the remaining SOU-142 boundary; SOU-156, @konung3, provides the original
Git resolved-object-kind/sealed-view witness. Their contract is due October 27 at
12:00 and delivery October 28 at 12:00, per the assignment. This Draft does not
wait for or duplicate either implementation.

The parent-owned follow-up must provide a daemon-owned verified launch binding;
this Draft adds no launcher or authority service. Before any relief can be enabled:

- Verify executable/runtime/package identity at the actual launch, with immutable
  file handles or equivalent protection against replacement between check and exec.
- Authenticate that launch identity through the collector IPC to the native
  session, registry/profile/schema and exact admitted Call/arguments. Bind the
  returned original frame and ordered channels to that same execution and receipt.
- Reject absent, stale, replayed, crossed-call/session/runtime or mismatched
  witnesses. Collector-supplied strings and static hashes alone are insufficient.
- Preserve current policy, all original body/path bytes, positive findings,
  receipt consumption, evidence capacity and audit-before-release. Unknown origin,
  parser ambiguity, budget exhaustion and failed evidence retention keep baseline.
- Demonstrate the actual verified launch -> IPC -> Call -> result path and matched
  attack controls, including another executable producing identical output.
  Unit parser success is not acceptance of that path.

The future consumer must join daemon-verified execution evidence with the parser's
exact registry/session/Call/arguments/frame/ordered-channel scope. Neither a wire
`trusted` flag, a model permit, an entrypoint hash nor parser offsets can construct
that execution authority. Witness verification must precede selecting any
nonempty attribution; a failed join selects the unchanged baseline.

Git additionally needs the object-kind/resolved-id/snapshot evidence below.
The follow-up must be separately reviewed before removing this baseline-only gate.

## Verification and frozen dev replay

Tests cover UTF-8 offsets/full coverage; fake, repeated and nested headers;
body delimiter overlap; wrong/reused bindings and arguments; channel mismatch;
unknown identity/schema; forged wire claims; non-native provenance; cross-channel
signatures/directives; current policy; and evidence capacity. Native controls
retain refusals with or without a matching test-only model permit.

The frozen dev set preserves all nine earlier declared public-record/owned cases,
labels and original channels. The unchanged classifier marks PMF201/256 unsupported
at its existing 200-leaf bound. Git channels use declared component-only call
arguments because the snapshot lacks original invocation arguments; r0029 uses a
generic native receipt. This is component replay, not live Git/host qualification.
The final run uses the existing daemon evidence capacity (10,000 entries), not the
earlier fixture's artificial 1,024-entry limit. Neither unsupported case is a
utility success. No model is called, and no input is relabelled after a result.

Run once into a fresh directory:

```sh
python3 scripts/run-sou109-structural-dev.py --output /tmp/sou109-dev-new
```

Final run metadata and the preserved earlier failed origin control are in the
adjacent evidence directory. The earlier pre-gate run is historical evidence only;
its apparent filesystem release did not establish verified runtime origin.

### Explicit Git gap

No Git formatter bytes are exempted. The original multi-file `git_show` and its
same-SHA/separator malicious control remain in the dev set without relabelling.
The official `mcp-server-git` 2026.10.10 function emits both commit patches and raw
blob content through the same string return type. A direct owned-repository
counterexample returns a blob whose bytes equal the captured multi-file commit
output; `git-gap.json` records the selector, package/source identity and returned hash.
This uses the existing local Git runtime, not protected pinned-Git qualification.
Syntax alone is not a proof of formatter ownership. In particular, HEAD inspection
needs a verified resolved object-kind/id and snapshot witness bound to the same
result, or an independently reviewed equivalent proof. That witness is not added
here. A future Git adapter may use the same private evidence contract; this Draft
does not claim the original Git utility repro is fixed and must not close SOU-109.
