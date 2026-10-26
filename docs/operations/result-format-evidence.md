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

## External execution/IPC acceptance contract

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
