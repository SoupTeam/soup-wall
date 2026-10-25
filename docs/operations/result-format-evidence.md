# Native formatter evidence (Draft slice)

This change corrects weak separator attribution for the pinned original filesystem
`read_multiple_files` formatter. It is not a benign-content classification, a wire
permission, or completion of SOU-109. No model is required. Policy YAML, signatures,
thresholds, resource authority, result receipts, taint retention and audit-before-release
remain in force. The inherited experimental reviewer stays default off. It cannot
rescue failed attribution for this formatter or the unresolved Git `git_show` path.

`native::result_evidence::ResultEvidence` has private fields, no deserializer, and no
wire representation. The daemon derives it only after existing authenticated native
session, current receipt, invocation binding and policy checks. It binds formatter
entrypoint identity, profile/schema, contract/registry/session/call, admitted arguments,
the exact raw frame digest and all ordered original channels. Callers, hooks and MCP
servers cannot submit offsets or `trusted` flags. Such unknown wire fields are refused.

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

Audit identifies fixed-formatter attribution with the formatter identity; existing
frame/call/registry hashes retain the delivery binding. Release still depends on
current policy, retained full original evidence, and successful audit.

## Verification and remaining scope

Focused tests cover UTF-8 offsets and full coverage, fake/nested headers, body
delimiter overlap, wrong/reused bindings and args, omitted/extra/mismatched channels,
unknown formatter/schema, forged wire claims, non-native provenance, cross-channel
signatures/directives, policy changes, signature/body floors, and taint retention.
Even a test-only negative model permit cannot rescue an ambiguous formatter result.

The frozen dev set contains the same nine previously declared public-record / owned
matched controls, with their original labels and channel bytes. Four PMF argument
sets are checked by the unchanged classifier; 201/256 remain unsupported at the
existing 200-leaf bound. Those two are not utility successes. Git original channel
bytes use the selected Git profile with explicitly declared component-only call
arguments because original Git invocation arguments are not in that snapshot.
r0029 uses a generic native receipt. This is component replay, not live Git/host
qualification. No Git utility success may be inferred from it.

Run once into a new output directory:

```sh
python3 scripts/run-sou109-structural-dev.py --output /tmp/sou109-dev-new
```

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
