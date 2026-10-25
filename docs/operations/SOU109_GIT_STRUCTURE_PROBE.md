# SOU-109 Git structure attribution probe

This is a separate model-free diagnostic after the behavior-preserving
[typed ledger](SOU109_EVIDENCE_LEDGER.md). It does not change production scoring,
policy or result delivery. A complete parse establishes syntax, not semantic
provenance, absence of instructions or execution authority.

## Frozen source and controls

Exact original ID20 `git_show HEAD` and ID21 `git_diff <full SHA>` frames come
from SOU-146 artifact 12587037385, ZIP SHA-256
`141302ea67f55ab6cc48dc72cad17b9cd85b30ae2a0b561d4a63de180243d2e7`.
The capture identity, raw original JSONL and decoded inputs are retained in
`crates/agent/tests/fixtures/result_detector/sou146-original/` with conversion
disabled. Raw frame digests agree with the author's failed-control records.
Artifact source is `2f5c3f52a865d771ad8fd99ff76c9487e695c710`, clean before/after.

ID200 retains its request, actual dispatch and withheld reply, but no separate
raw original frame in that failed-control record. Its original-byte attribution
is unknown. The matching HEAD request in ID20 does not substitute for that
missing capture or prove equality between independently installed profiles.

The parser recognizes a bounded subset of complete Git show/diff output: full
40-character object IDs, author/date framing, indented commit messages, paired
file headers, quoted Git paths and exact hunk old/new counts. Unsupported binary,
partial, malformed or ambiguous forms receive no ranges. Only the object-ID
tokens and old-file marker bytes are proposed for weak-evidence discount;
author, message, path and hunk text remains fully scanned. The model-free probe
retains every original signature/directive/secret/PII finding and original risk.
It counterfactually removes only structural contributions from the shared
`HeuristicSummary`, then uses the real policy evaluator and mandatory floors for
a fresh stateless ToolResult preview. It never dispatches or releases anything.

Before worker execution the script freezes parser/worker/source identities,
channel hashes and every parsed range. It fixes twelve matched controls: ordinary
file transmission in commit message, path, added/deleted/context lines and diff;
a strong signature; metadata decoding/adoption; malformed hunk count, partial
tail and forged commit header; and a second-channel adoption instruction.
Mutation anchors must occur exactly once in their declared first-hunk or whole
document scope. Missing/repeated/unchanged mutations fail setup. The first hunk
is selected deterministically, not searched adaptively for a passing attack.

## Reproduction

```sh
cargo build --locked -p soup-wall-agent --example git_structure_probe
python3 -m unittest discover -s scripts/tests -p test_git_structure_probe.py -v
python3 scripts/probe-git-result-structure.py \
  --inputs crates/agent/tests/fixtures/result_detector/sou146-original/inputs.json \
  --worker /absolute/target/debug/examples/git_structure_probe \
  --output /absolute/local-git-structure-evidence
```

No model assets, training, inference, paid traffic or private/held-out examples
are used. The ten-second local process timeout is unchanged. This syntax probe
does not qualify a native server, installer, active-session admission or effects.
An unsafe counterfactual is retained as a rejection, never installed to make
benign controls green. Strong findings, hard Deny/Ask, taint and exact original
payload integrity remain mandatory regardless of any future structural parsing.

The second targeted phase adds three previously frozen public signature cases
g05-a/g06-b/f05-a (`--public-inputs` points to the retained 58-input bundle).
It separately evaluates the actual policy after removing heuristic findings,
retaining all other findings and original risk. A second conservative diagnostic
obligation preserves Medium refusal for unresolved nonstructural content after
any structural discount. Neither projection is installed in production. This
tests whether pure structure attribution solves the next independent cause and
whether preserving the semantic obligation can still deliver the original cases.
