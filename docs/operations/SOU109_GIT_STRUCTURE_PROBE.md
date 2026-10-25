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

## Minimal context-relation integrity mechanism

`result-context-relations.py` supplies the mechanical part of a contextual
adjudication protocol: ordered length-prefixed channel hashing, full UTF-8 byte
partitions, typed mention/description/adoption/action scopes and source-indexed
`describes`/`adopts` edges across the whole result. It rejects stale source,
dropped or overlapping scope coverage, invalid UTF-8 ranges, unsupported origin
fields, duplicate or cyclic relations. Limits are 1024 channels, 8 MiB source,
65,536 scopes and 65,536 edges. Source bytes are encoded once for range checking;
the checker does not repeatedly decode whole prefixes for every scope.

No role label or metadata establishes authority. Every origin remains untrusted
MCP; even a structurally valid graph claiming only mentions has enforcement
`unresolved` and `semantic_validation=not_performed`. A deliberately false but
structurally valid annotation is an explicit regression: it cannot authorize
Allow. The missing component is a qualified source-wide semantic adjudicator,
not another regex exception or a claim that syntax proves benign intent.

The synthetic graph controls fix Russian, Spanish and German described/adopted
pairs, both adjacent and after 400 ordinary lines, within and across channels.
Reference roles/relations are manually supplied. Their successful validation
tests integrity/coverage only; it does **not** mean the checker understands those
languages or independently detects adoption. Actual current result preview is
also retained. Per-channel `[Deny, Allow]` aggregates to a withheld whole result,
never an attack success. Existing English quoted signatures still trigger.

```sh
python3 -m unittest discover -s scripts/tests -p test_result_context_relations.py -v
python3 scripts/probe-context-relations.py \
  --worker /absolute/target/debug/examples/git_structure_probe \
  --output /absolute/local-context-evidence
```

The runner freezes every control/source/proposal hash before executing the
worker. A separate fixed resource probe checks the maximum 8 MiB source and
65,536 scopes, with explicit refusal above the source bound. It has no semantic
efficacy claim. Previously rejected models are not repeated or qualified by this
graph; no component here can suppress production findings.

## Fresh direct ID200 reproduction

Install the shipped original Git `requirements.lock` with hashes in an isolated
Python 3.11 environment, then use that environment's interpreter:

```sh
/absolute/original-venv/bin/python scripts/reproduce-sou146-id200.py \
  --git /usr/bin/git --output /absolute/local-id200-evidence
```

The script creates an owned temporary repository and reproduces both exact
commit IDs using fixed dates, content and author. It calls the actual pinned
`mcp-server-git` package, captures a new raw ID200 frame, checks its decoded result
against retained ID20 without changing channel bytes, verifies the repository is
unchanged, and closes/reaps the original process. This is a new direct-server
witness; historical ID200 raw bytes and protected admission remain separate.
