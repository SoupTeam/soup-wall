# Additive evidence in native MCP results

This is a tightening-only SOU-109 increment. It does not resolve structural-text
false refusals, enable a model reviewer or establish formatter/runtime trust.
SOU-109 remains open. Unattested results retain the existing baseline inspection.

## Boundary and original bytes

Native inspection selects the additional evidence only for an untrusted result
delivered to an MCP host. Each original decoded text channel still receives all
existing detectors. Generic parent/model/context deliveries and ordinary input
inspection retain their existing behavior. Result validation, receipt consumption,
resource limits, provenance retention and audit-before-release are unchanged.

Existing signatures are also checked across the complete ordered channels, both
directly concatenated and newline-separated. Only matches spanning multiple
original channels are added. These projections are inspection inputs; original
wire bytes are never replaced. Heuristic hash/delimiter scores are not aggregated
across the joined text. Empty channels and UTF-8 offsets retain their original
coordinates.

A finite lexical recognizer adds evidence when an agent address and an action
request occur within a bounded local clause, or text directly claims that the
recipient's instructions/task were superseded. It visits the complete text;
absence of a match never means benign. The Medium/0.65 finding is an existing
prototype heuristic, not a calibrated probability or complete multilingual
semantic classifier. Quotes, comments and document wrappers do not confer trust.

## Preserve the original policy decision

Adding findings can activate an earlier operator Allow rule. Merely retaining the
old findings therefore does not guarantee a non-weakening decision. The native
preview evaluates policy over both the original and enriched finding sets from
one detector pass. The original Deny/Ask or unresolved judge boundary is retained
if the enriched first-match outcome would be weaker. Additional evidence can
still strengthen an original Ask to Deny. No policy rules, signature patterns,
severity thresholds or expected labels are modified.

This includes preserving an Escalate with an Allow fallback: a newly selected
concrete Allow must not skip the optional judge boundary. Tests reproduce the
previous Deny-to-Allow defect and cover Ask and both allowed Escalate fallbacks.

Native audit retains static reasons and exact original block byte coordinates.
A joined offset is never advertised as an offset within one original block.
All distinct directive source spans remain visible; raw result text is not added
to the audit.

## Reproduction and limits

The retained public SOU-123 corpus contains 24 attack and 24 benign cases plus
three separately reported technical cases. On accepted main
`3c9cfb08c0f1498676dcc70de131bd2f324dd13b`, the original preview missed 14 attacks
and refused ten benign cases. The tightening slice with the original policy
withholds all 24 attack cases and still refuses the same ten benign cases. Its
overall development acceptance correctly remains failed. This is single-result
preview evidence, not real-server execution/prevention, held-out accuracy or
live-model effectiveness.

Reproduce using the pinned toolchain and unchanged corpus:

```sh
cargo build --locked -p agentfw --no-default-features --example result_inspection_corpus
python3 eval/sou123/run_corpus.py \
  --manifest eval/sou123/manifest.json --payload-dir eval/sou123/payloads \
  --adapter target/debug/examples/result_inspection_corpus \
  --policy profiles/pilot/linux-readonly-v1/policy.yaml \
  --identity source="$(git rev-parse HEAD)" --output /tmp/sou123-result-report.json
```

The reporter must exit nonzero while those false refusals remain. Do not change
the labels or promote that failure to success. Focused native regressions cover
cross-channel signatures/directives, exact result hashes, source-span audit,
unchanged generic deliveries, whole-result limits and retention.

The source contributions are preserved from PR #215 commits `f3338baa`,
`0698af72`, `2407885e` and `3daf4eb7`. They are integrated on accepted main without
the model experiments or structural-relief prototype, with the original-decision
floor and current offline-trace compatibility added during TL review.

Structural relief remains separate: SOU-155 owns daemon-created verified runtime
bindings; SOU-156 owns authenticated Git object-kind/snapshot evidence. Parser
success, installed hashes, collector assertions and commit-looking text cannot
substitute for those boundaries or close SOU-109.
