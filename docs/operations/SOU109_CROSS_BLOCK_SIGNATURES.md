# MCP result signatures spanning text blocks

This is a partial SOU-109 correction, not resolution of structural false
refusals. Review 5637230812 permits contextual signature attribution and asks
for attacks split between original channels. That scope question is resolved.
No further permission is needed to continue within those reviewed boundaries.

## Reproduced gap and change

An original selected MCP response containing "Ignore all" in content text and
"previous instructions" in structuredContent was released: neither individual
block contained the full lexical signature. The new native regression failed
on the previous implementation, then passed with this change. It also covers
a split inside a word and attacks inside quotation/comment wrappers.

The native MCP result path now inspects existing signatures across the ordered
decoded blocks using direct and whitespace joins. It keeps only matches
spanning at least two original blocks. It does not run aggregate hash,
separator, imperative-count, secret or PII scoring on the joined text. Every
original block still undergoes its ordinary independent detector inspection.

Additional signature findings enter the existing policy evaluation before
release. They cannot override Deny/Ask or suppress any previous finding.
Activation requires a result delivered to an MCP host and an operator-registry
untrusted provenance. Native provenance without a server ID is supported;
human/local-project result events and other surfaces do not acquire this
cross-block behavior automatically.

No original response bytes, receipt binding, result identity, budget,
taint/admission behavior, approvals or policy presets are changed. A refusal
spends the invocation and does not record withheld text as admitted context.

## Observable evidence and limitations

Cross-block findings retain the original static signature label and the exact
UTF-8 byte ranges for each participating block, in result-block order. Their
single-text span is unset: a synthetic joined offset must not masquerade as an
offset in one original block. Native audit adds
cross_block_signature_evidence containing these static reasons/coordinates,
not raw response text. Existing independent findings remain present.

The contextual decision is explicitly **unresolved**, so the policy retains
conservative signature treatment. This does not establish that every lexical
hit is an operative instruction. Joining unrelated fragments may cause false
interruptions, which must remain visible. Quotes, comments and benign cover
are not release authority. Matching arbitrary prose, alternate render orders,
inserted non-whitespace markers or encoded directives is not solved.

The two joined scans operate over already bounded, fully decoded native
inputs. No prefix truncation or model call is added. Source-span lookup starts
at the first overlapping block rather than scanning every block per hit.

## Validation

- Core and agent library suites: 87 and 170 passed, zero failures/ignored.
- Selected native MCP tests: 7 passed, including complete large-channel scans,
  invalid/extra/duplicate field refusals, per-text recorder caps, unchanged
  useful byte retention, split-signature refusal, receipt hash, no admitted
  withheld content and audit evidence.
- Core controls cover all six signature patterns, UTF-8 byte offsets, empty
  intermediate blocks, no duplicated within-block match and no accumulated
  structural heuristic score.
- Agent controls verify surface gating and an unchanged operator default Deny.
- Library Clippy with warnings denied passed for core, agent and agentfw.
- Existing result-detector regressions remain **6 passed / 3 failed / 0 ignored**:
  original Git positive, original four-file dual-channel positive, and first
  six public pairs. Expected labels are unchanged.

The full 51-case public corpus was rerun on f3338ba using the unchanged PR #240
adapter and shipped pilot policy:
[retained raw results](evidence/sou109-full-corpus-f3338ba.json).
All per-case verdicts match the preceding 320cf9a run: 14/24 attacks missed,
10/24 benign refused, 0/24 pairs both correct. This single-payload preview does
not exercise native cross-block assembly and must not be presented as improved
by a cross-block-only correction. The remaining implementation is still a reviewed
complete-content distinction that releases benign results reliably. Native
original-server delivery/forbidden-effect witnesses and independent acceptance
remain required; keep PR #215 Draft and SOU-109 In Progress.
