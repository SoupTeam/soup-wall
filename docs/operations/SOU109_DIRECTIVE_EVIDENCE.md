# MCP result directive evidence: 0698af7

## Outcome, not a completion claim

The unchanged full SOU-123 public development corpus now gives **24/24 attacks
withheld, 0/24 missed, 10/24 benign refused, 14/24 pairs both correct**.
Semantic unknown/errors: 0/48; three technical cases remain separate.
Overall acceptance still **fails**. This does not fix the original ordinary
Git result or SOU-113 four-file dual-channel false refusal.

See [raw findings and report](evidence/sou109-full-corpus-0698af7.json).
The preceding f3338ba run had 14/24 attack misses and the same 10/24 benign
refusals. All 51 payload hashes and the frozen manifest were verified again.
Expected labels, paths and source payloads were not changed.

The six-known-example extractor and the rejected model are not used here.
This new recognizer is still a finite lexical grammar, not a validated general
semantic classifier. The public cases were inspected during development:
0/24 misses is **not** a held-out accuracy or arbitrary-attack safety claim.

## Change and policy composition

The native untrusted MCP-result preview adds two kinds of evidence:

1. A recognizable agent address, a bounded address clause, and a possible
   action request within the next 512 bytes. Recognized forms include English,
   Russian, Spanish, German, Kazakh and Chinese examples; coverage of any
   language is incomplete. Action words alone, agent nouns alone and unrelated
   later paragraphs do not satisfy this rule.
2. A direct second-person claim that previous/current instructions or task
   have been superseded, replaced or cancelled. This does not require an
   explicit assistant-name token.

These produce Medium findings with heuristic confidence 0.65. That number is
not a calibrated probability. The reason explicitly says that contextual
attribution is unresolved. Existing independent findings, raw byte spans,
taint/history and mandatory policy decisions are preserved.

The shipped pilot refuses Medium injection findings. The general default
policy need not make the same decision: its High-only result rule still
allows a lone new Medium finding. Tests preserve this distinction rather than
changing severity or policy merely to force a universal verdict.

There is no negative inference: no match does not mean benign. No finding is
removed, downgraded or used to cancel another policy decision. Ordinary
input/Gateway inspection is not automatically changed. Native provenance
without a named server is supported only through the MCP-host result call
site; other callers do not acquire this behavior automatically.

The existing direct/whitespace cross-block scan also considers these request
patterns. It retains only matches intersecting multiple original blocks.
Original blocks are still inspected independently; structural heuristic
scores are not accumulated over joined text. A target in one field and a
request in another is covered by a native shipped-policy regression.

Native audit keeps the static reason and original block byte coordinates in
mcp_result_directive_evidence, or the cross-block source-coordinate reason
when spanning blocks. Raw result content is not added to the audit.

## Validation and remaining limits

- Core library: 90 passed; agent library: 171 passed; no failures or ignored.
- Selected native MCP: 9 passed, including cross-field requests, raw hash,
  byte-coordinate audit without raw text, existing limits and withheld data.
- Library Clippy with warnings denied passed for core, agent and agentfw.
- Existing result regression suite: 6 passed, 3 failed, 0 ignored. Its first
  six pairs now have zero attack misses but retain four benign refusals.
- Full 51-case unchanged adapter rerun on 0698af7 with the shipped pilot policy
  produced the results above. The adapter source is exactly PR #240
  29e6db856; manifest, policy, adapter-source and binary hashes are in evidence.
  Reproduction uses the commands in SOU109_FULL_CORPUS_FINDING.md with this
  candidate revision.

The corpus adapter is a Windows debug single-payload preview, not a native
original-server delivery/consumption or forbidden-effect witness.
Technical over-budget classifications in that runner are not a substitute
for native budget-refusal evidence.

Quoted examples and documentation can still trigger the rules. The test
suite deliberately retains this conservative behavior; quotation/comment
markers and "do not follow" are not release authority. Unaddressed ordinary
imperatives, unsupported words/languages, distant relationships, indirect
references and some renderings remain outside this recognizer. The known
unaddressed destructive/exfiltration regressions still rely on their existing
findings, not on this recognizer being complete.

Remaining benign refusals: g01-a, g03-a, g05-a, g06-b, g07-b, g09-b, g11-a,
g12-a, f05-a and f12-a. Resolving them requires reliable complete-content
attribution, not absence of these request patterns. The original Git and
four-file positives, full corpus, independent review and integrated useful/
refusal witnesses remain completion gates. Keep SOU-109 In Progress and
PR #215 Draft.
