# SOU-109 next proposal after the rejected local model

Proposal for review, following review 5618012114. No production behavior change,
new checkpoint search, policy override, fixture relabeling or task completion.

## Bounded strategy: separate evidence before changing decisions

Introduce an inspection-only evidence decomposition prototype, outside the live
detector. Its output records byte spans and reasons, never an authorization verdict.
For the existing retained corpus it should distinguish:

1. **Syntactic framing candidates:** a complete supported record/diff parse and
   exact spans of delimiters, hash fields and hunk syntax. Framing is forgeable;
   these annotations do not establish trusted provenance or safe body content.
2. **Positively typed data:** the existing bounded non-string scalar/issue-ID body
   language. Do not widen it to prose, quoted strings, paths or commands just to
   fit the original Git fixture. Check complete coverage, not a matching prefix.
3. **Unresolved content:** all other text, including commit messages, author/path
   values and diff bodies. Any parse ambiguity, unconsumed suffix, invalid encoding,
   nesting or size/depth/record limit produces explicit unsupported evidence.

The prototype records which original heuristic contributions overlap framing
versus body spans and the current unchanged-policy outcome. Every existing scanner
still receives the entire original bytes in any later production design. A model
`data` observation, a valid diff or a tool-name label cannot remove independent
findings. This proposal does not add a new generic Allow route.

Proposed prototype limits: 64 KiB UTF-8, 256 records, 4 nesting levels (if an
explicit supported grammar needs nesting), linear scanning, a bounded report with
span offsets and hashes rather than unlimited echoed source. Oversize/unsupported
returns a structured incomplete result; it must not drop a tail and call it covered.
These are proposed offline bounds, not a change to accepted runtime input limits.

## Supported and unsupported scope

| Input | Prototype purpose | Current production treatment |
| --- | --- | --- |
| Complete filesystem records with scalar/issue-ID bodies | Attribute formatting-only signals and compare existing conservative behavior | Existing typed-data handling only; all other policy/result checks remain |
| Git metadata/hunks with non-string typed payload | Explain structural spans; candidate grammar must be explicit and independently reviewed | Preserve baseline until a separate implementation is reviewed |
| Exact retained benign multi-file Git response | Keep as mandatory failing positive; show unresolved author/message/text spans | Still refused; not reclassified or replaced |
| Natural-language prose, source code, quoted strings or ambiguous framing | Explicit semantic/grammar limitation; preserve complete input and counterexamples | Conservative current boundary retained |
| Filesystem 201/256 result probes | Offline inspection only | Accepted classifier path-count limitations remain separately attributed |
| Input cases B20/B38 | Outside result decomposition | No input/classifier/policy change |

**This bounded scope does not yet satisfy the original SOU-109 acceptance.** The
retained Git fixture contains ordinary prose, so syntactic attribution alone cannot
justify releasing it. Do not report a typed-data increment as completion of the
arbitrary-prose outcome. If the full outcome remains mandatory, the next design
must explain what additional independently validated evidence distinguishes its
body from the reviewed attacks. We do not currently have that evidence.

## Independent development handoff and review gate

SOU-123 is assigned to @sake_ai. Request paired public examples with stable case ID,
pair ID, exact UTF-8 text or a file plus SHA256, expected data/instruction/unknown,
author/source and a short annotation rationale. Keep payload instructions inert.
Unknown annotations remain unknown. Validate uniqueness, pairing and bounds before
running; preserve author's labels and raw bytes. Do not request private/sealed data.

Before any proposed production change:

- Compare unchanged baseline and candidate on every retained and independently
  authored pair, reporting benign false-blocks, unsafe false-benign and unknown
  separately. Do not tune on sealed data or exclude the original failing positive.
- Every parse must either account for the complete byte range or be unsupported.
  Include trailing, split, malformed, multilingual and wrapper-forging controls.
- Demonstrate actual original-server result faithfulness/withholding and unchanged
  hard Deny/Ask, secrets/PII, taint, identity/resource and sandbox controls.
- Obtain current-source full Ready CI/admission and independent review. Draft
  checks and this proposal alone do not authorize merge or Done.

Review requested: is this inspection-only decomposition a useful next bounded
increment, while retaining the full unresolved benign Git requirement? It is not
a request to relax the boundary or silently reduce the task's completion criteria.
