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

## Runnable first increment after review 5627143745

`scripts/inspect-result-framing.py` implements offline filesystem attribution,
not a production detector correction. It reads a bounded JSON-RPC result file,
rejects duplicate JSON keys and unsupported content channels, and independently
attributes every supported `content[i].text` and `structuredContent.content`.
Different channel values are never deduplicated or replaced by each other.

```
python scripts/inspect-result-framing.py crates/agent/tests/fixtures/result_detector/sou113-original/server-response-4files.jsonl
python -m unittest discover -s scripts/tests -p test_result_framing.py -v
```

The grammar is deliberately flat: ASCII absolute path plus colon, nonempty body,
standalone `---`, next path/body. LF only; no nested grammar. Paths remain
unresolved values. Separator spans are only forgeable framing candidates.
Non-string JSON scalar/issue-ID lines are typed atoms; all prose, commands,
quoted strings and tails remain unresolved. Complete reports partition every
UTF-8 byte, including line endings; failed parses return no partial spans and
explicit incomplete status. A structural `complete=true` is not a safety verdict.

Bounds: 256 KiB raw frame and total decoded text, 64 KiB per text channel,
1024 lines, 256 records/content items. The CLI reads at most frame-limit + 1
bytes; an oversized file has no whole-file hash rather than a misleading prefix
hash. Reports contain hashes/offsets/kinds and never echo payload text. This is
offline scope, not a change to the larger runtime budgets accepted in SOU-113.

Seven test groups pass: exact original 2/3/4-file captures in both channels,
different malicious secondary channel, multilingual/untrusted prose, byte-exact
coverage and appended tails, malformed/oversize/record-limit cases, invalid or
ambiguous JSON/channel shapes, and explicit unsupported Git input. Original
captures remain unchanged and all 18 hashes still verify after incorporating
accepted main 6fdbc56. No local model rerun was performed.

**Remaining blocker:** both four-file bodies and original Git prose remain
semantically unresolved. This tool cannot justify discounting their current
findings or releasing them. Git framing is explicitly unsupported in this first
increment, rather than parsed partially and called safe. Production scanner,
policy, retained positive expectations and attack fixtures are unchanged. The
30-attack independent delivery/useful-continuation qualification requested in
review has not been performed for this increment. SOU-123 public pairs remain
pending; no Ready, merge or Done qualification is claimed.

After the main refresh, `cargo fmt --all -- --check` passed and all eight
`result_detector` policy tests ran: six passed, two failed, zero ignored.
The failures remain the original benign Git response and both four-file text
channels. Existing attack controls passed. Initial local compilation was blocked
by the newly locked `ctutils 0.4.4` missing from the local offline cache; fetching
that exact crate with Cargo.lock SHA256 verification resolved the environment
failure without editing the lockfile. This does not constitute the independent
30-attack runtime qualification.
