# Result detector framing: incomplete conservative revision

**Draft / not qualified for completion.** Independent review of `0902167` found
that the expanded keyword/resource list still released direct destructive and
ordinary-file transmission instructions inside recognized diff/file framing.
Full Ready CI passed that source but did not cover these cases. The new regression
first reproduces its `Allow` and now requires `Deny`; it also includes French and
Russian instructions without any of the former address/role keywords.

The current revision removes all diff-header discounting and the expanded
address/resource keyword lists. Git retains accepted-main delimiter scoring.
Filesystem separators can be discounted only when every record body positively
matches a narrow data grammar: JSON non-string scalar literals or uppercase
issue identifiers (e.g. `ABC-123`). Every record needs a bounded-character absolute
path header and a nonempty body. Quoted strings, free prose, code, malformed
records and unknown syntax are not treated as harmless because a keyword is absent.
Existing imperative evidence still preserves all delimiter reinforcement even in
an otherwise typed record. Signatures, whole-text secret/PII checks and policy
floors remain unchanged. Repeated recognized records with unresolved bodies retain
a Medium finding rather than silently reducing evidence; this can also refuse
benign prose. Unsupported framing keeps baseline scoring.

This is a partial, conservative implementation, not a new completion criterion.
The public filesystem `SOU-97` records for 50/200/201/256 are within the data grammar;
unit/policy checks pass. That does not grant a tool or filename trust. The 201/256
execution limit and B20/B38 separation remain unchanged.

The exact retained ordinary multi-file Git response contains free prose. It is
still refused. **`recorded_original_multifile_git_show_is_released` remains active
with expected `Allow` and currently FAILS**; it has not been skipped, relabeled,
replaced with a numeric fixture or weakened. The original-server positive byte
comparisons remain mandatory and are not reported green for this revision.

Local evidence: six result-policy tests now have five passes and this one known
failure. The new destructive/transmission cases pass after failing on `0902167`.
Core tests and core/agent Clippy pass; the complete agent command is not passing
because of the unresolved Git positive. Runtime drivers retain all benign gates
and now contain four Git attack payloads and nine filesystem attack payloads.
They have not been qualified on this revision. Do not reuse older artifacts as
proof that the current task is complete.

## Remaining design decision

Arbitrary source prose needs a reviewed decision about semantic uncertainty;
format alone or another verb/address/resource list is insufficient evidence of
benignness. The current code retains refusal. A proposed next step is to agree
on an explicit semantic-inspection contract and evaluation (including abstention,
malformed/error/timeout behavior and the retained benign/attack pairs), with
unresolved results still refused by policy. No external model access, spending,
new authorization path or threshold change has been introduced. This proposal
requires maintainer agreement and does not close SOU-109.

## Historical evidence (superseded implementations)

The following provenance and successful/failed runs predate the conservative
revision. They are retained for reproducibility, not as current qualification.
Descriptions of earlier discounting or numbers of attack cases are historical.

## Evidence and controls

`crates/agent/tests/fixtures/result_detector/git-multifile-show.txt` is the exact
original-server text from SOU-107 Ready run `39603080085`, artifact `12347572182`,
member `sou107-git/multifile-original-show.txt`. Archive SHA-256:
`45c3a452e82dafc5490f1ae652870e26699fc239c1b7d35db72a3dc8ae1aa3db`.
Original text SHA-256:
`487c2aa2085289d02bfb268cc132093aa5fc88283ad5ca5a4d6b95f6efc04f33`.
The original refused response remains in that artifact.

Filesystem PMF-B16-B19 are 50/200/201/256 reads of
`/workspace/src/file_NNN.txt`, seeded with `SOU-97\n`, from PR #213 source
`d12827e5a56294995798e2cfd016c3b887c1f28c`.
The retained failed runtime run is `39557437555`, artifact `12326915042`.
Its replay file records withheld responses, not the withheld original text.
The newer exact-head artifact `12330512159` at
`f9afeaf235554a21cb5b3587757ca0db95b22631` was also verified (archive SHA-256
`932510584c0f7387fc0d8fb572b1455f0f9dd8b5bc67e40ec4bb6dcc5e722822`).
`filesystem-before.json` retains its six relevant cases and original identity
hashes, including the distinct zero-dispatch B20/B38 outcomes.
The local text fixtures reconstruct that documented shape; they are not labeled
as captured responses. The extended existing filesystem acceptance driver
executes the original unwrapped server for all four counts and attempts all four
through the protected path, retaining both responses. The accepted classifier
supports arrays only through 200 elements: 201/256 remain explicit `unsupported`
pre-dispatch `classifier_ask` outcomes with zero repository opens. They are not
successful protected reads and are not fixed by this detector change. The
unchanged-policy detector tests cover all four result shapes independently.
For 50/200, comparison normalizes only the host workspace
prefix to `/workspace`; production responses are never changed.
Both original and protected JSON-RPC byte frames are retained separately. Kernel
OPEN observations independently witness each bulk read. Matched original-server
attacks put seven payloads in the same 50-file response: existing instruction
override and its whitespace-split variation, the review attack and split address,
role-addressed transmission, shell exfiltration syntax and Russian addressing. Those results
must be withheld after observed execution; this does not undo server reads.

The existing Git acceptance fixture now has four files in its initial commit.
Its existing six-read original/protected comparison therefore exercises a real
multi-file `git_show`, retaining injection, cancellation, denied execution,
network/write and cleanup controls. Two additional Git objects carry the exact
review payload beside raw hashes/dashes and inside the retained multi-file diff;
both must have observed repository reads and the exact withheld envelope, with
original/protected byte frames retained. Existing filesystem security controls also
remain required. PMF-B20/B38 are pre-dispatch action refusals and are outside this
result-detector fix; no expected labels are changed.

Run `cargo test --locked -p soup-wall-core` and
`cargo test --locked -p soup-wall-agent` for detector and unchanged-policy tests.
The existing opt-in `mcp-real-filesystem.yml` and `mcp-real-git.yml` workflows
exercise real original servers. Unit/policy results alone do not qualify runtime
execution or result delivery. Attack regressions place override, exfiltration,
role impersonation, chat-template and stacked-imperative content in the same
headers, bodies and suffixes as benign data.

As a local before/after control, replacing only `heuristics.rs` with accepted
main `7af550291782cf3c11cffc8d7b30bb071f4bf5e9` makes all three benign regression
tests fail with Deny while the attack test passes. Restoring this correction
makes the original four pass. This historical control predates the review regression
and does not claim an original-server execution or resolution of that regression.

Failed first Linux filesystem run `39629133139` (source `e7dddb2`) retained the
successful 50/200 releases, then failed because the driver expected 201 to be
supported. Artifact `12358468030`, SHA-256
`126a5ccbafc36e81b577dcff1e0b47f6e45adf7a7c569d80379b7670b3c2e10e`,
shows the distinct classifier refusal before dispatch. The subsequent driver
records that existing limit explicitly; it does not weaken or bypass Ask.
