# Result detector framing regressions

The shared injection heuristic previously counted ordinary `---` filesystem
separators and unified-diff old-file headers as instruction delimiters. Three
separators emitted a Low injection finding, which the filesystem profile denies.
Combined with a Git SHA (matching the existing base64-shaped-token heuristic),
they emitted Medium, which the shipped Linux pilot policy denies.

The change discounts only a standalone `---` line and the first three dashes of
a `--- ` line immediately followed by a `+++ ` line. Remaining punctuation,
filenames and body text still reach the original detectors. There is no tool,
server or filename allowlist, no result rewriting, and no policy/classifier change.
Other delimiter forms, imperative scoring, base64-shaped token scoring and all
signature checks retain their previous behavior. If imperative language is present,
all delimiter reinforcement retains its previous weight, including ordinary framing.
This is a heuristic correction,
not a claim that diff-shaped text is trusted or that all injection is detected.

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
attacks put instruction override in the same 50-file response, including a
whitespace-split variation supported by the existing signatures. Those results
must be withheld after observed execution; this does not undo server reads.

The existing Git acceptance fixture now has four files in its initial commit.
Its existing six-read original/protected comparison therefore exercises a real
multi-file `git_show`, retaining injection, cancellation, denied execution,
network/write and cleanup controls. Existing filesystem security controls also
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
makes all four pass. This control does not claim an original-server execution.

Failed first Linux filesystem run `39629133139` (source `e7dddb2`) retained the
successful 50/200 releases, then failed because the driver expected 201 to be
supported. Artifact `12358468030`, SHA-256
`126a5ccbafc36e81b577dcff1e0b47f6e45adf7a7c569d80379b7670b3c2e10e`,
shows the distinct classifier refusal before dispatch. The subsequent driver
records that existing limit explicitly; it does not weaken or bypass Ask.
