# Reviewed selective CI consumers (SOU-221)

This is a closed registration in `scripts/ci_impact.py`, based on accepted main
`2a5bf6771c63c6ccf2c55d07dede512a72f26481`. The three Python files are
pinned to their reviewed base Git blobs. A later base revision requires a new
registration review. All paths outside the table retain the existing planner
classification, including full qualification for shared helpers, CI and
registry changes, generated evidence, unknown paths, and ambiguous consumers.

| Exact changed path | Executing consumers selected | Reviewed dependency boundary |
| --- | --- | --- |
| `scripts/check_docs.py` | `ci.yml` documentation and test | Both jobs run the checker and its unit tests. `scripts/local_pr_verify.py` and `scripts/ci/wall_python_linux.py` also call it as local feedback, without GitHub qualification authority. Only edits preserving the complete executable AST retain this reviewed closure. |
| `scripts/tests/test_check_docs.py` | `ci.yml` documentation and test | Both jobs discover the tests; they execute `check_docs.py` against owned Markdown fixtures. Only edits preserving the complete executable AST retain this reviewed closure. |
| `scripts/tests/test_macos_relay_headers.py` | `ci.yml` test | The general `scripts/tests/test_*.py` discovery executes its HTTP-header refusal witness. It imports `macos-file-acceptance.py`; that dependency's reviewed base blob is pinned. Only edits preserving the complete executable AST keep this plan. The macOS acceptance harness itself remains full when changed. |
| `docs/operations/ASK_INBOX.md` | `ci.yml` documentation | Non-executable operator guidance; the documentation job checks links and anchors. No workflow or source script reads it as a runtime input. |
| `docs/operations/GIT_LOCAL_REFERENCES.md` | `ci.yml` documentation | Same documented-only boundary. |
| `docs/operations/PILOT_PROVIDER_PROFILES.md` | `ci.yml` documentation | Same documented-only boundary. |
| `docs/benchmarks/task3_resilience.md` | `ci.yml` documentation | Non-executable benchmark prose; the documentation job checks links and anchors. |

The consumer scan covers `.github/workflows`, `scripts`, `eval`, `crates`, and
`profiles`, excluding recorded historical evidence. The documentation Python
family is explicitly invoked by `ci.yml`; its other observed references are
the local feedback tools above. The macOS relay unit is discovered by the
general `ci.yml` test job and imports its pinned fixture. The registered Markdown files have no executable
consumer reference. Markdown links to these files are read by the repository
documentation checker. Rust/native platform, gateway, identity, container,
release, and original-server jobs do not import or execute the registered
files. `test-environment.py` hashes the whole checkout into a provenance
manifest, but its test inputs are an explicit runtime-file list and do not
parse these documents or the registered documentation checker. Other generic
source digests likewise bind evidence to a commit without consuming the
changed text as runtime policy. The build producer remains selected when an existing build consumer is
selected by another changed path; this registration adds no producer edge.

## Fail-closed rules

Production scheduling reads the exact merge commit's base/head parents and
the base-to-merge change status. Trusted admission reads the current PR's
base/head/merge parents and the GitHub file status separately. Any added,
deleted, renamed, type-changed, duplicate, mixed unknown or incompletely
reported file requires the full registered plan. For the Python family, both
paths verify the reviewed base blob and compare the entire parsed executable
AST against the exact candidate. A changed assignment, alias, call, dynamic
lookup, import, control-flow expression or test assertion requires full CI;
only non-executable edits such as comments or formatting can keep the narrow
script plan. This deliberately avoids claiming static proof of Python's
indirect dependency closure. Admission reads the candidate
merge blob as bounded inert bytes and checks its Git blob digest. Absent,
oversized, malformed or inconsistent blob evidence requires full CI. A PR's
own scheduler output cannot narrow trusted admission.

Selected jobs must actually succeed, and all five CodeQL analyses remain
required on the current head. Other jobs are unexecuted; their skipped state
does not constitute qualification. Ruleset activation, status context names,
GitHub App identity and final Ready admission are unchanged.

## Fixed diff comparison

| Diff | Previous planner | Reviewed planner | Interpretation |
| --- | ---: | ---: | --- |
| `f1e13081fc` (one modified `PILOT_PROVIDER_PROFILES.md`) | 58 logical jobs | 1 logical job | Documentation still runs. Five CodeQL languages remain required. |
| Accepted PR #349 / main `2a5bf677` (two modified scripts plus one added test) | 58 logical jobs | 58 logical jobs | The new test and unregistered scripts keep full qualification. |

The 58 counts are registered logical jobs, before GitHub matrix expansion.
PR #349's observed 71 scheduled jobs are a separate runtime count. These are
modeled selections, not measured runner time or billing savings. A source
change to this planner/admission registration itself selects full CI. Final
live activation and Ready measurements belong to the team lead.
