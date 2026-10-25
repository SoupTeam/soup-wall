# SOU-109 typed result evidence

This increment preserves policy behavior. It does not fix the original Git/FS
false refusals, qualify a model, or authorize releasing previously withheld text.
The three existing positive integration regressions remain failing.

`InjectionDetector::mcp_result_evidence` reports the complete ordered channel
inventory, the component counts used by the production heuristic, and typed
occurrences with original UTF-8 byte ranges. Empty and duplicate channels keep
their own indexes. Callers must supply both `content` and `structuredContent`
channels, in their original inspection order, and separately retain raw frame and
decoded-channel hashes. The ledger does not trust metadata or copy source text.
`validate_sources` checks inventory/range shape, not content identity or intent.

The production heuristic and ledger share `heuristics::analyze` and
`HeuristicSummary::score`. Imperative and delimiter caps, encoded-token presence,
typed-record discount and unresolved-record floor are unchanged. An occurrence's
`active` flag means eligible before aggregate capping; it is not a separate score.
The existing signature and result-directive scanners expose streaming visitors.
The native preview's cross-block findings are projected from typed source ranges,
preserving legacy finding order, labels, spans and confidence. Direct and newline
joins are separate observations. There is no model or new policy path.

Every context status is unresolved, including instructions inside quotes or
comments. Structural ownership does not resolve semantic intent. The ledger has
no Allow/suppression method and is not automatically emitted to production audit
logs. It is an offline diagnostic API built from the same scanners used by the
common result path.

## Diagnostic bounds

Ledger input is bounded to 1024 channels and 8 MiB of decoded UTF-8. These are
diagnostic bounds, not changed native limits. Invalid UTF-8 is rejected by the
JSON diagnostic before any ledger exists. Excess input returns an incomplete
empty ledger. A joined representation over 8 MiB is refused before allocation.
Each observation is streamed and checked before retention against a 65,536 count
cap and a conservative 64 MiB JSON-size budget (including escaping and range
overhead). Cap exhaustion keeps `complete=false` while scanning the supported
input and retaining its full channel inventory and heuristic totals. Missing
observations are never represented as complete. Temporary match objects remain
bounded; the ledger does not first collect uncapped signature/directive vectors.

The offline example `result_evidence` accepts newline-delimited JSON objects
with `channels`, `policy` and optional lower `observation_cap`. It never dispatches
a tool. Its input/output limits are 8/64 MiB per response. The external Linux
supervisor enforces ten seconds end-to-end and 512 MiB address space, kills and
reaps the owned process group, and reports errors independently of predictions.
GNU time obtains the actual worker's wait4 peak RSS, not launcher RSS. Each case
uses one cold process; this is not a warmed throughput or installed-host test.

## Reproduction

Build with the locked workspace from the repository root:

```sh
cargo test --locked -p soup-wall-core -p soup-wall-agent --lib
cargo clippy --locked -p soup-wall-core -p soup-wall-agent --all-targets -- -D warnings
cargo build --locked -p soup-wall-agent --example result_evidence
python3 -m unittest discover -s scripts/tests -p test_result_evidence_replay.py -v
```

Build a separate baseline tree from #215 commit
`465c77c23b4ae0ff30fc063cee17062c8ac52f8b`. Copy only the diagnostic example into
its `crates/agent/examples/` directory and remove the block between its
`BEGIN LEDGER` / `END LEDGER` markers. No baseline production scanner changes are
needed. Build with a separate `CARGO_TARGET_DIR` and the same toolchain/profile.
Supply the retained public `inputs-and-report.json` containing 58 requests/refs:

```sh
python3 scripts/replay-result-evidence.py \
  --baseline /absolute/baseline-target/debug/examples/result_evidence \
  --candidate /absolute/candidate-target/debug/examples/result_evidence \
  --public-inputs /absolute/public/inputs-and-report.json \
  --build-identity /absolute/local-build-identity.json \
  --output /absolute/local-evidence-directory
```

The runner freezes input/control identities before either binary is executed.
It compares every core finding and full agent policy-preview Outcome exactly,
including float confidence, ordering, risk and cross-channel attribution. It
checks UTF-8 ranges independently and tests count exhaustion and malformed input.
Original Git/FS frames and policies come from committed baseline Git blobs,
independent of `core.autocrlf`; LF/CRLF Git variants are explicit separate cases.
Neither payloads nor expected labels are normalized or changed for acceptance.

Evidence records baseline/implementation commit and tree, binary hashes,
per-channel hashes, latency, actual-worker memory, coverage and explicit errors.
Only sanitized metadata is retained publicly. The original 58 remain public
development examples; no held-out cases, fitting, new model or inference occur.
These previews do not prove original-server execution, useful delivery, admission,
or that result withholding undoes server effects. Ready qualification remains a
separate task after a reviewed behavioral correction.

Replay requires a clean committed checkout. Build both binaries from Linux
`git archive` snapshots; record `rustc -Vv`, `cargo -V`, build command/profile,
features, lockfile and diagnostic-example hashes in the supplied build identity.
The build identity's `implementation_commit` and `baseline_commit` must match the
clean checkout and pinned parent. Keep earlier dirty diagnostic attempts separate.

## Contextual correction boundary

The matched `quote_described` / `quote_adopted_unaddressed` control keeps the same
quoted instruction and exact lexical spans, then changes only the later relation
from describing that example to carrying it out before answering the user. All
typed occurrences and component scores are identical. Therefore discounting
findings solely because their spans are quoted cannot distinguish the cases.
The regression preserves the complete source and unresolved context; no such
discount is installed. This is a reproducible counterexample to that specific
contextual correction, not a claim that semantic discrimination is impossible.

A subsequent correction must evaluate the adoption relation from the complete
source, including later and other-channel references; the ledger's occurrence
bag is insufficient. Existing full/global models remain disqualified by their
retained misses and bounds. No replacement model or inference follows from this
increment. Original Git/FS useful-delivery regressions stay mandatory.

## Retained clean-source comparison

[Manifest](evidence/sou109-ledger/manifest.json) and
[report](evidence/sou109-ledger/report.json) qualify only implementation
`ec3a7a97a93c28fb22aaa85bf40c0bff9af40a89` against the pinned #215 baseline.
Both Rust binaries were built from independently verified LF-preserving Linux
Git archive snapshots; compiler, lockfile, source and harness hashes are retained.
The final replay began from a clean checkout. The earlier working-tree replay
is kept locally as diagnostic history, not exact-source qualification.

All 77 cases preserve the exact legacy output: 58 unchanged public requests,
five original-frame/LF/CRLF cases, and fourteen frozen synthetic controls.
The count/byte-budget stress case is explicitly incomplete; it is not a successful
benign classification. Five malformed/unsupported input controls return explicit
diagnostic failure. Three supervisor tests independently verify deadline cleanup,
actual-worker memory measurement and address-space refusal. The bounded output
writer also has a regression that rejects serialization before retaining excess.

Cold end-to-end candidate median is 66.87 ms, nearest-rank p95 318.47 ms, and
maximum actual-worker RSS 167,960,576 bytes. These include input parsing, policy
preview, diagnostic collection and output. Every completed case remains below
ten seconds and 512 MiB; measured results do not justify relaxing either bound.
The three existing positive regression tests remain red (six pass / three fail).
Core 96 and Agent 171 library tests pass; targeted all-target Clippy, formatting,
the example test, three supervisor tests and documentation links pass. This is
neither whole-workspace Ready qualification nor live original-server acceptance.
