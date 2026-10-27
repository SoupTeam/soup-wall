# SOU-159 focused native qualification

The production stdio/native path passed **22/22** finite cases on native
Ubuntu 22.04 in [run 40463425198](https://github.com/SoupTeam/soup-wall/actions/runs/40463425198).
The exact executable source is `4cdd671476f813f6e661a2a45a6c6b4a14d566a2`.
The following evidence/documentation commit does not change that executable
source, its witnesses or its workflow.

## Retained proof

- [Native runtime observations](native-runtime.json): actual old/new inode and
  content hashes, outside sentinel, zero discovery-child dispatch, exact approved
  publication bindings, useful follow-up reads and owned-process cleanup.
- [Source/build/artifact provenance](native-provenance.json): binary SHA-256,
  report/archive/log SHA-256, verified ZIP CRC and isolation boundary.
- [All native attempts](native-attempts.json): setup failures and original
  ineffective controls are retained. The unsuccessful
  [fourth](attempt-4-runtime.json), [fifth](attempt-5-runtime.json) and
  [sixth](attempt-6-runtime.json) runtime reports are not accepted as green proof.
- [Local development](local-development.json): separate macOS checks, including
  the complete serial workspace result (1875 passed, 13 existing ignored),
  subsequent targeted checks, failures and their source/log fingerprints.

The successful Linux run also passed ten executor units, three replacement
binding/retention units, five native HTTP authority controls, thirteen existing
create-only controls, nine evidence/classifier controls, strict all-target
Clippy for agentfw and `cargo fmt --all --check`. No compiler warnings occurred.

## Effects and negative boundaries

The cases cover useful replacement/read, stale digest/object, same-version
competing writers, substituted target/root, symlink/hardlink/FIFO, missing
exclusion, unauthorized action, Ask reject/expiry/replay, changed old/new input
while pending, cancellation/restart, partial staging write, failed publication,
post-commit fsync failure and withheld committed result. Substitution verifies
both the replacement at the original name and the displaced original object;
the displaced root's inventory is checked too. Competing collectors both close
without forced cleanup, and only one exact approved call may publish.

Positive replacement cases use the unmodified production binary without
instrumentation. Three disposable collectors load the retained test-source
filesystem fault shim: accept five staging bytes then ENOSPC; fail rename;
or perform the real rename then fail directory fsync. No identity, grant or
successful effect is fabricated. For the withheld-result case only, a separate
disposable daemon tightens `provenance.max_source_bytes` to zero. A real-engine
unit proves invocation Ask remains available; actual result retention then
refuses with `native_provenance_source`. The file remains committed and the
caller receives `resource_replacement_committed`. Production defaults, policy,
approval TTLs and resource caps are unchanged.

## Scope of qualification

This is one opt-in component under the documented private sole-writer operator
contract, not general project overwrite or protection from untrusted same-UID
writers. Eligibility checks for other allowed filesystem families do not add
runtime evidence beyond this Ubuntu run. Final shared Ready qualification,
admission, review and main merge remain TL-owned as required by SOU-159.
