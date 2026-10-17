PR #161 / SOU-67 review — 2026-10-17

Verdict: request changes. This head is not production-ready as the completed SOU-67 delivery.

Reviewed source: `59bb5dfda3e326d314ac8f1a8a67222d9fa8229d`, matching local HEAD and GitHub PR head. Ran `git show 59bb5df` and inspected all four changed files plus registry loading, resource extraction/authorization, constrained execution, Windows handle validation, and affected regression fixtures. Host: Darwin arm64; rustc/cargo 1.99.0. Production source was left unchanged. Temporary witness test files were removed.

1. **P1 — The implementation supplies tool-name aliases, not the complete binding contract.**

   `native/resource.rs:530` still requires the exact `create_file_schema()` digest and a single `/path` selector. `create_file_binding()` additionally requires exactly the original `path` and `content` keys. There is no new additive/versioned original-tool binding validator for direct/nested path and content selectors, response contracts, or bound projections of original admitted arguments. Changing the name to `save_artifact` works with the legacy schema; arbitrary bounded original tool shapes do not thereby become supported.

   This scope distinction is independently confirmed by the primary reviewer's production-parser witness, as described in his review; that particular nested-schema witness was not independently rerun in this audit. @winux125 explicitly requested the missing contract, supported-selector validation, executor identity/limits, original-frame preservation, migration/support notes, and exact-source evidence, and asked that SOU-67 remain In Progress.

   Review: https://github.com/SoupTeam/soup-wall/pull/161#pullrequestreview-5557319159

2. **P1 — The complete test gate fails because an existing adversarial fixture still assumes name-based refusal.**

   `scripts/fixtures/mcp_resource_backpressure.py:100` schedules an operator-bound `read_note` invocation and expects `resource_executor_unsupported`. Under the new dispatch it correctly becomes an allowed constrained read. The assertion at line 303 and the expected native-gate counts are consequently stale. `crates/agentfw/tests/mcp_concurrency.rs:218` invokes this scenario.

   Reproduced locally with both `cargo test` and the focused `cargo test -p agentfw --test mcp_concurrency immediate_resource_refusals_preserve_same_session_recovery_and_eof`; both exit 101. The GitHub `test` and `all-features` jobs fail on the same scenario. Their observations show 33 broker reads/66 native gates where the fixture expected alternating immediate refusals and useful reads. No child dispatch was observed in that CI witness.

   Repair the fixture with a genuinely unsupported or unauthorized binding while preserving its immediate-refusal/backpressure/recovery assertions. Merely accepting every result would discard the intended control. Audit other SOU-18 name-based unsupported-tool expectations as well.

3. **P2 — Renamed create execution and Windows name changes lack direct execution evidence.**

   The new `native_endpoint.rs:2447` test ends after native allow/release and binding-digest assertions. It does not invoke the collector, create a file, verify its bytes, or prove that the hostile child was bypassed. It is also Unix-only. The new MCP test does prove actual custom-name read contents, traversal refusal, and zero child execution.

   Add owned collector create/refusal evidence with filesystem witnesses and the required no-overwrite, replacement/symlink, replay, cancellation, and post-commit withholding controls. Exercise nonlegacy names under Windows read/create profiles on Windows. Existing legacy executor tests provide useful shared coverage but do not establish those new combinations.

4. **P2 — “Any tool name” still has reserved-name exceptions.**

   `mcp/admission.rs:1718` reserves `https_get` for network authority; line 1725 reserves `create_file` for create authority. A fully reviewed ReadOnly read policy named `create_file` loads and reaches the collector, but the call is refused with `resource_create_profile_required` before constrained read dispatch.

   Reproduced by copying the existing MCP integration test into a temporary test target and replacing `fetch_document` with `create_file` throughout. The original success assertion fails and the logged correlated response identifies the refusal. This is fail-closed behavior and an inherited naming exception, not a sandbox escape. Document the reservation or resolve it consistently with the final binding contract.

5. **Inherited security finding — Unix v1 read policies do not compare their server identity with the collector's identity.**

   At `mcp/admission.rs:1785`, the collector/policy server-ID equality check is conditional on create, HTTPS, or Windows handle authority. Generic Unix reads skip it. At line 1861 the extraction invocation is populated from `policy.profile.server_id`, so extraction's later identity comparison does not independently check the actual collector server ID.

   A temporary witness retained collector server ID `fixture` and changed only the SOU-67 read policy's server ID to `other-server`. The original authorized-read test still passed and returned `custom bound contents`; its zero-child-execution and traversal checks also passed. This demonstrates missing server scoping, not escape from the configured resource/workspace allowlist. A collector with the matching installed tool/schema can consume the read policy despite a different declared server identity.

   The same conditional and policy-derived identity are present in the parent commit; this is not introduced by the six production-line changes in 59bb5df. Apply server identity validation consistently to Unix reads and add a negative witness, or explicitly resolve the intended authority model before claiming strict server-owned binding security.

**Security properties retained by this diff**

- The Unix constrained dispatch requires ReadOnly for non-create reads and SideEffecting for create policies. Windows policy validation requires those same respective classes. Generic Unix read class enforcement happens at dispatch rather than in generic policy loading.
- `Policy::validate()` requires profile tool name and schema digest to equal the installed tool at startup. Registry loading calls that validation; admission selects the installed tool by the original requested name. Generic extraction also compares the invocation tool name to the profile. Removing the literals does not allow an invocation to select an unrelated profile by name.
- Generic path extraction still rejects traversal, foreign path syntax, links/reparse points, unavailable/special targets, and canonical targets outside the workspace. Unix reads retain descriptor-rooted `PinnedWorkspace` opens with `O_NOFOLLOW` for every component, regular-file checks, and byte limits.
- Create authority still requires one exact direct-child destination, the fixed reviewed schema, supported execution profile/digest/limits, exact arguments, and bound content. Linux publication retains anonymous staging and atomic no-replace publication; Windows retains native handle identity/reparse protections. These executor mechanics were inspected, not changed.
- Resource execution stays on the constrained collector path and returns before generic child forwarding. Classifier, native admission, Ask/Deny, receipt binding, and result-release gates remain in place.
- No storage or migration changes were made; no SQLite/PostgreSQL divergence is introduced by this diff.
- No new filesystem confinement bypass was demonstrated. Windows runtime behavior and Linux file publication were not executed on this Darwin host; platform CI evidence and the missing renamed-tool execution witnesses remain necessary. Existing executor trust-model limitations are not converted into universal race-safety guarantees by this review.

**Verification results**

| Command / witness | Result |
| --- | --- |
| `cargo test -p agentfw --test mcp_admission` | Exit 0; 73 passed |
| `cargo test -p agentfw --test native_endpoint` | Exit 0; 113 passed |
| `cargo clippy --all-targets -- -D warnings` | Exit 0; no warnings |
| `cargo fmt --check` | Exit 0; clean |
| Additional `cargo test` | Exit 101; mcp_concurrency: 10 passed, 1 failed; later targets not all reached |
| Focused mcp_concurrency immediate-refusals witness | Exit 101; same failure as CI |
| Reserved create_file read-name witness | Expected success assertion fails; exact refusal captured |
| Mismatched read server-ID witness | Exit 0; successful read despite mismatched server IDs |

The intentionally failing review probe is separate from the unchanged production test results. Logs are retained alongside this report. The full workspace run also passed the 313 agentfw library tests before reaching the concurrency failure.

**GitHub snapshot**

PR is OPEN, MERGEABLE but BEHIND main. Review decision: CHANGES_REQUESTED, with @winux125's explicit review. Latest retained checks snapshot: 39 SUCCESS, 2 FAILURE (`test`, `all-features`), 3 IN_PROGRESS, 1 NEUTRAL. The two failure logs identify the same immediate-refusals test. Snapshots are observations, not a promise of final CI state.

The PR cannot be described as accepted on first pass: the primary reviewer has already requested changes. Complete the scoped binding contract and execution controls, repair the affected adversarial fixture, resolve the inherited authority gap, and obtain green current-head CI and reviewer approval before making the production-readiness/completion claim.
