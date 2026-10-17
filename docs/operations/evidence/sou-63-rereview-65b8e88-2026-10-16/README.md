# SOU-63 acceptance review of 65b8e88

Exact PR #146 head: `65b8e887c83ff29eb8f178edadf3a28c13c0675e`.

**Latest PreToolUse repair: APPROVE. Overall SOU-63 acceptance: REQUEST CHANGES.** No additional defect was found in the latest shape-validation repair during the focused checks. Previously reported incomplete/malformed-shape witnesses are now closed. The remaining overall blockers are original task deliverables already called out in the first review, not a claim that the six-case fix still fails.

## Verification

- All 82 shipped native endpoint tests passed, including all prior integrated review witnesses.
- All 13 hook endpoint tests passed.
- The previous mutex lock-order control passed.
- Two additional independent positive controls passed: all six unsupported shapes remain nonblocking in shadow mode without allocating a hook sequence, and valid benign Read/Bash requests remain allowed in enforce mode.
- Product source/tests were not modified. Testing used an exact-head archive under `/private/tmp/sou63-review/65b8e88`, separate Cargo output and a macOS sandbox denying network and writes outside review scratch.
- No independent full-workspace, complete stdio-suite or Clippy rerun was performed. Hosted CI was still running when inspected.

`additional-controls.patch` contains only the two positive controls for a disposable exact-head checkout. `results.json` pins source/patch hashes and observed results. No actual tool command, external delivery, commit, push or message occurred.

## Original acceptance still open

The current Linear SOU-63 description was fetched again during this review. Its original Deliver 1–3 and 5–6 remain applicable. These gaps were identified under Contract completeness in the first review and retained in subsequent reports.

### P1 — Authenticated actual-agent/parent and hook identity binding

`native/child_authority.rs:22-31` authenticates host_session, server_id and tool names, but carries no actual-agent or parent identity/recipient generation. `native.rs:1253-1257` still constructs fixed agent="native-runtime", parent=None. `map.rs:77-81` still maps raw hook payload session IDs with agent="main", parent=None. The hook handler authenticates the shared daemon hook bearer but does not validate a host/agent/parent-specific binding. Remembering a host_session string and protecting its taint while native children exist does not establish the required authenticated hook/runtime identity contract. Cross-agent/wrong-parent and parent lifecycle/revocation guarantees are not supplied by these mappings.

Complete the selected trusted-host binding and verification seam for supported hooks and collectors; explicitly refuse protected identity paths that the selected runtime cannot verify. Preserve per-invocation receipt binding and define restart/replay/revocation behavior.

### P1 — Child resources and destinations are not intersected with parent authority

`native.rs:897-912` checks the child's tool-name list and the global registry resource policy. It does not resolve an authenticated parent's effective resource/destination scope or intersect it with the child's request. The grant contains no corresponding scope or parent authority reference. Existing global confinement is valuable but does not implement original Deliver 3's narrowing relative to the actual parent. Implement the selected supported narrowing, or document the unprovable path as unsupported and refuse delegation that depends on it. This is a source-inspection finding, not an HMAC-forgery execution claim.

### P1 — Required retained real-process acceptance and support matrix

The existing SOU-63 stdio tests demonstrate one bound MCP collector result reaching hook policy, CLI verification and cancellation. The cross-collector and hook-to-MCP controls added during review use the in-process router fixture. They do not substitute for original Deliver 5's deterministic actual collector/daemon server-A → server-B and hook-result → MCP-call witnesses with execution/loopback receiver evidence, benign and separate-session controls, lifecycle/replay/truncation cases and source/policy/registry/binary identities. No such SOU-63 driver/report is retained in the reviewed tree. The added documentation describes token setup but lacks the required truthful identity/transport support matrix and full lifecycle/unsupported-delegation boundaries.

Retain those real-process witnesses and reproduction commands and reconcile the protocol/support documentation with the implemented scope before claiming the whole task complete. This finding concerns missing acceptance evidence/implementation requirements; it does not assert that a yet-unrun real-process scenario necessarily fails.
