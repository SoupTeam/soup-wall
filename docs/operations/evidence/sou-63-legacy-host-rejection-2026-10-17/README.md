# SOU-63 legacy shared-host bypass closure

The reviewer correctly identified that a legacy `mint()` token is not isolated when supplied with `host_session`. On base `c7579935f9fd27fb5146b24e67f3cd9663950b1b`, it bypassed scoped daemon-generation checks and completed-host tombstones.

Shared-host session start now requires a signed agent identity before accepting the grant, then always verifies the current daemon instance. Legacy signatures/time verification remain backward compatible, but a legacy grant receives HTTP 409 / `native_child_authority_identity_required` at shared-host bootstrap. Isolated native requests omit both binding fields and remain usable. Merely adding the current instance prefix or resources to an agentless grant cannot upgrade it. Production crypto encoding, TTL, parent scope and taint policies are unchanged.

## Adversarial evidence

- [baseline-red.log](baseline-red.log): all three new real-router controls fail against the original implementation. The first reproduces read → taint → destructive Deny → collector end → authenticated hook SessionEnd → identical legacy token replay accepted with a new collector ID. The restart control recreates daemon state with the same persisted bearer and observes legacy replay accepted. The third observes that an instance-prefixed but agentless grant is accepted.
- Fixed router: all 112 tests pass, including the original scoped lifecycle tests, early legacy refusal, restart refusal, instance-prefix downgrade, and genuinely isolated success controls. The legacy end witness retains the original vulnerable flow if its initial legacy bootstrap ever becomes accepted again.
- Real CLI/stdio witness: mint and verify the legacy token, then attempt a bound collector before/after daemon restart. Both attempts terminate before a server startup marker or execution ledger entry. All 72 MCP admission tests pass, including distinct A/B collectors, cancellation and signed hook→MCP controls.
- Positive host fixtures now issue proper current-instance scoped grants. Their hook controls supply the exact proof and registered tools; the shared-taint/audit, strict Ask and truncated-history assertions remain.

## Verification

Full isolated workspace: **1279 passed, 0 failed, 10 intentional ignores**. Clippy `--all-targets -- -D warnings` and formatting pass. [results.json](results.json) pins source hashes and every suite result. GitHub CI and reviewer acceptance must be confirmed separately on the pushed head.
