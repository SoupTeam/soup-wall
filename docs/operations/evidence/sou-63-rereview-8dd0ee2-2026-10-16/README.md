# SOU-63 adversarial re-review: 8dd0ee2

VERDICT: REQUEST CHANGES. Five P1 defects and one P2 defect reproduced.
Source: 8dd0ee2513d748731da1509a1602b798b64ddecd.
Original SOU-63 requirements re-read from Linear on 2026-10-16.

## Confirmed findings

1. **P1 — Unverified parent claims without host_session** (`native.rs:925-931`, parser `515-516`). A native session_start with agent_id, parent_id and child_authority="not-a-valid-signature", but no host_session, returns allow/release=true. Only presence of child_authority is checked; verification occurs only in the host_session branch. Reject partial binding tuples before granting identity or authority. Witness: review8dd_parent_claim_without_host_must_verify_signature.

2. **P1 — Child registered as root bypasses actual parent authority** (`native.rs:947-951`). Create a genuine parent session through the router granting only read_document. A signed child naming that parent but granting delete_document starts successfully and its destructive call gets allow/release=true. Parent tools/resources are not checked; set_root registers the child's requested privileges directly. Authenticate the current parent relation and enforce scope intersection before granting or mutating host authority; refuse unsupported/unprovable relations. Witness: review8dd_child_must_not_exceed_registered_parent.

3. **P1 — Filesystem grant uses string prefix** (`native.rs:213-215`). A child with grant /workspace/allowed can read /workspace/allowed-secret.txt when the wider registry permits it. Real router resource admission returns allow/release=true and a call receipt. Match canonical path components, including exact-file versus directory semantics; a lexical prefix is insufficient. Witness: review8dd_child_path_grant_must_respect_component_boundary.

4. **P1 — Missing resource scope authorizes network destinations** (`native.rs:1025-1036`). A scoped signed child grant includes send_email but granted_resources=None. The network tool has declared egress but no resource_policy. Sending to outside@attacker.invalid returns allow/release=true. Missing resource scope is rejected only for resource_policy tools, silently bypassing destination narrowing. Require provable destination scope for network/egress capabilities or explicitly refuse unsupported delegation. Witness: review8dd_missing_resources_must_not_allow_network.

5. **P1 — Hook parent identity is client-controlled** (`map.rs:87-90`, hook mapping in handlers.rs). Bind reader to parent with only read_document. A Bash hook with that agent and parent is denied; removing parent_id from the same authenticated hook yields {}. Raw optional payload IDs do not establish the signed relationship; omission disables the core child-authority check. Resolve identity from verified binding, reject mismatches/omissions when delegated authority is required, and document unsupported legacy paths. Witness: review8dd_hook_must_not_drop_authenticated_parent_identity.

6. **P2 — Exact URL grants are unusable** (`native.rs:231-236`). A grant for http://127.0.0.1:8000/allowed and matching resource policy accepts the exact URL resource comparison, then compares its extracted host against the full URL string and returns 409/native_child_authority_escalation. Preserve precise URL authority without requiring an additional broad host grant; apply the same typed semantics to mailbox grants. Witness: review8dd_exact_granted_url_must_remain_usable.

## Independent validation

- Unmodified baseline: 86 native endpoint, 13 hook endpoint, 280 library tests PASS.
- Both new real-process stdio witnesses PASS, including withheld execution ledger assertions.
- cargo clippy --offline --all-targets -- -D warnings PASS; cargo fmt --all --check PASS.
- All six additional negative/positive witnesses in reviewer-witnesses.patch FAIL on this commit as described above.
- Native/hook baseline and witnesses ran in a tracked source export with all network denied. Real-process and library socket fixtures ran with loopback-only networking. All target-controlled execution had write access only to /private/tmp/sou63-review.
- Initial library run with every socket denied had four fixture failures; loopback-only rerun passed all 280. These were isolation limitations, not product findings.
- Full workspace tests and the remaining MCP admission tests were not independently rerun.
- Product files were not modified. Only this report and witness patch were retained.

## Reproduction

Apply reviewer-witnesses.patch to a disposable checkout of this exact commit and run:

```sh
cargo test --offline -p agentfw --test native_endpoint review8dd -- --nocapture
```

The patch includes six router-level witnesses; the parent-narrowing witness creates both parent and child via the native endpoint. No external service or real credentials are needed.
