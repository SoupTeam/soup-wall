# SOU-83 original-create Ask follow-up

Separate from PR #196's bounded Allow increment. Current qualification is in
progress; no inherited green result or human approval is claimed.

| Requirement | Implementation / required evidence |
| --- | --- |
| Exact single-use resource and authority | Native signed grant, existing session/epoch/spend ledger; typed workspace/device/inode/target/content hash/byte count; selected schema/profile/classifier/snapshot/raw host request binding |
| No new mutators or broker authority | Exact Linux original create profile + SideEffecting write_file only; no resource_policy, workspace_profile or egress; read-only serialization unchanged |
| No execution before approval | Actual original-create driver: file inventory, no writer PID event, no private stage; independent read remains useful during Ask |
| Terminal and stale authority | Reject/expire/timeout/cancel/no opt-in/Deny/wrong binding/asset drift/root substitution/competing target/EOF/collector death/restart/owner lease expiry; all zero-publication |
| Real positive and replay | Actual pinned original write, 0600 exact bytes, one worker; repeated approval/spent host ID refused; fresh write/read continuation |
| Signed policy epochs and backend parity | Existing managed Console TLS driver extended for original write Allow/Deny, stale Ask across new same-policy sequence, fresh Ask after activation; SQLite and PostgreSQL required |
| Lifecycle / publication races | Existing original live worker/collector/daemon faults; real publisher cancel/EOF after result inspection and staging; special output and competing target after anonymous staging |
| Measurements and boundaries | Original native acceptance retains three matched warm unwrapped/protected monotonic write-RPC samples; no throughput, tail, model or arbitrary-server isolation claim |
| Exact-source qualification | Workspace Rust/Python, clippy -D warnings, fmt/docs/generated CI; native Linux original gates and trusted candidate admission |

Target code executes from a read-only source copy, writes only isolated scratch,
and has loopback-only network locally. Failed attempts remain failed in the
local ledger. Actual Linux qualification must provide independent source,
binary, file and transcript identities before final readiness is reported.
