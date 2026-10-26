# SOU-83 original-create Ask follow-up

Separate from PR #196's bounded Allow increment. Focused native qualification is complete on its explicitly recorded sources.
This dated snapshot does not assert final Ready CI/admission or human approval;
the PR records the latest complete candidate qualification.

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


Independently verified focused Linux results:

- [Original create/Ask run 40216060319](https://github.com/SoupTeam/soup-wall/actions/runs/40216060319), source `f7a45ed8755d51c45570dfc16d1f7fa3bb9906b2`: 17/17 cases; two exact permitted publications, zero denied effects; seven real completed-original output perturbations and three consuming publication boundaries; all observed processes stopped. ZIP SHA-256 `b8a3943375eba79b6db660a6cd6ab8c23fde15542e036a3d3b4b8221e752e686`, CRC and all sent/received transcript hashes match; actual original reply hash matches native audit. [Finite projection](focused-native.json).
- [Signed managed run 40216278340](https://github.com/SoupTeam/soup-wall/actions/runs/40216278340), source `2f192faa75afc123d222138f160688d32c9f72ee`: SQLite and PostgreSQL each pass 19/19 with zero skips, owned cleanup, original Allow/Deny, retirement on a new same-policy deployment and fresh exact Ask/read continuation. ZIP SHA-256 `ade2e585d9e30887f1d2ae20509948f4ecf9d2f1e67b1c8f676ba3ba0a09b6a3` and CRC match. [Finite projection](focused-managed.json).

The later managed source changes only its driver opt-in and evidence relative to
the focused native source. These are focused source-bound observations, not full
Ready qualification. The final candidate must pass its own required jobs.

Failures remain retained: the initial Linux refusal test expected the wrong MCP
envelope; an added staging test attempted to reuse a consuming output capability;
and global fixture liveness opt-in changed an old Git restart witness. Fixes use
exact refusal codes, a fresh actual original invocation per publication boundary,
and writer-only liveness opt-in. No capability, timeout, process bound, expected
effect or admission gate was weakened. The initial all-features attempt also
recorded an existing private executable calibration failure (`ETXTBSY`); it is not
claimed fixed by these changes. Raw ZIPs/logs remain private, with hashes and
failed attempt identities in [the local ledger](local-integration.json).
