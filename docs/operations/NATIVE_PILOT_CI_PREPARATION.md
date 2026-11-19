# Native pilot CI preparation and verified library-test reuse

The native Ubuntu job builds `agentfw`, the Git launcher, and the Rust library
test executable once through `build-native-pilot-inputs.py`. Its immutable
generation receipt binds the clean Git source/tree, `Cargo.lock`, Rust 1.94.1,
native build tools, Cargo commands, options, and selected binary digests. The
installed private-edit self-test now verifies that same selected generation
again and executes its `sandbox_tests` binary with the `self_test::tests`
filter. A missing marker, changed source/tool, modified binary, partial
generation, or incompatible receipt refuses. `--verify-existing` never builds
or selects a replacement. `clippy`, `fmt`, the installed self-test, and all
other native acceptance remain in place.

The accepted Ready run [41609665048](https://github.com/SoupTeam/soup-wall/actions/runs/41609665048)
had 69 successful jobs and two expected skips. Its native job
[125834693747](https://github.com/SoupTeam/soup-wall/actions/runs/41609665048/job/125834693747)
lasted about 52 minutes. Source-build timing recorded 182.001 seconds for a
clean build and 1.259 seconds for verified reuse. The later private-edit step
ran `cargo test --locked -p agentfw --lib self_test::tests`; its Cargo log
reported 1 minute 56 seconds of compilation immediately before the three
tests completed in under a second. The source builder had already compiled
the exact library test executable. The long guided/runtime scenarios are
independent qualification, not duplicate preparation.

An earlier attempted offline transport-input cache was measured on native
[run 41641773669](https://github.com/SoupTeam/soup-wall/actions/runs/41641773669).
The comparable front-door preparation total grew from 123.986 to 125.468
elapsed seconds, and from 126.556 to 129.023 CPU seconds. That approach was
removed. The run later hit the existing 65-minute job limit during an
additional existing-project scenario, so it is **not** a successful whole-job
qualification. Its passed front-door scenarios are retained only as
attributed partial evidence.

For an exact-source native comparison, dispatch `mcp-real-filesystem.yml` on
the reviewed branch with `private_edit_self_test_only=true`. This focused
path executes the receipt-verified binary and the old cold Cargo command in
an isolated external `CARGO_HOME`/`CARGO_TARGET_DIR`, checks equal passing
test counts, and uploads `private-edit-self-test/reuse-comparison.json`. The
report separates elapsed and CPU time for cold compilation plus tests from
receipt verification plus reused tests. It does not report the reused stage
as cold execution. The comparison adds work only to this explicit manual
focus; the normal Ready path runs the verified executable once. Do not infer
whole-workflow or billed-minute savings from this segment. Final Ready,
security, CodeQL, and exact-candidate admission remain required and are
coordinated by the team lead.
