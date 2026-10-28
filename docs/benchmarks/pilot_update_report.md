# Coordinated pilot update checks

SOU-164 adds an update coordinator over the accepted Agent lifecycle, installed helper and prepared-selection contracts. The implementation uses a private inactive Agent home, a versioned exact-input inventory, one atomic selection and a durable phase journal. Existing preparation, policy, sandbox and approval rules remain unchanged.

Accepted base: `144512b3`, a successor of the task's `d57a8696` base. Rust source, Cargo manifests and the lockfile are unchanged. The implementation uses the Python standard library.

## Local results

| Check | Result | Boundary |
| --- | --- | --- |
| Coordinator controls in Linux container, ordinary UID 1000 | 32/32 passed | Includes a locally built real Agent; container is Debian, not native Ubuntu acceptance |
| Current coordinator and qualification controls in WSL | 34 passed, one conditional integration test skipped | WSL does not establish the supported native environment |
| Native dispatch isolation and generated workflow controls | 19 passed | Ordinary qualification remains enabled; focused mode has separate evidence |
| Same controls on Windows | Two portable controls passed, 30 Linux controls skipped | No native Windows support claim |
| Complete Python test discovery in Linux snapshot | 1,788 tests; one setup error; 42 skips | `test_pilot_launch.PilotLaunchCliTests` cannot start because WSL has no `cargo`; this sweep is not green |
| Existing helper-component closure and archive controls | Passed in Linux sweep | Package includes the coordinator and accepted transition helper |
| Existing guided-entry, selection-transition and preparation controls | Passed in Linux sweep | No test assertions or expected labels changed |
| Offline Agent build | Passed | Existing Rust 1.99.0 and Cargo cache; repository pin remains 1.99.1; this is an interoperability build |
| Generated workflow check | Passed | One focused native mode added; no admission or global runner setting changed |

The container, Windows and complete Python-discovery rows record the initial `f4937110` development snapshot. The current WSL and workflow controls cover the refreshed candidate.

The coordinator tests cover read-only preview, exact source/hash/mode binding, independent archive-digest confirmation, incomplete inputs, changed interpreter/binaries/helpers, unlisted helper files, changed parent identity, linked/hard-linked records, active selection leases, stale confirmation, switch/rollback and repeated recovery. Fault controls interrupt actual local journal writes before and after publication. The coordinator switch test uses installer and capacity fixtures; it is not a native preparation witness.

The real-installer control uses the production Agent lifecycle and component commands in a disposable private directory under UID 1000. The container has no network, no capabilities and read-only source/binary mounts. It verifies a consistent managed home and installed bytes, then confirms that an invalid prepared input cannot become selected. Its capacity guard is a test fixture. It does not demonstrate a useful original-server run or a complete supported update cycle.

The interoperability Agent SHA-256 is `c65f89927ab3647d21d7938255983ea9c58aea14f6a939ad1921676bcb40ca18`. The build used `cargo build --offline --locked -p agentfw --bin agentfw`. It installed no new third-party dependency. Source and binary screening limitations are retained in the local review package; neither scan established complete coverage.

## Native qualification

The focused native Ubuntu 24.04 dispatch is `mcp-real-filesystem.yml` with `coordinated_update_only=true`. Set A comes from accepted `144512b3ed11f985c922d9911cba26f07599dea9`; set B comes from the exact dispatched head. Both use the accepted source builder, complete helper archives and separately prepared prefixes. Preparation consumes explicit offline package inputs; runtime update and rollback do not download or build.

`scripts/qualify-pilot-update.py` runs install, useful original-server run, update, useful run, rollback and useful run outside both checkouts. It uses an owned scripted loopback provider. Required controls include refusal during an authenticated live run, changed interpreter/binary/helper identities, five staging/publication interruptions, repeated recovery, owned cleanup and preservation of unrelated state. Phase-level I/O errors do not establish physical disk-full behaviour.

The source-bound `qualification.json` artifact is the native result. Current run links and outcome belong to [PR #289](https://github.com/SoupTeam/soup-wall/pull/289); local counts in this document do not establish native acceptance or active protection. Final CI, admission, review and merge remain separate gates.

Operator commands and recovery outcomes: [pilot update guide](../operations/pilot-update.md).
