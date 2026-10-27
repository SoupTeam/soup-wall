# Coordinated pilot update checks

SOU-164 adds an update coordinator over the accepted Agent lifecycle, installed helper and prepared-selection contracts. The implementation uses a private inactive Agent home, a versioned exact-input inventory, one atomic selection and a durable phase journal. Existing preparation, policy, sandbox and approval rules remain unchanged.

Accepted base: `f4937110`, a successor of the task's `d57a8696` base. Rust source, Cargo manifests and the lockfile are unchanged. The implementation uses the Python standard library.

## Local results

| Check | Result | Boundary |
| --- | --- | --- |
| Coordinator controls in Linux container, ordinary UID 1000 | 32/32 passed | Includes a locally built real Agent; container is Debian, not native Ubuntu acceptance |
| Same controls in WSL | 31 passed, one conditional integration test skipped | WSL does not establish the supported native environment |
| Same controls on Windows | Two portable controls passed, 30 Linux controls skipped | No native Windows support claim |
| Complete Python test discovery in Linux snapshot | 1,788 tests; one setup error; 42 skips | `test_pilot_launch.PilotLaunchCliTests` cannot start because WSL has no `cargo`; this sweep is not green |
| Existing helper-component closure and archive controls | Passed in Linux sweep | Package includes the coordinator and accepted transition helper |
| Existing guided-entry, selection-transition and preparation controls | Passed in Linux sweep | No test assertions or expected labels changed |
| Offline Agent build | Passed | Existing Rust 1.99.0 and Cargo cache; repository pin remains 1.99.1; this is an interoperability build |
| Generated workflow check | Passed | No workflow or admission file changed |

The coordinator tests cover read-only preview, exact source/hash/mode binding, independent archive-digest confirmation, incomplete inputs, changed interpreter/binaries/helpers, unlisted helper files, changed parent identity, linked/hard-linked records, active selection leases, stale confirmation, switch/rollback and repeated recovery. Fault controls interrupt actual local journal writes before and after publication. The coordinator switch test uses installer and capacity fixtures; it is not a native preparation witness.

The real-installer control uses the production Agent lifecycle and component commands in a disposable private directory under UID 1000. The container has no network, no capabilities and read-only source/binary mounts. It verifies a consistent managed home and installed bytes, then confirms that an invalid prepared input cannot become selected. Its capacity guard is a test fixture. It does not demonstrate a useful original-server run or a complete supported update cycle.

The interoperability Agent SHA-256 is `c65f89927ab3647d21d7938255983ea9c58aea14f6a939ad1921676bcb40ca18`. The build used `cargo build --offline --locked -p agentfw --bin agentfw`. It installed no new third-party dependency. Source and binary screening limitations are retained in the local review package; neither scan established complete coverage.

## Remaining acceptance

Native Ubuntu 24.04 qualification remains unverified. It must use two identified compatible local sets and exercise install, useful original-server run, update, useful run, rollback and useful run outside the checkout. `scripts/qualify-pilot-update.py` provides that driver with an owned scripted loopback provider, five staging/selection interruption points, repeated recovery and eligible abandoned-stage cleanup. The driver has not yet produced native evidence.

The full CLI test class also needs the supported pinned Rust environment. Final CI, admission and review must refer to the published source. No selection receipt or file hash in these local checks establishes active protection. SOU-164 is not ready to mark Done on this evidence.

Operator commands and recovery outcomes: [pilot update guide](../operations/pilot-update.md).
