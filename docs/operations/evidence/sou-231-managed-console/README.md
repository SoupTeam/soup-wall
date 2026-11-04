# SOU-231 installed managed Console connection evidence

Implementation starts independently from accepted main `5dd30c878d0c786d4ec6c623a33ce4b554469683`; SOU-226/227 branches are not dependencies.

Local qualification: 2,039 workspace tests passed, 15 explicitly ignored environment-dependent tests, 15 connection adversarial controls plus authenticated audience controls, workspace/all-target Clippy with warnings denied, formatting and 13 CI component tests passed. Local target execution used read-only source, scratch-only writes and loopback-only Seatbelt. Failed development attempts and their source/log hashes are retained in `local-validation.json`; raw logs and credentials are not published.

First two Linux attempts and exact-source hashes are retained, including their failure attribution. Authenticated empty-inbox audience verification and fixture publication have been corrected; final Linux installed qualification is pending. No merge/readiness claim is made by this checkpoint. The owned `managed-credential-rotation.yml` workflow runs `scripts/managed-connection-acceptance.py` on SQLite and TLS PostgreSQL 16. It checks actual signed application and Console acknowledgements, bad audience/key/CA, stale inputs, concurrent apply, a real SIGKILL at publication, credential rotation, online/offline restart, guarded disconnect, retained policy/anti-replay/user state, reconnect, environment-only startup and redaction.

See [setup and recovery](../../INSTALLED_MANAGED_CONSOLE.md). Final Ready/security/current-main admission and merge remain maintainer-owned.
