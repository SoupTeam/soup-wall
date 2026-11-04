# SOU-226 evidence

The local macOS real-process witness passed all 15 checks after 305 seconds of
actual downtime. It used real Console/Agent processes, production 300-second
ACK deadlines, no browser and no manual advance. Exact source-file and binary
hashes are in `sqlite-real-process.json`. The source commit is the accepted base
plus the explicitly hashed working snapshot; this is not a clean-commit claim.

`local-attempts.json` retains failed compilation attempts and subsequent passing
controls/build/witness commands with source and log hashes. PostgreSQL controls
are explicitly ignored locally; they require the dedicated PostgreSQL 16 CI
fixture. Local PostgreSQL 14 is not substituted for that qualification.

A subsequent diagnostic/shutdown refinement is covered by the final checks and
exact committed-source CI; the earlier local witness is attributed only to its
recorded source snapshot. No private process log, token, signing seed or database
connection string is published.

The first Draft run 41846138026 failed two generated-component equality checks:
the new profile steps had not been mirrored in ci-components.yml. The generated
copy is now synchronized; 13 component-contract and 30 documentation tests pass
locally, with 432 documents/1371 links checked. The complete CI Python suite
was also attempted locally; Linux child-process/subreaper controls do not pass
under macOS Seatbelt (7 failures, 4 skips), retained as an environment limitation.
The full CI Python suite must be confirmed on Linux, not reported green locally.

The entire workspace test suite and workspace/all-target Clippy -D warnings
passed at the recorded workspace-checks snapshot. A subsequent bounded-cycle
refinement pins a scan ceiling and is separately verified by SQLite controls
including two actual worker loops, shutdown and atomic restart regressions.
The updated PostgreSQL controls and real-process witness run on the final
implementation commit before acceptance is claimed.
