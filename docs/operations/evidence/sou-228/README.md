# SOU-228 installed Linux evidence (hashes only)

The original reports contain host paths, account and process identifiers and sealed
provenance, so they stay in operator custody and are **not** in this directory. The
[support index](../../roadmap-support-index.json) pins their raw-byte SHA-256 values.
Here, the public report therefore shows these rows as `missing`. The
[report guide](../../ROADMAP_SUPPORT_REPORT.md#sou-228-installed-linux-evidence) has
the offline command.

## Identities

| Role | Value |
| --- | --- |
| Tested product, driver and runtime source | `b4d3e7d67abe7cfc2a0e0877dbd21d1d0c8e232f`, tree `6b0afad2456b53a5e394ed04a08606bd5f39c187`, clean |
| SOU-228 baseline / merge commit | `5dd30c878d0c786d4ec6c623a33ce4b554469683`: same tree, **not executed**; reports read as `historical` for it |
| `accepted_baseline` field in clean-user reports | `9a3c5b38…`: a driver constant, not the tested product |
| Installed component (all three runs) | archive `3e0c7e3ad86d05810dde98c6bb7557a3d81a98016742f1031e18293f5a2b3172`, component `070bd7ad…8d72` |
| Selected policy | `dba24a1b419040d5f5dad62dfd485db6637c9359f37b9642f458101793062dbc` |
| Linux-v1 scope document | `a67a5822e57603affc678bde0b3e319d8fa43d3f90faf915c0650b28e6bc853e` (committed LF bytes) |

Native binaries were rebuilt per run and are not byte-identical, so each index row
pins its own `agentfw` digest: `c528b62f…` (41818201020), `98af293b…` (41818211366),
`05df6445…` (41818225908). Each matches that run's `source-summary.json` in the
`sou111-native-preparation` artifact; the toolchain attestation does not claim
byte-for-byte reproducibility.

## GitHub artifacts and original reports

Three kinds of hash are in play and must not be confused. The ZIP digest is GitHub's
hash of the whole artifact. The report hash is one member inside it, and is what the
index pins. The test fixtures under `scripts/tests/fixtures/sou228` are sanitized
derivatives with their own hashes (see its `provenance.json`).

| Run | Artifact (ID) | ZIP SHA-256 | Main report SHA-256 |
| --- | --- | --- | --- |
| [41818201020](https://github.com/SoupTeam/soup-wall/actions/runs/41818201020) | `sou215-pilot-scope-41818201020-1` (13316278678) | `864669ba33cb5df823e44d1c52c408948bcd342754bef38a3feab3d60ba44f1b` | `c360bb3f2e03141969f0ed700134cf1477bc05b887b16bc35be2968ed349c084` |
| [41818211366](https://github.com/SoupTeam/soup-wall/actions/runs/41818211366) | `sou216-clean-user-41818211366-1` (13316597197) | `ffa3b7a3f30f6707acdd1f5a2ac62128eab4557b1d4dca12ab8a032379faa1b1` | `5ae594e027b9b03354504898e89d1bf85b523d8e3da095a1de6b26b9299c9515` |
| [41818225908](https://github.com/SoupTeam/soup-wall/actions/runs/41818225908) | `sou216-clean-user-41818225908-1` (13317206981) | `8daccd83d0f88d49bbc5152bcedd2fdbaa32e51c49c03bace5fc15db5c95d6a3` | `55a53e973c8190408f8631ef75e02d5e20ad0580b3b7859b055dfad14986a51e` |

Each run's `sou111-native-preparation` artifact holds the `source-summary.json` used to
check the per-run binary digests. The report does not read these ZIPs:

| Run | Artifact (ID) | ZIP SHA-256 |
| --- | --- | --- |
| 41818201020 | `sou111-native-preparation-41818201020` (13316687649) | `115c0ea7fe48a48ffc12f2630d65187949fd4384b3db14a385394da4a84e2491` |
| 41818211366 | `sou111-native-preparation-41818211366` (13316742015) | `d837443fff09d68d11aff31d5b11efa83304ec51fb7af0de6bd34d872dd9e0a7` |
| 41818225908 | `sou111-native-preparation-41818225908` (13317376240) | `62ad341c459e94c8d7df3a822e4046f0155e4c7365215fd1ae3fd86206fd6264` |

Companion report hashes (installed pilot, demo, walkthrough, Ask and both user-session
observations) are pinned beside each row in the index. The artifacts expire on
2026-12-04; after that, only operator-retained copies can reproduce the report.

## Dispositions for `b4d3e7d6`

| Index row | Checks | Status | Why not further |
| --- | --- | --- | --- |
| `sou228-front-door-41818201020` | 40/40 (16 front-door, 12 installed pilot, 12 demo) | `unbound` | No build receipt in the report; witnesses are driver records; companions linked by binary identity only |
| `sou228-linux-v1-scope-41818201020` | 40/40; `linux-v1` selected, conforming, `enforce` while live | `unbound` | Same as above. The scope document itself claims no acceptance |
| `sou228-clean-user-41818211366` | 15/15; 2 expected `maintenance_entered` refusals kept | `unbound` | Receipt bytes absent (only its digest); witnesses are driver records; sealed provenance not verifiable offline |
| `sou228-clean-user-41818225908` | 15/15; 2 expected refusals kept | `unbound` | Same as above |

Both clean-user runs record `scope.selected: false` (`unselected`) in every live
status. They are **not** Linux-v1 scope evidence and never feed that capability. No
row is `pending-review`, no operator decision can attach, and no criterion or phase
changes from `open`.

## Test fixtures

`scripts/tests/fixtures/sou228` holds sanitized derivatives, never original report bytes.
Its `sanitize.py` regenerates them byte for byte from the extracted originals, and its
`provenance.json` maps each fixture to its original member and artifact ZIP.

## ROADMAP digest re-pin

SOU-228 updates the index's `roadmap_sha256` from `987c5916…6aff6` to
`447bac15183ffa222c41c1a83a7a0227b0bb6b03281cc74eb695a56e5ca53819`. Both are hashes of
committed Git blobs (LF), not of a working tree. The old value was the ROADMAP at the
SOU-80 commit `14d98555`; commits `21634b21`, `4d323ac0` and `a87d7c4f` (2026-10-17 to
10-20) made it stale, so the unchanged tool refused every report on the baseline. The
difference is one contiguous 19-line insertion of SOU-78/SOU-99 narrative in the
Phase 5 prose, after its readiness list. Every original line, all 15 headings and all
32 "Ready when" criteria are unchanged; the 6 Foundation criteria precede the insertion.
The block contains no READY, acceptance or decision text. The re-pin was approved on
that evidence.

## Limits

All runs used an owned scripted loopback provider on a hosted native Ubuntu 24.04
x86_64 runner, with a job-scoped sandbox permission and, for clean-user, an
exclusively owned, empty CI user session. Nothing here measures a live model, novice
users, a stock host or full-product acceptance.
