# Native Linux lifecycle preflight: observations, 2026-11-04

Guide: [installed lifecycle preflight](../PILOT_INSTALLED_FRONT_DOOR.md#read-only-lifecycle-preflight).
Draft implementation: [PR #355](https://github.com/SoupTeam/soup-wall/pull/355).

## Exact source and result

[Run #599](https://github.com/SoupTeam/soup-wall/actions/runs/41819280895)
passed both fresh GitHub-hosted Ubuntu 24.04 x86-64 jobs at clean source
`1b459b5e373240f60d4305dc7b91cd79e3a5ae28`, independently based on accepted main
`2a5bf6771c63c6ccf2c55d07dede512a72f26481`. Later evidence/documentation commits
are not the observed build. Both jobs used Rust 1.94.1, the native Agent built
from that source, the deterministic front-door component from the same source,
and the protected OS interpreter `/usr/bin/python3.12`. Agent and component
SHA-256 values are retained in each original report.

| Environment | Cases | Result |
| --- | --- | --- |
| [Ordinary native job](https://github.com/SoupTeam/soup-wall/actions/runs/41819280895/job/126538063271) | 3 | doctor; owned non-dumpable-process EACCES control; direct preparation required-prerequisite refusal |
| [Disposable installed-component job](https://github.com/SoupTeam/soup-wall/actions/runs/41819280895/job/126538063661) | 4 | doctor; EACCES control; installed preparation refusal; installed preflight outside checkout |

All observations report setup **satisfied**, protected-run admission **unknown**,
and current removal prerequisites **blocked**. The ordinary runner already had
inaccessible process evidence before the synthetic EACCES child was introduced;
the child control also retained the required inaccessible-evidence reason. These
are conditional successes of diagnosis/refusal, not a complete-removal pass or
proof that the child alone caused the blocked outcome. No service was stopped
or host permission/namespace/security setting changed to manufacture eligibility.

Both required-removal preparation calls returned exit 2,
`lifecycle_prerequisite_unavailable`, `executed: false`; the proposed prefix did
not exist afterward. The strict bounded syscall observer accepted only the
Agent entry, or the Agent plus its recorded interpreter for installed dispatch.
It observed zero extra exec attempts, non-thread children, network effects,
write opens or host mutation attempts during diagnosis/refusal. Raw traces stay
private and are deleted; original reports retain trace digests and finite
witness counts. The owned fixture exited, source stayed clean, and removal
remained unauthorized. A positive past preflight supplies no later authority.

Both jobs passed formatting, strict library Clippy, lifecycle phase/support
export tests, the native removal regressions, existing doctor tests and the
complete lifecycle/preparation/front-door/component Python suites before the
observations. Local validation separately passed 102 focused Python/CI-contract
tests (100 passed, two platform skips), existing Rust doctor/phase tests,
generator consistency, actionlint and documentation links.

## Retained originals

The four JSON files below are byte-for-byte extracts of each artifact's sole
`report.json`. ZIP SHA-256 matched GitHub's official digest, CRC passed, and
source/status/schema and privacy checks passed before inclusion. No raw syscall
traces, PID inventory, argv, environment bodies, maps or workspace paths are
published.

| Run / mode | Original report | Report SHA-256 | Artifact ZIP SHA-256 |
| --- | --- | --- | --- |
| 599 / ordinary | [report](sou225-lifecycle-599-ordinary-2026-11-04.json); [artifact](https://github.com/SoupTeam/soup-wall/actions/runs/41819280895/artifacts/13316242366) | `97678cde36de957d37357c77c953e32cdd07f3fd6d7dc41ee85ea5ead443b340` | `c5c48a3edccdc39ef1c4de44fc43c03fe27f1d07ef310e5bc6834f8d97c05eb6` |
| 599 / installed | [report](sou225-lifecycle-599-installed-2026-11-04.json); [artifact](https://github.com/SoupTeam/soup-wall/actions/runs/41819280895/artifacts/13316611329) | `e674a0dc62ea023b88af33139ea31bab2cee1e494644d00315854d150cc8b357` | `271d16a0e7eba65b1ae6db9239da6ff51eb75b1dbd9c0e94bfdcfb48cfb679fa` |
| 595 / ordinary | [report](sou225-lifecycle-595-ordinary-2026-11-04.json); [artifact](https://github.com/SoupTeam/soup-wall/actions/runs/41815559172/artifacts/13314881264) | `5751a6a54443dd3cbe92538c12e1a709703f4ccc13d3abf3c6b5af78be2553e8` | `cb79838938308ae34ef99e5102817414351149516e1a7137e1dd0885b01f9a27` |
| 595 / installed | [report](sou225-lifecycle-595-installed-2026-11-04.json); [artifact](https://github.com/SoupTeam/soup-wall/actions/runs/41815559172/artifacts/13313954839) | `57929f761d89d654540eaea45b6630bc2b9c29208ebe7a13a9d44f302945f37d` | `2039a37ab433a89d123907fe0697066a2033760aac9d8df57e375364a38d8b03` |

## Original failed attempts

- [#593](https://github.com/SoupTeam/soup-wall/actions/runs/41812442188), source
  `c980cc04172c0233ae6a0a43d0126dd0a113aaf3`: failed before native compilation,
  tests or observation because repository stable selected 1.99.1 without
  rustfmt. The manual job now explicitly selects 1.94.1 with rustfmt and Clippy.
  No installed report was produced.
- [#594](https://github.com/SoupTeam/soup-wall/actions/runs/41813612741), source
  `5a4d2bea2e8b24b4006ff10035ee5a8c8da7b05e`: Linux compilation reached strict
  Clippy and failed on one unused unit and two needless borrows. Corrected
  without a behavior waiver; no installed observation completed.
- [#595](https://github.com/SoupTeam/soup-wall/actions/runs/41815559172), source
  `af4f4d05437666d7e2e4f6320fc1703327544927`: native checks/builds passed, but
  both first doctor observations failed `diagnosis_effect_attempt`, zero cases
  completed. Its original reports do not identify the offending syscall, and
  raw traces were not retained. Source/dependency inspection found that the
  unnecessary Tokio runtime initializes a Unix signal socketpair. Lifecycle-only
  doctor now runs synchronously; the strict witness was not relaxed. The witness
  now retains a finite syscall failure code and parses syscall names only at
  line start, so returned private filenames cannot masquerade as syscalls.

These attempts remain failures. #599 is the new observation, not a relabeling
of earlier outcomes.

## Reproduce and boundaries

In the Draft branch, dispatch `mcp-real-filesystem.yml` with
`installed_focus=lifecycle-preflight`; leave other options off. The two fresh
jobs build from their recorded clean SHA and invoke
`scripts/verify-sou225-lifecycle-preflight.py` from outside checkout. Only the
sanitized original report is uploaded, including a failed report when available.

The disposable environment contains a verified installed front-door component
in a private Agent home. It is **not a fully prepared protected MCP runtime**.
Full protected-runtime preparation/admission, active protection, live provider
inference, applying removal and WSL2 were not measured here. These gaps remain
explicit; existing runtime/removal checks and WSL2 qualification still apply.
There is no dependency on SOU-216's open CI session-preparation helper, scope
configuration, classifiers or private evaluation data. Final shared Ready CI,
CodeQL qualification, candidate admission and merge remain TL-owned; PR stays Draft.
