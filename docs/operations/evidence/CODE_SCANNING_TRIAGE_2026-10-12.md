# Code scanning triage follow-up — 2026-10-12

Authorized live GitHub rereading now verifies **zero open / 81 closed alerts** for
`is:open branch:main`. Each of the six original Critical fixture findings (#85–#90)
is individually confirmed **Dismissed by `winux125` as used in tests on October 11**.
The dismissals agree with the recorded maintainer technical review and unchanged
source hashes. The exact selected candidate's Rust CodeQL configuration is working
as expected. No source repair, new dismissal or security-setting change was
performed in this verification.

[Structured evidence](CODE_SCANNING_TRIAGE_2026-10-12.json) records the current
scope, per-alert activity, analyzed revision, prior review and local snapshot hashes.
Raw authenticated navigation/account details and literal fixture inputs stay local.
[The October 11 inventory](CODE_SCANNING_TRIAGE_2026-10-11.md) remains immutable
historical evidence.

## Observation history

| Evidence | Actor/time | Supported conclusion |
| --- | --- | --- |
| Initial independent inventory and exact-main scan | October 11; source `9b055a6d97166a9b3f9347c45c305038c331cfcf` | Six open Critical / 74 closed at that observation; working Rust scan with Python/Actions configurations identifying the same revision |
| [SOU-17](https://linear.app/soup-wall/issue/SOU-17/task-11-independently-verify-failure-overlap-and-replay-behavior), comment `988e827e-d81e-4075-8ecb-443007074471` | Baubek Serikbay, October 11 07:38:40 UTC | Maintainer review supports six FP assessments on `91a401a03b9f4a44f5f341c83c53a25e7d6e527f`; no production repair identified |
| SOU-17, comment `6fff57c3-b72a-40ac-bc07-f3770bed2347` | Baubek Serikbay, October 11 07:43:28 UTC | Authenticated individual reread reported six open / 74 closed; no disposition changed by that check |
| [SOU-18](https://linear.app/soup-wall/issue/SOU-18/task-12-verify-clean-setup-and-actual-active-protection-status), comment `8982bba4-5583-4cc3-9b10-a536cedb029b` | Baubek Serikbay, October 11 09:54:16 UTC | Later historical overview reported zero open / 80 closed; the review itself changed no alerts/settings |
| Initial October 12 attempt | Independent security reread | DNS failure prevented verification; retained as an environmental phase, now resolved |
| Later authorized October 12 reread | Main open/closed lists, all six full activity pages and Rust status | Zero open / 81 closed, all six justified test-fixture dismissals individually verified, exact candidate Rust scan working |

These observations have different timestamps; the older 6/74 and 0/80 records are
not rewritten as current counts. Restored access resolved the initially reported
DNS blocker. The current check made no dismissals or settings changes.

## Exact source and analysis

Reviewed and analyzed candidate:
`45b611a36834533b9d17d12d6b9a1357a3843457`.
All six source links identify this revision. The
[Rust default-setup configuration](https://github.com/SoupTeam/soup-wall/security/code-scanning/tools/CodeQL/status/configurations/automatic/2b7122206b8ac86cd7b88fd927bd502861908b2a6bfb3dfdcf2968009cb71086) reports working as expected,
last scan October 12 at 14:50 Asia/Almaty (minute precision as observed):
CodeQL 2.27.2, `/language:rust`, rust-queries 0.1.44, rust-all 0.2.23 and
threat-models 1.0.59. The sidebar also identifies this source for Python and
Actions; their individual status pages were not inspected for this report.

## Per-alert review and actual disposition

| Alert | Candidate source | Evidence-backed rationale | Verified GitHub disposition |
| --- | --- | --- | --- |
| [#85](https://github.com/SoupTeam/soup-wall/security/code-scanning/85) | [provider_baseline.rs:165](https://github.com/SoupTeam/soup-wall/blob/45b611a36834533b9d17d12d6b9a1357a3843457/vendor/kryptering/tests/provider_baseline.rs#L165) | PBKDF2 known-answer input with fixed expected bytes; FIPS mode rejects undersized parameters. | Dismissed by `winux125`, used in tests, October 11 |
| [#86](https://github.com/SoupTeam/soup-wall/security/code-scanning/86) | [provider_baseline.rs:193](https://github.com/SoupTeam/soup-wall/blob/45b611a36834533b9d17d12d6b9a1357a3843457/vendor/kryptering/tests/provider_baseline.rs#L193) | Compliant PBKDF2 known-answer input; fixed expected output, independently documented Python hashlib comparison. | Dismissed by `winux125`, used in tests, October 11 |
| [#87](https://github.com/SoupTeam/soup-wall/security/code-scanning/87) | [provider_baseline.rs:524](https://github.com/SoupTeam/soup-wall/blob/45b611a36834533b9d17d12d6b9a1357a3843457/vendor/kryptering/tests/provider_baseline.rs#L524) | Negative RustCrypto test asserts UnsupportedAlgorithm before input parsing; no credential is installed. | Dismissed by `winux125`, used in tests, October 11 |
| [#88](https://github.com/SoupTeam/soup-wall/security/code-scanning/88) | [provider_baseline.rs:549](https://github.com/SoupTeam/soup-wall/blob/45b611a36834533b9d17d12d6b9a1357a3843457/vendor/kryptering/tests/provider_baseline.rs#L549) | Negative FIPS test asserts refusal of SHA-1 PBKDF2 before parameter validation. | Dismissed by `winux125`, used in tests, October 11 |
| [#89](https://github.com/SoupTeam/soup-wall/security/code-scanning/89) | [provider_parity.rs:502](https://github.com/SoupTeam/soup-wall/blob/45b611a36834533b9d17d12d6b9a1357a3843457/vendor/kryptering/tests/provider_parity.rs#L502) | Fixed PBKDF2 expected outputs check provider parity; FIPS mode rejects undersized parameters. | Dismissed by `winux125`, used in tests, October 11 |
| [#90](https://github.com/SoupTeam/soup-wall/security/code-scanning/90) | [provider_parity.rs:532](https://github.com/SoupTeam/soup-wall/blob/45b611a36834533b9d17d12d6b9a1357a3843457/vendor/kryptering/tests/provider_parity.rs#L532) | Compliant PBKDF2 parameter variants check fixed expected outputs across providers. | Dismissed by `winux125`, used in tests, October 11 |

Alert #85's activity time was observed at 14:01 Asia/Almaty on October 11, to minute
precision. Other retained activity pages establish the same date without claiming
an exact time. Each full activity page identifies `winux125` and the reason
`used in tests`; closed-list entries independently agree. Earlier loading-only
captures for #86–#90 are excluded from the evidence manifest.

The inputs are explicit Cargo integration-test fixtures with fixed expected outputs
or deliberate rejection checks. The production library target is `src/lib.rs`;
source searches found no production inclusion of these test files. The application
workspace excludes the vendored test/dev graph while consuming its library. There
is no production-secret defect established at these six locations. The maintainer's
technical assessment was recorded before their actual dispositions were independently
verified; fixture inputs were preserved rather than randomized to silence detection.

| File | SHA-256 on the selected candidate, matching initial triage and maintainer review |
| --- | --- |
| `provider_baseline.rs` | `70755b1ffd48ba145a7689b0a0572fc8be4d833c35dd419528a14fc9ad212fce` |
| `provider_parity.rs` | `29afd20f093375a539bb2efd8b0818bd6017671c966001be396bdafc0ad3889f` |

## Scope and follow-up

Initial triage, review-supported test-fixture dispositions and an exact-source working
Rust analysis are verified for this selected candidate. No confirmed source defect,
remediation issue, production fix or remediation-commit rescan is claimed for these
six findings. Zero open alerts is the observed main inventory, not a certification
of other branches or every historical closed alert.

Konung3 retains this evidence with the runtime report; any relevant later code change
requires affected checks on its new revision and any new open finding requires triage.
Nari remains PR review coordinator. Userarlan/SOU-18 owns scan/check configuration
and independently tested merge gates; no protections were activated or certified
here. Static-analysis success and justified dismissals do not establish actual
native/MCP execution enforcement effectiveness.
