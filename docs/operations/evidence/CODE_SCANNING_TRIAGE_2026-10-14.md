# Code scanning triage — 2026-10-14

Triage owner: konung3. Runtime task:
[SOU-17](https://linear.app/soup-wall/issue/SOU-17/task-11-independently-verify-failure-overlap-and-replay-behavior).
Review coordinator: Nari_Ab. Scan/check configuration acceptance remains with
[SOU-18](https://linear.app/soup-wall/issue/SOU-18/task-12-verify-clean-setup-and-actual-active-protection-status).

Authenticated repository access independently confirms **one open Critical alert
and 85 closed alerts** for `is:open branch:main`. This is not a zero-alert clean
scan. The sole open finding is an evidence-backed false-positive recommendation;
no confirmed static-analysis defect was found, no alert was dismissed and no
scan/security setting was changed. The previous
[October 12 inventory](CODE_SCANNING_TRIAGE_2026-10-12.md) remains historical.

[Structured inventory](CODE_SCANNING_TRIAGE_2026-10-14.json) records the exact
source, tool configuration, open finding and disposition. Original authenticated
UI snapshots, screenshots and exact-source excerpts are retained in the
[SOU-17 evidence manifest](../../benchmarks/evidence/sou17_candidate_5fc6d72_2026-10-14.json).

## Exact-source scan status

The CodeQL Default setup reports all three configurations working as expected
on `5fc6d72fd73ebe9faa70c56607fc492163df1a42`. Events are push and pull request to
main. CodeQL version: **2.27.2**; threat-models: **1.0.59**.

| Configuration | Last scan, UTC | Query/library packs | Scanned files |
| --- | --- | --- | --- |
| [Rust](https://github.com/SoupTeam/soup-wall/security/code-scanning/tools/CodeQL/status/configurations/automatic/2b7122206b8ac86cd7b88fd927bd502861908b2a6bfb3dfdcf2968009cb71086) | October 14, 15:20 | rust-queries 0.1.44 / rust-all 0.2.23 | 191/191 |
| [Python](https://github.com/SoupTeam/soup-wall/security/code-scanning/tools/CodeQL/status/configurations/automatic/26ede4f3754c9f4fcc89e7cdda1495e02b34ee829f82627c59dc0c777bd87f05) | October 14, 15:11 | python-queries 1.8.12 / python-all 7.2.7 | 192/192 |
| [Actions](https://github.com/SoupTeam/soup-wall/security/code-scanning/tools/CodeQL/status/configurations/automatic/f0d647c03610b6574e2d8c699190d896c36219c30f6f12c6ae368a6ea34ab51a) | October 14, 15:10 | actions-queries 0.6.37 / actions-all 0.6.3 | 11/11 |

The Actions configuration additionally lists javascript-all 2.10.3. These pages
establish analysis completion and source identity, not required-check/ruleset
enforcement or runtime tool-call protection.

## Open-alert triage

| Alert | Rule and severity | Affected source | Verdict |
| --- | --- | --- | --- |
| [#112](https://github.com/SoupTeam/soup-wall/security/code-scanning/112) | `rust/hard-coded-cryptographic-value`, Critical | [`crates/agentfw/src/grant.rs:448`](https://github.com/SoupTeam/soup-wall/blob/5fc6d72fd73ebe9faa70c56607fc492163df1a42/crates/agentfw/src/grant.rs#L448) on main | Evidence-backed false positive; still Open, coordinator review pending |

The reported constant `0o600` is a Unix filesystem permission mode passed to
`Permissions::from_mode` and `set_permissions`. It is not a nonce, key, salt or
cryptographic input. The displayed 16-step CodeQL flow carries the permissions
operation's `io::Result` through `write_unlocked`, the `issue` result tuple and a
test's returned Grant, then ends at the nonce used for a filename. Actual source
does not copy the permission mode into that Grant or mutate the borrowed Grant:
`write_unlocked` returns only a `PathBuf`, while `issue` passes its explicit
nonce into `mint_with_epoch`. The shown test obtains its nonce from
[`crate::token::generate()` at grant.rs:854](https://github.com/SoupTeam/soup-wall/blob/5fc6d72fd73ebe9faa70c56607fc492163df1a42/crates/agentfw/src/grant.rs#L854);
[`token.rs:14–17`](https://github.com/SoupTeam/soup-wall/blob/5fc6d72fd73ebe9faa70c56607fc492163df1a42/crates/agentfw/src/token.rs#L14)
fills 32 random bytes before encoding. This particular path therefore does not
establish the reported hard-coded cryptographic value.

The finding first appeared after [PR #94](https://github.com/SoupTeam/soup-wall/pull/94)
at `d940d9e71bd7074e9f368961e7393e0d52a85e91`; the current alert snippet and Rust
analysis identify the newer exact main `5fc6d72…`. Nari coordinates disposition.
No remediation issue is invented for a finding that does not establish a defect,
and no production randomization/refactoring is made solely to silence the query.
Any eventual dismissal must retain the source/flow rationale and normal review.

## Earlier findings and observed dispositions

- [#114](https://github.com/SoupTeam/soup-wall/security/code-scanning/114) and
  [#115](https://github.com/SoupTeam/soup-wall/security/code-scanning/115), High
  `py/weak-sensitive-data-hashing`, are now dismissed as false positives by
  `winux125` on October 14. The recorded rationale is a fresh 256-bit machine
  secret from `secrets.token_hex(32)`, Redis 7.2's required SHA-256 ACL verifier
  and a protected `0600` configuration containing only the verifier. The second
  finding is the companion regression assertion. Re-triage if entropy, input
  provenance or protocol use changes; do not generalize this to human passwords.
- [#113](https://github.com/SoupTeam/soup-wall/security/code-scanning/113), High
  `py/clear-text-storage-sensitive-data`, is absent from current main's open
  inventory and identifies only a historical PR #105 occurrence. Its page header
  still displays Open at `30e75b7`, while Activity explicitly records Fixed in
  `refs/pull/105/head` at `ae3e742a41f4512e7114b05d6cd094adec55f801`. This UI
  discrepancy is retained rather than misreported as an unresolved current-main
  defect or silently dismissed.
- Earlier dated fixture findings and dismissals remain documented in the
  October 9–12 reports. The updated aggregate count does not rewrite those
  historical observed states.

No newly confirmed code-scanning defect requires a fix issue or remediation
rescan in this inventory. The separate runtime findings
[SOU-44](https://linear.app/soup-wall/issue/SOU-44/refuse-post-admission-fifo-replacement-without-blocking-the)
and [SOU-45](https://linear.app/soup-wall/issue/SOU-45/enforce-unsupported-overlap-refusal-for-inline-constrained-mcp-reads)
have named implementation owner/reviewer Nari_Ab and independent verifier konung3.
Their completion requires reviewed runtime fixes and affected boundary reruns;
static analysis does not establish enforcement effectiveness.
