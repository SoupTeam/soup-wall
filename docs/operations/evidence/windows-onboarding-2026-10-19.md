# Native Windows onboarding verification

Task: [SOU-90](https://linear.app/soup-wall/issue/SOU-90), 19 October 2026.

Scope: local verification; standard-account CI pending.

## Implementation

`agentfw onboard-windows` provides `preview`, `apply`, `inspect`, `verify`,
`recover` and `remove`. It reuses the existing lifecycle manager, Windows MCP
connection transaction and installed self-test.

Preview binds the confirmation to the selected files, their SHA-256 digests,
host configuration and destinations. Apply creates a fresh private home and
records bounded recovery state before publishing the selected MCP connection.
Recovery checks ownership and preserves conflicting operator edits. Removal
restores the original selected entry and keeps unrelated files and settings.
The command does not download dependencies or request elevation.

The [operator guide](../WINDOWS_ONBOARDING.md) covers first use and recovery.

## Revision and environment

| Item | Value |
| --- | --- |
| Upstream base | `030178064a368a0fb21f2e70e9da2d6705273c0c` |
| Agent source | `e86b9dfc48d2626ca2a34fe37f153bb56d7f2a76` |
| Acceptance driver revision | `c76e6ffc304ea4d3b63a6aa262ac313885030e22` |
| Runtime | Native Windows, build 26200, local NTFS |
| Python | CPython 3.11.9 |
| Build | Rust 1.98.1, `x86_64-pc-windows-gnu`, cross-compiled in Docker |
| Account | Non-elevated; Administrators group present in the filtered token |

The driver revision adds a process-image check before interrupting the owned
daemon. It does not change the Agent binary. All execution, ACL, junction and
process-ownership checks ran on Windows, outside the source checkout.

## Results

| Check | Result |
| --- | --- |
| Native onboarding acceptance | 18 passed, 0 failed; cleanup verified |
| Installed self-test | 5 passed; protected send executed 0 times |
| Native Agent library | 488 passed, 0 failed, 2 ignored |
| CI scheduling and admission tests | 43 passed |
| Windows Python tests | 33 passed |
| Windows Clippy, all targets, warnings denied | Passed |
| Rust formatting and Linux all-target check | Passed |

The two ignored library entries are an internal subprocess helper, which its
parent test invokes, and an existing symlink test that requires Developer Mode
or a privilege. Mandatory junction checks and all 12 onboarding unit tests
passed. The 18-case acceptance has no skipped scenarios.

The acceptance driver interrupted live setup at `prepared`, `configured`,
`installed`, `daemon_started`, `publishing` and `connected`. Each recovery
restored useful MCP reads; subsequent removal restored the original entry.
Wrong hashes, stale confirmations, foreign port occupancy and operator edits
did not authorize replacement or execution. Unrelated settings, a file and a
running sentinel process remained intact.

After daemon loss, the configured wrapper dispatched no child call. Recovery
sent no credentials to the foreign listener and restored the owned daemon.
The installed self-test withheld the adversarial result and refused the
protected send with zero executor calls and zero receiver deliveries for that
scenario. Its separate direct receiver control delivered one message to prove
that the receiver worked; this is an expected control, not an escaped send.

### Timings

| Scenario | Elapsed seconds |
| --- | ---: |
| Apply and verify daemon identity | 43.813 |
| Installed self-test command | 29.203 |
| Daemon loss, refusal and recovery | 31.922 |
| Owned removal and repeated removal | 7.609 |

These are single-run command durations, including validation and process
startup. They are not classifier latency measurements. The JSON records each
interruption scenario's elapsed time.

## Artifact identities

| Selected artifact | SHA-256 |
| --- | --- |
| Agent | `f528cdec1f6a29fc883a3429f02b1281e86320ea11f122de71d360c010f993dd` |
| Python executable | `5f7b89a612c9b8af1d6456cdfcd1dbe5ca630849e79aebced9bee9a6694952ec` |
| Classifier source | `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd` |
| Onboarding registry | `edb2a0cb6ef8d0dcdee09aa089fe5c79fc068ca72ade64d6987b3c1c01095830` |
| Selected policy | `8b2bfb66b14a988a29cf2698c482bc7cd91ba550fea14ccfa63540e815eb3c57` |
| Acceptance driver | `4f352b69457f0f5824a88f482924af7b32fb38d97ee47121a2eb81e5be7b9571` |

The installed self-test uses its bundled fixture registry and shipped policy.
Its report records those identities separately from the selected onboarding
registry.

## Corrections and limits

Windows normalizes private directory permissions into both effective and
inheritance-only ACEs. The onboarding check accepts that representation while
retaining current-user ownership, protected DACLs and the current-user/SYSTEM
allowlist. It refuses narrowed rights without repairing them. Tests cover both
the normalized ACL and a read-only owner grant.

The existing connection inspector's eight-second probe did not complete on
this host. Acceptance uses a separate sequential MCP client with a 25-second
limit per response and checks the returned note and execution ledger. The
production inspector's deadline remains unchanged.

The report distinguishes configured state, verified daemon identity, witnessed
synthetic protection and pending host reload. A running host still needs an
explicit reload. Synthetic fixture results do not establish arbitrary-server
sandboxing or live-model effectiveness.

This filtered administrator token is not a clean standard account. Current-head
standard-account CI, Windows regression/security jobs and review remain
unverified. The shared CI component runs native qualification for eligible
Ready for review PRs; Draft checks alone do not run it. Local evidence does not
close SOU-90.

## Reproduction and evidence

From a non-elevated native Windows terminal with a built Agent:

```powershell
python scripts/test-windows-onboarding.py --agent .\target\debug\agentfw.exe `
  --baseline rule_baseline/rule_baseline.py --source-commit (git rev-parse HEAD) `
  --out .\target\onboarding-results
```

Use a fresh output directory. The driver stages its own private installed
fixture outside the checkout.

- [Acceptance results](windows-onboarding/acceptance.json)
- [Installed self-test report](windows-onboarding/self-test.json)
- [Native library test log](windows-onboarding/agent-tests.log)

Only sanitized reports and the passing test log belong in this evidence set.
Private journals, tokens, host snapshots and connection archives stay local.
