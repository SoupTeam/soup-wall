# Native Windows self-test verification

Date: 17 October 2026

Task: [SOU-71](https://linear.app/soup-wall/issue/SOU-71/deliver-native-windows-installed-agent-self-test-with-owned-process)

Base: `6f45156084722e35408a3c626d519eda163302c1`

## Method

The existing `agentfw self-test` command was extended with a Windows backend.
The shared fixture, five scenarios, status values, exit codes and
`sw-self-test/1` report format were retained. The Unix backend was preserved.

The executable was built with Rust 1.98.1 for `x86_64-pc-windows-gnu` and
executed on native Windows build 26200 with Python 3.11.9. The harness copied
the binary and classifier into a fresh directory outside the checkout.
The operator command used no compiler, Docker, administrator rights,
downloads or provider account.

The host temporary directory grants an additional account write access. Its ACL
was left unchanged. The harness created its staging directory with a private
DACL at creation and selected a private TEMP/TMP directory for each run.

## Observed behavior

All five scenarios passed in the retained positive run.

| Scenario | Fixture executions | Receiver connections | Reply latency, ms |
|---|---:|---:|---:|
| Exact allowed read | 1 | 0 | 200.70 |
| Adversarial result withheld | 1 | 0 | 145.54 |
| Synthetic-key send refused | 0 | 0 | 148.08 |
| Useful read after refusal | 1 | 0 | 154.62 |
| Actual daemon loss | 0 | 0 | 4223.47 |

Both useful reads preserved the original request and response bytes.
The adversarial result produced an Ask receipt and was withheld without
approval. The protected send produced a Deny receipt before fixture execution.
After daemon termination, the collector exited without forwarding the call.

The final journal contained exactly three permitted executions. The receiver
recorded one direct positive control and no tool-originated delivery.
Both owned process jobs were empty, their leaders were reaped, the receiver
closed and the workspace was removed. Timings are single-run debug-build
observations, not a latency-overhead benchmark.

## Boundary checks

The native acceptance driver passed 19 checks. These cover missing assets,
a wrong classifier hash, an existing report, alternate data streams, device
and trailing-name aliases, reparse paths, foreign ownership, unsafe parent
ACLs, a foreign listener, failed cleanup and actual Ctrl+C with an active
descendant. Sentinel files, a synthetic operator profile and an unrelated
process remained unchanged.

Processes enter kill-on-close jobs while suspended. New fixture objects have
the current user as owner and a protected private DACL. Existing directories
are inspected without repair. Report paths receive the same checked NTFS
name validation used by the Windows file executor before file creation.

## Regression checks

| Check | Result |
|---|---|
| Native Windows acceptance | 19 passed |
| Native self-test unit tests | 10 passed |
| Existing Windows boundary tests | 56 passed, 1 ignored |
| Windows Python controls | 31 passed |
| Complete Rust workspace, serial Linux run | 1430 passed, 12 ignored |
| Complete Python suite, Linux/Python 3.12 | 713 passed, 36 skipped |
| Python benchmark suite, Windows | 43 passed, 19 skipped |
| Workspace Clippy and Windows all-target Clippy | Passed with warnings denied |
| Rust formatting, PowerShell syntax and documentation links | Passed |

The ignored Windows symlink test requires Developer Mode; mandatory junction
checks passed. Other skips require explicitly selected databases, identity
providers, model runtimes or sandbox profiles.

The first parallel Rust run hit an occupied port in the unchanged
`mcp_concurrency` suite. The isolated repeat and complete serial run passed.
An unfiltered Windows Python run exposed existing POSIX, OpenSSL and locale
prerequisites; the complete suite passed in its Linux/Python 3.12 environment.
The benchmark suite passed on Windows, where its Git worktree metadata was
available.

## Evidence and scope

The [native report](sou71/self-test-report.json),
[acceptance results](sou71/acceptance.json),
[native unit log](sou71/native-tests.log),
[Windows regression log](sou71/windows-regressions.log) and
[source manifest](sou71/source-manifest.json) bind these results to the selected
binary, classifier, policy, registry, fixtures and the initial candidate's source files
at commit `a0d7e85`.
The [operator guide](../WINDOWS_SELF_TEST.md) gives the reproduction commands.

The local account used a non-elevated UAC token and retains administrator
group membership. This record does not replace acceptance under a clean
standard account. The added Windows workflow provisions that account, rejects
administrator membership and retains its evidence. That CI run and review
remain required before SOU-71 can be accepted.

The [first Windows CI run](https://github.com/SoupTeam/soup-wall/actions/runs/39055938409)
passed all 19 acceptance checks under a clean standard account. The launcher
still failed: the administrator could not remove the standard user's private
temporary directory. Cleanup now runs in the owning child process, including
failure paths; the launcher checks that the directory is gone. A native
regression covers successful and failed child runs without changing the ACL
rules. The [corrected workflow](https://github.com/SoupTeam/soup-wall/actions/runs/39056404158)
passed with 19 checks, no administrator group membership, and confirmed account
and staging removal. The broader Windows suite also exposed short-path aliases
in unit-test temporary paths. Those fixtures now resolve the temporary parent
and create an explicitly owned private directory. Production path validation
is unchanged; the complete Windows regression job remains required.

These results cover the scripted MCP fixture path. They do not establish
live-model effectiveness, an OS sandbox or completion of Phase 4.
