# SOU-188 author acceptance

The built-in Linux `pilot-removal` command removes only the verified installed
`pilot-front-door` component after an exact preview and explicit confirmation.
The Agent binary, recovery journal, preparation generations, project data,
outputs, review/export bundles, backups, audit/history and provider credentials
remain outside removal scope. See the [operator guide](../../INSTALLED_PILOT_REMOVAL.md).

Native source: `e2127abcbcb1c12cbd635099d0a4315f1ea8b9d7`.
Source tree: `188236b296c9dd034fd7a827dc3fac83b5ea707c`.
The source includes accepted main `7c5cf90c` and preserves SOU-189 diff consent
boundaries. Evidence/documentation added afterwards does not claim execution of
that later documentation commit.

[Native run 41118449085](https://github.com/SoupTeam/soup-wall/actions/runs/41118449085)
passed in explicit source mode, on non-root Ubuntu 24.04 x86_64 with read-only
source, scratch-only writes and loopback-only target networking. The candidate,
source tree, qualifier hash and binary digest were independently matched to the
retained source/build/report witnesses. The report also passed its strict finite
26-case grader. No paid inference or real credentials were used.

| Check | Verified result |
| --- | --- |
| Removal protocol tests | 11 passed |
| Installed removal qualification | 26/26 passed |
| Other installed workflow reports | 10 reports, 263 cases passed |
| Linux source build / all-target agentfw Clippy / formatting | Passed |
| macOS workspace regression | 1932 passed, 13 platform/environment ignored, 0 failed |
| macOS workspace all-target Clippy, `-D warnings` | Passed, 0 warnings |
| Qualifier grading controls / generated CI consistency | Passed |

The native scenarios verify installed startup with a 1 MiB stack, useful genuine
host create/read effects before removal, inert preview, both consent flags,
changed selections, damaged receipts, isolated symlink/hardlink/FIFO controls,
redirected roots, unknown state, live-process and active-edit refusal, actual
component removal, retained recovery and already-removed behavior. Syscall
faults cover SIGKILL before unlink, between completed objects and after unlink,
unlink I/O failure, failed parent sync, explicit bounded retry and substituted
objects. Missing/uncertain objects never become successful removal merely by
absence. The earlier public report attempts are retained in the finite ledger;
failed or cancelled attempts are not counted as acceptance.

`active-process-reference` is an owned process-reference control using `sleep`;
it is not described as a genuine read-only MCP run. The active edit and useful
create/read scenarios use actual installed native host processes and the pinned
scripted loopback provider. User/project/sibling/credential/output and retained
completed-run witnesses remained unchanged during removal operations; operator
provider requests were zero.

The command requires explicit maintenance exclusion and complete operator-selected
custom state roots. Cooperative locks and process observations do not provide
universal exclusion against arbitrary same-UID programs. Unsupported scopes and
unverified run evidence refuse; prerequisite generation cleanup remains the
separate accepted receipt-aware workflow. There is no force-stop or global Agent
or service uninstall.

[acceptance.json](acceptance.json) contains only finite outcomes, counts, public
source/build identities and artifact hashes. Raw operator payloads, local paths,
private contents and acknowledgement values are not published here. Final shared
Ready CI, CodeQL, candidate admission and merge remain team-lead-owned.
