# Native Windows Connection Evaluation

Task: [SOU-66](https://linear.app/soup-wall/issue/SOU-66/deliver-native-windows-claude-code-mcp-connect-verification-and-crash)

Date: October 16, 2026

Source base: `fb70696b87e6c35b0a5cedde0c6fba51c432419e`

## Result

All 35 local runtime controls passed. The production Windows Agent completed
preview, connect, inspect, controlled read/create and disconnect in disposable
profiles. A pinned Claude Code executable completed both control and protected
sessions against an owned local scripted provider.

Acceptance remains incomplete. The Windows account had a filtered
administrator token and still belonged to the Administrators group. This is
not the required genuine standard-user run. The dedicated CI workflow and
disposable-account launcher are prepared locally but have not run on GitHub.

## Verification

| Check | Observed Result |
| --- | --- |
| Windows connection regressions | 14 passed, no failures or skips |
| Full native Windows Agent library | 321 passed, no failures, 1 existing privileged symlink test ignored |
| Linux connection regressions | 22 passed, no failures or skips |
| Native runtime and actual-host controls | 35 passed, no failed controls or skips |
| Evidence parser regression controls | 4 passed |
| Windows and Linux Agent Clippy | Passed with warnings denied |
| Rust formatting | Passed |
| PowerShell launcher syntax | Passed |

The 14 focused regressions are included in the full native library count.
Mandatory junction coverage ran; the ignored symlink test requires Developer
Mode or a privilege that this account does not have.

The runtime controls exercised exact preservation of unrelated settings,
repeat connect/disconnect, a selected-entry conflict, unavailable daemon
refusal, private runtime selection, Unicode paths and executable paths with
spaces. A direct session retained an opaque Unicode JSON-RPC ID and the
original read argument. Its processes exited normally, reached stdout EOF and
joined the reader without forced cleanup.

The publication tests used real Windows file operations. They changed bytes
and replaced the destination at the publication boundary, wrote through an old
descriptor after success, and terminated child processes before and after
replacement. Conflicts retained the external version and journal. Recovery
accepted only exact recorded states.

## Host Observations

Claude Code version: `2.1.251`

The final run used the executable extracted from the official Windows x64 npm
package in temporary build storage. Its archive SHA-512 and executable SHA-256
match the pins in the acceptance workflow. No package lifecycle scripts ran.

Host SHA-256:
`8d1229a281281b98fd2dee72b3253a704be4fce4d45207200cd32a9bb5a6c909`

The unprotected control returned the owned document. The protected session
returned the same useful text, refused an outside-workspace creation and
created the allowed file with exact expected bytes. The original MCP child
ledger remained empty for protected calls: the native executor performed
admitted operations. The child received neither the fixture provider key nor
the application sentinel.

Scripted provider responses establish native host interoperability. They do
not measure live-model quality. No host installation, host update, real user
profile or paid provider account was used.

## Evidence

- [Runtime observations and source hashes](windows-connection-2026-10-16.json)
- [Full native Windows library output](windows-connection-tests-2026-10-16.txt)
- [Operator guide](../WINDOWS_MCP_CONNECTION.md)

Agent SHA-256:
`a6fe11842f532f492efaec31d52c4b054d33a90f896df0455f54a39e9c562d51`

Native test binary SHA-256:
`225f22c281c3b00b35c773a5aff467662e7f854778ce8a272da1c07078b58947`

The source base identifies the accepted starting point, not a clean committed
candidate. The retained source manifest identifies the local working-tree
files actually tested. Source and selected binary hashes remained unchanged
through the final run. Disposable profiles were removed and no Agent process
remained. The account SID in the retained JSON is replaced with its SHA-256;
runtime observations are otherwise unchanged.

## Remaining Acceptance

Run the prepared native acceptance workflow. It exercises both transactions
and the actual pinned Claude Code host under its disposable standard account,
and requires all 35 controls, exact source identity and successful cleanup.
Retain the resulting acceptance and launcher reports before claiming SOU-66
complete. The workflow has not yet run; local syntax and wiring checks do not
replace runtime evidence.

The local command uses `--diagnostic` and correctly returns incomplete status
despite all 35 runtime controls passing. Neither cross-compilation nor the
filtered administrator run supplies the missing account evidence.
