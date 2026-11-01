# Installed configuration recovery evidence

Only finite sanitized qualification reports are retained here. Private backup
bundles, configuration homes, authority, wire files and credentials are not
acceptance artifacts. All scenarios use owned synthetic projects and an owned
scripted provider; no paid inference or actual publication is attempted.

## Attempt history

| Attempt | Source | Outcome | Evidence |
| --- | --- | --- | --- |
| Native 1 | `77062f87ef04e0979c35873c4dd939c3a0a9bb0e` | Failed before operator scenarios: accepted selection still referenced checkout assets; outside-checkout guard refused | [Report](native-attempt-01-report.json), [workflow](https://github.com/SoupTeam/soup-wall/actions/runs/41296614453) |

Native attempt 1 passed all 23 Python recovery controls, 6 qualification grader
controls, 11 Rust projection tests, Agent Clippy with warnings denied, and
workspace formatting. Its installed qualification has 1 passed cleanup case,
1 failed precondition and 15 incomplete cases. It establishes no installed
recovery acceptance. Source was clean and unchanged; all owned processes were
stopped and private test state was removed.

Artifact `13079253967` ZIP SHA-256:
`e0d74d8ac9a1bea01658fb4a71eafe8e71b1725653770581d2e860fb80e07830`.
ZIP inventory/CRC and the single report were independently checked. Report
SHA-256: `e56aed79550c3f0b99c6946893667ee444a8800733c15e45ce044447ffb1e5bf`.

Earlier local WSL checks passed 11 Rust tests and an offline Agent build. Later
WSL startup failed with `CreateVm/HCS/ERROR_NO_SYSTEM_RESOURCES` before final
native syscall tests and Clippy could execute. This is an environment failure,
not a native Linux product result. Host/VM configuration was not changed;
Ubuntu and Docker WSL distributions were subsequently verified stopped.

Final shared CI, security review, exact-candidate admission and merge remain
separate maintainer decisions. Native Ubuntu evidence does not qualify WSL,
Windows or macOS.
