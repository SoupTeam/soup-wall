# SOU-63 integration with current main

Merged main `fb70696b87e6c35b0a5cedde0c6fba51c432419e` into SOU-63 head `1254366ecc527dd12c16eb9a076bf8dddccfbdfe`.

The native request keeps both authenticated child authority fields and SOU-62's typed MCP host call ID. Calls validate child scope before applying the selected result profile correlation checks. Both branches' native regression tests are retained. The new selected-server fault-test configuration explicitly uses the legacy unbound mode.

Full merged workspace: 1275 passed, 0 failed, 10 intentionally ignored. Clippy with `-D warnings` and formatting pass. Tests ran from an isolated temporary source export with only loopback networking. See [results.json](results.json) for suite summaries and exact changed-source hashes.

Earlier [hardening evidence](../sou-63-final-hardening-2026-10-16/README.md) describes the pre-integration head and retained real-process witnesses. This report covers the newer merged source. GitHub CI and reviewer approval are separate gates; this local evidence does not claim they have passed.
