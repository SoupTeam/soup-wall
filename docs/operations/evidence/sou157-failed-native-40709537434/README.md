# Failed formatter-shadow native witness

Run: https://github.com/SoupTeam/soup-wall/actions/runs/40709537434
Job: 122890824751. Source: `1fde15fcfe832ab5cb85f9fef1ee9148d995a5cf`.
Artifact: 12825582266; downloaded archive SHA-256:
`4f8d9a1787a9dc14649539be3e7822505cfb771351f7e4ed22e28a546a159809`.
The three JSON files retain the failed runtime, incomplete sidecar and rejected
projection. Archive CRC was verified. These are failed evidence, not acceptance.

The useful single-file read passed; the first 50-file benign exchange closed
before a response. Collector exit was 1; the owned root was empty after cleanup.
The old artifact did not retain a specific daemon failure code.

## Reproduced defect and repair

The collector captures `OriginalResult.metadata()` before inspection and compares
the complete receipt afterward. Formatter attribution was previously added only
in `consume()`, so the two receipts differed on attributed responses. A regression
assertion comparing these exact receipts fails against the old implementation.
This deterministic defect is consistent with the first multi-file failure; a new
Linux witness is still required to confirm the complete runtime path.

Attribution is now frozen with the private original response and bound invocation
arguments. Both receipt reads return the same metadata. Custody checks and strict
receipt equality remain enforced. No verdict, policy or resource limit changed.

Failure diagnostics now retain the current case and bounded exception type, plus
up to four allowlisted daemon failure records. Raw exception text, tool payloads
and credentials are excluded. The generated CI component workflow is synchronized.

Validation: 145 native Rust tests passed; Clippy with warnings denied passed.
Python CI-component/controller suite: 14 tests, OK with one platform skip.
Generated workflow check passed. The new controller test verifies incomplete
first-case evidence without leaking exception payloads.

This remains Draft/shadow work. No successful new Linux witness, production
relief, resolution of the 10 false refusals, or independent acceptance is claimed.
